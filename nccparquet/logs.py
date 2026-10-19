"""Parse NCC log members into nu_logs_local Parquet."""

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from nccparquet.archive import IP_RE, cvm_ip_from, iter_members, iter_text_lines
from nccparquet.dedup import IngestSeen, log_key
from nccparquet.layout import (
    LOG_DICTIONARY,
    LOG_ENCODING,
    LOG_SORT,
    ColumnWriter,
    write_sorted,
)
from nccparquet.parallel import map_unordered

MSG_CAP = 262144

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
GLOG_RE = re.compile(
    r"^(?P<level>[IWEF])(?P<date>\d{4}|\d{8}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)Z?\s+"
    r"(?P<pid>\d+)\s+(?P<src>[^:\s]+):(?P<line>\d+)\]?\s*(?P<msg>.*)$"
)
JAVA_RE = re.compile(
    r"^(?P<level>INFO|WARN|ERROR|DEBUG|FATAL|TRACE)\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}),(?P<frac>\d+)Z?\s+"
    r"(?P<src>\S+) \(line (?P<line>\d+)\)\s*(?P<msg>.*)$"
)
PY_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})[.,](?P<frac>\d+)Z?\s+"
    r"(?P<level>\S+)\s+(?:(?P<pid>\d+)\s+)?(?P<src>[^\s:]+):(?P<line>\d+)\]?\s*(?P<msg>.*)$"
)
PY_LOOSE_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})[.,](?P<frac>\d+)Z?\s+(?P<msg>.*)$"
)
GO_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2})\s+(?P<msg>.*)$"
)
DMESG_RE = re.compile(
    r"^\[(?P<dow>\w{3}) (?P<mon>\w{3}) (?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) (?P<year>\d{4})\]\s*(?P<msg>.*)$"
)
ISO_SYSLOG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})\.(?P<frac>\d+)"
    r"(?P<tz>[+-]\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<src>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
SALT_RE = re.compile(
    r"^(?P<src>[\w.-]+):\s+(?P<date>\d{4}-\d{2}-\d{2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}),(?P<frac>\d+)\s+(?P<msg>.*)$"
)
AUDIT_RE = re.compile(r"msg=audit\((?P<epoch>\d+)\.(?P<frac>\d+):")
SYSLOG_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<src>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
LEVEL_CHAR = {
    "I": "I", "W": "W", "E": "E", "F": "F", "D": "D", "T": "T",
    "INFO": "I", "WARN": "W", "WARNING": "W", "ERROR": "E",
    "FATAL": "F", "DEBUG": "D", "TRACE": "T", "CRITICAL": "C",
}
_LOG_STEMS = {"messages", "dmesg", "secure", "audit", "minion", "command_collector"}
_HASH_CACHE = {}

SCHEMA = pa.schema(
    [
        ("log_bundle_id", pa.uint64()),
        ("event_time", pa.timestamp("ms", tz="UTC")),
        ("created_at", pa.timestamp("s", tz="UTC")),
        ("log_level", pa.string()),
        ("source_log_filename", pa.string()),
        ("filename", pa.string()),
        ("filename_without_ext", pa.string()),
        ("pid", pa.uint32()),
        ("cvm_ip", pa.string()),
        ("message", pa.string()),
        ("anomaly", pa.uint8()),
        ("anomaly_category", pa.string()),
        ("line_number", pa.uint32()),
        ("log_hash", pa.string()),
        ("component", pa.string()),
        ("db_server", pa.string()),
        ("error_code", pa.string()),
        ("ip", pa.string()),
        ("log_version", pa.string()),
        ("operation_id", pa.string()),
        ("tenant_id", pa.string()),
        ("tag", pa.string()),
        ("thread", pa.string()),
        ("mentioned_uuids", pa.list_(pa.string())),
    ]
)


def level_char(raw):
    token = (raw or "I").strip().upper()
    if token in LEVEL_CHAR:
        return LEVEL_CHAR[token]
    return token[:1] or "I"


def to_utc(dt, tz):
    sign = 1 if tz[0] == "+" else -1
    hours, minutes = tz[1:].split(":")
    offset = timedelta(hours=sign * int(hours), minutes=sign * int(minutes))
    return dt - offset


def clamp_year(dt, collected):
    if dt > collected + timedelta(days=1):
        try:
            return dt.replace(year=dt.year - 1)
        except ValueError:
            return dt
    return dt


def dt_from(year, month, day, hh, mm, ss, micros, collected):
    try:
        dt = datetime(
            int(year), int(month), int(day),
            int(hh), int(mm), int(ss), int(micros), timezone.utc,
        )
    except ValueError:
        return None
    return clamp_year(dt, collected)


def parse_hms(time_s, frac="0"):
    hh, mm, ss = time_s.split(":")
    micros = int((frac + "000000")[:6])
    return int(hh), int(mm), int(ss), micros


def uuids_of(text):
    seen = []
    for item in UUID_RE.findall(text or ""):
        low = item.lower()
        if low not in seen:
            seen.append(low)
    return seen


def log_hash(filename_wo, level, source, line_no):
    key = (filename_wo, level, source, line_no)
    cached = _HASH_CACHE.get(key)
    if cached is None:
        raw = f"{filename_wo}|{level}|{source}|{line_no}"
        cached = hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).hexdigest()
        _HASH_CACHE[key] = cached
    return cached


def want_member(name):
    base = name.rstrip("/").rsplit("/", 1)[-1]
    if not base or base.endswith("/"):
        return False
    lower = base.lower()
    if lower.startswith("sar") and lower[3:5].isdigit():
        return False
    if "/cvm_config/" in name or name.endswith("/metadata"):
        return False
    if lower.endswith((".gz", ".zip", ".xz", ".bz2", ".zst")):
        return False
    if ".log" in lower or lower.endswith((".out", ".info", ".warning", ".error", ".fatal")):
        return True
    return lower.split(".", 1)[0] in _LOG_STEMS


def parse_header(line, collected):
    # Most rows in an NCC bundle are syslog. Try those before the app formats.
    m = ISO_SYSLOG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        stamp = dt_from(y, mo, d, hh, mm, ss, micros, collected)
        if stamp is not None:
            stamp = to_utc(stamp, m.group("tz"))
        return {
            "event_time": stamp,
            "log_level": "I",
            "source_log_filename": m.group("src").strip(),
            "pid": int(m.group("pid") or 0),
            "line_number": 0,
            "thread": "",
            "tag": "syslog",
            "message": m.group("msg"),
        }
    m = SYSLOG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        return {
            "event_time": dt_from(
                collected.year, MONTHS[m.group("mon")], m.group("day"), hh, mm, ss, 0, collected
            ),
            "log_level": "I",
            "source_log_filename": m.group("src").strip(),
            "pid": int(m.group("pid") or 0),
            "line_number": 0,
            "thread": "",
            "tag": "syslog",
            "message": m.group("msg"),
        }
    m = AUDIT_RE.search(line)
    if m and line.startswith("type="):
        epoch = int(m.group("epoch"))
        micros = int((m.group("frac") + "000000")[:6])
        stamp = datetime.fromtimestamp(epoch, timezone.utc) + timedelta(microseconds=micros)
        return {
            "event_time": stamp,
            "log_level": "I",
            "source_log_filename": "audit",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "audit",
            "message": line,
        }
    m = GLOG_RE.match(line)
    if m:
        date = m.group("date")
        hh, mm, ss, micros = parse_hms(m.group("time").split(".")[0], m.group("time").split(".")[1])
        if len(date) == 8:
            year, month, day = date[:4], date[4:6], date[6:8]
        else:
            year, month, day = collected.year, date[:2], date[2:]
        return {
            "event_time": dt_from(year, month, day, hh, mm, ss, micros, collected),
            "log_level": level_char(m.group("level")),
            "source_log_filename": m.group("src"),
            "pid": int(m.group("pid")),
            "line_number": int(m.group("line")),
            "thread": "",
            "tag": "glog",
            "message": m.group("msg"),
        }
    m = JAVA_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros, collected),
            "log_level": level_char(m.group("level")),
            "source_log_filename": m.group("src"),
            "pid": 0,
            "line_number": int(m.group("line")),
            "thread": m.group("thread"),
            "tag": "java",
            "message": m.group("msg"),
        }
    m = PY_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros, collected),
            "log_level": level_char(m.group("level")),
            "source_log_filename": m.group("src"),
            "pid": int(m.group("pid") or 0),
            "line_number": int(m.group("line")),
            "thread": "",
            "tag": "python",
            "message": m.group("msg"),
        }
    m = SALT_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros, collected),
            "log_level": "I",
            "source_log_filename": m.group("src"),
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "syslog",
            "message": m.group("msg"),
        }
    m = DMESG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        return {
            "event_time": dt_from(
                m.group("year"), MONTHS[m.group("mon")], m.group("day"), hh, mm, ss, 0, collected
            ),
            "log_level": "I",
            "source_log_filename": "dmesg",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "dmesg",
            "message": m.group("msg"),
        }
    m = GO_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        y, mo, d = m.group("date").split("/")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, 0, collected),
            "log_level": "I",
            "source_log_filename": "",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "go",
            "message": m.group("msg"),
        }
    m = PY_LOOSE_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros, collected),
            "log_level": "I",
            "source_log_filename": "",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "python",
            "message": m.group("msg"),
        }
    return None


def _add(writer, rec, filename, cvm_ip, log_bundle_id, created, seen):
    if rec["event_time"] is None:
        return False
    base = filename.rsplit("/", 1)[-1]
    wo = base.split(".", 1)[0]
    level = rec["log_level"]
    source = rec["source_log_filename"]
    line_no = rec["line_number"]
    message = rec["message"][:MSG_CAP]
    ip = cvm_ip if IP_RE.fullmatch(cvm_ip or "") else "0.0.0.0"
    if not seen.accept(log_key(cvm_ip or "0.0.0.0", wo, rec["event_time"], level, rec["pid"] & 0xFFFFFFFF, source, message)):
        return False
    writer.add_row(
        {
            "log_bundle_id": log_bundle_id,
            "event_time": rec["event_time"],
            "created_at": created,
            "log_level": level,
            "source_log_filename": source,
            "filename": base,
            "filename_without_ext": wo,
            "pid": rec["pid"] & 0xFFFFFFFF,
            "cvm_ip": cvm_ip or "0.0.0.0",
            "message": message,
            "anomaly": 0,
            "anomaly_category": "",
            "line_number": line_no & 0xFFFFFFFF,
            "log_hash": log_hash(wo, level, source, line_no),
            "component": "",
            "db_server": "",
            "error_code": "",
            "ip": ip,
            "log_version": "",
            "operation_id": "",
            "tenant_id": "",
            "tag": rec["tag"],
            "thread": rec["thread"],
            "mentioned_uuids": uuids_of(message),
        }
    )
    return True


def consume(lines, member_name, writer, log_bundle_id, collected, created, seen):
    cvm = cvm_ip_from(member_name)
    current = None
    emitted = 0
    for line in lines:
        header = parse_header(line, collected)
        if header:
            if current is not None and _add(writer, current, member_name, cvm, log_bundle_id, created, seen):
                emitted += 1
            current = header
            continue
        if current is not None and line:
            room = MSG_CAP - len(current["message"])
            if room > 0:
                current["message"] += ("\n" + line)[:room]
    if current is not None and _add(writer, current, member_name, cvm, log_bundle_id, created, seen):
        emitted += 1
    if emitted:
        writer.files += 1


def _existing_logs(path, seen):
    path = Path(path)
    if not path.is_file():
        return None
    table = pq.read_table(path)
    columns = {
        name: table.column(name).to_pylist()
        for name in (
            "cvm_ip",
            "filename_without_ext",
            "event_time",
            "log_level",
            "pid",
            "source_log_filename",
            "message",
        )
    }
    for i in range(table.num_rows):
        event_time = columns["event_time"][i]
        if event_time is None:
            continue
        seen.done.add(
            log_key(
                columns["cvm_ip"][i],
                columns["filename_without_ext"][i],
                event_time,
                columns["log_level"][i],
                columns["pid"][i],
                columns["source_log_filename"][i],
                columns["message"][i],
            )
        )
    print(f"existing logs {table.num_rows}")
    return table


class _ListWriter:
    def __init__(self):
        self.rows = []
        self.files = 0

    def add_row(self, row):
        self.rows.append(row)


def parse_log_member(name, raw, log_bundle_id, collected, created):
    """Parse one archive member. Safe to run in a worker process."""
    writer = _ListWriter()
    seen = IngestSeen()
    consume(iter_text_lines(raw), name, writer, log_bundle_id, collected, created, seen)
    return name, writer.rows, seen.skipped, writer.files


def _log_members(bundles, collected):
    for bundle in bundles:
        bundle_collected = collected.get(bundle) if isinstance(collected, dict) else collected
        for name, raw in iter_members(bundle):
            if want_member(name):
                yield name, raw, bundle_collected


def run_logs(bundles, out, log_bundle_id, collected, jobs=1):
    if isinstance(bundles, (str, bytes)) or not isinstance(bundles, (list, tuple)):
        bundles = [bundles]
    out = Path(out)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    seen = IngestSeen()
    existing = _existing_logs(out, seen)
    incoming = out.with_suffix(".incoming.parquet")
    writer = ColumnWriter(incoming, SCHEMA)

    def on_result(result):
        name, rows, skipped, files = result
        seen.skipped += skipped
        kept = 0
        for row in rows:
            key = log_key(
                row["cvm_ip"],
                row["filename_without_ext"],
                row["event_time"],
                row["log_level"],
                row["pid"],
                row["source_log_filename"],
                row["message"],
            )
            if not seen.accept(key):
                continue
            writer.add_row(row)
            kept += 1
        if files:
            writer.files += files
            print(f"{kept:8}  {name}", flush=True)

    map_unordered(
        jobs,
        (
            (name, raw, log_bundle_id, bundle_collected, created)
            for name, raw, bundle_collected in _log_members(bundles, collected)
        ),
        parse_log_member,
        on_result,
    )
    seen.finish_bundle()
    writer.close()
    added = pq.read_table(incoming)
    incoming.unlink()
    if existing is not None and existing.num_rows:
        table = pa.concat_tables([existing, added], promote_options="default")
    else:
        table = added
    meta = write_sorted(table, out, LOG_SORT, LOG_DICTIONARY, LOG_ENCODING)
    print(
        f"rows {meta.num_rows} files {writer.files} added {added.num_rows} "
        f"skipped_duplicates {seen.skipped} parquet {out} bytes {out.stat().st_size}"
    )
    return meta.num_rows
