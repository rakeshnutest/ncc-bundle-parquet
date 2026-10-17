#!/usr/bin/env python3
"""Read an NCC tar.gz in place and write Panacea Parquet files.

    python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz
    python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz --schemas logs
    python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz --out-dir /tmp/out --log-bundle-id 2734579

Does not extract the archive or any nested zip onto disk.
nu_logs_local follows the Panacea log columns. nu_metrics_sysstats follows
the Panacea sysstats columns and is written from the sarNN reports.
"""

import argparse
import hashlib
import io
import re
import sys
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

LOG_BUNDLE_ID = 0
COLLECTED = datetime.now(timezone.utc)
BATCH = 20000
MSG_CAP = 262144

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
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


def clamp_year(dt):
    if dt > COLLECTED + timedelta(days=1):
        try:
            return dt.replace(year=dt.year - 1)
        except ValueError:
            return dt
    return dt


def dt_from(year, month, day, hh, mm, ss, micros=0):
    try:
        dt = datetime(int(year), int(month), int(day), int(hh), int(mm), int(ss), int(micros), timezone.utc)
    except ValueError:
        return None
    return clamp_year(dt)


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
    raw = f"{filename_wo}|{level}|{source}|{line_no}"
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).hexdigest()


def cvm_ip_from(path):
    match = IP_RE.search(path.replace("\\", "/"))
    if match:
        return match.group(0)
    anon = re.search(r"XX\.XX\.XX\.\d+", path)
    return anon.group(0) if anon else "0.0.0.0"


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
    stem = lower.split(".", 1)[0]
    return stem in {"messages", "dmesg", "secure", "audit", "minion", "command_collector"}


def parse_header(line):
    m = GLOG_RE.match(line)
    if m:
        date = m.group("date")
        hh, mm, ss, micros = parse_hms(m.group("time").split(".")[0], m.group("time").split(".")[1])
        if len(date) == 8:
            year, month, day = date[:4], date[4:6], date[6:8]
        else:
            year, month, day = COLLECTED.year, date[:2], date[2:]
        return {
            "event_time": dt_from(year, month, day, hh, mm, ss, micros),
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
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros),
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
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros),
            "log_level": level_char(m.group("level")),
            "source_log_filename": m.group("src"),
            "pid": int(m.group("pid") or 0),
            "line_number": int(m.group("line")),
            "thread": "",
            "tag": "python",
            "message": m.group("msg"),
        }
    m = ISO_SYSLOG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        stamp = dt_from(y, mo, d, hh, mm, ss, micros)
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
    m = SALT_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        micros = int((m.group("frac") + "000000")[:6])
        y, mo, d = m.group("date").split("-")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros),
            "log_level": "I",
            "source_log_filename": m.group("src"),
            "pid": 0,
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
    m = DMESG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        return {
            "event_time": dt_from(m.group("year"), MONTHS[m.group("mon")], m.group("day"), hh, mm, ss, 0),
            "log_level": "I",
            "source_log_filename": "dmesg",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "dmesg",
            "message": m.group("msg"),
        }
    m = SYSLOG_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        return {
            "event_time": dt_from(COLLECTED.year, MONTHS[m.group("mon")], m.group("day"), hh, mm, ss, 0),
            "log_level": "I",
            "source_log_filename": m.group("src").strip(),
            "pid": int(m.group("pid") or 0),
            "line_number": 0,
            "thread": "",
            "tag": "syslog",
            "message": m.group("msg"),
        }
    m = GO_RE.match(line)
    if m:
        hh, mm, ss, _ = parse_hms(m.group("time"), "0")
        y, mo, d = m.group("date").split("/")
        return {
            "event_time": dt_from(y, mo, d, hh, mm, ss, 0),
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
            "event_time": dt_from(y, mo, d, hh, mm, ss, micros),
            "log_level": "I",
            "source_log_filename": "",
            "pid": 0,
            "line_number": 0,
            "thread": "",
            "tag": "python",
            "message": m.group("msg"),
        }
    return None


class Writer:
    def __init__(self, path):
        self.path = path
        self.created = datetime.now(timezone.utc).replace(microsecond=0)
        self.buf = {name: [] for name in SCHEMA.names}
        self.rows = 0
        self.files = 0
        self.writer = pq.ParquetWriter(path, SCHEMA, compression="zstd")

    def add(self, rec, filename, cvm_ip):
        if rec["event_time"] is None:
            return
        base = filename.rsplit("/", 1)[-1]
        wo = base.split(".", 1)[0]
        level = rec["log_level"]
        source = rec["source_log_filename"]
        line_no = rec["line_number"]
        message = rec["message"][:MSG_CAP]
        ip = cvm_ip if IP_RE.fullmatch(cvm_ip or "") else "0.0.0.0"
        row = {
            "log_bundle_id": LOG_BUNDLE_ID,
            "event_time": rec["event_time"],
            "created_at": self.created,
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
        for key, value in row.items():
            self.buf[key].append(value)
        self.rows += 1
        if len(self.buf["log_bundle_id"]) >= BATCH:
            self.flush()

    def flush(self):
        if not self.buf["log_bundle_id"]:
            return
        self.writer.write_batch(pa.record_batch(self.buf, schema=SCHEMA))
        self.buf = {name: [] for name in SCHEMA.names}

    def close(self):
        self.flush()
        self.writer.close()


def iter_text_lines(raw):
    if b"\x00" in raw[:4096]:
        return
        yield  # pragma: no cover
    text = raw.decode("utf-8", "replace")
    for line in text.splitlines():
        yield line.rstrip("\r")


def consume(lines, member_name, writer):
    cvm = cvm_ip_from(member_name)
    current = None
    emitted = 0
    for line in lines:
        header = parse_header(line)
        if header:
            if current is not None:
                writer.add(current, member_name, cvm)
                emitted += 1
            current = header
            continue
        if current is not None and line:
            extra = "\n" + line
            room = MSG_CAP - len(current["message"])
            if room > 0:
                current["message"] += extra[:room]
    if current is not None:
        writer.add(current, member_name, cvm)
        emitted += 1
    if emitted:
        writer.files += 1
        print(f"{emitted:8}  {member_name}", flush=True)


def infer_bundle_id(tar_path):
    match = re.search(r"case-(\d+)", str(tar_path))
    if match:
        return int(match.group(1))
    parent = tar_path.parent.name
    if parent.isdigit():
        return int(parent)
    return 0


def infer_collected(tar_path):
    match = re.search(r"(\d{2})-(\d{2})-(\d{4})", tar_path.name)
    if not match:
        return datetime.now(timezone.utc)
    month, day, year = (int(part) for part in match.groups())
    return datetime(year, month, day, tzinfo=timezone.utc)


def run_logs(bundle, out, log_bundle_id, collected):
    global LOG_BUNDLE_ID, COLLECTED
    LOG_BUNDLE_ID = log_bundle_id
    COLLECTED = collected
    writer = Writer(out)
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name
            if name.endswith(".zip"):
                blob = archive.extractfile(member).read()
                with zipfile.ZipFile(io.BytesIO(blob)) as nested:
                    for info in nested.infolist():
                        if info.is_dir() or not want_member(info.filename):
                            continue
                        raw = nested.read(info)
                        consume(iter_text_lines(raw), info.filename, writer)
                continue
            if not want_member(name):
                continue
            raw = archive.extractfile(member).read()
            consume(iter_text_lines(raw), name, writer)
    writer.close()
    meta = pq.read_metadata(out)
    print(f"rows {meta.num_rows} files {writer.files} parquet {out} bytes {out.stat().st_size}")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Read an NCC tar.gz in place and write Panacea Parquet. "
        "The archive is not extracted."
    )
    parser.add_argument("tar", type=Path, help="path to the NCC .tar.gz")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="directory for the parquet files (default: the tar's directory)",
    )
    parser.add_argument(
        "--log-bundle-id",
        type=int,
        default=None,
        help="value stored in log_bundle_id (default: case-<id> in the path, else 0)",
    )
    parser.add_argument(
        "--collected",
        default=None,
        help="YYYY-MM-DD used when a log line has no year "
        "(default: the date in the tar name)",
    )
    parser.add_argument(
        "--schemas",
        choices=("all", "logs", "sar"),
        default="all",
        help="which Parquet files to write (default: logs and sar)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    bundle = args.tar.expanduser().resolve()
    if not bundle.is_file():
        sys.exit(f"missing bundle {bundle}")
    out_dir = (args.out_dir or bundle.parent).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log_bundle_id = args.log_bundle_id if args.log_bundle_id is not None else infer_bundle_id(bundle)
    if args.collected:
        collected = datetime.strptime(args.collected, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        collected = infer_collected(bundle)
    print(f"tar {bundle}")
    print(f"log_bundle_id {log_bundle_id} collected {collected.date()} out {out_dir}")
    if args.schemas in ("all", "logs"):
        run_logs(bundle, out_dir / "nu_logs_local.parquet", log_bundle_id, collected)
    if args.schemas in ("all", "sar"):
        from sar_to_parquet import run as run_sar
        run_sar(bundle, out_dir / "nu_metrics_sysstats.parquet", log_bundle_id)


if __name__ == "__main__":
    main()
