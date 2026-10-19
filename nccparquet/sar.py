"""Parse sarNN text reports into nu_metrics_sysstats Parquet."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from nccparquet.archive import cvm_ip_from, iter_members
from nccparquet.dedup import IngestSeen, sar_key
from nccparquet.layout import (
    METRIC_DICTIONARY,
    METRIC_ENCODING,
    METRIC_SORT,
    ColumnWriter,
    write_sorted,
)
from nccparquet.parallel import map_unordered

LINUX_RE = re.compile(r"^Linux\s+.+\((?P<host>[^)]+)\)\s+(?P<date>\d{4}-\d{2}-\d{2})")
SAR_NAME = re.compile(r"sar\d+$")

PANACEA_NET = {
    "rxpck/s": ("sar_rx_packets_per_sec", "packets/sec"),
    "txpck/s": ("sar_tx_packets_per_sec", "packets/sec"),
    "rxkb/s": ("sar_rx_kb_per_sec", "KB/sec"),
    "rxkB/s": ("sar_rx_kb_per_sec", "KB/sec"),
    "txkb/s": ("sar_tx_kb_per_sec", "KB/sec"),
    "txkB/s": ("sar_tx_kb_per_sec", "KB/sec"),
    "%ifutil": ("sar_ifutil_pct", "percent"),
    "rxerr/s": ("sar_rx_errors_per_sec", "errors/sec"),
    "txerr/s": ("sar_tx_errors_per_sec", "errors/sec"),
    "coll/s": ("sar_collisions_per_sec", "collisions/sec"),
    "rxdrop/s": ("sar_rx_drops_per_sec", "drops/sec"),
    "txdrop/s": ("sar_tx_drops_per_sec", "drops/sec"),
}

SCHEMA = pa.schema(
    [
        ("log_bundle_id", pa.uint64()),
        ("cvm_ip", pa.string()),
        ("event_timestamp", pa.timestamp("ms", tz="UTC")),
        ("component", pa.string()),
        ("metric_name", pa.string()),
        ("component_instance", pa.string()),
        ("value", pa.float64()),
        ("unit", pa.string()),
        ("tags", pa.string()),
        ("source_file", pa.string()),
        ("unique_identifier", pa.string()),
        ("batch_id", pa.uint64()),
        ("created_at", pa.timestamp("s", tz="UTC")),
    ]
)


def is_float(token):
    try:
        float(token)
        return True
    except ValueError:
        return False


def norm_metric(column):
    name = (
        column.replace("%", "pct_")
        .replace("/", "_")
        .replace("-", "_")
        .replace(".", "_")
    )
    return "sar_" + name


def unit_of(column, explicit):
    if explicit:
        return explicit
    if column.startswith("%"):
        return "percent"
    if column.endswith("/s"):
        return "per_sec"
    return ""


def classify(cols):
    low = [c.lower() for c in cols]
    if not cols:
        return None
    if cols[0] == "CPU" and ("%usr" in cols or "%user" in cols):
        metrics = []
        for col in cols[1:]:
            if col == "%user":
                metrics.append("%usr")
            elif col == "%system":
                metrics.append("%sys")
            else:
                metrics.append(col)
        return "cpu", metrics, True
    if cols[0] == "IFACE" and "rxpck/s" in cols:
        return "network", cols[1:], True
    if cols[0] == "IFACE" and ("rxerr/s" in cols or "rxdrop/s" in cols):
        return "network", cols[1:], True
    if cols[0] == "DEV" and "tps" in cols:
        return "disk", cols[1:], True
    if "kbmemfree" in low or "kbmemused" in low:
        return "memory", cols, False
    if "runq-sz" in low or "ldavg-1" in low:
        return "load", cols, False
    if "proc/s" in low and "cswch/s" in low:
        return "task", cols, False
    if "pgpgin/s" in low:
        return "paging", cols, False
    if low[0] == "tps":
        return "io", cols, False
    return None


def clock(token, ampm):
    hh, mm, ss = (int(part) for part in token.split(":"))
    if ampm == "AM":
        if hh == 12:
            hh = 0
    elif ampm == "PM" and hh != 12:
        hh += 12
    return hh, mm, ss


def parse_time(parts):
    if len(parts) < 3 or parts[1].upper() not in ("AM", "PM"):
        return None
    if parts[0].count(":") != 2:
        return None
    try:
        hh, mm, ss = clock(parts[0], parts[1].upper())
    except ValueError:
        return None
    return (hh, mm, ss), parts[2:]


def tags_for(component, instance, cache):
    key = (component, instance)
    cached = cache.get(key)
    if cached is not None:
        return cached
    if component == "network":
        cached = json.dumps({"interface": instance})
    elif component == "cpu":
        cached = json.dumps({"cpu": instance})
    elif component == "disk":
        cached = json.dumps({"device": instance})
    else:
        cached = "{}"
    cache[key] = cached
    return cached


def ingest_text(text, member_name, cvm_ip, writer, log_bundle_id, created, tag_cache, seen):
    source = member_name.rsplit("/", 1)[-1]
    day = None
    section = None
    emitted = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Average:"):
            continue
        linux = LINUX_RE.match(line)
        if linux:
            day = datetime.strptime(linux.group("date"), "%Y-%m-%d").date()
            section = None
            continue
        parsed = parse_time(line.split())
        if parsed is None or day is None:
            continue
        (hh, mm, ss), rest = parsed
        if not rest:
            continue
        header = classify(rest)
        if header is not None and not is_float(rest[-1]):
            section = header
            continue
        if section is None:
            continue
        component, columns, has_instance = section
        if has_instance:
            if len(rest) < 2:
                continue
            instance, values = rest[0], rest[1:]
        else:
            instance, values = "host", rest
        stamp = datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=timezone.utc)
        stamp_iso = stamp.isoformat()
        tags = tags_for(component, instance, tag_cache)
        for column, raw_value in zip(columns, values):
            if not is_float(raw_value):
                continue
            explicit = PANACEA_NET.get(column) if component == "network" else None
            if explicit:
                metric_name, unit = explicit
            else:
                metric_name, unit = norm_metric(column), unit_of(column, "")
            unique_identifier = f"{cvm_ip}|{source}|{stamp_iso}|{instance}|{metric_name}"
            if not seen.accept(sar_key(unique_identifier)):
                continue
            writer.add_row(
                {
                    "log_bundle_id": log_bundle_id,
                    "cvm_ip": cvm_ip,
                    "event_timestamp": stamp,
                    "component": component,
                    "metric_name": metric_name,
                    "component_instance": instance,
                    "value": float(raw_value),
                    "unit": unit,
                    "tags": tags,
                    "source_file": source,
                    "unique_identifier": unique_identifier,
                    "batch_id": 0,
                    "created_at": created,
                }
            )
            emitted += 1
    if emitted:
        writer.files += 1


def _existing_sar(path, seen):
    path = Path(path)
    if not path.is_file():
        return None
    table = pq.read_table(path)
    for item in table.column("unique_identifier").to_pylist():
        seen.done.add(sar_key(item))
    print(f"existing sar {table.num_rows}")
    return table


def parse_sar_member(name, raw, log_bundle_id, created):
    """Parse one sarNN report. Safe to run in a worker process."""
    if b"\x00" in raw[:512] or not raw.startswith(b"Linux "):
        return name, [], 0, 0, True
    rows = []

    class _Rows:
        def __init__(self):
            self.files = 0

        def add_row(self, row):
            rows.append(row)

    seen = IngestSeen()
    writer = _Rows()
    ingest_text(
        raw.decode("utf-8", "replace"),
        name,
        cvm_ip_from(name),
        writer,
        log_bundle_id,
        created,
        {},
        seen,
    )
    return name, rows, seen.skipped, writer.files, False


def _sar_members(bundles):
    for bundle in bundles:
        for name, raw in iter_members(bundle):
            base = name.rsplit("/", 1)[-1]
            if SAR_NAME.match(base):
                yield name, raw


def run(bundles, out, log_bundle_id, jobs=1):
    if isinstance(bundles, (str, bytes)) or not isinstance(bundles, (list, tuple)):
        bundles = [bundles]
    out = Path(out)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    seen = IngestSeen()
    existing = _existing_sar(out, seen)
    incoming = out.with_suffix(".incoming.parquet")
    writer = ColumnWriter(incoming, SCHEMA)

    def on_result(result):
        name, rows, skipped, files, binary = result
        if binary:
            print(f"skip non-text {name}", flush=True)
            return
        seen.skipped += skipped
        kept = 0
        for row in rows:
            if not seen.accept(sar_key(row["unique_identifier"])):
                continue
            writer.add_row(row)
            kept += 1
        if files:
            writer.files += files
            print(f"{kept:8}  {name}", flush=True)

    map_unordered(
        jobs,
        ((name, raw, log_bundle_id, created) for name, raw in _sar_members(bundles)),
        parse_sar_member,
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
    meta = write_sorted(table, out, METRIC_SORT, METRIC_DICTIONARY, METRIC_ENCODING)
    print(
        f"rows {meta.num_rows} files {writer.files} added {added.num_rows} "
        f"skipped_duplicates {seen.skipped} parquet {out} bytes {out.stat().st_size}"
    )
    return meta.num_rows
