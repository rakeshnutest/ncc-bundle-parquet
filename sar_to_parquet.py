#!/usr/bin/env python3
"""Read sarNN text reports from the packed NCC archive into nu_metrics_sysstats Parquet.

Does not extract the tar or the nested zips onto disk.
Column layout follows panacea.nu_metrics_sysstats (physical columns only).
Network counters use the Panacea sar_* metric names. CPU, memory, disk,
load, paging, and task sections use the same table with their own metric names.
"""

import argparse
import io
import json
import re
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

LOG_BUNDLE_ID = 0
BATCH = 50000
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
LINUX_RE = re.compile(
    r"^Linux\s+.+\((?P<host>[^)]+)\)\s+(?P<date>\d{4}-\d{2}-\d{2})"
)
SAR_NAME = re.compile(r"sar\d+$")

# Panacea sar_parser names for the DEV / EDEV tables.
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


def cvm_ip_from(path):
    match = IP_RE.search(path)
    return match.group(0) if match else "0.0.0.0"


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
        return "cpu", "cpu", metrics, True
    if cols[0] == "IFACE" and "rxpck/s" in cols:
        return "network", "iface", cols[1:], True
    if cols[0] == "IFACE" and ("rxerr/s" in cols or "rxdrop/s" in cols):
        return "network", "iface", cols[1:], True
    if cols[0] == "DEV" and "tps" in cols:
        return "disk", "dev", cols[1:], True
    if "kbmemfree" in low or "kbmemused" in low:
        return "memory", "host", cols, False
    if "runq-sz" in low or "ldavg-1" in low:
        return "load", "host", cols, False
    if "proc/s" in low and "cswch/s" in low:
        return "task", "host", cols, False
    if "pgpgin/s" in low:
        return "paging", "host", cols, False
    if low[0] == "tps":
        return "io", "host", cols, False
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


class Writer:
    def __init__(self, path):
        self.created = datetime.now(timezone.utc).replace(microsecond=0)
        self.buf = {name: [] for name in SCHEMA.names}
        self.rows = 0
        self.files = 0
        self.writer = pq.ParquetWriter(path, SCHEMA, compression="zstd")

    def add(self, **row):
        row["created_at"] = self.created
        row["batch_id"] = 0
        row["log_bundle_id"] = LOG_BUNDLE_ID
        for key in SCHEMA.names:
            self.buf[key].append(row[key])
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


def ingest_text(text, member_name, cvm_ip, writer):
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
        component, _key, columns, has_instance = section
        if has_instance:
            if len(rest) < 2:
                continue
            instance, values = rest[0], rest[1:]
        else:
            instance, values = "host", rest
        stamp = datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=timezone.utc)
        for column, raw_value in zip(columns, values):
            if not is_float(raw_value):
                continue
            explicit = PANACEA_NET.get(column)
            if explicit and component == "network":
                metric_name, unit = explicit
            else:
                metric_name, unit = norm_metric(column), unit_of(column, "")
            if component == "network":
                tags = json.dumps({"interface": instance})
            elif component == "cpu":
                tags = json.dumps({"cpu": instance})
            elif component == "disk":
                tags = json.dumps({"device": instance})
            else:
                tags = "{}"
            writer.add(
                cvm_ip=cvm_ip,
                event_timestamp=stamp,
                component=component,
                metric_name=metric_name,
                component_instance=instance,
                value=float(raw_value),
                unit=unit,
                tags=tags,
                source_file=source,
                unique_identifier=f"{cvm_ip}|{source}|{stamp.isoformat()}|{instance}|{metric_name}",
            )
            emitted += 1
    if emitted:
        writer.files += 1
        print(f"{emitted:8}  {member_name}", flush=True)


def run(bundle, out, log_bundle_id):
    global LOG_BUNDLE_ID
    LOG_BUNDLE_ID = log_bundle_id
    writer = Writer(out)
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith(".zip"):
                continue
            blob = archive.extractfile(member).read()
            with zipfile.ZipFile(io.BytesIO(blob)) as nested:
                for info in nested.infolist():
                    base = info.filename.rsplit("/", 1)[-1]
                    if info.is_dir() or not SAR_NAME.match(base):
                        continue
                    raw = nested.read(info)
                    if b"\x00" in raw[:512] or not raw.startswith(b"Linux "):
                        print(f"skip non-text {info.filename}", flush=True)
                        continue
                    ingest_text(
                        raw.decode("utf-8", "replace"),
                        info.filename,
                        cvm_ip_from(info.filename),
                        writer,
                    )
    writer.close()
    meta = pq.read_metadata(out)
    print(
        f"rows {meta.num_rows} files {writer.files} "
        f"parquet {out} bytes {out.stat().st_size}"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read sarNN reports from an NCC tar.gz into nu_metrics_sysstats Parquet."
    )
    parser.add_argument("tar", type=Path, help="path to the NCC .tar.gz")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--log-bundle-id", type=int, default=0)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    bundle = args.tar.expanduser().resolve()
    if not bundle.is_file():
        sys.exit(f"missing bundle {bundle}")
    out_dir = (args.out_dir or bundle.parent).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run(bundle, out_dir / "nu_metrics_sysstats.parquet", args.log_bundle_id)


if __name__ == "__main__":
    main()
