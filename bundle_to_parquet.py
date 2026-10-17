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
import sys
from datetime import datetime, timezone
from pathlib import Path

from nccparquet.archive import infer_bundle_id, infer_collected
from nccparquet.logs import run_logs
from nccparquet.sar import run as run_sar


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
        run_sar(bundle, out_dir / "nu_metrics_sysstats.parquet", log_bundle_id)


if __name__ == "__main__":
    main()
