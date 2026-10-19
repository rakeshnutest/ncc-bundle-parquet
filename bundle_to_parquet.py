#!/usr/bin/env python3
"""Read an NCC tar.gz in place and write Panacea Parquet files.

    python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz
    python3 bundle_to_parquet.py --tar-list tars.txt --out-dir /tmp/out
    python3 bundle_to_parquet.py /path/to/another.tar.gz --out-dir /tmp/out

Does not extract the archive or any nested zip onto disk.
nu_logs_local follows the Panacea log columns. nu_metrics_sysstats follows
the Panacea sysstats columns and is written from the sarNN reports.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from nccparquet.archive import infer_bundle_id, infer_collected, read_tar_paths
from nccparquet.bundle_meta import load as load_meta
from nccparquet.bundle_meta import pending, record
from nccparquet.diamond import upload as upload_diamond
from nccparquet.logs import run_logs
from nccparquet.parallel import job_count
from nccparquet.sar import run as run_sar


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Read one or more NCC tar.gz files in place and write Panacea Parquet. "
        "The archives are not extracted. A line already ingested from an earlier "
        "tar is skipped."
    )
    parser.add_argument("tar", nargs="*", type=Path, help="NCC .tar.gz files from the same case")
    parser.add_argument(
        "--tar-list",
        type=Path,
        default=None,
        help="text file with one tar path per line; combined with any tar arguments",
    )
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
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="files to parse at once (default: one per CPU)",
    )
    parser.add_argument(
        "--diamond",
        action="store_true",
        help="after the local write, copy the parquet files to Diamond "
        "(off by default; /users/<user>/shared/ncc-bundle-parquet/<id>/)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    listed = read_tar_paths(args.tar_list) if args.tar_list else []
    bundles = [path.expanduser().resolve() for path in [*args.tar, *listed]]
    if not bundles:
        sys.exit("pass tar paths or --tar-list")
    for bundle in bundles:
        if not bundle.is_file():
            sys.exit(f"missing bundle {bundle}")
    out_dir = (args.out_dir or bundles[0].parent).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log_bundle_id = args.log_bundle_id if args.log_bundle_id is not None else infer_bundle_id(bundles[0])
    if args.collected:
        collected = datetime.strptime(args.collected, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        collected = {bundle: infer_collected(bundle) for bundle in bundles}
    print(f"tars {len(bundles)}")
    for bundle in bundles:
        when = collected if isinstance(collected, datetime) else collected[bundle]
        print(f"tar {bundle} collected {when.date()}")
    jobs = job_count(args.jobs)
    print(f"log_bundle_id {log_bundle_id} out {out_dir} jobs {jobs}")
    records = load_meta(out_dir)
    if args.schemas in ("all", "logs"):
        todo = pending(records, bundles, "logs")
        if todo:
            paths = [bundle for bundle, _ident in todo]
            run_logs(paths, out_dir / "nu_logs_local.parquet", log_bundle_id, collected, jobs)
            for _bundle, ident in todo:
                records = record(out_dir, records, ident, "logs", log_bundle_id)
    if args.schemas in ("all", "sar"):
        todo = pending(records, bundles, "sar")
        if todo:
            paths = [bundle for bundle, _ident in todo]
            run_sar(paths, out_dir / "nu_metrics_sysstats.parquet", log_bundle_id, jobs)
            for _bundle, ident in todo:
                records = record(out_dir, records, ident, "sar", log_bundle_id)
    if args.diamond:
        upload_diamond(out_dir, log_bundle_id)


if __name__ == "__main__":
    main()
