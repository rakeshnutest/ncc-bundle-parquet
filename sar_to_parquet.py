#!/usr/bin/env python3
"""Read sarNN text reports from the packed NCC archive into nu_metrics_sysstats Parquet."""

import argparse
import sys
from pathlib import Path

from nccparquet.archive import infer_bundle_id, read_tar_paths
from nccparquet.parallel import job_count
from nccparquet.sar import run


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read sarNN reports from an NCC tar.gz into nu_metrics_sysstats Parquet."
    )
    parser.add_argument("tar", nargs="*", type=Path, help="NCC .tar.gz files from the same case")
    parser.add_argument("--tar-list", type=Path, default=None, help="text file with one tar path per line")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--log-bundle-id", type=int, default=None)
    parser.add_argument("--jobs", type=int, default=0, help="files to parse at once (default: one per CPU)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
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
    run(bundles, out_dir / "nu_metrics_sysstats.parquet", log_bundle_id, job_count(args.jobs))


if __name__ == "__main__":
    main()
