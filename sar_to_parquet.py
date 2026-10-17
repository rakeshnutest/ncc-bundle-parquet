#!/usr/bin/env python3
"""Read sarNN text reports from the packed NCC archive into nu_metrics_sysstats Parquet."""

import argparse
import sys
from pathlib import Path

from nccparquet.archive import infer_bundle_id
from nccparquet.sar import run


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read sarNN reports from an NCC tar.gz into nu_metrics_sysstats Parquet."
    )
    parser.add_argument("tar", type=Path, help="path to the NCC .tar.gz")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--log-bundle-id", type=int, default=None)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    bundle = args.tar.expanduser().resolve()
    if not bundle.is_file():
        sys.exit(f"missing bundle {bundle}")
    out_dir = (args.out_dir or bundle.parent).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log_bundle_id = args.log_bundle_id if args.log_bundle_id is not None else infer_bundle_id(bundle)
    run(bundle, out_dir / "nu_metrics_sysstats.parquet", log_bundle_id)


if __name__ == "__main__":
    main()
