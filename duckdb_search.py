#!/usr/bin/env python3
"""Search the Panacea Parquet files with DuckDB.

Nothing is loaded into a database. ClickHouse is not used.

    python3 -m pip install -r requirements.txt
    python3 duckdb_search.py /path/to/parquet-dir
"""

import argparse
import sys
import time
from pathlib import Path

import duckdb


def timed(con, sql, params=()):
    started = time.perf_counter()
    rows = con.execute(sql, params).fetchall()
    return rows, time.perf_counter() - started


def main(argv=None):
    parser = argparse.ArgumentParser(description="Query nu_logs_local and nu_metrics_sysstats Parquet with DuckDB.")
    parser.add_argument("parquet_dir", type=Path, help="directory that holds the two Parquet files")
    parser.add_argument("--cvm", default="172.17.0.219")
    parser.add_argument("--filename", default="messages", help="filename_without_ext for the log filter")
    parser.add_argument("--start", default="2026-10-14 08:00:00+00")
    parser.add_argument("--end", default="2026-10-14 09:00:00+00")
    parser.add_argument("--level", default="E", help="log level counted inside the same hour")
    parser.add_argument("--metric", default="sar_rx_packets_per_sec")
    parser.add_argument("--word", default="ERROR")
    parser.add_argument("--word-cvm", default="172.17.0.220")
    parser.add_argument("--word-file", default="logbayd.log.20261013-140728Z", help="full filename for the word search")
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args(argv)

    directory = args.parquet_dir.expanduser().resolve()
    logs = directory / "nu_logs_local.parquet"
    sar = directory / "nu_metrics_sysstats.parquet"
    for path in (logs, sar):
        if not path.is_file():
            sys.exit(f"missing {path}")

    con = duckdb.connect()
    print(f"duckdb {duckdb.__version__}")
    print(f"logs {logs}")
    print(f"sar  {sar}")

    rows, seconds = timed(
        con,
        """
        SELECT count(*)
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND filename_without_ext = ?
          AND event_time >= ?::TIMESTAMPTZ
          AND event_time <  ?::TIMESTAMPTZ
        """,
        (str(logs), args.cvm, args.filename, args.start, args.end),
    )
    print(f"\nlogs {args.cvm} {args.filename} {args.start} .. {args.end}: {rows[0][0]} rows in {seconds:.3f}s")
    sample, _ = timed(
        con,
        """
        SELECT event_time, filename, log_level, source_log_filename, left(replace(message, chr(10), ' '), 110)
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND filename_without_ext = ?
          AND event_time >= ?::TIMESTAMPTZ
          AND event_time <  ?::TIMESTAMPTZ
        ORDER BY event_time
        LIMIT ?
        """,
        (str(logs), args.cvm, args.filename, args.start, args.end, args.limit),
    )
    for row in sample:
        print(" ", row)

    rows, seconds = timed(
        con,
        """
        SELECT count(*)
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND filename_without_ext = ?
          AND event_time >= ?::TIMESTAMPTZ
          AND event_time <  ?::TIMESTAMPTZ
          AND log_level = ?
        """,
        (str(logs), args.cvm, args.filename, args.start, args.end, args.level),
    )
    print(f"level {args.level} in that window: {rows[0][0]} rows in {seconds:.3f}s")

    rows, seconds = timed(
        con,
        """
        SELECT count(*)
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND filename = ?
          AND contains(message, ?)
        """,
        (str(logs), args.word_cvm, args.word_file, args.word),
    )
    print(f"\nmessage contains {args.word!r} in {args.word_file} on {args.word_cvm}: {rows[0][0]} rows in {seconds:.3f}s")

    rows, seconds = timed(
        con,
        """
        SELECT count(*), min(value), max(value)
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND metric_name = ?
          AND event_timestamp >= ?::TIMESTAMPTZ
          AND event_timestamp <  ?::TIMESTAMPTZ
        """,
        (str(sar), args.cvm, args.metric, args.start, args.end),
    )
    count, low, high = rows[0]
    print(f"\nsar {args.metric} {args.cvm}: {count} rows min {low} max {high} in {seconds:.3f}s")
    sample, _ = timed(
        con,
        """
        SELECT event_timestamp, component_instance, value, unit
        FROM read_parquet(?)
        WHERE cvm_ip = ?
          AND metric_name = ?
          AND event_timestamp >= ?::TIMESTAMPTZ
          AND event_timestamp <  ?::TIMESTAMPTZ
        ORDER BY event_timestamp, component_instance
        LIMIT ?
        """,
        (str(sar), args.cvm, args.metric, args.start, args.end, args.limit),
    )
    for row in sample:
        print(" ", row)


if __name__ == "__main__":
    main()
