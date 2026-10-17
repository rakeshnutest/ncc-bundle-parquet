# NCC bundle to Panacea Parquet

Read an NCC `.tar.gz` in place and write two Parquet files whose columns follow the Panacea ClickHouse tables. The archive is not extracted, and nothing is inserted into ClickHouse.

```bash
python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz
```

| Output | Panacea table | Contents |
|---|---|---|
| `nu_logs_local.parquet` | `panacea.nu_logs_local` | Parsed log lines |
| `nu_metrics_sysstats.parquet` | `panacea.nu_metrics_sysstats` | `sarNN` counters |

`log_bundle_id` comes from a `case-<id>` directory in the path. The collection date comes from the tar name (`NCC-logs-MM-DD-YYYY-...`).

```bash
python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz \
  --out-dir /tmp/out \
  --log-bundle-id 2734579 \
  --collected 2026-10-14 \
  --schemas all
```

`--schemas` is `all` (default), `logs`, or `sar`.

## Layout

Each file is rewritten once after parsing. Rows are stored in groups of 16,384 with a page index. Repeated text, including the log `message` and `log_hash`, uses dictionary pages. Timestamps use delta encoding. The SAR `value` column stays plain ZSTD.

| File | Sort key |
|---|---|
| `nu_logs_local.parquet` | `filename`, `cvm_ip`, `event_time`, `log_level` |
| `nu_metrics_sysstats.parquet` | `cvm_ip`, `component`, `metric_name`, `component_instance`, `event_timestamp` |

A filter on those columns skips row groups whose min/max cannot match. `cvm_ip` is in the log sort as well as the metrics sort, because a single bundle is one `log_bundle_id` and the useful cut is file, then CVM, then time. A word inside `message` still reads that column; Parquet stats do not describe tokens.

The code is split so the parsers do not each own a writer. `nccparquet/archive.py` walks the tar and nested zips in memory. `nccparquet/logs.py` and `nccparquet/sar.py` parse. `nccparquet/layout.py` writes the sorted files. `bundle_to_parquet.py` is the command.

## What one bundle measured

Diamond case `2734579`, alert `A130087`, collected 2026-10-14. Four CVM alert zips. ClickHouse was not loaded. The ClickHouse column is an estimate from the Panacea codecs (`ZSTD` on `message`, `Delta` on time, `Gorilla` on SAR `value`, plus the skip indexes).

| | Unpacked text | Parquet on disk | ClickHouse MergeTree, estimated |
|---|---:|---:|---:|
| Logs (4.47 million rows) | 766 MiB | 24.6 MiB | 26–30 MiB |
| SAR (5.43 million rows, 118 `sarNN` files) | 66 MiB | 15.0 MiB | 16–22 MiB |
| Both | 832 MiB | 39.6 MiB | 42–50 MiB |
| Source `.tar.gz` | | 83.6 MiB | |

Parquet is about 21 times smaller than the unpacked log and SAR text, and 44 MiB under the already-compressed tar. Dictionary pages on the log text and plain ZSTD on SAR values brought the pair down from 53.2 MiB to 39.6 MiB. ClickHouse would land in the same range for this bundle. The tar still holds about 230 MiB of unpacked files that these Parquet files do not include (`sar` binaries, `nodetool`, and other non-log members).

## Parquet and ClickHouse in Panacea

Both layouts use the same column names, so a later load is `INSERT INTO panacea.nu_logs_local SELECT * FROM file('nu_logs_local.parquet', Parquet)` (and the same for `nu_metrics_sysstats`). The difference is what Panacea can do with the data after that.

### Parquet

Advantages

- One bundle becomes a pair of files. No ClickHouse cluster, disk quota, or ingest worker is required.
- The NCC tar stays packed. Useful when the bundle must not be exploded on disk.
- About 16x smaller than the unpacked text that was parsed. Enough to keep a bundle next to the tar.
- Portable. PyArrow, DuckDB, or `clickhouse-local` can query the files without the Panacea service.
- No 30-day TTL. The file lasts as long as you keep it.
- Safe against the production Panacea ClickHouse: this tool never connects to it.

Disadvantages

- Panacea's product path does not read these files. Log explorer, known-issue rules, anomaly detection, and the AI report query `panacea.nu_logs_local` and `panacea.nu_metrics_sysstats` in ClickHouse.
- No skip indexes. A `message` search reads the whole 19 MiB message column. ClickHouse keeps a token bloom (`tokenbf_v1`) on `message`, blooms on `cvm_ip` and filename, and a set index on `log_level`, so those filters skip granules.
- No `proj_time_aggregation`. Hourly counts by file and level are a scan plus `GROUP BY`, not a projection.
- No `nu_metrics_sysstats_1min` or `nu_metrics_sysstats_hourly` views. Those are ClickHouse materialized views over the metrics table.
- Dictionary pages and delta timestamps are as close as Parquet gets to `LowCardinality` and `Delta`. SAR `value` stays plain ZSTD. There is still no token bloom on `message`.
- One file per bundle. Cross-bundle questions (same alert on many cases, known-issue history) need an extra union. ClickHouse stores every bundle in one table ordered by `(log_bundle_id, filename_without_ext, event_time, log_level)`.
- Replacing a bundle means rewriting the Parquet file. ClickHouse drops a bundle with a mutation on `log_bundle_id`.

### ClickHouse, as Panacea runs it

Advantages

- It is the table the rest of Panacea already queries. A bundle in `nu_logs_local` shows up in log explorer, metrics explorer, anomaly jobs, and known-issue rules.
- The sort key matches the usual filter: one bundle, one file, a time range, a level.
- Secondary indexes skip most granules for token search, CVM IP, and log level. That matters once many bundles share the cluster, more than it matters for a single 25 MiB file.
- `Delta` on timestamps is what this writer uses too. `Gorilla` on `value` is the piece Parquet does not match; plain ZSTD was smaller on these SAR numbers. The skip indexes and the materialized views are the other part Parquet does not carry.
- Materialized views keep 1-minute and hourly metric aggregates. The base table is not scanned for those dashboards.
- Many bundles live in one database, with `nu_metadata` beside them (`remote_log_bundle_path`, case number, cluster UUID).

Disadvantages

- A service, disks, and the ingest pipeline have to be up. A single oncall bundle does not need that if the question is local.
- Panacea's TTL is `created_at + 30 days` on both tables. The bundle disappears from ClickHouse even when the tar is still on Diamond.
- Space is not the reason to load this bundle. The estimated MergeTree size is 42–50 MiB against 39.6 MiB of Parquet. The win is indexes and the existing Panacea readers.
- Ingest is heavier than writing a file: date filters, partition limits, and the 30-day TTL all drop or rewrite rows on the way in.
- The production cluster is shared. Loading or deleting a bundle there affects everyone else's queries. These Parquet files stay on the machine that built them.

### When to use which

Use Parquet to keep a local, durable copy of one bundle's logs and SAR, or to try the Panacea column layout without a cluster. Use ClickHouse when the bundle should join the Panacea report, log search, metric anomaly, and known-issue path, or when the question spans many bundles.
