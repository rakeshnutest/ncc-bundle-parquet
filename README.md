# NCC bundle to Panacea Parquet

Read an NCC `.tar.gz` in place and write two Parquet files whose columns follow the Panacea ClickHouse tables. The archive is not extracted, and nothing is inserted into ClickHouse.

```bash
python3 -m pip install -r requirements.txt
python3 bundle_to_parquet.py /path/to/NCC-logs.tar.gz
python3 duckdb_search.py /path/to/the/parquet/directory
```

`requirements.txt` installs PyArrow, which writes the files, and DuckDB, which searches them. `duckdb_search.py` runs the log hour filter, the level count, the message word search, and the SAR metric filter. Its defaults are the case 2734579 queries below.

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

The code is split so the parsers do not each own a writer. `nccparquet/archive.py` walks the tar and nested zips in memory. `nccparquet/logs.py` and `nccparquet/sar.py` parse. `nccparquet/layout.py` writes the sorted files. `bundle_to_parquet.py` is the command.

## How filtering works

There is no separate search index. Each file is cut into blocks of 16,384 rows, and each block stores the smallest and largest value of its columns. DuckDB, or any other Parquet reader, skips a block when those two values cannot match the question.

Logs are ordered by the full filename (`messages.1`, then `messages.2`), then the CVM, then the time, then the level. One rotated file on one CVM sits in its own stretch of blocks, in time order. A question for that file, that CVM, and one hour opens only the blocks whose time range covers that hour. On this bundle that hour overlaps 6 of 273 log blocks.

SAR is ordered by the CVM, then the component, then the metric name, then the instance, then the time. All of one metric for one CVM is together. A question for `sar_rx_packets_per_sec` on one CVM overlaps 7 of 332 SAR blocks.

A search for a word inside `message` does not skip blocks. A block only records the first and last message in sorted order, which does not say whether a word appears in the middle. That search reads the message column.

## DuckDB search

`duckdb_search.py` runs these queries. DuckDB 1.5.6 read the two files directly. Nothing was loaded into a database, and ClickHouse was not used. Both structured filters finished in about 0.02 seconds. The word search took 0.33 seconds because it reads message text.

```bash
python3 duckdb_search.py /path/to/the/parquet/directory
```

Logs, one CVM, one file, one hour:

```sql
SELECT event_time, filename, log_level, source_log_filename, message
FROM read_parquet('nu_logs_local.parquet')
WHERE cvm_ip = '172.17.0.219'
  AND filename_without_ext = 'messages'
  AND event_time >= TIMESTAMPTZ '2026-10-14 08:00:00+00'
  AND event_time <  TIMESTAMPTZ '2026-10-14 09:00:00+00'
ORDER BY event_time;
```

This returned **6,645** rows, all level `I`, all from `messages.1`. The first lines are an iptables drop on `eth0` and `systemd` starting a root session. Adding `log_level = 'E'` returned **0** rows. That hour has no error lines in `messages`.

An error line does exist elsewhere. The latest one is in `logbayd.log.20261013-140728Z` on `172.17.0.220` at 2026-10-14 21:59:13 UTC, from `file_util.go`. Searching that file for the word `ERROR` returned **11** rows:

```sql
SELECT event_time, message
FROM read_parquet('nu_logs_local.parquet')
WHERE cvm_ip = '172.17.0.220'
  AND filename = 'logbayd.log.20261013-140728Z'
  AND contains(message, 'ERROR');
```

SAR, same CVM and hour, one metric:

```sql
SELECT event_timestamp, component_instance, value, unit
FROM read_parquet('nu_metrics_sysstats.parquet')
WHERE cvm_ip = '172.17.0.219'
  AND metric_name = 'sar_rx_packets_per_sec'
  AND event_timestamp >= TIMESTAMPTZ '2026-10-14 08:00:00+00'
  AND event_timestamp <  TIMESTAMPTZ '2026-10-14 09:00:00+00'
ORDER BY event_timestamp, component_instance;
```

This returned **24** samples across `eth0`, `eth1`, `eth2`, and `lo`. At 08:00, `eth0` was 1,381.71 packets/sec and `eth2` was 0.

## What one bundle measured

Diamond case `2734579`, alert `A130087`, collected 2026-10-14. Four CVM alert zips. ClickHouse was not loaded. The ClickHouse column is an estimate from the Panacea codecs (`ZSTD` on `message`, `Delta` on time, `Gorilla` on SAR `value`, plus the skip indexes).

| | Unpacked text | Parquet on disk | ClickHouse MergeTree, estimated |
|---|---:|---:|---:|
| Logs (4.47 million rows) | 766 MiB | 24.6 MiB | 26–30 MiB |
| SAR (5.43 million rows, 118 `sarNN` files) | 66 MiB | 15.0 MiB | 16–22 MiB |
| Both | 832 MiB | 39.6 MiB | 42–50 MiB |
| Source `.tar.gz` | | 83.6 MiB | |

Parquet is about 21 times smaller than the unpacked log and SAR text, and 44 MiB under the already-compressed tar. Dictionary pages on the log text and plain ZSTD on SAR values brought the pair down from 53.2 MiB to 39.6 MiB. ClickHouse would land in the same range for this bundle. The tar still holds about 230 MiB of unpacked files that these Parquet files do not include (`sar` binaries, `nodetool`, and other non-log members).

## How the compression was achieved

The compressor on every column is still ZSTD, at level 3. The drop from 53.2 MiB to 39.6 MiB comes from encoding each column before ZSTD runs, and from sorting so similar values sit next to each other.

Dictionary. A repeated value is stored once and each row keeps a small id. Log `message` and `log_hash` use this, along with the short names (`cvm_ip`, filename, `metric_name`, `log_level`). With the dictionary off, `message` grew from 18.7 MiB to 20.0 MiB and `log_hash` from 0.18 MiB to 0.39 MiB. With it on, `log_hash` is 0.17 MiB and `message` is 19.1 MiB.

Delta. A timestamp column stores the first value, then the gap to the next one. After the rows are sorted by time those gaps are small. Log `event_time` fell from 8.8 MiB to 2.4 MiB. SAR `event_timestamp` uses the same encoding. Writing that SAR column as plain numbers made it 4.5 MiB, so the delta encoding stayed.

Sort, then plain ZSTD, for the SAR numbers. `value` is a normal float column. Grouping one metric's samples together made neighboring numbers similar, and ZSTD compressed that run from 10.1 MiB to 6.9 MiB. The same sort put the repeated prefix of `unique_identifier` (`cvm|file|time|instance|metric`) on adjacent rows, and that column fell from 11.4 MiB to 5.6 MiB.

Byte-stream split was tried on `value` and removed. It splits each float into eight byte streams, which is the Parquet stand-in for ClickHouse Gorilla. These blocks hold several metrics at once, the scales jump, and `value` grew to 12.7 MiB. Plain ZSTD was smaller, so that is what the file uses.

## Parquet and ClickHouse in Panacea

Both layouts use the same column names, so a later load is `INSERT INTO panacea.nu_logs_local SELECT * FROM file('nu_logs_local.parquet', Parquet)` (and the same for `nu_metrics_sysstats`). The difference is what Panacea can do with the data after that.

### Parquet

Advantages

- One bundle becomes a pair of files. No ClickHouse cluster, disk quota, or ingest worker is required.
- The NCC tar stays packed. Useful when the bundle must not be exploded on disk.
- About 21 times smaller than the unpacked text that was parsed. Enough to keep a bundle next to the tar.
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
