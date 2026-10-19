"""Stream rows, then rewrite Parquet sorted like the Panacea order key.

The rewrite sorts rows so a filter can skip row groups, and picks the
encoding that was smaller on this data. Log messages and hashes use dictionary pages. Log timestamps and SAR
timestamps use delta encoding. SAR values stay plain ZSTD. Row groups
are 16384 rows, and each log group is one rotated file.
"""

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

ROW_GROUP_ROWS = 16384
BATCH_ROWS = 65536

LOG_SORT = [
    ("filename", "ascending"),
    ("cvm_ip", "ascending"),
    ("event_time", "ascending"),
    ("log_level", "ascending"),
]
LOG_DICTIONARY = [
    "message",
    "log_hash",
    "log_level",
    "source_log_filename",
    "filename",
    "filename_without_ext",
    "cvm_ip",
    "anomaly_category",
    "component",
    "db_server",
    "error_code",
    "ip",
    "log_version",
    "operation_id",
    "tenant_id",
    "tag",
    "thread",
]
LOG_ENCODING = {
    "event_time": "DELTA_BINARY_PACKED",
    "created_at": "DELTA_BINARY_PACKED",
    "pid": "DELTA_BINARY_PACKED",
    "line_number": "DELTA_BINARY_PACKED",
    "log_bundle_id": "DELTA_BINARY_PACKED",
    "anomaly": "DELTA_BINARY_PACKED",
}

METRIC_SORT = [
    ("cvm_ip", "ascending"),
    ("component", "ascending"),
    ("metric_name", "ascending"),
    ("component_instance", "ascending"),
    ("event_timestamp", "ascending"),
]
METRIC_DICTIONARY = [
    "cvm_ip",
    "component",
    "metric_name",
    "component_instance",
    "unit",
    "tags",
    "source_file",
]
METRIC_ENCODING = {
    "log_bundle_id": "DELTA_BINARY_PACKED",
    "event_timestamp": "DELTA_BINARY_PACKED",
    "batch_id": "DELTA_BINARY_PACKED",
    "created_at": "DELTA_BINARY_PACKED",
}


class ColumnWriter:
    def __init__(self, path, schema):
        self.path = Path(path)
        self.schema = schema
        self.buf = {name: [] for name in schema.names}
        self.rows = 0
        self.files = 0
        self._writer = pq.ParquetWriter(self.path, schema, compression="zstd")

    def add_row(self, row):
        names = self.schema.names
        buf = self.buf
        for name in names:
            buf[name].append(row[name])
        self.rows += 1
        if len(buf[names[0]]) >= BATCH_ROWS:
            self.flush()

    def flush(self):
        names = self.schema.names
        if not self.buf[names[0]]:
            return
        self._writer.write_batch(pa.record_batch(self.buf, schema=self.schema))
        self.buf = {name: [] for name in names}

    def close(self):
        self.flush()
        self._writer.close()


def write_sorted(table, path, sort_keys, dictionary_columns, column_encoding):
    path = Path(path)
    if table.num_rows:
        table = table.sort_by(sort_keys)
    tmp = path.with_suffix(".sorting.parquet")
    pq.write_table(
        table,
        tmp,
        compression="zstd",
        compression_level=3,
        row_group_size=ROW_GROUP_ROWS,
        use_dictionary=dictionary_columns,
        column_encoding=column_encoding,
        write_statistics=True,
        write_page_index=True,
        data_page_size=1024 * 1024,
    )
    tmp.replace(path)
    return pq.read_metadata(path)


def rewrite_sorted(path, sort_keys, dictionary_columns, column_encoding):
    path = Path(path)
    return write_sorted(pq.read_table(path), path, sort_keys, dictionary_columns, column_encoding)
