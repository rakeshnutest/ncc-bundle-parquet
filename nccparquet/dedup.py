"""Drop a log or SAR row that was already written in this run.

The check happens before the row is stored. The same line is skipped
whether the second copy is later in the same tar or in another tar:
same node, same file stem, same timestamp, same text. SAR uses the
sample identity (node, sar file, timestamp, instance, metric).
"""

import hashlib


class IngestSeen:
    def __init__(self):
        self.done = set()
        self.batch = set()
        self.skipped = 0

    def accept(self, key):
        if key in self.done or key in self.batch:
            self.skipped += 1
            return False
        self.batch.add(key)
        return True

    def finish_bundle(self):
        self.done.update(self.batch)
        self.batch.clear()


def digest(*parts):
    raw = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).digest()


def log_key(cvm, filename_stem, event_time, level, pid, source, message):
    # Match the millisecond timestamp stored in Parquet, so a later append
    # recognizes a line that is already in the file.
    event_time = event_time.replace(microsecond=(event_time.microsecond // 1000) * 1000)
    return digest(
        cvm,
        filename_stem,
        event_time.isoformat(),
        level,
        int(pid),
        source,
        message,
    )


def sar_key(unique_identifier):
    return digest(unique_identifier)
