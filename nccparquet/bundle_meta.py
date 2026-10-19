"""Remember which tar files were ingested so a second run skips them.

The record sits next to the Parquet files as ingested_bundles.json.
Identity is the sha256 of the tar, so the same archive is skipped even
when it is passed by a different path. A new tar is still ingested, and
line-level checks still drop rows that are already stored.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

META_NAME = "ingested_bundles.json"


def meta_path(out_dir):
    return Path(out_dir) / META_NAME


def fingerprint(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {
        "name": path.name,
        "path": str(path),
        "size": size,
        "sha256": digest.hexdigest(),
    }


def load(out_dir):
    path = meta_path(out_dir)
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    return list(data.get("bundles", []))


def save(out_dir, bundles):
    path = meta_path(out_dir)
    path.write_text(json.dumps({"bundles": bundles}, indent=2) + "\n")


def schemas_done(records, sha256):
    for record in records:
        if record.get("sha256") == sha256:
            return set(record.get("schemas", []))
    return set()


def pending(records, bundles, schema):
    waiting = []
    for bundle in bundles:
        ident = fingerprint(bundle)
        if schema in schemas_done(records, ident["sha256"]):
            print(f"skip ingested {ident['name']} {schema} {ident['sha256'][:12]}")
            continue
        waiting.append((bundle, ident))
    return waiting


def record(out_dir, records, ident, schema, log_bundle_id):
    for existing in records:
        if existing.get("sha256") == ident["sha256"]:
            done = set(existing.get("schemas", []))
            done.add(schema)
            existing["schemas"] = sorted(done)
            existing["path"] = ident["path"]
            existing["ingested_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            save(out_dir, records)
            return records
    records.append(
        {
            "name": ident["name"],
            "path": ident["path"],
            "size": ident["size"],
            "sha256": ident["sha256"],
            "log_bundle_id": log_bundle_id,
            "schemas": [schema],
            "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    save(out_dir, records)
    return records
