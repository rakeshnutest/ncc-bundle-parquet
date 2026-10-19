"""Walk an NCC tar.gz and its nested zips without writing them to disk."""

import io
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
ANON_IP_RE = re.compile(r"XX\.XX\.XX\.\d+")


def cvm_ip_from(path):
    text = str(path).replace("\\", "/")
    match = IP_RE.search(text)
    if match:
        return match.group(0)
    anon = ANON_IP_RE.search(text)
    return anon.group(0) if anon else "0.0.0.0"


def infer_bundle_id(tar_path):
    match = re.search(r"case-(\d+)", str(tar_path))
    if match:
        return int(match.group(1))
    parent = Path(tar_path).parent.name
    if parent.isdigit():
        return int(parent)
    return 0


def read_tar_paths(list_path):
    """Read tar paths from a text file, one per line. Blank lines and # comments are ignored."""
    paths = []
    for line in Path(list_path).expanduser().read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        paths.append(Path(line))
    return paths


def infer_collected(tar_path):
    match = re.search(r"(\d{2})-(\d{2})-(\d{4})", Path(tar_path).name)
    if not match:
        return datetime.now(timezone.utc)
    month, day, year = (int(part) for part in match.groups())
    return datetime(year, month, day, tzinfo=timezone.utc)


def iter_members(tar_path):
    """Yield (member_name, bytes) for each file in the tar and nested zips."""
    with tarfile.open(tar_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name
            if name.endswith(".zip"):
                blob = archive.extractfile(member).read()
                with zipfile.ZipFile(io.BytesIO(blob)) as nested:
                    for info in nested.infolist():
                        if not info.is_dir():
                            yield info.filename, nested.read(info)
                continue
            yield name, archive.extractfile(member).read()


def iter_text_lines(raw):
    if b"\x00" in raw[:4096]:
        return
    text = raw.decode("utf-8", "replace")
    for line in text.splitlines():
        yield line.rstrip("\r")
