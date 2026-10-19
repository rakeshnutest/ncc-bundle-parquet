"""Copy Parquet files onto Diamond the way Panacea stores reports.

Off unless the caller asks. Files go under the eng shared directory, which
Diamond serves as https://diamond.corp.nutanix.com/~<user>/...
The case directory on /mnt/data_vol is not writable.
"""

import os
import subprocess
from pathlib import Path

ENV_CANDIDATES = (
    Path("/home/rakeshkumar.r/panacea/panacea-ingestion-pipeline/.env.cluster"),
)
PARQUET_NAMES = ("nu_logs_local.parquet", "nu_metrics_sysstats.parquet")


def _load_env_file():
    found = {}
    for path in ENV_CANDIDATES:
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            found[key.strip()] = value.strip().strip('"').strip("'")
    return found


def diamond_account():
    file_env = _load_env_file()
    host = os.environ.get("DIAMOND_HOST") or file_env.get("DIAMOND_HOST") or "diamond.corp.nutanix.com"
    user = os.environ.get("DIAMOND_USERNAME") or file_env.get("DIAMOND_USERNAME") or "eng"
    password = os.environ.get("DIAMOND_PASSWORD") or file_env.get("DIAMOND_PASSWORD")
    if not password:
        raise RuntimeError("DIAMOND_PASSWORD is not set and was not found in the Panacea env file")
    return host, user, password


def remote_dir(user, log_bundle_id):
    return f"/users/{user}/shared/ncc-bundle-parquet/{log_bundle_id}"


def web_url(user, log_bundle_id, name):
    return f"https://diamond.corp.nutanix.com/~{user}/ncc-bundle-parquet/{log_bundle_id}/{name}"


def _ssh(host, user, password, remote_command):
    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = [
        "sshpass", "-e", "ssh",
        "-o", "PreferredAuthentications=keyboard-interactive,password",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "NumberOfPasswordPrompts=1",
        f"{user}@{host}",
        remote_command,
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        safe = [line for line in detail if "password" not in line.lower()]
        raise RuntimeError("ssh failed: " + (safe[-1] if safe else f"exit {result.returncode}"))


def _scp(host, user, password, local_path, remote_path):
    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = [
        "sshpass", "-e", "scp",
        "-o", "PreferredAuthentications=keyboard-interactive,password",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "NumberOfPasswordPrompts=1",
        str(local_path),
        f"{user}@{host}:{remote_path}",
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        safe = [line for line in detail if "password" not in line.lower()]
        raise RuntimeError("scp failed: " + (safe[-1] if safe else f"exit {result.returncode}"))


def upload(out_dir, log_bundle_id):
    host, user, password = diamond_account()
    destination = remote_dir(user, log_bundle_id)
    _ssh(host, user, password, f"mkdir -p '{destination}'")
    uploaded = []
    for name in PARQUET_NAMES:
        local = Path(out_dir) / name
        if not local.is_file():
            continue
        _scp(host, user, password, local, f"{destination}/{name}")
        uploaded.append((name, web_url(user, log_bundle_id, name)))
    if not uploaded:
        raise RuntimeError(f"no parquet files in {out_dir}")
    print(f"diamond {destination}")
    for name, url in uploaded:
        print(f"diamond {name} {url}")
    return uploaded
