"""SafeYolo-managed NATS server for the coord v1 substrate.

Owns the nats-server lifecycle end-to-end: pinned binary (downloaded on
first use, verified against SHA256), auth-required config (host-only
`127.0.0.1` listener, generated SafeYolo credential), JetStream data
directory, and process control. No system-installed `nats-server` is
required; SafeYolo does not accept an operator-installed one either
(pinning is a security posture per #371 reviewer point 2).

Design:
    - `SY_LOCAL` NATS account holds coord traffic. `SY_FED_*` names are
      reserved for future federation but not created.
    - Global JetStream file-store cap enforced at account level; per-room
      streams add their own MaxBytes/MaxAge.
    - Auth mandatory even on loopback (user + generated password). Config
      file and creds file are both mode 0600.

Not wired into `safeyolo start/stop` yet — the initial commits stand up
the runtime module and its unit-testable helpers. Lifecycle wiring is a
follow-up commit in the same branch.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from .identity import coord_data_dir

# Pinned. Bump requires updating _NATS_CHECKSUMS for every supported
# platform tuple. Never trust an operator-installed nats-server or a
# system package: SafeYolo owns the binary.
NATS_VERSION = "2.14.5"

# SHA256 of the `.tar.gz` archives from
# https://github.com/nats-io/nats-server/releases/download/v<VERSION>/
# nats-server-v<VERSION>-<PLATFORM>.tar.gz
_NATS_CHECKSUMS: dict[str, str] = {
    "linux-amd64":  "5e3b603d47c447bda1f77f9ac16dbf91c90aac4ff3681f8fbbc7201e4ed99355",
    "linux-arm64":  "673a98d3faa79dde3f9ebf16d6dfac36a5f694e7ad2015e4954dd7939c85cd4c",
    "darwin-amd64": "f95c98d6b6ed2b63c5681b46b092c9585c99767d547cf495730c329234625e96",
    "darwin-arm64": "ddd907854d9a2de834af133fa396915fe6442fe6d8909ae31390d1ea7a0fea50",
}

# 127.0.0.1 only, mandatory auth. No LAN listener.
NATS_LISTEN_HOST = "127.0.0.1"
NATS_CLIENT_PORT = 4222
NATS_MONITOR_PORT = 8222

# 1 GB total JetStream on-disk. Prevents unlimited-room-creation storage
# growth per #371 reviewer point 3. Individual per-room streams add their
# own MaxBytes/MaxAge on top of this ceiling.
JETSTREAM_MAX_FILE_STORE = 1 * 1024 * 1024 * 1024

_ACCOUNT_LOCAL = "SY_LOCAL"
_USERNAME = "safeyolo"


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system not in ("linux", "darwin"):
        raise RuntimeError(
            f"nats-server bundling supports linux and darwin; got {system!r}. "
            "Windows is out of scope for v1."
        )
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        raise RuntimeError(f"unsupported architecture: {machine!r}")
    return f"{system}-{arch}"


# ---------- paths ----------


def nats_root() -> Path:
    """Root of the SafeYolo-owned NATS install (binary, config, data)."""
    return coord_data_dir() / "nats"


def nats_bin_dir() -> Path:
    return nats_root() / "bin"


def nats_binary_path() -> Path:
    return nats_bin_dir() / "nats-server"


def nats_config_path() -> Path:
    return nats_root() / "nats.conf"


def nats_data_path() -> Path:
    return nats_root() / "jetstream"


def nats_creds_path() -> Path:
    """Client-side credential (SafeYolo reads this to connect). Contains
    only the generated password. Not agent-facing."""
    return nats_root() / "creds"


def nats_pid_path() -> Path:
    return nats_root() / "nats.pid"


# ---------- binary bootstrap ----------


def _download_url() -> str:
    key = _platform_key()
    return (
        f"https://github.com/nats-io/nats-server/releases/download/v{NATS_VERSION}/"
        f"nats-server-v{NATS_VERSION}-{key}.tar.gz"
    )


def _expected_checksum() -> str:
    key = _platform_key()
    try:
        return _NATS_CHECKSUMS[key]
    except KeyError as e:
        raise RuntimeError(
            f"no pinned checksum for platform {key!r} — nats-server v{NATS_VERSION}"
        ) from e


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_binary() -> Path:
    """Download and verify the pinned nats-server binary if not already
    present. Returns the path to the executable. Idempotent."""
    binary = nats_binary_path()
    if binary.exists() and os.access(binary, os.X_OK):
        return binary

    nats_bin_dir().mkdir(parents=True, exist_ok=True)
    url = _download_url()
    expected = _expected_checksum()

    with tempfile.NamedTemporaryFile(
        suffix=".tar.gz", dir=nats_bin_dir(), delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        # Deliberately urllib.request rather than httpx: no client cert /
        # proxy trust required for github.com.
        with urllib.request.urlopen(url) as resp:
            shutil.copyfileobj(resp, tmp_path.open("wb"))
        actual = _sha256_of(tmp_path)
        if actual != expected:
            raise RuntimeError(
                f"nats-server checksum mismatch for {_platform_key()}: "
                f"expected {expected}, got {actual}. Refusing to install."
            )
        # Extract nats-server binary out of the archive (top-level dir
        # contains it). Use strip-components=1 semantics manually.
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                # Take only the nats-server executable, flatten path
                if member.isfile() and member.name.endswith("/nats-server"):
                    member.name = "nats-server"
                    tar.extract(member, path=nats_bin_dir(), filter="data")
                    break
            else:
                raise RuntimeError(
                    "nats-server archive did not contain expected 'nats-server' file"
                )
        binary.chmod(0o755)
    finally:
        tmp_path.unlink(missing_ok=True)
    return binary


# ---------- credentials ----------


def ensure_credentials() -> str:
    """Generate the host-only NATS credential on first call.

    Returns the password (str). Idempotent: subsequent calls return the
    existing password without regenerating.
    """
    creds = nats_creds_path()
    if creds.exists():
        return creds.read_text().strip()
    nats_root().mkdir(parents=True, exist_ok=True)
    password = secrets.token_hex(32)
    creds.write_text(password + "\n")
    creds.chmod(0o600)
    return password


def read_credentials() -> str:
    """Read the existing password. Raises FileNotFoundError if absent."""
    return nats_creds_path().read_text().strip()


# ---------- config ----------


def write_config() -> Path:
    """Generate the nats-server config file. Idempotent — regenerates
    every call so a bumped constant (port, max_file_store) takes effect
    on the next start.

    Config bakes in:
      - loopback-only listener
      - monitoring endpoint (also loopback-only)
      - mandatory auth
      - `SY_LOCAL` account with JetStream enabled
      - global file-store cap
      - JetStream data directory under coord_data_dir
    """
    password = ensure_credentials()
    config = f"""# Generated by SafeYolo coord/nats_runtime.py. Do not edit by hand.
listen: {NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}
http: {NATS_LISTEN_HOST}:{NATS_MONITOR_PORT}
server_name: safeyolo-local

# JetStream lives under coord data dir; global cap enforced here so
# unlimited room creation cannot exhaust disk (per #371 reviewer point 3).
jetstream {{
    store_dir: "{nats_data_path()}"
    max_file_store: {JETSTREAM_MAX_FILE_STORE}
}}

# SY_LOCAL is the one account for local coord traffic. SY_FED_* names are
# reserved for future federation but not defined here (per #371 identity
# model — SY_LOCAL never federates).
accounts {{
    {_ACCOUNT_LOCAL} {{
        jetstream: enabled
        users: [
            {{ user: {_USERNAME}, password: "{password}" }}
        ]
    }}
}}
# No default account; unauthenticated connections are rejected.
no_auth_user: ""
"""
    path = nats_config_path()
    nats_root().mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    path.chmod(0o600)
    nats_data_path().mkdir(parents=True, exist_ok=True)
    return path


# ---------- lifecycle ----------


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_pid() -> int | None:
    path = nats_pid_path()
    if not path.exists():
        return None
    try:
        pid = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if _is_running(pid) else None


def start_server(wait_for_ready: bool = True, ready_timeout: float = 10.0) -> int:
    """Ensure binary + config, then start nats-server as a background
    subprocess. Returns the PID.

    Idempotent: if a process matching the recorded PID is already running,
    returns that PID without spawning a duplicate.
    """
    existing = _read_pid()
    if existing is not None:
        return existing

    binary = ensure_binary()
    config = write_config()
    proc = subprocess.Popen(
        [str(binary), "-c", str(config)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    nats_pid_path().write_text(str(proc.pid) + "\n")
    nats_pid_path().chmod(0o600)

    if wait_for_ready:
        deadline = time.monotonic() + ready_timeout
        while time.monotonic() < deadline:
            if is_healthy():
                return proc.pid
            time.sleep(0.05)
        # If we time out, kill so we don't leave a zombie
        with contextlib.suppress(OSError):
            proc.terminate()
        raise TimeoutError(f"nats-server did not become healthy within {ready_timeout}s")
    return proc.pid


def stop_server() -> bool:
    """Stop the SafeYolo-managed nats-server. Returns True if a process
    was signalled, False if nothing was running."""
    pid = _read_pid()
    if pid is None:
        nats_pid_path().unlink(missing_ok=True)
        return False
    with contextlib.suppress(OSError):
        os.kill(pid, 15)  # SIGTERM
    # Wait up to 3s for it to die
    for _ in range(60):
        if not _is_running(pid):
            break
        time.sleep(0.05)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, 9)  # SIGKILL
    nats_pid_path().unlink(missing_ok=True)
    return True


def is_healthy() -> bool:
    """Check the /healthz endpoint. Returns True iff nats-server is
    responsive AND JetStream is enabled."""
    import http.client

    try:
        conn = http.client.HTTPConnection(NATS_LISTEN_HOST, NATS_MONITOR_PORT, timeout=1.0)
        conn.request("GET", "/healthz?js-enabled-only=true")
        resp = conn.getresponse()
        # /healthz returns 200 with body {"status":"ok"} on healthy
        return resp.status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        with contextlib.suppress(Exception):
            conn.close()


def status() -> dict:
    """Diagnostic summary for `safeyolo doctor` / status commands."""
    pid = _read_pid()
    return {
        "binary": str(nats_binary_path()) if nats_binary_path().exists() else None,
        "version": NATS_VERSION,
        "config": str(nats_config_path()) if nats_config_path().exists() else None,
        "data_dir": str(nats_data_path()),
        "listen": f"{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}",
        "pid": pid,
        "healthy": is_healthy() if pid else False,
    }


def client_url() -> str:
    """URL SafeYolo passes to the nats-py client."""
    return f"nats://{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}"


def client_user_credentials() -> tuple[str, str]:
    """Return (username, password) for SafeYolo's own client. Not
    agent-facing — this stays inside the coord process."""
    return (_USERNAME, read_credentials())
