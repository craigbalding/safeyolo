"""SafeYolo-managed NATS server for the coord v1 substrate.

Owns the nats-server lifecycle end-to-end: pinned binary (downloaded on
first use, verified against SHA256, stored under a version-scoped path),
auth-required config (host-only `127.0.0.1` listener, generated SafeYolo
credential), JetStream data directory, and process control.

Ownership contract (reviewer hardening pass):
    - Every start generates a nonce and configures nats-server with
      `server_name = safeyolo-<nonce>`. That name is persisted in a JSON
      pidfile alongside the PID.
    - Before signalling a recorded PID, SafeYolo verifies the process is
      alive AND that `/varz` at the monitor port reports the SAME
      server_name. A stale PID that has been reused by an unrelated
      host process will fail the name check and will NEVER be signalled.
    - Version bumps get a fresh binary because the path is
      `nats/bin/<version>/nats-server` — an old install is never treated
      as satisfying a new pinned version.

Diagnostics:
    - Child stdout+stderr go to `nats/log/nats-server.log` (append mode).
    - The readiness loop polls `proc.poll()` — if the child exits before
      health, `start_server` fails fast with a log tail rather than
      waiting the full timeout.
    - `status()` reports the actual `nats-server -v` output, not the
      requested pin.

Not wired into `safeyolo start/stop` yet; the lifecycle module lives
independently so its hardening can be reviewed on its own.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from .identity import coord_data_dir

# Pinned. Bump requires updating _NATS_CHECKSUMS for every supported
# platform tuple. Never trust an operator-installed nats-server or a
# system package: SafeYolo owns the binary.
NATS_VERSION = "2.14.5"

# SHA256 of the EXTRACTED `nats-server` binary (not the .tar.gz archive).
# Verified against the pinned value on every ensure_binary() call —
# on-disk re-verification catches tampering with the binary between runs,
# not just corruption at download time. Values obtained by downloading
# and extracting each release tarball manually.
_NATS_CHECKSUMS: dict[str, str] = {
    "linux-amd64":  "e1a2f9ba25077f4cf753bee829483bd68fbf0a4eec9b6645a1e5785a6de0c0d1",
    "linux-arm64":  "ebccb25ba4f364dd8878630f1985d8b24d9e0a6e35aa4d8e1a7ecab38c881419",
    "darwin-amd64": "5df71e798cab833b99514f42d65123bcbd60ef64673b4c543bfd00e6482a22a7",
    "darwin-arm64": "0a8beaf990916185fa8a4e2236f1c6525a8be8f5f1c1d83225458b4baa822e0e",
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

# Directory perms tighter than coord defaults: NATS data + config live here.
_SECURE_DIR_MODE = 0o700
_SECURE_FILE_MODE = 0o600


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


def _secure_mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(_SECURE_DIR_MODE)
    return path


def nats_root() -> Path:
    """Root of the SafeYolo-owned NATS install (binary, config, data)."""
    return coord_data_dir() / "nats"


def nats_bin_dir() -> Path:
    """Bin dir is version-scoped so a version bump installs fresh binary
    (reviewer point 2). Old versioned dirs are harmless but not cleaned up
    automatically — a follow-up can prune."""
    return nats_root() / "bin" / NATS_VERSION


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
    """JSON pidfile: {pid, server_name, binary, started_at}. Ownership is
    proven via server_name matching /varz, NOT via PID alone."""
    return nats_root() / "nats.pid.json"


def nats_log_path() -> Path:
    return nats_root() / "log" / "nats-server.log"


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
    present at the version-scoped path. Returns the executable path.
    Idempotent.

    ALWAYS re-verifies SHA256 against the pinned checksum, even if a
    binary already exists at the versioned path. An attacker who wrote
    to `nats/bin/<version>/nats-server` before SafeYolo's first
    ensure_binary() call must not gain execution just because the file
    exists and is executable (adversarial test class:
    TestBinaryChecksumOnExisting).
    """
    binary = nats_binary_path()
    expected = _expected_checksum()
    if binary.exists() and os.access(binary, os.X_OK):
        actual = _sha256_of(binary)
        if actual == expected:
            return binary
        raise RuntimeError(
            f"nats-server binary at {binary} has SHA256 {actual}, "
            f"expected {expected}. Refusing to run — delete the file "
            f"to trigger a fresh verified download."
        )

    _secure_mkdir(nats_bin_dir())
    url = _download_url()

    with tempfile.NamedTemporaryFile(
        suffix=".tar.gz", dir=nats_bin_dir(), delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with urllib.request.urlopen(url) as resp:
            shutil.copyfileobj(resp, tmp_path.open("wb"))
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                # Restrict to regular files (symlinks named `nats-server`
                # pointing at /etc/passwd would otherwise sneak through);
                # rewrite member.name so path-traversal entries land as
                # the safe leaf name; extract with filter="data" so any
                # residual unsafe patterns are rejected by the stdlib.
                if member.isfile() and member.name.endswith("/nats-server"):
                    member.name = "nats-server"
                    tar.extract(member, path=nats_bin_dir(), filter="data")
                    break
            else:
                raise RuntimeError(
                    "nats-server archive did not contain expected 'nats-server' file"
                )
        # Verify the extracted binary against the pinned checksum. A
        # tampered / corrupted tarball that manages to extract something
        # is caught here; we never chmod +x a binary that doesn't match.
        actual = _sha256_of(binary)
        if actual != expected:
            binary.unlink(missing_ok=True)
            raise RuntimeError(
                f"nats-server binary checksum mismatch for {_platform_key()}: "
                f"expected {expected}, got {actual}. Refusing to install."
            )
        binary.chmod(0o755)
    finally:
        tmp_path.unlink(missing_ok=True)
    return binary


def _actual_binary_version(binary: Path) -> str | None:
    """Report `nats-server -v` output. Used by status() so it reflects
    what's actually on disk rather than the requested pin."""
    if not binary.exists():
        return None
    try:
        result = subprocess.run(
            [str(binary), "-v"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip()
    # nats-server prints "nats-server: v2.14.5"
    m = re.search(r"v?(\d+\.\d+\.\d+\S*)", text)
    return m.group(1) if m else text or None


# ---------- credentials ----------


def ensure_credentials() -> str:
    """Generate the host-only NATS credential on first call.

    Returns the password (str). Idempotent: subsequent calls return the
    existing password without regenerating.
    """
    creds = nats_creds_path()
    if creds.exists():
        return creds.read_text().strip()
    _secure_mkdir(nats_root())
    password = secrets.token_hex(32)
    creds.write_text(password + "\n")
    creds.chmod(_SECURE_FILE_MODE)
    return password


def read_credentials() -> str:
    """Read the existing password. Raises FileNotFoundError if absent."""
    return nats_creds_path().read_text().strip()


# ---------- config ----------


def _new_server_name() -> str:
    """Fresh per-start server_name. Used for ownership verification via
    /varz — a stale PID reused by an unrelated process cannot match this."""
    return f"safeyolo-{secrets.token_hex(8)}"


def write_config(server_name: str) -> Path:
    """Generate the nats-server config file with the caller's server_name.

    Idempotent within a single start (same server_name → same content) but
    rewritten on each `start_server` so the ownership token changes.
    """
    password = ensure_credentials()
    config = f"""# Generated by SafeYolo coord/nats_runtime.py. Do not edit by hand.
listen: {NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}
http: {NATS_LISTEN_HOST}:{NATS_MONITOR_PORT}
server_name: {server_name}

# JetStream lives under coord data dir; global cap enforced here so
# unlimited room creation cannot exhaust disk (per #371 reviewer point 3).
jetstream {{
    store_dir: "{nats_data_path()}"
    max_file_store: {JETSTREAM_MAX_FILE_STORE}
}}

# SY_LOCAL is the one account for local coord traffic. SY_FED_* names are
# reserved for future federation but not defined here (per #371 identity
# model — SY_LOCAL never federates). No default account is defined, so
# unauthenticated connections cannot select any account and are rejected
# by the server.
accounts {{
    {_ACCOUNT_LOCAL} {{
        jetstream: enabled
        users: [
            {{ user: {_USERNAME}, password: "{password}" }}
        ]
    }}
}}
"""
    _secure_mkdir(nats_root())
    _secure_mkdir(nats_data_path())
    path = nats_config_path()
    path.write_text(config)
    path.chmod(_SECURE_FILE_MODE)
    return path


# ---------- ownership + health ----------


def _read_pidfile() -> dict | None:
    """Parse JSON pidfile. Returns None if absent, malformed, or missing
    required fields."""
    path = nats_pid_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("pid"), int) or not isinstance(data.get("server_name"), str):
        return None
    return data


def _write_pidfile(pid: int, server_name: str, binary: str) -> None:
    _secure_mkdir(nats_root())
    payload = {
        "pid": pid,
        "server_name": server_name,
        "binary": binary,
        "started_at": int(time.time()),
    }
    path = nats_pid_path()
    path.write_text(json.dumps(payload) + "\n")
    path.chmod(_SECURE_FILE_MODE)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _varz_server_name(timeout: float = 1.0) -> str | None:
    """Ask the monitor endpoint for the running server's name. Returns
    None on any error (connection refused, timeout, malformed JSON).

    This is the trusted ownership signal: no PID reuse can produce a
    process that answers /varz with our per-start nonce."""
    import http.client

    conn = None
    try:
        conn = http.client.HTTPConnection(NATS_LISTEN_HOST, NATS_MONITOR_PORT, timeout=timeout)
        conn.request("GET", "/varz")
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = json.loads(resp.read())
        name = data.get("server_name")
        return name if isinstance(name, str) else None
    except (OSError, ValueError, __import__("http").client.HTTPException):
        return None
    finally:
        if conn:
            with contextlib.suppress(Exception):
                conn.close()


def _verified_ownership() -> dict | None:
    """Return the pidfile dict iff (a) it parses, (b) the PID is alive,
    and (c) the /varz server_name matches what we recorded. Otherwise
    None — treat as stale, never signal.
    """
    stored = _read_pidfile()
    if not stored:
        return None
    if not _pid_alive(stored["pid"]):
        return None
    actual_name = _varz_server_name()
    if actual_name is None or actual_name != stored["server_name"]:
        return None
    return stored


def is_healthy() -> bool:
    """True iff a SafeYolo-owned nats-server is running and reachable.

    Combines liveness + ownership check: a random nats-server on
    :8222 that isn't ours returns False.
    """
    return _verified_ownership() is not None


# ---------- lifecycle ----------

# Intra-process serialization. `fcntl.flock` on Linux is per-process,
# not per-thread, so multiple threads racing start_server would all
# pass the file lock. threading.Lock inside the process + fcntl.flock
# across processes gives full protection.
_START_LOCK = threading.Lock()


def _tail_log(nbytes: int = 4096) -> str:
    """Read the last `nbytes` of the NATS log for diagnostics."""
    log = nats_log_path()
    if not log.exists():
        return "(no log)"
    try:
        with log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", errors="replace")
    except OSError as e:
        return f"(log read failed: {e})"


def _reap_child(proc: subprocess.Popen, term_timeout: float = 2.0, kill_timeout: float = 2.0) -> None:
    """SIGTERM → wait → SIGKILL → wait. Never leaves the caller with a
    live process, never raises on already-dead child."""
    with contextlib.suppress(OSError):
        proc.terminate()
    try:
        proc.wait(timeout=term_timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=kill_timeout)


def start_server(ready_timeout: float = 10.0) -> int:
    """Ensure binary + config, start nats-server, verify ownership + health.

    Idempotent AND race-safe (adversarial test class:
    TestConcurrentStart): serialized by an in-process threading.Lock plus
    a cross-process fcntl.flock on a file under nats_root. Two callers
    racing on either axis are guaranteed to end up sharing the same
    single spawned nats-server, not two competing for port 4222.

    Diagnostics: child stdout/stderr → nats/log/nats-server.log. If the
    child exits before becoming healthy (bad config, port collision, etc.)
    this raises RuntimeError immediately with the log tail, rather than
    waiting for the full timeout.
    """
    _secure_mkdir(nats_root())
    lock_path = nats_root() / ".start.lock"
    lock_path.touch()
    with _START_LOCK, open(lock_path) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            return _start_server_locked(ready_timeout)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _start_server_locked(ready_timeout: float) -> int:
    """Body of start_server, called under both threading + file locks."""
    verified = _verified_ownership()
    if verified:
        return verified["pid"]

    # If the pidfile exists but ownership doesn't verify, it's stale.
    # Remove it before spawning so we don't leave the operator with
    # confusing state.
    nats_pid_path().unlink(missing_ok=True)

    binary = ensure_binary()
    server_name = _new_server_name()
    config = write_config(server_name)

    log_path = nats_log_path()
    _secure_mkdir(log_path.parent)
    log_fp = log_path.open("ab")
    log_fp.write(
        f"\n=== SafeYolo nats-server start at {int(time.time())} "
        f"(server_name={server_name}, binary={binary}) ===\n".encode()
    )
    log_fp.flush()

    proc = subprocess.Popen(
        [str(binary), "-c", str(config)],
        stdin=subprocess.DEVNULL,
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # log_fp is now owned by the child; close our handle so we don't hold
    # an extra fd. The child keeps its own dup.
    log_fp.close()

    _write_pidfile(proc.pid, server_name, str(binary))

    deadline = time.monotonic() + ready_timeout
    while time.monotonic() < deadline:
        # Fail-fast: child died on startup (bad config, port collision).
        rc = proc.poll()
        if rc is not None:
            nats_pid_path().unlink(missing_ok=True)
            raise RuntimeError(
                f"nats-server exited immediately (exit={rc}). Log tail:\n"
                f"{_tail_log()}"
            )
        # Success: ownership verified via /varz.
        if _verified_ownership() is not None:
            return proc.pid
        time.sleep(0.05)

    # Timed out. Reap the child cleanly, then remove pidfile.
    _reap_child(proc)
    nats_pid_path().unlink(missing_ok=True)
    raise TimeoutError(
        f"nats-server did not verify healthy within {ready_timeout}s. Log tail:\n"
        f"{_tail_log()}"
    )


def stop_server() -> bool:
    """Stop the SafeYolo-managed nats-server. Returns True iff we
    signalled a process WE OWN. Never signals a PID that fails ownership
    verification — a stale pidfile pointing to an unrelated host process
    (PID reuse) results in a no-op cleanup, not a kill.
    """
    verified = _verified_ownership()
    if not verified:
        # Nothing to signal — either absent, dead, or not ours. Clear
        # the stale pidfile so subsequent state is clean.
        nats_pid_path().unlink(missing_ok=True)
        return False
    pid = verified["pid"]
    with contextlib.suppress(OSError):
        os.kill(pid, 15)  # SIGTERM
    for _ in range(60):
        if not _pid_alive(pid):
            break
        time.sleep(0.05)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, 9)  # SIGKILL
        # Brief wait for the kernel to reap
        for _ in range(20):
            if not _pid_alive(pid):
                break
            time.sleep(0.05)
    nats_pid_path().unlink(missing_ok=True)
    return True


def status() -> dict:
    """Diagnostic summary for `safeyolo doctor` / status commands."""
    binary = nats_binary_path()
    verified = _verified_ownership()
    return {
        "binary": str(binary) if binary.exists() else None,
        "requested_version": NATS_VERSION,
        "actual_version": _actual_binary_version(binary),
        "config": str(nats_config_path()) if nats_config_path().exists() else None,
        "data_dir": str(nats_data_path()),
        "log_file": str(nats_log_path()) if nats_log_path().exists() else None,
        "listen": f"{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}",
        "pid": verified["pid"] if verified else None,
        "server_name": verified["server_name"] if verified else None,
        "healthy": verified is not None,
    }


def client_url() -> str:
    """URL SafeYolo passes to the nats-py client."""
    return f"nats://{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}"


def client_user_credentials() -> tuple[str, str]:
    """Return (username, password) for SafeYolo's own client. Not
    agent-facing — this stays inside the coord process."""
    return (_USERNAME, read_credentials())
