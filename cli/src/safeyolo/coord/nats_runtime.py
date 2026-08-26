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

Wired into `safeyolo start/stop/status/doctor` via
`commands.lifecycle` — start is best-effort (a NATS failure marks
coord degraded but does not prevent the proxy from starting), stop
tears NATS down before the proxy so the message plane never outlives
the process that reads it, and doctor surfaces the runtime state
alongside the other health checks.

Recorded runtime hardening deferred to future commits (per reviewer
round 2 close-out — real, not dismissed):
    - Log rotation: `nats/log/nats-server.log` is append-only. A busy
      or misbehaving server will grow it unbounded. Add size cap +
      rename (or logrotate friendliness) once the message-layer commit
      generates real traffic patterns.
    - Config TOCTOU: an attacker who can write to nats_root between
      write_config() and Popen could swap the config. Window is
      microseconds; mitigated by 0600/0700 modes; not blocking stage 1
      because SafeYolo agents cannot write the host-side NATS dir.
    - Credential-path symlink: 0700 dir + non-root operation cover the
      normal case; O_NOFOLLOW on the write path would harden if
      SafeYolo ever ran as root.
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

# Pinned. Bump requires updating BOTH checksum maps below for every
# supported platform tuple. Never trust an operator-installed nats-server
# or a system package: SafeYolo owns the binary.
NATS_VERSION = "2.14.5"

# SHA256 of the upstream release tarball
# (nats-server-v<VERSION>-<PLATFORM>.tar.gz on the GitHub Releases page).
# These are the digests that GitHub publishes; anyone can independently
# verify SafeYolo's pin against upstream artefacts. Checked BEFORE the
# tar parser touches the archive (defense against a malicious download
# handed to tarfile.open with a modified SHA that we never verified).
_NATS_ARCHIVE_SHA256: dict[str, str] = {
    "linux-amd64":  "5e3b603d47c447bda1f77f9ac16dbf91c90aac4ff3681f8fbbc7201e4ed99355",
    "linux-arm64":  "673a98d3faa79dde3f9ebf16d6dfac36a5f694e7ad2015e4954dd7939c85cd4c",
    "darwin-amd64": "f95c98d6b6ed2b63c5681b46b092c9585c99767d547cf495730c329234625e96",
    "darwin-arm64": "ddd907854d9a2de834af133fa396915fe6442fe6d8909ae31390d1ea7a0fea50",
}

# SHA256 of the EXTRACTED `nats-server` binary. Verified on every
# ensure_binary() call — on-disk re-verification catches tampering
# between runs (an attacker who wrote to nats/bin/<version>/nats-server
# before SafeYolo's first start_server must not gain execution simply
# because the file exists + is executable).
_NATS_BINARY_SHA256: dict[str, str] = {
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

# nats-server's default max_payload is 1 MiB, but our per-room stream
# needs 2 MiB headroom to fit a max-sized (256 KiB) body's worst-case
# JSON encoding plus envelope overhead. Raise the server ceiling in
# lockstep so an oversized publish fails at the API validator
# (MAX_BODY_BYTES) rather than as a nats-server "maximum payload
# exceeded" that would look like a NATS bug to the operator.
NATS_MAX_PAYLOAD = 2 * 1024 * 1024

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
    """Create a security-sensitive directory at mode 0700. Fails LOUDLY
    if we cannot enforce the mode — silently continuing with whatever
    permissions were previously in place would leave NATS data / config
    world-readable on a mis-configured host."""
    path.mkdir(parents=True, exist_ok=True)
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


def _expected_archive_sha256() -> str:
    key = _platform_key()
    try:
        return _NATS_ARCHIVE_SHA256[key]
    except KeyError as e:
        raise RuntimeError(
            f"no pinned archive checksum for platform {key!r} — nats-server v{NATS_VERSION}"
        ) from e


def _expected_binary_sha256() -> str:
    key = _platform_key()
    try:
        return _NATS_BINARY_SHA256[key]
    except KeyError as e:
        raise RuntimeError(
            f"no pinned binary checksum for platform {key!r} — nats-server v{NATS_VERSION}"
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

    Two-tier verification (reviewer round 2, point 3):
      - `_NATS_ARCHIVE_SHA256` is verified BEFORE the tar parser touches
        the download. This is the digest GitHub publishes for the release
        tarball, so an operator can independently audit our pin against
        upstream.
      - `_NATS_BINARY_SHA256` is verified on every call — the extracted
        binary's digest, checked whether we just downloaded it or found
        an existing file at the versioned path. Catches on-disk tampering
        (adversarial test class: TestBinaryChecksumOnExisting).
    """
    binary = nats_binary_path()
    binary_expected = _expected_binary_sha256()

    if binary.exists() and os.access(binary, os.X_OK):
        actual = _sha256_of(binary)
        if actual == binary_expected:
            return binary
        raise RuntimeError(
            f"nats-server binary at {binary} has SHA256 {actual}, "
            f"expected {binary_expected}. Refusing to run — delete the file "
            f"to trigger a fresh verified download."
        )

    _secure_mkdir(nats_bin_dir())
    url = _download_url()
    archive_expected = _expected_archive_sha256()

    with tempfile.NamedTemporaryFile(
        suffix=".tar.gz", dir=nats_bin_dir(), delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        # Bounded per-request timeout. urlopen's default is infinite;
        # a stalled GitHub connection would otherwise turn best-effort
        # `safeyolo start` into an indefinite hang on first run
        # (reviewer round-5 follow-up).
        with urllib.request.urlopen(url, timeout=30) as resp:
            shutil.copyfileobj(resp, tmp_path.open("wb"))

        # ARCHIVE verify BEFORE tar parsing — a modified download must
        # not reach tarfile.open (which is the parser we'd rather not
        # feed attacker-controlled data to).
        archive_actual = _sha256_of(tmp_path)
        if archive_actual != archive_expected:
            raise RuntimeError(
                f"nats-server archive checksum mismatch for {_platform_key()}: "
                f"expected {archive_expected}, got {archive_actual}. "
                f"Refusing to parse the archive."
            )

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
        # BINARY verify AFTER extraction — a tampered tarball with a
        # legitimate SHA (impossible without collision, but this is the
        # belt to the archive verify's braces) would still fail here.
        binary_actual = _sha256_of(binary)
        if binary_actual != binary_expected:
            binary.unlink(missing_ok=True)
            raise RuntimeError(
                f"nats-server binary checksum mismatch for {_platform_key()}: "
                f"expected {binary_expected}, got {binary_actual}. "
                f"Refusing to install."
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
    descriptor, staged_name = tempfile.mkstemp(
        dir=nats_root(), prefix=".creds.", suffix=".tmp"
    )
    try:
        os.fchmod(descriptor, _SECURE_FILE_MODE)
        with os.fdopen(descriptor, "w") as staged:
            # SafeYolo's local NATS client must retain one credential across
            # restarts. It is generated randomly, stored in a 0600 file under
            # a 0700 directory, and never exposed to agents or command lines.
            staged.write(password + "\n")  # lgtm[py/clear-text-storage-sensitive-data]
            staged.flush()
            os.fsync(staged.fileno())
        try:
            # Atomic create-if-absent: a racing process either publishes this
            # complete file or reads the complete credential that won first.
            os.link(staged_name, creds)
        except FileExistsError:
            return creds.read_text().strip()
    finally:
        Path(staged_name).unlink(missing_ok=True)
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
    ensure_credentials()
    config = f"""# Generated by SafeYolo coord/nats_runtime.py. Do not edit by hand.
listen: {NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}
http: {NATS_LISTEN_HOST}:{NATS_MONITOR_PORT}
server_name: {server_name}

# Match per-room MaxMsgSize in nats_client (2 MiB) so an oversized
# publish is rejected by the API validator, not by nats-server.
max_payload: {NATS_MAX_PAYLOAD}

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
            {{ user: {_USERNAME}, password: $SAFEYOLO_NATS_PASSWORD }}
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
    any of the required identity fields (pid + server_name + server_id).
    An older pidfile that lacks server_id is treated as invalid — we
    cannot verify ownership without both halves of the identity pair."""
    path = nats_pid_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if (
        not isinstance(data.get("pid"), int)
        or not isinstance(data.get("server_name"), str)
        or not isinstance(data.get("server_id"), str)
    ):
        return None
    return data


def _write_pidfile(pid: int, server_name: str, server_id: str, binary: str) -> None:
    """Atomically record ownership. Called ONLY after start_server has
    proven (via /varz) that the child is our nats-server AND obtained
    its `server_id`. Reviewer round 2, point 2: the pair
    (server_name, server_id) is unforgeable by a stale PID reuse — a
    restarted nats-server with the same configured server_name gets a
    fresh server_id, and ownership fails cleanly.

    Any exception here must reap the orphan child (see _start_server_locked).
    """
    _secure_mkdir(nats_root())
    payload = {
        "pid": pid,
        "server_name": server_name,
        "server_id": server_id,
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


def _varz(timeout: float = 1.0) -> dict | None:
    """Ask the monitor endpoint for the running server's identity fields.
    Returns a dict with at least server_name + server_id on success, or
    None on any error (connection refused, timeout, malformed JSON,
    missing fields).

    This is the trusted ownership signal: the (server_name, server_id)
    pair is generated fresh on every nats-server start, so a stale PID
    reuse cannot answer with both halves matching our record."""
    import http.client

    conn = None
    try:
        conn = http.client.HTTPConnection(NATS_LISTEN_HOST, NATS_MONITOR_PORT, timeout=timeout)
        conn.request("GET", "/varz")
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = json.loads(resp.read())
        if not isinstance(data, dict):
            return None
        name = data.get("server_name")
        sid = data.get("server_id")
        if not isinstance(name, str) or not isinstance(sid, str):
            return None
        return {"server_name": name, "server_id": sid}
    except (OSError, ValueError, __import__("http").client.HTTPException):
        return None
    finally:
        if conn:
            with contextlib.suppress(Exception):
                conn.close()


def _verified_ownership() -> dict | None:
    """Return the pidfile dict iff (a) it parses, (b) the PID is alive,
    AND (c) /varz reports BOTH server_name and server_id matching what
    we recorded. Otherwise None — treat as stale, never signal.

    Reviewer round 2 point 2: requiring server_id in addition to
    server_name closes the stale-PID + restarted-NATS case — a manually
    restarted nats-server using the same config gets a new server_id,
    so ownership fails cleanly rather than blessing an unrelated live PID.
    """
    stored = _read_pidfile()
    if not stored:
        return None
    if not _pid_alive(stored["pid"]):
        return None
    live = _varz()
    if (
        live is None
        or live["server_name"] != stored["server_name"]
        or live["server_id"] != stored["server_id"]
    ):
        return None
    return stored


def is_healthy() -> bool:
    """True iff a SafeYolo-owned nats-server is running and reachable.

    Combines liveness + ownership check: a random nats-server on
    :8222 that isn't ours returns False.
    """
    return _verified_ownership() is not None


# ---------- lifecycle ----------

# Shared start/stop serialization (reviewer round 2 final point).
# Both start_server and stop_server acquire this pair — a concurrent
# start+stop cannot mutate the pidfile / process out from under each
# other. threading.Lock covers intra-process; fcntl.flock covers
# inter-process (Linux flock is per-process, not per-thread, so both
# are needed for full protection).
_LIFECYCLE_LOCK = threading.Lock()


@contextlib.contextmanager
def _lifecycle_lock():
    """Hold the intra-process lock + the cross-process file lock as a
    matched pair for the duration of a start or stop operation."""
    _secure_mkdir(nats_root())
    lock_path = nats_root() / ".lifecycle.lock"
    lock_path.touch()
    with _LIFECYCLE_LOCK, open(lock_path) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


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

    Idempotent AND race-safe (test class TestConcurrentStart): shared
    lifecycle lock with stop_server so concurrent start+stop cannot
    mutate pidfile/process underneath each other. Two callers racing
    on either axis share the single spawned nats-server, not two
    competing for port 4222.

    Diagnostics: child stdout/stderr → nats/log/nats-server.log. If the
    child exits before becoming healthy (bad config, port collision, etc.)
    this raises RuntimeError immediately with the log tail rather than
    waiting for the full timeout.
    """
    with _lifecycle_lock():
        return _start_server_locked(ready_timeout)


def _start_server_locked(ready_timeout: float) -> int:
    """Body of start_server, called under the lifecycle lock."""
    verified = _verified_ownership()
    if verified:
        return verified["pid"]

    # Stale pidfile — clear before spawning so we don't leave the
    # operator with confusing state.
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
        # Keep the credential out of the generated config. NATS parses the
        # environment value as config syntax, so JSON quoting preserves it as
        # a string even if an existing generated secret happens to be numeric.
        env={
            **os.environ,
            "SAFEYOLO_NATS_PASSWORD": json.dumps(ensure_credentials()),
        },
    )
    # log_fp is now owned by the child; close our handle so we don't hold
    # an extra fd. The child keeps its own dup.
    log_fp.close()

    # Reviewer round 2 point 1 (P0): any exception between spawn and
    # successful startup MUST reap the orphan child. Previously, a
    # _write_pidfile failure (disk full, chmod denied) would leave a
    # live NATS with no pidfile — stop_server would refuse to signal it.
    try:
        deadline = time.monotonic() + ready_timeout
        while time.monotonic() < deadline:
            rc = proc.poll()
            if rc is not None:
                raise RuntimeError(
                    f"nats-server exited immediately (exit={rc}). Log tail:\n"
                    f"{_tail_log()}"
                )
            # /varz gives us both server_name (to confirm the running
            # server is the one we just spawned) and server_id (to seal
            # ownership against stale-PID reuse — point 2).
            live = _varz()
            if live is not None and live["server_name"] == server_name:
                # Write pidfile ONLY after ownership is confirmed. A
                # failure inside _write_pidfile falls through to the
                # outer except and reaps the orphan.
                _write_pidfile(
                    proc.pid, server_name, live["server_id"], str(binary),
                )
                return proc.pid
            time.sleep(0.05)
        raise TimeoutError(
            f"nats-server did not verify healthy within {ready_timeout}s. Log tail:\n"
            f"{_tail_log()}"
        )
    except BaseException:
        # Any failure post-Popen: reap the child, clear any half-written
        # pidfile, re-raise. Never leave an unmanaged nats-server behind.
        _reap_child(proc)
        nats_pid_path().unlink(missing_ok=True)
        raise


class WedgedNatsServer(RuntimeError):
    """The pidfile points at a live PID we own on paper (the file was
    written by us), but /varz can't confirm ownership. Someone or
    something has left NATS in a state we cannot safely signal — either
    the monitor endpoint is unreachable, or a different nats-server has
    reused the PID. Never delete the pidfile in this state (reviewer
    round-4 unhealthy-stop edge): that turns a wedged owned NATS into
    an unmanaged host process."""


def stop_server() -> bool:
    """Stop the SafeYolo-managed nats-server. Returns True iff we
    signalled a process WE OWN. Never signals a PID that fails
    ownership verification (stale pidfile / PID reuse).
    Shares the lifecycle lock with start_server so concurrent start+stop
    cannot race on pidfile or process state. Raises WedgedNatsServer
    when the pidfile PID is alive but ownership cannot be verified —
    the operator has to intervene rather than us silently orphaning it.
    """
    with _lifecycle_lock():
        return _stop_server_locked()


def _stop_server_locked() -> bool:
    verified = _verified_ownership()
    if verified is None:
        # Two shapes of "no verified ownership":
        #   1. No pidfile / stale pidfile with dead PID  → safe to clear
        #      the pidfile, nothing to stop, return False.
        #   2. Pidfile PID is alive but /varz cannot confirm ownership
        #      → wedged; DO NOT delete the pidfile (that would abandon
        #      an owned-on-paper live process to become unmanaged).
        stored = _read_pidfile()
        if stored is not None and _pid_alive(stored["pid"]):
            raise WedgedNatsServer(
                f"pidfile PID {stored['pid']} is alive but /varz ownership "
                f"cannot be verified (server_name={stored['server_name']}). "
                "Refusing to delete the pidfile or signal an unverified "
                "process. Investigate manually: check nats-server log "
                f"({nats_log_path()}) and monitor endpoint "
                f"({NATS_LISTEN_HOST}:{NATS_MONITOR_PORT})."
            )
        nats_pid_path().unlink(missing_ok=True)
        return False
    pid = verified["pid"]
    with contextlib.suppress(OSError):
        os.kill(pid, 15)
    for _ in range(60):
        if not _pid_alive(pid):
            break
        time.sleep(0.05)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, 9)
        for _ in range(20):
            if not _pid_alive(pid):
                break
            time.sleep(0.05)
    nats_pid_path().unlink(missing_ok=True)
    return True


def status() -> dict:
    """Diagnostic summary for `safeyolo doctor` / status commands.

    `state` is one of:
      - "healthy"      : running + owned (verified via /varz)
      - "wedged"       : pidfile PID alive but /varz unverified — a live
                         process we cannot signal safely; needs operator
                         attention (reviewer round-5 follow-up)
      - "not-running"  : no live NATS we own (pidfile absent or stale)
    """
    binary = nats_binary_path()
    verified = _verified_ownership()
    stored = _read_pidfile()
    if verified is not None:
        state = "healthy"
    elif stored is not None and _pid_alive(stored["pid"]):
        state = "wedged"
    else:
        state = "not-running"
    return {
        "binary": str(binary) if binary.exists() else None,
        "requested_version": NATS_VERSION,
        "actual_version": _actual_binary_version(binary),
        "config": str(nats_config_path()) if nats_config_path().exists() else None,
        "data_dir": str(nats_data_path()),
        "log_file": str(nats_log_path()) if nats_log_path().exists() else None,
        "listen": f"{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}",
        # Always the pidfile path so doctor/status remediation can
        # reference it precisely — separate from `config`, which points
        # at the generated nats-server config file.
        "pidfile": str(nats_pid_path()),
        "pid": verified["pid"] if verified else (stored["pid"] if stored else None),
        "server_name": verified["server_name"] if verified else (
            stored["server_name"] if stored else None
        ),
        "server_id": verified["server_id"] if verified else None,
        "healthy": verified is not None,
        "state": state,
    }


def client_url() -> str:
    """URL SafeYolo passes to the nats-py client."""
    return f"nats://{NATS_LISTEN_HOST}:{NATS_CLIENT_PORT}"


def client_user_credentials() -> tuple[str, str]:
    """Return (username, password) for SafeYolo's own client. Not
    agent-facing — this stays inside the coord process."""
    return (_USERNAME, read_credentials())
