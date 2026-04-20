"""Snapshot metadata + validity for agent warm-boot.

Three files per snapshottable agent live under ~/.safeyolo/agents/<name>/:

    snapshot.bin             -- VM memory image, written by safeyolo-vm
                               on SIGUSR1 (see vm/Sources/SafeYoloVM).
    snapshot.bin.meta.json   -- hardware fingerprint, also written by
                               safeyolo-vm. Matches what the helper
                               reads back at restore time.
    snapshot.bin.rootfs      -- APFS clone of the live rootfs captured at
                               the same paused moment as snapshot.bin.
                               VZ requires the restore-time disk to be
                               byte-identical to its state at save time.
    snapshot.version.json    -- CLI-owned fingerprint of the inputs that
                               determine whether the snapshot is still
                               restorable. Written by this module; read
                               by the mode-decision in commands/agent.py.

PR 3 writes the version file; PR 4 adds the restore path that reads it.
PR 5 extends this to Linux via runsc checkpoint images.
"""

import hashlib
import json
import os
import platform as _platform
import subprocess
from pathlib import Path

from .config import get_config_dir, get_data_dir
from .vm import (
    find_vm_helper,
    get_agents_dir,
    get_base_rootfs_path,
    get_initrd_path,
    get_kernel_path,
)

# Bumped when the snapshot layout itself changes in a backwards-incompatible
# way (e.g., adding a new sidecar, renaming files). Version.json mismatch
# invalidates the snapshot regardless of the input hashes.
SNAPSHOT_SCHEMA = 1

# A snapshot.bin smaller than this is almost certainly a partial write or
# early-failure stub, not a real memory image. Default memory is 4 GiB so
# 16 MiB is a very conservative floor.
MIN_SNAPSHOT_BYTES = 16 * 1024 * 1024


def snapshot_path(name: str) -> Path:
    return get_agents_dir() / name / "snapshot.bin"


def snapshot_sidecar_path(name: str) -> Path:
    # Written by safeyolo-vm itself; we never write this file.
    return get_agents_dir() / name / "snapshot.bin.meta.json"


def snapshot_rootfs_clone_path(name: str) -> Path:
    # Auto-derived by safeyolo-vm from the snapshot path.
    return get_agents_dir() / name / "snapshot.bin.rootfs"


def snapshot_version_path(name: str) -> Path:
    # Owned by this module.
    return get_agents_dir() / name / "snapshot.version.json"


# ---------------------------------------------------------------------------
# Hash cache -- avoids re-reading 2 GB of rootfs + kernel/initrd on every
# agent run just to produce a fingerprint that rarely changes.
#
# Key by (path, mtime_ns, size). Same convention as ccache / make: if any
# of those change, content may have changed and we rehash. In practice
# kernel/initrd/rootfs change only when the user rebuilds guest images,
# so cache hits dominate.
#
# Cache file is a plain JSON map stored under the data dir. Corrupted /
# missing cache files are treated as empty -- worst case we redo the
# hashing once and rewrite. No locking: `safeyolo agent run` invocations
# are interactive and typically not concurrent; if they were, two writers
# would at worst duplicate work or lose one entry, not corrupt downstream
# state (because snapshot.version.json is always written fresh from the
# returned dict, not from cache contents).
# ---------------------------------------------------------------------------

def _hash_cache_path() -> Path:
    return get_data_dir() / "hash-cache.json"


def _load_hash_cache() -> dict:
    path = _hash_cache_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_hash_cache(cache: dict) -> None:
    path = _hash_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write via temp file + rename. Avoids a torn write if the
        # process is interrupted mid-save.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(cache, sort_keys=True))
        os.replace(tmp, path)
    except OSError:
        # Non-fatal: next call will redo the hashing and try to save again.
        pass


def _sha256_file_uncached(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    """Cached sha256 of a file, keyed by (path, mtime_ns, size).

    Cache invalidates automatically whenever the file changes in any
    filesystem-visible way. First call after a file edit pays the full
    read cost; subsequent calls return in microseconds.
    """
    try:
        st = path.stat()
    except OSError:
        # Fall through -- caller handles missing files per their own logic.
        raise

    cache = _load_hash_cache()
    entry = cache.get("sha256", {}).get(str(path))
    if (
        entry is not None
        and entry.get("mtime_ns") == st.st_mtime_ns
        and entry.get("size") == st.st_size
    ):
        return entry["sha256"]

    digest = _sha256_file_uncached(path)
    cache.setdefault("sha256", {})[str(path)] = {
        "mtime_ns": st.st_mtime_ns,
        "size": st.st_size,
        "sha256": digest,
    }
    _save_hash_cache(cache)
    return digest


def _vm_helper_version() -> str:
    """Ask safeyolo-vm for its version string. "unknown" on any failure --
    this field participates in the fingerprint, so two hosts running
    different helper versions won't share a snapshot even if we can't
    parse one side's version output.

    Cached by the helper binary's (path, mtime_ns, size). Avoids a
    ~50-100 ms Popen per agent run just to re-read a version constant.
    """
    try:
        helper = find_vm_helper()
    except Exception:
        return "unknown"

    try:
        st = helper.stat()
    except OSError:
        st = None

    cache = _load_hash_cache()
    helper_cache = cache.get("helper_version", {})
    entry = helper_cache.get(str(helper))
    if (
        st is not None
        and entry is not None
        and entry.get("mtime_ns") == st.st_mtime_ns
        and entry.get("size") == st.st_size
    ):
        return entry["version"]

    try:
        result = subprocess.run(
            [str(helper), "version"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    # Expected format: "safeyolo-vm 0.2.0"
    parts = result.stdout.strip().split()
    version = parts[-1] if parts else "unknown"

    if st is not None:
        cache.setdefault("helper_version", {})[str(helper)] = {
            "mtime_ns": st.st_mtime_ns,
            "size": st.st_size,
            "version": version,
        }
        _save_hash_cache(cache)
    return version


def compute_snapshot_version(
    *,
    memory_mb: int,
    cpus: int,
    gateway_ip: str,
    guest_ip: str,
) -> dict:
    """Hash everything that must match for a snapshot to be restorable.

    Any change to these inputs between capture and restore makes the
    snapshot invalid -- the guest would wake up inconsistent with its
    environment (different CA cert, different kernel, different IP, ...).
    """
    cli_dir = Path(__file__).parent
    static_script = cli_dir / "guest-init-static.sh"
    ca_cert = get_config_dir() / "certs" / "mitmproxy-ca-cert.pem"
    kernel = get_kernel_path()
    initrd = get_initrd_path()
    base_rootfs = get_base_rootfs_path()

    return {
        "snapshot_schema": SNAPSHOT_SCHEMA,
        "guest_init_static_sha256": _sha256_file(static_script),
        "ca_cert_sha256": _sha256_file(ca_cert) if ca_cert.exists() else "",
        "kernel_sha256": _sha256_file(kernel) if kernel.exists() else "",
        "initrd_sha256": _sha256_file(initrd) if initrd.exists() else "",
        "rootfs_base_sha256": _sha256_file(base_rootfs) if base_rootfs.exists() else "",
        "memory_mb": memory_mb,
        "cpus": cpus,
        "network_gateway_ip": gateway_ip,
        "network_guest_ip": guest_ip,
        "vm_helper_version": _vm_helper_version(),
    }


def write_snapshot_version(name: str, version: dict) -> None:
    path = snapshot_version_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(version, indent=2, sort_keys=True))


def is_snapshot_valid(name: str, expected: dict) -> bool:
    """True iff all four artefacts exist, the snapshot is above the
    corruption floor, and our version.json matches `expected` field-for-field.

    Strict: any mismatch returns False. Callers who get False should
    invalidate and recapture.
    """
    snap = snapshot_path(name)
    sidecar = snapshot_sidecar_path(name)
    rootfs_clone = snapshot_rootfs_clone_path(name)
    version = snapshot_version_path(name)

    for p in (snap, sidecar, rootfs_clone, version):
        if not p.exists():
            return False
    try:
        if snap.stat().st_size < MIN_SNAPSHOT_BYTES:
            return False
    except OSError:
        return False
    try:
        actual = json.loads(version.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return actual == expected


def invalidate_snapshot(name: str) -> None:
    """Best-effort delete of every snapshot artefact for an agent.
    Leaves the agent's other state (rootfs, config-share) alone.

    The `.run` working copy -- a per-restore clone of the pristine rootfs
    that start_vm creates so the restored VM doesn't corrupt the
    pristine clone -- is also removed here. It's recreated on the next
    restore and has no meaning after a snapshot is invalidated."""
    agent_dir = get_agents_dir() / name
    for path in (
        snapshot_path(name),
        snapshot_sidecar_path(name),
        snapshot_rootfs_clone_path(name),
        snapshot_version_path(name),
        agent_dir / "snapshot.bin.run",
    ):
        # missing_ok covers the common "already gone" case; any other
        # OSError (permission, EBUSY) should surface -- we own these
        # files, if unlink fails there's something the user needs to
        # know about (disk full, corrupted FS, manual chmod).
        path.unlink(missing_ok=True)


def platform_supports_snapshot() -> bool:
    """True on platforms where we can capture a VM snapshot today.

    Currently macOS 14+ (VZVirtualMachine.save is 14+). PR 5 will extend
    to Linux when runsc is available.
    """
    if _platform.system() != "Darwin":
        return False
    mac_ver = _platform.mac_ver()[0]
    if not mac_ver:
        return False
    try:
        major = int(mac_ver.split(".", 1)[0])
    except ValueError:
        return False
    return major >= 14
