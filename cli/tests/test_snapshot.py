"""Tests for snapshot.py -- version fingerprinting, validity checks,
invalidation, and platform gating.

These tests exercise the Python-side orchestration that sits on top of
the safeyolo-vm save/restore primitives from PR #133. They don't run a
real VM; the focus is on "is a given snapshot still restorable?" -- a
decision the CLI makes before it ever launches the helper.
"""

import json
import os
from pathlib import Path

import pytest

import safeyolo.snapshot as snap_mod
from safeyolo.snapshot import (
    MIN_SNAPSHOT_BYTES,
    SNAPSHOT_SCHEMA,
    compute_snapshot_version,
    invalidate_snapshot,
    is_snapshot_valid,
    platform_supports_snapshot,
    snapshot_path,
    snapshot_rootfs_clone_path,
    snapshot_sidecar_path,
    snapshot_version_path,
    write_snapshot_version,
)


@pytest.fixture
def agent_dir(tmp_config_dir):
    """~/.safeyolo/agents/agent1/ ready to receive snapshot artefacts."""
    agent_dir = tmp_config_dir / "agents" / "agent1"
    agent_dir.mkdir(parents=True)
    return agent_dir


@pytest.fixture
def snapshot_inputs(tmp_config_dir, monkeypatch):
    """Stub out everything compute_snapshot_version hashes so tests stay
    deterministic and don't depend on a real kernel/initrd on disk."""
    share = tmp_config_dir / "share"
    share.mkdir()
    (share / "Image").write_bytes(b"fake-kernel")
    (share / "initramfs.cpio.gz").write_bytes(b"fake-initrd")
    (share / "rootfs-base.ext4").write_bytes(b"fake-rootfs")
    (tmp_config_dir / "certs" / "mitmproxy-ca-cert.pem").write_bytes(b"fake-ca")

    monkeypatch.setattr(snap_mod, "get_kernel_path", lambda: share / "Image")
    monkeypatch.setattr(snap_mod, "get_initrd_path", lambda: share / "initramfs.cpio.gz")
    monkeypatch.setattr(snap_mod, "get_base_rootfs_path", lambda: share / "rootfs-base.ext4")
    monkeypatch.setattr(snap_mod, "_vm_helper_version", lambda: "0.2.0")
    return share


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


class TestSnapshotPaths:
    def test_snapshot_path_under_agent_dir(self, tmp_config_dir):
        assert snapshot_path("agent1") == tmp_config_dir / "agents" / "agent1" / "snapshot.bin"

    def test_sidecar_is_sibling_of_bin(self, tmp_config_dir):
        assert snapshot_sidecar_path("agent1") == tmp_config_dir / "agents" / "agent1" / "snapshot.bin.meta.json"

    def test_rootfs_clone_is_sibling_of_bin(self, tmp_config_dir):
        assert snapshot_rootfs_clone_path("agent1") == tmp_config_dir / "agents" / "agent1" / "snapshot.bin.rootfs"

    def test_version_is_sibling_of_bin(self, tmp_config_dir):
        assert snapshot_version_path("agent1") == tmp_config_dir / "agents" / "agent1" / "snapshot.version.json"


# ---------------------------------------------------------------------------
# compute_snapshot_version
# ---------------------------------------------------------------------------


class TestComputeSnapshotVersion:
    def test_is_deterministic(self, snapshot_inputs):
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="1.1.1.1", guest_ip="1.1.1.2")
        v2 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="1.1.1.1", guest_ip="1.1.1.2")
        assert v1 == v2

    def test_includes_schema_field(self, snapshot_inputs):
        v = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        assert v["snapshot_schema"] == SNAPSHOT_SCHEMA

    def test_memory_changes_invalidate(self, snapshot_inputs):
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        v2 = compute_snapshot_version(memory_mb=8192, cpus=4, gateway_ip="x", guest_ip="y")
        assert v1 != v2

    def test_cpus_change_invalidates(self, snapshot_inputs):
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        v2 = compute_snapshot_version(memory_mb=4096, cpus=8, gateway_ip="x", guest_ip="y")
        assert v1 != v2

    def test_gateway_ip_change_invalidates(self, snapshot_inputs):
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="10.0.0.1", guest_ip="10.0.0.2")
        v2 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="10.0.0.99", guest_ip="10.0.0.2")
        assert v1 != v2

    def test_static_script_content_change_invalidates(self, snapshot_inputs, monkeypatch, tmp_path):
        """Changing guest-init-static.sh on disk must yield a different
        fingerprint -- the script runs inside the snapshot, so stale
        captured state would diverge from what the new script expects."""
        fake_cli_dir = tmp_path / "fakepkg"
        fake_cli_dir.mkdir()
        script = fake_cli_dir / "guest-init-static.sh"
        script.write_text("v1")
        # Force distinct mtimes so the hash cache doesn't treat these as
        # the same file (same size + same mtime + same path → cache hit).
        # Real edits always change mtime; the test just compresses that.
        os.utime(script, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
        monkeypatch.setattr(snap_mod, "__file__", str(fake_cli_dir / "snapshot.py"))
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")

        script.write_text("v2")
        os.utime(script, ns=(2_000_000_000_000_000_000, 2_000_000_000_000_000_000))
        v2 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        assert v1 != v2

    def test_kernel_change_invalidates(self, snapshot_inputs):
        v1 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        (snapshot_inputs / "Image").write_bytes(b"different-kernel")
        v2 = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        assert v1 != v2



# ---------------------------------------------------------------------------
# _sha256_file hash cache
# ---------------------------------------------------------------------------


class TestSha256FileCache:
    """Caching hot-path: kernel/initrd/rootfs hashes rarely change but are
    recomputed on every `safeyolo agent run`. Cache by (path, mtime_ns, size)
    so the common-case run hits cache and avoids reading GB of rootfs."""

    def _write_file_with_mtime(self, path: Path, content: bytes, mtime_ns: int) -> None:
        path.write_bytes(content)
        os.utime(path, ns=(mtime_ns, mtime_ns))

    def test_first_call_computes_and_caches(self, tmp_config_dir, tmp_path):
        from safeyolo.snapshot import _hash_cache_path, _sha256_file

        f = tmp_path / "big.bin"
        self._write_file_with_mtime(f, b"hello", 1_000_000_000_000_000_000)

        digest1 = _sha256_file(f)

        cache = json.loads(_hash_cache_path().read_text())
        entry = cache["sha256"][str(f)]
        assert entry["sha256"] == digest1
        assert entry["mtime_ns"] == 1_000_000_000_000_000_000
        assert entry["size"] == 5

    def test_second_call_does_not_read_file(self, tmp_config_dir, tmp_path, monkeypatch):
        """If cache key matches, the file is never opened. This is the
        load-bearing assertion -- the whole point is skipping the I/O."""
        from safeyolo.snapshot import _sha256_file

        f = tmp_path / "big.bin"
        self._write_file_with_mtime(f, b"hello", 1_000_000_000_000_000_000)

        _sha256_file(f)  # populate cache

        # Now spy on open() at the module level: any attempt to open the
        # tracked file on the second call would be a cache miss.
        import safeyolo.snapshot as snap_mod
        real_uncached = snap_mod._sha256_file_uncached
        def should_not_run(p):
            raise AssertionError(f"cache miss -- _sha256_file_uncached called on {p}")
        monkeypatch.setattr(snap_mod, "_sha256_file_uncached", should_not_run)

        digest2 = _sha256_file(f)  # must NOT call the uncached path
        # Sanity: same answer as the first call.
        # Restore for anything else the test suite might do.
        monkeypatch.setattr(snap_mod, "_sha256_file_uncached", real_uncached)
        assert digest2 == _sha256_file(f)

    def test_mtime_change_invalidates_cache(self, tmp_config_dir, tmp_path):
        from safeyolo.snapshot import _sha256_file

        f = tmp_path / "big.bin"
        self._write_file_with_mtime(f, b"hello", 1_000_000_000_000_000_000)
        digest1 = _sha256_file(f)

        # Simulate a rebuild: content AND mtime change.
        self._write_file_with_mtime(f, b"world", 2_000_000_000_000_000_000)
        digest2 = _sha256_file(f)
        assert digest1 != digest2

    def test_size_change_invalidates_cache(self, tmp_config_dir, tmp_path):
        """mtime-preserving edits (rare but possible with `touch -t`) are
        caught by the size check."""
        from safeyolo.snapshot import _sha256_file

        f = tmp_path / "big.bin"
        self._write_file_with_mtime(f, b"hello", 1_000_000_000_000_000_000)
        digest1 = _sha256_file(f)

        # Different content AND different size, same mtime.
        self._write_file_with_mtime(f, b"hello-longer", 1_000_000_000_000_000_000)
        digest2 = _sha256_file(f)
        assert digest1 != digest2

    def test_corrupt_cache_file_is_tolerated(self, tmp_config_dir, tmp_path):
        """A garbage cache file shouldn't break hashing -- just redo the
        work and rewrite."""
        from safeyolo.snapshot import _hash_cache_path, _sha256_file

        _hash_cache_path().parent.mkdir(parents=True, exist_ok=True)
        _hash_cache_path().write_text("{not json")

        f = tmp_path / "big.bin"
        self._write_file_with_mtime(f, b"hello", 1_000_000_000_000_000_000)
        digest = _sha256_file(f)  # must not raise

        # Cache file should be rewritten with valid JSON.
        cache = json.loads(_hash_cache_path().read_text())
        assert cache["sha256"][str(f)]["sha256"] == digest


# ---------------------------------------------------------------------------
# is_snapshot_valid
# ---------------------------------------------------------------------------


class TestIsSnapshotValid:
    def _write_full_snapshot(self, agent_dir: Path, name: str, version: dict, size: int) -> None:
        """All four artefacts present + version.json matches."""
        (agent_dir / "snapshot.bin").write_bytes(b"x" * size)
        (agent_dir / "snapshot.bin.meta.json").write_text("{}")
        (agent_dir / "snapshot.bin.rootfs").write_bytes(b"rootfs-clone")
        (agent_dir / "snapshot.version.json").write_text(json.dumps(version))

    def test_all_present_and_matching_is_valid(self, agent_dir, snapshot_inputs):
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, MIN_SNAPSHOT_BYTES + 1)
        assert is_snapshot_valid("agent1", version) is True

    def test_missing_snapshot_bin_is_invalid(self, agent_dir, snapshot_inputs):
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, MIN_SNAPSHOT_BYTES + 1)
        (agent_dir / "snapshot.bin").unlink()
        assert is_snapshot_valid("agent1", version) is False

    def test_missing_rootfs_clone_is_invalid(self, agent_dir, snapshot_inputs):
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, MIN_SNAPSHOT_BYTES + 1)
        (agent_dir / "snapshot.bin.rootfs").unlink()
        assert is_snapshot_valid("agent1", version) is False

    def test_missing_sidecar_is_invalid(self, agent_dir, snapshot_inputs):
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, MIN_SNAPSHOT_BYTES + 1)
        (agent_dir / "snapshot.bin.meta.json").unlink()
        assert is_snapshot_valid("agent1", version) is False

    def test_mismatched_version_is_invalid(self, agent_dir, snapshot_inputs):
        """Version.json on disk differs from what the CLI computed now
        (e.g., memory was bumped between runs) -- snapshot is stale."""
        saved = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", saved, MIN_SNAPSHOT_BYTES + 1)
        current = compute_snapshot_version(memory_mb=8192, cpus=4, gateway_ip="x", guest_ip="y")
        assert is_snapshot_valid("agent1", current) is False

    def test_tiny_snapshot_is_invalid(self, agent_dir, snapshot_inputs):
        """Files exist but snapshot.bin is below the corruption floor --
        almost certainly a partial write. Treat as invalid."""
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, 1024)  # 1 KiB
        assert is_snapshot_valid("agent1", version) is False

    def test_corrupt_version_json_is_invalid(self, agent_dir, snapshot_inputs):
        """A non-JSON version file shouldn't crash is_snapshot_valid;
        it should cleanly fail the validity check."""
        version = compute_snapshot_version(memory_mb=4096, cpus=4, gateway_ip="x", guest_ip="y")
        self._write_full_snapshot(agent_dir, "agent1", version, MIN_SNAPSHOT_BYTES + 1)
        (agent_dir / "snapshot.version.json").write_text("{not json")
        assert is_snapshot_valid("agent1", version) is False


# ---------------------------------------------------------------------------
# invalidate_snapshot
# ---------------------------------------------------------------------------


class TestInvalidateSnapshot:
    def test_removes_all_four_artefacts(self, agent_dir):
        for name in ("snapshot.bin", "snapshot.bin.meta.json",
                     "snapshot.bin.rootfs", "snapshot.version.json"):
            (agent_dir / name).write_text("x")
        invalidate_snapshot("agent1")
        for name in ("snapshot.bin", "snapshot.bin.meta.json",
                     "snapshot.bin.rootfs", "snapshot.version.json"):
            assert not (agent_dir / name).exists()

    def test_is_no_op_when_nothing_exists(self, agent_dir):
        """Running invalidate before any capture has happened must not
        raise -- the CLI calls this unconditionally in capture-mode
        preparation."""
        invalidate_snapshot("agent1")  # no artefacts yet

    def test_leaves_unrelated_files_alone(self, agent_dir):
        """Invalidate must not touch rootfs.ext4, config-share, etc."""
        (agent_dir / "rootfs.ext4").write_text("live-rootfs")
        (agent_dir / "vm.pid").write_text("12345")
        (agent_dir / "snapshot.bin").write_text("x")
        invalidate_snapshot("agent1")
        assert (agent_dir / "rootfs.ext4").exists()
        assert (agent_dir / "vm.pid").exists()


# ---------------------------------------------------------------------------
# write_snapshot_version
# ---------------------------------------------------------------------------


class TestWriteSnapshotVersion:
    def test_writes_pretty_sorted_json(self, agent_dir):
        version = {"b": 2, "a": 1, "snapshot_schema": 1}
        write_snapshot_version("agent1", version)
        content = (agent_dir / "snapshot.version.json").read_text()
        loaded = json.loads(content)
        assert loaded == version
        # Sorted keys so diffs are readable.
        lines = content.splitlines()
        assert lines[1].lstrip().startswith('"a":')

    def test_creates_parent_dir_if_missing(self, tmp_config_dir):
        """write_snapshot_version must not assume the agent dir already
        exists -- first-ever run might race against directory creation."""
        # Agent dir intentionally does NOT exist yet.
        write_snapshot_version("fresh-agent", {"snapshot_schema": 1})
        assert (tmp_config_dir / "agents" / "fresh-agent" / "snapshot.version.json").exists()


# ---------------------------------------------------------------------------
# platform_supports_snapshot
# ---------------------------------------------------------------------------


class TestPlatformSupportsSnapshot:
    def test_darwin_14_supported(self, monkeypatch):
        import platform as pymod
        monkeypatch.setattr(pymod, "system", lambda: "Darwin")
        monkeypatch.setattr(pymod, "mac_ver", lambda: ("14.2.1", ("", "", ""), ""))
        assert platform_supports_snapshot() is True

    def test_darwin_15_supported(self, monkeypatch):
        import platform as pymod
        monkeypatch.setattr(pymod, "system", lambda: "Darwin")
        monkeypatch.setattr(pymod, "mac_ver", lambda: ("15.0", ("", "", ""), ""))
        assert platform_supports_snapshot() is True

    def test_darwin_13_not_supported(self, monkeypatch):
        """VZVirtualMachine.save requires macOS 14+ -- older hosts must
        fall through to cold boot."""
        import platform as pymod
        monkeypatch.setattr(pymod, "system", lambda: "Darwin")
        monkeypatch.setattr(pymod, "mac_ver", lambda: ("13.6.1", ("", "", ""), ""))
        assert platform_supports_snapshot() is False

    def test_linux_not_supported_yet(self, monkeypatch):
        """PR 5 will add runsc checkpoint; until then Linux cold-boots."""
        import platform as pymod
        monkeypatch.setattr(pymod, "system", lambda: "Linux")
        assert platform_supports_snapshot() is False

    def test_empty_mac_ver_handled(self, monkeypatch):
        """mac_ver() can return empty string on some platforms/errors --
        must not raise."""
        import platform as pymod
        monkeypatch.setattr(pymod, "system", lambda: "Darwin")
        monkeypatch.setattr(pymod, "mac_ver", lambda: ("", ("", "", ""), ""))
        assert platform_supports_snapshot() is False
