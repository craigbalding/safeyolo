"""Tests for coord.nats_runtime — v1 substrate lifecycle module.

Three tiers:
  - unit: no subprocess, no network. Config content, permissions,
    credential idempotency, versioned paths, pidfile roundtrip.
  - subprocess: spawns a stand-in (sleep) to exercise ownership /
    reap paths without needing a nats-server binary.
  - integration: needs the nats-server binary. Downloads once per
    session via a shared cache dir; if download fails, integration
    tests are skipped rather than failed (network flakes shouldn't
    block unit-only runs).

Reviewer hardening pass regressions (per #371 comment):
  - #1 PID ownership: stale PID pointing to unrelated process is
    NOT signalled by stop_server.
  - #2 versioned binary path.
  - #3 failed-startup diagnostics: immediate child exit fails fast
    with log tail; timeout reaps child + cleans pidfile.
  - #4 tests for all of the above plus config content, permissions,
    unauthenticated connection rejected.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import time
from unittest.mock import patch

import pytest

from safeyolo.coord import nats_runtime as nr

# Fixtures (isolated_coord, _binary_cache, nats_env) live in
# conftest.py and are shared with test_coord_nats_client.py.


# ---------- unit ----------


class TestPathsAndCredentials:
    def test_binary_path_is_version_scoped(self, isolated_coord):
        """Reviewer #2: version bump gets a fresh install."""
        assert nr.NATS_VERSION in str(nr.nats_binary_path())
        with patch.object(nr, "NATS_VERSION", "9.9.9"):
            assert "9.9.9" in str(nr.nats_binary_path())

    def test_ensure_credentials_generates_once_and_persists(self, isolated_coord):
        pw1 = nr.ensure_credentials()
        pw2 = nr.ensure_credentials()
        assert pw1 == pw2
        assert len(pw1) == 64
        assert nr.nats_creds_path().stat().st_mode & 0o777 == 0o600

    def test_secure_dir_modes(self, isolated_coord):
        """Reviewer small fix: data dirs 0700, not default umask."""
        nr.write_config("safeyolo-test")
        assert nr.nats_root().stat().st_mode & 0o777 == 0o700
        assert nr.nats_data_path().stat().st_mode & 0o777 == 0o700


class TestConfig:
    def test_config_is_loopback_auth_and_sy_local(self, isolated_coord):
        path = nr.write_config("safeyolo-test-name")
        content = path.read_text()
        assert f"listen: {nr.NATS_LISTEN_HOST}:{nr.NATS_CLIENT_PORT}" in content
        assert f"http: {nr.NATS_LISTEN_HOST}:{nr.NATS_MONITOR_PORT}" in content
        assert "server_name: safeyolo-test-name" in content
        assert "SY_LOCAL" in content
        assert "jetstream: enabled" in content
        assert f"max_file_store: {nr.JETSTREAM_MAX_FILE_STORE}" in content
        # Reviewer small fix: no_auth_user directive removed as redundant
        assert "no_auth_user" not in content
        assert path.stat().st_mode & 0o777 == 0o600

    def test_config_embeds_credentials(self, isolated_coord):
        pw = nr.ensure_credentials()
        path = nr.write_config("safeyolo-test")
        assert pw in path.read_text()


class TestPidfile:
    def test_read_pidfile_absent_returns_none(self, isolated_coord):
        assert nr._read_pidfile() is None

    def test_read_pidfile_malformed_returns_none(self, isolated_coord):
        nr.nats_root().mkdir(parents=True, exist_ok=True)
        nr.nats_pid_path().write_text("not json\n")
        assert nr._read_pidfile() is None

    def test_read_pidfile_missing_fields_returns_none(self, isolated_coord):
        nr.nats_root().mkdir(parents=True, exist_ok=True)
        nr.nats_pid_path().write_text(json.dumps({"pid": 1234}) + "\n")
        assert nr._read_pidfile() is None

    def test_read_pidfile_without_server_id_returns_none(self, isolated_coord):
        """Reviewer round 2: pidfile without server_id can't prove
        ownership; older format must be treated as invalid."""
        nr.nats_root().mkdir(parents=True, exist_ok=True)
        nr.nats_pid_path().write_text(
            json.dumps({"pid": 1234, "server_name": "safeyolo-x"}) + "\n"
        )
        assert nr._read_pidfile() is None

    def test_write_and_read_pidfile_roundtrip(self, isolated_coord):
        nr._write_pidfile(12345, "safeyolo-abcd1234", "NDABCDEF123456", "/bin/nats-server")
        data = nr._read_pidfile()
        assert data is not None
        assert data["pid"] == 12345
        assert data["server_name"] == "safeyolo-abcd1234"
        assert data["server_id"] == "NDABCDEF123456"
        assert data["binary"] == "/bin/nats-server"
        assert isinstance(data["started_at"], int)
        assert nr.nats_pid_path().stat().st_mode & 0o777 == 0o600


# ---------- subprocess (no nats-server needed) ----------


class TestOwnershipSafety:
    """Reviewer #1: the sharpest hardening — stale PID reused by an
    unrelated host process must NEVER be signalled."""

    def test_stale_pid_pointing_to_unrelated_process_is_never_signalled(self, isolated_coord):
        victim = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            nr._write_pidfile(victim.pid, "safeyolo-not-real", "NDFAKE", "/opt/fake/nats-server")
            # /varz won't answer at all (victim isn't NATS) → ownership fails
            assert nr._verified_ownership() is None
            # stop_server must be a no-op cleanup, NOT a signal
            assert nr.stop_server() is False
            time.sleep(0.1)
            assert victim.poll() is None, "IMPOSTOR PROCESS WAS KILLED — pidfile trust bug"
            assert not nr.nats_pid_path().exists()
        finally:
            victim.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                victim.wait(timeout=5)

    def test_ownership_check_requires_matching_server_name(self, isolated_coord):
        """Even if PID is alive, wrong server_name means not-ours."""
        victim = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            nr._write_pidfile(victim.pid, "safeyolo-wrong", "NDFAKE", "/opt/fake")
            assert not nr.is_healthy()
            assert nr._verified_ownership() is None
        finally:
            victim.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                victim.wait(timeout=5)

    def test_ownership_check_requires_matching_server_id(self, nats_env):
        """Reviewer round 2 point 2: even when server_name matches (config
        replays it), server_id must also match. A restarted NATS with the
        same config gets a fresh server_id, and ownership fails cleanly."""
        from unittest.mock import patch
        nr.start_server(ready_timeout=8.0)
        try:
            stored = nr._read_pidfile()
            assert stored is not None
            # Patch /varz to return a DIFFERENT server_id — simulates a
            # nats-server restart under the same config, or a stale
            # pidfile plus another instance of the same server_name.
            with patch.object(nr, "_varz", return_value={
                "server_name": stored["server_name"],
                "server_id": "ND-DIFFERENT-ID",
            }):
                assert nr._verified_ownership() is None
                assert not nr.is_healthy()
        finally:
            nr.stop_server()


class TestReapChild:
    def test_reap_child_terminates_normal_process(self, isolated_coord):
        proc = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        nr._reap_child(proc, term_timeout=1.0, kill_timeout=1.0)
        assert proc.poll() is not None

    def test_reap_child_kills_sigterm_ignoring_process(self, isolated_coord):
        proc = subprocess.Popen(
            ["sh", "-c", "trap '' TERM; sleep 60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        nr._reap_child(proc, term_timeout=0.3, kill_timeout=2.0)
        assert proc.poll() is not None


# ---------- integration (needs nats-server binary) ----------


class TestLifecycleHappyPath:
    def test_start_verify_stop(self, nats_env):
        pid = nr.start_server(ready_timeout=8.0)
        try:
            assert nr.is_healthy()
            s = nr.status()
            assert s["pid"] == pid
            assert s["server_name"].startswith("safeyolo-")
            assert s["healthy"] is True
            assert s["actual_version"] == nr.NATS_VERSION
        finally:
            assert nr.stop_server() is True
        assert not nr.is_healthy()

    def test_second_start_is_idempotent(self, nats_env):
        pid1 = nr.start_server(ready_timeout=8.0)
        try:
            pid2 = nr.start_server(ready_timeout=8.0)
            assert pid2 == pid1
        finally:
            nr.stop_server()

    def test_stop_when_nothing_running_is_noop(self, nats_env):
        assert nr.stop_server() is False


class TestFailedStartupDiagnostics:
    def test_bad_config_causes_immediate_exit_with_log_tail(self, nats_env):
        """Reviewer #3: child exits immediately (bad config) — should
        raise fast with the log tail, not wait the full timeout."""
        def bad_config(server_name):
            path = nr.nats_config_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("this is deliberately not a valid nats config\n")
            path.chmod(0o600)
            return path

        t0 = time.monotonic()
        with patch.object(nr, "write_config", bad_config):
            with pytest.raises(RuntimeError) as exc:
                nr.start_server(ready_timeout=8.0)
        elapsed = time.monotonic() - t0
        assert elapsed < 4.0, f"immediate-exit should fail fast; took {elapsed:.1f}s"
        assert "exited immediately" in str(exc.value)
        assert "Log tail" in str(exc.value)
        assert not nr.nats_pid_path().exists()

    def test_startup_timeout_reaps_child_and_cleans_pidfile(self, nats_env):
        """Reviewer round 1 #3: on timeout the child is reaped + pidfile
        removed. /varz forced to return a mismatched name so startup
        never succeeds."""
        with patch.object(nr, "_varz", return_value={
            "server_name": "not-our-name", "server_id": "ND-X",
        }):
            with pytest.raises(TimeoutError):
                nr.start_server(ready_timeout=1.5)
        assert not nr.nats_pid_path().exists()
        assert not nr.is_healthy()

    def test_pidfile_write_failure_reaps_orphan_child(self, nats_env):
        """Reviewer round 2 P0: if _write_pidfile raises after Popen,
        the child MUST be reaped. Otherwise there's an unmanaged live
        nats-server with no ownership record — stop_server would refuse
        to signal it."""
        # Save the real _write_pidfile so we can observe the effective pid
        real_write = nr._write_pidfile
        captured_pid = {}

        def failing_write(pid, server_name, server_id, binary):
            captured_pid["pid"] = pid
            # Simulate disk full / chmod denied AFTER we know the PID
            raise OSError("simulated disk full")

        with patch.object(nr, "_write_pidfile", side_effect=failing_write):
            with pytest.raises(OSError, match="simulated disk full"):
                nr.start_server(ready_timeout=8.0)

        # Orphan reaped
        assert "pid" in captured_pid, "test setup issue: never reached _write_pidfile"
        pid = captured_pid["pid"]
        # Wait briefly for reap
        for _ in range(60):
            if not nr._pid_alive(pid):
                break
            time.sleep(0.05)
        # Even accounting for zombie: /varz must be gone
        for _ in range(60):
            if nr._varz() is None:
                break
            time.sleep(0.05)
        assert nr._varz() is None, "nats-server still running after _write_pidfile failure"
        # No pidfile left behind
        assert not nr.nats_pid_path().exists()
        # Restore for teardown
        # `real_write` and `_write_pidfile` restored by patch context exit;
        # captured_pid usage above is what mattered.
        _ = real_write


class TestConcurrentStart:
    """Adversarial: 5 threads race start_server on a fresh install.
    threading.Lock + fcntl.flock guarantee exactly one nats-server
    spawns, no port-conflict deaths, no orphaned pidfile."""

    def test_concurrent_starts_serialize_to_one_server(self, nats_env):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(nr.start_server, 8.0) for _ in range(5)]
            results = [f.result() for f in futures]
        try:
            # All 5 return the same PID
            assert len(set(results)) == 1, f"race produced multiple PIDs: {results}"
            # One healthy server
            assert nr.is_healthy()
            pf = nr._read_pidfile()
            assert pf is not None
            assert pf["pid"] == results[0]
        finally:
            nr.stop_server()


class TestBinaryChecksumOnExisting:
    """Adversarial: attacker who wrote to nats/bin/<version>/nats-server
    before SafeYolo's first ensure_binary() must NOT gain execution just
    because the file exists + is executable."""

    def test_existing_binary_wrong_checksum_rejected(self, isolated_coord):
        bp = nr.nats_binary_path()
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_bytes(b"#!/bin/sh\necho i-am-not-nats-server\n")
        bp.chmod(0o755)
        with pytest.raises(RuntimeError, match="SHA256"):
            nr.ensure_binary()

    def test_existing_binary_correct_checksum_accepted(self, nats_env):
        """Positive case: legitimate binary passes re-verification and
        is returned without re-downloading."""
        # nats_env fixture symlinked the cached (real) binary in already
        result = nr.ensure_binary()
        assert result == nr.nats_binary_path()


class TestPortCollisionFastFail:
    """Adversarial: another process already bound to 4222. nats-server
    exits immediately with a bind error; we should fast-fail with the
    log tail rather than hang the full ready_timeout."""

    def test_port_conflict_causes_fast_fail(self, nats_env):
        import socket
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind((nr.NATS_LISTEN_HOST, nr.NATS_CLIENT_PORT))
        squatter.listen(1)
        try:
            t0 = time.monotonic()
            with pytest.raises(RuntimeError):
                nr.start_server(ready_timeout=6.0)
            elapsed = time.monotonic() - t0
            assert elapsed < 4.0, f"port-conflict should fail fast; took {elapsed:.1f}s"
            assert not nr.nats_pid_path().exists()
        finally:
            squatter.close()


class TestExternalKillHygiene:
    """Adversarial: something else kills our nats-server. Next health
    check must return False; stop_server must be a clean no-op."""

    def test_external_sigkill_leaves_no_state(self, nats_env):
        pid = nr.start_server(ready_timeout=8.0)
        assert nr.is_healthy()
        os.kill(pid, 9)
        # Wait until the server stops responding on /varz. We can't rely on
        # _pid_alive because start_server's Popen isn't reaped in this test
        # scope so the killed process shows up as a zombie for a bit; the
        # meaningful signal is the ownership predicate, which requires a
        # live /varz answer.
        for _ in range(60):
            if nr._varz() is None:
                break
            time.sleep(0.05)
        # Ownership check fails cleanly
        assert not nr.is_healthy()
        # stop_server is a no-op (nothing ours to stop) AND cleans stale state
        assert nr.stop_server() is False
        assert not nr.nats_pid_path().exists()


class TestMaliciousTarball:
    """Adversarial: whatever the download path fetches, extraction must
    be safe. Defenses: filter='data' + manual name rewrite to the safe
    leaf 'nats-server' + isfile() check that excludes symlinks."""

    def _fake_download(self, monkeypatch, tarball_bytes: bytes):
        """Patch urllib to return `tarball_bytes` AND pin the archive
        checksum to match — otherwise the archive-checksum guard rejects
        our synthetic tarball before extraction and the test can't
        exercise the tar-parser defenses."""
        import hashlib
        import io
        class FakeResp:
            def __init__(self, data):
                self._buf = io.BytesIO(data)
            def read(self, n=-1):
                return self._buf.read(n)
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda url: FakeResp(tarball_bytes),
        )
        monkeypatch.setattr(
            nr, "_expected_archive_sha256",
            lambda: hashlib.sha256(tarball_bytes).hexdigest(),
        )

    def test_symlink_named_nats_server_rejected(self, isolated_coord, monkeypatch):
        """A symlink named nats-server pointing at /etc/passwd would let
        a chmod 0755 change the perms of the target if we treated it as
        a regular file. isfile() filter blocks it."""
        import io
        import tarfile as tf
        buf = io.BytesIO()
        with tf.open(fileobj=buf, mode="w:gz") as t:
            info = tf.TarInfo(name="release/nats-server")
            info.type = tf.SYMTYPE
            info.linkname = "/etc/passwd"
            info.size = 0
            t.addfile(info)
        self._fake_download(monkeypatch, buf.getvalue())
        with pytest.raises(RuntimeError, match="did not contain"):
            nr.ensure_binary()

    def test_path_traversal_member_extracted_safely(self, isolated_coord, monkeypatch):
        """A member named `../../etc/evil/nats-server` should be renamed
        to `nats-server` and land under nats_bin_dir, not outside it.
        The extracted-binary checksum then rejects it since it's fake."""
        import io
        import tarfile as tf
        buf = io.BytesIO()
        fake_binary = b"#!/bin/sh\necho fake\n"
        with tf.open(fileobj=buf, mode="w:gz") as t:
            info = tf.TarInfo(name="../../etc/evil/nats-server")
            info.size = len(fake_binary)
            info.mode = 0o755
            t.addfile(info, io.BytesIO(fake_binary))
        self._fake_download(monkeypatch, buf.getvalue())

        with pytest.raises(RuntimeError, match="checksum mismatch"):
            nr.ensure_binary()

        # Whatever landed on disk, it landed UNDER nats_bin_dir, not
        # outside it. And ensure_binary cleaned it up on the checksum
        # rejection path.
        assert not nr.nats_binary_path().exists()
        # Nothing escaped bin_dir
        for p in nr.nats_bin_dir().rglob("*"):
            assert str(p.resolve()).startswith(str(nr.nats_bin_dir().resolve()))


class TestUnauthenticatedRejected:
    """Reviewer #4 acceptance: prove mandatory auth is actually enforced,
    not just config-shaped."""

    def test_unauth_client_gets_authorization_violation(self, nats_env):
        pytest.importorskip("nats")
        import asyncio

        import nats
        nr.start_server(ready_timeout=8.0)
        try:
            async def probe():
                with pytest.raises(Exception) as exc:
                    await nats.connect(
                        nr.client_url(),
                        allow_reconnect=False,
                        max_reconnect_attempts=1,
                        connect_timeout=2.0,
                    )
                return exc
            exc = asyncio.run(probe())
            assert "uthorization" in str(exc.value)  # matches both cases
        finally:
            nr.stop_server()

    def test_auth_client_can_use_jetstream(self, nats_env):
        pytest.importorskip("nats")
        import asyncio

        import nats
        nr.start_server(ready_timeout=8.0)
        try:
            async def probe():
                user, pw = nr.client_user_credentials()
                nc = await nats.connect(nr.client_url(), user=user, password=pw)
                js = nc.jetstream()
                await js.add_stream(name="TEST_JS", subjects=["test.js"])
                ack = await js.publish("test.js", b"hello")
                assert ack.seq >= 1
                await js.delete_stream("TEST_JS")
                await nc.close()
            asyncio.run(probe())
        finally:
            nr.stop_server()
