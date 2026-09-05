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
import hmac
import io
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from safeyolo.coord import nats_runtime as nr

# Fixtures (isolated_coord, _binary_cache, nats_env) live in
# conftest.py and are shared with test_coord_nats_client.py.

_PARALLEL_SERVER = r"""
import json
import os
import time
from pathlib import Path

from safeyolo.coord import nats_runtime as nr

pid = nr.start_server(ready_timeout=8.0)
stored = nr._read_pidfile()
assert stored is not None
barrier = Path(os.environ["SAFEYOLO_NATS_TEST_BARRIER"])
(barrier / f"{os.environ['SAFEYOLO_NATS_TEST_INSTANCE']}.ready").write_text("ready\n")
deadline = time.monotonic() + 8.0
try:
    while len(list(barrier.glob("*.ready"))) < 2:
        if time.monotonic() >= deadline:
            raise TimeoutError("parallel test peer did not start")
        time.sleep(0.02)
    assert nr.is_healthy()
finally:
    nr.stop_server()
print(json.dumps(stored), flush=True)
"""


# ---------- unit ----------


class TestPathsAndCredentials:
    @pytest.mark.parametrize(
        ("state", "expected"),
        [("R", True), ("S", True), ("Z", False)],
    )
    def test_pid_alive_uses_linux_proc_state(
        self, isolated_coord, state, expected
    ):
        with (
            patch.object(nr.os, "kill", autospec=True),
            patch.object(nr.platform, "system", autospec=True, return_value="Linux"),
            patch.object(
                nr.Path,
                "read_text",
                autospec=True,
                return_value=f"123 (nats server) {state} 1 2 3\n",
            ),
        ):
            assert nr._pid_alive(123) is expected

    def test_pid_alive_reports_missing_linux_proc_entry_dead(
        self, isolated_coord
    ):
        with (
            patch.object(nr.os, "kill", autospec=True),
            patch.object(nr.platform, "system", autospec=True, return_value="Linux"),
            patch.object(
                nr.Path,
                "read_text",
                autospec=True,
                side_effect=FileNotFoundError,
            ),
        ):
            assert nr._pid_alive(123) is False

    @pytest.mark.parametrize("stat_result", [PermissionError, "malformed"])
    def test_pid_alive_is_conservative_when_proc_state_is_unknown(
        self, isolated_coord, stat_result
    ):
        read_kwargs = (
            {"side_effect": stat_result}
            if isinstance(stat_result, type) and issubclass(stat_result, OSError)
            else {"return_value": stat_result}
        )
        with (
            patch.object(nr.os, "kill", autospec=True),
            patch.object(nr.platform, "system", autospec=True, return_value="Linux"),
            patch.object(nr.Path, "read_text", autospec=True, **read_kwargs),
        ):
            assert nr._pid_alive(123) is True

    def test_test_mode_refuses_operator_home_state(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", "owned-test")
        monkeypatch.delenv("SAFEYOLO_COORD_DATA_DIR", raising=False)

        with pytest.raises(RuntimeError, match="default coord state"):
            nr.nats_root()

        assert not (fake_home / ".safeyolo").exists()

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

    def test_ensure_credentials_publishes_atomically_under_race(self, isolated_coord):
        with ThreadPoolExecutor(max_workers=16) as pool:
            passwords = list(pool.map(lambda _: nr.ensure_credentials(), range(64)))

        assert len(set(passwords)) == 1
        assert nr.read_credentials() == passwords[0]
        assert nr.nats_creds_path().stat().st_mode & 0o777 == 0o600
        assert list(nr.nats_root().glob(".creds.*.tmp")) == []

    def test_missing_credential_regenerates_without_leaking_it(
        self, isolated_coord
    ):
        original = nr.ensure_credentials()
        nr.nats_creds_path().unlink()

        replacement = nr.ensure_credentials()

        if hmac.compare_digest(original, replacement):
            pytest.fail("missing NATS credential was not regenerated")
        assert nr.read_credentials() == replacement
        assert nr.nats_creds_path().stat().st_mode & 0o777 == 0o600

    def test_secure_dir_modes(self, isolated_coord):
        """Reviewer small fix: data dirs 0700, not default umask."""
        nr.write_config("safeyolo-test")
        assert nr.nats_root().stat().st_mode & 0o777 == 0o700
        assert nr.nats_data_path().stat().st_mode & 0o777 == 0o700

    def test_wedged_stop_does_not_emit_runbook_success_signal(
        self, isolated_coord
    ):
        """The manual-rotation guard must fail closed on a caught wedge."""
        from rich.console import Console

        from safeyolo.commands import lifecycle

        credential = nr.ensure_credentials()
        output = io.StringIO()
        with (
            patch.object(
                nr,
                "stop_server",
                autospec=True,
                side_effect=nr.WedgedNatsServer("simulated ownership wedge"),
            ),
            patch.object(
                lifecycle,
                "console",
                Console(file=output, color_system=None),
            ),
        ):
            lifecycle._stop_coord_best_effort()

        rendered = output.getvalue()
        assert "coord message plane stopped" not in rendered
        assert "simulated ownership wedge" in rendered
        assert nr.nats_creds_path().exists()
        if credential in rendered:
            pytest.fail("caught stop failure printed the raw NATS credential")


class TestConfig:
    def test_config_is_loopback_auth_and_sy_local(self, isolated_coord):
        path = nr.write_config("safeyolo-test-name")
        content = path.read_text()
        assert f"listen: {nr.NATS_LISTEN_HOST}:-1" in content
        assert f"http: {nr.NATS_LISTEN_HOST}:-1" in content
        assert "server_name: safeyolo-test-name" in content
        assert "SY_LOCAL" in content
        assert "jetstream: enabled" in content
        assert f"max_file_store: {nr.JETSTREAM_MAX_FILE_STORE}" in content
        # Reviewer small fix: no_auth_user directive removed as redundant
        assert "no_auth_user" not in content
        assert path.stat().st_mode & 0o777 == 0o600

    def test_production_ports_remain_fixed_defaults(
        self, isolated_coord, monkeypatch
    ):
        monkeypatch.delenv("SAFEYOLO_NATS_TEST_INSTANCE")

        path = nr.write_config("safeyolo-production-shape")
        content = path.read_text()

        assert f"listen: {nr.NATS_LISTEN_HOST}:{nr.NATS_CLIENT_PORT}" in content
        assert f"http: {nr.NATS_LISTEN_HOST}:{nr.NATS_MONITOR_PORT}" in content
        assert nr.client_url() == "nats://127.0.0.1:4222"

    def test_config_references_runtime_credential_environment(self, isolated_coord):
        pw = nr.ensure_credentials()
        path = nr.write_config("safeyolo-test")
        content = path.read_text()
        assert pw not in content
        assert "password: $SAFEYOLO_NATS_PASSWORD" in content


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
            # Reviewer round-4 wedge-guard: PID alive + ownership unverified
            # means "either wedged owned NATS or impostor on our port" —
            # both are dangerous to silently paper over. stop_server must
            # raise rather than either signal the victim or wipe the
            # pidfile we can't confirm is stale.
            with pytest.raises(nr.WedgedNatsServer):
                nr.stop_server()
            time.sleep(0.1)
            assert victim.poll() is None, "IMPOSTOR PROCESS WAS KILLED — pidfile trust bug"
            # Pidfile preserved so the operator can see what state we found
            # rather than us silently orphaning it.
            assert nr.nats_pid_path().exists()
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
            with patch.object(nr, "_varz", autospec=True, return_value={
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

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux proc zombie state")
    def test_later_process_observes_zombie_without_reaping_it(self, isolated_coord):
        """A later CLI sees completed exit while the parent retains reap ownership."""
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        try:
            os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
            os.kill(proc.pid, 0)
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from safeyolo.coord.nats_runtime import _wait_for_pid_exit; "
                    f"assert _wait_for_pid_exit({proc.pid}, 0) == (True, False)",
                ],
                check=True,
                timeout=5,
            )
            assert nr._wait_for_pid_exit(proc.pid, 0) == (True, True)
        finally:
            proc.wait(timeout=5)

    def test_wait_for_pid_exit_reaps_same_process_child(self, isolated_coord):
        proc = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        reaped = False
        try:
            assert nr._wait_for_pid_exit(proc.pid, 0) == (False, True)
            proc.terminate()
            assert nr._wait_for_pid_exit(proc.pid, 1.0) == (True, True)
            reaped = True
            assert not nr._pid_alive(proc.pid)
            with pytest.raises(ChildProcessError):
                os.waitpid(proc.pid, os.WNOHANG)
        finally:
            if not reaped:
                nr._reap_child(proc, term_timeout=1.0, kill_timeout=1.0)

    def test_stop_reaps_sigterm_ignoring_child(self, isolated_coord):
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); time.sleep(60)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline() == "ready\n"
            nr._write_pidfile(proc.pid, "safeyolo-test", "NDTEST", "/test/nats-server")
            verified = nr._read_pidfile()
            assert verified is not None
            real_kill = os.kill
            with (
                patch.object(
                    nr, "_verified_ownership", autospec=True, return_value=verified
                ),
                patch.object(nr, "_STOP_TERM_TIMEOUT_S", 0.1),
                patch.object(
                    nr.os, "kill", autospec=True, wraps=real_kill
                ) as kill,
            ):
                assert nr._stop_server_locked() is True
            signals = [entry.args[1] for entry in kill.call_args_list]
            assert signal.SIGTERM in signals
            assert signal.SIGKILL in signals
            assert not nr._pid_alive(proc.pid)
            assert not nr.nats_pid_path().exists()
            with pytest.raises(ChildProcessError):
                os.waitpid(proc.pid, os.WNOHANG)
        finally:
            if nr._pid_alive(proc.pid):
                nr._reap_child(proc, term_timeout=0.1, kill_timeout=1.0)

    @pytest.mark.parametrize("alive,exited", [(True, False), (False, True)])
    def test_wait_for_pid_exit_falls_back_for_non_child(
        self, isolated_coord, alive, exited
    ):
        with (
            patch.object(
                nr.os, "waitpid", autospec=True, side_effect=ChildProcessError
            ),
            patch.object(
                nr, "_pid_alive", autospec=True, return_value=alive
            ) as pid_alive,
        ):
            assert nr._wait_for_pid_exit(12345, 0) == (exited, False)
        pid_alive.assert_called_once_with(12345)

    def test_stop_timeout_preserves_pidfile_and_raises(self, isolated_coord):
        nr._write_pidfile(12345, "safeyolo-test", "NDTEST", "/test/nats-server")
        verified = nr._read_pidfile()
        assert verified is not None
        with (
            patch.object(
                nr, "_verified_ownership", autospec=True, return_value=verified
            ),
            patch.object(
                nr, "_wait_for_pid_exit", autospec=True, return_value=(False, True)
            ),
            patch.object(nr.os, "kill", autospec=True) as kill,
            pytest.raises(nr.WedgedNatsServer, match="remains present after SIGKILL"),
        ):
            nr.stop_server()

        assert [entry.args for entry in kill.call_args_list] == [
            (12345, signal.SIGTERM),
            (12345, signal.SIGKILL),
        ]
        assert nr.nats_pid_path().exists()

    def test_stop_refuses_sigkill_after_non_child_ownership_loss(
        self, isolated_coord
    ):
        nr._write_pidfile(12345, "safeyolo-test", "NDTEST", "/test/nats-server")
        verified = nr._read_pidfile()
        assert verified is not None
        with (
            patch.object(
                nr,
                "_verified_ownership",
                autospec=True,
                side_effect=[verified, None],
            ),
            patch.object(
                nr, "_wait_for_pid_exit", autospec=True, return_value=(False, False)
            ),
            patch.object(nr.os, "kill", autospec=True) as kill,
            pytest.raises(nr.WedgedNatsServer, match="can no longer be verified"),
        ):
            nr.stop_server()

        assert [entry.args for entry in kill.call_args_list] == [
            (12345, signal.SIGTERM),
        ]
        assert nr.nats_pid_path().exists()


# ---------- integration (needs nats-server binary) ----------


class TestLifecycleHappyPath:
    def test_start_verify_stop(self, nats_env):
        default_before = nr._varz(monitor_port=nr.NATS_MONITOR_PORT)
        pid = nr.start_server(ready_timeout=8.0)
        try:
            assert nr.is_healthy()
            s = nr.status()
            stored = nr._read_pidfile()
            assert stored is not None
            assert s["pid"] == pid
            assert s["server_name"].startswith(
                f"safeyolo-test-{os.environ['SAFEYOLO_NATS_TEST_INSTANCE']}-"
            )
            assert s["healthy"] is True
            assert s["actual_version"] == nr.NATS_VERSION
            assert stored["test_instance"] == os.environ[
                "SAFEYOLO_NATS_TEST_INSTANCE"
            ]
            assert stored["client_port"] not in {
                nr.NATS_CLIENT_PORT,
                nr.NATS_MONITOR_PORT,
            }
            assert stored["monitor_port"] not in {
                nr.NATS_CLIENT_PORT,
                nr.NATS_MONITOR_PORT,
            }
            assert stored["client_port"] != stored["monitor_port"]
            assert s["listen"] == (
                f"{nr.NATS_LISTEN_HOST}:{stored['client_port']}"
            )
            assert nr.client_url() == (
                f"nats://{nr.NATS_LISTEN_HOST}:{stored['client_port']}"
            )
            assert nr.nats_root().is_relative_to(nats_env)
            assert nr._varz(monitor_port=nr.NATS_MONITOR_PORT) == default_before
        finally:
            started = time.monotonic()
            assert nr.stop_server() is True
            elapsed = time.monotonic() - started
            assert elapsed < 2.0, f"same-process stop took {elapsed:.1f}s"
        assert not nr._pid_alive(pid)
        assert nr._varz() is None
        assert nr._varz(monitor_port=nr.NATS_MONITOR_PORT) == default_before
        assert list(nr.nats_ports_dir().glob("*.ports")) == []
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
        assert not nr.is_healthy()

    def test_stop_server_started_by_prior_process(self, nats_env):
        starter = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os; "
                "from safeyolo.coord import nats_runtime as nr; "
                "pid = nr.start_server(ready_timeout=8.0); "
                "print(pid, flush=True); os.waitpid(pid, 0)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert starter.stdout is not None
            pid = int(starter.stdout.readline().strip())
            assert nr._pid_alive(pid)
            with pytest.raises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

            assert nr.stop_server() is True
            assert not nr._pid_alive(pid)
            assert nr._varz() is None
            with pytest.raises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
            stdout, stderr = starter.communicate(timeout=5)
            assert starter.returncode == 0, stderr
            assert stdout == ""
        finally:
            with contextlib.suppress(nr.WedgedNatsServer):
                nr.stop_server()
            if starter.poll() is None:
                starter.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    starter.wait(timeout=5)

    def test_second_start_is_idempotent(self, nats_env):
        pid1 = nr.start_server(ready_timeout=8.0)
        try:
            pid2 = nr.start_server(ready_timeout=8.0)
            assert pid2 == pid1
        finally:
            nr.stop_server()

    def test_stop_when_nothing_running_is_noop(self, nats_env):
        assert nr.stop_server() is False

    @pytest.mark.timeout(30)
    def test_parallel_test_instances_use_disjoint_real_endpoints(
        self, tmp_path, _binary_cache
    ):
        barrier = tmp_path / "barrier"
        barrier.mkdir()
        children = []
        environments = []
        for index in range(2):
            coord_dir = tmp_path / f"coord-{index}"
            binary = (
                coord_dir
                / "nats"
                / "bin"
                / nr.NATS_VERSION
                / "nats-server"
            )
            binary.parent.mkdir(parents=True)
            os.symlink(_binary_cache, binary)
            environment = os.environ.copy()
            environment["SAFEYOLO_COORD_DATA_DIR"] = str(coord_dir)
            environment["SAFEYOLO_NATS_TEST_INSTANCE"] = f"parallel-{index}"
            environment["SAFEYOLO_NATS_TEST_BARRIER"] = str(barrier)
            environments.append(environment)
            children.append(
                subprocess.Popen(
                    [sys.executable, "-c", _PARALLEL_SERVER],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
            )

        results = []
        try:
            for child in children:
                stdout, stderr = child.communicate(timeout=20)
                assert child.returncode == 0, stderr
                results.append(json.loads(stdout.strip().splitlines()[-1]))
        finally:
            for child, environment in zip(children, environments, strict=True):
                if child.poll() is None:
                    child.terminate()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        child.wait(timeout=5)
                subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "from safeyolo.coord import nats_runtime as nr; "
                        "nr.stop_server(); "
                        "nr.nats_test_endpoints_path().unlink(missing_ok=True)",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    env=environment,
                )

        assert results[0]["test_instance"] != results[1]["test_instance"]
        assert results[0]["server_name"] != results[1]["server_name"]
        first_ports = {
            results[0]["client_port"],
            results[0]["monitor_port"],
        }
        second_ports = {
            results[1]["client_port"],
            results[1]["monitor_port"],
        }
        assert first_ports.isdisjoint(second_ports)


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
        with patch.object(nr, "_varz", autospec=True, return_value={
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

        def failing_write(pid, server_name, server_id, binary, **_kwargs):
            captured_pid["pid"] = pid
            # Simulate disk full / chmod denied AFTER we know the PID
            raise OSError("simulated disk full")

        with patch.object(
            nr, "_write_pidfile", autospec=True, side_effect=failing_write
        ):
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
        # The process may already be a zombie; /varz must also be gone.
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
    """A forced collision still fails fast without using a fixed port."""

    def test_port_conflict_causes_fast_fail(self, nats_env):
        import socket
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind((nr.NATS_LISTEN_HOST, 0))
        squatter.listen(1)
        collision_port = squatter.getsockname()[1]
        real_write_config = nr.write_config

        def colliding_config(server_name):
            path = real_write_config(server_name)
            content = path.read_text().replace(
                f"listen: {nr.NATS_LISTEN_HOST}:-1",
                f"listen: {nr.NATS_LISTEN_HOST}:{collision_port}",
            )
            path.write_text(content)
            return path

        try:
            t0 = time.monotonic()
            with (
                patch.object(
                    nr,
                    "write_config",
                    autospec=True,
                    side_effect=colliding_config,
                ),
                pytest.raises(RuntimeError),
            ):
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
        # Wait until the process exits (not just stops answering /varz), then
        # reap it when possible so this test does not leave a zombie behind.
        for _ in range(60):
            try:
                gone_pid, _ = os.waitpid(pid, os.WNOHANG)
                if gone_pid == pid:
                    break
            except ChildProcessError:
                break
            time.sleep(0.05)
        for _ in range(60):
            if not nr._pid_alive(pid) and nr._varz() is None:
                break
            time.sleep(0.05)
        # Ownership check fails cleanly
        assert not nr.is_healthy()
        # Process is no longer runnable, so stop_server clears the stale
        # pidfile and returns False.
        assert nr.stop_server() is False
        assert not nr.nats_pid_path().exists()

    def test_pid_alive_but_varz_wedged_refuses_to_orphan(self, nats_env):
        """Reviewer round-4 unhealthy-stop edge: when the pidfile PID is
        alive but /varz cannot confirm ownership (transient monitor
        issue, impostor on our port, or genuine wedge), stop_server must
        NOT delete the pidfile. Silently orphaning it would turn a
        wedged owned NATS into an unmanaged host process."""
        from unittest.mock import patch
        nr.start_server(ready_timeout=8.0)
        try:
            stored = nr._read_pidfile()
            assert stored is not None
            # Simulate /varz down while our nats-server is still running.
            with patch.object(nr, "_varz", autospec=True, return_value=None):
                with pytest.raises(nr.WedgedNatsServer):
                    nr.stop_server()
                # Pidfile survives; the operator can inspect it.
                assert nr.nats_pid_path().exists()
        finally:
            # Real stop with /varz restored so we don't leak nats-server
            # into the next test.
            nr.stop_server()


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
            # Accept **kwargs so runtime's `timeout=` (added round-5)
            # doesn't break this mock next time we tweak the call.
            lambda url, **_: FakeResp(tarball_bytes),
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
