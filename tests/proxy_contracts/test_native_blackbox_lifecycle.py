"""Exercise retained blackbox consumers against an owned installed native proxy.

Only the sandbox status/shell leg of the restart control is simulated here.
Real full-platform runs still prove that leg with the same running guest.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox import installed_host_smoke as smoke
from tests.blackbox import installed_lifecycle as lifecycle
from tests.proxy_contracts.harness import connection, request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_inputs, native_instance

BLACKBOX = Path(__file__).resolve().parents[1] / "blackbox"
ADMIN_TOKEN = "synthetic-blackbox-admin-token"


@pytest.mark.parametrize("change", ["watcher", "admin"])
def test_native_lifecycle_observes_changed_policy_while_admitted_sse_stays_live(tmp_path, change):
    with origin_server(stream_seconds=0.04) as origin:
        host = f"127.0.0.1:{origin.server_address[1]}"
        allowed_source = f'[hosts]\n"*"={{egress="deny"}}\n"{host}"={{egress="allow"}}\n'
        denied_source = allowed_source.replace('egress="allow"', 'egress="deny"')
        with native_instance(tmp_path, source=allowed_source) as instance:
            audit = instance.root / "logs/audit.jsonl"
            before = lifecycle.wait_policy_load(audit, 0)
            legacy_before = sum(row["event"] == "ops.policy_reload" for row in lifecycle.event_rows(audit))
            stream = connection(instance.paths["alice"])
            try:
                stream.request("GET", f"http://{host}/stream-control")
                response = stream.getresponse()
                assert response.status == 200
                first = b"data: first-event\n\n"
                assert response.read(len(first)) == first
                assert origin.stream_initial_sent.is_set()
                assert not origin.stream_release.is_set() and not origin.stream_finished.is_set()

                if change == "watcher":
                    instance.policy.write_text(denied_source)
                else:
                    instance.admin("POST", "/admin/policy/host/deny", {"host": host})
                denied_load = lifecycle.wait_policy_load(audit, before)
                origin_before = len(origin.requests)
                status, headers, body = request(instance.paths["alice"], f"http://{host}/echo")
                assert status == 403, body
                assert headers["x-blocked-by"] == "network-guard"
                assert len(origin.requests) == origin_before
                assert not origin.stream_release.is_set() and not origin.stream_finished.is_set()

                origin.stream_release.set()
                assert response.read() == b"data: " + b"x" * (16384 - 8) + b"\n\n"
                assert origin.stream_finished.wait(5)
                assert not origin.stream_cancelled.is_set()
                instance.admin("POST", "/admin/policy/host/allow", {"host": host, "rate": 600})
                assert lifecycle.wait_policy_load(audit, denied_load) > denied_load
                status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
                assert (status, body) == (200, b"hello")
                assert len(origin.requests) == origin_before + 1
                assert sum(row["event"] == "ops.policy_reload" for row in lifecycle.event_rows(audit)) == legacy_before
            finally:
                origin.stream_release.set()
                stream.close()
        assert instance.process.poll() is not None


def test_native_lifecycle_load_observation_distinguishes_old_rejected_and_unapplied_policy(tmp_path):
    with origin_server() as origin:
        host = f"127.0.0.1:{origin.server_address[1]}"
        source = f'[hosts]\n"*"={{egress="deny"}}\n"{host}"={{egress="allow"}}\n'
        denied_source = source.replace('egress="allow"', 'egress="deny"')
        with native_instance(tmp_path, source=source) as instance:
            audit = instance.root / "logs/audit.jsonl"
            initial_load = lifecycle.wait_policy_load(audit, 0)
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            instance.apply('[hosts\n', valid=False)
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            unapplied_source = denied_source + "\n[credential.activation_failure]\nmatch = ['\\uD800']\n"
            failed = instance.apply(unapplied_source, valid=False)
            assert "activation failed" in failed.stderr
            assert instance.policy.read_text() == source
            assert instance.show()["saved_matches_active"]
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            # The real watcher emits before Runtime preparation. The compiler
            # accepts this string, but detector activation rejects its regex.
            instance.policy.write_text(unapplied_source)
            unapplied_load = lifecycle.wait_policy_load(audit, initial_load)
            status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
            assert (status, body) == (200, b"hello")
            assert len(origin.requests) == 1
            assert instance.show()["status"] == "saved_differs"
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, unapplied_load, timeout=0.05)

            instance.apply(denied_source)
            assert instance.show()["saved_matches_active"]
            status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
            assert status == 403, body
            assert len(origin.requests) == 1
        assert instance.process.poll() is not None


@pytest.mark.parametrize("control", ["clean", "stale_receipt", "admin_operand", "agent_operand", "missing_agent_token"])
def test_native_process_secrecy_consumer_observes_tokens_and_owned_process(tmp_path, monkeypatch, control):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from installed_host_smoke import SmokeError

    from tests.blackbox.host.security.test_firewall_structural import TestProcessSecrecy

    directory = tmp_path / {"admin_operand": ADMIN_TOKEN, "agent_operand": AGENT_TOKEN}.get(control, "owned")
    directory.mkdir()
    admin_token = directory / "admin-auth"
    admin_token.write_text(ADMIN_TOKEN)
    with native_instance(directory, agent_api=True, extra_config=(
        f'admin_api_token_file={json.dumps(str(admin_token))}\n'
        'tls_ca_file="certs/mitmproxy-ca.pem"\n'
    )) as instance:
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(instance.root))
        receipt = instance.root / "data/proxy-process.json"
        if control == "stale_receipt":
            original = receipt.read_bytes()
            record = json.loads(original)
            record["token"] = "wrong-process-birth"
            receipt.write_text(json.dumps(record))
            try:
                with pytest.raises(SmokeError, match="does not own"):
                    TestProcessSecrecy().test_no_tokens_in_process_cmdline()
            finally:
                receipt.write_bytes(original)
        elif control == "missing_agent_token":
            (instance.root / "data/agent_token").unlink()
            with pytest.raises(FileNotFoundError):
                TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        elif control.endswith("operand"):
            with pytest.raises(AssertionError, match="token appears"):
                TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        else:
            TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        ca = Path(smoke._native_config(instance.root / "config.toml", directory)["raw"]["tls_ca_file"])
        assert ca.is_file() and ca.parent == instance.root / "certs"


@pytest.mark.parametrize("changed", [None, "run_id", "agent_id", "backend_token", "home", "socket_directory"])
def test_native_restart_consumer_uses_real_start_and_checks_sandbox_continuity(tmp_path_factory, monkeypatch, changed):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from tests.blackbox.host.lifecycle.test_token_lifecycle import TestLiveAgentLifecycle

    directory = tmp_path_factory.mktemp("restart")
    with native_instance(directory, agent_api=True, agent_addresses={"alice": "10.0.0.2"}) as instance:
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(instance.root))
        monkeypatch.setenv("SAFEYOLO_TEST_AGENT", "alice")
        listener = smoke._agent_listeners(instance.root)[0]
        socket_path = Path(listener["path"])
        sandbox = {"name": "alice", "agent_id": "ag-owned", "run_id": "0123456789abcdef0123456789abcdef",
                   "runtime_state": "running"}
        directory = instance.root / "agents/alice"
        (directory / "home").mkdir(parents=True)
        backend = {**sandbox, "backend_pid": os.getpid(), "backend_token": smoke._process_start_token(os.getpid())}
        (directory / "runtime.json").write_text(json.dumps(backend))
        operations = []

        def command(*arguments, **kwargs):
            operations.append(arguments)
            if arguments == ("agent", "status", "alice"):
                value = dict(sandbox)
                if ("start",) in operations and changed in {"run_id", "agent_id"}:
                    value[changed] = "different-incarnation"
                return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")
            if arguments[:2] == ("agent", "shell"):
                fields = shlex.split(arguments[4])
                home_file = directory / "home" / Path(fields[-1]).name
                if fields[0] == "printf":
                    home_file.write_text(fields[2])
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                assert fields[0] == "cat"
                return SimpleNamespace(returncode=0, stdout=home_file.read_text(), stderr="")
            result = instance.cli(*arguments, **kwargs)
            if arguments == ("start",) and changed == "socket_directory":
                # Preserve the old directory so inode reuse cannot mask replacement.
                old = socket_path.parent.with_name("old-directory")
                socket_path.parent.rename(old)
                socket_path.parent.mkdir()
                (old / "proxy.sock").rename(socket_path)
            if arguments == ("start",) and changed == "backend_token":
                (directory / "runtime.json").write_text(json.dumps({**backend, "backend_token": "other-birth"}))
            if arguments == ("start",) and changed == "home":
                next((directory / "home").iterdir()).write_text("lost-home-state")
            return result

        consumer = TestLiveAgentLifecycle()
        monkeypatch.setattr(consumer, "_safeyolo", command)
        monkeypatch.setattr(consumer, "_agent_api_health", lambda _name: smoke._probe_agent_health(
            listener, instance.root,
        )["status"])
        monkeypatch.setattr(consumer, "_allowed_traffic", lambda _name, marker: {"marker": marker, "status": 200})
        # Exercise the real native stop/start and API sockets. Only the guest
        # inventory/shell observations use the controlled retained status shape.
        try:
            if changed:
                with pytest.raises(AssertionError, match="sandbox identity|socket directory|process birth|persistent home"):
                    consumer.test_agent_api_survives_proxy_restart()
            else:
                consumer.test_agent_api_survives_proxy_restart()
            assert [call for call in operations if call[:2] != ("agent", "shell")] == [
                ("agent", "status", "alice"), ("stop",), ("agent", "status", "alice"),
                ("start",), ("agent", "status", "alice"),
            ]
            assert instance.process.wait(timeout=10) == 0
        finally:
            stopped = instance.cli("stop")
            assert stopped.returncode == 0, stopped.stderr


def test_native_lifecycle_consumer_retains_inactive_receipt_and_uses_configured_readiness(tmp_path, monkeypatch):
    with native_instance(tmp_path, agent_api=True) as instance:
        stopped = instance.cli("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert instance.process.wait(timeout=10) == 0
        config = instance.root / "config.toml"
        document = tomlkit.parse(config.read_text())
        document["readiness_file"] = "data/selected-ready.json"
        config.write_text(tomlkit.dumps(document))
        started = instance.cli("start")
        assert started.returncode == 0, started.stderr
        native = smoke._native_config(instance.root / "config.toml", tmp_path)
        listener = Path(instance.paths["alice"])
        try:
            runtime = smoke._runtime_observation(
                instance.root, native, instance.root / "bin/safeyolo-proxy",
                config_path=config, working_directory=tmp_path,
                require_running=True, require_authenticated_identity=True,
            )
            # Only the guest/origin legs are controlled here. The owner's
            # configured marker, kernel process birth and live API are real.
            owner = {"runtime": runtime, "config_sha256": smoke._sha256(config),
                     "policy_sha256": smoke._sha256(instance.policy)}
            monkeypatch.setattr(lifecycle, "guest", lambda _cli, _agent, phase, _marker, **_kwargs: {
                "status": 200 if phase == "echo" else 403,
            })
            marker = "p4-owned"
            sinkhole = SimpleNamespace(get_requests=lambda **kwargs: (
                [SimpleNamespace(path=f"/p4/echo/{marker}")] if kwargs["host"] == lifecycle.FIXTURE else []
            ))
            assert lifecycle.owner_controls(str(instance.root / "bin/safeyolo"), instance.root, listener,
                                            owner, instance.environment, marker, sinkhole)["pid"] == runtime["pid"]
            with monkeypatch.context() as clock:
                clock.setattr(lifecycle.time, "monotonic", iter((0, 13)).__next__)
                with pytest.raises(AssertionError, match="did not withdraw readiness"):
                    lifecycle.assert_proxy_stopped(instance.root, listener, runtime)
        finally:
            stopped = instance.cli("stop")
            assert stopped.returncode == 0, stopped.stderr
        # Native stop preserves its inactive identity record, and withdraws
        # the actual configured readiness and accepting listener.
        assert (instance.root / "data/proxy-process.json").is_file()
        lifecycle.assert_proxy_stopped(instance.root, listener, runtime)
        assert not Path(native["readiness_file"]).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="the owned-child probe uses Linux procfs")
@pytest.mark.parametrize("control,coord_control", [
    ("immediate", "ready"), ("delayed", "ready"), ("exited", "ready"), ("unready", "ready"),
    ("immediate", "delayed"), ("exited", "delayed"), ("exited_after_ready", "delayed"),
    ("delayed", "failed"),
])
def test_native_start_waits_for_verified_readiness_and_bounds_owned_child(tmp_path, control, coord_control):
    # Use the existing native CLI initialization boundary. No guest payload or
    # package rebuild is needed to exercise these host-only start/stop commands.
    artifacts, _, _ = native_inputs()
    if bundle := os.environ.get("SAFEYOLO_NATIVE_BUNDLE"):
        artifacts = Path(bundle) / "bin"
    root = tmp_path / "i"
    (root / "bin").mkdir(parents=True)
    for binary in ("safeyolo", "safeyolo-proxy"):
        (root / "bin" / binary).symlink_to((artifacts / binary).resolve(strict=True))
    command = [str(root / "bin/safeyolo"), "--root", str(root)]
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root), SAFEYOLO_HOME=str(root),
                       SAFEYOLO_NATIVE_CONFIG_PATH=str(root / "config.toml"), SAFEYOLO_NATS_TEST_INSTANCE=str(root))
    environment.pop("SAFEYOLO_OPERATOR_INSTANCE_ID_FILE", None)
    initialized = subprocess.run([*command, "init"], env=environment, capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    config = root / "config.toml"
    document = tomlkit.parse(config.read_text())
    document.update(admin_port=0, flow_store_enabled=False, readiness_file="data/selected-ready.json",
                    admin_api_token_file="data/admin_token",
                    listeners=[{"agent_id": "alice", "socket_path": str(tmp_path / "a.sock"), "source_id": "10.0.0.2"}])
    config.write_text(tomlkit.dumps(document))
    coord_command = [*command, "coord", "start"]
    if nats := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
        coord_command += ["--binary", nats]
    coordinated = subprocess.run(coord_command, env=environment, capture_output=True, text=True, timeout=15)
    assert coordinated.returncode == 0, coordinated.stderr
    coord_lock = None
    if coord_control != "ready":
        stopped = subprocess.run([*command, "coord", "stop"], env=environment, capture_output=True,
                                 text=True, timeout=10)
        assert stopped.returncode == 0, stopped.stderr
        nats = root / "data/coord/nats"
        if coord_control == "delayed":
            coord_lock = os.open(nats / "runtime.lock", os.O_RDWR)
            fcntl.flock(coord_lock, fcntl.LOCK_EX)
        else:
            # Damage only this fixture's copied NATS input. The proxy must
            # still initialize when the managed Coord prerequisite is absent.
            cached, = nats.glob("bin/*/nats-server")
            cached.write_bytes(b"incorrect-reviewed-nats-pin")
    ca = root / "certs/mitmproxy-ca.pem"
    pem = ca.read_bytes()
    ca.unlink()
    os.mkfifo(ca, 0o600)
    readiness = root / "data/selected-ready.json"
    readiness.write_text('{"ready":true,"pid":1}')
    receipt = root / "data/proxy-process.json"
    previous = '{"pid":1,"token":"stale-birth"}'
    receipt.write_text(previous)
    writer = None
    pid = birth = None
    started = time.monotonic()
    startup = subprocess.Popen([*command, "start"], cwd=tmp_path, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def owned_proxy_children():
        children = set()
        try:
            tasks = list(Path(f"/proc/{startup.pid}/task").iterdir())
        except FileNotFoundError:
            return []  # The CLI exited before this cleanup observation.
        for task in tasks:
            try:
                for child in (task / "children").read_text().split():
                    # gVisor can list thread IDs here. Select their process ID
                    # once so a multithreaded proxy remains one owned child.
                    status = Path(f"/proc/{child}/status").read_text().splitlines()
                    children.add(int(next(line.split()[1] for line in status if line.startswith("Tgid:"))))
            except FileNotFoundError:
                # A CLI or child thread exited between these observations.
                continue
        return [child for child in children
                if smoke._process_executable(child) == (root / "bin/safeyolo-proxy").resolve()
                and smoke._process_command_line(child) == [
                    os.fsencode(root / "bin/safeyolo-proxy"), b"--config", os.fsencode(config),
                ]]

    try:
        # A writer can open only after the real initializer starts reading
        # its configured CA. Hold EOF to keep that initializer unready.
        while writer is None:
            assert startup.poll() is None, startup.communicate()
            assert time.monotonic() - started < 10, "proxy did not open its configured CA"
            try:
                writer = os.open(ca, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise
                time.sleep(0.02)
        ca.unlink()
        ca.write_bytes(pem)
        owned = owned_proxy_children()
        assert len(owned) == 1, owned
        pid = owned[0]
        birth = smoke._process_start_token(pid)
        assert birth is not None
        assert not readiness.exists(), "start retained a stale readiness marker"
        assert receipt.read_text() == previous
        held = time.monotonic()
        if control == "delayed":
            time.sleep(6)
            assert startup.poll() is None, startup.communicate()
            assert smoke._process_start_token(pid) == birth
            assert not readiness.exists()
        if control != "unready":
            if control != "exited":
                assert os.write(writer, pem) == len(pem)
            os.close(writer)
            writer = None
        if coord_lock is not None:
            deadline = time.monotonic() + 5
            while (Path(f"/proc/{pid}").exists() if control == "exited"
                   else not readiness.is_file() or receipt.read_text() == previous):
                assert startup.poll() is None, startup.communicate()
                assert time.monotonic() < deadline, "proxy startup waited for managed NATS"
                time.sleep(0.02)
            # Proxy readiness or owned failure finishes independently. The
            # command must retain the pending NATS start and its startup lock.
            assert startup.poll() is None, "start returned before managed NATS resolved"
            if control == "exited_after_ready":
                os.kill(pid, signal.SIGTERM)
                while smoke._process_start_token(pid) == birth:
                    assert time.monotonic() < deadline, "ready proxy did not exit"
                    time.sleep(0.02)
            fcntl.flock(coord_lock, fcntl.LOCK_UN)
            os.close(coord_lock)
            coord_lock = None
        stdout, stderr = startup.communicate(timeout=20)
        elapsed = time.monotonic() - started
        if control == "unready":
            assert startup.returncode != 0, stdout
            assert "did not publish readiness within fifteen seconds" in stderr
            assert 15 <= elapsed < 20
        elif control in {"exited", "exited_after_ready"}:
            assert startup.returncode != 0, stdout
            assert "proxy exited during startup" in stderr
            assert time.monotonic() - held < 5
        else:
            assert startup.returncode == 0, stderr
            assert time.monotonic() - held < (6 if control == "delayed" else 0) + 5
            record = json.loads(receipt.read_text())
            assert (record["pid"], record["token"]) == (pid, birth)
            native = smoke._native_config(config, tmp_path)
            runtime = smoke._runtime_observation(
                root, native, root / "bin/safeyolo-proxy", config_path=config,
                working_directory=tmp_path, require_running=True, require_authenticated_identity=True,
            )
            assert runtime["pid"] == pid
        if control in {"exited", "exited_after_ready", "unready"}:
            assert not Path(f"/proc/{pid}").exists(), "startup did not reap its failed owned child"
            assert not readiness.exists()
            if control == "exited_after_ready":
                assert json.loads(receipt.read_text())["pid"] == pid
            else:
                assert receipt.read_text() == previous
        if coord_control == "failed":
            assert "Coord unavailable: NATS executable differs from its reviewed platform pin" in stderr
        else:
            status = subprocess.run([*command, "coord", "status"], env=environment,
                                    capture_output=True, text=True, timeout=10)
            assert status.returncode == 0, status.stderr
            assert json.loads(status.stdout)["state"] == "running"
    finally:
        if ca.is_fifo():
            ca.unlink()
            ca.write_bytes(pem)
        if coord_lock is not None:
            fcntl.flock(coord_lock, fcntl.LOCK_UN)
            os.close(coord_lock)
        if writer is not None:
            os.close(writer)
        if startup.poll() is None:
            for child in owned_proxy_children():
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Closing the CA writer can let the child exit first.
        startup.communicate(timeout=5)
        stopped = subprocess.run([*command, "stop"], env=environment, capture_output=True, text=True, timeout=10)
        assert stopped.returncode == 0, stopped.stderr
    if control in {"immediate", "delayed"}:
        assert receipt.is_file()
        lifecycle.assert_proxy_stopped(root, tmp_path / "a.sock", runtime)


@pytest.mark.parametrize("exits", [True, False])
def test_native_stop_observer_waits_for_process_exit_and_rejects_a_live_birth(tmp_path, monkeypatch, exits):
    real_monotonic = time.monotonic
    readiness = tmp_path / "ready.json"
    monkeypatch.setattr(lifecycle, "_native_config", lambda *_args: {"readiness_file": str(readiness)})
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    runtime = {"pid": process.pid, "receipt": {"start_token": smoke._process_start_token(process.pid)}}
    assert runtime["receipt"]["start_token"] is not None
    try:
        if exits:
            # The readiness marker is already absent while the real OS child
            # remains live. Let it exit after the observer has started waiting.
            released = threading.Timer(0.1, process.terminate)
            released.start()
            try:
                lifecycle.assert_proxy_stopped(tmp_path, tmp_path / "listener.sock", runtime)
            finally:
                released.join()
            process.wait(timeout=3)
            assert not smoke._pid_alive(process.pid)
        else:
            clock = iter((0, 0, 6))
            monkeypatch.setattr(lifecycle.time, "monotonic", lambda: next(clock))
            with pytest.raises(AssertionError, match="remains live after stop"):
                lifecycle.assert_proxy_stopped(tmp_path, tmp_path / "listener.sock", runtime)
            assert smoke._pid_alive(process.pid)
    finally:
        monkeypatch.setattr(lifecycle.time, "monotonic", real_monotonic)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=3)


@pytest.mark.parametrize("missing_ca", [False, True])
def test_native_host_smoke_preserves_configured_ca_failure_and_owned_cleanup(tmp_path, monkeypatch, missing_ca):
    with native_instance(tmp_path, source=None, agent_api=True,
                         extra_config='tls_ca_file="certs/mitmproxy-ca.pem"\n') as instance:
        stopped = instance.cli("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert instance.process.wait(timeout=10) == 0
        root = instance.root
        (root / ".safeyolo-platform-smoke").touch()
        monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(root / "config.toml"))
        ca = root / "certs/mitmproxy-ca.pem"
        original = smoke._sha256(ca)
        held_ca = ca.with_suffix(".held")
        if missing_ca:
            ca.rename(held_ca)
        try:
            report, exit_code = smoke._native_smoke(SimpleNamespace(
                config_dir=str(root), rust_config=str(root / "config.toml"),
                rust_bin=str(root / "bin/safeyolo-proxy"), cli=str(root / "bin/safeyolo"),
                working_directory=str(tmp_path), http_port=0, agent="alice",
                nats_client_port=None, nats_monitor_port=None,
                install_commit=smoke._cli_identity(root / "bin/safeyolo")["source_revision"],
            ))
            assert report["cleanup"] == {"status": "stopped", "errors": []}
            if missing_ca:
                assert exit_code == 2 and report["status"] == "infrastructure_failure"
                assert "proxy exited during startup" in report["error"]
                assert "No such file" in (root / "logs/proxy.log").read_text()
            else:
                assert exit_code == 0 and report["status"] == "host_package_passed", report
                assert report["origin"]["allowed_status"] == 200 and report["origin"]["denied_status"] == 403
                assert smoke._sha256(ca) == original
        finally:
            if missing_ca:
                held_ca.rename(ca)
