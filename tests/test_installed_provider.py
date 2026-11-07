"""Controls for the native-provider recipe's shell workload and observations."""

import hashlib
import http.client
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from argparse import Namespace
from pathlib import Path

import pytest
import tomlkit

from tests.blackbox import installed_provider
from tests.blackbox.installed_host_smoke import _process_start_token
from tests.blackbox.installed_provider import (
    ParentObserver,
    capture_guest_command,
    client_observation,
    origin_observation,
    prepare,
)
from tests.blackbox.native_credentials import native_cli

SCRIPTS = Path(__file__).parent / "blackbox/isolation"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_guest_output_uses_pipes_and_keeps_private_log_ownership(tmp_path, exit_code):
    program = '''
import os, stat, sys
assert stat.S_ISFIFO(os.fstat(1).st_mode)
assert stat.S_ISFIFO(os.fstat(2).st_mode)
sys.stdout.buffer.write(b'o' * 131072)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b'e' * 131072)
sys.stderr.buffer.flush()
sys.exit(int(sys.argv[1]))
'''
    log = tmp_path / "guest.log"
    failures = []
    child, reader, finished = capture_guest_command(
        [sys.executable, "-c", program, str(exit_code)], os.environ, log, failures)
    try:
        # Waiting before capture finishes exercises output beyond pipe capacity.
        assert child.wait(timeout=10) == exit_code
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        finished.set()
        reader.join(timeout=5)
    assert not reader.is_alive() and failures == []
    assert child.returncode == exit_code
    assert log.read_bytes() == b'o' * 131072 + b'e' * 131072
    assert log.stat().st_uid == os.getuid() and log.stat().st_gid == os.getgid()
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_producer_records_accept_before_parsing_and_never_records_authorization(tmp_path):
    result = subprocess.run(["bash", str(SCRIPTS / "provider-origin.sh"), str(tmp_path)],
        input="GET /api/v1/value HTTP/1.1\r\nHost: proofspot.safeyolo.internal:8088\r\n"
              "Authorization: Bearer fixture-secret\r\nX-SafeYolo-Agent: forged\r\n"
              "X-SafeYolo-Agent-ID: ag-caller\r\nX-SafeYolo-Agent-ID: forged-id\r\n"
              "X-SafeYolo-Agent-Name: caller\r\n\r\n", capture_output=True, text=True, check=True)
    assert result.stdout.endswith("native-http-service\n")
    assert origin_observation(tmp_path) == {"accepts": 1, "requests": [[
        "GET /api/v1/value HTTP/1.1", "forged-id", "caller", "proofspot.safeyolo.internal:8088",
        "1", "1", "2", "1"]]}
    assert "fixture-secret" not in (tmp_path / "requests.tsv").read_text()
    incomplete = subprocess.run(["bash", str(SCRIPTS / "provider-origin.sh"), str(tmp_path)],
                                input="", capture_output=True, text=True)
    assert incomplete.returncode != 0
    assert origin_observation(tmp_path)["accepts"] == 2
    assert len(origin_observation(tmp_path)["requests"]) == 1


@pytest.mark.parametrize(("service", "route"), [("proofspot", "/api/v1/value"), ("notes", "/api/v1/notes")])
def test_caller_runs_all_phases_with_token_only_on_stdin(tmp_path, service, route):
    tools = tmp_path / "bin"
    tools.mkdir()
    cat = tools / "cat"
    cat.write_text("#!/bin/bash\n[[ $1 == /app/agent_token ]] || exit 2\nprintf 'fixture-agent-token'\n")
    cat.chmod(0o755)
    curl = tools / "curl"
    curl.write_text(f"#!{sys.executable}\n" + r'''
import os, pathlib, sys
args = sys.argv[1:]
service, route = os.environ['PROVIDER_TEST_SERVICE'], os.environ['PROVIDER_TEST_ROUTE']
header = sys.stdin.read()
if args[-1].endswith('/gateway/services'):
    assert header == 'Authorization: Bearer fixture-agent-token\n'
    # Model the separate token generations after reauthorization and listener reload.
    generation = pathlib.Path('generation')
    number = int(generation.read_text()) + 1 if generation.exists() else 1
    generation.write_text(str(number))
    print('{"authorized":{"proofspot":{"token":"sgw_fixture-proof' + str(number) + '"}}}')
else:
    counter = pathlib.Path('counter')
    index = int(counter.read_text()) if counter.exists() else 0
    generation = 1 if index < 6 else 2 if index < 8 else 3
    assert header == f'Authorization: Bearer sgw_fixture-proof{generation}\n'
    statuses = [403, 403, 403, 403, 200, 403, 200, 503, 503]
    expected = [('DELETE', route), ('GET', '/outside')] + [('GET', route)] * 7
    assert args[args.index('--request') + 1] == expected[index][0]
    assert args[-1].endswith(expected[index][1])
    if index == 2:
        assert 'unrelated.safeyolo.internal' in args[-1]
    else:
        assert f'{service}.safeyolo.internal' in args[-1]
    if index == 3:
        assert ':8089/' in args[-1]
    counter.write_text(str(index + 1))
    status = statuses[index]
    pathlib.Path(args[args.index('--output') + 1]).write_bytes(
        b'native-http-service\n' if status == 200 else b'refused')
    pathlib.Path(args[args.index('--dump-header') + 1]).write_text('HTTP/1.1\n')
    print(status, end='')
''')
    curl.chmod(0o755)
    for phase in ("allowed", "revoked", "recovered", "closed", "stopped"):
        (tmp_path / f"{phase}.go").touch()
    arguments = [] if service == "proofspot" else [service, route]
    result = subprocess.run(["bash", str(SCRIPTS / "provider-caller.sh"), str(tmp_path), *arguments],
        env=os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"],
                          "PROVIDER_TEST_SERVICE": service, "PROVIDER_TEST_ROUTE": route},
        capture_output=True, text=True, timeout=15, check=True)
    observations = client_observation(tmp_path)
    assert {label: row["status"] for label, row in observations.items()} == {
        "method": 403, "path": 403, "destination": 403, "port": 403, "allowed": 200,
        "revoked": 403, "recovered": 200, "closed": 503, "stopped": 503}
    assert observations["allowed"]["body_sha256"] == hashlib.sha256(b"native-http-service\n").hexdigest()
    assert (tmp_path / "generation").read_text() == "3"
    assert "sgw_" not in result.stdout + result.stderr + (tmp_path / "results.tsv").read_text()
    assert not (tmp_path / "response").exists() and not (tmp_path / "headers").exists()


@pytest.mark.parametrize(("stage", "stop_error"), [
    ("startup", None), ("startup", RuntimeError("fixture stop failure")),
    ("startup", subprocess.TimeoutExpired("fixture stop", 1)), ("startup", OSError("fixture stop failure")),
    ("loopback", None), ("extra_interface", None), ("no_interfaces", None), ("corrupt_clients", None),
])
def test_network_observation_and_owned_cleanup_on_partial_failure(tmp_path, monkeypatch, stage, stop_error):
    """Use live process births with controlled native startup, netlink and stop results."""
    base, root, output = tmp_path / "base", tmp_path / "instance", tmp_path / "report"
    base.mkdir()
    for name in ("config.toml", "policy.toml"):
        (base / name).write_text("fixture input")
    calls, backends = [], {}
    guest = b"fixture guest bytes"

    def prepare_instance(*_args):
        (root / "data").mkdir(parents=True)
        (root / ".safeyolo-platform-smoke").touch()

    def native(command, **_kwargs):
        arguments = command[3:]
        calls.append(arguments)
        if arguments[:2] == ["agent", "create"]:
            directory = root / "agents" / arguments[2] / "config-share"
            directory.mkdir(parents=True)
            (directory / "safeyolo-guest").write_bytes(guest)
        elif arguments[:2] == ["agent", "start"]:
            name = arguments[2]
            child = backends[name] = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            directory = root / "agents" / name
            (directory / "container.pid").write_text(str(child.pid))
            runtime = {"name": name, "agent_id": f"ag-{name}", "run_id": f"run-{name}",
                       "backend_pid": child.pid, "backend_token": _process_start_token(child.pid)}
            (directory / "runtime.json").write_text(json.dumps(runtime))
            if stage == "startup":
                raise RuntimeError("original operation failure")
        elif arguments[:2] == ["agent", "status"]:
            return json.dumps({"name": arguments[2], "agent_id": f"ag-{arguments[2]}",
                               "run_id": f"run-{arguments[2]}", "runtime_state": "running"})
        elif arguments[:2] == ["agent", "shell"]:
            assert arguments[3:] == ["-c", "ip -j link show"]
            links = [{"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"]}]
            if stage == "extra_interface":
                links.append({"ifname": "eth0", "flags": ["BROADCAST", "UP"]})
            return json.dumps([] if stage == "no_interfaces" else links)
        elif arguments[:2] == ["agent", "stop"]:
            if arguments[2] == "proofspot" and stop_error:
                raise stop_error
            if child := backends.get(arguments[2]):
                child.terminate()
                child.wait(timeout=5)
        elif arguments == ["stop"] and stop_error:
            raise RuntimeError("fixture global stop failure")
        return ""

    def after_interfaces(*_args, **_kwargs):
        if stage == "corrupt_clients":
            (root / "workspaces/caller/results.tsv").write_text("incomplete")
        raise RuntimeError("original operation failure")

    def selected_inputs(_base, revision):
        assert revision == "runtime"
        return {"guest": {"sha256": hashlib.sha256(guest).hexdigest()}}

    monkeypatch.setattr(installed_provider, "checked", native)
    monkeypatch.setattr(installed_provider, "prepare", prepare_instance)
    monkeypatch.setattr(installed_provider, "inputs", selected_inputs)
    monkeypatch.setattr(installed_provider, "_agent_listeners", lambda *_: [
        {"agent_id": name, "path": str(root / f"{name}.sock")} for name in installed_provider.NAMES])
    monkeypatch.setattr(installed_provider, "runsc_identity", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(installed_provider, "_native_config", lambda *_: {})
    monkeypatch.setattr(installed_provider, "_runtime_observation", after_interfaces)
    try:
        error = AssertionError if stage in {"extra_interface", "no_interfaces"} else RuntimeError
        with pytest.raises(error) as failure:
            installed_provider.run(Namespace(prepared_config=base, root=root, output=output,
                                            revision="fixture", runtime_revision="runtime", admin_port=19437))
        if error is RuntimeError:
            assert str(failure.value) == "original operation failure"
        report = json.loads((output / "result.json").read_text())
        assert report["status"] == "failed"
        assert report["revision"] == "fixture" and report["runtime_revision"] == "runtime"
        assert calls[-3:] == [["agent", "stop", "proofspot"], ["agent", "stop", "caller"], ["stop"]]
        assert report["cleanup"] == ("failed" if stop_error or stage == "corrupt_clients" else "stopped")
        if stop_error:
            assert any("agent stop proofspot:" in finding for finding in report["cleanup_failures"])
            assert any("global stop:" in finding for finding in report["cleanup_failures"])
            assert any(f"owned process {backends['proofspot'].pid} is still live" == finding
                       for finding in report["cleanup_failures"])
        else:
            assert all(child.poll() is not None for child in backends.values())
            if stage == "corrupt_clients":
                assert len(report["cleanup_failures"]) == 1
                assert report["cleanup_failures"][0].startswith("cannot read clients observations:")
            else:
                assert report["cleanup_failures"] == []
        if stage == "startup":
            assert report["participants"] == {}
        else:
            assert report["participants"]["proofspot"]["runtime"]["backend_pid"] == backends["proofspot"].pid
            assert "interfaces" in report["participants"]["proofspot"]
            if stage == "loopback":
                assert set(report["participants"]) == set(installed_provider.NAMES)
    finally:
        for child in backends.values():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


def test_parent_observer_counts_connections_before_http(tmp_path):
    with ParentObserver() as parent:
        thread = threading.Thread(target=parent.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", parent.server_port, timeout=3)
            try:
                connection.request("GET", "/control")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == b"fallback"
            finally:
                connection.close()
            assert parent.accepts == 1
        finally:
            parent.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


@pytest.mark.skipif(sys.platform != "linux" or not os.environ.get("SAFEYOLO_NATIVE_CLI"),
                    reason="Requires the selected native Linux CLI")
def test_prepared_configuration_is_readable_by_native_cli(tmp_path):
    """Use the real config reader without starting a proxy, broker or sandbox."""
    cli = native_cli()
    base, root = tmp_path / "base", tmp_path / "instance"
    subprocess.run([str(cli), "--root", str(base), "init"], check=True, capture_output=True)
    (base / "bin").mkdir()
    (base / "bin/safeyolo").symlink_to(cli)
    (base / "host").mkdir()
    (base / "host/prepared-sentinel").write_text("preserved")
    (base / "data/coord/nats/bin").mkdir(parents=True)
    config = tomlkit.parse((base / "config.toml").read_text())
    config["linux"] = {"host_uid": os.getuid(), "host_gid": os.getgid(), "uid_base": 100000,
                       "gid_base": 100000, "runsc": shutil.which("true"), "runsc_origin": "system"}
    (base / "config.toml").write_text(tomlkit.dumps(config))
    prepare(base, root, 19437, 19438)
    assert (root / "host").resolve() == base / "host"
    assert (base / "host/prepared-sentinel").read_text() == "preserved"
    subprocess.run([str(cli), "--root", str(root), "status"], check=True, capture_output=True)
