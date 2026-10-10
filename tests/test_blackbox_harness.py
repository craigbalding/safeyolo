"""Regression tests for blackbox harness isolation and backend selection."""

import hashlib
import http.client
import json
import os
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from tests.blackbox import installed_access, installed_sections, installed_shared_approvals
from tests.blackbox import installed_lifecycle as lifecycle
from tests.blackbox import installed_state_transition as continuity
from tests.blackbox.harness.vz_fixture import P2Fixture, Parent, VZRequest
from tests.blackbox.installed_ingress import installed_identity
from tests.blackbox.isolation import installed_access as guest
from tests.blackbox.isolation import installed_lifecycle as guest_lifecycle
from tests.blackbox.isolation import installed_workloads as guest_workloads
from tests.blackbox.proxy_backend import SelectionError, identity
from tests.proxy_contracts import harness as proxy_harness
from tests.proxy_contracts.websocket_peer import read_head


@pytest.fixture
def native_binary(tmp_path):
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("#!/bin/sh\nprintf 'safeyolo-proxy 0.1.0 (fixture)\\n'\n")
    binary.chmod(0o755)
    return binary


def test_prepared_inputs_reach_native_lifecycle_with_fresh_state(monkeypatch):
    """Prepared executables serve fresh section state through the real caller."""
    binary = os.environ.get("SAFEYOLO_TEST_NATIVE_CLI")
    if not binary:
        pytest.skip("requires the built native CLI (SAFEYOLO_TEST_NATIVE_CLI)")

    with tempfile.TemporaryDirectory(prefix="sy908-", dir="/tmp") as directory:
        parent = Path(directory)
        source = parent / "prepared"
        (source / "bin").mkdir(parents=True)
        (source / "bin/safeyolo").symlink_to(binary)
        (source / "assets").mkdir()
        (source / "assets/input").write_bytes(b"immutable prepared input")
        roots = [parent / name for name in ("subject", "owner")]
        for root in roots:
            installed_sections.prepare_native_instance(source, root)
            monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
            monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
            assert json.loads(subprocess.check_output([str(root / "bin/safeyolo"), "--root", str(root), "status"]))["agents"] == []
            assert (root / "bin/safeyolo").resolve() == Path(binary).resolve()
            assert (root / "assets/input").stat().st_ino == (source / "assets/input").stat().st_ino
        assert (roots[0] / "data/admin_token").read_bytes() != (roots[1] / "data/admin_token").read_bytes()
        assert (roots[0] / "config.toml").stat().st_ino != (roots[1] / "config.toml").stat().st_ino
        assert not (source / "config.toml").exists()


def test_shared_approval_transport_keeps_owned_selection_when_preparation_fails(tmp_path_factory, monkeypatch):
    """An inherited TOML cannot redirect the actual native status/stop transport."""
    binary = os.environ.get("SAFEYOLO_TEST_NATIVE_CLI")
    if not binary:
        pytest.skip("requires the built native CLI (SAFEYOLO_TEST_NATIVE_CLI)")
    # Native stop derives a Unix socket path; keep the owned fixture short.
    tmp_path = tmp_path_factory.mktemp("s821")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    owned, unrelated = tmp_path / "owned", tmp_path / "unrelated"
    identities = {}
    for root in (owned, unrelated):
        installed_shared_approvals.checked([binary, "--root", str(root), "init"])
        for name in ("worker", "helper"):
            created = installed_shared_approvals.checked([
                binary, "--root", str(root), "agent", "create", name,
                "--workspace", str(workspace), "--launcher", "supervisor",
            ])
            identities[root, name] = json.loads(created)["configuration"]["id"]
    (owned / ".safeyolo-platform-smoke").touch()
    (owned / "data/agent_map.json").write_text(json.dumps({
        "worker": {"ip": "127.0.0.2"}, "helper": {"ip": "127.0.0.3"},
    }))
    untouched = {path: path.read_bytes() for path in (unrelated / "config.toml", unrelated / "policy.toml")}
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(unrelated))
    monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(unrelated / "config.toml"))
    # Restore the process environment after the driver selects its own root.
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(unrelated / "logs"))
    with pytest.raises(FileNotFoundError):
        installed_shared_approvals.run(SimpleNamespace(
            config_dir=owned, worker="worker", helper="helper",
            native_cli=Path(binary), native_proxy=tmp_path / "missing-proxy",
        ))
    for operation in ("status", "stop"):
        observed = json.loads(installed_shared_approvals.checked([binary, "agent", operation, "worker"]))
        assert observed["agent_id"] == identities[owned, "worker"]
        assert observed["agent_id"] != identities[unrelated, "worker"]
    assert {path: path.read_bytes() for path in untouched} == untouched


def test_model_fixture_policy_runs_without_retired_product_python(tmp_path):
    """Standalone U3 preparation preserves model routing and credential controls."""
    policy = '''# retained model route
budget=17
[hosts]
"chatgpt.com:443"={egress="allow"}
"127.0.0.2:49124"={egress="allow"}
[controls.credentials]
enabled=true
[agents.worker]
agent_id="worker-id"
folder="/owned/worker"
[agents.worker.hosts]
"127.0.0.2:49124"={egress="allow"}
[agents.helper]
agent_id="helper-id"
folder="/owned/helper"
evidence_reads=[{request_id="old-id"}]
'''
    (tmp_path / "policy.toml").write_text(policy)
    # pytest includes tests/reference for historical tests. Exercise the
    # installed driver's ordinary import path so that cannot mask retirement.
    script = (
        "from pathlib import Path\n"
        "from tests.blackbox.installed_shared_approvals import model_fixture_policy\n"
        "import sys\n"
        "print(model_fixture_policy(Path(sys.argv[1]), ('worker', 'helper'), 49123))\n"
    )
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[1], env={**os.environ, "PYTHONPATH": "."},
        capture_output=True, text=True, check=True, timeout=15)
    selected = tomllib.loads(result.stdout)
    assert "# retained model route" in result.stdout
    assert selected["hosts"] == {"chatgpt.com:443": {"egress": "allow"}}
    assert selected["controls"]["credentials"]["enabled"] is True
    assert selected["budget"] == 17
    for name in ("worker", "helper"):
        assert selected["agents"][name]["agent_id"] == name + "-id"
        assert selected["agents"][name]["folder"] == "/owned/" + name
        assert selected["agents"][name]["hosts"] == {
            "127.0.0.2": {"egress": "deny"}, "127.0.0.2:49123": {"egress": "prompt"}}
    assert "evidence_reads" not in selected["agents"]["helper"]
    assert (tmp_path / "policy.toml").read_text() == policy


def test_shared_approval_coord_uses_staged_home_binary(tmp_path, monkeypatch):
    """The shared-room caller works with ordinary home staging alone."""
    homes = {name: tmp_path / name / "home/agent" for name in ("helper", "worker")}
    for name, home in homes.items():
        executable = home / ".safeyolo/safeyolo-coord"
        executable.parent.mkdir(parents=True)
        executable.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"print(json.dumps({{'agent': {name!r}, 'operation': sys.argv[1:], 'arguments': json.load(sys.stdin)}}))\n"
        )
        executable.chmod(0o755)
    transport = tmp_path / "selected-safeyolo"

    def guest_shell(cli, name, command):
        assert cli == transport
        # Map the guest's absolute home path into this isolated staging tree.
        # No config-share Coord binary is supplied.
        guest_executable = shlex.split(command)[4]
        staged = homes[name] / Path(guest_executable).relative_to("/home/agent")
        return ["sh", "-c", command.replace(guest_executable, shlex.quote(str(staged)), 1)]

    monkeypatch.setattr(installed_shared_approvals, "guest_command_args", guest_shell)
    for name, operation, arguments in (
        ("helper", "join_room", {"room_name": "operator-821"}),
        ("worker", "join_room", {"room_name": "operator-821"}),
        ("helper", "send", {"room_name": "operator-821", "body": "quoted ' $(exit 7) `exit 8`", "notify": ["worker"]}),
        ("worker", "read_room", {"room_name": "operator-821", "since_sequence": 5, "limit": 1}),
    ):
        assert installed_shared_approvals.guest_coord(transport, name, operation, arguments) == {
            "agent": name, "operation": ["call", operation], "arguments": arguments,
        }


@pytest.mark.parametrize("unavailable_model_port", [None, 49124], ids=["real-helper", "model-unavailable"])
@pytest.mark.parametrize("agents", [
    pytest.param('''[agents.worker]
agent_id="worker-id"
folder="/owned/worker"
network_slot=1
evidence_reads=[{request_id="worker-kept"}]
[agents.helper]
agent_id="helper-id"
folder="/owned/helper"
network_slot=2
evidence_reads=[{request_id="helper-stale"}]
''', id="regular-absent-hosts"),
    pytest.param('''[agents]
worker={agent_id="worker-id",folder="/owned/worker",network_slot=1,evidence_reads=[{request_id="worker-kept"}]}
helper={agent_id="helper-id",folder="/owned/helper",network_slot=2,evidence_reads=[{request_id="helper-stale"}]}
''', id="inline-agent"),
    pytest.param('''agents={worker={agent_id="worker-id",network_slot=1},helper={agent_id="helper-id",network_slot=2}}
''', id="inline-parent"),
    pytest.param('''[agents]
worker.agent_id="worker-id"
worker.folder="/owned/worker"
worker.network_slot=1
helper.agent_id="helper-id"
helper.folder="/owned/helper"
helper.network_slot=2
''', id="dotted-agent"),
    pytest.param('''agents.worker.agent_id="worker-id"
agents.worker.folder="/owned/worker"
agents.worker.network_slot=1
agents.helper.agent_id="helper-id"
agents.helper.folder="/owned/helper"
agents.helper.network_slot=2
''', id="root-dotted-agent"),
    pytest.param('''[agents.worker]
agent_id="worker-id"
hosts={}
[agents.helper]
agent_id="helper-id"
hosts={}
''', id="empty-inline-hosts"),
    pytest.param('''[agents.worker]
agent_id="worker-id"
[agents.worker.hosts]
"model.test:443"={egress="allow"}
"127.0.0.2:49125"={egress="allow"}
"127.0.0.3:49124"={egress="allow"}
[agents.helper]
agent_id="helper-id"
[agents.helper.hosts]
"model.test:443"={egress="allow"}
''', id="existing-hosts"),
    pytest.param('''[agents]
worker={agent_id="worker-id",hosts={"model.test:443"={egress="allow"}}}
helper={agent_id="helper-id",hosts={"model.test:443"={egress="allow"}}}
''', id="existing-inline-hosts"),
    pytest.param('''[agents.worker]
agent_id="worker-id"
[agents.helper]
agent_id="helper-id"
[agents.worker.hosts]
"model.test:443"={egress="allow"}
''', id="out-of-order-hosts"),
])
def test_model_fixture_policy_preserves_hierarchy_scope_and_saved_policy(tmp_path, agents, unavailable_model_port):
    """Supported TOML forms retain identity and the exact Worker/Helper scope."""
    original = 'budget=17\n' + agents + '''
[hosts]
"chatgpt.com:443"={egress="allow"}
"127.0.0.2:49125"={egress="allow"}
"127.0.0.3:49124"={egress="allow"}
[controls.credentials]
enabled=true
'''
    (tmp_path / "policy.toml").write_text(original)
    saved = tomllib.loads(original)
    policy = tomllib.loads(installed_shared_approvals.model_fixture_policy(
        tmp_path, ("worker", "helper"), 49123, unavailable_model_port=unavailable_model_port))
    assert set(policy) == set(saved)
    assert policy["budget"] == saved["budget"]
    assert policy["controls"] == saved["controls"]
    assert policy["hosts"] == {
        "chatgpt.com:443": {"egress": "allow"},
        **({"127.0.0.3:49124": {"egress": "allow"}} if unavailable_model_port is None else {}),
    }
    assert set(policy["agents"]) == {"worker", "helper"}
    for name in ("worker", "helper"):
        original_agent = saved["agents"][name]
        expected_hosts = {"127.0.0.2": {"egress": "deny"}, "127.0.0.2:49123": {"egress": "prompt"}}
        if "model.test:443" in original_agent.get("hosts", {}):
            expected_hosts["model.test:443"] = {"egress": "allow"}
        if unavailable_model_port is not None:
            expected_hosts["127.0.0.3"] = {"egress": "deny"}
            if name == "helper":
                expected_hosts["127.0.0.3:49124"] = {"egress": "allow"}
        elif "127.0.0.3:49124" in original_agent.get("hosts", {}):
            expected_hosts["127.0.0.3:49124"] = {"egress": "allow"}
        retained = {key: value for key, value in original_agent.items()
                    if key != "hosts" and not (name == "helper" and key == "evidence_reads")}
        assert policy["agents"][name] == {**retained, "hosts": expected_hosts}
    assert (tmp_path / "policy.toml").read_text() == original


def test_fixture_policy_validation_precedes_apply_without_disclosing_parser_keys():
    """A valid prefix cannot hide an invalid tail or expose its private key."""
    calls = []

    def operator(method, path, body):
        calls.append((method, path, body))
        return {"status": 200}

    private_key = "synthetic-private-policy-key"
    policy = 'budget=17\n[hosts]\n"model.test:443"={egress="allow"}\n'
    with pytest.raises(AssertionError) as failure:
        installed_shared_approvals.apply_fixture_policy(operator, policy + f'{private_key}={{a=1,a=2}}\n')
    assert str(failure.value) == "fixture policy is invalid TOML; baseline was not applied"
    assert private_key not in str(failure.value)
    assert failure.value.__suppress_context__
    assert calls == []
    installed_shared_approvals.apply_fixture_policy(operator, policy)
    assert calls == [("PUT", "/admin/policy/baseline", {"source": policy})]


@pytest.mark.parametrize("status,diagnosis", [
    (400, "native policy request rejected"),
    (401, "operator authentication required"),
    (403, "operator request refused"),
    (500, "native policy apply failed"),
    (503, "native runtime unavailable"),
])
def test_fixture_policy_apply_failure_reports_status_without_private_bytes(status, diagnosis):
    """Rejected applies identify the failing boundary without a response dump."""
    policy = 'budget=17\nprivate="synthetic-policy-secret"\n'
    private_response = "synthetic-response-secret\x1b[2J" * 10000

    def operator(method, path, body):
        assert (method, path, body) == ("PUT", "/admin/policy/baseline", {"source": policy})
        return {"status": status, "body": {"error": private_response}}

    with pytest.raises(AssertionError) as failure:
        installed_shared_approvals.apply_fixture_policy(operator, policy)
    assert str(failure.value) == (
        f"fixture baseline apply returned HTTP {status}: {diagnosis}; inspect private native logs")
    assert "synthetic" not in str(failure.value)


def test_unavailable_model_origin_observes_before_returning_diagnosable_503():
    """Exercise the real HTTP failure injection independently of a model run."""
    observations = []
    marker = "821-owned-model-control"
    server = HTTPServer(("127.0.0.1", 0), partial(
        installed_shared_approvals.UnavailableModelOrigin, marker=marker, observe=observations.append))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
    request = {"model": "configured-model", "input": [{"role": "user", "content": "Diagnose req-selected"}]}
    try:
        connection.request("POST", "/v1/responses", json.dumps(request),
            {"Content-Type": "application/json", "X-SafeYolo-U6": marker})
        response = connection.getresponse()
        assert response.status == 503
        assert json.loads(response.read()) == {"error": {
            "message": marker + ": model unavailable", "type": "server_error", "code": "model_unavailable"}}
        assert observations == [{**request, "marker": marker, "authenticated": False}]
        connection.request("POST", "/wrong-model-path", json.dumps(request))
        response = connection.getresponse()
        assert response.status == 400
        response.read()
        assert len(observations) == 1
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert not thread.is_alive()


def test_unavailable_model_command_and_capture_preserve_specific_failure(tmp_path):
    """A failed turn needs its initialized thread and actual injected diagnosis."""
    marker = "821-controlled"
    arguments = installed_shared_approvals.unavailable_model_arguments(49124, marker)
    overrides = [arguments[index + 1] for index, value in enumerate(arguments) if value == "-c"]
    configuration = tomllib.loads("\n".join(overrides))
    provider = configuration["model_providers"][configuration["model_provider"]]
    assert provider["base_url"] == "http://127.0.0.3:49124/v1"
    assert provider["requires_openai_auth"] is False and provider["supports_websockets"] is False
    assert provider["request_max_retries"] == provider["stream_max_retries"] == 0
    assert provider["http_headers"] == {"X-SafeYolo-U6": marker}
    assert set(configuration) == {"model_provider", "model_providers"}
    message = f"unexpected status 503 Service Unavailable: {marker}: model unavailable"
    events = [
        {"type": "thread.started", "thread_id": "owned-thread"},
        {"type": "turn.started"}, {"type": "turn.failed", "error": {"message": message}},
    ]
    output = "\n".join(json.dumps(event) for event in events) + "\n"
    path = tmp_path / "failed-model.jsonl"
    captured = installed_shared_approvals.run_helper(
        [sys.executable, "-c", f"import sys; sys.stdout.write({output!r}); sys.exit(1)"],
        path, expected_exit=1)
    assert installed_shared_approvals.model_failure_diagnosis(captured, marker) == ("owned-thread", message)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for replacement in ("missing launcher", "authentication required", "unexpected status 403", "unrelated 503 model unavailable"):
        bad_events = [*events[:-1], {"type": "turn.failed", "error": {"message": replacement}}]
        with pytest.raises(AssertionError, match="not the injected model failure"):
            installed_shared_approvals.model_failure_diagnosis("\n".join(json.dumps(event) for event in bad_events), marker)
    with pytest.raises(AssertionError, match="model turn did not start"):
        installed_shared_approvals.model_failure_diagnosis("\n".join(json.dumps(event) for event in (events[0], events[2])), marker)
    with pytest.raises(AssertionError, match="reported success"):
        installed_shared_approvals.model_failure_diagnosis(output + '{"type":"turn.completed"}\n', marker)
    with pytest.raises(AssertionError, match="Helper exited 0; expected 1"):
        installed_shared_approvals.run_helper(
            [sys.executable, "-c", f"print({output!r})"], tmp_path / "false-success.jsonl", expected_exit=1)


def test_helper_journey_waits_for_external_canonical_decision(monkeypatch):
    """Pending preparation never decides; a later human outcome unlocks retry."""
    action = {"kind": "network_allow", "agent": "worker", "agent_id": "worker-id",
              "host": "127.0.0.2", "port": 49123, "revision": "selected"}
    pending = {"request_id": "selected", "status": "pending", "action": action}
    approved = {**pending, "status": "approved"}
    replies = iter([pending, pending, approved])
    reads = []

    def read():
        reply = next(replies)
        reads.append(reply["status"])
        return reply

    monkeypatch.setattr(installed_shared_approvals.time, "sleep", lambda _seconds: None)
    assert installed_shared_approvals.wait_for_operator(read, action, 1) == approved
    assert reads == ["pending", "pending", "approved"]
    assert pending["status"] == "pending"


@pytest.mark.parametrize("status", ["rejected", "unavailable"])
def test_helper_journey_refuses_nonapproval(status):
    action = {"agent": "worker", "host": "127.0.0.2", "port": 49123}
    with pytest.raises(AssertionError, match="no Worker retry"):
        installed_shared_approvals.wait_for_operator(lambda: {"action": action, "status": status}, action, 1)


def test_helper_journey_expiry_and_changed_action_do_not_grant():
    action = {"agent": "worker", "host": "127.0.0.2", "port": 49123}
    with pytest.raises(AssertionError, match="no automatic approval"):
        installed_shared_approvals.wait_for_operator(lambda: {"action": action, "status": "pending"}, action, 0)
    with pytest.raises(AssertionError, match="operator action changed"):
        installed_shared_approvals.wait_for_operator(lambda: {
            "action": {**action, "port": 49124}, "status": "approved"}, action, 1)


def test_failed_real_helper_output_survives_before_parsing(tmp_path):
    """One failed model attempt retains its operands without a diagnostic rerun."""
    events = tmp_path / "helper-events.jsonl"
    command = [sys.executable, "-c", 'import sys; print("unparsed failing event"); print("failure operand", file=sys.stderr); raise SystemExit(1)']
    with pytest.raises(AssertionError, match="inspect private events"):
        installed_shared_approvals.run_helper(command, events)
    assert events.read_text() == "unparsed failing event\n"
    assert stat.S_IMODE(events.stat().st_mode) == 0o600
    errors = tmp_path / "helper-events.jsonl.stderr"
    assert errors.read_text() == "failure operand\n"
    assert stat.S_IMODE(errors.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        installed_shared_approvals.run_helper([sys.executable, "-c", 'print("replacement")'], events)
    assert events.read_text() == "unparsed failing event\n"


PRIVATE_CAPTURE_DESCRIPTOR_CHECK = "\n".join([
    "import os, stat, sys",
    "assert all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1, 2))",
    "assert os.fstat(1).st_ino != os.fstat(2).st_ino",
    "saved = [os.stat(path) for path in sys.argv[1:3]]",
    "directory = '/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'",
    "for entry in os.listdir(directory):",
    "    try: current = os.fstat(int(entry))",
    "    except OSError: continue  # The directory enumeration FD is already closed.",
    "    assert all((current.st_dev, current.st_ino) != (path.st_dev, path.st_ino) for path in saved), 'private capture descriptor reached child'",
])


def test_helper_capture_refuses_a_donated_private_file_descriptor(tmp_path):
    events = tmp_path / "events"
    errors = tmp_path / "errors"
    errors.write_bytes(b"")
    with events.open("xb") as donated:
        result = subprocess.run(
            [sys.executable, "-c", PRIVATE_CAPTURE_DESCRIPTOR_CHECK, str(events), str(errors)],
            pass_fds=(donated.fileno(),), capture_output=True, timeout=5,
        )
    assert result.returncode != 0
    assert b"private capture descriptor reached child" in result.stderr


def test_helper_capture_keeps_private_files_in_parent_and_flushes_before_exit(tmp_path):
    """Actual child descriptors are pipes; both large streams are readable live."""
    events = tmp_path / "helper-events.jsonl"
    errors = events.with_name(events.name + ".stderr")
    stdout_unit = b'{"event":"private output"}\r\n'
    stderr_unit = b"private stderr\r\n\x00\xff"
    stdout, stderr = stdout_unit * 32768, stderr_unit * 32768
    tail = b'{"event":"after barrier"}\r\n'
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        script = "\n".join([
            "import os, socket, stat, sys, threading",
            PRIVATE_CAPTURE_DESCRIPTOR_CHECK,
            "def write(fd, data):",
            "    while data: data = data[os.write(fd, data):]",
            "outputs = [threading.Thread(target=write, args=(fd, data)) for fd, data in",
            f"           ((1, {stdout_unit!r} * 32768), (2, {stderr_unit!r} * 32768))]",
            "for output in outputs: output.start()",
            "for output in outputs: output.join()",
            f"with socket.create_connection({listener.getsockname()!r}, timeout=5) as barrier:",
            "    assert barrier.recv(1) == b'x'",
            f"write(1, {tail!r})",
        ])
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(installed_shared_approvals.run_helper,
                [sys.executable, "-c", script, str(events), str(errors)], events, timeout=5)
            connection, _ = listener.accept()
            with connection:
                try:
                    deadline = time.monotonic() + 3
                    while events.read_bytes() != stdout or errors.read_bytes() != stderr:
                        assert time.monotonic() < deadline, "output was not flushed before exit"
                        time.sleep(0.01)
                    assert not result.done()
                    for path in (events, errors):
                        state = path.stat()
                        assert stat.S_IMODE(state.st_mode) == 0o600
                        assert (state.st_uid, state.st_gid) == (os.getuid(), os.getgid())
                    assert events.stat().st_ino != errors.stat().st_ino
                finally:
                    connection.sendall(b"x")
            assert result.result(timeout=5) == (stdout + tail).decode().replace("\r\n", "\n")
    assert events.read_bytes() == stdout + tail
    assert errors.read_bytes() == stderr


@pytest.mark.parametrize("failure", ["nonzero", "launch", "timeout", "closed_timeout", "lingering_zero", "lingering_nonzero"])
def test_helper_capture_preserves_partial_bytes_and_precleanup_exit(tmp_path, monkeypatch, failure):
    """A live writer cannot hide a completed exit or prevent owned cleanup."""
    events = tmp_path / "helper-events.jsonl"
    errors = events.with_name(events.name + ".stderr")
    stdout, stderr = b"partial\r\n\x00\xff", b"stderr\r\n\xff"
    lingering = failure.startswith("lingering_")
    live = failure in {"timeout", "closed_timeout"}
    code = 17 if failure in {"nonzero", "lingering_nonzero"} else 0
    script = f"import os,sys,time\nos.write(1,{stdout!r})\nos.write(2,{stderr!r})\n"
    if failure == "closed_timeout":
        script += "os.close(1);os.close(2)\n"
    script += "time.sleep(5)\n" if live else f"sys.exit({code})\n"
    command = [str(tmp_path / "absent")] if failure == "launch" else [sys.executable, "-c", script]
    popen = subprocess.Popen
    children, writers = [], []

    def launch(*args, **kwargs):
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        if lingering:
            stdout_read, stdout_write = os.pipe()
            stderr_read, stderr_write = os.pipe()
            try:
                process = popen(*args, **{**kwargs, "stdout": stdout_write, "stderr": stderr_write})
                process.stdout = os.fdopen(stdout_read, "rb", buffering=0)
                process.stderr = os.fdopen(stderr_read, "rb", buffering=0)
                writers.append(popen([sys.executable, "-c", "import time;time.sleep(10)"],
                    stdout=stdout_write, stderr=stderr_write))
                process.wait(timeout=3)
            finally:
                os.close(stdout_write)
                os.close(stderr_write)
        else:
            process = popen(*args, **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(installed_shared_approvals.subprocess, "Popen", launch)
    expected = FileNotFoundError if failure == "launch" else AssertionError if code else subprocess.TimeoutExpired
    started = time.monotonic()
    try:
        with pytest.raises(expected) as raised:
            installed_shared_approvals.run_helper(command, events, timeout=0.2)
        assert time.monotonic() - started < 3
        assert all(child.poll() is not None for child in children)
        assert events.read_bytes() == (b"" if failure == "launch" else stdout)
        assert errors.read_bytes() == (b"" if failure == "launch" else stderr)
        if code:
            assert "Helper exited 17" in str(raised.value)
            assert children[0].returncode == 17
        if failure == "lingering_nonzero":
            assert isinstance(raised.value.__cause__, subprocess.TimeoutExpired)
            assert "capture also failed" in raised.value.__notes__[0]
        elif not code:
            observed = "0" if lingering else "unknown"
            assert f"exit before cleanup: {observed}" in raised.value.__notes__[0]
        if live:
            assert children[0].returncode < 0
        if lingering:
            assert children[0].returncode == code and all(writer.poll() is None for writer in writers)
        # This is the caller's independently owned cleanup, after capture returned.
    finally:
        for child in [*children, *writers]:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
    for path in (events, errors):
        state = path.stat()
        assert stat.S_IMODE(state.st_mode) == 0o600
        assert (state.st_uid, state.st_gid) == (os.getuid(), os.getgid())


@pytest.mark.parametrize("exit_code", [None, 0, 17])
def test_helper_capture_write_failure_keeps_partial_output_and_original_error(tmp_path, monkeypatch, exit_code):
    events = tmp_path / "helper-events.jsonl"
    children = []
    popen, fdopen = subprocess.Popen, os.fdopen

    def launch(*args, **kwargs):
        process = popen(*args, **kwargs)
        children.append(process)
        if exit_code is not None:
            process.wait(timeout=3)
        return process

    class FailedEvents:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def write(self, data):
            self.file.write(data[:4])
            self.file.flush()
            raise PermissionError("controlled private capture failure")

    def open_output(fd, *args, **kwargs):
        file = fdopen(fd, *args, **kwargs)
        return FailedEvents(file) if os.fstat(fd).st_ino == events.stat().st_ino else file

    monkeypatch.setattr(installed_shared_approvals.subprocess, "Popen", launch)
    monkeypatch.setattr(installed_shared_approvals.os, "fdopen", open_output)
    script = "import os,sys,time\nos.write(1,b'partial output')\n"
    script += "time.sleep(5)\n" if exit_code is None else f"sys.exit({exit_code})\n"
    with pytest.raises(AssertionError if exit_code == 17 else PermissionError) as raised:
        installed_shared_approvals.run_helper([sys.executable, "-c", script], events, timeout=3)
    assert events.read_bytes() == b"part"
    assert len(children) == 1 and children[0].poll() is not None
    if exit_code == 17:
        assert "Helper exited 17" in str(raised.value)
        assert isinstance(raised.value.__cause__, PermissionError)
        assert "controlled private capture failure" in raised.value.__notes__[0]
    else:
        assert str(raised.value) == "controlled private capture failure"
        observed = "unknown" if exit_code is None else "0"
        assert f"exit before cleanup: {observed}" in raised.value.__notes__[0]
    if exit_code is None:
        assert children[0].returncode < 0
    else:
        assert children[0].returncode == exit_code


def test_harness_assigns_distinct_proxy_admin_and_web_ports():
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "TEST_PROXY_PORT=8180" in harness
    assert "TEST_ADMIN_PORT=9190" in harness
    assert "TEST_WEB_PORT=8181" in harness
    assert "TEST_PROXY_PORT=8180" in harness
    assert 'config["admin_port"] = int(sys.argv[2])' in harness
    assert "TEST_WEB_PORT=8181" in harness


def test_native_isolation_lane_selects_rust_before_test_start():
    """Ordinary installed guest runs select the production native runtime."""
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    selector = "INSTALLED_RUST_BIN="
    start = "safeyolo start"
    assert 'PROXY_IMPL="rust"' in harness
    assert selector in harness
    assert harness.index(selector) < harness.index(start)


def test_installed_native_vm_lane_fails_before_instance_setup_without_packaged_binary(tmp_path):
    """A native guest label cannot fall back to a checkout binary or Python."""
    cli = tmp_path / "safeyolo"
    cli.write_text("#!/bin/sh\nprintf 'safeyolo fixture\\n'\n")
    cli.chmod(0o755)
    config_dir = tmp_path / "test-instance"
    result = subprocess.run(
        [str(Path(__file__).parent / "blackbox" / "run-tests.sh"), "--isolation", "--proxy-impl", "rust"],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "SAFEYOLO_TEST_CONFIG_DIR": str(config_dir),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "installed CLI has no usable packaged Rust proxy" in result.stderr
    assert not config_dir.exists()


@pytest.mark.parametrize("options", [
    ["--expect-platform", "vz", "--proxy-impl", "rust", "--workloads"],
    ["--expect-platform", "kvm", "--proxy-impl", "python", "--workloads"],
    ["--expect-platform", "kvm", "--proxy-impl", "rust", "--workloads", "--ingress"],
])
def test_workloads_reject_a_different_lane_before_setup(tmp_path, options):
    config_dir = tmp_path / "test-instance"
    result = subprocess.run(
        [str(Path(__file__).parent / "blackbox" / "run-tests.sh"), *options],
        env={**os.environ, "SAFEYOLO_TEST_CONFIG_DIR": str(config_dir)},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    if "python" in options:
        assert "unsupported proxy implementation" in result.stderr
    else:
        assert "--workloads requires --expect-platform kvm|systrap --proxy-impl rust" in result.stderr
    assert not config_dir.exists()


def test_runner_cleanup_only_reclaims_owned_sinkhole_processes():
    """The compatibility lane must not kill unrelated process names."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "pkill" not in runner
    assert "killall" not in runner
    assert 'SINKHOLE_PID_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.pid"' in runner
    assert (
        'stop_owned_pid_file "$SINKHOLE_PID_FILE" "$SINKHOLE_SCRIPT" "$SINKHOLE_ARGV_FILE"'
        in runner
    )
    assert 'SINKHOLE_ARGV_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.argv"' in runner
    assert 'printf \'%s\\n%s\\n\' "$SINKHOLE_PID" "$SINKHOLE_START_ID" > "$SINKHOLE_PID_FILE"' in runner
    assert 'kill "$HOST_LISTENER_PID"' in runner
    assert "printf -v quoted_arg '%q' \"$forwarded_arg\"" in runner
    assert 'pytest${PYTEST_FORWARD_SHELL}' in runner


def test_vz_fixture_shares_http_origin_parent_and_control_without_losing_capture(tmp_path):
    """The fixed HTTP listener serves each path and rejects an unknown direct host."""
    from server import clear_requests, get_requests

    with Parent(None, None, host="127.0.0.1", request_handler=VZRequest) as server:
        server.https_port = 1
        server.p2_fixture = P2Fixture(tmp_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            clear_requests()

            def get(target, host, **headers):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    connection.request("GET", target, headers={"Host": host, **headers})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            assert get("/health", "127.0.0.1")[0] == 200
            assert get("/p2/health", "127.0.0.1")[0] == 200
            assert get("/p4/echo/p4-" + "a" * 32, "failing.test") == (
                200, b"echo:p4-" + b"a" * 32
            )
            assert get("/p4/echo/invalid", "failing.test")[0] == 400
            assert get("/direct", "httpbin.org")[0] == 200
            assert get("http://httpbin.org/absolute?x=1", "httpbin.org",
                       **{"Proxy-Authorization": "Basic fixture"})[0] == 200
            assert get("/unknown", "unknown.test")[0] == 400
            assert get(f"http://127.0.0.1:{server.server_port}/health", "127.0.0.1")[0] == 502
            assert get("http://httpbin.org:bad/path", "httpbin.org")[0] == 400
            assert get("/requests", "127.0.0.1")[0] == 200
            captured = get_requests(host="httpbin.org")
            assert [(item.path, item.raw_target) for item in captured] == [
                ("/direct", "/direct"),
                ("/absolute", "/absolute?x=1"),
            ]
            assert "Proxy-Authorization" not in captured[1].headers
        finally:
            server.shutdown()
            thread.join(timeout=5)
            clear_requests()


def _runner_cleanup_helpers():
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    start = runner.index("canonical_path() {")
    end = runner.index("\ncleanup() {", start)
    return runner[start:end]


def _run_cleanup_probe(tmp_path, mode, *, reference_path=None):
    target = tmp_path / "owned-process.py"
    target.write_text(
        "import signal\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        "if '--ignore-term' in sys.argv:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "Path(sys.argv[0] + '.ready').write_text('ready')\n"
        "time.sleep(60)\n"
    )
    probe = tmp_path / f"cleanup-{mode}.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        + _runner_cleanup_helpers()
        + """
expected="$1"
mode="$2"
pid_file="$3"
argv_file="$4"
target_pid=""
owned_pids=()

cleanup_probe() {
    local pid
    for pid in ${owned_pids[@]+"${owned_pids[@]}"}; do
        kill "$pid" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup_probe EXIT

record_process() {
    local pid="$1"
    local output="$2"
    local start
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        start="$(process_start_identity "$pid" 2>/dev/null || true)"
        if [ -n "$start" ] && capture_process_argv "$pid" "$output" && [ -s "$output" ]; then
            printf '%s\n' "$start"
            return 0
        fi
        sleep 0.05
    done
    return 1
}

case "$mode" in
    owned)
        python3 "$expected" &
        target_pid=$!
        owned_pids+=("$target_pid")
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=owned_survived'
            exit 1
        fi
        echo 'result=owned_stopped'
        ;;
    ignore)
        python3 "$expected" --ignore-term &
        target_pid=$!
        owned_pids+=("$target_pid")
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=ignore_survived'
            exit 1
        fi
        echo 'result=ignore_stopped'
        ;;
    unrelated)
        python3 -c 'import time; time.sleep(60)' "$expected" &
        target_pid=$!
        owned_pids+=("$target_pid")
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if ! kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=unrelated_killed'
            exit 1
        fi
        echo 'result=unrelated_survived'
        ;;
    stale)
        python3 "$expected" &
        stale_pid=$!
        owned_pids+=("$stale_pid")
        stale_start="$(record_process "$stale_pid" "$argv_file")"
        kill "$stale_pid"
        wait "$stale_pid" 2>/dev/null || true
        owned_pids=()
        printf '%s\n%s\n' "$stale_pid" "$stale_start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        echo 'result=stale_safe'
        ;;
    reused)
        python3 "$expected" &
        stale_pid=$!
        owned_pids+=("$stale_pid")
        stale_start="$(record_process "$stale_pid" "$argv_file")"
        kill "$stale_pid"
        wait "$stale_pid" 2>/dev/null || true
        owned_pids=()
        python3 -c 'import time; time.sleep(60)' "$expected" &
        target_pid=$!
        owned_pids+=("$target_pid")
        printf '%s\n%s\n' "$target_pid" "$stale_start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if ! kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=reused_killed'
            exit 1
        fi
        echo 'result=reused_survived'
        ;;
    bootstrap_failure)
        python3 "$expected" --ignore-term &
        target_pid=$!
        owned_pids+=("$target_pid")
        printf '%s\n' "$target_pid" > "$pid_file"
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            [ ! -e "$expected.ready" ] || break
            sleep 0.05
        done
        test -e "$expected.ready"
        # Challenge a real failed child import before an ownership receipt.
        python3 -c 'from safeyolo.runtime_identity import process_start_token'
        ;;
    *)
        echo "unknown mode: $mode" >&2
        exit 2
        ;;
esac
"""
    )
    probe.chmod(0o755)
    result = subprocess.run(
        [str(probe), str(target), mode, str(tmp_path / "owned.pid"), str(tmp_path / "owned.argv")],
        env={**os.environ, "SCRIPT_DIR": str(Path(__file__).parent / "blackbox"),
             "PYTHONPATH": str(reference_path if reference_path is not None else Path(__file__).parent / "reference")},
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if mode == "bootstrap_failure":
        assert result.returncode != 0 and "ModuleNotFoundError" in result.stderr, result.stderr + result.stdout
        return result.stdout
    assert result.returncode == 0, result.stderr + result.stdout
    return result.stdout


@pytest.mark.parametrize("mode", ["owned", "unrelated", "stale", "reused", "ignore"])
def test_runner_cleanup_process_identity_behaves_as_owned_only(tmp_path, mode):
    output = _run_cleanup_probe(tmp_path, mode)

    assert f"result={mode}_" in output
    if mode == "ignore":
        assert "Escalating owned process" in output
    else:
        assert "Escalating owned process" not in output


def test_cleanup_probe_reaps_term_ignoring_child_after_failed_bootstrap(tmp_path):
    _run_cleanup_probe(tmp_path, "bootstrap_failure", reference_path=tmp_path / "absent-reference")
    assert (tmp_path / "owned-process.py.ready").exists()
    pid = int((tmp_path / "owned.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.parametrize("forwarded", [False, True])
def test_runner_vm_forwarding_preserves_arguments_without_shell_execution(tmp_path, forwarded):
    """Empty and supplied VM arguments work with the host's /bin/bash."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    start = runner.index('PYTEST_FORWARD_SHELL=""')
    end = runner.index("\n\n# The focused", start)
    quoting = runner[start:end]
    output = tmp_path / "forwarded.json"
    sentinel = tmp_path / "injected"
    probe = tmp_path / "forwarding.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "output=\"$1\"\n"
        "shift\n"
        "PYTEST_FORWARD_ARGS=(\"$@\")\n"
        + quoting
        + "\n"
        "printf -v code '%q' 'import json,sys; print(json.dumps(sys.argv[1:]))'\n"
        "bash -lc \"python3 -c $code${PYTEST_FORWARD_SHELL}\" > \"$output\"\n"
    )
    probe.chmod(0o755)
    arguments = [
        "--marker",
        "value with spaces",
        f"$(touch {sentinel})",
        f"semi;touch {sentinel}",
        "*",
        "quote\"single'",
        "line1\nline2",
    ] if forwarded else []
    result = subprocess.run(
        ["/bin/bash", str(probe), str(output), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text()) == arguments
    assert not sentinel.exists()


def test_kvm_lane_prepares_operator_and_subordinate_access_before_native_installation():
    lane = (Path(__file__).parent / "blackbox/run-lane.sh").read_text()
    acl = 'sudo -n setfacl -m "u:$(id -u):rw,u:100000:rw" /dev/kvm'
    assert acl in lane
    assert lane.index(acl) < lane.index('"$checkout/install.sh"')
    assert 'safeyolo bootstrap' not in lane


@pytest.mark.parametrize('lane,system', [('vz', 'Darwin'), ('proxy', 'Linux')])
@pytest.mark.parametrize('start_exit', [0, 7])
def test_lane_preparation_selects_vz_coord_ports_and_preserves_start_failure(tmp_path, lane, system, start_exit):
    """Execute the maintained preparer with controlled installer/tool output."""
    tools = tmp_path / 'tools'
    checkout = tmp_path / 'checkout'
    root = tmp_path / 'owned'
    assets = tmp_path / 'assets'
    for path in (tools, checkout, assets):
        path.mkdir()
    for name in ('Image', 'initramfs.cpio.gz', 'rootfs-base.ext4'):
        (assets / name).touch()
    (tools / 'uname').write_text(f'#!/bin/sh\nprintf "%s\\n" {system}\n')
    (tools / 'uv').write_text('#!/bin/sh\nexit 0\n')
    native = tools / 'selected-native'
    calls = tmp_path / 'calls'
    native.write_text(f'''#!{sys.executable}
import json,sys
with open({str(calls)!r}, 'a') as stream:
    stream.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[4] == 'start': sys.exit({start_exit})
''')
    (checkout / 'install.sh').write_text(
        f'#!/bin/sh\nmkdir -p {shlex.quote(str(root / "bin"))}\n'
        f'cp {shlex.quote(str(native))} {shlex.quote(str(root / "bin/safeyolo"))}\n'
    )
    for path in (tools / 'uname', tools / 'uv', native, checkout / 'install.sh'):
        path.chmod(0o755)
    env = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}', SAFEYOLO_CONFIG_DIR=str(root),
               SAFEYOLO_PLATFORM_ASSETS=str(assets), SAFEYOLO_NATIVE_BUNDLE=str(tmp_path / 'bundle'),
               SAFEYOLO_COORD_NATS_BINARY=str(tmp_path / 'pinned-nats'))
    result = subprocess.run([str(ROOT / 'tests/blackbox/run-lane.sh'), lane,
                             '--install-checkout', str(checkout), '--prepare-only'],
                            env=env, capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == start_exit, result.stderr
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    expected = ['--root', str(root), 'coord', 'start', '--binary', env['SAFEYOLO_COORD_NATS_BINARY']]
    if lane == 'vz':
        expected += ['--client-port', '46370', '--monitor-port', '46372']
    assert commands == [expected] + ([] if start_exit else [['--root', str(root), 'coord', 'stop']])
    assert ('no test guest started' in result.stdout) == (start_exit == 0)


def test_backend_selector_records_actual_rust_binary_identity(tmp_path):
    """Rust evidence comes from the executable's version and bytes."""
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("#!/bin/sh\nprintf 'safeyolo-proxy 0.1.0 (fixture)\\n'\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

    result = identity("rust", rust_bin=binary, test_suite_root=Path(__file__).parents[1])

    assert result["executable"] == str(binary.resolve())
    assert result["executable_version"].startswith("safeyolo-proxy 0.1.0")
    assert result["policy_mode"] == "native"
    assert len(result["executable_sha256"]) == 64
    assert result["test_suite"]["root"] == str(Path(__file__).parents[1].resolve())

    wrong = tmp_path / "wrong-program"
    wrong.write_text("#!/bin/sh\nprintf 'something-else\\n'\n")
    wrong.chmod(wrong.stat().st_mode | stat.S_IXUSR)
    try:
        identity("rust", rust_bin=wrong)
    except SelectionError as exc:
        assert "unexpected identity" in str(exc)
    else:
        raise AssertionError("an unrelated executable was accepted as Rust")


def test_backend_selector_reports_unknown_interpreter_for_pytest_wrapper(tmp_path, monkeypatch, native_binary):
    """A shell wrapper must not be reported as a Python interpreter."""
    launcher = tmp_path / "pytest"
    launcher.write_text('#!/bin/sh\nexec python3 -m pytest "$@"\n')
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")

    python = identity("rust", rust_bin=native_binary, test_suite_root=Path(__file__).parents[1])["python"]
    assert python["pytest_launcher"] == str(launcher)
    assert python["interpreter"] is None
    assert python["interpreter_version"] is None

    launcher.write_text(f"#!{sys.executable}\n")
    python = identity("rust", rust_bin=native_binary, test_suite_root=Path(__file__).parents[1])["python"]
    assert Path(python["interpreter"]).resolve() == Path(sys.executable).resolve()
    assert python["interpreter_version"] == sys.version


@pytest.mark.parametrize("selector", ["wasm", "python", "both"])
def test_selected_runner_rejects_bad_selector_and_missing_binary(tmp_path, selector):
    """Invalid selections fail before setup can touch a live instance."""
    runner = Path(__file__).parent / "blackbox" / "run-tests.sh"
    invalid = subprocess.run(
        [str(runner), "--proxy", "--proxy-impl", selector],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode == 2
    assert "unsupported proxy implementation" in invalid.stderr

    missing = subprocess.run(
        [str(runner), "--proxy", "--proxy-impl", "rust", "--rust-bin", str(tmp_path / "gone")],
        text=True,
        capture_output=True,
        check=False,
    )
    assert missing.returncode == 2
    assert "Rust proxy executable" in missing.stderr


def test_selected_runner_rejects_wrong_rust_executable_before_pytest(tmp_path):
    """A wrong program is infrastructure failure, without a fallback run."""
    binary = tmp_path / "wrong-program"
    binary.write_text("#!/bin/sh\nprintf 'unrelated-program 1.0\\n'\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    pytest_log = tmp_path / "pytest-ran"
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(f"#!/bin/sh\ntouch {pytest_log}\nexit 0\n")
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    artifacts = tmp_path / "artifacts"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(artifacts),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "rust",
            "--rust-bin",
            str(binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unexpected identity" in result.stderr
    assert not pytest_log.exists()
    evidence = json.loads((artifacts / "proxy-rust-runtime.json").read_text())
    assert evidence["backend"] == "rust"
    assert evidence["status"] == "infrastructure_failure"


@pytest.mark.parametrize(
    "pytest_exit,expected",
    [(1, 1), (2, 2), (3, 2), (4, 2), (5, 2)],
    ids=["test-failure", "interrupted", "internal", "usage", "no-collection"],
)
def test_selected_runner_classifies_pytest_exit_codes(tmp_path, pytest_exit, expected, native_binary):
    """Only pytest's ordinary test-failure code remains a test failure."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(f"#!/bin/sh\nexit {pytest_exit}\n")
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(tmp_path / "artifacts"),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "rust",
            "--rust-bin",
            str(native_binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == expected


INSTALLED_PYTEST_SLOTS = (
    "PROXY", "FIREWALL", "IDENTITY", "ISOLATION", "ROOT_ISOLATION", "LIFECYCLE",
)


@pytest.fixture
def installed_pytest_runner(tmp_path):
    """Run the installed suite commands and summary with controlled command exits."""
    directory = tmp_path / "pytest-runner"
    (directory / "host").mkdir(parents=True)
    runner = (Path(__file__).parent / "blackbox/run-tests.sh").read_text()
    script = directory / "run-tests.sh"
    script.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        + r'''
SCRIPT_DIR="$(dirname "$0")"
RUN_PROXY=true
RUN_ISOLATION=true
AGENT_NAME=bbtest
INSTALLED_CLI=fixture-package-cli
VERBOSE=
PYTEST_FORWARD_ARGS=()
PYTEST_FORWARD_SHELL=

fixture_suite_exit() {
    printf '%s\n' "$1" >> "$SCRIPT_DIR/suites.log"
    local variable="FIXTURE_${1}_EXIT"
    return "${!variable:-0}"
}

pytest() {
    case "$*" in
        *native/) fixture_suite_exit PROXY ;;
        *security/) fixture_suite_exit FIREWALL ;;
        *identity/) fixture_suite_exit IDENTITY ;;
        *lifecycle/) fixture_suite_exit LIFECYCLE ;;
        *) return 99 ;;
    esac
}

python3() {
    if [[ "$1" != */guest_exec.py ]]; then
        command python3 "$@"
        return
    fi
    case "$*" in
        *"--user root"*) fixture_suite_exit ROOT_ISOLATION ;;
        *) fixture_suite_exit ISOLATION ;;
    esac
}
'''
        + runner[runner.index("# --- Phase 2: Run tests ---"):]
    )
    script.chmod(0o755)
    return script


@pytest.mark.parametrize("slot", INSTALLED_PYTEST_SLOTS)
@pytest.mark.parametrize("suite_exit,expected", [(1, 1), (2, 2), (3, 2), (4, 2), (5, 2), (127, 2)])
def test_installed_runner_classifies_each_suite_exit(installed_pytest_runner, slot, suite_exit, expected):
    env = {**os.environ, **{f"FIXTURE_{name}_EXIT": "0" for name in INSTALLED_PYTEST_SLOTS}}
    env[f"FIXTURE_{slot}_EXIT"] = str(suite_exit)
    result = subprocess.run(
        [str(installed_pytest_runner)], env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)


@pytest.mark.parametrize("suite_exits,expected", [
    ((0, 0, 0, 0, 0, 0), 0),
    ((3, 0, 0, 0, 0, 1), 2),
    ((1, 0, 0, 0, 0, 3), 2),
], ids=["all-success", "infrastructure-before-assertion", "infrastructure-after-assertion"])
def test_installed_runner_failure_precedence(installed_pytest_runner, suite_exits, expected):
    env = {**os.environ, **{
        f"FIXTURE_{slot}_EXIT": str(code) for slot, code in zip(INSTALLED_PYTEST_SLOTS, suite_exits, strict=True)
    }}
    result = subprocess.run(
        [str(installed_pytest_runner)], env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)


def test_selected_runner_classifies_readiness_failure_as_infrastructure(tmp_path, native_binary):
    """A legacy pytest plugin's code-1 readiness report is still infrastructure."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in --junitxml=*) junit=\"${arg#*=}\";; esac\n"
        "done\n"
        "printf '%s\\n' '<testsuite><testcase><failure>ReadinessError: timed out</failure></testcase></testsuite>' > \"$junit\"\n"
        "exit 1\n"
    )
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    artifacts = tmp_path / "artifacts"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(artifacts),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "rust",
            "--rust-bin",
            str(native_binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2


@pytest.mark.parametrize("native_policy", [False, True])
def test_selected_rust_runner_requires_native_policy_provenance(tmp_path, monkeypatch, native_policy):
    """Every Rust fixture supplies its policy file and records native ownership."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    selector = (Path(__file__).parent / "proxy_contracts" / "run.py").read_text()
    assert "SAFEYOLO_RUST_NATIVE_ONLY" not in runner + selector

    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("fixture binary")
    monkeypatch.setenv("SAFEYOLO_RUST_PROXY", str(binary))

    @contextmanager
    def fake_child_process(command, directory, env):
        assert command[0] == str(binary)
        yield object()

    monkeypatch.setattr(proxy_harness, "child_process", fake_child_process)
    monkeypatch.setattr(proxy_harness, "wait_ready", lambda *args, **kwargs: None)
    directory = tmp_path / "fixture"
    with proxy_harness.launch_proxy(
        "rust", directory, '[hosts]\n"*" = { egress = "deny" }\n',
        native_policy=native_policy,
    ):
        config = json.loads((directory / "proxy.json").read_text())
        provenance = json.loads((directory / "native-policy-provenance.json").read_text())

    assert config["policy_file"] == str(directory / "policy.toml")
    assert "temporary_policy_socket" not in config
    assert provenance == {
        "backend": "rust",
        "policy_mode": "native",
        "policy_file": config["policy_file"],
        "temporary_policy_socket": None,
        "temporary_policy_adapter": False,
    }


ROOT = Path(__file__).resolve().parents[1]
REQUEST_ID = "req-" + "a" * 32
MARKER = "p3-" + "b" * 32
OTHER_REVISION = "b" * 40
SELECTED_REVISION = "a" * 40


@pytest.mark.parametrize("platform,operator_journey", [("systrap", False), ("systrap", True),
                                                        ("vz", False), ("vz", True)])
def test_access_launcher_targets_match_selected_guest_requests(tmp_path, monkeypatch, platform, operator_journey):
    """Read the launcher's final native policy and capture its matching guest calls."""
    binary = os.environ.get('SAFEYOLO_TEST_NATIVE_CLI')
    if not binary:
        pytest.skip('requires built native CLI (SAFEYOLO_TEST_NATIVE_CLI)')
    tools = tmp_path / 'tools'
    tools.mkdir()
    (tools / 'safeyolo').symlink_to(binary)
    source = tmp_path / "source-instance"
    instance = tmp_path / "test-instance"
    environment = os.environ.copy()
    environment.update(
        SAFEYOLO_CONFIG_DIR=str(source),
        SAFEYOLO_TEST_CONFIG_DIR=str(instance),
        SAFEYOLO_NATIVE_CLI=str(binary),
        PATH=f"{tools}:{Path(sys.executable).parent}:{environment['PATH']}",
        PYTHONPATH=f"{ROOT / 'tests/reference'}:{ROOT}",
    )
    command = [
        str(ROOT / "tests/blackbox/run-tests.sh"),
        "--expect-platform",
        platform,
        "--proxy-impl",
        "rust",
        "--access-config-only",
    ]
    if operator_journey:
        command.append("--operator-journey")
    prepared = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert prepared.returncode == 0, prepared.stdout[-1000:] + prepared.stderr[-1000:]
    assert "no proxy or guest started" in prepared.stdout
    config = tomllib.loads((instance / "config.toml").read_text())
    assert config.get("desktop", {}).get("present_host_port", 0) == (
        46375 if platform == "vz" and operator_journey else 0
    )
    targets = tomllib.loads((instance / "policy.toml").read_text())["controls"]["test_context"]["target_hosts"]
    policy = tomllib.loads((instance / "policy.toml").read_text())
    assert policy["hosts"][guest.BASIC_HOST]["service"] == "p3_basic"
    assert policy["hosts"][guest.CONTRACT_HOST]["service"] == "p3_contract"
    assert policy["hosts"]["failing.test"]["egress"] == "allow"

    calls: list[tuple[str, str, bool]] = []

    def exchange(method, target, *, headers=None, **_kwargs):
        calls.append((method, urlsplit(target).hostname, bool(headers and "X-SafeYolo-Test-Context" in headers)))
        status = 428 if method == "POST" else 200
        return status, {"x-safeyolo-request-id": REQUEST_ID}, b'{"received":true}'

    declared = None

    def api(method, path, *, payload=None):
        nonlocal declared
        if method == "POST" and path == "/api/test-context/current":
            declared = {"run": "installed-p3", "agent": "bbtest", "test": MARKER}
            return 200, {}, {"context": declared}
        if method == "GET" and path == "/api/test-context/current":
            return 200, {}, {"context": declared}
        if method == "GET" and path.startswith("/trace?"):
            return 200, {}, {"agent_id": "bbtest"}
        if method == "POST" and path == "/api/flows/search":
            return 200, {}, {"flows": [{"id": "owned-flow", "request_id": REQUEST_ID, "agent_id": "bbtest"}]}
        if method == "GET" and path == "/api/flows/owned-flow":
            return 200, {}, {"request_id": REQUEST_ID}
        if method == "DELETE" and path == "/api/test-context/current":
            declared = None
            return 200, {}, {"status": "cleared"}
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(guest, "service_token", lambda _service: "sgw_fixture")
    monkeypatch.setattr(guest, "exchange", exchange)
    monkeypatch.setattr(guest, "api", api)
    guest.basic_read(MARKER)
    guest.contract_prompt()
    guest.context_and_evidence("bbtest", MARKER)

    assert calls == [
        ("GET", guest.BASIC_HOST, False),
        ("POST", guest.CONTRACT_HOST, False),
        ("GET", guest.BASIC_HOST, True),
    ]
    assert targets == ["failing.test"], (
        "access needs an owned activation target without mandatory context on ordinary hosts"
    )
    assert all(host not in targets or has_context for _, host, has_context in calls)
    assert guest.BASIC_HOST not in targets, "the explicit header must exercise a non-target host"

    # The operator's execution-970 configuration would block both ordinary calls.
    old_targets = ["httpbin.org", "failing.test", "legitimate-api.com", "httpbin.org"]
    assert [host for _, host, has_context in calls if host in old_targets and not has_context] == [
        guest.BASIC_HOST,
        guest.CONTRACT_HOST,
    ]


def test_installed_setup_command_failure_is_infrastructure(tmp_path):
    cli = tmp_path / "safeyolo"
    cli.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then\n"
                   "echo 'safeyolo 0.1.0 commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa profile=debug'\n"
                   "exit 0\nfi\necho 'deliberate init failure' >&2\nexit 1\n")
    cli.chmod(0o755)
    environment = {**os.environ,
                   "PATH": f"{tmp_path}:{Path(sys.executable).parent}:{os.environ['PATH']}",
                   "SAFEYOLO_NATIVE_CLI": str(cli),
                   "SAFEYOLO_CONFIG_DIR": str(tmp_path / "prepared"),
                   "SAFEYOLO_TEST_CONFIG_DIR": str(tmp_path / "section")}
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--expect-platform", "systrap",
         "--access-config-only"],
        env=environment, capture_output=True, text=True, check=False, timeout=20,
    )
    assert "deliberate init failure" in result.stderr
    assert result.returncode == 2
    assert "Starting sinkhole" not in result.stdout


def test_held_guest_keeps_preamble_and_observation(monkeypatch):
    observation = {
        "phase": "drain",
        "agent": "bbtest",
        "forwarder": {"pid": 42},
        "result": {"http": "completed", "connect_closed": True},
    }
    script = (
        "print('shell preamble'); "
        "print('P4_READY=drain', flush=True); "
        f"print('P4_OBSERVATION=' + {json.dumps(json.dumps(observation))}, flush=True)"
    )
    monkeypatch.setattr(lifecycle, "guest_command", lambda *_args: [sys.executable, "-u", "-c", script])

    process, first = lifecycle.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)
    assert lifecycle.finish_guest(process, first, "drain", "bbtest") == observation["result"]


def test_held_guest_reports_exit_before_ready(monkeypatch):
    monkeypatch.setattr(
        lifecycle,
        "guest_command",
        lambda *_args: [sys.executable, "-u", "-c", "print('shell preamble', flush=True); raise SystemExit(4)"],
    )

    with pytest.raises(AssertionError, match="exited before its admitted-work boundary"):
        lifecycle.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)


@pytest.mark.parametrize("client", [guest_workloads, guest_lifecycle], ids=["workloads", "lifecycle"])
@pytest.mark.parametrize("chunked", [False, True], ids=["close-delimited", "chunked"])
def test_guest_sse_decodes_http_before_reporting_admitted_event(monkeypatch, client, chunked):
    marker = "p2-" + "a" * 32
    first, last = (f"data: {position}:{marker}\n\n".encode() for position in ("first", "last"))
    admitted = threading.Event()
    errors = []

    def report(*_args, **_kwargs):
        admitted.set()

    def serve(listener):
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                _, headers = read_head(connection)
                assert headers["host"] == ["failing.test"]
                framing = b"Transfer-Encoding: chunked\r\n" if chunked else b""
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                   + framing + b"Connection: close\r\n\r\n")

                def send_event(payload):
                    for part in (payload[:7], payload[7:-1], payload[-1:]):
                        connection.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n" if chunked else part)

                send_event(first)
                assert admitted.wait(3), "guest did not admit the first event before origin release"
                send_event(last)
                if chunked:
                    connection.sendall(b"0\r\n\r\n")
        except (OSError, AssertionError) as exc:
            errors.append(exc)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(3)
        monkeypatch.setattr(client, "PROXY", listener.getsockname())
        monkeypatch.setattr(client, "print", report, raising=False)
        server = threading.Thread(target=serve, args=(listener,))
        server.start()
        try:
            result = client.sse(marker, "bbtest") if client is guest_workloads else client.sse(marker)
            assert result == {"first": first.decode(), "last": last.decode()}
        finally:
            admitted.set()
            server.join(timeout=5)
        assert not server.is_alive()
        assert errors == []


@pytest.mark.parametrize("body,message", [(b"data: truncated", "ended before"), (b"x" * 8192, "exceeded")],
                         ids=["incomplete", "oversized"])
def test_guest_sse_rejects_incomplete_or_oversized_events(body, message):
    reader, writer = socket.socketpair()
    errors = []

    def send():
        try:
            writer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body)
            writer.shutdown(socket.SHUT_WR)
        except OSError as exc:
            errors.append(exc)

    with reader, writer:
        reader.settimeout(3)
        writer.settimeout(3)
        writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        # macOS's socketpair buffer cannot hold this whole response before a read.
        # A small buffer also exercises producer backpressure on Linux.
        sender = threading.Thread(target=send, name="SSE fixture sender")
        sender.start()
        try:
            with http.client.HTTPResponse(reader) as response:
                response.begin()
                with pytest.raises(AssertionError, match=message):
                    guest_workloads._event(response)
        finally:
            reader.close()
            sender.join(timeout=5)
            assert not sender.is_alive(), "SSE fixture sender did not stop after socket cleanup"
        assert errors == []


def test_retained_python_timeout_reports_blocked_sse_and_cleans_sockets(tmp_path):
    """The retained job's signal timeout reports the blocked read and runs finally."""
    cleanup = tmp_path / "cleanup.json"
    control = tmp_path / "test_blocked_sse.py"
    control.write_text(f'''import http.client
import json
import socket
from pathlib import Path
from tests.blackbox.isolation.installed_workloads import _event

def test_blocked_sse_input():
    reader, writer = socket.socketpair()
    response = http.client.HTTPResponse(reader)
    try:
        writer.sendall(b"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\n\\r\\ndata: unfinished")
        response.begin()
        _event(response)
    finally:
        response.close()
        reader.close()
        writer.close()
        Path({str(cleanup)!r}).write_text(json.dumps([reader.fileno(), writer.fileno()]))
''')
    environment = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--noconftest", "-v", "--tb=short",
         "--timeout=1", "--timeout-method=signal", str(control)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10, check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1, output
    assert "Timeout (>1.0s)" in output, output
    assert "test_blocked_sse_input" in output and "installed_workloads.py" in output, output
    assert json.loads(cleanup.read_text()) == [-1, -1]


def test_selected_installed_identity_requires_native_source_binary_and_instance(tmp_path):
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    subprocess.run(['git', 'init', '-q', str(checkout)], check=True)
    subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@test',
                    '-c', 'core.hooksPath=/dev/null', 'commit', '--allow-empty', '-qm', 'fixture'], check=True)
    revision = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    package = tmp_path / 'package'
    (package / 'bin').mkdir(parents=True)
    packaged = package / 'bin/safeyolo-proxy'
    packaged.write_bytes(b'selected native bytes')
    cli = package / 'bin/safeyolo'
    root = tmp_path / 'instance'
    diagnostic = {'proxy_state': 'running', 'root': str(root)}
    cli.write_text(f'#!{sys.executable}\nimport json\nprint({json.dumps(json.dumps(diagnostic))})\n')
    cli.chmod(0o755)
    runtime = {'status': 'attached_ready', 'instance': {'config_dir': str(root)},
               'cli': {'path': str(cli), 'package_root': str(package), 'source_revision': revision, 'profile': 'debug'},
               'candidate': {'path': str(packaged), 'sha256': hashlib.sha256(packaged.read_bytes()).hexdigest()},
               'runtime': {'status': 'ready', 'actual_executable': str(packaged),
                           'authenticated_runtime_identity': {'status': 'authenticated'}}, 'native': {}}
    selected = installed_identity(runtime, checkout, expected_revision=revision)
    assert selected['build_identity']['source_revision'] == revision
    assert selected['cli_diagnostics'] == diagnostic
    with pytest.raises(AssertionError, match='CLI source differs'):
        installed_identity(runtime, checkout, expected_revision=OTHER_REVISION)
    packaged.write_bytes(b'substituted')
    with pytest.raises(AssertionError):
        installed_identity(runtime, checkout, expected_revision=revision)
    packaged.write_bytes(b'selected native bytes')
    diagnostic['root'] = str(tmp_path / 'other')
    cli.write_text(f'#!{sys.executable}\nprint({json.dumps(json.dumps(diagnostic))})\n')
    with pytest.raises(AssertionError, match='selected running instance'):
        installed_identity(runtime, checkout, expected_revision=revision)


def test_install_commit_option_needs_an_installed_selection(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--install-commit", SELECTED_REVISION],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "SAFEYOLO_TEST_CONFIG_DIR": str(tmp_path / "test-instance"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires an installed ingress, workloads, access, or lifecycle selection" in result.stderr
    assert not (tmp_path / "test-instance").exists()


@pytest.mark.parametrize("selection", ["default", "matching", "mismatched", "missing_checkout"])
def test_direct_installed_selection_resolves_current_source_before_setup(tmp_path, selection):
    checkout = tmp_path / "source"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    (checkout / "source.txt").write_text("selected source\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
         "commit", "-qm", "Selected source"], check=True,
    )
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    instance = tmp_path / "test-instance"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "SAFEYOLO_TEST_CONFIG_DIR": str(instance)}
    if selection != "missing_checkout":
        env["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"] = str(checkout)
    options = ["--expect-platform", "systrap", "--workloads"]
    if selection != "default":
        options += ["--install-commit", OTHER_REVISION if selection == "mismatched" else revision]
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), *options], env=env,
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 2
    if selection in {"default", "matching"}:
        assert f"Installed source: {revision}" in result.stdout
        assert "installed safeyolo CLI is required" in result.stderr
    elif selection == "mismatched":
        assert "install checkout must contain the exact full selected commit" in result.stderr
        assert "Installed source:" not in result.stdout
    else:
        assert "installed sections need SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT" in result.stderr
    assert not instance.exists()


@pytest.fixture
def installed_section_commands(tmp_path, monkeypatch):
    """Owned subprocesses exercise preparation reuse and section cleanup."""
    repository = tmp_path / "repository"
    scripts = repository / "tests/blackbox"
    scripts.mkdir(parents=True)
    prepare = scripts / "run-lane.sh"
    stop_script = f"#!{sys.executable}\n" + "\n".join([
        "import os, pathlib, sys",
        "root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])",
        "if os.environ.get('FAIL_CLEANUP') and root.name == 'isolation': sys.exit(7)",
        "for marker in root.glob('agents/*/container.pid'): marker.unlink()",
        "for marker in root.glob('data/proxy*.json'): marker.unlink()",
        "",
    ])
    prepare.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])\n"
        "root.mkdir(parents=True)\n"
        "(root / 'prepared-once').write_text('one installation')\n"
        "assert sys.argv[-1] == '--prepare-only'\n"
        "if os.environ.get('FAIL_PREPARATION'): sys.exit(9)\n"
        "(root / 'share').mkdir()\n"
        "(root / 'share/kernel').write_bytes(b'compatible immutable boot input')\n"
        "binary_dir = root / 'bin'\n"
        "binary_dir.mkdir(parents=True)\n"
        f"(binary_dir / 'safeyolo').write_text({stop_script!r})\n"
        "(binary_dir / 'safeyolo').chmod(0o755)\n"
    )
    section = scripts / "run-tests.sh"
    section.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys, uuid\n"
        "root = pathlib.Path(os.environ['SAFEYOLO_TEST_CONFIG_DIR'])\n"
        "source = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])\n"
        "assert '--proxy-impl' in sys.argv and 'rust' in sys.argv\n"
        "assert os.environ['SAFEYOLO_COORD_DATA_DIR'] == str(root / 'data/coord')\n"
        "assert os.environ['SAFEYOLO_BLACKBOX_ARTIFACTS_DIR'].endswith('/' + root.name)\n"
        "assert not root.exists(), 'a section received another section writable state'\n"
        "root.mkdir(parents=True)\n"
        "(root / 'share').symlink_to(source / 'share')\n"
        "(root / 'config.toml').write_text('owned section configuration')\n"
        "(root / 'agents/bbtest').mkdir(parents=True)\n"
        "(root / 'agents/bbtest/container.pid').write_text(str(os.getpid()))\n"
        "(root / 'data').mkdir()\n"
        "(root / 'data/proxy-process.json').write_text(json.dumps({'pid': os.getpid()}))\n"
        "for name in ('token', 'certificate', 'capture', 'approval', 'overlay'):\n"
        "    (root / name).write_text(uuid.uuid4().hex)\n"
        "(root / 'selection.json').write_text(json.dumps(sys.argv[1:]))\n"
        "(root / 'nats-instance').write_text(os.environ['SAFEYOLO_NATS_TEST_INSTANCE'])\n"
        "if root.name == 'isolation': sys.exit(int(os.environ.get('FAIL_SECTION', '0')))\n"
    )
    prepare.chmod(0o755)
    section.chmod(0o755)
    monkeypatch.setattr(installed_sections, "REPOSITORY", repository)
    return repository


@pytest.mark.parametrize("failure,expected", [(0, 0), (1, 1), (2, 2)])
def test_installed_sections_reuse_preparation_and_separate_live_state(
    tmp_path, monkeypatch, installed_section_commands, failure, expected
):
    monkeypatch.setenv("FAIL_SECTION", str(failure))
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    result = installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    )
    assert result == expected
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["preparation"]["exit"] == 0
    assert [row["section"] for row in report["sections"]] == ["isolation", "access"]
    assert all(row["cleanup"] == "stopped" for row in report["sections"])
    assert report["sections"][0]["result"] == {
        0: "passed", 1: "assertion_failure", 2: "preparation_failure"
    }[failure]
    first, second = directory / "isolation", directory / "access"
    assert (first / "share/kernel").stat().st_ino == (second / "share/kernel").stat().st_ino
    for name in ("token", "certificate", "capture", "approval", "overlay", "nats-instance"):
        assert (first / name).read_text() != (second / name).read_text()
    assert not list(directory.glob("*/agents/*/container.pid"))
    assert not list(directory.glob("*/data/proxy-process.json"))
    selected = json.loads((second / "selection.json").read_text())
    assert "--access" in selected and selected[-2:] == ["--install-commit", "a" * 40]
    assert "--operator-journey" not in selected


@pytest.mark.parametrize("platform", ["systrap", "vz"])
def test_installed_operator_selection_keeps_one_access_root_and_owned_cleanup(
    tmp_path, installed_section_commands, platform
):
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        platform, ("access",), installed_section_commands, "a" * 40, directory, artifacts,
        operator_journey=True,
    ) == 0
    selected = json.loads((directory / "access/selection.json").read_text())
    assert selected == ["--expect-platform", platform, "--proxy-impl", "rust", "--access",
                        "--operator-journey", "--install-commit", "a" * 40]
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert len(report["sections"]) == 1 and report["sections"][0]["cleanup"] == "stopped"
    assert not list(directory.glob("*/agents/*/container.pid"))


@pytest.mark.parametrize("platform,sections,valid", [
    ("systrap", ["access"], True), ("vz", ["access"], True),
    ("kvm", ["isolation"], False), ("vz", [], False),
    ("vz", ["access", "lifecycle"], False),
])
def test_operator_cli_selection_requires_one_supported_access_section(
    tmp_path, monkeypatch, platform, sections, valid
):
    arguments = ["run-installed", platform, "--operator-journey"]
    for section in sections:
        arguments.extend(["--section", section])
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(installed_sections.subprocess, "check_output",
                        lambda args, **kwargs: "a" * 40 if "rev-parse" in args else "")
    calls = []
    monkeypatch.setattr(installed_sections, "run_sections", lambda *args, **kwargs: calls.append((args, kwargs)) or 0)
    monkeypatch.setattr(installed_sections.tempfile, "mkdtemp", lambda **kwargs: str(tmp_path))
    if valid:
        assert installed_sections.main() == 0
        assert calls[0][0][:2] == (platform, ("access",))
        assert calls[0][1] == {"operator_journey": True}
    else:
        with pytest.raises(SystemExit) as error:
            installed_sections.main()
        assert error.value.code == 2 and calls == []


@pytest.mark.parametrize("platform", ["systrap", "vz"])
def test_operator_access_checks_selected_source_before_runtime_setup(tmp_path, platform):
    """Both operator paths must reach the existing installed-source refusal."""
    result = subprocess.run([
        sys.executable, str(ROOT / "tests/blackbox/installed_access.py"),
        "--config-dir", str(tmp_path / "uncreated"), "--agent", "bbtest",
        "--runtime", str(tmp_path / "unread-runtime.json"), "--platform", platform,
        "--output", str(tmp_path / "unwritten.json"), "--install-commit", "a" * 40,
        "--operator-journey",
    ], env={**os.environ, "SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT": str(ROOT),
            "PYTHONPATH": f"{ROOT / 'tests/reference'}:{ROOT}"},
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 1 and "expected " + "a" * 40 in result.stderr, result.stderr
    assert not (tmp_path / "uncreated").exists() and not (tmp_path / "unwritten.json").exists()


@pytest.mark.parametrize("status,headers", [(200, {}), (403, {}), (403, {"x-blocked-by": "credentials"}),
                                         (403, {"x-blocked-by": "network-guard"})])
def test_operator_traffic_distinguishes_policy_refusal_from_an_origin_response(monkeypatch, status, headers):
    owned = {"agent_id": "bbtest", "request_id": "req-owned", "flow_id": 7}
    monkeypatch.setattr(guest, "seed_owned_flow", lambda agent, marker: owned)
    requests = []

    def exchange(method, target):
        requests.append((method, target))
        return status, headers, b"controlled response"

    monkeypatch.setattr(guest, "exchange", exchange)
    if headers.get("x-blocked-by") != "network-guard":
        with pytest.raises(AssertionError):
            guest.operator_traffic("bbtest", "r3-owned")
    else:
        assert guest.operator_traffic("bbtest", "r3-owned") == {
            "allowed": owned, "denied_status": 403, "blocked_by": "network-guard",
        }
    assert requests == [("GET", "http://evil.com/installed-flow/r3-owned/bbtest")]


@pytest.mark.parametrize("failure", [None, "no-vnc", "missing-500"])
def test_operator_desktop_reaches_unlocked_page_and_requires_vnc_and_missing_target(monkeypatch, failure):
    requests = []

    class Page(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, body))
            self.send_response(303)
            self.send_header("Set-Cookie", "fixture_preview=owned; Path=/; HttpOnly")
            self.end_headers()

        def do_GET(self):
            requests.append((self.path, self.headers.get("Cookie")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>noVNC</html>")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Page)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    authority = f"127.0.0.1:{server.server_port}"
    targets = []

    def present(agent_id):
        targets.append(agent_id)
        if agent_id != "ag-owned":
            raise installed_access.APIError("controlled missing target", 500 if failure == "missing-500" else 404)
        return {"agent_id": agent_id, "url": f"http://{authority}/vnc.html#autoconnect=true",
                "unlock_code": "synthetic-only"}

    @contextmanager
    def websocket(url, **options):
        assert url == f"ws://{authority}/websockify"
        assert options == {"origin": f"http://{authority}",
                           "additional_headers": {"Cookie": "fixture_preview=owned"}, "proxy": None}
        yield SimpleNamespace(recv=lambda **_args: b"not VNC" if failure == "no-vnc" else b"RFB 003.008\n")

    monkeypatch.setattr(installed_access, "connect", websocket)
    try:
        api = SimpleNamespace(present_desktop=present)
        if failure:
            with pytest.raises(AssertionError):
                installed_access.operator_desktop(api, "ag-owned")
        else:
            observed = installed_access.operator_desktop(api, "ag-owned")
            assert observed["agent_id"] == "ag-owned" and observed["missing_target_status"] == 404
            assert observed["vnc_banner"] == "RFB 003.008\n" and "unlock_code" not in observed
            assert observed["observation_scope"] == "unlocked noVNC page and live VNC banner; no visual interaction"
        assert requests == [("/_safeyolo_preview/unlock", b"code=synthetic-only"),
                            ("/vnc.html", "fixture_preview=owned")]
        assert targets[0] == "ag-owned"
        if failure != "no-vnc":
            assert len(targets) == 2 and targets[1] != "ag-owned"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_installed_sections_do_not_continue_across_unclean_boundary(
    tmp_path, monkeypatch, installed_section_commands
):
    monkeypatch.setenv("FAIL_CLEANUP", "1")
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert len(report["sections"]) == 1
    assert report["sections"][0]["cleanup"] == "failed"
    assert any("agent stop bbtest exited 7" in error for error in report["sections"][0]["cleanup_failures"])
    assert (directory / "isolation/agents/bbtest/container.pid").exists()
    assert not (directory / "access").exists()


@pytest.mark.parametrize("leave_process_live,section_exit,aggregate", [
    (True, 1, False), (False, 1, False), (False, 3, False),
    (False, 3, True), (True, 3, True),
], ids=["survivor", "clean-assertion-failure", "clean-pytest-internal-error",
        "clean-aggregated-pytest-internal-error", "survivor-with-aggregated-infrastructure"])
@pytest.mark.parametrize("owner", [False, True], ids=["subject", "lifecycle-owner"])
def test_installed_sections_preserve_inner_cleanup_outcome(
    tmp_path, monkeypatch, installed_section_commands, installed_pytest_runner,
    leave_process_live, section_exit, aggregate, owner
):
    """Run the real inner trap and outer loop when stop removes a PID marker."""
    repository = installed_section_commands
    scripts = repository / "tests/blackbox"
    stop_script = f"#!{sys.executable}\n" + f"""
import json, os, pathlib, signal, sys, time
sys.path.insert(0, {str(ROOT)!r})
from tests.blackbox.installed_host_smoke import _pid_alive
root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])
marker = root / 'data/proxy-process.json'
if marker.exists():
    pid = json.loads(marker.read_text())['pid']
    marker.unlink()
    if os.environ['LEAVE_PROCESS_LIVE'] == '0':
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while _pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not _pid_alive(pid)
"""
    prepare = scripts / "run-lane.sh"
    prepare.write_text(prepare.read_text()
                       + f"(binary_dir / 'safeyolo').write_text({stop_script!r})\n")
    runner = (ROOT / "tests/blackbox/run-tests.sh").read_text()
    trap_start = runner.index("cleanup() {")
    trap_end = runner.index("\n# --- Clean stale state", trap_start)
    section = scripts / "run-tests.sh"
    first_section = "lifecycle" if owner else "isolation"
    owned_root = '"${SAFEYOLO_CONFIG_DIR%/*}/lifecycle-owner"' if owner else '"$SAFEYOLO_CONFIG_DIR"'
    section.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        "export SAFEYOLO_CONFIG_DIR=\"$SAFEYOLO_TEST_CONFIG_DIR\"\n"
        "mkdir -p \"$SAFEYOLO_CONFIG_DIR/data\"\n"
        "touch \"$SAFEYOLO_CONFIG_DIR/config.toml\"\n"
        "if [ \"${SAFEYOLO_CONFIG_DIR##*/}\" = access ]; then\n"
        "    touch \"$SAFEYOLO_CONFIG_DIR/access-started\"\n"
        "    exit 0\n"
        "fi\n"
        f"SCRIPT_DIR={str(ROOT / 'tests/blackbox')!r}\n"
        f"STARTED_VM=false\nSTARTED_PROXY={'false' if owner else 'true'}\n"
        "STARTED_PARENT=false\nSTARTED_SINKHOLE=false\n"
        "PARENT_PID=\nSINKHOLE_PID=\nHOST_LISTENER_PID=\nPROXY_IMPL=rust\nAGENT_NAME=bbtest\n"
        f"LIFECYCLE={'true' if owner else 'false'}\n"
        + _runner_cleanup_helpers()
        + runner[trap_start:trap_end]
        + f"\nowned_root={owned_root}\n"
        + 'mkdir -p "$owned_root/data"\ntouch "$owned_root/config.toml"\n'
        + "printf '{\"pid\":%s}\\n' \"$OWNED_TEST_PID\" > \"$owned_root/data/proxy-process.json\"\n"
        + ('set +e\n"$FIXTURE_INSTALLED_RUNNER"\nexit $?\n' if aggregate else f"exit {section_exit}\n")
    )
    section.chmod(0o755)
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    # This fixture owns the child. Reap it while the inner stop command waits,
    # rather than leaving a Darwin zombie until run_sections returns.
    reaper = threading.Thread(target=process.wait)
    reaper.start()
    monkeypatch.setenv("OWNED_TEST_PID", str(process.pid))
    monkeypatch.setenv("LEAVE_PROCESS_LIVE", "1" if leave_process_live else "0")
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}:{os.environ['PATH']}")
    monkeypatch.setenv("FIXTURE_INSTALLED_RUNNER", str(installed_pytest_runner))
    for slot in INSTALLED_PYTEST_SLOTS:
        monkeypatch.setenv(f"FIXTURE_{slot}_EXIT", str(section_exit if slot == "ISOLATION" else 0))
    try:
        result = installed_sections.run_sections(
            "systrap", (first_section, "access"), repository, "a" * 40, directory, artifacts
        )
        report = json.loads((artifacts / "installed-sections.json").read_text())
        first = report["sections"][0]
        if aggregate:
            assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)
        assert not (directory / ("lifecycle-owner" if owner else "isolation") / "data/proxy-process.json").exists()
        if leave_process_live:
            assert process.poll() is None, "the injected stop must leave the owned lifetime live"
            assert result == 2
            assert first["result"] == "cleanup_failure" and first["cleanup"] == "failed"
            assert len(report["sections"]) == 1
            assert not (directory / "access/access-started").exists()
        else:
            process.wait(timeout=5)
            expected = 1 if section_exit == 1 else 2
            assert result == expected
            assert first["exit"] == expected
            assert first["result"] == ("assertion_failure" if expected == 1 else "preparation_failure")
            assert first["cleanup"] == "stopped"
            assert len(report["sections"]) == 2
            assert (directory / "access/access-started").is_file()
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        reaper.join(timeout=5)
        assert not reaper.is_alive()


def test_installed_sections_attribute_preparation_failure_without_starting_section(
    tmp_path, monkeypatch, installed_section_commands
):
    monkeypatch.setenv("FAIL_PREPARATION", "1")
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["preparation"]["exit"] == 9
    assert report["sections"] == []
    assert not (directory / "isolation").exists()


@pytest.mark.parametrize("failure,expected,results", [
    ({}, 0, ["passed", "passed"]),
    ({"FAIL_SECTION": "1"}, 1, ["assertion_failure", "passed"]),
    ({"FAIL_SECTION": "2"}, 2, ["preparation_failure", "passed"]),
    ({"FAIL_PREPARATION": "1"}, 2, []),
    ({"FAIL_CLEANUP": "1"}, 2, ["cleanup_failure"]),
])
def test_installed_sections_start_and_clean_up_without_an_installed_python_package(
    tmp_path, installed_section_commands, failure, expected, results
):
    """A clean-shell parent must inspect cleanup and save each section result."""
    repository = installed_section_commands
    scripts = repository / "tests/blackbox"
    for name in ("run-installed.sh", "installed_sections.py", "installed_host_smoke.py"):
        shutil.copy2(ROOT / "tests/blackbox" / name, scripts / name)
    (scripts / 'harness').mkdir(exist_ok=True)
    shutil.copy2(ROOT / 'tests/blackbox/harness/process_identity.py', scripts / 'harness/process_identity.py')
    package = repository / "tests/reference/safeyolo"
    package.mkdir(parents=True)
    for name in ("__init__.py", "runtime_identity.py"):
        shutil.copy2(ROOT / "tests/reference/safeyolo" / name, package / name)
    for command in (
        ["git", "init", "--quiet"],
        ["git", "add", "."],
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
         "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "clean host fixture"],
    ):
        subprocess.run(command, cwd=repository, check=True, capture_output=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    clean_env = tmp_path / "clean-python"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(clean_env)], check=True)
    env = {key: value for key, value in os.environ.items()
           if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
           and not key.startswith("FAIL_")}
    home = tmp_path / "bare-home"
    home.mkdir()
    env.update(PATH=f"{clean_env / 'bin'}:/usr/bin:/bin", HOME=str(home),
               PYTHONNOUSERSITE="1", **failure)
    # This interpreter has neither the checkout package nor development
    # dependencies. A later preparation child cannot add imports to its parent.
    subprocess.run([str(clean_env / "bin/python3"), "-c",
                    "import importlib.util; assert importlib.util.find_spec('safeyolo') is None"],
                   cwd=repository, env=env, check=True)
    assert not (repository / ".venv").exists()
    artifacts = tmp_path / "literal artifacts $(unused) ; [space]"
    result = subprocess.run(
        [str(scripts / "run-installed.sh"), "systrap", "--section", "isolation",
         "--section", "access", "--install-checkout", str(repository),
         "--install-commit", revision, "--artifacts", str(artifacts)],
        cwd=repository, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["source_revision"] == revision
    assert report["preparation"]["exit"] == (9 if "FAIL_PREPARATION" in failure else 0)
    assert [row["result"] for row in report["sections"]] == results
    for row in report["sections"]:
        root = Path(row["config_dir"])
        if row["result"] == "cleanup_failure":
            assert row["cleanup"] == "failed" and row["cleanup_failures"]
            assert (root / "data/proxy-process.json").exists()
            assert not (root.parent / "access").exists()
        else:
            assert row["cleanup"] == "stopped" and row["cleanup_failures"] == []
            assert not (root / "data/proxy-process.json").exists()
            assert not (root / "agents/bbtest/container.pid").exists()
        if row["section"] == "access":
            selected = json.loads((root / "selection.json").read_text())
            assert selected[-2:] == ["--install-commit", revision]


def test_installed_source_rejects_ambiguous_commit_before_preparation(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-installed.sh"), "systrap", "--install-commit", "abcd1234"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 2
    assert "exact full selected commit" in result.stderr
    assert "Prepared product and section state:" not in result.stdout


def test_cleanup_cannot_hide_a_live_owned_process_by_removing_its_pid_file(tmp_path):
    root = tmp_path / "instance"
    (root / "data").mkdir(parents=True)
    (root / "config.toml").write_text("owned fixture")
    cli = tmp_path / "cli"
    cli.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib\n"
        "(pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR']) / 'data/proxy-process.json').unlink()\n"
    )
    cli.chmod(0o755)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (root / "data/proxy-process.json").write_text(json.dumps({"pid": process.pid}))
        failures = installed_sections.cleanup_instance(cli, root)
        assert not (root / "data/proxy-process.json").exists()
        assert any(f"owned process {process.pid} is still live" == error for error in failures)
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_continuity_keeps_nats_in_its_state_directory_with_a_valid_instance(tmp_path, monkeypatch):
    from safeyolo.coord import nats_runtime

    root = tmp_path / ("installed-native-continuity-" + "x" * 80)
    env = continuity.env_for(root)
    for key in ("SAFEYOLO_NATS_TEST_INSTANCE", "SAFEYOLO_COORD_DATA_DIR"):
        monkeypatch.setenv(key, env[key])
    assert nats_runtime.nats_root() == root / "data/coord/nats"
    assert env["SAFEYOLO_NATS_TEST_INSTANCE"] != continuity.env_for(root.with_name("peer"))["SAFEYOLO_NATS_TEST_INSTANCE"]


@pytest.mark.parametrize("host,bind_host", [
    ("127.0.0.1", "127.0.0.1"),
    # Use Darwin's configured IPv6 loopback as the second bind address.
    ("::1", "::1") if sys.platform == "darwin" else ("127.0.0.2", "127.0.0.2"),
    ("127.0.0.2", "127.0.0.1"),
])
def test_continuity_tls_origin_uses_selected_bind_address_and_certificate(tmp_path, host, bind_host):
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    with socket.socket(family) as reserve:
        reserve.bind((bind_host, 0))
        port = reserve.getsockname()[1]
    origin, root_cert = continuity.https_origin(tmp_path, host, port, bind_host)
    assert origin.server_address[:2] == (bind_host, port)
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    context = ssl.create_default_context(cafile=root_cert)
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    try:
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.sock = secured
                try:
                    connection.request("GET", "/selected-host")
                    response = connection.getresponse()
                    assert response.status == 200 and response.read() == continuity.BODY
                finally:
                    connection.close()
        wrong_host = "127.0.0.2" if host == "127.0.0.1" else "127.0.0.1"
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname=wrong_host)
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        assert [row["path"] for row in origin.seen] == ["/selected-host"]
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_continuity_owned_parent_routes_only_its_tls_origin(tmp_path):
    tls_origin, root_cert = continuity.https_origin(tmp_path, "127.0.0.2", bind_host="127.0.0.1")
    origin = continuity.Origin(("127.0.0.1", 0))
    origin.tls_target = ("127.0.0.2", tls_origin.server_port)
    origin.tls_address = tls_origin.server_address
    threads = [threading.Thread(target=server.serve_forever) for server in (origin, tls_origin)]
    for thread in threads:
        thread.start()
    try:
        connection = http.client.HTTPSConnection(*origin.server_address, timeout=3,
                                                context=ssl.create_default_context(cafile=root_cert))
        connection.set_tunnel(*origin.tls_target)
        try:
            connection.request("GET", "/selected-tunnel")
            response = connection.getresponse()
            assert response.status == 200 and response.read() == continuity.BODY
        finally:
            connection.close()
        invalid = http.client.HTTPConnection(*origin.server_address, timeout=3)
        try:
            invalid.request("CONNECT", f"127.0.0.2:{tls_origin.server_port+1}")
            response = invalid.getresponse()
            assert response.status == 400
            response.read()
        finally:
            invalid.close()
        assert not origin.seen
        assert [row["path"] for row in tls_origin.seen] == ["/selected-tunnel"]
    finally:
        for server in (origin, tls_origin):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()


def test_continuity_owned_parent_keeps_oauth_provider_separate():
    origin = continuity.Origin(("127.0.0.1", 0))
    oauth = continuity.Origin(("127.0.0.1", 0), oauth=True)
    origin.oauth_address = oauth.server_address
    threads = [threading.Thread(target=server.serve_forever) for server in (origin, oauth)]
    for thread in threads:
        thread.start()
    connection = http.client.HTTPConnection(*origin.server_address, timeout=3)
    try:
        connection.request("POST", f"http://127.0.0.1:{oauth.server_port}/oauth/token",
                           body=b"grant_type=refresh_token&refresh_token=synthetic-test")
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 200 and payload["access_token"] == "synthetic-r638-access-v1"
        assert len(oauth.seen) == 1 and oauth.seen[0]["path"] == "/oauth/token"
        assert oauth.seen[0]["body"] == b"grant_type=refresh_token&refresh_token=synthetic-test"
        assert not origin.seen
        connection.request("POST", f"http://127.0.0.2:{origin.server_port}/ordinary?item=one",
                           body=b"separate-origin-body")
        response = connection.getresponse()
        assert response.status == 200 and response.read() == continuity.BODY
        assert origin.seen == [{"method": "POST", "path": "/ordinary?item=one",
                                "body": b"separate-origin-body", "authorization": ""}]
        assert len(oauth.seen) == 1
    finally:
        connection.close()
        for server in (origin, oauth):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()
