"""Run the maintained Helper consumer with a real selected native proxy.

Guest status/transport and Codex events are controlled source-test inputs.
Native ownership, policy, approval, Helper commands, HTTP and cleanup are real.
The installed sandbox/Codex witness remains a separate operator run.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox import installed_host_smoke as smoke
from tests.blackbox import installed_shared_approvals as approvals
from tests.proxy_contracts.harness import request as http_request
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_instance


@pytest.mark.parametrize("count,expected", [(0, None), (8, None), (8, 8), (200, 200), (201, None), (8, 7), (8, 9)])
def test_fresh_reviewer_attention_cutoff_records_all_prior_edges(monkeypatch, capsys, count, expected):
    edges = [{"attention_id": f"expired-{index}"} for index in range(count)]
    calls = []

    def metadata_only(cli, name, operation, arguments):
        assert cli == Path("owned-cli") and name == "helper"
        assert operation == "wait_for_attention", "fresh setup must not read or resolve prior payloads"
        assert arguments["limit"] == 100 and arguments["timeout_seconds"] == 0
        cursor = arguments["since_sequence"]
        calls.append(cursor)
        page = edges[cursor:cursor + 100]
        return {"edges": page, "next_cursor": cursor + len(page)}

    monkeypatch.setattr(approvals, "guest_coord", metadata_only)
    if expected is not None and expected != count:
        with pytest.raises(AssertionError, match="explicit attention cutoff differs"):
            approvals.reviewer_attention_cutoff(Path("owned-cli"), "helper", expected)
    else:
        observation = approvals.reviewer_attention_cutoff(Path("owned-cli"), "helper", expected)
        assert observation["since_sequence"] == count
    recorded = json.loads(capsys.readouterr().out)["observation"]
    assert recorded["since_sequence"] == count and recorded["expected_cutoff"] == expected
    assert recorded["prior_attention_edges"] == edges
    assert "payload availability unverified" in recorded["prior_history"]
    assert "No prior object was read or resolved" in recorded["prior_history"]
    assert calls == list(range(0, count + 1, 100))


@pytest.fixture
def helper_instance(tmp_path_factory, monkeypatch):
    directory = tmp_path_factory.mktemp("u6")
    (directory / "operator-token").write_text("synthetic-helper-admin-token")
    fixture = (Path(__file__).parents[1] / "blackbox/fixtures/delegated-approval-service.yaml").read_text()
    service_fixture = (Path(__file__).parents[1] / "blackbox/fixtures/delegated-service-authorization.yaml").read_text()
    binding_fixture = (Path(__file__).parents[1] / "blackbox/fixtures/delegated-contract-binding.yaml").read_text()
    with native_instance(directory, services=True, agent_api=True,
                         service_sources={"delegated-fixture.yaml": fixture, "delegated-service-fixture.yaml": service_fixture,
                                          "delegated-binding-fixture.yaml": binding_fixture},
                         agent_addresses={"worker": "10.0.0.2", "helper": "10.0.0.3"},
                         extra_config='readiness_file="data/selected-ready.json"\nadmin_api_token_file="../operator-token"\n') as instance:
        root = instance.root
        (root / ".safeyolo-platform-smoke").touch()
        # The actual driver must override inherited selection of another root.
        for key in ("SAFEYOLO_CONFIG_DIR", "SAFEYOLO_NATIVE_CONFIG_PATH", "SAFEYOLO_LOGS_DIR"):
            monkeypatch.setenv(key, str(directory / "unrelated"))
        commit = dict(line.split("=", 1) for line in (root / "package-info").read_text().splitlines())["source_commit"]
        args = SimpleNamespace(config_dir=root, native_cli=root / "bin/safeyolo", native_proxy=root / "bin/safeyolo-proxy",
            transport_cli=str(root / "bin/safeyolo"), worker="worker", helper="helper", commit=commit,
            interfaces=True, model_unavailable=True, real_helper=False, shared_room=None, helper_events=None,
            wait_for_operator=False, operator_timeout=1, reconcile_seconds=0, attention_cutoff=None)
        yield instance, args


@pytest.mark.parametrize("control,diagnosis", [
    ("missing_receipt", "process receipt is missing"),
    ("stale_receipt", "does not own"),
    ("foreign_receipt", "selected native configuration"),
    ("foreign_executable", "expected selected Rust binary"),
    ("foreign_readiness", "different process"),
    ("foreign_instance", "disagrees with process readiness"),
    ("invalid_auth", "HTTP 401"),
    ("foreign_socket", "listener map differs"),
])
def test_helper_consumer_refuses_unowned_runtime_before_guest_effects(helper_instance, monkeypatch, control, diagnosis):
    instance, args = helper_instance
    root = instance.root
    receipt = root / "data/proxy-process.json"
    marker = root / "data/selected-ready.json"
    if control == "missing_receipt":
        receipt.unlink()
    elif control == "stale_receipt":
        record = json.loads(receipt.read_text())
        record["token"] = "different-process-birth"
        receipt.write_text(json.dumps(record))
    elif control == "foreign_receipt":
        receipt.write_text(json.dumps({"pid": os.getpid(), "token": smoke._process_start_token(os.getpid())}))
    elif control == "foreign_executable":
        args.native_proxy = root.parent / "other-proxy"
        # On macOS, a new hard link can change the running executable's
        # observed path. Use a distinct file for the foreign selection.
        shutil.copy2(root / "bin/safeyolo-proxy", args.native_proxy)
        assert not args.native_proxy.samefile(root / "bin/safeyolo-proxy")
    elif control.startswith("foreign_") and control != "foreign_socket":
        record = json.loads(marker.read_text())
        record["pid" if control == "foreign_readiness" else "instance_id"] = 1 if control == "foreign_readiness" else "other-instance"
        marker.write_text(json.dumps(record))
    elif control == "invalid_auth":
        (root.parent / "operator-token").write_text("synthetic-wrong-token")
    elif control == "foreign_socket":
        settings = tomlkit.parse((root / "config.toml").read_text())
        settings["listeners"][0]["socket_path"] = "data/foreign.sock"
        (root / "config.toml").write_text(tomlkit.dumps(settings))
    original = instance.policy.read_bytes()

    def no_guest(*arguments, **kwargs):
        pytest.fail("unowned preflight reached a guest")

    monkeypatch.setattr(approvals, "runsc_identity", no_guest)
    with pytest.raises((smoke.SmokeError, AssertionError), match=diagnosis) as failure:
        approvals.run(args)
    assert "synthetic-wrong-token" not in str(failure.value)
    assert instance.policy.read_bytes() == original
    assert instance.process.poll() is None


@pytest.mark.parametrize("control", ["clean", "different_launch", "wrong_guest_profile", "guest_cleanup_failure", "delegated", "delegated_lifecycle",
    "lifecycle_remainder", "lifecycle_crash_only", "delegated_clients", "delegated_service", "delegated_service_cutoff", "delegated_binding"])
def test_helper_consumer_failed_model_keeps_native_approval_and_owned_cleanup(helper_instance, monkeypatch, capsys, control, request):
    instance, args = helper_instance
    root = instance.root
    ids = {}
    for name in (args.worker, args.helper):
        created = instance.cli("agent", "create", name, "--workspace", str(root.parent), "--launcher", "supervisor")
        assert created.returncode == 0, created.stderr
        ids[name] = json.loads(created.stdout)["configuration"]["id"]
    share = root / "agents/helper/config-share"
    share.mkdir(exist_ok=True)
    model_config = root / "agents/helper/home/.codex/config.toml"
    model_config.parent.mkdir(parents=True, exist_ok=True)
    model_config.write_text('model="controlled-model"\n')
    state = {"agent_id": ids[args.helper], "run_id": "owned-sandbox", "launch_id": "previous-launch",
             "runtime_state": "running", "agent_state": "stopped", "exec": True}
    backend = None
    backends = []
    lifecycle = control in {"delegated_lifecycle", "lifecycle_remainder", "lifecycle_crash_only"}
    remaining = control == "lifecycle_remainder"
    crash_only = control == "lifecycle_crash_only"
    crashing = lifecycle and not remaining
    clients = control == "delegated_clients"
    service = control in {"delegated_service", "delegated_service_cutoff"}
    binding = control == "delegated_binding"
    if control == "delegated" or service or binding or lifecycle or clients:
        if sys.platform != "linux":
            pytest.skip("controlled run backend uses the Linux birth/argv boundary")
        args.delegated = control == "delegated"
        args.delegated_service = service
        args.delegated_binding = binding
        args.attention_cutoff = 8 if control == "delegated_service_cutoff" else None
        args.delegated_lifecycle = lifecycle
        args.delegated_lifecycle_remainder = remaining
        args.delegated_lifecycle_crash_only = crash_only
        args.delegated_clients = clients
        args.real_helper, args.model_unavailable = args.delegated or args.delegated_service or binding, False
        generation = "0123456789abcdef0123456789abcdef"
        backend = subprocess.Popen(["runsc-sandbox", "-c", "import time; time.sleep(300)", "boot",
            "safeyolo-" + generation, "--root", str(root / "run")], executable=sys.executable)
        backends.append(backend)
        def stop_backend():
            instance.cli("coord", "stop")
            for child in backends:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
        request.addfinalizer(stop_backend)
        for name in ids:
            directory = root / "agents" / name
            (directory / "config-share").mkdir(exist_ok=True)
            (directory / "runtime.json").write_text(json.dumps({"name": name, "agent_id": ids[name],
                "run_id": generation, "state": "running", "backend_pid": backend.pid,
                "backend_token": smoke._process_start_token(backend.pid)}))
            (directory / "config-share/host-launch-context.json").write_text(json.dumps({
                "agent_id": ids[name], "generation": generation}))
        state["run_id"] = generation
        instance.environment["SAFEYOLO_NATS_TEST_INSTANCE"] = str(root)
        nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
        started = instance.cli("coord", "start", *(["--binary", nats] if nats else []))
        assert started.returncode == 0, started.stderr
        if control == "delegated" or service or binding or clients:
            for operands in (("coord", "room", "create", "helper-agent"),
                             ("coord", "grant", "helper-agent", args.helper)):
                assert instance.cli(*operands).returncode == 0
            if service or binding:
                for index in range(8):
                    prior = instance.cli("coord", "send", "helper-agent", f"Prior journey {index}", "--to", args.helper)
                    assert prior.returncode == 0, prior.stderr
    checked = approvals.checked
    run_command = subprocess.run
    stopped = []
    stale_attempts = []
    inert = socket.socket(socket.AF_UNIX)

    def command(arguments, **kwargs):
        if arguments[0] == "controlled-guest":
            name, operands = arguments[1], shlex.split(arguments[2])
            if operands[0] == "python3":
                method, url, body, *extra = json.loads(operands[-1])
                headers = {"Content-Type": "application/json", **(extra[0] if extra else {})}
                if "_safeyolo.proxy.internal" in url:
                    headers["Authorization"] = f"Bearer {AGENT_TOKEN}"
                status, headers, payload = http_request(instance.paths[name], url, method=method,
                    body=json.dumps(body).encode() if body is not None else b"",
                    headers=headers)
                return json.dumps({"status": status, "body": payload.decode(), "request_id": headers.get("x-safeyolo-request-id"),
                    "approval_id": headers.get("x-safeyolo-approval-id")})
            if operands[0].endswith("safeyolo-guest"):
                guest = root / "assets/guest/safeyolo-guest"
                # The Mac installer verifies the guest's .version file.
                # The Linux guest executable cannot run on the Mac host.
                if sys.platform == "darwin":
                    version = guest.with_suffix(".version").read_text().strip()
                else:
                    version = checked([str(guest), "--version"])
                if control == "wrong_guest_profile":
                    return version.replace("profile=debug", "profile=production") if "profile=debug" in version else version.replace("profile=production", "profile=debug")
                return version
            if operands[0].endswith(".safeyolo-interactive-command"):
                return "codex-cli controlled" if operands[-1] == "--version" else "controlled login readiness"
            if operands[:2] == ["printf", "%s"] and operands[4].endswith(".safeyolo/safeyolo-coord"):
                environment = dict(instance.environment, SAFEYOLO_COORD_SOCKET=instance.paths[name],
                    SAFEYOLO_COORD_TOKEN_PATH=str(root / "data/agent_token"))
                data = json.loads(operands[2])
                return subprocess.check_output([str(root / "bin/safeyolo-coord"), "call", operands[-1]],
                    input=json.dumps(data), text=True, env=environment, timeout=30)
            staged = share / Path(operands[0]).name
            return checked([str(staged), *operands[1:], "--socket", instance.paths[name],
                            "--token-file", str(root / "data/agent_token")] if operands[1] == "helper"
                           else [str(staged), *operands[1:]])
        if arguments[3:] == ["agent", "status", args.helper]:
            return json.dumps(state)
        if crashing and arguments[3:] == ["start"]:
            # Pytest owns and reaps the crashed child; the installed host's
            # daemon is reaped by its ordinary parent.
            assert instance.process.wait(timeout=5) == -9
        result = checked(arguments, **kwargs)
        if arguments[3:] == ["stop"]:
            # Pytest owns the child and must reap it before the consumer
            # checks for a surviving proxy.
            assert instance.process.wait(timeout=5) == (-9 if crashing else 0)
            # A stopped native receipt and a bound socket without a listener
            # are retained inert files, not surviving owned processes.
            if not crashing:
                inert.bind(instance.paths[args.worker])
        return result

    def capture_stale(arguments, **kwargs):
        if arguments[0] != "controlled-guest":
            return run_command(arguments, **kwargs)
        name = arguments[1]
        directory = root / "agents" / name
        current = json.loads((directory / "runtime.json").read_text())
        context = json.loads((directory / "config-share/host-launch-context.json").read_text())
        assert context["generation"] != current["run_id"]
        stale_attempts.append((directory, current["run_id"]))
        assert kwargs == {"capture_output": True, "text": True, "timeout": 60}
        if control == "delegated_lifecycle":
            return subprocess.CompletedProcess(arguments, 0, command(arguments), "")
        return subprocess.CompletedProcess(arguments, 1, "", "safeyolo: provider sandbox or guest port is unavailable\n")

    def guest_transport(cli, name, text):
        assert str(cli) == args.transport_cli
        assert os.environ["SAFEYOLO_NATIVE_CONFIG_PATH"] == str(root / "config.toml")
        return ["controlled-guest", name, text]

    def model_turn(arguments, events_path, **kwargs):
        if control == "delegated" or service or binding:
            # The reviewer and guest transport are deliberate doubles here.
            # The calls below execute the actual native attention, canonical
            # read, decision and permission boundaries used by the runner.
            state.update(launch_id="controlled-reviewer", agent_state="running")
            cursor = int(re.search(r"since_sequence=(\d+)", arguments[-1])[1])
            assert cursor == (8 if service or binding else 0)
            events = []
            with events_path.open("x", encoding="utf-8") as output:
                def call(tool, data):
                    event = {"type": "item.started", "item": {"type": "mcp_tool_call", "tool": tool}}
                    events.append(event)
                    output.write(json.dumps(event) + "\n")
                    output.flush()
                    environment = dict(instance.environment, SAFEYOLO_COORD_SOCKET=instance.paths[args.helper],
                        SAFEYOLO_COORD_TOKEN_PATH=str(root / "data/agent_token"))
                    value = json.loads(subprocess.check_output([str(root / "bin/safeyolo-coord"), "call", tool],
                        input=json.dumps(data), text=True, env=environment, timeout=30))
                    return value
                for _ in range(1 if service or binding else 3):
                    attention = call("wait_for_coord", {"since_sequence": cursor, "timeout_seconds": 20, "limit": 1})
                    assert len(attention["objects"]) == 1
                    cursor = attention["next_cursor"]
                    identifier = re.search(r"apr-[0-9a-f]{32}", attention["objects"][0]["object"]["body"])[0]
                    canonical = call("read_approval", {"approval_id": identifier})
                    option = "delegated_once" if canonical["observed"]["service"] == "delegated-fixture" else "run"
                    choice = next(choice for choice in canonical["choices"] if choice["option"] == option)
                    value = call("resolve_approval", {"approval_id": identifier, "decision": "approve",
                        "delegation": choice["delegation"], "option": option})
                    assert value["status"] == "approved"
            state.update(agent_state="exited", exit_code=0)
            return "\n".join(json.dumps(event) for event in events)
        assert kwargs == {"timeout": 60, "expected_exit": 1}
        state.update(launch_id="controlled-model-launch", agent_state="running")
        settings = tomlkit.parse("\n".join(arguments[index + 1] for index, arg in enumerate(arguments) if arg == "-c"))
        provider = settings["model_providers"][settings["model_provider"]]
        status, _, payload = http_request(instance.paths[args.helper], provider["base_url"] + "/responses", method="POST",
            body=json.dumps({"model": "controlled-model", "input": [{"role": "user", "content": arguments[-1]}]}).encode(),
            headers={"Content-Type": "application/json", **provider["http_headers"]})
        assert status == 503
        state.update(agent_state="failed", exit_code=1)
        if control == "different_launch":
            state["launch_id"] = "unrelated-launch"
        events = [{"type": "thread.started", "thread_id": "controlled-thread"}, {"type": "turn.started"},
                  {"type": "turn.failed", "error": {"message": "HTTP 503: " + json.loads(payload)["error"]["message"]}}]
        return "\n".join(json.dumps(event) for event in events)

    def stop_guest(cli, selected, name):
        assert str(cli) == args.transport_cli and selected == root
        stopped.append(name)
        if control == "guest_cleanup_failure" and name == args.worker:
            raise AssertionError("controlled guest stop failed")
        if lifecycle:
            path = root / "agents" / name / "runtime.json"
            record = json.loads(path.read_text())
            record["state"] = "stopped"
            path.write_text(json.dumps(record))

    def start_guest(cli, selected, name):
        # Only guest boot/transport are doubled. Proxy restart, host-created
        # identities, typed grants and canonical decisions remain native.
        if name == args.helper:
            for directory, run_id in stale_attempts:
                assert json.loads((directory / "config-share/host-launch-context.json").read_text())["generation"] == run_id
        generation = uuid.uuid4().hex
        child = subprocess.Popen(["runsc-sandbox", "-c", "import time; time.sleep(300)", "boot",
            "safeyolo-" + generation, "--root", str(root / "run")], executable=sys.executable)
        backends.append(child)
        agent_id = tomlkit.parse(instance.policy.read_text())["agents"][name]["agent_id"]
        directory = root / "agents" / name
        (directory / "runtime.json").write_text(json.dumps({"name": name, "agent_id": agent_id,
            "run_id": generation, "state": "running", "backend_pid": child.pid,
            "backend_token": smoke._process_start_token(child.pid)}))
        (directory / "config-share/host-launch-context.json").write_text(json.dumps({
            "agent_id": agent_id, "generation": generation}))
        return Path(instance.paths[name])

    monkeypatch.setattr(approvals, "checked", command)
    monkeypatch.setattr(approvals.subprocess, "run", capture_stale)
    monkeypatch.setattr(approvals, "guest_command_args", guest_transport)
    monkeypatch.setattr(approvals, "run_helper", model_turn)
    monkeypatch.setattr(approvals, "runsc_identity", lambda _root, name, listener, **kwargs: {"controlled_guest": name})
    monkeypatch.setattr(approvals, "stop_guest", stop_guest)
    monkeypatch.setattr(approvals, "start_guest", start_guest)
    if clients:
        def operator_choice(read, action, _timeout):
            pending = read()
            assert pending["status"] == "pending" and pending["action"] == action
            option = "delegated_once" if action["kind"] == "gateway_route" else "run"
            instance.admin("POST", "/admin/approvals/" + pending["approval_id"],
                           {"decision": "approve", "option": option})
            return read()
        monkeypatch.setattr(approvals, "wait_for_operator", operator_choice)
    original = instance.policy.read_bytes()
    try:
        successful = control in {"clean", "delegated", "delegated_lifecycle", "lifecycle_remainder", "lifecycle_crash_only", "delegated_clients"} or service or binding
        if successful:
            approvals.run(args)
        else:
            diagnosis = {"different_launch": "launch does not match", "wrong_guest_profile": "guest executable is not the selected source",
                         "guest_cleanup_failure": "controlled guest stop failed"}[control]
            with pytest.raises(AssertionError, match=diagnosis):
                approvals.run(args)
        output = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
        final = [row for row in output if row.get("owned_guests_proxy_and_origins_stopped")]
        assert bool(final) == successful
        if final:
            result = final[0]
            if service or binding:
                assert result["attention_start"]["since_sequence"] == 8
                assert result["attention_start"]["expected_cutoff"] == args.attention_cutoff
                assert len(result["attention_start"]["prior_attention_edges"]) == 8
                assert result["reviewer_launch_id"] == "controlled-reviewer"
                assert len(result["exchanges"]) == 1
                exchange = result["exchanges"][0]
                assert exchange["type"] == ("binding" if binding else "service")
                assert exchange["decision"]["action"]["kind"] == ("contract_binding" if binding else "service_authorize")
                if binding:
                    assert exchange["value_refusal"]["status"] == exchange["operation_refusal"]["status"] == 403
                    assert exchange["helper_binding_refusal"]["status"] == exchange["revoked_retry"]["status"] == 403
                    assert exchange["revoked_approval"]["grant_active"] is False
                assert exchange["decision"]["result"]["issued_access"]["beneficiary"]["agent_id"] == ids[args.worker]
                assert exchange["resource_refusal"]["status"] == 403
                assert exchange["risk_refusal"]["status"] == 428
                assert not list((root / "data").glob("sy1349-*.value"))
                credentials = instance.cli("credentials", "list")
                assert credentials.returncode == 0, credentials.stderr
                assert "sy1349-" not in credentials.stdout
            elif control == "delegated" or clients:
                assert [exchange["type"] for exchange in result["exchanges"]] == ["network", "credential", "gateway"]
                if clients:
                    assert [exchange["decision"]["option"] for exchange in result["exchanges"]] == ["run", "run", "delegated_once"]
                    assert result["coord_unavailable"]["state"] == "stopped"
                    assert result["exchanges"][-1]["consumed_once_retry"]["status"] == 428
                else:
                    assert result["reviewer_launch_id"] == "controlled-reviewer"
            elif crash_only:
                assert result["lifecycle_selection"] == "crash_only"
                recovery = result["crash_recovery"]
                before, after = recovery["before_crash"], recovery["after_restart"]
                assert before["approval"]["approval_id"] == after["approval"]["approval_id"]
                assert before["policy_receipt"] == after["policy_receipt"]
                assert before["network_grant"] == after["network_grant"]
                assert before["origin_hits"] == after["origin_hits"] == []
                assert len(recovery["explicit_retry"]["origin_hits"]) == 1
                assert "replacement_agent_id" not in result and "stale_context" not in result
            elif lifecycle:
                assert result["original_agent_id"] != result["replacement_agent_id"]
                assert result["original_run_id"] != result["restarted_run_id"]
                assert len(result["origin_hits"]) == (1 if remaining else 2)
                assert result["lifecycle_selection"] == ("remainder" if remaining else "full")
                assert ("proxy_crash_kept_exact_receipt" in result) is not remaining
                stale = result["stale_context"]
                assert stale["approval_id"] == result["approval_ids"][0]
                assert stale["original_run_id"] == result["original_run_id"]
                assert stale["current_run_id"] == result["restarted_run_id"]
                assert stale["origin_hits_before"] == stale["origin_hits_after"]
                assert stale["origin_count_before"] == stale["origin_count_after"] == (0 if remaining else 1)
                assert stale["grant"]["approval_id"] == stale["approval_id"]
                assert stale["grant"]["grant_active"] is False
                assert stale["outcome"] == ("native_refusal" if remaining else "http_refusal")
                assert next(row["observation"] for row in output if row.get("phase") == "stale_context") == stale
                assert next(row["observation"] for row in output if row.get("phase") == "reviewer_restart") == result["reviewer_restart"]
                checks = next(row for row in output if row.get("phase") == "lifecycle_checks")
                assert checks["observation"] == {key: value for key, value in result.items() if key != "owned_guests_proxy_and_origins_stopped"}
                assert all(row["phase_passed"] is True for row in output if "phase_passed" in row)
                setup = [row["approval"] for row in output if row.get("phase") == "lifecycle_setup"]
                assert len(setup) == int(remaining)
                if remaining:
                    assert setup[0]["approval_id"] == stale["approval_id"]
                    assert setup[0]["grant_active"] is True
                assert result["reviewer_restart"]["approval"]["approval_id"] == result["approval_ids"][1]
                assert result["reviewer_restart"]["approval"]["grant_active"] is True
                assert result["replacement_grant"]["approval_id"] == result["approval_ids"][1]
                assert result["replacement_grant"]["grant_active"] is False
                if remaining:
                    assert stale["returncode"] == 1 and stale["http"] is None
                    assert stale["stdout"] == ""
                else:
                    assert stale["returncode"] == 0 and stale["http"]["status"] in (403, 428)
            else:
                runtime = result["runtime"]
                assert runtime["pid"] == instance.process.pid
                assert runtime["authenticated_runtime_identity"]["status"] == "authenticated"
                assert result["model_failure"]["pending_after_failure"]["status"] == "pending"
                assert result["direct_operator_outcome"]["status"] == "approved"
                assert len(result["origin_hits"]) == 2 and result["origin_hits"][0] == result["origin_hits"][1]
                assert result["scope_controls"] == "Helper and second port refused"
        assert stopped == ([args.worker, args.helper, args.worker, args.worker, args.helper]
                           if lifecycle and not crash_only else [args.worker, args.helper])
        assert instance.process.wait(timeout=5) == (-9 if crashing else 0)
        assert (root / "data/proxy-process.json").is_file()
        assert not (root / "data/selected-ready.json").exists()
        assert not smoke._socket_accepting(Path(instance.paths[args.worker]))
        if not crashing:
            assert Path(instance.paths[args.worker]).is_socket()
        assert not list(share.glob("native-operator-821-*"))
        assert instance.policy.read_bytes() == original
    finally:
        if backend is not None:
            stop_backend()
        inert.close()
        Path(instance.paths[args.worker]).unlink(missing_ok=True)
