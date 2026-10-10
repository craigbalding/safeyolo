"""Run the maintained Helper consumer with a real selected native proxy.

Guest status/transport and Codex events are controlled source-test inputs.
Native ownership, policy, approval, Helper commands, HTTP and cleanup are real.
The installed sandbox/Codex witness remains a separate operator run.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox import installed_host_smoke as smoke
from tests.blackbox import installed_shared_approvals as approvals
from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_instance


@pytest.fixture
def helper_instance(tmp_path_factory, monkeypatch):
    directory = tmp_path_factory.mktemp("u6")
    (directory / "operator-token").write_text("synthetic-helper-admin-token")
    with native_instance(directory, agent_api=True, agent_map={"worker": "10.0.0.2", "helper": "10.0.0.3"},
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
            wait_for_operator=False, operator_timeout=1, reconcile_seconds=0)
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
        args.native_proxy.hardlink_to(root / "bin/safeyolo-proxy")
    elif control.startswith("foreign_") and control != "foreign_socket":
        record = json.loads(marker.read_text())
        record["pid" if control == "foreign_readiness" else "instance_id"] = 1 if control == "foreign_readiness" else "other-instance"
        marker.write_text(json.dumps(record))
    elif control == "invalid_auth":
        (root.parent / "operator-token").write_text("synthetic-wrong-token")
    elif control == "foreign_socket":
        mapping = json.loads((root / "data/agent_map.json").read_text())
        mapping["worker"]["ip"] = "10.0.0.9"
        (root / "data/agent_map.json").write_text(json.dumps(mapping))
    original = instance.policy.read_bytes()

    def no_guest(*arguments, **kwargs):
        pytest.fail("unowned preflight reached a guest")

    monkeypatch.setattr(approvals, "runsc_identity", no_guest)
    with pytest.raises((smoke.SmokeError, AssertionError), match=diagnosis) as failure:
        approvals.run(args)
    assert "synthetic-wrong-token" not in str(failure.value)
    assert instance.policy.read_bytes() == original
    assert instance.process.poll() is None


@pytest.mark.parametrize("control", ["clean", "different_launch", "wrong_guest_profile", "guest_cleanup_failure"])
def test_helper_consumer_failed_model_keeps_native_approval_and_owned_cleanup(helper_instance, monkeypatch, capsys, control):
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
    checked = approvals.checked
    stopped = []
    inert = socket.socket(socket.AF_UNIX)

    def command(arguments, **kwargs):
        if arguments[0] == "controlled-guest":
            name, operands = arguments[1], shlex.split(arguments[2])
            if operands[0] == "python3":
                method, url, body = json.loads(operands[-1])
                status, headers, payload = request(instance.paths[name], url, method=method,
                    body=json.dumps(body).encode() if body is not None else b"",
                    headers={"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"})
                return json.dumps({"status": status, "body": payload.decode(), "request_id": headers.get("x-safeyolo-request-id")})
            if operands[0].endswith("safeyolo-guest"):
                version = checked([str(root / "assets/guest/safeyolo-guest"), "--version"])
                if control == "wrong_guest_profile":
                    return version.replace("profile=debug", "profile=production") if "profile=debug" in version else version.replace("profile=production", "profile=debug")
                return version
            if operands[0].endswith(".safeyolo-interactive-command"):
                return "codex-cli controlled" if operands[-1] == "--version" else "controlled login readiness"
            staged = share / Path(operands[0]).name
            return checked([str(staged), *operands[1:], "--socket", instance.paths[name],
                            "--token-file", str(root / "data/agent_token")] if operands[1] == "helper"
                           else [str(staged), *operands[1:]])
        if arguments[3:] == ["agent", "status", args.helper]:
            return json.dumps(state)
        result = checked(arguments, **kwargs)
        if arguments[3:] == ["stop"]:
            # A stopped native receipt and a bound socket without a listener
            # are retained inert files, not surviving owned processes.
            inert.bind(instance.paths[args.worker])
        return result

    def guest_transport(cli, name, text):
        assert str(cli) == args.transport_cli
        assert os.environ["SAFEYOLO_NATIVE_CONFIG_PATH"] == str(root / "config.toml")
        return ["controlled-guest", name, text]

    def model_turn(arguments, events_path, **kwargs):
        assert kwargs == {"timeout": 60, "expected_exit": 1}
        state.update(launch_id="controlled-model-launch", agent_state="running")
        settings = tomlkit.parse("\n".join(arguments[index + 1] for index, arg in enumerate(arguments) if arg == "-c"))
        provider = settings["model_providers"][settings["model_provider"]]
        status, _, payload = request(instance.paths[args.helper], provider["base_url"] + "/responses", method="POST",
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

    monkeypatch.setattr(approvals, "checked", command)
    monkeypatch.setattr(approvals, "guest_command_args", guest_transport)
    monkeypatch.setattr(approvals, "run_helper", model_turn)
    monkeypatch.setattr(approvals, "runsc_identity", lambda _root, name, listener, **kwargs: {"controlled_guest": name})
    monkeypatch.setattr(approvals, "stop_guest", stop_guest)
    original = instance.policy.read_bytes()
    try:
        if control == "clean":
            approvals.run(args)
        else:
            diagnosis = {"different_launch": "launch does not match", "wrong_guest_profile": "guest executable is not the selected source",
                         "guest_cleanup_failure": "controlled guest stop failed"}[control]
            with pytest.raises(AssertionError, match=diagnosis):
                approvals.run(args)
        output = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
        final = [row for row in output if row.get("owned_guests_proxy_and_origins_stopped")]
        assert bool(final) == (control == "clean")
        if final:
            result = final[0]
            runtime = result["runtime"]
            assert runtime["pid"] == instance.process.pid
            assert runtime["authenticated_runtime_identity"]["status"] == "authenticated"
            assert result["model_failure"]["pending_after_failure"]["status"] == "pending"
            assert result["direct_operator_outcome"]["status"] == "approved"
            assert len(result["origin_hits"]) == 2 and result["origin_hits"][0] == result["origin_hits"][1]
            assert result["scope_controls"] == "Helper and second port refused"
        assert stopped == [args.worker, args.helper]
        assert instance.process.wait(timeout=5) == 0
        assert (root / "data/proxy-process.json").is_file()
        assert not (root / "data/selected-ready.json").exists()
        assert Path(instance.paths[args.worker]).is_socket() and not smoke._socket_accepting(Path(instance.paths[args.worker]))
        assert not list(share.glob("native-operator-821-*"))
        assert instance.policy.read_bytes() == original
    finally:
        inert.close()
        Path(instance.paths[args.worker]).unlink(missing_ok=True)
