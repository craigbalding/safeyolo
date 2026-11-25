"""Agent host calls preserve typed preparation and never replay a failed effect."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import subprocess
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "cli/src/safeyolo/agent_context/skills/safeyolo/scripts/host-operation.py"
spec = importlib.util.spec_from_file_location("host_operation_client", SOURCE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


@pytest.fixture
def transport(tmp_path, monkeypatch):
    token = tmp_path / "agent-token"
    token.write_text("fixture-agent")
    monkeypatch.setattr(client, "TOKEN_PATH", token)
    calls = []
    responses = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert timeout > 0
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return Reply(json.dumps(response).encode())

    monkeypatch.setattr(client.urllib.request, "build_opener", lambda *_args: Opener())
    return calls, responses


def test_discovery_pins_and_typed_data_cross_preparation_without_authority_fields(tmp_path, transport):
    calls, responses = transport
    responses.extend([{"discovery": {"operations": [{"operation_id": "selected", "operation_sha256": "op",
                        "implementation_sha256": "implementation", "revisions": {"authority": "observed"}}]}},
                      {"kind": "proposal", "prepared": {"invocation": {"typed": True}, "revisions": {"authority": "observed"}}}])
    arguments = tmp_path / "args.json"
    values = {"value": "quotes '\" $() ; are data", "flag": True, "count": 4, "paths": ["a", "b"]}
    arguments.write_text(json.dumps(values))
    result = client.run(argparse.Namespace(command="propose", binding="case:linux", request_id="proposal-1",
                                          operation="selected", resource="fixed", arguments=str(arguments)))
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps(result))
    assert calls[-1].full_url.endswith("/gateway/host/case:linux")
    proposal = json.loads(calls[-1].data)
    assert proposal["action"]["invocation"]["arguments"] == values
    assert proposal["expected"] == {"authority": "observed"}
    assert set(proposal) == {"request_id", "expected", "action"}
    responses.extend([{"host_bindings": [{"binding": "case", "target_id": "local-test", "issuer_id": "issuer"}]},
                      {"kind": "job", "receipt": {"job_id": "original", "request_id": "invoke-1"}}])
    result = client.run(argparse.Namespace(command="invoke", binding="case", request_id="invoke-1", prepared=str(prepared)))
    assert result["receipt"]["job_id"] == "original"
    invoke = json.loads(calls[-1].data)
    assert invoke["action"] == {"kind": "invoke", "invocation": {"typed": True}}
    assert invoke["expected"] == {"authority": "observed"}


def test_file_cli_keeps_target_path_revision_and_read_failure(transport, monkeypatch, capsys):
    calls, responses = transport
    responses.extend([
        {"discovery": {"revisions": {"authority": "observed"}}},
        {"kind": "file", "file_revision": "file-1", "data_base64": "cGFydGlhbA==", "eof": False},
    ])
    arguments = [str(SOURCE), "file", "case:linux", "--request-id", "file-read", "--job", "job-original",
                 "--path", "/selected/result with spaces; $data", "--offset", "7", "--bytes", "4096", "--file-revision", "file-1"]
    monkeypatch.setattr(client.sys, "argv", arguments)
    assert client.main() == 0
    assert json.loads(capsys.readouterr().out)["file_revision"] == "file-1"
    assert json.loads(calls[-1].data) == {
        "request_id": "file-read", "expected": {"authority": "observed"},
        "action": {"kind": "file", "job_id": "job-original", "path": "/selected/result with spaces; $data",
                   "offset": 7, "max_bytes": 4096, "expected_file_revision": "file-1"},
    }
    responses.extend([{"discovery": {"revisions": {"authority": "observed"}}}, TimeoutError("file unavailable")])
    assert client.main() == 1
    failure = json.loads(capsys.readouterr().out)
    assert failure["execution_outcome"] == "unavailable"
    assert failure["request_id"] == "file-read"
    assert len(calls) == 4  # Each explicit attempt does discovery and one read.


@pytest.mark.parametrize("kind", ["invoke", "cancel", "adopt"])
def test_lost_mutation_reply_is_uncertain_and_is_not_retried(transport, kind):
    calls, responses = transport
    responses.append(TimeoutError("lost reply"))
    with pytest.raises(client.RequestFailed) as caught:
        client.call("case", "original-id", {"kind": kind})
    assert len(calls) == 1
    assert caught.value.value["execution_outcome"] == "uncertain"
    assert caught.value.value["request_id"] == "original-id"


def test_code_adoption_uses_a_separate_class_and_never_invokes(tmp_path, transport):
    calls, responses = transport
    script = tmp_path / "task.sh"
    script.write_text("printf 'selected task'\n")
    ceiling = {"execution": {"argv": [{"kind": "literal", "value": "-c"}, {"kind": "literal", "value": "pwd"}],
                             "filesystem": {"write": ["/selected"]}, "resources": {"processes": 8},
                             "broader": ["processes"], "dependencies": {}}}
    responses.extend([
        {"host_bindings": [{"binding": "case", "task_active": True, "agent_code_classes": [
            {"prefix": "task:", "excluded": [], "rule": {"ceiling": ceiling}}]}]},
        {"discovery": {"package_sha256": "exact-base", "revisions": {"authority": "current"}}},
        {"kind": "adoption", "package_sha256": "new-package"},
    ])
    result = client.run(argparse.Namespace(command="adopt", binding="case", request_id="req-code", operation="task:run",
                                          definition=None, dependencies=None, script=str(script)))
    assert result["kind"] == "adoption"
    posted = json.loads(calls[-1].data)
    assert posted["expected"] == {"authority": "current"}
    assert posted["action"]["base_package_sha256"] == "exact-base"
    assert posted["action"]["operation"]["execution"]["filesystem"] == {"write": ["/selected"]}
    assert posted["action"]["operation"]["execution"]["argv"][1]["value"] == script.read_text()
    assert posted["action"]["operation"]["execution"]["resources"]["processes"] == 8
    assert posted["action"]["operation"]["execution"]["broader"] == ["processes"]
    assert [json.loads(call.data)["action"]["kind"] for call in calls if call.data] == ["discover", "adopt"]


@pytest.mark.parametrize("path,value", [
    ("/gateway/host-setup", {"kind": "prepare", "operation_id": "req-setup"}),
    ("/gateway/host-setup", {"kind": "submit", "operation_id": "req-setup"}),
    ("/gateway/host/case/resume", {"request_id": "req-resume"}),
])
def test_setup_and_resume_lost_replies_preserve_uncertainty(transport, path, value):
    calls, responses = transport
    responses.append(TimeoutError("original reply lost"))
    with pytest.raises(client.RequestFailed) as caught:
        client.request(path, value)
    assert len(calls) == 1
    assert caught.value.value["execution_outcome"] == "uncertain"
    assert caught.value.value["request_id"] == value.get("request_id", value.get("operation_id"))


def test_setup_recovery_is_an_original_read_with_no_creation(transport):
    calls, responses = transport
    responses.append({"operation_id": "req-original", "status": "prepared", "permission_granted": False})
    result = client.run(argparse.Namespace(command="setup-status", original_request_id="req-original"))
    assert result["permission_granted"] is False
    assert calls[0].full_url.endswith("/gateway/host-setup/req-original")
    assert calls[0].data is None


def test_adoption_recovery_does_not_require_matching_discovery(transport):
    calls, responses = transport
    responses.append({"kind": "adoption", "package_sha256": "committed-target-package"})
    result = client.run(argparse.Namespace(command="adoption", binding="case", request_id="req-read",
                                          original_request_id="req-original"))
    assert result["package_sha256"] == "committed-target-package"
    assert len(calls) == 1
    assert json.loads(calls[0].data) == {"request_id": "req-read", "expected": None,
                                       "action": {"kind": "adoption", "request_id": "req-original"}}


def test_staging_preserves_binary_bytes_and_quotes_the_selected_path(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(bytes(range(256)))
    target = tmp_path / "result; $(touch accidental) ' quoted"
    scripts = []

    def adopt(_args, script):
        scripts.append(script)
        return {"operation_sha256": "operation", "original": {"request": {"target_id": "target", "issuer_id": "issuer"}}}

    def call(_binding, _request_id, action, _expected=None):
        if action["kind"] == "discover":
            return {"discovery": {"target_id": "target", "operations": [{"operation_id": "task:stage", "operation_sha256": "operation",
                    "implementation_sha256": "implementation", "revisions": {}}]}}
        if action["kind"] == "propose":
            return {"prepared": {"invocation": action["invocation"], "revisions": {}}}
        assert action["kind"] == "invoke"
        return {"receipt": {"job_id": "original-stage"}}

    monkeypatch.setattr(client, "adopt_code", adopt)
    monkeypatch.setattr(client, "call", call)
    result = client.stage(argparse.Namespace(binding="case", request_id="req-stage", file=str(source), path=str(target)))
    assert result["target_result"]["receipt"]["job_id"] == "original-stage"
    # Check the emitted POSIX bytes/quoting locally; this is not native containment proof.
    subprocess.run(["/bin/sh", "-c", scripts[0]], cwd=tmp_path, check=True)
    assert target.read_bytes() == source.read_bytes()
    assert not (tmp_path / "accidental").exists()


def test_interleaved_staging_refuses_another_calls_adopted_program(tmp_path, monkeypatch):
    # Exercise full helper calls over HTTP. This controlled gateway checks pins
    # and runs benign local scripts; it does not prove native containment.
    first_adopted, second_adopted = Event(), Event()
    current = {}
    invoked = []
    ceiling = {"execution": {"argv": [{"kind": "literal", "value": "-c"}], "resources": {"processes": 8}}}

    class AgentAPI(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.respond({"host_bindings": [{"binding": "case", "target_id": "target", "task_active": True,
                          "agent_code_classes": [{"prefix": "task:", "excluded": [], "rule": {"ceiling": ceiling}}]}]})

        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            action, request_id = value["action"], value["request_id"]
            if action["kind"] == "discover":
                if request_id == "req-stage-a-discovery":
                    assert second_adopted.wait(5)
                self.respond({"discovery": {"target_id": "target", "package_sha256": "package", "revisions": {},
                              "operations": [current["operation"]] if current else []}})
            elif action["kind"] == "adopt":
                script = action["operation"]["execution"]["argv"][1]["value"]
                digest = hashlib.sha256(script.encode()).hexdigest()
                current.update(script=script, operation={"operation_id": "task:stage", "operation_sha256": digest,
                               "implementation_sha256": digest, "revisions": {"package": digest}})
                self.respond({"operation_sha256": digest, "original": {"request": {"target_id": "target",
                              "issuer_id": "issuer", "request_id": request_id, "action": action}}})
                (first_adopted if request_id == "req-stage-a-adopt" else second_adopted).set()
            else:
                assert value["expected"] == current["operation"]["revisions"]
                assert action["invocation"]["operation_sha256"] == current["operation"]["operation_sha256"]
                if action["kind"] == "propose":
                    self.respond({"prepared": {"invocation": action["invocation"], "revisions": value["expected"]}})
                else:
                    assert action["kind"] == "invoke"
                    invoked.append(request_id)
                    subprocess.run(["/bin/sh", "-c", current["script"]], cwd=tmp_path, check=True)
                    self.respond({"receipt": {"job_id": request_id}})

    source = tmp_path / "source"
    source.write_bytes(b"selected bytes")
    token = tmp_path / "token"
    token.write_text("fixture-agent")
    monkeypatch.setattr(client, "TOKEN_PATH", token)
    first = argparse.Namespace(binding="case", request_id="req-stage-a", file=str(source), path=str(tmp_path / "a"))
    second = argparse.Namespace(binding="case", request_id="req-stage-b", file=str(source), path=str(tmp_path / "b"))
    with ThreadingHTTPServer(("127.0.0.1", 0), AgentAPI) as server:
        monkeypatch.setattr(client, "BASE_URL", f"http://127.0.0.1:{server.server_port}")
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            with ThreadPoolExecutor(max_workers=2) as calls:
                a = calls.submit(client.stage, first)
                assert first_adopted.wait(5)
                b = calls.submit(client.stage, second)
                with pytest.raises(client.RequestFailed) as caught:
                    a.result(timeout=5)
                assert caught.value.value["adoption"]["original"]["request"]["request_id"] == "req-stage-a-adopt"
                assert "No staging program was invoked" in caught.value.value["next_action"]
                assert b.result(timeout=5)["target_result"]["receipt"]["job_id"] == "req-stage-b-invoke"
        finally:
            server.shutdown()
            worker.join(timeout=5)
    assert invoked == ["req-stage-b-invoke"]
    assert not (tmp_path / "a").exists()
    assert (tmp_path / "b").read_bytes() == source.read_bytes()


@pytest.mark.parametrize("target,operations", [
    ("another-target", [{"operation_id": "task:stage", "operation_sha256": "original"}]),
    ("target", []),
])
def test_staging_refuses_a_changed_target_or_removed_operation(tmp_path, monkeypatch, target, operations):
    source = tmp_path / "source"
    source.write_bytes(b"selected bytes")
    adoption = {"operation_sha256": "original", "original": {"request": {"target_id": "target"}}}
    monkeypatch.setattr(client, "adopt_code", lambda *_args: adoption)
    calls = []

    def call(_binding, _request_id, action, _expected=None):
        calls.append(action["kind"])
        assert action["kind"] == "discover"
        return {"discovery": {"target_id": target, "operations": operations}}

    monkeypatch.setattr(client, "call", call)
    with pytest.raises(client.RequestFailed) as caught:
        client.stage(argparse.Namespace(binding="case", request_id="req-stage", file=str(source), path="/selected/file"))
    assert caught.value.value["adoption"] == adoption
    assert calls == ["discover"]


@pytest.mark.parametrize("gateway_reply", [False, True])
def test_lost_cancel_reply_retains_the_selected_job_without_repeating_cancellation(transport, gateway_reply, monkeypatch, capsys):
    calls, responses = transport
    canonical = {"execution_outcome": "uncertain", "request_id": "cancel-1", "possible_job_id": "job-original",
                 "target_id": "gateway-target", "host_binding": "case"}
    failure = (urllib.error.HTTPError(client.BASE_URL, 503, "lost cancel reply", {}, Reply(json.dumps(canonical).encode()))
               if gateway_reply else TimeoutError("complete cancellation reply lost"))
    responses.extend([{"discovery": {"target_id": "discovered-target", "revisions": {"authority": "observed"}}}, failure])
    monkeypatch.setattr(client.sys, "argv", [str(SOURCE), "cancel", "case", "--request-id", "cancel-1", "--job", "job-original", "--revision", "3"])
    assert client.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result["execution_outcome"] == "uncertain"
    assert result["possible_job_id"] == "job-original"
    assert result["target_id"] == ("gateway-target" if gateway_reply else "discovered-target")
    assert result["host_binding"] == "case"
    assert len(calls) == 2
    assert json.loads(calls[-1].data)["action"] == {"kind": "cancel", "job_id": "job-original", "expected_revision": 3}
    if gateway_reply:
        assert result == canonical


@pytest.mark.parametrize("gateway_reply", [False, True])
def test_lost_complete_reply_retains_original_job_context_without_another_effect(tmp_path, transport, gateway_reply):
    calls, responses = transport
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps({"prepared": {"invocation": {"typed": True}, "revisions": {"authority": "observed"}}}))
    canonical = {"execution_outcome": "uncertain", "request_id": "original-id", "possible_job_id": "job-gateway",
                 "target_id": "gateway-target", "host_binding": "case"}
    failure = (urllib.error.HTTPError(client.BASE_URL, 503, "lost target reply", {}, Reply(json.dumps(canonical).encode()))
               if gateway_reply else TimeoutError("complete invocation reply lost"))
    responses.extend([{"host_bindings": [{"binding": "case", "target_id": "local-test", "issuer_id": "issuer"}]}, failure])
    with pytest.raises(client.RequestFailed) as caught:
        client.run(argparse.Namespace(command="invoke", binding="case", request_id="original-id", prepared=str(prepared)))
    expected_job = "job-gateway" if gateway_reply else "job-32a58fdae1911df72559aebfe25b6b88cfe2f3fd049473eca697be20c6b18796"
    assert caught.value.value["possible_job_id"] == expected_job
    assert caught.value.value["target_id"] == ("gateway-target" if gateway_reply else "local-test")
    assert caught.value.value["host_binding"] == "case"
    assert caught.value.value["execution_outcome"] == "uncertain"
    assert len(calls) == 2
    assert calls[0].data is None
    assert json.loads(calls[-1].data)["action"]["kind"] == "invoke"
    if gateway_reply:
        assert caught.value.value == canonical


def test_unavailable_binding_prevents_invocation_after_preparation(tmp_path, transport):
    calls, responses = transport
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps({"prepared": {"invocation": {}, "revisions": {}}}))
    responses.append({"host_bindings": []})
    with pytest.raises(client.RequestFailed) as caught:
        client.run(argparse.Namespace(command="invoke", binding="case", request_id="original-id", prepared=str(prepared)))
    assert "no invocation was sent" in caught.value.value["next_action"]
    assert len(calls) == 1 and calls[0].data is None


def test_private_refusal_is_preserved_without_escalation_or_resubmit(transport):
    calls, responses = transport
    body = {"challenge_id": "private-finding", "reason": "unavailable required check"}
    responses.append(urllib.error.HTTPError(client.BASE_URL, 403, "refused", {}, Reply(json.dumps(body).encode())))
    with pytest.raises(client.RequestFailed) as caught:
        client.call("case", "original-id", {"kind": "invoke"})
    assert caught.value.value == body
    assert len(calls) == 1


def test_redirect_does_not_create_another_authenticated_request():
    assert client.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid") is None


@pytest.mark.parametrize("command", ["invoke", "cancel"])
@pytest.mark.parametrize("reply", ["success", "disconnect", "truncated", "invalid-json", "non-json-error", "truncated-error", "refusal", "uncertain"])
def test_real_http_mutation_reply_retains_recovery_context(tmp_path, monkeypatch, capsys, command, reply):
    mutations = []
    canonical = {"execution_outcome": "uncertain", "request_id": "original-id", "possible_job_id": "job-gateway",
                 "target_id": "gateway-target", "host_binding": "case"}
    refusal = {"challenge_id": "private-finding", "reason": "unavailable required check"}
    success = {"kind": "job", "receipt": {"job_id": "job-original", "request_id": "original-id"}}

    class AgentAPI(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, status, body, length=None):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body) if length is None else length))
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            self.respond(200, {"host_bindings": [{"binding": "case", "target_id": "local-test", "issuer_id": "issuer"}]})

        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if value["action"]["kind"] == "discover":
                self.respond(200, {"discovery": {"target_id": "local-test", "revisions": {"authority": "observed"}}})
                return
            mutations.append(value)
            if reply == "disconnect":
                self.close_connection = True
            elif reply in {"truncated", "truncated-error"}:
                self.respond(200 if reply == "truncated" else 503, b'{"kind":"job",', length=1000)
            elif reply in {"invalid-json", "non-json-error"}:
                self.respond(200 if reply == "invalid-json" else 503, b"Unavailable")
            elif reply == "refusal":
                self.respond(403, refusal)
            elif reply == "uncertain":
                self.respond(503, canonical)
            else:
                self.respond(200, success)

    token = tmp_path / "agent-token"
    token.write_text("fixture-agent")
    monkeypatch.setattr(client, "TOKEN_PATH", token)
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps({"prepared": {"invocation": {"typed": True}, "revisions": {"authority": "observed"}}}))
    arguments = [str(SOURCE), command, "case", "--request-id", "original-id"]
    arguments.extend(["--prepared", str(prepared)] if command == "invoke" else ["--job", "job-original", "--revision", "3"])
    monkeypatch.setattr(client.sys, "argv", arguments)
    with HTTPServer(("127.0.0.1", 0), AgentAPI) as server:
        monkeypatch.setattr(client, "BASE_URL", f"http://127.0.0.1:{server.server_port}")
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            status = client.main()
        finally:
            server.shutdown()
            worker.join(timeout=5)
    result = json.loads(capsys.readouterr().out)
    assert len(mutations) == 1
    assert mutations[0]["action"]["kind"] == command
    assert mutations[0]["request_id"] == "original-id"
    assert status == (0 if reply == "success" else 1)
    if reply in {"success", "refusal", "uncertain"}:
        assert result == {"success": success, "refusal": refusal, "uncertain": canonical}[reply]
    else:
        assert result["execution_outcome"] == "uncertain"
        assert result["request_id"] == "original-id"
        assert result["possible_job_id"] == ("job-32a58fdae1911df72559aebfe25b6b88cfe2f3fd049473eca697be20c6b18796" if command == "invoke" else "job-original")
        assert result["target_id"] == "local-test"
        assert result["host_binding"] == "case"
        assert "no request was retried" in result["next_action"]
        if reply in {"non-json-error", "truncated-error"}:
            assert result["http_status"] == 503


@pytest.mark.parametrize("action", [None, {"kind": "discover"}])
def test_undecodable_read_error_is_unavailable(transport, action):
    calls, responses = transport
    responses.append(urllib.error.HTTPError(client.BASE_URL, 503, "unavailable", {}, Reply(b"Unavailable")))
    with pytest.raises(client.RequestFailed) as caught:
        client.request("/gateway/host", None if action is None else {"request_id": "read-id", "action": action})
    assert caught.value.value["execution_outcome"] == "unavailable"
    assert caught.value.value["http_status"] == 503
    assert "possible_job_id" not in caught.value.value
    assert len(calls) == 1


@pytest.mark.parametrize("broader_processes", [False, True])
def test_stage_does_not_reserve_the_service_listener(tmp_path, transport, broader_processes):
    calls, responses = transport
    source = tmp_path / "selected"
    source.write_bytes(b"selected bytes")
    network = {"destinations": [], "listeners": [{"address": "0.0.0.0", "port": 8080, "transport": "tcp"}],
               "listener_handoff": {"candidates": [{"address": "0.0.0.0", "port": 8080}]}, "ipc": []}
    broader = ["network_ipc", "memory"] + (["processes"] if broader_processes else [])
    ceiling = {"execution": {"argv": [{"kind": "literal", "value": "-c"}, {"kind": "literal", "value": "pwd"}],
                             "network": network, "broader": broader,
                             "resources": {"processes": 8}, "dependencies": {}}}
    responses.extend([
        {"host_bindings": [{"binding": "case", "agent_code_classes": [
            {"prefix": "task:", "excluded": [], "rule": {"ceiling": ceiling}}]}]},
        {"discovery": {"package_sha256": "base", "revisions": {}}},
        {"operation_sha256": "own", "original": {"request": {"target_id": "target", "issuer_id": "issuer"}}},
        {"discovery": {"target_id": "target", "operations": [{"operation_id": "task:stage", "operation_sha256": "own",
            "implementation_sha256": "implementation", "revisions": {}}]}},
        {"prepared": {"invocation": {}, "revisions": {}}},
        {"receipt": {"job_id": "staging"}},
    ])
    client.stage(argparse.Namespace(binding="case", request_id="req-stage", file=str(source), path="/selected/input"))
    execution = json.loads(calls[2].data)["action"]["operation"]["execution"]
    assert execution["network"] == {"destinations": [], "listeners": [], "ipc": []}
    assert execution["broader"] == ["memory"]
    assert execution["resources"]["processes"] == (1 if broader_processes else 8)
    assert ceiling["execution"]["resources"]["processes"] == 8
    assert ceiling["execution"]["network"] == network
