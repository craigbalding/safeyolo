"""Existing supervised checkpoint seams, exercised through the native command.

The HTTP and model event fixtures are deterministic transport seams. They do
not claim a real model login or a deployed G2/G4 result.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
ATTENTION = "attn-" + "a" * 32
TARGET = "https://example.test/issues/818"
TASK = f"TASK target={TARGET} assignee=forge\n\nDeliver the assigned work."
EDGE = {"attention_id": ATTENTION, "room_id": "rm-backlog", "kind": "message", "object_id": "msg-task", "revision_or_sequence": 42, "membership_granted_at": 1}
OBJECT = {"msg_id": "msg-task", "sequence": 42, "room_id": "rm-backlog", "sender_kind": "agent", "sender_agent_id": "ag-relay", "sender_agent_name": "relay", "body": TASK}


@pytest.fixture
def binary():
    path = Path(os.environ.get("SAFEYOLO_COORD_TEST_BINARY", ROOT / "proxy/target/debug/safeyolo-coord"))
    assert path.is_file(), "Build safeyolo-coord before running the native supervisor tests"
    return path


class CoordFixture:
    def __init__(self):
        self.messages = []
        self.sends = 0
        self.agent_name = "forge"
        self.unknown_send = False
        self.page = {"edges": [EDGE], "next_cursor": 7}
        self.bad_object = False
        self.objects = {ATTENTION: {"edge": EDGE, "object": OBJECT}}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == "/health":
                    result = {"agent_api": "ok"}
                elif path == "/api/coord/attention/wait":
                    result = owner.page
                elif path.startswith("/api/coord/attention/") and path.endswith("/object"):
                    if owner.bad_object:
                        return self.reply(403, {"error": "membership revoked"})
                    result = owner.objects[path.split("/")[-2]]
                elif path.endswith("/messages"):
                    result = {"messages": owner.messages, "next_cursor": 50, "has_more": False}
                else:
                    return self.reply(404, {"error": "missing fixture route"})
                self.reply(200, result)

            def do_POST(self):
                args = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                path = urlsplit(self.path).path
                if path.endswith("/join"):
                    return self.reply(200, {"room_id": "rm-backlog", "permissions": ["send", "receive"], "brief": {"revision": 0}})
                if path.endswith("/send"):
                    owner.sends += 1
                    envelope = {"body": args["body"], "msg_id": f"msg-{owner.sends}", "sender_kind": "agent", "sender_agent_name": owner.agent_name, "sender_agent_id": "ag-" + owner.agent_name, "sequence": 43 + owner.sends}
                    owner.messages.append(envelope)
                    if owner.unknown_send:
                        return self.reply(503, {"error": "receipt unavailable", "send_outcome": "unknown"})
                    return self.reply(200, {"envelope": envelope, "sequence": envelope["sequence"], "attention_intent": {"mode": "targeted"}, "attention_status": "ready"})
                self.reply(404, {"error": "missing fixture route"})

            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


@pytest.fixture
def fixture(tmp_path, binary):
    coord = CoordFixture()
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text(f'''forced_chatgpt_auth=false
model_provider="fixture"
model="fixture-model"
[mcp_servers.safeyolo-coord]
command={json.dumps(str(binary))}
[model_providers.fixture.auth]
command="/usr/bin/true"
args=[]
''')
    token = tmp_path / "agent-token"
    token.write_text("fixture-token")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"agent_name": "forge", "rooms": ["backlog"], "coordinators": ["relay"], "workspace": str(tmp_path), "wait_seconds": 1, "terminate_grace_seconds": 1, "completion_grace_seconds": 5, "startup_timeout_seconds": 30, "work_timeout_seconds": 30}))
    state = tmp_path / "state.json"
    env = {**os.environ, "HOME": str(home), "CODEX_HOME": str(home / ".codex"), "HTTP_PROXY": f"http://127.0.0.1:{coord.server.server_port}", "SAFEYOLO_COORD_TOKEN_PATH": str(token)}
    env.pop("SAFEYOLO_COORD_SOCKET", None)
    capture = tmp_path / "invocations"
    capture.mkdir()
    harness = tmp_path / "fake-codex"
    env["SAFEYOLO_CODEX_BIN"] = str(harness)
    env["SAFEYOLO_PI_BIN"] = str(harness)
    yield coord, env, config, state, harness, capture
    coord.close()


def harness_script(path, binary, capture, *, paused=False, terminal=True, pi=False):
    # Actual native send output is what the deterministic model seam emits as
    # an MCP receipt; ordinary model text cannot complete an attention object.
    source = f'''#!{sys.executable}
import json,os,sys,time,subprocess
from pathlib import Path
if "--version" in sys.argv or sys.argv[1:3]==["auth","check"]:
    print("fixture-harness");sys.exit(0)
prompt=sys.stdin.read()
root=Path({str(capture)!r})
(root/("prompt-"+str(os.getpid()))).write_text(prompt)
(root/("argv-"+str(os.getpid()))).write_text(json.dumps(sys.argv[1:]))
print(json.dumps({{"type": {"session" if pi else "thread.started"!r}, {"id" if pi else "thread_id"!r}:"fixture-thread"}}),flush=True)
print(json.dumps({{"type": {"agent_start" if pi else "turn.started"!r}}}),flush=True)
'''
    if paused:
        source += "time.sleep(30)\n"
    elif terminal:
        source += f'''
args={{"room_name":"backlog","body":{f'DONE target={TARGET} attention_id={ATTENTION}'!r},"notify":["relay"]}}
result=subprocess.run([{str(binary)!r},"call","send"],input=json.dumps(args),capture_output=True,text=True)
'''
        if pi:
            source += '''print(json.dumps({"type":"tool_execution_start","toolCallId":"send-1","toolName":"send","args":args}),flush=True)
if result.returncode==0:
    print(json.dumps({"type":"tool_execution_end","toolCallId":"send-1","toolName":"send","isError":False,"result":{"details":json.loads(result.stdout)}}),flush=True)
'''
        else:
            source += '''if result.returncode==0:
    print(json.dumps({"type":"item.completed","item":{"type":"mcp_tool_call","server":"safeyolo-coord","tool":"send","status":"completed","arguments":args,"result":{"structured_content":json.loads(result.stdout)}}}),flush=True)
'''
        source += '''else:
    print(result.stderr,file=sys.stderr)
'''
    source += f'print(json.dumps({{"type": {"agent_end" if pi else "turn.completed"!r}}}),flush=True)\n'
    path.write_text(source)
    path.chmod(0o755)


def run(binary, fixture, *args):
    _coord, env, config, state, _harness, _capture = fixture
    return subprocess.run([str(binary), "supervise", "--config", str(config), "--state", str(state), "--once", "--", *args], env=env, capture_output=True, text=True, timeout=12)


def until(predicate):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.025)
    pytest.fail("native boundary did not arrive within eight seconds")


def test_structured_wait_checkpoints_task_before_terminal(binary, fixture):
    coord, _env, _config, state, harness, capture = fixture
    harness.write_text("#!/bin/sh\nexit 0\n")
    harness.chmod(0o600)  # accepted attention, then executable launch fails
    result = run(binary, fixture)
    assert result.returncode != 0
    saved = json.loads(state.read_text())
    assert saved["phase"] == "accepted"
    assert saved["safe_cursor"] == 7
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert saved["in_flight"][0]["sequence"] == 42
    assert not list(capture.iterdir())
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    assert coord.sends == 1
    assert json.loads(state.read_text())["in_flight"] == []


def test_interrupted_turn_recovers_uncertain_checkpoint(binary, fixture):
    _coord, env, config, state, harness, capture = fixture
    harness_script(harness, binary, capture, paused=True)
    proc = subprocess.Popen([str(binary), "supervise", "--config", str(config), "--state", str(state), "--once"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    owned = None
    try:
        def started():
            if not state.exists():
                return None
            saved = json.loads(state.read_text())
            return saved if saved["phase"] == "running" else None
        saved = until(started)
        owned = saved["owned_process"]
        assert owned["token"].startswith("linux:")
        assert saved["in_flight"][0]["attention_id"] == ATTENTION
        proc.kill()  # seam (b): no terminal checkpoint, owned child still live
        proc.communicate(timeout=5)
        harness_script(harness, binary, capture)
        result = run(binary, fixture)
        assert result.returncode == 0, result.stderr
        prompts = [p.read_text() for p in capture.glob("prompt-*")]
        assert any('"recovery":"uncertain"' in p for p in prompts)
        assert len(prompts) == 2
        assert json.loads(state.read_text())["in_flight"] == []
        # Recovery terminated the exact recorded invocation, with no PID-name
        # matching or signal to the replacement model turn.
        stat = Path(f'/proc/{owned["pid"]}/stat')
        assert not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=5)
        if owned and Path(f'/proc/{owned["pid"]}/stat').exists():
            # Cleanup only our recorded test child if its birth token matches.
            text = Path(f'/proc/{owned["pid"]}/stat').read_text()
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            token = f'linux:{boot}:{owned["pid"]}:{text.rsplit(")", 1)[1].split()[19]}'
            if token == owned["token"]:
                os.kill(owned["pid"], signal.SIGKILL)


def test_terminal_checkpoint_is_not_dispatched_after_restart(binary, fixture):
    coord, _env, _config, state, harness, capture = fixture
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == [] and ATTENTION in saved["recent_attention_ids"]
    assert run(binary, fixture).returncode == 0
    assert len(list(capture.glob("prompt-*"))) == 1
    assert coord.sends == 1


def test_model_narration_and_process_success_do_not_complete_work(binary, fixture):
    _coord, _env, _config, state, harness, capture = fixture
    harness_script(harness, binary, capture, terminal=False)
    assert run(binary, fixture).returncode != 0
    saved = json.loads(state.read_text())
    assert saved["phase"] == "uncertain"
    assert saved["in_flight"][0]["attention_id"] == ATTENTION


def test_canonical_history_recovers_terminal_lost_after_send(binary, fixture):
    coord, _env, _config, state, harness, capture = fixture
    coord.unknown_send = True
    harness_script(harness, binary, capture)
    result = run(binary, fixture)
    assert result.returncode == 0, result.stderr
    assert "send outcome unknown" in result.stderr
    assert coord.sends == 1
    assert json.loads(state.read_text())["in_flight"] == []
    assert run(binary, fixture).returncode == 0
    assert coord.sends == 1


def test_pi_events_use_the_same_terminal_checkpoint_contract(binary, fixture):
    coord, _env, config, state, harness, capture = fixture
    settings = json.loads(config.read_text())
    settings["harness"] = "pi"
    config.write_text(json.dumps(settings))
    harness_script(harness, binary, capture, pi=True)
    result = run(binary, fixture, "--provider", "fixture", "--model", "fixture")
    assert result.returncode == 0, result.stderr
    assert coord.sends == 1
    assert json.loads(state.read_text())["harness"] == "pi"
    assert json.loads(state.read_text())["in_flight"] == []


def test_failed_page_resolution_does_not_advance_cursor(binary, fixture):
    coord, _env, _config, state, harness, capture = fixture
    coord.bad_object = True
    harness_script(harness, binary, capture)
    result = run(binary, fixture)
    assert result.returncode != 0
    assert json.loads(state.read_text())["safe_cursor"] == 0
    assert not list(capture.iterdir())


def test_empty_external_wait_does_not_launch_codex(binary, fixture):
    coord, _env, _config, _state, harness, capture = fixture
    coord.page = {"edges": [], "next_cursor": 0}
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    assert not list(capture.iterdir())


def factory_configuration(config):
    value = json.loads(config.read_text())
    value["factory"] = {
        "schema": "safeyolo.factory/v1", "name": "backlog", "role": "owner",
        "roles": {"coordinator": "relay", "owner": "forge", "reviewer": "lens"},
        "operator_input": {"to": "coordinator", "types": ["DIRECTION"]},
        "contract_sha256": "a" * 64, "snapshot_id": "b" * 64,
        "handoffs": [
            {"request": "TASK", "from": "coordinator", "to": "owner", "responses": ["DONE", "BLOCKED", "FAILED"], "response_to": ["coordinator"]},
            {"request": "REVIEW_READY", "from": "owner", "to": "reviewer", "responses": ["READY", "CHANGES_REQUIRED", "BLOCKED"], "response_to": ["owner", "coordinator"]},
        ], "updates": [{"type": "CONTEXT", "from": "coordinator", "to": "owner", "fields": ["target"]}],
    }
    config.write_text(json.dumps(value))


def prompt_checkpoint(capture):
    return json.loads(next(capture.glob("prompt-*" )).read_text().split("Supervisor checkpoint:\n", 1)[1])


@pytest.mark.parametrize("sender,body", [("mallory", TASK), ("relay", TASK.replace("assignee=forge", "assignee=lens")), ("relay", "TASK task=818 assignee=forge")])
def test_factory_rejects_unauthorized_or_malformed_objects(binary, fixture, sender, body):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    coord.objects[ATTENTION] = {"edge": EDGE, "object": {**OBJECT, "sender_agent_name": sender, "body": body}}
    harness_script(harness, binary, capture, terminal=False)
    assert run(binary, fixture).returncode == 0
    received = prompt_checkpoint(capture)["in_flight"][0]
    assert received["requires_terminal"] is False
    assert received["protocol_warning"]
    assert json.loads(state.read_text())["in_flight"] == []


def test_factory_rejects_an_other_room_even_for_an_exact_handoff(binary, fixture):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    edge = {**EDGE, "room_id": "rm-unconfigured"}
    coord.page["edges"] = [edge]
    coord.objects[ATTENTION] = {"edge": edge, "object": {**OBJECT, "room_id": "rm-unconfigured"}}
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    assert not list(capture.iterdir())
    assert json.loads(state.read_text())["safe_cursor"] == 7


def awaiting_review():
    target = "https://example.test/pull/818/commits/" + "a" * 40
    return {"room_name": "backlog", "request": "REVIEW_READY", "recipient_agent": "lens", "body": f"REVIEW_READY target={target}", "correlation": {"target": target}}


def prepare_response(binary, fixture, kind, target):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    saved = json.loads(subprocess.check_output([str(binary), "read-state", str(state)]))
    saved["in_flight"] = [{"attention_id": ATTENTION, "room_name": "backlog", "sender_agent_name": "relay", "sender_agent_id": "ag-relay", "sequence": 42, "body": TASK, "requires_terminal": True}]
    saved["awaiting_handoffs"] = [awaiting_review()]
    saved["phase"] = "accepted"
    subprocess.run([str(binary), "write-state", str(state)], input=json.dumps(saved), text=True, check=True)
    response_id = "attn-" + "b" * 32
    edge = {**EDGE, "attention_id": response_id, "object_id": "msg-review", "revision_or_sequence": 49}
    coord.page = {"edges": [edge], "next_cursor": 8}
    coord.objects[response_id] = {"edge": edge, "object": {**OBJECT, "msg_id": "msg-review", "sequence": 49, "sender_agent_name": "lens", "sender_agent_id": "ag-lens", "body": f"{kind} target={target} attention_id={response_id}"}}
    harness_script(harness, binary, capture, terminal=False)
    return state, capture


def test_factory_rejects_a_response_for_a_different_review_object(binary, fixture):
    state, capture = prepare_response(binary, fixture, "READY", "https://example.test/other")
    run(binary, fixture)
    assert json.loads(state.read_text())["awaiting_handoffs"] == [awaiting_review()]
    assert prompt_checkpoint(capture)["in_flight"][-1]["protocol_warning"]


@pytest.mark.parametrize("kind", ["READY", "CHANGES_REQUIRED", "BLOCKED"])
def test_factory_admits_every_reviewer_to_owner_response(binary, fixture, kind):
    state, capture = prepare_response(binary, fixture, kind, awaiting_review()["correlation"]["target"])
    run(binary, fixture)
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == []
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    response = prompt_checkpoint(capture)["in_flight"][-1]
    assert "protocol_warning" not in response
    assert response["requires_terminal"] is False


def test_factory_handoff_survives_restart_then_terminal_is_deduplicated(binary, fixture):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    review = awaiting_review()
    harness_script(harness, binary, capture)
    source = harness.read_text().replace(f"DONE target={TARGET} attention_id={ATTENTION}", review["body"]).replace('"notify":["relay"]', '"notify":["lens"]')
    harness.write_text(source)
    assert run(binary, fixture).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == [review]
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert saved["thread_id"] == "fixture-thread"
    response_id = "attn-" + "b" * 32
    edge = {**EDGE, "attention_id": response_id, "object_id": "msg-review", "revision_or_sequence": 49}
    coord.page = {"edges": [edge], "next_cursor": 8}
    coord.objects[response_id] = {"edge": edge, "object": {**OBJECT, "msg_id": "msg-review", "sequence": 49, "sender_agent_name": "lens", "sender_agent_id": "ag-lens", "body": f'READY target={review["correlation"]["target"]} attention_id={response_id}'}}
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == []
    assert saved["awaiting_handoffs"] == []
    assert ATTENTION in saved["recent_attention_ids"]
    assert any("resume" in json.loads(path.read_text()) for path in capture.glob("argv-*"))
    count = len(list(capture.glob("prompt-*")))
    coord.page = {"edges": [EDGE], "next_cursor": 8}
    assert run(binary, fixture).returncode == 0
    assert len(list(capture.glob("prompt-*"))) == count == 2
    assert coord.sends == 2


def test_factory_concurrent_handoffs_are_checkpointed_together(binary, fixture):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    value = json.loads(config.read_text())
    value["agent_name"] = "relay"
    value["factory"]["role"] = "coordinator"
    value["factory"]["handoffs"].append({"request": "TASK", "from": "coordinator", "to": "reviewer", "responses": ["DONE", "BLOCKED", "FAILED"], "response_to": ["coordinator"]})
    config.write_text(json.dumps(value))
    coord.agent_name = "relay"
    coord.objects[ATTENTION] = {"edge": EDGE, "object": {**OBJECT, "sender_kind": "operator", "sender_agent_name": None, "sender_agent_id": None, "body": "Check implementation and security independently."}}
    harness_script(harness, binary, capture, terminal=False)
    source = harness.read_text()
    completed = 'print(json.dumps({"type": \'turn.completed\'}),flush=True)'
    sends = ''
    for agent in ["forge", "lens"]:
        args = {"room_name": "backlog", "body": f"TASK target=https://example.test/{agent} assignee={agent}", "notify": [agent]}
        sends += f'''\nargs={args!r}\nresult=subprocess.run([{str(binary)!r},"call","send"],input=json.dumps(args),capture_output=True,text=True,check=True)\nprint(json.dumps({{"type":"item.completed","item":{{"type":"mcp_tool_call","server":"safeyolo-coord","tool":"send","status":"completed","arguments":args,"result":{{"structured_content":json.loads(result.stdout)}}}}}}),flush=True)\n'''
    harness.write_text(source.replace(completed, sends + '\n' + completed))
    assert run(binary, fixture).returncode == 0
    saved = json.loads(subprocess.check_output([str(binary), "read-state", str(state)]))
    assert saved["in_flight"] == []
    assert {item["recipient_agent"] for item in saved["awaiting_handoffs"]} == {"forge", "lens"}
    assert saved["thread_id"] == "fixture-thread"
    assert coord.sends == 2
