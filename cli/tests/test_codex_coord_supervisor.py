"""Existing supervised checkpoint seams, exercised through the native command.

The HTTP and model event fixtures are deterministic transport seams. They do
not claim a real model login or a deployed G2/G4 result.
"""
from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
ATTENTION = "attn-" + "a" * 32
REQUEST_ATTENTION = f"attn-{16:032x}"
TARGET = "https://example.test/issues/818"
TASK = f"TASK target={TARGET} assignee=forge\n\nDeliver the assigned work."
EDGE = {"attention_id": ATTENTION, "room_id": "rm-backlog", "kind": "message", "object_id": "msg-task", "revision_or_sequence": 42, "membership_granted_at": 1}
OBJECT = {"msg_id": "msg-task", "sequence": 42, "room_id": "rm-backlog", "sender_kind": "agent", "sender_agent_id": "ag-relay", "sender_agent_name": "relay", "body": TASK}


@pytest.fixture
def binary():
    path = Path(os.environ.get("SAFEYOLO_COORD_TEST_BINARY", ROOT / "proxy/target/release/safeyolo-coord"))
    assert path.is_file(), "Build safeyolo-coord before running the native supervisor tests"
    return path


class CoordFixture:
    def __init__(self):
        self.messages = []
        self.sends = 0
        self.requests = []
        self.agent_name = "forge"
        self.unknown_send = False
        self.include_attention_recipients = True
        self.page = {"edges": [EDGE], "next_cursor": 7}
        self.backlog = None
        self.bad_object = False
        self.objects = {ATTENTION: {"edge": EDGE, "object": OBJECT}}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.requests.append(("GET", self.path))
                path = urlsplit(self.path).path
                if path == "/health":
                    result = {"agent_api": "ok"}
                elif path == "/api/coord/attention/wait":
                    if owner.backlog is None:
                        result = owner.page
                    else:
                        query = parse_qs(urlsplit(self.path).query)
                        since, limit = int(query["since"][0]), int(query["limit"][0])
                        pending = [(cursor, edge) for cursor, edge in owner.backlog if cursor > since][:limit]
                        result = {"edges": [edge for _, edge in pending],
                                  "next_cursor": pending[-1][0] if pending else since}
                elif path.startswith("/api/coord/attention/") and path.endswith("/object"):
                    if owner.bad_object:
                        return self.reply(403, {"error": "membership revoked"})
                    result = owner.objects[path.split("/")[-2]]
                elif path.endswith("/messages"):
                    result = {"messages": owner.messages, "next_cursor": 50, "has_more": False}
                elif path.endswith("/state"):
                    result = {"members": [{"agent_id": "ag-" + name, "display_name": name} for name in ("relay", "forge", "lens")]}
                else:
                    return self.reply(404, {"error": "missing fixture route"})
                self.reply(200, result)

            def do_POST(self):
                owner.requests.append(("POST", self.path))
                args = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                path = urlsplit(self.path).path
                if path.endswith("/join"):
                    return self.reply(200, {"room_id": "rm-backlog", "permissions": ["send", "receive"], "brief": {"revision": 0}})
                if path.endswith("/send"):
                    owner.sends += 1
                    envelope = {"body": args["body"], "msg_id": f"msg-{owner.sends}", "sender_kind": "agent", "sender_agent_name": owner.agent_name, "sender_agent_id": "ag-" + owner.agent_name, "sequence": 43 + owner.sends}
                    notify = args["notify"]
                    if isinstance(notify, list) and notify:
                        intent = {"mode": "targeted", "agent_ids": ["ag-" + name for name in dict.fromkeys(notify)]}
                    elif notify == "room":
                        intent = {"mode": "room", "agent_ids": ["ag-relay", "ag-lens"]}
                    else:
                        intent = {"mode": "none", "agent_ids": []}
                    owner.messages.append({**envelope, "attention_intent": intent})
                    if owner.unknown_send:
                        return self.reply(503, {"error": "receipt unavailable", "send_outcome": "unknown"})
                    receipt = {"envelope": envelope, "sequence": envelope["sequence"], "attention_intent": {"mode": intent["mode"]}, "attention_status": "ready"}
                    if owner.include_attention_recipients:
                        receipt["attention_recipients"] = [{"agent_id": agent_id, "attention_id": f"attn-{owner.sends * 16 + index:032x}"} for index, agent_id in enumerate(intent["agent_ids"])]
                    return self.reply(200, receipt)
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
def fixture(request):
    if sys.platform != "linux":
        pytest.skip("Model-turn execution belongs to the Linux guest, including VZ guests")
    return request.getfixturevalue("coord_fixture")


@pytest.fixture
def coord_fixture(tmp_path, binary):
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


@pytest.mark.skipif(sys.platform != "darwin", reason="native Mac host refusal")
def test_host_supervision_refusal_does_not_launch_a_model_or_send_a_terminal(binary, coord_fixture):
    coord, _env, _config, _state, harness, capture = coord_fixture
    harness_script(harness, binary, capture)
    result = run(binary, coord_fixture)
    assert result.returncode != 0
    assert "model-turn supervision runs inside a Linux guest" in result.stderr
    assert coord.sends == 0
    assert not list(capture.iterdir())


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


def run(binary, fixture, *args, confirm_fresh_identity=True):
    _coord, env, config, state, _harness, _capture = fixture
    confirmation = ["--confirm-fresh-identity"] if confirm_fresh_identity else []
    return subprocess.run([str(binary), "supervise", "--config", str(config), "--state", str(state), "--once", *confirmation, "--", *args], env=env, capture_output=True, text=True, timeout=12)


@pytest.mark.parametrize("harness_name", ["codex", "pi"])
@pytest.mark.parametrize("factory", [False, True])
def test_missing_checkpoint_refuses_before_coord_model_or_save_on_every_retry(binary, fixture, harness_name, factory):
    coord, _env, config, state, harness, capture = fixture
    if factory:
        factory_configuration(config)
    settings = json.loads(config.read_text())
    settings["harness"] = harness_name
    config.write_text(json.dumps(settings))
    # Even a version or login probe would leave a marker at the model seam.
    harness.write_text(f"#!/bin/sh\ntouch '{capture}/unexpected-model'\nexit 1\n")
    harness.chmod(0o755)
    for _ in range(2):
        result = run(binary, fixture, confirm_fresh_identity=False)
        assert result.returncode != 0
        assert "--confirm-fresh-identity" in result.stderr
        assert "Clearing room messages does not reset attention" in result.stderr
        assert not state.exists()
        assert coord.requests == []
        assert not list(capture.iterdir())


@pytest.mark.parametrize("harness_name", ["codex", "pi"])
def test_confirmed_first_start_uses_cursor_zero_and_existing_state_needs_no_confirmation(binary, fixture, harness_name):
    coord, _env, config, state, harness, capture = fixture
    settings = json.loads(config.read_text())
    settings["harness"] = harness_name
    config.write_text(json.dumps(settings))
    harness_script(harness, binary, capture, pi=harness_name == "pi")
    args = ["--provider", "fixture", "--model", "fixture"] if harness_name == "pi" else []
    result = run(binary, fixture, *args)
    assert result.returncode == 0, result.stderr
    waits = [parse_qs(urlsplit(path).query)["since"] for _, path in coord.requests
             if urlsplit(path).path == "/api/coord/attention/wait"]
    assert waits == [["0"]]
    saved = json.loads(state.read_text())
    assert saved["safe_cursor"] == 7
    assert saved["harness"] == harness_name
    assert coord.sends == 1
    result = run(binary, fixture, *args, confirm_fresh_identity=False)
    assert result.returncode == 0, result.stderr
    # Ordinary idle restart retires a completed session; retained attention
    # and all other checkpoint state stay intact.
    assert json.loads(state.read_text()) == {**saved, "thread_id": None}
    assert len(list(capture.glob("prompt-*"))) == 1
    assert coord.sends == 1


@pytest.mark.parametrize("confirmed", [False, True])
def test_invalid_checkpoint_is_not_reinitialized_by_confirmation(binary, fixture, confirmed):
    coord, _env, _config, state, harness, capture = fixture
    invalid = json.loads(subprocess.check_output([str(binary), "read-state", str(state)]))
    invalid["schema"] = "unsupported"
    state.write_text(json.dumps(invalid))
    saved = state.read_bytes()
    harness_script(harness, binary, capture)
    result = run(binary, fixture, confirm_fresh_identity=confirmed)
    assert result.returncode != 0
    assert "invalid Coord checkpoint" in result.stderr
    assert state.read_bytes() == saved
    assert coord.requests == []
    assert not list(capture.iterdir())


@pytest.mark.parametrize("harness_name", ["codex", "pi"])
def test_staged_launcher_carries_confirmation_without_forwarding_it_to_the_model(binary, fixture, harness_name):
    coord, env, config, state, harness, capture = fixture
    home = Path(env["HOME"])
    directory = home / ".safeyolo"
    directory.mkdir()
    (directory / "safeyolo-coord").symlink_to(binary)
    config.rename(directory / "coord-supervisor.json")
    settings = json.loads((directory / "coord-supervisor.json").read_text())
    settings["harness"] = harness_name
    (directory / "coord-supervisor.json").write_text(json.dumps(settings))
    state = directory / "coord-supervisor-state.json"
    harness_script(harness, binary, capture, pi=harness_name == "pi")
    launcher = home / ".safeyolo-command"
    # Stage the same foreground anchors used by the ordinary host setups.
    source = ('supervised_args=()\nargs=()\nexec codex "${args[@]}" "$@"\n'
              if harness_name == "codex" else
              f'args=(--provider fixture --model fixture)\npi_bin={str(harness)!r}\nexec "$pi_bin" "${{args[@]}}" "$@"\n')
    launcher.write_text("#!/usr/bin/env bash\nset -e\n" + source)
    launcher.chmod(0o755)
    subprocess.run([str(binary), "supervised-launcher", str(launcher), harness_name], check=True, capture_output=True)
    refused = subprocess.run([str(launcher)], env=env, capture_output=True, text=True, timeout=5)
    assert refused.returncode != 0 and "--confirm-fresh-identity" in refused.stderr
    assert not state.exists() and coord.requests == [] and not list(capture.iterdir())
    process = subprocess.Popen([str(launcher), "--confirm-fresh-identity", "--model", "fixture"],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        until(lambda: state.exists() and ATTENTION in json.loads(state.read_text())["recent_attention_ids"])
        prompt = prompt_checkpoint(capture)
        assert prompt["in_flight"][0]["attention_id"] == ATTENTION
        arguments = json.loads(next(capture.glob("argv-*")).read_text())
        assert "--confirm-fresh-identity" not in arguments
        assert "--model" in arguments and "fixture" in arguments
        assert coord.sends == 1
    finally:
        process.terminate()
        process.communicate(timeout=5)


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
    proc = subprocess.Popen([str(binary), "supervise", "--config", str(config), "--state", str(state), "--once", "--confirm-fresh-identity"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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


def live_process_token(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return None
    if fields[0] == "Z":
        return None
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return f"linux:{boot}:{pid}:{fields[19]}"


@pytest.mark.parametrize("close_stdio", [False, True])
def test_fast_leader_exit_cleans_an_escaped_child_and_preserves_an_unrelated_process(binary, fixture, close_stdio):
    _coord, _env, _config, state, harness, capture = fixture
    harness_script(harness, binary, capture, terminal=False)
    marker = capture / "escaped-child.json"
    child = f'''
if os.fork() == 0:
    os.setsid()
    pid = os.getpid()
    fields = Path(f"/proc/{{pid}}/stat").read_text().rsplit(")", 1)[1].split()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    Path({str(marker)!r}).write_text(json.dumps({{"pid":pid,"token":f"linux:{{boot}}:{{pid}}:{{fields[19]}}"}}))
    if {close_stdio!r}:
        os.close(1)
        os.close(2)
    time.sleep(60)
    os._exit(0)
while not Path({str(marker)!r}).exists():
    time.sleep(.001)
'''
    completed = 'print(json.dumps({"type": \'turn.completed\''
    harness.write_text(harness.read_text().replace(completed, child + "\n" + completed))
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        result = run(binary, fixture)
        assert result.returncode != 0, result.stderr  # The task has no terminal response.
        assert marker.is_file(), result.stderr
        escaped = json.loads(marker.read_text())
        assert live_process_token(escaped["pid"]) != escaped["token"]
        assert unrelated.poll() is None
        saved = json.loads(state.read_text())
        assert saved["owned_process"] is None
        assert saved["phase"] == "uncertain"
        assert saved["in_flight"][0]["attention_id"] == ATTENTION
    finally:
        if marker.is_file():
            escaped = json.loads(marker.read_text())
            if live_process_token(escaped["pid"]) == escaped["token"]:
                os.kill(escaped["pid"], signal.SIGKILL)
                until(lambda: live_process_token(escaped["pid"]) != escaped["token"])
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_supervisor_preserves_non_utf8_path_operands_and_harness_arguments(binary, fixture):
    coord, _env, config, state, harness, capture = fixture
    new_config = config.with_name(os.fsdecode(b"config-\x80.json"))
    new_state = state.with_name(os.fsdecode(b"state-\xff.json"))
    config.rename(new_config)
    fixture = (coord, _env, new_config, new_state, harness, capture)
    harness_script(harness, binary, capture)
    raw_argument = b"path-\x80\xff"
    result = run(binary, fixture, raw_argument)
    assert result.returncode == 0, result.stderr
    assert json.loads(new_state.read_text())["in_flight"] == []
    args = json.loads(next(capture.glob("argv-*")).read_text())
    assert os.fsencode(args[0]) == raw_argument


@pytest.mark.parametrize("component", [b"ascii", b"\x80", b"\xff"])
def test_checkpoint_lock_preserves_filename_bytes_and_same_checkpoint_exclusion(binary, fixture, component):
    coord, env, config, state, harness, capture = fixture
    state = state.with_name(os.fsdecode(b"checkpoint-" + component + b".json"))
    fixture = (coord, env, config, state, harness, capture)
    unrelated = state.with_name("checkpoint-\N{REPLACEMENT CHARACTER}.json.lock")
    selected_lock = state.with_name(state.name + ".lock")
    harness_script(harness, binary, capture)
    with unrelated.open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(binary, fixture)
        assert result.returncode == 0, result.stderr
        assert json.loads(state.read_text())["in_flight"] == []
        assert coord.sends == 1
        assert len(list(capture.glob("prompt-*"))) == 1
        assert selected_lock.is_file()
        assert selected_lock.stat().st_mode & 0o777 == 0o600

    saved = state.read_bytes()
    with selected_lock.open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(binary, fixture)
        assert result.returncode != 0
        assert "another supervisor owns this checkpoint" in result.stderr
        assert state.read_bytes() == saved
        assert coord.sends == 1
        assert len(list(capture.glob("prompt-*"))) == 1


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


@pytest.mark.parametrize("role", ["owner", "reviewer"])
def test_canonical_history_recovers_terminal_lost_after_send(binary, fixture, role):
    coord, _env, config, state, harness, capture = fixture
    factory_configuration(config)
    if role == "reviewer":
        settings = json.loads(config.read_text())
        settings["agent_name"] = "lens"
        settings["factory"]["role"] = role
        config.write_text(json.dumps(settings))
        coord.agent_name = "lens"
        coord.objects[ATTENTION]["object"] = {
            **OBJECT, "sender_agent_name": "forge", "sender_agent_id": "ag-forge",
            "body": awaiting_review()["body"],
        }
    coord.unknown_send = True
    harness_script(harness, binary, capture)
    if role == "reviewer":
        target = awaiting_review()["correlation"]["target"]
        harness.write_text(harness.read_text()
                           .replace(f"DONE target={TARGET} attention_id={ATTENTION}", f"READY target={target} attention_id={ATTENTION}")
                           .replace('"notify":["relay"]', '"notify":["relay","forge"]'))
    result = run(binary, fixture)
    assert result.returncode == 0, result.stderr
    assert "send outcome unknown" in result.stderr
    assert coord.sends == 1
    assert json.loads(state.read_text())["in_flight"] == []
    assert run(binary, fixture).returncode == 0
    assert coord.sends == 1


@pytest.mark.parametrize("unknown_send", [False, True])
@pytest.mark.parametrize("notify", [["lens"], "none", "room", [], ["relay", "lens"]])
def test_factory_history_does_not_complete_a_terminal_on_the_wrong_route(binary, fixture, notify, unknown_send):
    coord, _env, config, state, harness, capture = fixture
    factory_configuration(config)
    coord.unknown_send = unknown_send
    harness_script(harness, binary, capture)
    harness.write_text(harness.read_text().replace('"notify":["relay"]', f'"notify":{notify!r}'))
    result = run(binary, fixture)
    assert result.returncode != 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["phase"] == "uncertain"
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert ATTENTION not in saved["recent_attention_ids"]
    assert coord.sends == 1
    assert len(list(capture.glob("prompt-*"))) == 1
    coord.page = {"edges": [], "next_cursor": 7}
    harness_script(harness, binary, capture, terminal=False)
    assert run(binary, fixture).returncode != 0
    assert coord.sends == 1  # Recovery does not replay the uncertain send.
    assert json.loads(state.read_text())["in_flight"][0]["attention_id"] == ATTENTION
    assert len(list(capture.glob("prompt-*"))) == 2


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
    return {"room_name": "backlog", "request": "REVIEW_READY", "recipient_agent": "lens", "body": f"REVIEW_READY target={target}", "correlation": {"target": target}, "request_attention_id": REQUEST_ATTENTION}


def response_page(coord, kind, target, request_attention_id, *, sequence=49, sender="lens"):
    response_id = f"attn-{sequence:032x}"
    edge = {**EDGE, "attention_id": response_id, "object_id": f"msg-response-{sequence}", "revision_or_sequence": sequence}
    coord.page = {"edges": [edge], "next_cursor": sequence}
    coord.objects[response_id] = {"edge": edge, "object": {**OBJECT, "msg_id": edge["object_id"], "sequence": sequence, "sender_agent_name": sender, "sender_agent_id": "ag-" + sender, "body": f"{kind} target={target} attention_id={request_attention_id}"}}


def prepare_response(binary, fixture, kind, target):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    saved = json.loads(subprocess.check_output([str(binary), "read-state", str(state)]))
    saved["in_flight"] = [{"attention_id": ATTENTION, "room_name": "backlog", "sender_agent_name": "relay", "sender_agent_id": "ag-relay", "sequence": 42, "body": TASK, "requires_terminal": True}]
    saved["awaiting_handoffs"] = [awaiting_review()]
    saved["phase"] = "accepted"
    subprocess.run([str(binary), "write-state", str(state)], input=json.dumps(saved), text=True, check=True)
    response_page(coord, kind, target, REQUEST_ATTENTION)
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


@pytest.mark.parametrize("request_kind", ["TASK", "REVIEW_READY"])
@pytest.mark.parametrize("pi", [False, True])
def test_factory_old_response_cannot_consume_new_same_target_request(binary, fixture, request_kind, pi):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    settings = json.loads(config.read_text())
    if request_kind == "TASK":
        settings["agent_name"] = "relay"
        settings["factory"]["role"] = "coordinator"
        coord.agent_name = "relay"
        coord.objects[ATTENTION]["object"] = {**OBJECT, "sender_kind": "operator", "sender_agent_name": None, "sender_agent_id": None, "body": "Deliver the bounded fix."}
    if pi:
        settings["harness"] = "pi"
    harness_args = ["--provider", "fixture", "--model", "fixture"] if pi else []
    config.write_text(json.dumps(settings))
    target = TARGET if request_kind == "TASK" else awaiting_review()["correlation"]["target"]
    recipient = "forge" if request_kind == "TASK" else "lens"
    kind = "DONE" if request_kind == "TASK" else "READY"
    body = TASK if request_kind == "TASK" else awaiting_review()["body"]
    harness_script(harness, binary, capture, pi=pi)
    harness.write_text(harness.read_text().replace(repr(f"DONE target={TARGET} attention_id={ATTENTION}"), repr(body)).replace('"notify":["relay"]', f'"notify":["{recipient}"]'))
    result = run(binary, fixture, *harness_args)
    assert result.returncode == 0, result.stderr
    old_request = json.loads(state.read_text())["awaiting_handoffs"][0]
    assert old_request["request_attention_id"] == REQUEST_ATTENTION

    # The first request completes; the same turn sends a new request with the
    # same room, worker, target and response kind, but a different receipt ID.
    response_page(coord, kind, target, old_request["request_attention_id"], sender=recipient)
    result = run(binary, fixture, *harness_args)
    assert result.returncode == 0, result.stderr
    new_request = json.loads(state.read_text())["awaiting_handoffs"][0]
    assert new_request["request_attention_id"] == f"attn-{32:032x}"
    assert new_request["correlation"] == old_request["correlation"]
    assert coord.sends == 2

    # A new attention edge carries the duplicated old reply after restart.
    # It cannot consume the newer request or release its suspended parent.
    response_page(coord, kind, target, old_request["request_attention_id"], sequence=50, sender=recipient)
    harness_script(harness, binary, capture, terminal=False, pi=pi)
    result = run(binary, fixture, *harness_args)
    # Consuming the stale reply makes progress without settling the TASK or
    # its newer handoff.
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == [new_request]
    if request_kind == "REVIEW_READY":
        assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert len([m for m in coord.messages if not m["body"].startswith("PROTOCOL_WARNING ")]) == 2

    response_page(coord, kind, target, new_request["request_attention_id"], sequence=51, sender=recipient)
    harness_script(harness, binary, capture, terminal=request_kind == "REVIEW_READY", pi=pi)
    result = run(binary, fixture, *harness_args)
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == []
    assert saved["in_flight"] == []
    assert len([m for m in coord.messages if not m["body"].startswith("PROTOCOL_WARNING ")]) == (3 if request_kind == "REVIEW_READY" else 2)


def test_factory_legacy_handoff_cannot_consume_a_reply_or_hide_a_new_request(binary, fixture):
    coord, _, _, state, harness, capture = fixture
    review = awaiting_review()
    prepare_response(binary, fixture, "READY", review["correlation"]["target"])
    saved = json.loads(state.read_text())
    legacy = saved["awaiting_handoffs"][0]
    del legacy["request_attention_id"]
    legacy["parent_attention_id"] = ATTENTION
    state.write_text(json.dumps(saved))  # A checkpoint from before this repair.
    harness_script(harness, binary, capture)
    harness.write_text(harness.read_text().replace(f"DONE target={TARGET} attention_id={ATTENTION}", review["body"]).replace('"notify":["relay"]', '"notify":["lens"]'))
    result = run(binary, fixture)
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    review["request_attention_id"] = f"attn-{32:032x}"
    assert saved["awaiting_handoffs"] == [legacy, review]
    assert saved["in_flight"][0]["attention_id"] == ATTENTION

    response_page(coord, "READY", review["correlation"]["target"], review["request_attention_id"], sequence=50)
    harness_script(harness, binary, capture, terminal=False)
    result = run(binary, fixture)
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == [legacy]
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert len([m for m in coord.messages if m["body"].startswith("REVIEW_READY ")]) == 1


def test_factory_receipt_without_request_identity_stays_pending_after_restart(binary, fixture):
    coord, _, config, state, harness, capture = fixture
    factory_configuration(config)
    coord.include_attention_recipients = False
    review = awaiting_review()
    harness_script(harness, binary, capture)
    harness.write_text(harness.read_text().replace(f"DONE target={TARGET} attention_id={ATTENTION}", review["body"]).replace('"notify":["relay"]', '"notify":["lens"]'))
    assert run(binary, fixture).returncode == 0
    saved = json.loads(state.read_text())
    assert "request_attention_id" not in saved["awaiting_handoffs"][0]
    pending = saved["awaiting_handoffs"]
    response_page(coord, "READY", review["correlation"]["target"], REQUEST_ATTENTION)
    harness_script(harness, binary, capture, terminal=False)
    result = run(binary, fixture)
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["awaiting_handoffs"] == pending
    assert saved["in_flight"][0]["attention_id"] == ATTENTION
    assert len([m for m in coord.messages if m["body"].startswith("REVIEW_READY ")]) == 1


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
    response_page(coord, "READY", review["correlation"]["target"], REQUEST_ATTENTION)
    harness_script(harness, binary, capture)
    assert run(binary, fixture).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == []
    assert saved["awaiting_handoffs"] == []
    assert ATTENTION in saved["recent_attention_ids"]
    assert any("resume" in json.loads(path.read_text()) for path in capture.glob("argv-*"))
    count = len(list(capture.glob("prompt-*")))
    coord.page = {"edges": [EDGE], "next_cursor": 49}
    assert run(binary, fixture).returncode == 0
    assert len(list(capture.glob("prompt-*"))) == count == 2
    assert coord.sends == 2


def retained_tasks(binary, fixture, count):
    coord, _, _, state, harness, capture = fixture
    review = awaiting_review()
    prepare_response(binary, fixture, "READY", review["correlation"]["target"])
    saved = json.loads(state.read_text())
    task = saved["in_flight"][0]
    saved["in_flight"] += [{**task, "attention_id": f"attn-{1000 + i:032x}",
                            "sequence": 100 + i} for i in range(count - 1)]
    saved["safe_cursor"] = 7
    saved["phase"] = "accepted"
    subprocess.run([str(binary), "write-state", str(state)], input=json.dumps(saved), text=True, check=True)
    harness_script(harness, binary, capture, terminal=False)
    return coord, state, harness, capture, saved


def capacity_harness(harness, binary, *, recover_history=False):
    # The full-checkpoint continuation uses the existing canonical history
    # recovery path. It does not receive or acknowledge new attention.
    source = harness.read_text()
    action = f'''
checkpoint=json.loads(prompt.split("Supervisor checkpoint:\\n",1)[1])
objects=checkpoint["in_flight"]
if {recover_history!r}:
    args={{"room_name":"backlog","since_sequence":42,"limit":100}}
    result=subprocess.run([{str(binary)!r},"call","read_room"],input=json.dumps(args),capture_output=True,text=True,check=True)
    objects=json.loads(result.stdout)["messages"]
ready=any(p.get("sender_agent_name")=="lens" and p["body"]=={f'READY target={awaiting_review()["correlation"]["target"]} attention_id={REQUEST_ATTENTION}'!r} for p in objects)
if ready:
    for task in checkpoint["in_flight"]:
        if not task["requires_terminal"]: continue
        args={{"room_name":"backlog","body":f"DONE target={TARGET} attention_id={{task['attention_id']}}","notify":["relay"]}}
        result=subprocess.run([{str(binary)!r},"call","send"],input=json.dumps(args),capture_output=True,text=True,check=True)
        print(json.dumps({{"type":"item.completed","item":{{"type":"mcp_tool_call","server":"safeyolo-coord","tool":"send","status":"completed","arguments":args,"result":{{"structured_content":json.loads(result.stdout)}}}}}}),flush=True)
'''
    completed = 'print(json.dumps({"type": \'turn.completed\'}),flush=True)'
    assert completed in source
    harness.write_text(source.replace(completed, action + "\n" + completed))


@pytest.mark.parametrize("count,page_limit", [(1, 16), (14, 16), (15, 16), (1, 1), (1, 8), (13, 2)])
def test_retained_tasks_admit_backlog_within_free_capacity(binary, fixture, count, page_limit):
    coord, state, harness, capture, original = retained_tasks(binary, fixture, count)
    config = fixture[2]
    settings = json.loads(config.read_text())
    settings["page_limit"] = page_limit
    config.write_text(json.dumps(settings))
    capacity_harness(harness, binary)
    ready = coord.page["edges"][0]
    # Sixteen new objects reproduce the real page16 failure, with ordinary
    # informational updates before READY.
    edges = []
    for i in range(15):
        sequence = 200 + i
        edge = {**EDGE, "attention_id": f"attn-{sequence:032x}",
                "object_id": f"msg-info-{i}", "revision_or_sequence": sequence}
        coord.objects[edge["attention_id"]] = {"edge": edge, "object": {
            **OBJECT, "msg_id": edge["object_id"], "sequence": sequence,
            "body": f"CONTEXT target={TARGET}\nCurrent information."}}
        edges.append(edge)
    edges.append(ready)
    coord.backlog = list(enumerate(edges, 8))
    for _ in range(16):
        result = run(binary, fixture, confirm_fresh_identity=False)
        assert result.returncode == 0, result.stderr
        saved = json.loads(state.read_text())
        assert len(saved["in_flight"]) <= 16
        assert saved["consecutive_failures"] == 0
        if saved["safe_cursor"] == 23:
            break
        assert saved["in_flight"] == original["in_flight"]
        assert saved["awaiting_handoffs"] == original["awaiting_handoffs"]
        assert coord.sends == 0
    else:
        pytest.fail("the bounded backlog did not finish")
    waits = [parse_qs(urlsplit(path).query) for method, path in coord.requests
             if method == "GET" and urlsplit(path).path == "/api/coord/attention/wait"]
    assert all(int(q["limit"][0]) == min(page_limit, 16 - count) for q in waits)
    assert saved["in_flight"] == saved["awaiting_handoffs"] == []
    assert all(p["attention_id"] in saved["recent_attention_ids"] for p in original["in_flight"])
    assert len([m for m in coord.messages if m["body"].startswith("DONE ")]) == count
    prompts = len(list(capture.glob("prompt-*")))
    assert run(binary, fixture, confirm_fresh_identity=False).returncode == 0
    assert len(list(capture.glob("prompt-*"))) == prompts
    assert coord.sends == count


def test_duplicate_attention_preserves_capacity_and_handoff(binary, fixture):
    coord, state, _, capture, original = retained_tasks(binary, fixture, 15)
    coord.page = {"edges": [EDGE], "next_cursor": 8}
    assert run(binary, fixture, confirm_fresh_identity=False).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["safe_cursor"] == 8
    assert saved["in_flight"] == original["in_flight"]
    assert saved["awaiting_handoffs"] == original["awaiting_handoffs"]
    assert not list(capture.iterdir())
    assert coord.sends == 0


def test_full_suspended_checkpoint_continues_before_receiving(binary, fixture):
    coord, state, harness, capture, original = retained_tasks(binary, fixture, 16)
    ready = coord.page["edges"][0]
    coord.messages.append(coord.objects[ready["attention_id"]]["object"])
    capacity_harness(harness, binary, recover_history=True)
    result = run(binary, fixture, confirm_fresh_identity=False)
    assert result.returncode == 0, result.stderr
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == []
    assert saved["awaiting_handoffs"] == original["awaiting_handoffs"]
    assert saved["safe_cursor"] == original["safe_cursor"]
    assert not any("/attention/" in path for _, path in coord.requests)
    assert any("/messages?" in path for _, path in coord.requests)
    assert len(prompt_checkpoint(capture)["in_flight"]) == 16
    assert coord.sends == 16
    # After restart the unchanged attention cursor still delivers READY. The
    # handoff is settled only when that response is admitted and checkpointed.
    assert run(binary, fixture, confirm_fresh_identity=False).returncode == 0
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == saved["awaiting_handoffs"] == []
    assert saved["safe_cursor"] == 49
    assert coord.sends == 16
    coord.page = {"edges": [EDGE], "next_cursor": 50}
    assert run(binary, fixture, confirm_fresh_identity=False).returncode == 0
    assert coord.sends == 16


def test_full_checkpoint_without_progress_retains_uncertainty_and_backoff(binary, fixture):
    coord, state, _, capture, original = retained_tasks(binary, fixture, 16)
    result = run(binary, fixture, confirm_fresh_identity=False)
    assert result.returncode != 0 and "incomplete or uncertain" in result.stderr
    saved = json.loads(state.read_text())
    for field in ("in_flight", "awaiting_handoffs", "safe_cursor", "recent_attention_ids"):
        assert saved[field] == original[field]
    assert saved["phase"] == "uncertain"
    assert saved["consecutive_failures"] == 1
    assert not any("/attention/" in path for _, path in coord.requests)
    assert coord.sends == 0
    _, env, config, _, _, _ = fixture
    settings = json.loads(config.read_text())
    settings.update(backoff_initial_seconds=1, backoff_max_seconds=1)
    config.write_text(json.dumps(settings))
    previous = set(capture.glob("prompt-*"))
    process = subprocess.Popen([str(binary), "supervise", "--config", str(config), "--state", str(state)],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        until(lambda: len(set(capture.glob("prompt-*")) - previous) >= 2)
        times = sorted(p.stat().st_mtime for p in set(capture.glob("prompt-*")) - previous)
        assert times[1] - times[0] >= 0.9
        assert not any("/attention/" in path for _, path in coord.requests)
        assert coord.sends == 0
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_information_does_not_mask_an_uncertain_send_for_ready_work(binary, fixture):
    coord, state, harness, capture, original = retained_tasks(binary, fixture, 1)
    saved = json.loads(state.read_text())
    saved["awaiting_handoffs"] = []
    info_id = f"attn-{2000:032x}"
    saved["in_flight"].append({**saved["in_flight"][0], "attention_id": info_id,
                              "requires_terminal": False, "body": f"CONTEXT target={TARGET}"})
    subprocess.run([str(binary), "write-state", str(state)], input=json.dumps(saved), text=True, check=True)
    coord.unknown_send = True
    harness_script(harness, binary, capture)
    harness.write_text(harness.read_text().replace('"notify":["relay"]', '"notify":["mallory"]'))
    result = run(binary, fixture, confirm_fresh_identity=False)
    assert result.returncode != 0
    saved = json.loads(state.read_text())
    assert saved["in_flight"] == original["in_flight"]
    assert info_id in saved["recent_attention_ids"]
    assert saved["phase"] == "uncertain"
    assert saved["consecutive_failures"] == 1
    harness_script(harness, binary, capture, terminal=False)
    assert run(binary, fixture, confirm_fresh_identity=False).returncode != 0
    assert coord.sends == 1


def test_oversized_receive_retains_tasks_handoffs_and_cursor(binary, fixture):
    coord, state, _, capture, original = retained_tasks(binary, fixture, 15)
    # A server that violates the effective receive limit must fail before
    # any object or cursor is admitted, even though config allows page16.
    coord.page["edges"] = [EDGE, coord.page["edges"][0]]
    result = run(binary, fixture, confirm_fresh_identity=False)
    assert result.returncode != 0 and "exceeds requested limit" in result.stderr
    saved = json.loads(state.read_text())
    for field in ("in_flight", "awaiting_handoffs", "safe_cursor", "recent_attention_ids"):
        assert saved[field] == original[field]
    assert not list(capture.iterdir())
    assert coord.sends == 0


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
