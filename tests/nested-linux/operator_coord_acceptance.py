"""Observe native operator/guest Coord exchange on an owned Ubuntu systrap guest.

Run this host-side Python test driver with a disposable installed root, its
already running native proxy and booted systrap guests. --commit is the actual
full source ID reported by the installed host and guest executables.

With one guest, the G5 observation uses no model or Python guest command.
With --peer, the G2/G4 observation uses both guests, test-only Python HTTP
calls, and one already authenticated Codex session in the primary guest. Stage
the ordinary Codex host setup and native Model Context Protocol (MCP) launcher
before boot. The peer
needs the staged native Coord executable. Permit httpbin.org/get and the
provisioned Codex provider route in this disposable instance's policy.

The driver checks room scope, real callers, history and restart, and requires
completed MCP call results for the real session. On success or failure, the
driver attempts to stop both guests, the proxy and NATS, then checks their
owned process lifetimes. A cleanup failure fails the run. Other instances are
outside the selected root. Run from the source checkout with its locked Python test
environment and PYTHONPATH=tests/reference:.; keep results on disk-backed
storage. For example, after preparation:

    .venv/bin/python tests/nested-linux/operator_coord_acceptance.py --root /owned/root \
        --agent bbtest --peer bbpeer --commit FULL_EXECUTABLE_SOURCE_ID
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import select
import shlex
import struct
import subprocess
import termios
import time
import uuid
from pathlib import Path


def mcp_observation(output: str, room: str, marker: str, agent: str) -> dict:
    """Require completed native MCP calls and their actual structured results."""
    calls = []
    thread_id = None
    completed = False
    for line in output.splitlines():
        event = json.loads(line)
        if event.get("type") == "thread.started":
            thread_id = event["thread_id"]
        if event.get("type") == "turn.completed":
            completed = True
        assert event.get("type") not in ("turn.failed", "error"), event
        item = event.get("item", {})
        if event.get("type") == "item.completed" and item.get("type") == "mcp_tool_call":
            if item.get("server") == "safeyolo-coord":
                assert item.get("status") == "completed" and not item.get("error"), item
                result = item["result"]
                assert not result.get("isError"), result
                value = result.get("structured_content", result.get("structuredContent"))
                if value is None:
                    value = next(json.loads(row["text"]) for row in result["content"] if row["type"] == "text")
                calls.append({"tool": item["tool"], "arguments": item["arguments"], "result": value})
    assert thread_id and completed, "real Codex session did not complete"
    tools = [call["tool"] for call in calls]
    required = ["join_room", "send", "read_room", "wait_for_message"]
    assert all(tool in tools for tool in required) and tools.count("send") == 1, calls
    positions = [tools.index(tool) for tool in required]
    assert positions == sorted(positions), calls
    sequence = [calls[index] for index in positions]
    assert all(call["arguments"]["room_name"] == room for call in calls), calls
    sent = sequence[1]["result"]["envelope"]
    assert sequence[1]["arguments"]["body"] == sent["body"] == marker, sent
    assert sent["sender_kind"] == "agent" and sent["sender_agent_name"] == agent, sent
    for call in sequence[2:]:
        messages = call["result"]["messages"]
        assert any(row["msg_id"] == sent["msg_id"] and row["body"] == marker
                   and row["sender_agent_id"] == sent["sender_agent_id"] for row in messages), call
    return {"thread_id": thread_id, "calls": calls, "message_id": sent["msg_id"], "sender_agent_id": sent["sender_agent_id"]}


def coordination_journey(root: Path, primary: str, peer: str, commit: str, command) -> dict:
    """Observe the missing G2/G4 guest composition without repeating G5 or Factory."""
    from tests.blackbox.installed_host_smoke import _agent_map, _process_start_token
    from tests.blackbox.installed_ingress import runsc_identity

    native = "/home/agent/.safeyolo/safeyolo-coord"
    room = "g2-" + uuid.uuid4().hex
    private = room + "-private"
    marker = "G2:" + uuid.uuid4().hex
    host_versions = {}
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        version = subprocess.check_output([str(root / "bin" / name), "--version"], text=True, timeout=5).strip()
        assert f"commit={commit} " in version, version
        host_versions[name] = version
    proxy_identity = json.loads((root / "data/proxy-process.json").read_text())
    proxy_path = Path(f"/proc/{proxy_identity['pid']}/exe").resolve(strict=True)
    assert proxy_path == (root / "bin/safeyolo-proxy").resolve(strict=True), proxy_path
    assert _process_start_token(proxy_identity["pid"]) == proxy_identity["token"], proxy_identity

    def shell(agent, script, *, check=True, timeout=30):
        return command("agent", "shell", agent, "-c", "cd /workspace && " + script,
                       check=check, timeout=timeout)

    def call(agent, tool, arguments):
        source = shlex.quote(json.dumps(arguments))
        return json.loads(shell(agent, f"printf '%s' {source} | {native} call {shlex.quote(tool)}"))

    def api(agent, method, path, payload=None):
        # Reuse the guest proxy-only HTTP helper. It reads /app/agent_token for
        # each request and returns only the nonsecret response, never headers.
        script = ("from tests.blackbox.isolation.installed_access import api; import json; "
                  f"status, _, value = api({method!r}, {path!r}, payload={payload!r}); "
                  "print(json.dumps({'status':status,'body':value}))")
        return json.loads(shell(agent, "python3 -c " + shlex.quote(script)))

    def history(agent):
        return call(agent, "read_room", {"room_name": room, "since_sequence": 0, "limit": 20})["messages"]

    identities = {}
    for name in (primary, peer):
        state = json.loads(command("agent", "status", name))
        assert state["runtime_state"] == "running" and state["control_state"] == "ready", state
        listener = next(row for row in _agent_map(root) if row["agent_id"] == name)
        bridge = runsc_identity(root, name, Path(listener["path"]), platform="systrap")
        versions = {binary: shell(name, binary + " --version").strip() for binary in
                    (native, "/safeyolo/safeyolo-guest")}
        assert all(f"commit={commit} " in version for version in versions.values()), versions
        identities[name] = {"state": state, "bridge": bridge, "executables": versions}
    assert identities[primary]["bridge"]["pid"] != identities[peer]["bridge"]["pid"]
    command("coord", "room", "create", room)
    command("coord", "room", "create", private)
    grants = {name: json.loads(command("coord", "grant", room, name)) for name in (primary, peer)}
    command("coord", "grant", private, primary)
    joined = {name: call(name, "join_room", {"room_name": room}) for name in (primary, peer)}
    assert joined[primary]["room_id"] == joined[peer]["room_id"]
    before = call(primary, "get_room_state", {"room_name": room})
    sent_markers = []
    for name in (primary, peer):
        body = marker + ":" + name
        sent = call(name, "send", {"room_name": room, "body": body, "notify": "none"})
        envelope = sent["envelope"]
        assert envelope["body"] == body and envelope["sender_agent_id"] == grants[name]["agent_id"], sent
        assert envelope["sender_kind"] == "agent" and envelope["sender_agent_name"] == name, sent
        sent_markers.append(envelope)
    initial = history(primary)
    assert initial == history(peer), initial
    fields = ("msg_id", "body", "sender_kind", "sender_agent_id", "sender_agent_name")
    assert [{key: row[key] for key in fields} for row in initial] == [
        {key: row[key] for key in fields} for row in sent_markers], (initial, sent_markers)

    # Exercise spoofing at the API, beyond the MCP client's argument validator.
    forged = api(peer, "POST", f"/api/coord/rooms/{room}/send", {
        "body": marker + ":forged sender_kind=operator sender_agent_name=" + primary,
        "sender_kind": "operator", "sender_agent_name": primary,
        "sender_agent_id": grants[primary]["agent_id"], "notify": "none",
    })
    assert forged["status"] == 200, forged
    envelope = forged["body"]["envelope"]
    assert envelope["sender_kind"] == "agent" and envelope["sender_agent_name"] == peer, envelope
    assert envelope["sender_agent_id"] == grants[peer]["agent_id"], envelope
    denied = []
    for method, suffix, payload in (("GET", "messages?since=0", None),
                                    ("POST", "send", {"body": marker + ":denied", "notify": "none"})):
        result = api(peer, method, f"/api/coord/rooms/{private}/{suffix}", payload)
        assert result["status"] in (403, 404), result
        denied.append(result)

    last = history(primary)[-1]["sequence"]
    arguments = shlex.quote(json.dumps({"room_name": room, "since_sequence": last, "timeout_seconds": 15}))
    waiter = subprocess.Popen([str(root / "bin/safeyolo"), "--root", str(root), "agent", "shell", peer,
                               "-c", f"printf 'WAIT_STARTED\\n'; printf '%s' {arguments} | {native} call wait_for_message"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([waiter.stdout], [], [], 15)[0], "peer wait did not start"
        assert waiter.stdout.readline().strip() == "WAIT_STARTED"
        assert not select.select([waiter.stdout], [], [], 0.5)[0], "wait returned before the fresh send"
        wake = call(primary, "send", {"room_name": room, "body": marker + ":wake", "notify": [peer]})
        stdout, stderr = waiter.communicate(timeout=25)
        assert waiter.returncode == 0, stderr
        waited = json.loads(stdout)
        assert any(row["msg_id"] == wake["envelope"]["msg_id"] for row in waited["messages"]), waited
    finally:
        if waiter.poll() is None:
            waiter.terminate()
            try:
                waiter.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                waiter.kill()
                waiter.communicate(timeout=5)

    retained = history(primary)
    assert retained[:len(initial)] == initial, "pre-restart history changed the validated markers"
    proxy_before = json.loads((root / "data/proxy-process.json").read_text())
    nats_before = json.loads((root / "data/coord/nats/process.json").read_text())
    command("stop")  # Native Coord lives in the proxy; this also stops its owned NATS.
    command("start")
    proxy_after = json.loads((root / "data/proxy-process.json").read_text())
    nats_after = json.loads((root / "data/coord/nats/process.json").read_text())
    assert proxy_before != proxy_after and nats_before != nats_after, "Coord owners did not restart"
    after = call(primary, "get_room_state", {"room_name": room})
    for key in ("room_id", "origin_instance_id", "members"):
        assert before[key] == after[key], (key, before, after)
    for name in (primary, peer):
        current = json.loads(command("agent", "status", name))
        for key in ("agent_id", "run_id", "runtime_state", "control_state"):
            assert current[key] == identities[name]["state"][key], (key, current, identities[name])
        identities[name]["state_after_restart"] = current
        restored = call(name, "join_room", {"room_name": room})
        for key in ("room_id", "permissions", "history_visibility"):
            assert restored[key] == joined[name][key], (key, restored, joined[name])
        assert history(name) == retained, "restart changed retained messages or order"
    fresh = call(peer, "send", {"room_name": room, "body": marker + ":after restart", "notify": "none"})
    assert fresh["sequence"] > retained[-1]["sequence"]

    # Stop only the owned NATS while the native proxy and both guests stay live.
    command("coord", "stop")
    unavailable = api(primary, "POST", f"/api/coord/rooms/{room}/send", {"body": marker + ":unavailable", "notify": "none"})
    assert unavailable["status"] == 503 and "unavailable" in unavailable["body"]["error"], unavailable
    target = shlex.quote("http://httpbin.org/get?g2_marker=" + marker)
    traffic = json.loads(shell(peer, f"curl --fail --silent --show-error --max-time 15 {target}"))
    assert traffic["args"]["g2_marker"] == marker, traffic
    command("coord", "start", "--client-port", str(nats_after["client_port"]),
            "--monitor-port", str(nats_after["monitor_port"]))
    deadline = time.monotonic() + 15
    while True:
        restored = api(primary, "GET", f"/api/coord/rooms/{room}/messages?since=0&limit=20")
        if restored["status"] == 200:
            break
        assert restored["status"] == 503 and time.monotonic() < deadline, restored
        time.sleep(0.1)  # Existing NATS connection needs to reconnect to its same endpoint.
    assert not any(row["body"] == marker + ":unavailable" for row in restored["body"]["messages"])

    codex_marker = "G4:" + uuid.uuid4().hex
    cursor = fresh["sequence"]
    prompt = (f"Use the discovered safeyolo-coord MCP tools only for this task. Join room {room}. "
              f"Send exactly {codex_marker} with notify=none and declared_content_type=text/plain once. "
              f"Read the room since_sequence={cursor}. Then call wait_for_message with room_name={room}, "
              f"since_sequence={cursor}, include_self=true, timeout_seconds=1. "
              "Verify your exact marker in both results. End the session after these four calls. "
              "Do not substitute shell calls, invent results, retry a send, or edit files.")
    codex_version = shell(primary, "/home/agent/.safeyolo-command --version").strip()
    login = shell(primary, "/home/agent/.safeyolo-command login status", check=False)
    assert login.returncode == 0, "provisioned Codex login is missing"
    # Reuse the installed real-Helper's five-minute session deadline.
    events = shell(primary, "/home/agent/.safeyolo-command exec --json --skip-git-repo-check " + shlex.quote(prompt), timeout=300)
    mcp = mcp_observation(events, room, codex_marker, primary)
    observed = history(peer)
    matches = [row for row in observed if row["body"] == codex_marker]
    assert len(matches) == 1 and matches[0]["msg_id"] == mcp["message_id"], matches
    assert matches[0]["sender_agent_id"] == grants[primary]["agent_id"] == mcp["sender_agent_id"]
    return {"journey": "G2/G4 Ubuntu systrap", "executable_commit": commit,
            "host_executables": host_versions, "actual_proxy_path": str(proxy_path), "guests": identities,
            "room": room, "joined": joined, "room_before": before, "room_after": after, "sent_markers": sent_markers,
            "history_before_restart": retained, "history_after_mcp": observed,
            "forged_sender": envelope, "nonmember_refusals": denied, "wait": waited,
            "proxy_before": proxy_before, "proxy_after": proxy_after,
            "nats_before": nats_before, "nats_after": nats_after,
            "nats_unavailable": unavailable, "permitted_traffic_marker": traffic["args"]["g2_marker"],
            "codex_version": codex_version, "mcp": mcp}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--peer", help="Run the G2/G4 journey with a second already booted systrap guest and provisioned Codex")
    args = parser.parse_args()
    if args.peer == args.agent:
        parser.error("--peer requires a second guest")
    root = args.root.resolve()
    cli = root / "bin/safeyolo"

    def command(*arguments, check=True, timeout=30):
        result = subprocess.run([str(cli), "--root", str(root), *arguments],
                                capture_output=True, text=True, timeout=timeout)
        if check:
            assert result.returncode == 0, result.stderr
            return result.stdout
        return result

    guest = "/home/agent/.safeyolo/safeyolo-coord"

    def shell(script):
        return command("agent", "shell", args.agent, "-c", script)

    result = None
    processes = []
    try:
        if args.peer:
            from tests.blackbox.installed_sections import owned_processes, surviving_processes
            processes = owned_processes(root)
        host = command("--version").strip()
        assert f"commit={args.commit} " in host, host
        state = json.loads(command("agent", "status", args.agent))
        assert state["runtime_state"] == "running" and state["control_state"] == "ready", state
        assert json.loads(command("coord", "status"))["state"] == "running"
        if args.peer:
            result = coordination_journey(root, args.agent, args.peer, args.commit, command)
            return
        identity = shell(f"{guest} --version").strip()
        assert f"commit={args.commit} " in identity, identity
        room = f"g5-{args.agent}"
        command("coord", "room", "create", room)
        command("coord", "grant", room, args.agent)
        outbound = "G5 operator → actual guest\nexact payload"
        command("coord", "send", room, outbound, "--to", args.agent, "--content-type", "text/plain")

        def call(tool, payload):
            source = shlex.quote(json.dumps(payload, ensure_ascii=False))
            return json.loads(shell(f"printf '%s' {source} | {guest} call {shlex.quote(tool)}"))

        received = call("read_room", {"room_name": room, "since_sequence": 0})
        operator = next(m for m in received["messages"] if m["body"] == outbound)
        assert operator["sender_kind"] == "operator" and operator["sender_agent_id"] is None
        forged = shlex.quote(json.dumps({"room_name": room, "body": "forged guest", "sender_kind": "operator"}))
        refused = command("agent", "shell", args.agent, "-c",
                          f"printf '%s' {forged} | {guest} call send", check=False)
        assert refused.returncode != 0 and "unknown argument sender_kind" in refused.stderr, refused

        # The same operator PTY observes actual guest arrival while its draft
        # is unfinished, then sends and receives another actual guest reply.
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        chat = subprocess.Popen([str(cli), "--root", str(root), "coord", "chat", room, "--to", args.agent],
                                stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                env={**os.environ, "TERM": "xterm-256color"})
        os.close(slave)

        def until(marker):
            buffer = bytearray()
            deadline = time.monotonic() + 10
            while marker not in buffer and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    buffer.extend(os.read(master, 65536))
                assert chat.poll() is None, bytes(buffer)
            assert marker in buffer, bytes(buffer)

        inbound = "G5 actual guest → operator"
        draft = "G5 unfinished café draft"
        reply = "G5 actual guest reply after send"
        try:
            until(b"op> ")
            os.write(master, draft.encode())
            sent = call("send", {"room_name": room, "body": inbound, "notify": "none"})
            assert sent["envelope"]["sender_kind"] == "agent", sent
            assert sent["envelope"]["sender_agent_name"] == args.agent, sent
            until(inbound.encode())
            os.write(master, b"\r")
            until(b"message accepted;")
            call("send", {"room_name": room, "body": reply, "notify": "none"})
            until(reply.encode())
            os.write(master, b":q\r")
            chat.wait(timeout=5)
            assert chat.returncode == 0
        finally:
            if chat.poll() is None:
                chat.terminate()
                chat.wait(timeout=5)
            os.close(master)
        history = [json.loads(line) for line in command("coord", "history", room).splitlines()]
        assert [m["body"] for m in history] == [outbound, inbound, draft, reply], history
        assert history[1]["sender_agent_id"] == sent["envelope"]["sender_agent_id"]
        assert history[2]["sender_kind"] == "operator" and history[2]["sender_agent_id"] is None
        timeline = command("coord", "watch", room, "--once")
        assert "OP" in timeline and inbound in timeline
        print(json.dumps({"host": host, "guest": identity, "room": room,
                          "messages": [{k: m[k] for k in ("msg_id", "sequence", "sender_kind", "sender_agent_id", "sender_agent_name", "body")} for m in history]}, ensure_ascii=False))
    finally:
        # Stop all three owned lifetimes. Proxy stop alone leaves a guest live.
        failures = []
        if args.peer:
            try:
                # Include current owners even if the journey failed after restart.
                processes.extend(owned_processes(root))
            except (OSError, ValueError, KeyError) as error:
                failures.append(f"owned process inspection: {error}")
        guests = (args.agent, args.peer) if args.peer else (args.agent,)
        for arguments in [("agent", "stop", name) for name in guests] + [("stop",), ("coord", "stop")]:
            try:
                stopped = command(*arguments, check=False, timeout=60)
                if stopped.returncode:
                    failures.append(f"{' '.join(arguments)} exited {stopped.returncode}: {stopped.stderr}")
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"{' '.join(arguments)}: {error}")
        checks = [(("agent", "status", name), "runtime_state") for name in guests]
        for arguments, key in checks + [(("coord", "status"), "state")]:
            try:
                state = json.loads(command(*arguments))
                if state[key] != "stopped":
                    failures.append(f"{' '.join(arguments)} is {state[key]}")
            except (OSError, subprocess.SubprocessError, AssertionError, ValueError, KeyError) as error:
                failures.append(f"{' '.join(arguments)}: {error}")
        if args.peer:
            failures.extend(surviving_processes(processes))
        assert not failures, failures
        if result is not None:
            result["cleanup"] = {"guests": [args.agent, args.peer], "owned_processes_stopped": processes}
            print(json.dumps(result, ensure_ascii=False))
        print("Owned guests, native proxy and NATS stopped", flush=True)


if __name__ == "__main__":
    main()
