#!/usr/bin/env python3
"""Exercise installed access through two live systrap or VZ guests.

Retain service and contract binding/risk approvals, exact credential injection
and live peer denial, populated owner-positive/peer-negative guest flow search
and detail, test-context/trace evidence, real NATS Coord and attention, operator
collaboration approval/exchange/revocation, WebSocket peer effects and traffic-inspector
filter/transcript/export, exact host-secret custody and abrupt proxy recovery.
These observations stay in one installed composition.
The fixture prepares guest desktop packages and an owned host opener. Headless
Linux runs also own a host Xvfb display for the typed action's display check.
Viewer checks observe VNC bytes, session binding and cessation on revocation,
expiry and run turnover; they do not require visual UI automation.
"""

from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import pty
import re
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .execution_receipt import ProcedureReceipt, save
    from .guest_exec import guest_command_args, prepare_guest_tests
    from .harness.containment import secret_commitments
    from .host.sinkhole_client import SinkholeClient
    from .installed_host_smoke import _agent_listeners, _native_config, _runtime_observation, _sha256
    from .installed_ingress import installed_identity, runsc_identity
    from .installed_lifecycle import crash_owned_proxy
    from .installed_workloads import control
else:
    from execution_receipt import ProcedureReceipt, save
    from guest_exec import guest_command_args, prepare_guest_tests
    from harness.containment import secret_commitments
    from host.sinkhole_client import SinkholeClient
    from installed_host_smoke import _agent_listeners, _native_config, _runtime_observation, _sha256
    from installed_ingress import installed_identity, runsc_identity
    from installed_lifecycle import crash_owned_proxy
    from installed_workloads import control
from urllib.parse import urlencode, urlsplit

from websockets.exceptions import ConnectionClosed, InvalidStatus
from websockets.sync.client import connect

from safeyolo.api import AdminAPI, APIError
from safeyolo.operator_approvals import approve

ROOM = "p3-owned-room"
PEER = "bbpeer"


def host_secret_custody(cli: str, root: Path, agent: str, vault_value: str) -> list[dict]:
    """Prove exact CA/vault canary absence after authorized TLS and injection."""
    commitments = secret_commitments(root / "certs/mitmproxy-ca.pem", vault_value)
    path = root / "agents" / agent / "config-share/host-secret-commitments.json"
    with path.open("x") as output:
        output.write(json.dumps(commitments))
    path.chmod(0o444)
    observations = []
    try:
        code = ("import sys; sys.path.insert(0, '/workspace/tests/blackbox'); "
                "from isolation.test_key_isolation import installed_custody; "
                "installed_custody('/safeyolo/host-secret-commitments.json')")
        for guest_root in (False, True):
            result = checked(guest_command_args(cli, agent, shlex.join(["python3", "-c", code]),
                                                guest_root=guest_root), timeout=120)
            lines = [line.removeprefix("SECRET_CUSTODY=") for line in result.stdout.splitlines()
                     if line.startswith("SECRET_CUSTODY=")]
            assert len(lines) == 1, "guest custody observation missing"
            value = json.loads(lines[0])
            assert value["uid"] == (0 if guest_root else 1000)
            assert value["fingerprints"] == commitments and value["files_inspected"] > 0
            observations.append(value)
    finally:
        path.unlink()
    return observations


def abrupt_authority(cli: str, root: Path, agent: str, platform: str, marker: str,
                     admin: AdminAPI, sinkhole: SinkholeClient, consumed: str, runtime: dict,
                     report: dict, save) -> None:
    """Exercise outage, revoked/consumed authority and explicit recovery calls."""
    value = report["abrupt_failure"] = {"status": "incomplete", "consumed_grant": consumed}
    guest(cli, agent, platform, marker, "crash-tokens")
    value["service_revocation"] = admin.revoke_service(agent, "p3_basic")
    assert all(row.get("grant_id") != consumed for row in admin.list_gateway_grants()["grants"])
    before = len(sinkhole.get_requests())
    selected = runtime["runtime"]
    native = _native_config(root / "config.toml", root)
    binary = Path(runtime["candidate"]["path"])
    save()
    value["crash"] = crash_owned_proxy(root, binary, native, selected["pid"], selected["receipt"]["start_token"])
    save()
    value["outage"] = guest(cli, agent, platform, marker, "crash-outage")
    value["outage_origin_count"] = len(sinkhole.get_requests())
    save()
    assert value["outage_origin_count"] == before, "guest delivered during proxy outage"
    checked([cli, "--instance-dir", str(root), "--json", "start"], timeout=60)
    recovered = _runtime_observation(root, native, binary, config_path=root / "config.toml",
        working_directory=root, require_running=True, require_authenticated_identity=True)
    value["recovered"] = recovered
    save()
    assert recovered["receipt"]["start_token"] != selected["receipt"]["start_token"]
    assert len(sinkhole.get_requests()) == before, "recovery automatically replayed an operation"
    assert all(row.get("grant_id") != consumed for row in admin.list_gateway_grants()["grants"]), "consumed grant reappeared"
    value["explicit_denied_retries"] = guest(cli, agent, platform, marker, "crash-recovered")
    save()
    assert len(sinkhole.get_requests()) == before, "revoked or consumed authority delivered after recovery"
    value["allowed_after_recovery"] = guest(cli, agent, platform, marker + "-crash-control", "flow-seed")
    value["origin_count_after_control"] = len(sinkhole.get_requests())
    assert value["origin_count_after_control"] == before + 1, "authorized recovery origin control failed"
    value["status"] = "passed"
    save()


def checked(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    assert result.returncode == 0, f"{command[0]} exited {result.returncode}: {result.stderr[-700:]}"
    return result


def guest_command(cli: str, agent: str, platform: str, marker: str, phase: str, **options: str | int) -> list[str]:
    request = [
        "/usr/bin/python3",
        "-m",
        "tests.blackbox.isolation.installed_access",
        "--phase",
        phase,
        "--platform",
        platform,
        "--agent",
        agent,
        "--marker",
        marker,
    ]
    for key, value in options.items():
        request.extend(["--" + key.replace("_", "-"), str(value)])
    return guest_command_args(cli, agent, "cd /workspace && " + shlex.join(request))


def observation(output: str, phase: str, agent: str) -> dict:
    lines = [line.removeprefix("P3_OBSERVATION=") for line in output.splitlines() if line.startswith("P3_OBSERVATION=")]
    assert len(lines) == 1, f"guest {phase} did not return one observation: {output[-700:]}"
    value = json.loads(lines[0])
    assert value["phase"] == phase and value["agent"] == agent
    assert value["forwarder"]["pid"] > 1
    return value["result"]


def guest(cli: str, agent: str, platform: str, marker: str, phase: str, **options: str | int) -> dict:
    command = guest_command(cli, agent, platform, marker, phase, **options)
    result = checked(command, timeout=50)
    return observation(result.stdout, phase, agent)


def wait_for_approval(
    api: AdminAPI,
    approval_type: str,
    *,
    request_id: str | None = None,
    agent: str | None = None,
    service: str | None = None,
) -> dict:
    deadline = time.monotonic() + 7
    observed = []
    while time.monotonic() < deadline:
        pending = api.pending_approvals()
        observed = [{key: row.get(key) for key in ("approval_id", "request_id", "agent", "action")}
                    for row in pending if row.get("approval", {}).get("approval_type") == approval_type]
        matches = [
            row
            for row in pending
            if row.get("approval", {}).get("approval_type") == approval_type
            and (request_id is None or row.get("request_id") == request_id)
            and (agent is None or row.get("agent") == agent)
            and (service is None or row.get("action", {}).get("service") == service)
        ]
        if len(matches) == 1:
            print(json.dumps({"phase": "approval_pending", "approval_type": approval_type,
                              "observed": observed}), flush=True)
            return matches[0]
        time.sleep(0.05)
    raise AssertionError(f"operator did not see one {approval_type} request for {agent}/{service}/{request_id}; "
                         f"observed={json.dumps(observed)}")


def approve_service(api: AdminAPI, agent: str, service: str, credential: str, *, request_id: str) -> None:
    event = wait_for_approval(api, "service", agent=agent, service=service, request_id=request_id)
    assert event["agent"] == agent and event["action"]["service"] == service, event
    assert approve(event, api, service_credential=credential) in {"authorized", "ok"}


def authorize_access(api: AdminAPI, cli: str, agent: str, platform: str, marker: str, credential: str) -> dict:
    """Request each approval after the preceding policy decision is published."""
    first = guest(cli, agent, platform, marker, "access")
    approve_service(api, agent, "p3_basic", credential, request_id=first["service_request_id"])
    # Service authorization adds gateway permissions. The revision guard can
    # supersede a binding submitted before that policy change.
    requested = guest(cli, agent, platform, marker, "binding")
    binding = wait_for_approval(api, "contract_binding", agent=agent, service="p3_contract",
                                request_id=requested["binding_request_id"])
    assert approve(binding, api) in {"bound", "ok"}
    contract = guest(cli, agent, platform, marker, "contract-access")
    authorized = api.authorize_service(agent=agent, service="p3_contract", capability="writer", credential=credential)
    assert authorized["status"] == "authorized", authorized
    return {"service_request_id": first["service_request_id"],
            "binding_request_id": requested["binding_request_id"],
            "challenge_after_binding": contract["contract_challenge"]}


def setup_coord(cli: str, root: Path, primary: str, peer: str, *, room: str = ROOM) -> dict:
    """Provision the real native Coord owner rather than the Python reference."""
    prefix = [cli, "--instance-dir", str(root), "--json", "coord"]
    status = json.loads(checked([*prefix, "status"]).stdout)
    assert status["state"] == "running", "owned native NATS is not running"
    created = json.loads(checked([*prefix, "room", "create", room]).stdout)
    identities = {}
    for name in (primary, peer):
        granted = json.loads(checked([*prefix, "grant", room, name]).stdout)
        identities[name] = granted
    return {"instance_id": (root / "data/instance_id").read_text().strip(),
            "room_id": created["room_id"], "agents": identities}


def run_coord(cli: str, primary: str, platform: str, marker: str) -> dict:
    first_join = guest(cli, primary, platform, marker, "coord-join")
    second_join = guest(cli, PEER, platform, marker, "coord-join")
    assert first_join["room_id"] == second_join["room_id"]
    first = "p3-first:" + marker
    sent = guest(cli, primary, platform, marker, "coord-send", message=first)
    read = guest(cli, PEER, platform, marker, "coord-read", message=first)
    assert read["found"] == first
    next_message = "p3-wake:" + marker
    process = subprocess.Popen(
        guest_command(cli, PEER, platform, marker, "coord-wait", after=sent["sequence"], message=next_message),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    try:
        ready, _, _ = select.select([process.stdout], [], [], 15)
        assert ready and process.stdout.readline().strip() == "P3_WAIT_READY=coord", (
            "peer did not start its real room wait"
        )
        notified = guest(cli, primary, platform, marker, "coord-send", message=next_message, notify=PEER)
        stdout, stderr = process.communicate(timeout=25)
        assert process.returncode == 0, f"peer wait exited {process.returncode}: {stderr[-700:]}"
        waited = observation(stdout, "coord-wait", PEER)
        assert waited["waited_message_id"] == notified["message_id"]
        assert waited["backing_sequence"] == notified["sequence"]
        return {
            "room_id": first_join["room_id"],
            "read": sent["message_id"],
            "waited": waited["waited_message_id"],
            "attention_resolved": waited["attention_id"],
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


def wait_for_approval_event(websocket, identifier: str, *, timeout: float = 7) -> dict:
    """Match the approval within a deadline, allowing intervening state controls."""
    deadline = time.monotonic() + timeout
    observed = []
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            candidate = json.loads(websocket.recv(timeout=remaining))
        except TimeoutError:
            break
        observed.append({key: candidate.get(key) for key in ("type", "revision", "event", "approval")})
        if candidate.get("approval", {}).get("key") == identifier:
            print(json.dumps({"phase": "approval_event", "approval_id": identifier, "frames": observed}), flush=True)
            return candidate
    raise AssertionError(f"authenticated operator stream missed collaboration approval {identifier}; frames={observed}")


def run_collaboration_and_event(
    api: AdminAPI, cli: str, config_dir: Path, primary: str, platform: str, marker: str, operator_token: str
) -> dict:
    admin = urlsplit(api.base_url)
    assert admin.scheme == "http" and admin.hostname == "127.0.0.1" and admin.port
    with connect(
        f"ws://127.0.0.1:{admin.port}/admin/events",
        additional_headers={"Authorization": f"Bearer {operator_token}"},
        proxy=None,
    ) as websocket:
        requested = guest(cli, primary, platform, marker, "collaboration-request", peer=PEER)
        identifier, room = requested["approval_id"], requested["room_name"]
        event = wait_for_approval_event(websocket, identifier)
        assert event.get("approval", {}).get("approval_type") == "coord_room", (
            "authenticated operator stream missed the collaboration approval"
        )
        assert any(row["approval_id"] == identifier for row in api.pending_approvals())
        current = api.approval(identifier)
        assert {row["name"] for row in current["action"]["participants"]} == {primary, PEER}
        approved = api.resolve_approval(identifier, "approve", option="collaboration")
        assert approved["status"] == "approved" and approved["result"]["room_name"] == room
        sent = guest(cli, primary, platform, marker, "collaboration-send", room=room)
        read = guest(cli, PEER, platform, marker, "collaboration-read", room=room)
        assert sent["message_id"] and read["message_count"] >= 1
        checked([cli, "--instance-dir", str(config_dir), "--json", "coord", "revoke", room, PEER,
                 "--operation-id", marker + "-revoke"])
        revoked = guest(cli, PEER, platform, marker, "collaboration-revoked", room=room)
        return {"approval_id": identifier, "operator_event": event["event"], "room_name": room,
                "peer_message_id": sent["message_id"], "revoked_read_status": revoked["revoked_read_status"]}


def inspect_traffic(api: AdminAPI, output: Path, primary: str, marker: str) -> dict:
    """Consume native evidence; this test harness has no presentation client."""
    api.set_traffic_scope(agent=primary)
    api.set_traffic_filter("~u p3")
    flows = api.traffic_flows()["flows"]
    assert all(row.get("agent") == primary and "p3" in row.get("url", "") for row in flows)
    rows = [row for row in flows if "/p3/read" in row.get("url", "")]
    assert rows, flows
    selected = rows[0]
    detail = api.traffic_flow(selected["id"])
    assert detail["id"] == selected["id"]
    exported = output.parent / f"access-selected-{marker}.raw_request"
    api.traffic_export(selected["id"], "raw_request", exported)
    assert exported.is_file() and b"/p3/read" in exported.read_bytes()
    api.set_traffic_filter("~u p2/ws")
    flows = api.traffic_flows()["flows"]
    assert all(row.get("agent") == primary and "/p2/ws" in row.get("url", "") for row in flows)
    ws_rows = [row for row in flows if "/p2/ws/" in row.get("url", "")]
    assert ws_rows, flows
    messages = api.traffic_websocket_messages(ws_rows[0]["id"])["messages"]
    assert len(messages) >= 2, messages
    api.set_traffic_filter("")
    return {
        "http_flows_visible": len(rows),
        "selected_flow_id": selected["id"],
        "selected_export": str(exported),
        "selected_export_bytes": exported.stat().st_size,
        "websocket_flow_id": ws_rows[0]["id"],
        "transcript_messages": len(messages),
    }


def check_origin(sinkhole: SinkholeClient, credential: str, marker: str) -> dict:
    requests = sinkhole.get_requests()
    basic = [row for row in requests if row.host == "legitimate-api.com" and row.path == "/p3/read"]
    contract = [row for row in requests if row.host == "httpbin.org" and row.path == "/p3/write"]
    assert len(basic) == 2 and len(contract) == 1, (len(basic), len(contract))
    assert all(
        {key.lower(): value for key, value in row.headers.items()}.get("authorization") == f"Bearer {credential}"
        for row in basic + contract
    )
    assert all(all("sgw_" not in value for value in row.headers.values()) for row in basic + contract)
    assert sorted({key.lower(): value for key, value in row.headers.items()}.get("x-p3-marker") for row in basic) == [
        marker,
        marker + "-context",
    ]
    assert contract[0].method == "POST" and contract[0].query_params == {"ticket": ["T-1"]}
    assert all(row.body_bytes == b'{"project":"alpha"}' for row in contract)
    assert not any(row.path == "/p3/outside" for row in requests)
    return {
        "basic_deliveries": len(basic),
        "contract_deliveries": len(contract),
        "vault_credential_exact": True,
        "gateway_token_absent_upstream": True,
        "out_of_scope_deliveries": 0,
    }


def operator_terminal(cli: str, root: Path, agent: str, marker: str) -> dict:
    """Attach to an owned shell command while opening an independent shell."""
    prefix = [cli, "--instance-dir", str(root), "--json", "agent"]
    checked([*prefix, "configure", agent, "--launcher", "tmux-window", "--command",
             f"printf '{marker}\\n'; exec sleep 600"])
    checked([*prefix, "start", agent], timeout=130)
    deadline = time.monotonic() + 15
    while True:
        before = json.loads(checked([*prefix, "status", agent]).stdout)
        if before["agent_state"] == "running":
            break
        assert time.monotonic() < deadline, "owned terminal command did not start"
        time.sleep(0.05)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    environment = dict(os.environ, TERM="xterm-256color")
    environment.pop("TMUX", None)
    environment.pop("TMUX_PANE", None)
    try:
        viewer = subprocess.Popen([*prefix, "attach", agent], stdin=slave, stdout=slave,
                                  stderr=slave, env=environment, start_new_session=True)
    except OSError:
        os.close(master)
        raise
    finally:
        os.close(slave)
    screen = bytearray()
    try:
        deadline = time.monotonic() + 15
        while marker.encode() not in screen:
            assert time.monotonic() < deadline, "attached terminal did not show the owned command"
            assert viewer.poll() is None, "native attach exited before showing the owned terminal"
            if select.select([master], [], [], 0.1)[0]:
                screen.extend(os.read(master, 4096))
                assert len(screen) <= 65536, "attached terminal exceeded the fixture output bound"
        independent = checked([*prefix, "shell", agent, "-c", "printf '%s\\n' \"$$\"; id -u"]).stdout.splitlines()
        assert len(independent) == 2 and independent[0].isdigit() and independent[1] == "1000", independent
        assert viewer.poll() is None, "opening an independent shell ended the attachment"
        os.write(master, b"\x02d")
        assert viewer.wait(timeout=10) == 0, "native terminal detach failed"
    finally:
        if viewer.poll() is None:
            os.killpg(viewer.pid, signal.SIGHUP)
            try:
                viewer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(viewer.pid, signal.SIGKILL)
                viewer.wait(timeout=5)
        os.close(master)
    after = json.loads(checked([*prefix, "status", agent]).stdout)
    assert after["agent_state"] == "running", after
    for field in ("agent_id", "run_id", "launch_id"):
        assert after[field] == before[field], f"terminal/shell operation changed {field}"
    return {"agent_id": after["agent_id"], "run_id": after["run_id"], "launch_id": after["launch_id"],
            "independent_shell_pid": int(independent[0]), "shell_uid": 1000, "detached_command_running": True,
            "launcher": "tmux-window", "command": "owned shell marker and sleep; no model"}


def operator_desktop(api: AdminAPI, agent_id: str, *, presentation=None, after_banner=None) -> dict:
    """Unlock the native desktop page and reach VNC through its viewer route."""
    presentation = presentation or api.present_desktop(agent_id)
    assert presentation["agent_id"] == agent_id, "desktop returned another target"
    url = urlsplit(presentation["url"])
    assert url.scheme == "http" and url.port and (url.hostname == "127.0.0.1" or
            url.hostname is not None and url.hostname.endswith(".localhost")), "fixture requires local presentation"
    assert url.path == "/_safeyolo_desktop/", "presentation did not return the native desktop path"
    connection = http.client.HTTPConnection("127.0.0.1", url.port, timeout=10)
    session = None
    try:
        connection.request("POST", "/_safeyolo_preview/unlock",
                           body=urlencode({"code": presentation["unlock_code"]}),
                           headers={"Content-Type": "application/x-www-form-urlencoded", "Host": url.netloc})
        response = connection.getresponse()
        response.read(1_000_001)
        assert response.status == 303, f"desktop unlock failed: status={response.status}"
        cookie = response.getheader("Set-Cookie")
        assert cookie, "desktop unlock did not return its session cookie"
        connection.request("GET", url.path, headers={"Cookie": cookie.split(";", 1)[0], "Host": url.netloc})
        response = connection.getresponse()
        page = response.read(1_000_001)
        page_markers = {
            "title": b"<title>SafeYolo Desktop</title>" in page,
            "screen": b'id="screen"' in page,
            "script": b'src="/_safeyolo_desktop/page.js"' in page,
        }
        # Report only bounded status, size and marker operands. Response bodies
        # and authentication headers can contain secrets.
        assert response.status == 200 and len(page) <= 1_000_000 and all(page_markers.values()), (
            f"desktop page unavailable: status={response.status} bytes_read={len(page)} markers={page_markers}"
        )
        viewer_path = "/_safeyolo_desktop/viewer?" + uuid.uuid4().hex
        with connect(f"ws://{url.netloc}{viewer_path}", origin=f"http://{url.netloc}",
                     additional_headers={"Cookie": cookie.split(";", 1)[0]},
                     subprotocols=["binary"], proxy=None,
                     sock=socket.create_connection(("127.0.0.1", url.port), timeout=10)) as websocket:
            deadline = time.monotonic() + 10
            banner = b""
            # The guest bridge sends TCP reads as separate WebSocket messages.
            while len(banner) < 12:
                chunk = websocket.recv(timeout=max(0, deadline - time.monotonic()))
                assert isinstance(chunk, bytes) and b"RFB ".startswith((banner + chunk)[:4]), (
                    f"desktop returned no live VNC banner: type={type(chunk).__name__} bytes_read={len(banner) + len(chunk)}"
                )
                banner += chunk
            assert re.fullmatch(rb"RFB [0-9]{3}\.[0-9]{3}\n", banner), (
                f"desktop returned no live VNC banner: bytes_read={len(banner)}"
            )
            observed = {"agent_id": agent_id, "page_status": 200, "page_bytes": len(page),
                        "vnc_banner": banner.decode("ascii"),
                        "observation_scope": "unlocked native desktop page and live VNC banner; no visual interaction"}
            if after_banner:
                session = after_banner(websocket, cookie.split(";", 1)[0], url, observed)
    finally:
        connection.close()
    missing = "ag-" + uuid.uuid4().hex
    try:
        api.present_desktop(missing)
    except APIError as error:
        assert error.status_code == 404, f"missing desktop target did not report not found: status={error.status_code}"
    else:
        raise AssertionError("missing desktop target unexpectedly opened")
    result = {**observed, "url": presentation["url"], "missing_target_status": 404}
    if session is not None:
        result["session"] = session
    return result


def refused_viewer(url, cookie, *, retired=False):
    """Observe refusal before a viewer can deliver any VNC bytes."""
    try:
        with connect(f"ws://{url.netloc}/_safeyolo_desktop/viewer", origin=f"http://{url.netloc}",
                     additional_headers={"Cookie": cookie}, subprotocols=["binary"], proxy=None,
                     sock=socket.create_connection(("127.0.0.1", url.port), timeout=5)):
            raise AssertionError("unauthorized viewer completed its upgrade")
    except InvalidStatus as error:
        assert error.response.status_code in {401, 403, 404, 410}, "unexpected viewer refusal"
        return error.response.status_code
    except ConnectionRefusedError:
        assert retired, "live viewer observer was unavailable"
        return "listener-closed"


def desktop_action_observation(response: dict) -> dict:
    """Retain bounded diagnostics without copying private response content."""
    observed = {"http_status": response["status"], "reason": "unrecognized_response"}
    try:
        body = json.loads(response["body"])
    except json.JSONDecodeError:
        observed["reason"] = "non_json_response"
        return observed
    if not isinstance(body, dict):
        return observed
    diagnostic = body.get("diagnostic")
    code = diagnostic.get("code") if isinstance(diagnostic, dict) else None
    # These codes and errors come from the typed-action owner. Free text,
    # operator_details and unknown fields can contain session material.
    if code in ("host_settings_unavailable", "operator_preview_path_unavailable", "sandbox_unavailable",
                "desktop_missing", "tailnet_serve_permission", "tailscale_command_unavailable",
                "tailscale_disconnected", "tailnet_preview_unavailable"):
        observed["reason"] = code
    elif body.get("error") in ("Could not identify agent", "operator actions unavailable",
                               "trusted current-run requester identity required",
                               "requesting agent identity unavailable", "host agent registry unavailable",
                               "host agent identity is ambiguous", "requesting agent was removed or replaced"):
        observed["reason"] = body["error"]
    elif body.get("status") == "pending_approval":
        observed["reason"] = "pending_approval"
    return observed


def desktop_sharing(api, cli, root, worker, output):
    """Observe exact target/session binding and active viewer cessation."""
    from tests.blackbox.installed_shared_approvals import GUEST_REQUEST

    prefix = [cli, "--instance-dir", str(root)]
    policy = tomllib.loads((root / "policy.toml").read_text())
    ids = {name: policy["agents"][name]["agent_id"] for name in (worker, PEER)}
    report = {"status": "incomplete", "sessions": {}, "browser_opener": "owned headless marker; no visual UI"}
    path = output.with_name("desktop-effects.json")
    save(path, report)

    def request(name, method, route, body=None):
        command = shlex.join(["python3", "-c", GUEST_REQUEST,
                              json.dumps([method, "http://_safeyolo.proxy.internal" + route, body])])
        result = checked(guest_command_args(cli, name, command), timeout=60)
        return json.loads(result.stdout)

    peer = operator_desktop(api, ids[PEER])
    report["peer_positive"] = {key: value for key, value in peer.items() if key != "url"}
    save(path, report)
    for phase, ttl in (("revocation", 120), ("expiry", 10), ("stale-run", 120)):
        pending = request(worker, "POST", "/operator-actions",
                          {"action_id": "desktop.present", "parameters": {"ttl_seconds": ttl}})
        phase_report = {"request": desktop_action_observation(pending)}
        report["sessions"][phase] = phase_report
        save(path, report)
        assert pending["status"] == 202, f"desktop action request failed: {phase_report['request']}"
        identifier = json.loads(pending["body"])["approval_id"]
        action = api.approval(identifier)["action"]
        phase_report.update(approval_id=identifier, run=action["run"])
        save(path, report)
        assert action["agent_id"] == ids[worker] and action["presentation"] == "local"
        delegation_path = "/admin/approval-delegations/bb-desktop"
        proposal = {"expected_revision": None, "delegation": {
            "reviewers": [{"name": PEER, "agent_id": ids[PEER]}],
            "beneficiaries": [{"name": worker, "agent_id": ids[worker]}],
            "scopes": [{"type": "desktop_present", "run": action["run"], "presentation": "local",
                        "browser_urls": [None], "any_browser_url": False, "max_ttl_seconds": 120}],
            "expires_at": None, "grant_seconds": None, "gateway_once": False, "acknowledgment": None}}
        preview = api._request("POST", delegation_path + "/preview", json=proposal)
        proposal["delegation"] = preview["after"]
        proposal["delegation"]["acknowledgment"] = preview["acknowledgment"]
        proposal["authority"] = preview["authority"]
        api._request("POST", delegation_path + "/apply", json=proposal)
        revision = preview["revision"]
        revoked = False
        try:
            openings = root / "desktop-openings"
            before = len(openings.read_text().splitlines()) if openings.exists() else 0
            resolved = request(PEER, "POST", "/approvals/" + identifier + "/resolve",
                               {"decision": "approve", "delegation": "bb-desktop", "option": "once"})
            assert resolved["status"] == 200
            canonical = api.approval(identifier)
            assert canonical["result"]["status"] == "started" and canonical["result"]["preview_active"] is True
            assert len(openings.read_text().splitlines()) == before + 1
            repeated = request(PEER, "POST", "/approvals/" + identifier + "/resolve",
                               {"decision": "approve", "delegation": "bb-desktop", "option": "once"})
            assert repeated["status"] == 200 and len(openings.read_text().splitlines()) == before + 1

            def end_session(websocket, cookie, url, observed):
                nonlocal revoked
                phase_report["positive"] = dict(observed)
                save(path, report)
                observation = {"invalid_session": refused_viewer(url, "invalid=synthetic")}
                phase_report.update(observation)
                save(path, report)
                observation["wrong_target"] = refused_viewer(urlsplit(peer["url"]), cookie)
                phase_report.update(observation)
                save(path, report)
                if phase == "revocation":
                    api._request("POST", delegation_path + "/revoke", json={"expected_revision": revision})
                    revoked = True
                elif phase == "stale-run":
                    checked([*prefix, "agent", "stop", worker], timeout=130)
                    checked([*prefix, "agent", "start", worker, "--sandbox-only"], timeout=130)
                    current = json.loads(checked([*prefix, "agent", "status", worker]).stdout)
                    assert current["agent_id"] == ids[worker] and current["run_id"] != action["run"]["run_id"]
                    observation["new_run_id"] = current["run_id"]
                    phase_report.update(observation)
                    save(path, report)
                    prepare_guest_tests(cli, worker)
                else:
                    deadline = time.monotonic() + 15
                    while api.approval(identifier)["result"]["status"] != "expired":
                        assert time.monotonic() < deadline, "desktop authority did not expire"
                        time.sleep(.05)
                try:
                    websocket.recv(timeout=8)
                except ConnectionClosed:
                    observation["active_viewer_closed"] = True
                else:
                    raise AssertionError("retired desktop kept delivering viewer bytes")
                phase_report.update(observation)
                save(path, report)
                observation["old_session"] = refused_viewer(url, cookie, retired=True)
                phase_report.update(observation)
                save(path, report)
                return observation

            observed = operator_desktop(api, ids[worker], presentation=canonical["operator_preview"], after_banner=end_session)
            phase_report["positive"] = {key: value for key, value in observed.items() if key != "url"}
            save(path, report)
        finally:
            if not revoked:
                api._request("POST", delegation_path + "/revoke", json={"expected_revision": revision})
    report["status"] = "passed"
    save(path, report)
    return report


def operator_restart(cli: str, root: Path, agent: str, marker: str, terminal: dict,
                     sinkhole: SinkholeClient, *, platform: str) -> dict:
    """Return to the same installed target and observe new usable traffic."""
    prefix = [cli, "--instance-dir", str(root)]
    instance = (root / "data/instance_id").read_text()
    policy = _sha256(root / "policy.toml")
    before = guest(cli, agent, platform, marker + "-before", "operator-traffic")
    checked([*prefix, "agent", "stop", agent], timeout=130)
    stopped = json.loads(checked([*prefix, "agent", "status", agent]).stdout)
    assert stopped["runtime_state"] == "stopped", stopped
    absent = subprocess.run([*prefix, "agent", "attach", agent], capture_output=True, text=True, timeout=10)
    assert absent.returncode != 0 and "terminal" in absent.stderr.lower(), "attach hid the stopped target"
    checked([*prefix, "stop"], timeout=60)
    if platform == "vz":
        checked([*prefix, "coord", "start", "--client-port", "46370", "--monitor-port", "46372"])
    checked([*prefix, "start"], timeout=60)
    checked([*prefix, "agent", "start", agent], timeout=130)
    prepare_guest_tests(cli, agent)
    returned = json.loads(checked([*prefix, "agent", "status", agent]).stdout)
    assert returned["runtime_state"] == "running" and returned["agent_id"] == terminal["agent_id"], returned
    assert returned["run_id"] != terminal["run_id"], "restart reused the stopped guest run"
    assert (root / "data/instance_id").read_text() == instance and _sha256(root / "policy.toml") == policy
    after = guest(cli, agent, platform, marker + "-after", "operator-traffic")
    history = guest(cli, agent, platform, marker, "coord-read", message="p3-first:" + marker)
    paths = {f"/installed-flow/{marker}-{phase}/{agent}" for phase in ("before", "after")}
    requests = [row for row in sinkhole.get_requests() if row.path in paths]
    assert len(requests) == 2 and {row.host for row in requests} == {"api.github.com"}, "restart origin delivery mismatch"
    assert {row.path for row in requests} == paths, "restart did not deliver both fresh markers"
    return {"instance_id": instance.strip(), "agent_id": returned["agent_id"],
            "before_run_id": terminal["run_id"], "after_run_id": returned["run_id"],
            "traffic_before": before, "traffic_after": after, "retained_coord": history,
            "allowed_origin_deliveries": 2, "denied_origin_deliveries": 0}


def main() -> None:
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit("access test timed out"))
    signal.signal(signal.SIGALRM, lambda _signum, _frame: sys.exit("access test exceeded eight minutes"))
    signal.alarm(8 * 60)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--platform", choices=("systrap", "vz"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install-commit", required=True)
    parser.add_argument("--operator-journey", action="store_true",
                        help="Observe terminal, desktop and restart in this systrap or VZ access instance")
    args = parser.parse_args()
    receipt = ProcedureReceipt('access', args.output)
    config_dir = args.config_dir.resolve()
    selected_checkout = os.environ.get("SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT")
    install_checkout = Path(selected_checkout).resolve() if selected_checkout else None
    if install_checkout is not None:
        revision = checked(["git", "-C", str(install_checkout), "rev-parse", "HEAD"]).stdout.strip()
        assert revision == args.install_commit, f"installed {revision}, expected {args.install_commit}"
    runtime = json.loads(args.runtime.read_text())
    identity = installed_identity(runtime, install_checkout, expected_revision=args.install_commit)
    native = _native_config(config_dir / "config.toml", config_dir)["raw"]
    policy = tomllib.loads((config_dir / "policy.toml").read_text())
    assert native["parent_proxy"].startswith("http://127.0.0.1:")
    assert Path(native["upstream_ca_file"]).is_file()
    assert policy["hosts"]["evil.com"]["egress"] == "deny"
    assert policy["hosts"]["legitimate-api.com"]["service"] == "p3_basic"
    substrate = runtime["substrate"]
    expected = "virtualization.framework" if args.platform == "vz" else "gvisor"
    assert substrate["status"] == "discovered" and substrate["kind"] == expected, substrate
    substrate["sha256"] = _sha256(Path(substrate["path"]))
    listener = next(item for item in runtime["guest_ingress"]["agents"] if item["agent_id"] == args.agent)
    if args.platform != "vz":
        bridge = runsc_identity(config_dir, args.agent, Path(listener["path"]), platform=args.platform)
    else:
        bridge = {"platform": "vz", "host_listener": listener["path"], "guest_forwarder": "vsock:2:1080"}
    cli = identity["cli"]["path"]
    receipt.checkpoint('identity')
    admin = AdminAPI(
        base_url=f"http://127.0.0.1:{runtime['runtime']['readiness']['admin_port']}", token=(config_dir / "data/admin_token").read_text().strip()
    )
    fixture = json.loads((config_dir / "p3-fixture.json").read_text())
    marker = "p3-" + uuid.uuid4().hex
    sinkhole = SinkholeClient(os.environ.get("SINKHOLE_API", "http://127.0.0.1:19999"))
    peer_added = False
    stolen_token_file = config_dir / "agents" / PEER / "config-share" / "p3-stolen-token"
    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        sinkhole.clear_requests()
        terminal = None
        if args.operator_journey:
            # The runner created/booted this owned agent. Use an ordinary native
            # shell command for attachment, carrying forward accepted H4/Codex
            # results rather than starting another model or using a fake login.
            checked(guest_command_args(cli, args.agent, "/safeyolo/guest-desktop check"))
            checked([cli, "--instance-dir", str(config_dir), "--json", "policy", "apply", str(config_dir / "policy.toml")])
            terminal = operator_terminal(cli, config_dir, args.agent, marker)
        repository = Path(__file__).resolve().parents[2]
        checked([cli, "agent", "create", PEER, "--workspace", str(repository)], timeout=30)
        peer_added = True
        checked([cli, "agent", "start", PEER, "--sandbox-only"], timeout=120)
        prepare_guest_tests(cli, PEER)
        peer_listeners = [item for item in _agent_listeners(config_dir) if item["agent_id"] == PEER]
        assert len(peer_listeners) == 1 and peer_listeners[0]["path"] != listener["path"]
        peer_socket = Path(peer_listeners[0]["path"])
        assert peer_socket.is_socket(), "second guest has no installed native proxy listener"
        peer_bridge = (
            runsc_identity(config_dir, PEER, peer_socket, platform=args.platform)
            if args.platform != "vz"
            else {"platform": "vz", "host_listener": str(peer_socket), "guest_forwarder": "vsock:2:1080"}
        )
        access = authorize_access(admin, cli, args.agent, args.platform, marker, fixture["credential_name"])
        basic = guest(cli, args.agent, args.platform, marker, "basic")
        token = basic.pop("token")  # Transient synthetic token is absent from the report.
        descriptor = os.open(stolen_token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "w") as secret_file:
            secret_file.write(token + "\n")
        peer_denial = guest(cli, PEER, args.platform, marker, "peer-denial")
        receipt.checkpoint('service')
        stolen_token_file.unlink()
        prompt = guest(cli, args.agent, args.platform, marker, "contract-prompt")
        assert not any(row.path == "/p3/write" for row in sinkhole.get_requests())
        risk = wait_for_approval(admin, "gateway_risky_route", agent=args.agent, service="p3_contract",
                                request_id=prompt["request_id"])
        grant_id = approve(risk, admin)
        assert isinstance(grant_id, str) and grant_id
        contract = guest(cli, args.agent, args.platform, marker, "contract-effect")
        assert all(row.get("grant_id") != grant_id for row in admin.list_gateway_grants()["grants"])
        receipt.checkpoint('contract')
        context = guest(cli, args.agent, args.platform, marker, "context")
        owned_flows = {
            agent: guest(cli, agent, args.platform, marker, "flow-seed")
            for agent in (args.agent, PEER)
        }
        flow_deliveries = sinkhole.get_requests(host="api.github.com")
        expected_flow_paths = {f"/installed-flow/{marker}/{agent}" for agent in (args.agent, PEER)}
        assert len(flow_deliveries) == 2 and {row.path for row in flow_deliveries} == expected_flow_paths
        assert all(row.method == "GET" for row in flow_deliveries)
        flow_ownership = []
        for agent, peer in ((args.agent, PEER), (PEER, args.agent)):
            foreign = owned_flows[peer]
            flow_ownership.append(guest(
                cli, agent, args.platform, marker, "flow-peer-denial", peer=peer,
                flow_id=foreign["flow_id"], message=foreign["request_id"],
            ))
        coord_backing = setup_coord(cli, config_dir, args.agent, PEER)
        receipt.checkpoint('flow-ownership')
        coord = run_coord(cli, args.agent, args.platform, marker)
        assert coord["room_id"] == coord_backing["room_id"]
        collaboration = run_collaboration_and_event(admin, cli, config_dir, args.agent, args.platform, marker, admin.token)
        receipt.checkpoint('coord')
        ws = guest(cli, args.agent, args.platform, marker, "websocket")
        assert ws["server"] == "server:p2-" + marker[3:]
        ws_state = control("GET", "/p2/state/p2-" + marker[3:])["websockets"]
        assert len(ws_state) == 1 and ws_state[0]["status"] == "complete", ws_state
        assert ws_state[0]["client"] == ws["client"], ws_state
        origin = check_origin(sinkhole, fixture["credential"], marker)
        custody = host_secret_custody(cli, config_dir, args.agent, fixture["credential"])
        tls_paths = {row["tls_origin_path"] for row in custody}
        tls_deliveries = [row for row in sinkhole.get_requests(host="api.github.com") if row.path in tls_paths]
        assert len(tls_deliveries) == 2 and {row.path for row in tls_deliveries} == tls_paths
        assert not any(fixture["credential"] in json.dumps(vars(row)) for row in sinkhole.get_requests()
                       if row.host != "legitimate-api.com" and row.host != "httpbin.org"), "vault value reached an unauthorized origin"
        receipt.checkpoint('host-secret-custody')
        inspector = inspect_traffic(admin, args.output, args.agent, marker)
        receipt.checkpoint('origin')
        report = {
            "status": "desktop_incomplete",
            "source_revision": args.install_commit,
            "platform": args.platform,
            "host": runtime["host"],
            "installed": identity,
            "substrate": substrate,
            "bridge": bridge,
            "peer_bridge": peer_bridge,
            "runtime_config": {"parent_proxy": native["parent_proxy"], "upstream_ca_file": native["upstream_ca_file"]},
            "service": {
                "requested": access["service_request_id"],
                "authorized_origin": basic,
                "unauthorized_peer": peer_denial,
            },
            "contract": {
                "binding_request": access["binding_request_id"],
                "challenge_after_binding": access["challenge_after_binding"],
                "risk_request": prompt["request_id"],
                "effect": contract,
            },
            "context_and_evidence": context,
            "guest_flow_ownership": {"owned_flows": owned_flows, "peer_denials": flow_ownership,
                                     "origin_paths": sorted(expected_flow_paths), "origin_deliveries": len(flow_deliveries)},
            "coord_backing": coord_backing,
            "coord": coord,
            "collaboration_and_event": collaboration,
            "websocket_peer": ws_state,
            "origin": origin,
            "host_secret_custody": custody,
            "inspector": inspector,
        }
        def save():
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        save()
        report["desktop_sharing"] = desktop_sharing(admin, cli, config_dir, args.agent, args.output)
        receipt.checkpoint('desktop-sharing', **report["desktop_sharing"])
        report["status"] = "abrupt_incomplete"
        save()
        abrupt_authority(cli, config_dir, args.agent, args.platform, marker, admin, sinkhole,
                         grant_id, identity, report, save)
        receipt.checkpoint('abrupt-failure')
        if args.operator_journey:
            # Retain the already reached access observations if a later operator
            # step fails. A partial result is not a completed journey.
            report["status"] = "operator_incomplete"
            report["operator"] = {"terminal": terminal}
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            report["operator"]["desktop"] = operator_desktop(admin, terminal["agent_id"])
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            report["operator"]["restart"] = operator_restart(
                cli, config_dir, args.agent, marker, terminal, sinkhole, platform=args.platform,
            )
        report["status"] = "journeys_passed"
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{args.platform} access, host-secret custody and abrupt recovery verified ({args.output})")
    finally:
        stolen_token_file.unlink(missing_ok=True)
        sinkhole.close()
        if peer_added:
            checked([cli, "agent", "stop", PEER], timeout=30)
            assert not (config_dir / "agents" / PEER / "container.pid").exists(), "disposable peer guest did not stop"
    receipt.checkpoint('finished')


if __name__ == "__main__":
    main()
