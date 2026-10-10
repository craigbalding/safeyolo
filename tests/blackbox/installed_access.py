#!/usr/bin/env python3
"""Exercise installed access through two live systrap or VZ guests.

Retain service and contract binding/risk approvals, exact credential injection
and live peer denial, populated owner-positive/peer-negative guest flow search
and detail, test-context/trace evidence, real NATS Coord and attention, operator
Plumb approval/exchange/closure, WebSocket peer effects and traffic-inspector
filter/transcript/export. These observations stay in one installed composition.
"""

from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import pty
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .guest_exec import guest_command_args
    from .host.sinkhole_client import SinkholeClient
    from .installed_host_smoke import _agent_map, _native_config, _sha256
    from .installed_ingress import installed_identity, runsc_identity
    from .installed_workloads import control
else:
    from guest_exec import guest_command_args
    from host.sinkhole_client import SinkholeClient
    from installed_host_smoke import _agent_map, _native_config, _sha256
    from installed_ingress import installed_identity, runsc_identity
    from installed_workloads import control
from urllib.parse import urlencode, urlsplit

from websockets.sync.client import connect

from safeyolo.api import AdminAPI, APIError
from safeyolo.operator_approvals import approve

ROOM = "p3-owned-room"
PEER = "bbpeer"


def checked(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    assert result.returncode == 0, f"{command[0]} exited {result.returncode}: {result.stderr[-700:]}"
    return result


def guest_command(cli: str, agent: str, platform: str, marker: str, phase: str, **options: str | int) -> list[str]:
    request = [
        "python3",
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
    while time.monotonic() < deadline:
        matches = [
            row
            for row in api.pending_approvals()
            if row.get("approval", {}).get("approval_type") == approval_type
            and (request_id is None or row.get("request_id") == request_id)
            and (agent is None or row.get("agent") == agent)
            and (service is None or row.get("approval", {}).get("target") == service)
        ]
        if len(matches) == 1:
            return matches[0]
        time.sleep(0.05)
    raise AssertionError(f"operator did not see one {approval_type} request for {agent}/{service}/{request_id}")


def approve_service(api: AdminAPI, agent: str, service: str, credential: str) -> None:
    event = wait_for_approval(api, "service", agent=agent, service=service)
    assert event["agent"] == agent and event["approval"]["target"] == service, event
    assert approve(event, api, service_credential=credential) in {"authorized", "ok"}


def setup_coord(cli: str, root: Path, primary: str, peer: str) -> dict:
    """Provision the real native Coord owner rather than the Python reference."""
    prefix = [cli, "--root", str(root), "coord"]
    status = json.loads(checked([*prefix, "status"]).stdout)
    assert status["state"] == "running", "owned native NATS is not running"
    room = json.loads(checked([*prefix, "room", "create", ROOM]).stdout)
    identities = {}
    for name in (primary, peer):
        granted = json.loads(checked([*prefix, "grant", ROOM, name]).stdout)
        identities[name] = granted
    return {"instance_id": (root / "data/instance_id").read_text().strip(),
            "room_id": room["room_id"], "agents": identities}


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


def run_plumb_and_event(
    api: AdminAPI, cli: str, primary: str, platform: str, marker: str, operator_token: str
) -> dict:
    admin = urlsplit(api.base_url)
    assert admin.scheme == "http" and admin.hostname == "127.0.0.1" and admin.port
    with connect(
        f"ws://127.0.0.1:{admin.port}/admin/events",
        additional_headers={"Authorization": f"Bearer {operator_token}"},
        proxy=None,
    ) as websocket:
        requested = guest(cli, primary, platform, marker, "plumb-request", peer=PEER)
        event = None
        for _ in range(5):
            candidate = json.loads(websocket.recv(timeout=5))
            if candidate.get("approval", {}).get("key") == requested["request_id"]:
                event = candidate
                break
        assert event is not None and event.get("approval", {}).get("approval_type") == "plumb", (
            "authenticated operator stream missed the selected Plumb approval"
        )
        pending = api.plumb_pending()["pending"]
        assert any(row["request_id"] == requested["request_id"] for row in pending), pending
        approved = api.plumb_approve(requested["request_id"], ttl_seconds=120)
        conversation = approved["conversation_id"]
        sent = guest(cli, primary, platform, marker, "plumb-send", conversation=conversation)
        read = guest(cli, PEER, platform, marker, "plumb-read", conversation=conversation)
        assert sent["message_id"] and read["message_count"] >= 1
        closed = api.plumb_close(conversation)
        assert closed.get("closed") == conversation, closed
        peer_closed = guest(cli, PEER, platform, marker, "plumb-closed", conversation=conversation)
        return {
            "request_id": requested["request_id"],
            "operator_event": event["event"],
            "conversation_id": conversation,
            "peer_message_id": sent["message_id"],
            "closed_read_status": peer_closed["closed_read_status"],
        }


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
    prefix = [cli, "--root", str(root), "agent"]
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


def operator_desktop(api: AdminAPI, agent_id: str) -> dict:
    """Open the native Admin presentation, unlock noVNC and reach live VNC."""
    presentation = api.present_desktop(agent_id)
    assert presentation["agent_id"] == agent_id, "desktop returned another target"
    url = urlsplit(presentation["url"])
    assert url.scheme == "http" and url.hostname == "127.0.0.1" and url.port, "fixture requires local presentation"
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    try:
        connection.request("POST", "/_safeyolo_preview/unlock",
                           body=urlencode({"code": presentation["unlock_code"]}),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        response = connection.getresponse()
        response.read()
        assert response.status == 303, "desktop unlock failed"
        cookie = response.getheader("Set-Cookie")
        assert cookie, "desktop unlock did not return its session cookie"
        connection.request("GET", url.path, headers={"Cookie": cookie.split(";", 1)[0]})
        response = connection.getresponse()
        page = response.read(1_000_001)
        assert response.status == 200 and len(page) <= 1_000_000 and b"novnc" in page.lower(), "desktop page unavailable"
        with connect(f"ws://{url.netloc}/websockify", origin=f"http://{url.netloc}",
                     additional_headers={"Cookie": cookie.split(";", 1)[0]}, proxy=None) as websocket:
            banner = websocket.recv(timeout=10)
            assert isinstance(banner, bytes) and banner.startswith(b"RFB "), "desktop returned no live VNC banner"
    finally:
        connection.close()
    missing = "ag-" + uuid.uuid4().hex
    try:
        api.present_desktop(missing)
    except APIError as error:
        assert error.status_code == 404, "missing desktop target did not report not found"
    else:
        raise AssertionError("missing desktop target unexpectedly opened")
    return {"agent_id": agent_id, "url": presentation["url"], "page_status": 200,
            "vnc_banner": banner.decode("ascii"), "missing_target_status": 404}


def operator_restart(cli: str, root: Path, agent: str, marker: str, terminal: dict,
                     sinkhole: SinkholeClient) -> dict:
    """Return to the same installed target and observe new usable traffic."""
    prefix = [cli, "--root", str(root)]
    instance = (root / "data/instance_id").read_text()
    policy = _sha256(root / "policy.toml")
    before = guest(cli, agent, "systrap", marker + "-before", "operator-traffic")
    checked([*prefix, "agent", "stop", agent], timeout=130)
    stopped = json.loads(checked([*prefix, "agent", "status", agent]).stdout)
    assert stopped["runtime_state"] == "stopped", stopped
    absent = subprocess.run([*prefix, "agent", "attach", agent], capture_output=True, text=True, timeout=10)
    assert absent.returncode != 0 and "terminal" in absent.stderr.lower(), "attach hid the stopped target"
    checked([*prefix, "stop"], timeout=60)
    checked([*prefix, "start"], timeout=60)
    checked([*prefix, "agent", "start", agent], timeout=130)
    returned = json.loads(checked([*prefix, "agent", "status", agent]).stdout)
    assert returned["runtime_state"] == "running" and returned["agent_id"] == terminal["agent_id"], returned
    assert returned["run_id"] != terminal["run_id"], "restart reused the stopped guest run"
    assert (root / "data/instance_id").read_text() == instance and _sha256(root / "policy.toml") == policy
    after = guest(cli, agent, "systrap", marker + "-after", "operator-traffic")
    history = guest(cli, agent, "systrap", marker, "coord-read", message="p3-first:" + marker)
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
                        help="Observe the continuous Ubuntu terminal/desktop/restart path in this access instance")
    args = parser.parse_args()
    if args.operator_journey and args.platform != "systrap":
        parser.error("--operator-journey requires systrap")
    config_dir = args.config_dir.resolve()
    install_checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
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
            checked([cli, "--root", str(config_dir), "policy", "apply", str(config_dir / "policy.toml")])
            terminal = operator_terminal(cli, config_dir, args.agent, marker)
        repository = Path(__file__).resolve().parents[2]
        checked([cli, "agent", "create", PEER, "--workspace", str(repository)], timeout=30)
        peer_added = True
        checked([cli, "agent", "start", PEER, "--sandbox-only"], timeout=120)
        peer_listeners = [item for item in _agent_map(config_dir) if item["agent_id"] == PEER]
        assert len(peer_listeners) == 1 and peer_listeners[0]["path"] != listener["path"]
        peer_socket = Path(peer_listeners[0]["path"])
        assert peer_socket.is_socket(), "second guest has no installed native proxy listener"
        peer_bridge = (
            runsc_identity(config_dir, PEER, peer_socket, platform=args.platform)
            if args.platform != "vz"
            else {"platform": "vz", "host_listener": str(peer_socket), "guest_forwarder": "vsock:2:1080"}
        )
        first = guest(cli, args.agent, args.platform, marker, "access")
        approve_service(admin, args.agent, "p3_basic", fixture["credential_name"])
        binding = wait_for_approval(admin, "contract_binding", agent=args.agent, service="p3_contract")
        assert approve(binding, admin) in {"bound", "ok"}
        contract_request = guest(cli, args.agent, args.platform, marker, "contract-access")
        authorized = admin.authorize_service(
            agent=args.agent, service="p3_contract", capability="writer", credential=fixture["credential_name"]
        )
        assert authorized["status"] == "authorized", authorized
        basic = guest(cli, args.agent, args.platform, marker, "basic")
        token = basic.pop("token")  # Transient synthetic token is absent from the report.
        descriptor = os.open(stolen_token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "w") as secret_file:
            secret_file.write(token + "\n")
        peer_denial = guest(cli, PEER, args.platform, marker, "peer-denial")
        stolen_token_file.unlink()
        prompt = guest(cli, args.agent, args.platform, marker, "contract-prompt")
        assert not any(row.path == "/p3/write" for row in sinkhole.get_requests())
        risk = wait_for_approval(admin, "gateway_route", request_id=prompt["request_id"])
        grant_id = approve(risk, admin)
        assert isinstance(grant_id, str) and grant_id
        contract = guest(cli, args.agent, args.platform, marker, "contract-effect")
        assert all(row.get("grant_id") != grant_id for row in admin.list_gateway_grants()["grants"])
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
        coord = run_coord(cli, args.agent, args.platform, marker)
        assert coord["room_id"] == coord_backing["room_id"]
        plumb = run_plumb_and_event(admin, cli, args.agent, args.platform, marker, admin.token)
        ws = guest(cli, args.agent, args.platform, marker, "websocket")
        assert ws["server"] == "server:p2-" + marker[3:]
        ws_state = control("GET", "/p2/state/p2-" + marker[3:])["websockets"]
        assert len(ws_state) == 1 and ws_state[0]["status"] == "complete", ws_state
        assert ws_state[0]["client"] == ws["client"], ws_state
        origin = check_origin(sinkhole, fixture["credential"], marker)
        inspector = inspect_traffic(admin, args.output, args.agent, marker)
        report = {
            "status": "journeys_passed",
            "source_revision": args.install_commit,
            "platform": args.platform,
            "host": runtime["host"],
            "installed": identity,
            "substrate": substrate,
            "bridge": bridge,
            "peer_bridge": peer_bridge,
            "runtime_config": {"parent_proxy": native["parent_proxy"], "upstream_ca_file": native["upstream_ca_file"]},
            "service": {
                "requested": first["service_request_id"],
                "authorized_origin": basic,
                "unauthorized_peer": peer_denial,
            },
            "contract": {
                "binding_request": first["binding_request_id"],
                "challenge_after_binding": contract_request["contract_challenge"],
                "risk_request": prompt["request_id"],
                "effect": contract,
            },
            "context_and_evidence": context,
            "guest_flow_ownership": {"owned_flows": owned_flows, "peer_denials": flow_ownership,
                                     "origin_paths": sorted(expected_flow_paths), "origin_deliveries": len(flow_deliveries)},
            "coord_backing": coord_backing,
            "coord": coord,
            "collaboration_and_event": plumb,
            "websocket_peer": ws_state,
            "origin": origin,
            "inspector": inspector,
        }
        if args.operator_journey:
            # Retain the already reached access observations if a later operator
            # step fails. A partial result is not a completed journey.
            report["status"] = "operator_incomplete"
            report["operator"] = {"terminal": terminal}
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            report["operator"]["desktop"] = operator_desktop(admin, terminal["agent_id"])
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            report["operator"]["restart"] = operator_restart(cli, config_dir, args.agent, marker, terminal, sinkhole)
            report["status"] = "journeys_passed"
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{args.platform} access: six installed guest journeys and operator effects verified ({args.output})")
    finally:
        stolen_token_file.unlink(missing_ok=True)
        sinkhole.close()
        if peer_added:
            checked([cli, "agent", "stop", PEER], timeout=30)
            assert not (config_dir / "agents" / PEER / "container.pid").exists(), "disposable peer guest did not stop"


if __name__ == "__main__":
    main()
