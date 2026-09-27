#!/usr/bin/env python3
"""Check six retained P3 journeys on an installed proxy and real guest bridge."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import select
import shlex
import signal
import subprocess
import sys
import time
import tomllib
import uuid
from pathlib import Path

from host.sinkhole_client import SinkholeClient
from installed_host_smoke import _agent_map, _sha256
from kvm_p1_ingress import installed_identity, runsc_identity
from p2_installed_linux import control
from websockets.sync.client import connect

from safeyolo.agents_store import get_agent_id
from safeyolo.api import AdminAPI
from safeyolo.coord import api as coord_api
from safeyolo.coord.identity import new_operation_id
from safeyolo.coord.nats_runtime import is_healthy
from safeyolo.core.operator_event_server import OperatorEventServer
from safeyolo.operator_approvals import approve
from safeyolo.traffic_inspector import TrafficInspector

FROZEN_R = "36462777e23c368adda65c9d880fe2fd8c8c76cb"
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
        "tests.blackbox.isolation.p3_guest_journeys",
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
    return [cli, "agent", "shell", agent, "-c", "cd /workspace && " + shlex.join(request)]


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


def setup_coord(primary: str, peer: str) -> dict:
    assert is_healthy(), "owned NATS backing service is not healthy"
    instance = coord_api.bootstrap()
    room_id = asyncio.run(coord_api.create_room(ROOM))
    identities = {}
    for name in (primary, peer):
        agent_id = get_agent_id(name)
        assert agent_id and agent_id.startswith("ag-"), name
        coord_api.grant(ROOM, "agent", agent_id, operation_id=new_operation_id())
        identities[name] = agent_id
    return {"instance_id": instance, "room_id": room_id, "agents": identities}


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
    api: AdminAPI, config_dir: Path, cli: str, primary: str, platform: str, marker: str, operator_token: str
) -> dict:
    audit = config_dir / "logs" / "safeyolo.jsonl"
    server = OperatorEventServer(log_path=audit, token=operator_token, port=0)
    server.start()
    try:
        with connect(
            f"ws://127.0.0.1:{server.port}/admin/events",
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
    finally:
        server.stop()


def inspect_traffic(api: AdminAPI, output: Path, primary: str, marker: str) -> dict:
    inspector = TrafficInspector(api)
    inspector.set_scope("agent", primary)
    inspector.set_filter("~u p3")
    asyncio.run(inspector.refresh())
    assert "unavailable" not in inspector.notice.lower(), inspector.notice
    assert inspector.scope.get("agent") == primary
    assert all(row.get("agent") == primary and "p3" in row.get("url", "") for row in inspector.flows)
    rows = [row for row in inspector.flows if "/p3/read" in row.get("url", "")]
    assert rows, inspector.rows_text()
    selected = rows[0]
    index = next(i for i, row in enumerate(inspector.flows) if row["id"] == selected["id"])
    inspector.select(index)
    asyncio.run(inspector.refresh())
    assert inspector.detail and inspector.detail["id"] == selected["id"]
    exported = output.parent / f"p3-selected-{marker}.raw_request"
    inspector.queue_export(selected["id"], "raw_request", str(exported))
    asyncio.run(inspector.refresh())
    assert exported.is_file() and b"/p3/read" in exported.read_bytes(), inspector.export_report

    inspector.set_filter("~u p2/ws")
    asyncio.run(inspector.refresh())
    assert all(row.get("agent") == primary and "/p2/ws" in row.get("url", "") for row in inspector.flows)
    ws_rows = [row for row in inspector.flows if "/p2/ws/" in row.get("url", "")]
    assert ws_rows, inspector.rows_text()
    index = next(i for i, row in enumerate(inspector.flows) if row["id"] == ws_rows[0]["id"])
    inspector.select(index)
    asyncio.run(inspector.refresh())
    inspector.toggle_websocket()
    asyncio.run(inspector.refresh())
    assert inspector.websocket_mode and len(inspector.transcript.messages) >= 2, inspector.detail_text()
    api.set_traffic_filter("")
    return {
        "http_flows_visible": len(rows),
        "selected_flow_id": selected["id"],
        "selected_export": str(exported),
        "selected_export_bytes": exported.stat().st_size,
        "websocket_flow_id": ws_rows[0]["id"],
        "transcript_messages": len(inspector.transcript.messages),
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


def main() -> None:
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit("P3 pilot timed out"))
    signal.signal(signal.SIGALRM, lambda _signum, _frame: sys.exit("P3 pilot exceeded eight minutes"))
    signal.alarm(8 * 60)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--platform", choices=("systrap", "vz"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    install_checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
    revision = checked(["git", "-C", str(install_checkout), "rev-parse", "HEAD"]).stdout.strip()
    assert revision == FROZEN_R, f"pilot installed {revision}, expected frozen R"
    runtime = json.loads(args.runtime.read_text())
    identity = installed_identity(runtime, install_checkout, frozen_revision=FROZEN_R)
    native = json.loads((config_dir / "data/native.json").read_text())
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
        base_url=f"http://127.0.0.1:{native['admin_port']}", token=(config_dir / "data/admin_token").read_text().strip()
    )
    fixture = json.loads((config_dir / "p3-fixture.json").read_text())
    marker = "p3-" + uuid.uuid4().hex
    sinkhole = SinkholeClient("http://127.0.0.1:19999")
    peer_added = False
    stolen_token_file = config_dir / "agents" / PEER / "config-share" / "p3-stolen-token"
    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        sinkhole.clear_requests()
        repository = Path(__file__).resolve().parents[2]
        checked([cli, "agent", "add", PEER, str(repository), "--no-run"], timeout=30)
        peer_added = True
        checked([cli, "agent", "run", PEER, "--sandbox-only"], timeout=120)
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
        coord_backing = setup_coord(args.agent, PEER)
        coord = run_coord(cli, args.agent, args.platform, marker)
        assert coord["room_id"] == coord_backing["room_id"]
        plumb = run_plumb_and_event(admin, config_dir, cli, args.agent, args.platform, marker, admin.token)
        ws = guest(cli, args.agent, args.platform, marker, "websocket")
        assert ws["server"] == "server:p2-" + marker[3:]
        ws_state = control("GET", "/p2/state/p2-" + marker[3:])["websockets"]
        assert len(ws_state) == 1 and ws_state[0]["status"] == "complete", ws_state
        assert ws_state[0]["client"] == ws["client"], ws_state
        origin = check_origin(sinkhole, fixture["credential"], marker)
        inspector = inspect_traffic(admin, args.output, args.agent, marker)
        report = {
            "status": "journeys_passed",
            "frozen_revision": FROZEN_R,
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
            "coord_backing": coord_backing,
            "coord": coord,
            "collaboration_and_event": plumb,
            "websocket_peer": ws_state,
            "origin": origin,
            "inspector": inspector,
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{args.platform} P3: six installed guest journeys and operator effects verified ({args.output})")
    finally:
        stolen_token_file.unlink(missing_ok=True)
        sinkhole.close()
        if peer_added:
            checked([cli, "agent", "stop", PEER], timeout=30)
            assert not (config_dir / "agents" / PEER / "container.pid").exists(), "disposable peer guest did not stop"


if __name__ == "__main__":
    main()
