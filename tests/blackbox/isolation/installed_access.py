#!/usr/bin/env python3
"""Run installed access calls through a real guest's proxy forwarder."""

from __future__ import annotations

import argparse
import http.client
import json
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from tests.blackbox.isolation.installed_ingress import AGENT_API, bridge
from tests.blackbox.isolation.installed_workloads import websocket

BASIC_HOST = "legitimate-api.com"
CONTRACT_HOST = "httpbin.org"
FLOW_HOST = "api.github.com"
ROOM = "p3-owned-room"
MAX_BODY = 1_000_000


def exchange(
    method: str,
    target: str,
    *,
    payload: dict | None = None,
    bearer: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict, bytes]:
    """Send one request through the configured guest bridge only."""
    url = urlsplit(target)
    assert url.scheme == "http" and url.netloc, target
    fields = {"Host": url.netloc, **(headers or {})}
    if bearer is not None:
        fields["Authorization"] = f"Bearer {bearer}"
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    if body is not None:
        fields["Content-Type"] = "application/json"
    client = http.client.HTTPConnection("127.0.0.1", 8080, timeout=12)
    try:
        client.request(method, target, body=body, headers=fields)
        response = client.getresponse()
        content = response.read(MAX_BODY + 1)
        assert len(content) <= MAX_BODY, f"{target} response exceeded the access bound"
        return response.status, {name.lower(): value for name, value in response.getheaders()}, content
    finally:
        client.close()


def api(method: str, path: str, *, payload: dict | None = None) -> tuple[int, dict, dict]:
    token = Path("/app/agent_token").read_text().strip()
    assert token and "\n" not in token
    status, headers, raw = exchange(method, AGENT_API + path, payload=payload, bearer=token)
    value = json.loads(raw)
    assert isinstance(value, dict), (status, path)
    return status, headers, value


def service_token(service: str) -> str:
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        status, _, view = api("GET", "/gateway/services")
        assert status == 200, view
        token = view.get("authorized", {}).get(service, {}).get("token")
        if isinstance(token, str) and token.startswith("sgw_"):
            return token
        time.sleep(0.1)
    raise AssertionError(f"authorized {service} gateway token did not appear")


def wait_for_owned_flow(agent: str, host: str, request_id: str, *, limit: int = 100) -> dict:
    """Wait for the asynchronous store without accepting another request or owner."""
    deadline = time.monotonic() + 7
    while True:
        search = api("POST", "/api/flows/search", payload={"host": host, "limit": limit})
        assert search[0] == 200, search
        rows = search[2]["flows"]
        assert all(row["agent_id"] == row["evidence_owner"] == agent for row in rows), search
        owned = [row for row in rows if row["request_id"] == request_id]
        if owned:
            assert len(owned) == 1, owned
            return owned[0]
        assert time.monotonic() < deadline, f"guest-owned flow did not persist: {request_id}"
        time.sleep(0.1)


def access() -> dict:
    basic = api(
        "POST",
        "/gateway/request-access",
        payload={
            "service": "p3_basic",
            "capability": "reader",
            "reason": "installed access test",
        },
    )
    assert basic[0] == 202 and basic[1].get("x-safeyolo-request-id", "").startswith("req-"), basic
    challenge = api(
        "POST",
        "/gateway/request-access",
        payload={
            "service": "p3_contract",
            "capability": "writer",
            "reason": "installed access test",
        },
    )
    assert challenge[0] == 200 and challenge[2].get("decision") == "needs_contract_binding", challenge
    binding = api(
        "POST",
        "/gateway/submit-binding",
        payload={
            "service": "p3_contract",
            "capability": "writer",
            "bindings": {"project": "alpha", "ticket": "T-1"},
            "purpose_code": "write",
        },
    )
    assert binding[0] == 202 and binding[1].get("x-safeyolo-request-id", "").startswith("req-"), binding
    return {
        "service_request_id": basic[1]["x-safeyolo-request-id"],
        "binding_request_id": binding[1]["x-safeyolo-request-id"],
        "contract_challenge": challenge[2]["decision"],
    }


def contract_access() -> dict:
    # A contract capability always challenges request-access. The operator
    # approves the binding and then authorizes the service through Admin API.
    result = api(
        "POST",
        "/gateway/request-access",
        payload={"service": "p3_contract", "capability": "writer", "reason": "approved binding"},
    )
    assert result[0] == 200 and result[2].get("decision") == "needs_contract_binding", result
    assert result[2]["template"] == "p3.write.v1"
    return {"contract_challenge": result[2]["decision"]}


def basic_read(marker: str) -> dict:
    token = service_token("p3_basic")
    status, headers, raw = exchange(
        "GET", f"http://{BASIC_HOST}/p3/read", bearer=token, headers={"X-P3-Marker": marker, "X-SafeYolo-Trace": "1"}
    )
    assert status == 200 and json.loads(raw)["received"] is True, (status, raw)
    request_id = headers.get("x-safeyolo-request-id")
    assert request_id and request_id.startswith("req-")
    return {"status": status, "request_id": request_id, "token": token}


def peer_denial() -> dict:
    status, _, view = api("GET", "/gateway/services")
    assert status == 200 and "p3_basic" not in view.get("authorized", {}), view
    token = Path("/safeyolo/p3-stolen-token").read_text().strip()
    assert token.startswith("sgw_")
    result = exchange("GET", f"http://{BASIC_HOST}/p3/read", bearer=token)
    assert result[0] == 403, (result[0], result[2])
    return {"stolen_token_status": result[0], "authorized_services": sorted(view.get("authorized", {}))}


def contract_prompt() -> dict:
    token = service_token("p3_contract")
    status, headers, _ = exchange(
        "POST",
        f"http://{CONTRACT_HOST}/p3/write?ticket=T-1",
        payload={"project": "alpha"},
        bearer=token,
    )
    assert status == 428, status
    request_id = headers.get("x-safeyolo-request-id")
    assert request_id and request_id.startswith("req-")
    return {"pending_status": status, "request_id": request_id}


def contract_effect() -> dict:
    token = service_token("p3_contract")
    target = f"http://{CONTRACT_HOST}/p3/write?ticket=T-1"
    bad = exchange("POST", target, payload={"project": "beta"}, bearer=token)
    assert bad[0] == 403, (bad[0], bad[2])
    outside = exchange("GET", f"http://{CONTRACT_HOST}/p3/outside", bearer=token)
    assert outside[0] == 403, (outside[0], outside[2])
    approved = exchange("POST", target, payload={"project": "alpha"}, bearer=token)
    assert approved[0] == 200 and json.loads(approved[2])["received"] is True, approved[0]
    reused = exchange("POST", target, payload={"project": "alpha"}, bearer=token)
    assert reused[0] == 428, (reused[0], reused[2])
    return {"bad_binding": bad[0], "outside_route": outside[0], "approved": approved[0], "after_once_grant": reused[0]}


def context_and_evidence(agent: str, marker: str) -> dict:
    declared = api(
        "POST",
        "/api/test-context/current",
        payload={
            "context": f"run=installed-p3;agent={agent};test={marker}",
            "ttl": 90,
        },
    )
    assert declared[0] == 200 and declared[2]["context"]["agent"] == agent, declared
    current = api("GET", "/api/test-context/current")
    assert current[0] == 200 and current[2]["context"] == declared[2]["context"], current
    token = service_token("p3_basic")
    status, headers, raw = exchange(
        "GET",
        f"http://{BASIC_HOST}/p3/read",
        bearer=token,
        headers={
            "X-P3-Marker": marker + "-context",
            "X-SafeYolo-Trace": "1",
            "X-SafeYolo-Test-Context": f"run=installed-p3;agent={agent};test={marker}",
        },
    )
    assert status == 200 and json.loads(raw)["received"] is True
    request_id = headers["x-safeyolo-request-id"]
    trace = api("GET", "/trace?request_id=" + quote(request_id))
    assert trace[0] == 200 and trace[2]["agent_id"] == agent, trace
    owned = wait_for_owned_flow(agent, BASIC_HOST, request_id, limit=30)
    detail = api("GET", f"/api/flows/{owned['id']}")
    assert detail[0] == 200 and detail[2]["request_id"] == request_id, detail
    cleared = api("DELETE", "/api/test-context/current")
    assert cleared[0] == 200, cleared
    after = api("GET", "/api/test-context/current")
    assert after[0] == 200 and after[2].get("context") is None, after
    return {"declared_agent": agent, "trace_request_id": request_id, "flow_id": owned["id"], "cleared": True}


def seed_owned_flow(agent: str, marker: str) -> dict:
    """Populate evidence from this live guest and require its exact owner."""
    target = f"http://{FLOW_HOST}/installed-flow/{marker}/{agent}"
    status, headers, raw = exchange("GET", target, headers={
        "X-SafeYolo-Test-Context": f"run=installed-access;agent={agent};test={marker}",
        "X-SafeYolo-Trace": "1",
    })
    assert status == 200 and json.loads(raw)["received"] is True, (status, raw)
    request_id = headers["x-safeyolo-request-id"]
    owned = wait_for_owned_flow(agent, FLOW_HOST, request_id)
    detail = api("GET", f"/api/flows/{owned['id']}")
    assert detail[0] == 200 and detail[2]["agent_id"] == detail[2]["evidence_owner"] == agent, detail
    assert detail[2]["request_id"] == request_id, detail
    return {"agent_id": agent, "flow_id": owned["id"], "request_id": request_id}


def operator_traffic(agent: str, marker: str) -> dict:
    """Observe fresh owned traffic and policy refusal in the selected guest."""
    allowed = seed_owned_flow(agent, marker)
    denied = exchange("GET", f"http://evil.com/installed-flow/{marker}/{agent}")
    assert denied[0] == 403 and denied[1].get("x-blocked-by") == "network-guard", denied[:2]
    return {"allowed": allowed, "denied_status": denied[0], "blocked_by": denied[1]["x-blocked-by"]}


def reject_peer_flow(agent: str, peer: str, foreign_id: int, foreign_request: str) -> dict:
    """Keep a populated own search while rejecting a known live peer's detail."""
    search = api("POST", "/api/flows/search", payload={"host": FLOW_HOST, "limit": 100})
    assert search[0] == 200 and search[2]["flows"], search
    assert all(row["agent_id"] == row["evidence_owner"] == agent for row in search[2]["flows"]), search
    assert all(row["request_id"] != foreign_request for row in search[2]["flows"]), search
    for field in ("agent_id", "evidence_owner"):
        forged = api("POST", "/api/flows/search", payload={"host": FLOW_HOST, field: peer, "limit": 100})
        assert forged[0] == 200, forged
        assert all(row["agent_id"] == row["evidence_owner"] == agent and row["request_id"] != foreign_request
                   for row in forged[2]["flows"]), forged
    foreign = api("GET", f"/api/flows/{foreign_id}")
    assert foreign[0] == 404 and foreign_request not in json.dumps(foreign[2]), foreign
    return {"owner": agent, "live_peer": peer, "own_search_populated": True,
            "foreign_search_absent": True, "foreign_detail_status": foreign[0]}


def coord_join() -> dict:
    status, _, body = api("POST", f"/api/coord/rooms/{ROOM}/join")
    assert status == 200 and body.get("room_id"), body
    return {"room_id": body["room_id"]}


def coord_send(message: str, notify: str | None) -> dict:
    payload = {"body": message, "notify": [notify] if notify else "none"}
    status, _, body = api("POST", f"/api/coord/rooms/{ROOM}/send", payload=payload)
    assert status == 200 and body["envelope"]["body"] == message, body
    return {
        "message_id": body["envelope"]["msg_id"],
        "sequence": body["sequence"],
        "attention_status": body.get("attention_status"),
    }


def coord_read(message: str) -> dict:
    status, _, page = api("GET", f"/api/coord/rooms/{ROOM}/messages?since=0&limit=10")
    assert status == 200 and any(row["body"] == message for row in page["messages"]), page
    return {"message_count": len(page["messages"]), "found": message}


def coord_wait(after: int, message: str) -> dict:
    print("P3_WAIT_READY=coord", flush=True)
    status, _, page = api("GET", f"/api/coord/rooms/{ROOM}/wait?since={after}&timeout=15")
    assert status == 200 and any(row["body"] == message for row in page["messages"]), page
    feed = api("GET", "/api/coord/attention/wait?since=0&timeout=1")
    assert feed[0] == 200 and feed[2]["edges"], feed
    edge = next(
        (
            item
            for item in feed[2]["edges"]
            if item["object_id"] in {row["msg_id"] for row in page["messages"] if row["body"] == message}
        ),
        None,
    )
    assert edge is not None, feed
    resolved = api("GET", f"/api/coord/attention/{edge['attention_id']}/object")
    assert resolved[0] == 200 and resolved[2]["object"]["body"] == message, resolved
    return {
        "waited_message_id": edge["object_id"],
        "attention_id": edge["attention_id"],
        "backing_sequence": next(row["sequence"] for row in page["messages"] if row["body"] == message),
    }


def plumb_request(peer: str) -> dict:
    status, _, body = api("POST", "/plumb/request-chat", payload={"participants": [peer]})
    assert status == 202 and body.get("request_id"), body
    return {"request_id": body["request_id"]}


def plumb_send(conversation: str, marker: str) -> dict:
    status, _, body = api(
        "POST", f"/plumb/conversations/{conversation}/messages", payload={"body": f"p3-message:{marker}"}
    )
    assert status == 200 and body.get("id"), body
    return {"message_id": body["id"]}


def plumb_read(conversation: str, marker: str) -> dict:
    view = api("GET", "/plumb/conversations")
    assert view[0] == 200 and any(row["conversation_id"] == conversation for row in view[2]["conversations"]), view
    result = api("GET", f"/plumb/conversations/{conversation}/messages")
    assert result[0] == 200 and any(row["body"] == f"p3-message:{marker}" for row in result[2]["messages"]), result
    return {"conversation_id": conversation, "message_count": len(result[2]["messages"])}


def plumb_closed(conversation: str) -> dict:
    view = api("GET", "/plumb/conversations")
    assert view[0] == 200 and all(row["conversation_id"] != conversation for row in view[2]["conversations"]), view
    result = api("GET", f"/plumb/conversations/{conversation}/messages")
    assert result[0] == 403, result
    return {"closed_read_status": result[0]}




def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--platform", choices=("systrap", "vz"), required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--peer")
    parser.add_argument("--marker", required=True)
    parser.add_argument("--conversation")
    parser.add_argument("--message")
    parser.add_argument("--notify")
    parser.add_argument("--after", type=int)
    parser.add_argument("--flow-id", type=int)
    args = parser.parse_args()
    forwarder = bridge(args.platform)
    match args.phase:
        case "access":
            result = access()
        case "contract-access":
            result = contract_access()
        case "basic":
            result = basic_read(args.marker)
        case "peer-denial":
            result = peer_denial()
        case "contract-prompt":
            result = contract_prompt()
        case "contract-effect":
            result = contract_effect()
        case "context":
            result = context_and_evidence(args.agent, args.marker)
        case "flow-seed":
            result = seed_owned_flow(args.agent, args.marker)
        case "operator-traffic":
            result = operator_traffic(args.agent, args.marker)
        case "flow-peer-denial":
            result = reject_peer_flow(args.agent, args.peer, args.flow_id, args.message)
        case "coord-join":
            result = coord_join()
        case "coord-send":
            result = coord_send(args.message, args.notify)
        case "coord-read":
            result = coord_read(args.message)
        case "coord-wait":
            result = coord_wait(args.after, args.message)
        case "plumb-request":
            result = plumb_request(args.peer)
        case "plumb-send":
            result = plumb_send(args.conversation, args.marker)
        case "plumb-read":
            result = plumb_read(args.conversation, args.marker)
        case "plumb-closed":
            result = plumb_closed(args.conversation)
        case "websocket":
            result = websocket("p2-" + args.marker[3:], args.agent, tls=False)
        case _:
            raise AssertionError(f"unknown access phase: {args.phase}")
    print(
        "P3_OBSERVATION="
        + json.dumps(
            {"phase": args.phase, "agent": args.agent, "forwarder": forwarder, "result": result}, sort_keys=True
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
