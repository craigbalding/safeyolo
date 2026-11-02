"""Existing-room approval journey within the owned shared-approval venue.

The parent driver verifies exact installed artifacts and real systrap ingress,
then owns guest/proxy teardown and policy restoration. No model is required.
"""

from __future__ import annotations

import uuid
from urllib.parse import quote


def room_exchange(args, ids, guest, coord, operator, native, host_send, host_history, turnover):
    """Exercise current host-generated room effects through both real guests."""
    worker, reviewer = args.worker, args.helper
    room = args.delegated_room
    api = "http://_safeyolo.proxy.internal"
    path = "/api/coord/rooms/" + quote(room, safe="")
    state = native("coord", "status", room)
    assert state["members"] == [], "select an existing fixture room with only its operator member"
    assert guest(worker, "POST", api + path + "/join")["status"] == 404
    assert guest(reviewer, "POST", api + path + "/join")["status"] == 404
    name = "sy768-room-" + uuid.uuid4().hex
    rights = ["receive", "send", "page_operator"]
    proposal = {"expected_revision": None, "delegation": {
        "reviewers": [{"name": reviewer, "agent_id": ids[reviewer]}],
        "beneficiaries": [{"name": worker, "agent_id": ids[worker]}],
        "scopes": [{"type": "coord_room", "room_id": state["room_id"], "permissions": rights,
                    "participants": [
                        {"principal_kind": "operator", "principal_id": "operator", "permissions": rights},
                        {"principal_kind": "agent", "principal_id": ids[worker], "permissions": rights}]}],
        "expires_at": None, "grant_seconds": 120, "gateway_once": False, "acknowledgment": None}}
    endpoint = "/admin/approval-delegations/" + name
    preview = operator("POST", endpoint + "/preview", proposal)
    assert preview["status"] == 200, preview
    proposal["delegation"] = preview["body"]["after"]
    revision = preview["body"]["revision"]
    proposal["delegation"]["acknowledgment"] = revision
    applied = operator("POST", endpoint + "/apply", proposal)
    assert applied["status"] == 200, applied
    cutoff = coord(reviewer, "wait_for_attention", {"since_sequence": 0, "timeout_seconds": 0, "limit": 200})
    while len(cutoff["edges"]) == 200:
        cutoff = coord(reviewer, "wait_for_attention", {"since_sequence": cutoff["next_cursor"], "timeout_seconds": 0, "limit": 200})
    before = "retained-room-" + uuid.uuid4().hex
    host_send(before)

    def decide(permissions):
        request = coord(worker, "request_room_access", {"room_name": room, "permissions": permissions, "operation_id": uuid.uuid4().hex})
        assert "action" not in request and "participants" not in request
        identifier = request["approval_id"]
        view = coord(reviewer, "read_approval", {"approval_id": identifier})
        assert view["observed"]["room_id"] == state["room_id"]
        assert view["observed"]["permissions"] == sorted(permissions)
        assert guest(reviewer, "POST", api + path + "/join")["status"] == 404
        assert any(choice["delegation"] == name and choice["option"] == "run" for choice in view["choices"])
        decision = coord(reviewer, "resolve_approval", {"approval_id": identifier, "delegation": name, "decision": "approve", "option": "run"})
        assert decision["status"] == "approved", decision
        return identifier, view

    first, inspected = decide(["receive"])
    notice = coord(reviewer, "wait_for_attention", {"since_sequence": cutoff["next_cursor"], "timeout_seconds": 2, "limit": 200})
    notices = [coord(reviewer, "read_attention", {"attention_id": edge["attention_id"]}) for edge in notice["edges"] if edge["kind"] == "message"]
    reference = next(item for item in notices if first in item["object"].get("body", ""))
    assert reference["object"]["sender_kind"] == "operator"
    assert state["room_id"] not in reference["object"]["body"] and ids[worker] not in reference["object"]["body"]
    history = coord(worker, "read_room", {"room_name": room, "since_sequence": 0, "limit": 200})
    assert any(message["body"] == before and message["sender_kind"] == "operator" for message in history["messages"])
    refused = guest(worker, "POST", api + path + "/send", {"body": "receive-only-refusal", "notify": "none"})
    assert refused["status"] == 403, refused
    second, _ = decide(rights)
    marker = "worker-room-" + uuid.uuid4().hex
    sent = coord(worker, "send", {"room_name": room, "body": marker, "notify": "none", "declared_content_type": "text/plain"})
    assert sent["sequence"] > 0
    assert marker in host_history(), "operator must receive the actual guest message"
    host_send("operator-reply-" + marker)
    replied = coord(worker, "read_room", {"room_name": room, "since_sequence": sent["sequence"], "limit": 200})
    assert any(message["body"] == "operator-reply-" + marker and message["sender_kind"] == "operator" for message in replied["messages"])
    signal = coord(worker, "create_signal", {"room_name": room, "kind": "blocker", "summary": marker, "basis": "observed", "operation_id": uuid.uuid4().hex})
    assert signal["signal"]["needs_operator"] is True
    assert any(item["signal"]["signal_id"] == signal["signal"]["signal_id"] for item in native("coord", "status", room)["needs_operator"]["items"])
    revoked = operator("POST", endpoint + "/revoke", {"expected_revision": revision})
    assert revoked["status"] == 200, revoked
    for suffix in ("messages", "state", "brief", "work", "signals"):
        assert guest(worker, "GET", api + path + "/" + suffix)["status"] in {403, 404}, suffix
    inactive = native("approvals", "show", second)
    assert inactive["status"] == "approved" and inactive["grant_active"] is False
    # Regrant and turn over the actual sandbox. No saved grant may move to the
    # new run, even when the agent keeps its configured name and durable ID.
    proposal["expected_revision"] = None
    assert operator("POST", endpoint + "/apply", proposal)["status"] == 200
    third, _ = decide(["receive"])
    assert native("approvals", "show", third)["grant_active"] is True
    restarted = turnover(third)
    assert guest(worker, "GET", api + path + "/messages")["status"] in {403, 404}
    assert native("approvals", "show", third)["grant_active"] is False
    assert operator("POST", endpoint + "/revoke", {"expected_revision": revision})["status"] == 200
    return {"room_id": state["room_id"], "room_name": room, "approval_ids": [first, second, third],
            "canonical_inspection": inspected, "reference_attention": reference,
            "receive_only_send_status": refused["status"], "guest_message_sequence": sent["sequence"],
            "page_signal_id": signal["signal"]["signal_id"], "revoked_approval": inactive,
            "worker_turnover": restarted, "reviewer_target_membership": "absent before and after decisions"}
