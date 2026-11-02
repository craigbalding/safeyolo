"""Shared approval mutations for trusted SafeYolo operator clients."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from safeyolo.core.destination import validate_port

if TYPE_CHECKING:
    from .api import AdminAPI


class ApprovalActionError(NotImplementedError):
    """The audit event doesn't contain enough data for the requested action."""


def _gateway_approval(event: dict, api: AdminAPI) -> dict:
    """Read the same native gateway request before applying its fixed scope."""
    action = event.get("action", {})
    kind = {
        "service": "service_authorize",
        "contract_binding": "contract_binding",
        "gateway_risky_route": "gateway_route",
    }[event["approval"]["approval_type"]]
    if (
        not event.get("approval_id") or not event.get("request_id")
        or not all(action.get(key) for key in ("agent", "agent_id", "service", "capability"))
        or event.get("agent") != action["agent"] or action.get("kind") != kind
    ):
        raise ApprovalActionError("Gateway approval is missing its canonical request or action scope")
    current = api.approval(event["approval_id"])
    if any(current.get(key) != event.get(key) for key in ("approval_id", "request_id", "agent", "action")):
        raise ApprovalActionError("Gateway approval no longer matches the selected request and action")
    return current


def _approve_gateway(event: dict, api: AdminAPI, credential: str | None) -> str:
    """Choose an offered option and resolve the exact native gateway approval."""
    current = _gateway_approval(event, api)
    kind = current["action"]["kind"]
    if kind == "service_authorize":
        options = [option["id"] for option in current["options"]
                   if option.get("parameters", {}).get("credential") == (credential or "")]
    else:
        selected = "persistent" if kind == "contract_binding" else "once"
        options = [option["id"] for option in current["options"] if option["id"] == selected]
    if len(options) != 1:
        raise ApprovalActionError("Gateway approval does not offer the selected credential or lifetime")
    resolved = api.resolve_approval(current["approval_id"], "approve", option=options[0])
    if resolved.get("status") != "approved" or resolved.get("option") != options[0]:
        raise ApprovalActionError(f"Canonical gateway approval is {resolved.get('status')}; this decision did not grant access")
    if kind == "gateway_route":
        return resolved["result"]["grant_id"]
    return "bound" if kind == "contract_binding" else "authorized"


def network_scope(event: dict) -> dict:
    """Return the narrow destination scope recorded by the network sensor."""
    port = event.get("approval", {}).get("scope_hint", {}).get("port")
    if port is None:
        port = event.get("details", {}).get("port")
    result = {}
    if port is not None:
        result["port"] = validate_port(port)
    if event.get("agent"):
        result["agent"] = event["agent"]
    return result


def approve(
    event: dict,
    api: AdminAPI,
    *,
    service_credential: str | None = None,
) -> str | dict | None:
    """Approve one audit request through its existing typed Admin API route."""
    approval = event.get("approval", {})
    details = event.get("details", {})
    approval_type = approval.get("approval_type")

    if approval_type == "credential":
        fingerprint = approval.get("key", details.get("fingerprint", ""))
        host = event.get("host", approval.get("target", ""))
        result = api.add_approval(destination=host, cred_id=fingerprint)
        return result.get("status", "ok")

    if approval_type == "gateway_route":
        result = api.add_gateway_grant(
            agent=event.get("agent", "unknown"),
            service=details.get("service", "unknown"),
            method=details.get("method", ""),
            path=details.get("path", details.get("risky_route", "")),
            lifetime="once",
        )
        return result.get("grant_id")

    if approval_type == "network_egress":
        if details.get("network_action", {}).get("kind") == "network_allow":
            status = api.resolve_approval(event["request_id"], "approve").get("status")
            if status != "approved":
                raise ApprovalActionError(f"Canonical network approval is {status}; this decision did not grant access")
            return status
        host = event.get("host", approval.get("target", ""))
        result = api.allow_host(host=host, rate=600, **network_scope(event))
        return result.get("status", "ok")

    if approval_type in {"service", "contract_binding", "gateway_risky_route"}:
        return _approve_gateway(event, api, service_credential)

    if approval_type == "plumb":
        result = api.plumb_approve(request_id=approval.get("key", ""))
        return result.get("conversation_id") or result.get("status", "ok")

    if approval_type == "desktop_present":
        agent_id = approval.get("scope_hint", {}).get("agent_id", "")
        if not agent_id:
            raise ApprovalActionError("Desktop presentation is missing agent_id")
        return api.present_desktop(
            agent_id,
            approval_request_id=event.get("request_id"),
        )

    raise ApprovalActionError(f"Unsupported approval type: {approval_type!r}")


def deny(event: dict, api: AdminAPI) -> None:
    """Deny one audit request through its existing typed Admin API route."""
    approval = event.get("approval", {})
    details = event.get("details", {})
    approval_type = approval.get("approval_type")

    if approval_type == "credential":
        api.log_denial(
            destination=event.get("host", approval.get("target", "")),
            cred_id=approval.get("key", details.get("fingerprint", "")),
            reason="user_denied",
            approval_request_id=event.get("request_id"),
        )
        return

    if approval_type == "gateway_route":
        api.log_gateway_denial(
            agent=event.get("agent", "unknown"),
            service=details.get("service", "unknown"),
            method=details.get("method", ""),
            path=details.get("path", details.get("risky_route", "")),
        )
        return

    if approval_type == "network_egress":
        if details.get("network_action", {}).get("kind") == "network_allow":
            status = api.resolve_approval(event["request_id"], "reject").get("status")
            if status != "rejected":
                raise ApprovalActionError(f"Canonical network approval is {status}; this decision did not reject it")
            return
        host = event.get("host", approval.get("target", ""))
        expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        api.deny_host(host=host, expires=expires, **network_scope(event))
        return

    if approval_type in {"service", "contract_binding", "gateway_risky_route"}:
        current = _gateway_approval(event, api)
        status = api.resolve_approval(current["approval_id"], "reject").get("status")
        if status != "rejected":
            raise ApprovalActionError(f"Canonical gateway approval is {status}; this decision did not reject it")
        return

    if approval_type == "plumb":
        api.plumb_deny(request_id=approval.get("key", ""))
        return

    if approval_type == "desktop_present":
        api.log_denial(
            destination=approval.get("target", ""),
            cred_id=approval.get("key", "desktop.present"),
            reason="user_denied",
            approval_request_id=event.get("request_id"),
        )
        return

    raise ApprovalActionError(f"Unsupported approval type: {approval_type!r}")
