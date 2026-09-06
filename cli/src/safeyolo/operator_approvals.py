"""Shared approval mutations for trusted SafeYolo operator clients."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import AdminAPI


class ApprovalActionError(NotImplementedError):
    """The audit event doesn't contain enough data for the requested action."""


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
        host = event.get("host", approval.get("target", ""))
        result = api.allow_host(host=host, rate=600)
        return result.get("status", "ok")

    if approval_type == "service":
        scope = approval.get("scope_hint", {})
        agent = event.get("agent", "")
        service = approval.get("target", "")
        capability = scope.get("capability", "")
        if not agent or not service or not capability or not service_credential:
            raise ApprovalActionError("Service approval is missing agent, service, capability, or credential")
        result = api.authorize_service(
            agent=agent,
            service=service,
            capability=capability,
            credential=service_credential,
        )
        return result.get("status", "authorized")

    if approval_type == "contract_binding":
        scope = approval.get("scope_hint", {})
        agent = event.get("agent", "")
        service = approval.get("target", "")
        capability = scope.get("capability", "")
        if not agent or not service or not capability:
            raise ApprovalActionError("Contract binding event missing agent, service, or capability")
        result = api.approve_contract_binding(
            agent=agent,
            service=service,
            capability=capability,
            template=scope.get("template", ""),
            bindings=scope.get("bindings", {}),
            grantable_operations=scope.get("grantable_operations", []),
        )
        return result.get("status", "bound")

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
        host = event.get("host", approval.get("target", ""))
        expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        api.deny_host(host=host, expires=expires)
        return

    if approval_type in {"service", "contract_binding"}:
        suffix = "service_access" if approval_type == "service" else "contract_binding"
        api.log_denial(
            destination=f"gateway:{approval.get('target', 'unknown')}",
            cred_id=f"{event.get('agent', 'unknown')}:{suffix}",
            reason="user_denied",
        )
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
