"""Admin API client for SafeYolo proxy."""

import os
from pathlib import Path
from typing import Any

import httpx

from . import rust_proxy
from .config import get_admin_token, load_config


class APIError(Exception):
    """API request failed."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class AdminAPI:
    """Client for SafeYolo admin API."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = 10.0,
    ):
        """Initialize API client.

        Args:
            base_url: Admin API URL (default: the recorded Rust listener or Python config)
            token: Auth token (default: environment override or the selected listener's file)
            timeout: Request timeout in seconds
        """
        self._rust_process: rust_proxy.RustProcess | None = None
        self._token_override = token
        if base_url is None:
            base_url, self._rust_process = self._default_connection()

        self.base_url = base_url.rstrip("/")
        self.token = token or self._default_token(self._rust_process)
        self.timeout = timeout

    def _default_connection(self, *, require_rust: bool = False) -> tuple[str, rust_proxy.RustProcess | None]:
        try:
            process = rust_proxy.read_process()
        except (OSError, ValueError, RuntimeError) as exc:
            raise APIError(f"Cannot read Rust proxy ownership: {exc}") from exc
        if process is None:
            if require_rust:
                raise APIError("The Rust proxy has no current process record")
            config = load_config()
            return f"http://localhost:{config['proxy']['admin_port']}", None
        self._check_rust_process(process)
        port = process.admin_port
        if port is None:
            raise APIError("The running Rust proxy has no admin listener configured")
        if port == 0:
            try:
                marker = rust_proxy.readiness(process)
            except OSError as exc:
                raise APIError("Cannot read the Rust proxy's admin listener readiness") from exc
            if marker is None:
                raise APIError("The Rust proxy has not published its admin listener port yet")
            port = marker["admin_port"]
            self._check_rust_process(process)
        return f"http://127.0.0.1:{port}", process

    def _default_token(self, process: rust_proxy.RustProcess | None) -> str | None:
        if process is None:
            return get_admin_token()
        if process.admin_token_file is None:
            return os.environ.get("SAFEYOLO_ADMIN_TOKEN") or None
        try:
            return get_admin_token(token_path=Path(process.admin_token_file))
        except (OSError, UnicodeError) as exc:
            raise APIError("Cannot read the Rust proxy's admin token file") from exc

    def _check_rust_process(self, process: rust_proxy.RustProcess) -> None:
        try:
            alive = rust_proxy.is_alive(process)
        except (OSError, ValueError, RuntimeError) as exc:
            raise APIError(f"Cannot verify Rust proxy process identity: {exc}") from exc
        if not alive:
            raise APIError("The recorded Rust proxy process has exited or changed")

    def _refresh_rust_connection(self) -> None:
        """Follow a recorded native restart while rejecting stale ownership."""
        previous = self._rust_process
        if previous is None:
            return
        base_url, process = self._default_connection(require_rust=True)
        assert process is not None
        if (process.pid, process.start_token) != (previous.pid, previous.start_token):
            token = self._token_override or self._default_token(process)
            self.base_url, self.token, self._rust_process = base_url, token, process

    def _headers(self) -> dict[str, str]:
        """Get request headers with auth."""
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json: dict | None = None,
        require_auth: bool = True,
    ) -> Any:
        """Make an API request."""
        self._refresh_rust_connection()
        url = f"{self.base_url}{path}"
        headers = self._headers() if require_auth else {}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.request(method, url, headers=headers, json=json)
        except httpx.ConnectError:
            raise APIError(f"Cannot connect to {self.base_url} - is SafeYolo running?")
        except httpx.RemoteProtocolError:
            raise APIError(
                "Server disconnected unexpectedly - admin API may have crashed. "
                "Check ~/.local/state/safeyolo/mitmproxy.log for details."
            )
        except httpx.ReadError:
            raise APIError(
                f"Connection lost while reading response from {self.base_url}. Check ~/.local/state/safeyolo/mitmproxy.log for errors."
            )
        except httpx.TimeoutException:
            raise APIError(
                f"Request to {url} timed out after {self.timeout}s. "
                f"Admin API may still be starting - try again in a few seconds."
            )

        if response.status_code == 401:
            raise APIError("Authentication failed - check admin token", 401)
        if response.status_code == 403:
            raise APIError("Permission denied", 403)
        if response.status_code >= 400:
            raise APIError(
                f"API error: {response.status_code} {response.text}",
                response.status_code,
            )

        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return response.text

    def health(self) -> dict[str, Any]:
        """Check proxy health (no auth required)."""
        return self._request("GET", "/health", require_auth=False)

    def stats(self) -> dict[str, Any]:
        """Get aggregated stats from all addons."""
        return self._request("GET", "/stats")

    def get_traffic_scope(self) -> dict[str, Any]:
        return self._request("GET", "/admin/traffic/scope")

    def set_traffic_scope(self, **scope: Any) -> dict[str, Any]:
        return self._request("PUT", "/admin/traffic/scope", json=scope)

    def metrics(self) -> str:
        """Get Prometheus format metrics."""
        return self._request("GET", "/metrics")

    def get_modes(self) -> dict[str, Any]:
        """Get all addon modes."""
        return self._request("GET", "/modes")

    def set_mode(self, addon: str, mode: str) -> dict[str, Any]:
        """Set mode for specific addon.

        Args:
            addon: Addon name (e.g., 'credential-guard')
            mode: Mode ('warn' or 'block')
        """
        return self._request(
            "PUT",
            f"/plugins/{addon}/mode",
            json={"mode": mode},
        )

    def set_all_modes(self, mode: str) -> dict[str, Any]:
        """Set mode for all addons."""
        return self._request("PUT", "/modes", json={"mode": mode})

    def get_policy(self, project: str = "default") -> dict[str, Any]:
        """Get policy for a project."""
        return self._request("GET", f"/admin/policy/{project}")

    def list_policies(self) -> dict[str, Any]:
        """List all policies."""
        return self._request("GET", "/admin/policies")

    def set_policy(self, project: str, policy: dict[str, Any]) -> dict[str, Any]:
        """Write/update policy for a project."""
        return self._request("PUT", f"/admin/policy/{project}", json={"policy": policy})

    def add_approval(
        self,
        destination: str,
        cred_id: str,
        tier: str = "explicit",
    ) -> dict[str, Any]:
        """Add a credential approval to baseline policy.

        Args:
            destination: Target host (e.g., "api.openai.com")
            cred_id: Credential identifier (e.g., "hmac:abc123" or "openai:*")
            tier: Permission tier ("explicit", "wildcard", etc.)
        """
        payload = {
            "destination": destination,
            "cred_id": cred_id,
            "tier": tier,
        }
        return self._request("POST", "/admin/policy/baseline/approve", json=payload)

    def get_allowlist(self) -> list[dict[str, Any]]:
        """Get temp allowlist entries."""
        return self._request("GET", "/plugins/credential-guard/allowlist")

    def add_allowlist(
        self,
        credential_prefix: str,
        host: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Add temp allowlist entry."""
        return self._request(
            "POST",
            "/plugins/credential-guard/allowlist",
            json={
                "credential_prefix": credential_prefix,
                "host": host,
                "ttl_seconds": ttl_seconds,
            },
        )

    def clear_allowlist(self) -> dict[str, Any]:
        """Clear all temp allowlist entries."""
        return self._request("DELETE", "/plugins/credential-guard/allowlist")

    def log_denial(
        self,
        destination: str,
        cred_id: str,
        reason: str = "user_denied",
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        """Log a credential denial event.

        Args:
            destination: Target host that was denied
            cred_id: Credential identifier (e.g., "hmac:abc123")
            reason: Reason for denial
        """
        payload = {
            "destination": destination,
            "cred_id": cred_id,
            "reason": reason,
        }
        if approval_request_id:
            payload["approval_request_id"] = approval_request_id
        return self._request("POST", "/admin/policy/baseline/deny", json=payload)

    def add_gateway_grant(
        self,
        agent: str,
        service: str,
        method: str,
        path: str,
        lifetime: str = "once",
    ) -> dict[str, Any]:
        """Add a risky route grant via the admin API.

        Args:
            agent: Agent name (e.g., "claude")
            service: Service name (e.g., "minifuse")
            method: HTTP method (e.g., "DELETE")
            path: Request path (e.g., "/v1/feeds/658")
            lifetime: Grant scope ("once", "session", "remembered")
        """
        return self._request(
            "POST",
            "/admin/gateway/grant",
            json={
                "agent": agent,
                "service": service,
                "method": method,
                "path": path,
                "lifetime": lifetime,
            },
        )

    def list_gateway_grants(self) -> dict[str, Any]:
        """List active risky route grants."""
        return self._request("GET", "/admin/gateway/grants")

    def revoke_gateway_grant(self, grant_id: str) -> dict[str, Any]:
        """Revoke a risky route grant."""
        return self._request("DELETE", f"/admin/gateway/grants/{grant_id}")

    def log_gateway_denial(
        self,
        agent: str,
        service: str,
        method: str,
        path: str,
        reason: str = "user_denied",
    ) -> dict[str, Any]:
        """Log a risky route denial event."""
        return self._request(
            "POST",
            "/admin/policy/baseline/deny",
            json={
                "destination": f"gateway:{service}",
                "cred_id": f"{agent}:{method}:{path}",
                "reason": reason,
            },
        )

    def authorize_service(
        self,
        agent: str,
        service: str,
        capability: str,
        credential: str,
    ) -> dict[str, Any]:
        """Authorize an agent to use a service.

        Args:
            agent: Agent name (e.g., "boris")
            service: Service name (e.g., "gmail")
            capability: Capability name (e.g., "readonly")
            credential: Vault credential name (e.g., "gmail-oauth2")
        """
        return self._request(
            "POST",
            f"/admin/agents/{agent}/services",
            json={
                "service": service,
                "capability": capability,
                "credential": credential,
            },
        )

    def approve_contract_binding(
        self,
        agent: str,
        service: str,
        capability: str,
        template: str,
        bindings: dict[str, Any],
        grantable_operations: list[str],
    ) -> dict[str, Any]:
        """Approve a contract binding for an agent/service/capability.

        Args:
            agent: Agent name
            service: Service name
            capability: Capability name
            template: Contract template identifier
            bindings: Bound variable values
            grantable_operations: List of grantable operation names
        """
        return self._request(
            "POST",
            "/admin/gateway/contract-binding",
            json={
                "agent": agent,
                "service": service,
                "capability": capability,
                "template": template,
                "bindings": bindings,
                "grantable_operations": grantable_operations,
            },
        )

    def revoke_service(
        self,
        agent: str,
        service: str,
    ) -> dict[str, Any]:
        """Revoke an agent's access to a service.

        Args:
            agent: Agent name (e.g., "boris")
            service: Service name (e.g., "gmail")
        """
        return self._request(
            "DELETE",
            f"/admin/agents/{agent}/services/{service}",
        )

    def update_host_rate(self, host: str, rate: int) -> dict[str, Any]:
        """Update rate limit for a host.

        Args:
            host: Host pattern (e.g., "api.openai.com")
            rate: New rate limit (requests per minute)
        """
        return self._request(
            "POST",
            "/admin/policy/host/rate",
            json={"host": host, "rate": rate},
        )

    def allow_host(
        self, host: str, rate: int | None = None, agent: str | None = None, port: int | None = None,
    ) -> dict[str, Any]:
        """Allow a new host in policy.

        Args:
            host: Host pattern (e.g., "cdn.example.com")
            rate: Optional rate limit (requests per minute)
            agent: Optional agent name for agent-scoped entry
        """
        payload: dict[str, Any] = {"host": host}
        if rate is not None:
            payload["rate"] = rate
        if agent is not None:
            payload["agent"] = agent
        if port is not None:
            payload["port"] = port
        return self._request(
            "POST",
            "/admin/policy/host/allow",
            json=payload,
        )

    def deny_host(
        self, host: str, expires: str | None = None, agent: str | None = None, port: int | None = None,
    ) -> dict[str, Any]:
        """Deny egress to a host in policy.

        Args:
            host: Host pattern (e.g., "dodgy-site.com")
            expires: Optional ISO datetime for auto-expiry
            agent: Optional agent name for agent-scoped entry
        """
        payload: dict[str, Any] = {"host": host}
        if expires is not None:
            payload["expires"] = expires
        if agent is not None:
            payload["agent"] = agent
        if port is not None:
            payload["port"] = port
        return self._request(
            "POST",
            "/admin/policy/host/deny",
            json=payload,
        )

    def reset_circuit(self, host: str) -> dict[str, Any]:
        """Reset circuit breaker for a host.

        Args:
            host: Host to reset circuit for
        """
        return self._request(
            "POST",
            "/admin/circuit-breaker/reset",
            json={"host": host},
        )

    # ---- Plumb (agent-to-agent collaboration) --------------------------------
    def plumb_pending(self) -> dict[str, Any]:
        """List pending plumb chat requests awaiting operator approval."""
        return self._request("GET", "/admin/plumb/pending")

    def plumb_conversations(self) -> dict[str, Any]:
        """List active plumb conversation grants."""
        return self._request("GET", "/admin/plumb/conversations")

    def plumb_approve(self, request_id: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        """Approve a plumb chat request, creating a conversation grant.

        Args:
            request_id: The pending request id from the approval event.
            ttl_seconds: Optional operator override for the grant lifetime.
        """
        payload: dict[str, Any] = {"request_id": request_id}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request("POST", "/admin/plumb/approve", json=payload)

    def plumb_deny(self, request_id: str) -> dict[str, Any]:
        """Deny a plumb chat request."""
        return self._request("POST", "/admin/plumb/deny", json={"request_id": request_id})

    def plumb_close(self, conversation_id: str) -> dict[str, Any]:
        """Close an active plumb conversation."""
        return self._request(
            "POST", "/admin/plumb/close", json={"conversation_id": conversation_id}
        )

    def add_host_bypass(self, host: str, addon: str) -> dict[str, Any]:
        """Add addon bypass for a host.

        Args:
            host: Host pattern
            addon: Addon name to bypass (e.g., "pattern-scanner")
        """
        return self._request(
            "POST",
            "/admin/policy/host/bypass",
            json={"host": host, "addon": addon},
        )

    def reset_budget(self, resource: str | None = None) -> dict[str, Any]:
        """Reset budget counters.

        Args:
            resource: Optional specific resource to reset. If None, resets all.
        """
        payload: dict[str, Any] = {}
        if resource is not None:
            payload["resource"] = resource
        return self._request(
            "POST",
            "/admin/budgets/reset",
            json=payload if payload else None,
        )

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Get unresolved approval requests from SafeYolo's audit history."""
        result = self._request("GET", "/admin/approvals")
        return result.get("approvals", [])

    def instance(self) -> dict[str, Any]:
        """Get the stable SafeYolo instance identity and client capabilities."""
        return self._request("GET", "/admin/instance")

    def agents(self) -> list[dict[str, Any]]:
        """List configured agents and their live state."""
        result = self._request("GET", "/admin/agents")
        return result.get("agents", [])

    def start_agent(self, agent_id: str, *, interactive: bool = False) -> dict[str, Any]:
        """Start one configured agent by stable identity."""
        action = "start-interactive" if interactive else "start"
        return self._request("POST", f"/admin/agents/{agent_id}/{action}")

    def stop_agent(self, agent_id: str) -> dict[str, Any]:
        """Stop one configured agent by stable identity."""
        return self._request("POST", f"/admin/agents/{agent_id}/stop")

    def present_desktop(
        self,
        agent_id: str,
        *,
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        """Start or reuse a local preview for a stable agent identity."""
        payload = {"approval_request_id": approval_request_id} if approval_request_id else None
        return self._request(
            "POST",
            f"/admin/agents/{agent_id}/desktop/present",
            json=payload,
        )


def get_api() -> AdminAPI:
    """Get a configured API client instance."""
    return AdminAPI()
