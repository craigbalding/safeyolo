"""Admin API client for SafeYolo proxy."""

from typing import Any

import httpx

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
            base_url: Admin API URL (default: from config)
            token: Auth token (default: from config/env)
            timeout: Request timeout in seconds
        """
        if base_url is None:
            config = load_config()
            port = config["proxy"]["admin_port"]
            base_url = f"http://localhost:{port}"

        self.base_url = base_url.rstrip("/")
        self.token = token or get_admin_token()
        self.timeout = timeout

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
                "Check 'docker logs safeyolo' for details."
            )
        except httpx.ReadError:
            raise APIError(
                f"Connection lost while reading response from {self.base_url}. Check 'docker logs safeyolo' for errors."
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

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Get pending credential approval requests.

        TODO: Implement when proxy-side tracking is added.
        Currently returns empty list as the feature is not yet implemented.
        """
        return []


def get_api() -> AdminAPI:
    """Get a configured API client instance."""
    return AdminAPI()
