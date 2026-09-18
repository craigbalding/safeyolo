"""Admin API client for SafeYolo proxy."""

import os
import stat
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from . import rust_proxy
from .config import get_admin_token, load_config
from .core.identifiers import validate_task_id


class APIError(Exception):
    """API request failed."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ExportCancelled(Exception):
    """The caller abandoned an in-progress traffic export."""


class ExportPublicationState:
    """Coordinate cancellation with the final local publication commit."""

    def __init__(self):
        self._cancel_event = threading.Event()
        self._publication_lock = threading.Lock()

    def is_set(self) -> bool:
        return self._cancel_event.is_set()

    def set(self) -> None:
        with self._publication_lock:
            self._cancel_event.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._cancel_event.wait(timeout)

    def publish(self, temporary: Path, destination: Path) -> None:
        """Replace the destination unless detach won the same boundary."""
        with self._publication_lock:
            if self._cancel_event.is_set():
                raise ExportCancelled()
            os.replace(temporary, destination)


class TrafficExportResult:
    """Metadata for a completed local traffic export."""

    def __init__(
        self,
        *,
        status_code: int,
        content_type: str,
        bytes_written: int,
        cleanup_warning: str | None = None,
    ):
        self.status_code = status_code
        self.content_type = content_type
        self.bytes_written = bytes_written
        self.cleanup_warning = cleanup_warning


def _content_length(headers: httpx.Headers) -> int | None:
    value = headers.get("content-length")
    if value is None:
        return None
    try:
        length = int(value)
    except (TypeError, ValueError) as exc:
        raise APIError("Traffic export response had an invalid length") from exc
    if length < 0:
        raise APIError("Traffic export response had an invalid length")
    return length


def _destination_details(destination: Path) -> tuple[Path, int | None]:
    """Resolve a symlink target and retain an existing target's mode."""
    try:
        previous = destination.stat()
    except FileNotFoundError:
        previous = None
    except OSError as exc:
        raise APIError("Cannot inspect traffic export destination") from exc
    try:
        publication_path = destination.resolve(strict=False) if destination.is_symlink() else destination
    except (OSError, RuntimeError) as exc:
        raise APIError("Cannot resolve traffic export destination") from exc
    mode = stat.S_IMODE(previous.st_mode) if previous is not None else None
    return publication_path, mode


def _check_export_cancel(cancel_event: threading.Event | ExportPublicationState | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ExportCancelled()


def _publish_export(
    cancel_event: threading.Event | ExportPublicationState | None,
    temporary: Path,
    destination: Path,
) -> None:
    if isinstance(cancel_event, ExportPublicationState):
        cancel_event.publish(temporary, destination)
    else:
        _check_export_cancel(cancel_event)
        os.replace(temporary, destination)


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

    @property
    def is_native(self) -> bool:
        """Whether the default client selected a recorded Rust process."""
        return self._rust_process is not None

    def traffic_flows(self) -> dict[str, Any]:
        return self._request("GET", "/admin/traffic/flows")

    def traffic_flow(self, flow_id: str) -> dict[str, Any]:
        return self._request("GET", f"/admin/traffic/flows/{quote(flow_id, safe='')}")

    def traffic_body(self, flow_id: str, side: str) -> dict[str, Any]:
        if side not in {"request", "response"}:
            raise ValueError("body side must be request or response")
        return self._request("GET", f"/admin/traffic/flows/{quote(flow_id, safe='')}/body?side={side}")

    def traffic_export(
        self,
        flow_id: str,
        format_name: str,
        destination: Path,
        *,
        cancel_event: threading.Event | ExportPublicationState | None = None,
    ) -> TrafficExportResult:
        """Stream one retained flow export to a local file atomically.

        The destination is used only by this client.  The server receives the
        frozen flow ID and format in the request path/query and never sees the
        local path.  A sibling temporary file is published only after the
        response stream, file write, and file close all complete.
        """
        _check_export_cancel(cancel_event)
        self._refresh_rust_connection()
        encoded_id = quote(flow_id, safe="")
        encoded_format = quote(format_name, safe="")
        url = f"{self.base_url}/admin/traffic/flows/{encoded_id}/export?format={encoded_format}"
        headers = self._headers()
        try:
            return self._write_traffic_export(url, headers, destination, cancel_event)
        except (APIError, ExportCancelled):
            raise
        except httpx.HTTPError as exc:
            raise APIError("Traffic export stream failed") from exc
        except OSError as exc:
            raise APIError("Cannot write traffic export") from exc

    def _write_traffic_export(
        self,
        url: str,
        headers: dict[str, str],
        destination: Path,
        cancel_event: threading.Event | ExportPublicationState | None,
    ) -> TrafficExportResult:
        publication_path, existing_mode = _destination_details(destination)
        temporary_dir = tempfile.TemporaryDirectory(
            prefix=".export-",
            dir=publication_path.parent,
        )
        result = None
        try:
            temporary = Path(temporary_dir.name) / publication_path.name
            status_code, content_type, bytes_written = self._stream_traffic_export(
                url, headers, temporary, cancel_event
            )
            if existing_mode is not None:
                os.chmod(temporary, existing_mode)
            _publish_export(cancel_event, temporary, publication_path)
            result = TrafficExportResult(
                status_code=status_code,
                content_type=content_type,
                bytes_written=bytes_written,
            )
        finally:
            active_exception = sys.exc_info()[0] is not None
            try:
                temporary_dir.cleanup()
            except OSError:
                if result is not None:
                    result.cleanup_warning = "staging cleanup warning"
                elif not active_exception:
                    raise
        assert result is not None
        return result

    def _stream_traffic_export(
        self,
        url: str,
        headers: dict[str, str],
        temporary: Path,
        cancel_event: threading.Event | ExportPublicationState | None,
    ) -> tuple[int, str, int]:
        bytes_written = 0
        with temporary.open("wb") as output:
            _check_export_cancel(cancel_event)
            with httpx.Client(timeout=self.timeout) as client:
                _check_export_cancel(cancel_event)
                with client.stream("GET", url, headers=headers) as response:
                    status_code = response.status_code
                    if status_code != 200:
                        raise APIError(f"Traffic export failed (HTTP {status_code})", status_code)
                    content_type = response.headers.get("content-type", "")
                    expected_length = _content_length(response.headers)
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        _check_export_cancel(cancel_event)
                        if not isinstance(chunk, bytes):
                            raise APIError("Traffic export returned an invalid byte chunk")
                        output.write(chunk)
                        bytes_written += len(chunk)
                    if expected_length is not None and bytes_written != expected_length:
                        raise APIError("Traffic export stream was truncated")
                    output.flush()
                    os.fsync(output.fileno())
        return status_code, content_type, bytes_written

    def traffic_websocket_messages(self, flow_id: str) -> dict[str, Any]:
        return self._request("GET", f"/admin/traffic/flows/{quote(flow_id, safe='')}/websocket/messages")

    def traffic_websocket_message_body(self, flow_id: str, message_id: int, offset: int = 0) -> dict[str, Any]:
        if type(offset) is not int or offset < 0:
            raise ValueError("message body offset must be a nonnegative integer")
        message = quote(str(message_id), safe="")
        return self._request(
            "GET", f"/admin/traffic/flows/{quote(flow_id, safe='')}/websocket/messages/{message}/body?offset={offset}",
        )

    def traffic_facets(self) -> dict[str, Any]:
        return self._request("GET", "/admin/traffic/facets")

    def set_traffic_scope(self, **scope: Any) -> dict[str, Any]:
        return self._request("PUT", "/admin/traffic/scope", json=scope)

    def set_traffic_filter(self, expression: str) -> dict[str, Any]:
        return self._request("PUT", "/admin/traffic/filter", json={"user_filter": expression})

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

    def activate_task_policy(self, task_id: str) -> dict[str, Any]:
        """Activate one registered task policy at the native policy boundary."""
        task_id = validate_task_id(task_id)
        return self._request(
            "POST",
            f"/admin/policy/task/{quote(task_id, safe='')}/activate",
        )

    def clear_task_policy(self, task_id: str) -> dict[str, Any]:
        """Clear one registered task policy and its active overlay."""
        task_id = validate_task_id(task_id)
        return self._request("DELETE", f"/admin/policy/task/{quote(task_id, safe='')}")

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
