"""
admin_api.py - HTTP API addon for runtime control

Provides REST endpoints for:
- Policy management (baseline and task policies)
- Stats from all addons
- Health checks

Runs on a separate port from the main proxy.

Usage:
    mitmdump -s addons/admin_api.py --set admin_port=9090
"""

import json
import logging
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from mitmproxy import ctx
from utils import sanitize_for_log, write_event

from audit_schema import EventKind, Severity
from pdp import get_policy_client, is_policy_client_configured

log = logging.getLogger("safeyolo.admin")


# Alias for brevity within this module
_sanitize_log = sanitize_for_log


class AdminRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for admin API requests."""

    # Reference to addon instances (set by AdminAPI)
    credential_guard = None
    addons_with_stats: dict = {}  # name -> addon instance
    admin_token = None  # Bearer token for authentication (set by AdminAPI)

    # Addons that support mode switching: name -> list of option names
    # All options use consistent "block" semantics: True=block, False=warn
    MODE_SWITCHABLE = {
        "network-guard": ["network_guard_block"],
        "credential-guard": ["credguard_block"],
        "pattern-scanner": ["pattern_block_request", "pattern_block_response"],
    }

    def log_message(self, format, *args):
        """Override to use mitmproxy logging."""
        log.debug(f"Admin API: {format % args}")

    def _check_auth(self) -> bool:
        """Verify bearer token authentication.

        Returns:
            True if authenticated, False otherwise
        """
        if not self.admin_token:
            log.error("Admin API token not configured!")
            return False

        # Check Authorization header
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        # Extract and compare token (timing-attack resistant)
        provided_token = auth_header[7:]  # Strip "Bearer "
        return secrets.compare_digest(provided_token, self.admin_token)

    def _require_auth(self) -> bool:
        """Check auth and send 401 if unauthorized.

        Returns:
            True if should continue processing, False if unauthorized
        """
        if self._check_auth():
            return True

        client_ip = self._get_client_ip()
        write_event(
            "admin.auth_failure",
            kind=EventKind.ADMIN,
            severity=Severity.HIGH,
            summary=f"Auth failure from {_sanitize_log(client_ip)} on {_sanitize_log(self.path)}",
            addon="admin-api",
            details={"client_ip": client_ip, "path": self.path, "reason": "invalid_or_missing_token"},
        )
        self._send_json(
            {
                "error": "Unauthorized",
                "message": "Missing or invalid Bearer token",
                "hint": "Add header: Authorization: Bearer <token>",
            },
            401,
        )
        return False

    # Set by AdminAPI._discover_addons() — reference to mitmproxy's addon manager
    _addons_obj = None

    def _get_addon(self, addon_name: str):
        """Look up an addon by name — uses live addon manager to survive hot reloads."""
        if self._addons_obj:
            try:
                addon = self._addons_obj.get(addon_name)
                if addon is not None:
                    return addon
            except Exception:  # noqa: BLE001
                pass  # mitmproxy internals may raise; fall through to static cache
        # Fall back to static cache
        return self.addons_with_stats.get(addon_name)

    def _get_client_ip(self) -> str:
        """Get client IP for logging."""
        # Check X-Forwarded-For if behind proxy
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        """Read JSON from request body.

        Returns the parsed dict on success, or None if no body was sent.
        On malformed JSON, sends a 400 response directly and returns None
        so the caller's `if not data` check short-circuits correctly with
        the right error message already sent.
        """
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return None
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.warning("Malformed JSON in request body: %s: %s", type(e).__name__, e)
            self._send_json({"error": "Malformed JSON in request body", "detail": str(e)}, 400)
            return None
        except ValueError as e:
            log.warning("Invalid request body: %s: %s", type(e).__name__, e)
            return None

    def _get_addon_mode(self, addon_name: str) -> dict | None:
        """Get current mode for an addon."""
        if addon_name not in self.MODE_SWITCHABLE:
            return None

        option_names = self.MODE_SWITCHABLE[addon_name]
        try:
            option_values = {name: getattr(ctx.options, name) for name in option_names}
            # "block" if any option is True, "warn" if all are False
            any_blocking = any(option_values.values())
            mode = "block" if any_blocking else "warn"
            return {
                "addon": addon_name,
                "mode": mode,
                "options": option_values,
            }
        except AttributeError:
            return {"addon": addon_name, "mode": "unknown", "error": "option not available"}

    def _set_addon_mode(self, addon_name: str, mode: str) -> dict | None:
        """Set mode for an addon. Returns result dict or None if addon not found."""
        if addon_name not in self.MODE_SWITCHABLE:
            return None

        option_names = self.MODE_SWITCHABLE[addon_name]
        option_value = mode == "block"

        try:
            for option_name in option_names:
                setattr(ctx.options, option_name, option_value)
            option_values = dict.fromkeys(option_names, option_value)
            log.info(f"Mode changed: {_sanitize_log(addon_name)} -> {_sanitize_log(mode)} ({option_values})")
            return {
                "addon": addon_name,
                "mode": mode,
                "options": option_values,
                "status": "updated",
            }
        except Exception as e:
            log.error(f"Failed to set mode for {_sanitize_log(addon_name)}: {type(e).__name__}: {e}")
            return {"addon": addon_name, "error": f"{type(e).__name__}: {e}"}

    def _get_all_modes(self) -> dict:
        """Get current mode for all switchable addons."""
        modes = {}
        for addon_name in self.MODE_SWITCHABLE:
            info = self._get_addon_mode(addon_name)
            if info:
                modes[addon_name] = info.get("mode", "unknown")
        return modes

    def _set_all_modes(self, mode: str) -> dict:
        """Set mode for all switchable addons."""
        results = {}
        for addon_name in self.MODE_SWITCHABLE:
            result = self._set_addon_mode(addon_name, mode)
            if result:
                results[addon_name] = result.get("status", result.get("error", "unknown"))
        return results

    # =========================================================================
    # GET Handlers
    # =========================================================================

    def _handle_get_health(self) -> None:
        """GET /health - Health check (no auth required)."""
        self._send_json({"status": "ok"})

    def _handle_get_stats(self) -> None:
        """GET /stats - Aggregate stats from all addons."""
        stats = {"proxy": "safeyolo"}
        for name, addon in self.addons_with_stats.items():
            try:
                stats[name] = addon.get_stats()
            except Exception as e:
                stats[name] = {"error": f"{type(e).__name__}: {e}"}
        self._send_json(stats)

    def _handle_get_debug_addons(self) -> None:
        """GET /debug/addons - Debug addon discovery."""
        debug_info = {"discovered": list(self.addons_with_stats.keys())}
        try:
            addons_obj = ctx.master.addons
            debug_info["addons_type"] = type(addons_obj).__name__

            for addon in addons_obj.chain:
                if type(addon).__name__ == "ScriptLoader":
                    debug_info["script_loader_dir"] = [x for x in dir(addon) if not x.startswith("_")]
                    for attr in ["addons", "scripts", "script_paths", "loaded"]:
                        if hasattr(addon, attr):
                            val = getattr(addon, attr)
                            if hasattr(val, "__iter__") and not isinstance(val, str):
                                items = []
                                for item in val:
                                    item_info = {"type": type(item).__name__}
                                    if hasattr(item, "addons"):
                                        item_info["addons"] = [
                                            {
                                                "type": type(a).__name__,
                                                "name": getattr(a, "name", None),
                                                "has_stats": hasattr(a, "get_stats"),
                                            }
                                            for a in item.addons
                                        ]
                                    if hasattr(item, "path"):
                                        item_info["path"] = str(item.path)
                                    if hasattr(item, "name"):
                                        item_info["name"] = item.name
                                    items.append(item_info)
                                debug_info[f"scriptloader_{attr}"] = items
                            else:
                                debug_info[f"scriptloader_{attr}"] = str(val)[:200]
                    break

        except Exception as e:
            import traceback

            debug_info["error"] = f"{type(e).__name__}: {e}"
            debug_info["traceback"] = traceback.format_exc()
        self._send_json(debug_info)

    def _handle_get_modes(self) -> None:
        """GET /modes - Current mode for all switchable addons."""
        modes = self._get_all_modes()
        self._send_json({"modes": modes})

    def _handle_get_plugin_mode(self, addon_name: str) -> None:
        """GET /plugins/{name}/mode - Mode for a specific addon."""
        mode_info = self._get_addon_mode(addon_name)
        if mode_info is None:
            self._send_json({"error": f"addon '{addon_name}' not found or doesn't support mode switching"}, 404)
        else:
            self._send_json(mode_info)

    def _handle_get_policy_baseline(self) -> None:
        """GET /admin/policy/baseline - Read baseline policy."""
        client = get_policy_client()
        baseline = client.get_baseline()
        if baseline is None:
            self._send_json({"error": "No baseline policy loaded"}, 404)
            return
        self._send_json({"baseline": baseline, "path": client.get_baseline_path()})

    def _handle_get_policy_task(self, task_id: str) -> None:
        """GET /admin/policy/task/{id} - Read task policy."""
        if not task_id:
            self._send_json({"error": "missing task_id"}, 400)
            return
        client = get_policy_client()
        task_policy = client.get_task_policy(task_id)
        if task_policy is None:
            self._send_json({"error": f"Task policy '{task_id}' not found"}, 404)
            return
        self._send_json({"task_id": task_id, "policy": task_policy})

    def _handle_get_budgets(self) -> None:
        """GET /admin/budgets - Current budget usage."""
        client = get_policy_client()
        budget_stats = client.get_budget_stats()
        self._send_json(budget_stats)

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Health endpoint exempt from auth (for monitoring)
        if path == "/health":
            return self._handle_get_health()

        # All other endpoints require auth
        if not self._require_auth():
            return None

        # Static route dispatch
        static_handlers = {
            "/stats": self._handle_get_stats,
            "/debug/addons": self._handle_get_debug_addons,
            "/modes": self._handle_get_modes,
            "/admin/policy/baseline": self._handle_get_policy_baseline,
            "/admin/budgets": self._handle_get_budgets,
            "/admin/gateway/grants": self._handle_get_gateway_grants,
        }

        if path in static_handlers:
            return static_handlers[path]()

        # Parameterized routes
        if path.startswith("/plugins/") and path.endswith("/mode"):
            addon_name = path[9:-5]  # strip "/plugins/" and "/mode"
            return self._handle_get_plugin_mode(addon_name)

        if path.startswith("/admin/policy/task/"):
            task_id = path[19:]  # strip "/admin/policy/task/"
            return self._handle_get_policy_task(task_id)

        self._send_json({"error": "not found"}, 404)
        return None

    # =========================================================================
    # POST Handlers
    # =========================================================================

    def _handle_post_policy_validate(self) -> None:
        """POST /admin/policy/validate - Validate YAML content."""
        data = self._read_json()
        if not data or "content" not in data:
            self._send_json({"error": "missing 'content' field"}, 400)
            return

        try:
            import yaml

            yaml.safe_load(data["content"])
            self._send_json({"valid": True})
        except yaml.YAMLError as e:
            self._send_json({"valid": False, "error": str(e)}, 400)

    def _handle_post_baseline_approve(self) -> None:
        """POST /admin/policy/baseline/approve - Add credential permission."""
        client = get_policy_client()

        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        destination = data.get("destination")
        cred_id = data.get("cred_id")
        tier = data.get("tier", "explicit")

        if not destination:
            self._send_json({"error": "missing 'destination' field"}, 400)
            return
        if not cred_id:
            self._send_json({"error": "missing 'cred_id' field"}, 400)
            return

        result = client.add_credential_approval(destination=destination, cred_id=cred_id, tier=tier)

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.approval_added",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Baseline approval added: {_sanitize_log(cred_id)} -> {_sanitize_log(destination)}",
            addon="admin-api",
            details={"client_ip": client_ip, "destination": destination, "cred_id": cred_id, "tier": tier},
        )
        safe_cred_id = _sanitize_log(cred_id)
        safe_destination = _sanitize_log(destination)
        log.info(f"Baseline approval added: {safe_cred_id} -> {safe_destination}")

        self._send_json(
            {
                "status": "added",
                "destination": destination,
                "cred_id": cred_id,
                "tier": tier,
                "permission_count": result.get("permission_count", 1),
            }
        )

    def _handle_post_baseline_deny(self) -> None:
        """POST /admin/policy/baseline/deny - Log credential denial."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        destination = data.get("destination")
        cred_id = data.get("cred_id")
        reason = data.get("reason", "user_denied")

        if not destination:
            self._send_json({"error": "missing 'destination' field"}, 400)
            return
        if not cred_id:
            self._send_json({"error": "missing 'cred_id' field"}, 400)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.denial",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Credential denied: {_sanitize_log(cred_id)} -> {_sanitize_log(destination)}",
            addon="admin-api",
            details={"client_ip": client_ip, "destination": destination, "cred_id": cred_id, "reason": reason},
        )
        safe_cred_id = _sanitize_log(cred_id)
        safe_destination = _sanitize_log(destination)
        log.info(f"Credential denied: {safe_cred_id} -> {safe_destination} ({_sanitize_log(reason)})")

        self._send_json(
            {
                "status": "logged",
                "destination": destination,
                "cred_id": cred_id,
                "reason": reason,
            }
        )

    def _handle_post_gateway_grant(self) -> None:
        """POST /admin/gateway/grant - Add a risky route grant."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        agent = data.get("agent")
        service = data.get("service")
        method = data.get("method")
        path = data.get("path")
        lifetime = data.get("lifetime", "once")

        if not all([agent, service, method, path]):
            self._send_json({"error": "missing required fields: agent, service, method, path"}, 400)
            return

        if lifetime not in ("once", "session", "remembered"):
            # Allow integer seconds as session alias
            if isinstance(lifetime, int):
                lifetime = "session"
            else:
                self._send_json({"error": "lifetime must be 'once', 'session', or 'remembered'"}, 400)
                return

        # Find the service gateway addon (live lookup to survive hot reloads)
        gateway = self._get_addon("service-gateway")
        if not gateway or not hasattr(gateway, "add_grant"):
            self._send_json({"error": "service gateway not available"}, 503)
            return

        grant = gateway.add_grant(
            agent=agent,
            service=service,
            method=method,
            path=path,
            scope=lifetime,
        )

        client_ip = self._get_client_ip()
        write_event(
            "admin.gateway_grant",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Gateway grant added: {_sanitize_log(agent)}/{_sanitize_log(service)} {_sanitize_log(method)} {_sanitize_log(path)}",
            addon="admin-api",
            details={
                "client_ip": client_ip,
                "grant_id": grant.grant_id,
                "agent": agent,
                "service": service,
                "method": method,
                "path": path,
                "scope": lifetime,
            },
        )

        self._send_json(
            {
                "grant_id": grant.grant_id,
                "status": "granted",
            }
        )

    def _handle_get_gateway_grants(self) -> None:
        """GET /admin/gateway/grants - List active grants."""
        gateway = self._get_addon("service-gateway")
        if not gateway or not hasattr(gateway, "list_grants"):
            self._send_json({"error": "service gateway not available"}, 503)
            return

        grants = gateway.list_grants()
        self._send_json({"grants": grants})

    def _handle_delete_gateway_grant(self, grant_id: str) -> None:
        """DELETE /admin/gateway/grants/{id} - Revoke a grant."""
        if not grant_id:
            self._send_json({"error": "missing grant_id"}, 400)
            return

        gateway = self._get_addon("service-gateway")
        if not gateway or not hasattr(gateway, "revoke_grant"):
            self._send_json({"error": "service gateway not available"}, 503)
            return

        if gateway.revoke_grant(grant_id):
            client_ip = self._get_client_ip()
            write_event(
                "admin.gateway_grant_revoked",
                kind=EventKind.ADMIN,
                severity=Severity.MEDIUM,
                summary=f"Gateway grant revoked: {_sanitize_log(grant_id)}",
                addon="admin-api",
                details={"client_ip": client_ip, "grant_id": grant_id},
            )
            self._send_json({"status": "revoked", "grant_id": grant_id})
        else:
            self._send_json({"error": f"grant '{grant_id}' not found"}, 404)

    # =========================================================================
    # Agent Service Authorization
    # =========================================================================

    @staticmethod
    def _policy_toml_mutate(mutate_fn):
        """Read-modify-write policy.toml [agents] section under file lock.

        Args:
            mutate_fn: callable(agents_dict) -> result_value.
                       Receives the unwrapped agents dict, mutates it in place.
                       May raise KeyError/ValueError for 404/400.

        Returns:
            Whatever mutate_fn returns.

        Raises:
            RuntimeError: if PDP/loader not available.
            KeyError: propagated from mutate_fn (caller maps to 404).
            ValueError: propagated from mutate_fn (caller maps to 400).
        """
        from toml_roundtrip import (
            load_agents,
            locked_policy_mutate,
            policy_path_for_loader,
            upsert_agent,
        )

        if not is_policy_client_configured():
            raise RuntimeError("Policy client not configured")

        client = get_policy_client()
        pdp = getattr(client, "_pdp", None)
        engine = getattr(pdp, "_engine", None) if pdp else None
        loader = getattr(engine, "_loader", None) if engine else None
        if not loader:
            raise RuntimeError("Policy loader not available")

        policy_path = policy_path_for_loader(loader)
        if not policy_path:
            raise RuntimeError("Policy path not available")

        result_holder = []

        def _mutate(doc):
            agents = load_agents(doc)
            result = mutate_fn(agents)
            result_holder.append(result)
            # Write back all agents
            for name, data in agents.items():
                upsert_agent(doc, name, data)
            # Remove agents deleted by mutate_fn
            existing = doc.get("agents")
            if existing:
                for name in list(existing):
                    if name not in agents:
                        del existing[name]

        locked_policy_mutate(policy_path, _mutate)
        return result_holder[0] if result_holder else None

    def _handle_post_agent_service(self, agent_name: str) -> None:
        """POST /admin/agents/{name}/services - Authorize agent for a service."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        service = data.get("service")
        capability = data.get("capability")
        credential = data.get("credential")

        if not service or not capability or not credential:
            self._send_json({"error": "missing required fields: service, capability, credential"}, 400)
            return

        def mutate(raw):
            if agent_name not in raw:
                raise KeyError(agent_name)
            agent_data = raw[agent_name]
            services = agent_data.setdefault("services", {})
            services[service] = {"capability": capability, "token": credential}

        try:
            self._policy_toml_mutate(mutate)
        except RuntimeError as e:
            self._send_json({"error": str(e)}, 503)
            return
        except KeyError:
            self._send_json({"error": f"agent '{agent_name}' not found"}, 404)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.agent_service_authorized",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Agent service authorized: {_sanitize_log(agent_name)} -> {_sanitize_log(service)}",
            addon="admin-api",
            details={
                "client_ip": client_ip,
                "agent": agent_name,
                "service": service,
                "capability": capability,
                "credential": credential,
            },
        )
        log.info(
            f"Agent service authorized: {_sanitize_log(agent_name)} -> "
            f"{_sanitize_log(service)} (capability={_sanitize_log(capability)})"
        )

        self._send_json({
            "status": "authorized",
            "agent": agent_name,
            "service": service,
            "capability": capability,
        })

    def _handle_delete_agent_service(self, agent_name: str, service_name: str) -> None:
        """DELETE /admin/agents/{name}/services/{service} - Revoke agent service."""
        credential = ""

        def mutate(raw):
            nonlocal credential
            if agent_name not in raw:
                raise KeyError(agent_name)
            agent_data = raw[agent_name]
            services = agent_data.get("services", {})
            if service_name not in services:
                raise KeyError(service_name)
            entry = services[service_name]
            credential = entry.get("token", "") if isinstance(entry, dict) else ""
            del services[service_name]
            if not services:
                agent_data.pop("services", None)

        try:
            self._policy_toml_mutate(mutate)
        except RuntimeError as e:
            self._send_json({"error": str(e)}, 503)
            return
        except KeyError:
            self._send_json({"error": f"agent '{agent_name}' or service '{service_name}' not found"}, 404)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.agent_service_revoked",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Agent service revoked: {_sanitize_log(agent_name)} -> {_sanitize_log(service_name)}",
            addon="admin-api",
            details={
                "client_ip": client_ip,
                "agent": agent_name,
                "service": service_name,
                "credential": credential,
            },
        )
        log.info(f"Agent service revoked: {_sanitize_log(agent_name)} -> {_sanitize_log(service_name)}")

        self._send_json({
            "status": "revoked",
            "agent": agent_name,
            "service": service_name,
            "credential": credential,
        })

    def _handle_post_contract_binding(self) -> None:
        """POST /admin/gateway/contract-binding - Approve a contract binding."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        agent = data.get("agent")
        service = data.get("service")
        capability = data.get("capability")
        template = data.get("template", "")
        bindings = data.get("bindings", {})
        grantable_operations = data.get("grantable_operations", [])

        if not all([agent, service, capability]):
            self._send_json({"error": "missing required fields: agent, service, capability"}, 400)
            return

        if not isinstance(bindings, dict) or not bindings:
            self._send_json({"error": "bindings must be a non-empty object"}, 400)
            return

        # Find the service gateway addon (live lookup to survive hot reloads)
        gateway = self._get_addon("service-gateway")
        if not gateway or not hasattr(gateway, "add_contract_binding"):
            self._send_json({"error": "service gateway not available"}, 503)
            return

        binding_state = gateway.add_contract_binding(
            agent=agent,
            service=service,
            capability=capability,
            template=template,
            bound_values=bindings,
            grantable_operations=grantable_operations,
        )

        client_ip = self._get_client_ip()
        write_event(
            "admin.contract_binding_approved",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Contract binding approved: {_sanitize_log(agent)}/{_sanitize_log(service)}/{_sanitize_log(capability)}",
            addon="admin-api",
            details={
                "client_ip": client_ip,
                "binding_id": binding_state.binding_id,
                "agent": agent,
                "service": service,
                "capability": capability,
                "template": template,
                "bindings": bindings,
                "grantable_operations": grantable_operations,
            },
        )

        self._send_json({
            "binding_id": binding_state.binding_id,
            "status": "bound",
        })

    def _handle_post_host_rate(self) -> None:
        """POST /admin/policy/host/rate - Update host rate limit."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        host = data.get("host")
        rate = data.get("rate")

        if not host:
            self._send_json({"error": "missing 'host' field"}, 400)
            return
        if rate is None or not isinstance(rate, int) or rate < 1:
            self._send_json({"error": "'rate' must be a positive integer"}, 400)
            return

        client = get_policy_client()
        try:
            result = client.update_host_rate(host=host, rate=rate)
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        except Exception as e:
            log.error("Internal error updating host rate: %s: %s", type(e).__name__, e)
            self._send_json({"error": "Internal server error"}, 500)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.host_rate_updated",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host rate updated: {_sanitize_log(host)} {result.get('old_rate')} -> {rate}",
            addon="admin-api",
            details={"client_ip": client_ip, "host": host, "old_rate": result.get("old_rate"), "new_rate": rate},
        )
        log.info("Host rate updated: %s -> %s", _sanitize_log(host), _sanitize_log(str(rate)))
        self._send_json(result)

    def _handle_post_host_allow(self) -> None:
        """POST /admin/policy/host/allow - Allow a new host."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        host = data.get("host")
        rate = data.get("rate")  # optional
        agent = data.get("agent")  # optional — agent-scoped if set

        if not host or not isinstance(host, str):
            self._send_json({"error": "'host' must be a non-empty string"}, 400)
            return
        if rate is not None and (not isinstance(rate, int) or rate < 1):
            self._send_json({"error": "'rate' must be a positive integer if provided"}, 400)
            return
        if agent is not None and not isinstance(agent, str):
            self._send_json({"error": "'agent' must be a string if provided"}, 400)
            return

        client = get_policy_client()
        try:
            result = client.add_host_allowance(host=host, rate=rate, agent=agent)
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        except Exception as e:
            log.error("Internal error adding host allowance: %s: %s", type(e).__name__, e)
            self._send_json({"error": "Internal server error"}, 500)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.host_allowed",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host allowed: {_sanitize_log(host)} (rate={rate})",
            addon="admin-api",
            details={"client_ip": client_ip, "host": host, "rate": rate},
        )
        log.info("Host allowed: %s (rate=%s)", _sanitize_log(host), _sanitize_log(str(rate)))
        self._send_json(result)

    def _handle_post_host_deny(self) -> None:
        """POST /admin/policy/host/deny - Deny egress to a host."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        host = data.get("host")
        expires = data.get("expires")  # optional ISO datetime
        agent = data.get("agent")  # optional — agent-scoped if set

        if not host or not isinstance(host, str):
            self._send_json({"error": "'host' must be a non-empty string"}, 400)
            return
        if expires is not None and not isinstance(expires, str):
            self._send_json({"error": "'expires' must be an ISO datetime string"}, 400)
            return
        if agent is not None and not isinstance(agent, str):
            self._send_json({"error": "'agent' must be a string if provided"}, 400)
            return

        client = get_policy_client()
        try:
            result = client.add_host_denial(host=host, expires=expires, agent=agent)
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        except Exception as e:
            log.error("Host denial failed: %s: %s", type(e).__name__, e)
            self._send_json({"error": "Internal server error"}, 500)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.host_denied",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host denied: {_sanitize_log(host)} (expires={_sanitize_log(str(expires))})",
            addon="admin-api",
            details={"client_ip": client_ip, "host": host, "expires": expires},
        )
        log.info("Host denied: %s (expires=%s)", _sanitize_log(host), _sanitize_log(str(expires)))
        self._send_json(result)

    def _handle_post_circuit_breaker_reset(self) -> None:
        """POST /admin/circuit-breaker/reset - Reset circuit breaker for a host."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        host = data.get("host")
        if not host:
            self._send_json({"error": "missing 'host' field"}, 400)
            return

        cb = self._get_addon("circuit-breaker")
        if not cb or not hasattr(cb, "reset"):
            self._send_json({"error": "circuit breaker not available"}, 503)
            return

        cb.reset(host)

        client_ip = self._get_client_ip()
        write_event(
            "admin.circuit_breaker_reset",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Circuit breaker reset: {_sanitize_log(host)}",
            addon="admin-api",
            details={"client_ip": client_ip, "host": host},
        )
        log.info(f"Circuit breaker reset: {_sanitize_log(host)}")
        self._send_json({"status": "reset", "host": host})

    def _handle_post_host_bypass(self) -> None:
        """POST /admin/policy/host/bypass - Add addon bypass for a host."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        host = data.get("host")
        addon = data.get("addon")

        if not host:
            self._send_json({"error": "missing 'host' field"}, 400)
            return
        if not addon:
            self._send_json({"error": "missing 'addon' field"}, 400)
            return

        client = get_policy_client()
        try:
            result = client.add_host_bypass(host=host, addon=addon)
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        except Exception as e:
            log.error("Internal error adding host bypass: %s: %s", type(e).__name__, e)
            self._send_json({"error": "Internal server error"}, 500)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.host_bypass_added",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host bypass added: {_sanitize_log(host)} bypass={_sanitize_log(addon)}",
            addon="admin-api",
            details={"client_ip": client_ip, "host": host, "addon": addon, "bypass": result.get("bypass")},
        )
        log.info(f"Host bypass added: {_sanitize_log(host)} bypass={_sanitize_log(addon)}")
        self._send_json(result)

    def _handle_post_budgets_reset(self) -> None:
        """POST /admin/budgets/reset - Reset budget counters."""
        client = get_policy_client()

        data = self._read_json() or {}
        resource = data.get("resource")  # Optional: reset specific resource

        result = client.reset_budgets(resource=resource)

        if result.get("status") == "error":
            log.error(f"Failed to reset budgets: {result.get('error')}")
            self._send_json({"error": result.get("error")}, 500)
            return

        client_ip = self._get_client_ip()
        safe_resource = _sanitize_log(resource) if resource else "all"
        write_event(
            "admin.budgets_reset",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Budget counters reset: {safe_resource}",
            addon="admin-api",
            details={"client_ip": client_ip, "resource": resource},
        )
        log.info(f"Budget counters reset: {safe_resource}")
        self._send_json(result)

    def do_POST(self):
        """Handle POST requests."""
        if not self._require_auth():
            return None

        parsed = urlparse(self.path)
        path = parsed.path

        # Static route dispatch
        static_handlers = {
            "/admin/policy/validate": self._handle_post_policy_validate,
            "/admin/policy/baseline/approve": self._handle_post_baseline_approve,
            "/admin/policy/baseline/deny": self._handle_post_baseline_deny,
            "/admin/policy/host/rate": self._handle_post_host_rate,
            "/admin/policy/host/allow": self._handle_post_host_allow,
            "/admin/policy/host/deny": self._handle_post_host_deny,
            "/admin/policy/host/bypass": self._handle_post_host_bypass,
            "/admin/circuit-breaker/reset": self._handle_post_circuit_breaker_reset,
            "/admin/budgets/reset": self._handle_post_budgets_reset,
            "/admin/gateway/grant": self._handle_post_gateway_grant,
            "/admin/gateway/contract-binding": self._handle_post_contract_binding,
        }

        if path in static_handlers:
            return static_handlers[path]()

        # Parameterized routes
        m = re.match(r"^/admin/agents/([^/]+)/services$", path)
        if m:
            return self._handle_post_agent_service(m.group(1))

        self._send_json({"error": "not found"}, 404)
        return None

    # =========================================================================
    # PUT Handlers
    # =========================================================================

    def _handle_put_modes(self) -> None:
        """PUT /modes - Set mode for all switchable addons."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        mode = data.get("mode")
        if mode not in ("warn", "block"):
            self._send_json({"error": "mode must be 'warn' or 'block'"}, 400)
            return

        old_modes = self._get_all_modes()
        results = self._set_all_modes(mode)
        client_ip = self._get_client_ip()
        write_event(
            "admin.mode_change",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"All addons mode changed to {mode}",
            addon="admin-api",
            details={"client_ip": client_ip, "target_addon": "all", "old_modes": old_modes, "new_mode": mode},
        )
        self._send_json({"status": "updated", "mode": mode, "results": results})

    def _handle_put_plugin_mode(self, addon_name: str) -> None:
        """PUT /plugins/{name}/mode - Set mode for a specific addon."""
        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        mode = data.get("mode")
        if mode not in ("warn", "block"):
            self._send_json({"error": "mode must be 'warn' or 'block'"}, 400)
            return

        old_mode = self._get_addon_mode(addon_name)
        old_mode_value = old_mode.get("mode") if old_mode else None

        result = self._set_addon_mode(addon_name, mode)
        if result is None:
            self._send_json({"error": f"addon '{addon_name}' not found or doesn't support mode switching"}, 404)
        else:
            client_ip = self._get_client_ip()
            write_event(
                "admin.mode_change",
                kind=EventKind.ADMIN,
                severity=Severity.MEDIUM,
                summary=f"{_sanitize_log(addon_name)} mode changed to {mode}",
                addon="admin-api",
                details={
                    "client_ip": client_ip,
                    "target_addon": addon_name,
                    "old_mode": old_mode_value,
                    "new_mode": mode,
                },
            )
            self._send_json(result)

    def _handle_put_policy_baseline(self) -> None:
        """PUT /admin/policy/baseline - Replace baseline policy.

        Full baseline replacement is intended for machine-to-machine automation.
        This operation may not preserve YAML comments, layout, or human-authored
        formatting in policy.yaml. Operators who use inline comments as guidance
        should prefer incremental local updates or regenerate from a canonical source.
        """
        client = get_policy_client()

        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        policy_data = data.get("policy")
        if policy_data is None:
            self._send_json({"error": "missing 'policy' field in request body"}, 400)
            return

        result = client.replace_baseline(policy_data)

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        client_ip = self._get_client_ip()
        write_event(
            "admin.baseline_update",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Baseline policy updated: {result.get('permission_count', 0)} permissions",
            addon="admin-api",
            details={"client_ip": client_ip, "permission_count": result.get("permission_count", 0)},
        )
        log.info(f"Baseline policy updated: {result.get('permission_count', 0)} permissions")

        self._send_json(
            {
                "status": "updated",
                "permission_count": result.get("permission_count", 0),
                "message": "Baseline policy updated",
            }
        )

    def _handle_put_policy_task(self, task_id: str) -> None:
        """PUT /admin/policy/task/{id} - Create/update task policy."""
        if not task_id:
            self._send_json({"error": "missing task_id"}, 400)
            return

        client = get_policy_client()

        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        policy_data = data.get("policy")
        if policy_data is None:
            self._send_json({"error": "missing 'policy' field in request body"}, 400)
            return

        result = client.upsert_task_policy(task_id, policy_data)

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        # PDPCore returns 'permissions', normalize to 'permission_count' for compatibility
        permission_count = result.get("permissions", result.get("permission_count", 0))

        client_ip = self._get_client_ip()
        write_event(
            "admin.task_policy_update",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Task policy '{_sanitize_log(task_id)}' updated: {permission_count} permissions",
            addon="admin-api",
            details={"client_ip": client_ip, "task_id": task_id, "permission_count": permission_count},
        )
        log.info(f"Task policy '{_sanitize_log(task_id)}' updated: {permission_count} permissions")

        self._send_json(
            {
                "status": "updated",
                "task_id": task_id,
                "permission_count": permission_count,
                "message": "Task policy updated",
            }
        )

    def do_PUT(self):
        """Handle PUT requests."""
        if not self._require_auth():
            return None

        parsed = urlparse(self.path)
        path = parsed.path

        # Static route dispatch
        static_handlers = {
            "/modes": self._handle_put_modes,
            "/admin/policy/baseline": self._handle_put_policy_baseline,
        }

        if path in static_handlers:
            return static_handlers[path]()

        # Parameterized routes
        if path.startswith("/plugins/") and path.endswith("/mode"):
            addon_name = path[9:-5]  # strip "/plugins/" and "/mode"
            return self._handle_put_plugin_mode(addon_name)

        if path.startswith("/admin/policy/task/"):
            task_id = path[19:]  # strip "/admin/policy/task/"
            return self._handle_put_policy_task(task_id)

        self._send_json({"error": "not found"}, 404)
        return None

    def do_DELETE(self):
        """Handle DELETE requests."""
        # All DELETE endpoints require auth
        if not self._require_auth():
            return None

        parsed = urlparse(self.path)
        path = parsed.path

        # Parameterized routes
        if path.startswith("/admin/gateway/grants/"):
            grant_id = path[len("/admin/gateway/grants/") :]
            return self._handle_delete_gateway_grant(grant_id)

        m = re.match(r"^/admin/agents/([^/]+)/services/([^/]+)$", path)
        if m:
            return self._handle_delete_agent_service(m.group(1), m.group(2))

        self._send_json({"error": "not found"}, 404)
        return None


class AdminAPI:
    """
    Native mitmproxy addon that provides admin HTTP API.

    Discovers other addons to expose their stats and control methods.
    """

    name = "admin-api"

    def __init__(self):
        self.server: HTTPServer | None = None
        self.server_thread: threading.Thread | None = None

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="admin_port",
            typespec=int,
            default=9090,
            help="Port for admin API server",
        )
        loader.add_option(
            name="admin_api_token",
            typespec=str,
            default="",
            help="Bearer token for admin API authentication",
        )

    def configure(self, updates):
        """Handle configuration updates."""
        # Start server with delay to ensure mitmproxy is fully initialized
        if self.server is None and not hasattr(self, "_start_scheduled"):
            self._start_scheduled = True

            def delayed_start():
                import time

                # Wait for mitmproxy to fully initialize
                for attempt in range(10):
                    time.sleep(1)
                    if self.server is not None:
                        return  # Already started
                    if hasattr(ctx, "options") and hasattr(ctx, "master"):
                        try:
                            self._start_server()
                            return
                        except Exception as e:
                            log.error(f"Admin server start attempt {attempt + 1} failed: {type(e).__name__}: {e}")
                    else:
                        log.debug(f"Admin server waiting for ctx (attempt {attempt + 1})")
                log.error("Admin server failed to start after 10 attempts")

            threading.Thread(target=delayed_start, daemon=True).start()

    def running(self):
        """Called when proxy is fully running - backup server start."""
        if self.server is not None:
            return
        try:
            self._start_server()
        except Exception as e:
            log.error(f"Failed to start admin server in running(): {type(e).__name__}: {e}")

    def _start_server(self):
        """Start the admin HTTP server."""
        port = ctx.options.admin_port
        token = ctx.options.admin_api_token

        # Set token on handler class
        AdminRequestHandler.admin_token = token

        if token:
            log.info("Admin API: Authentication enabled")
        else:
            log.warning("Admin API: UNAUTHENTICATED - set admin_api_token option to enable auth")

        log.info(f"Admin API starting on port {port}...")

        # Find other addons to wire up
        self._discover_addons()

        # Start HTTP server in background thread with error handling
        # allow_reuse_address must be set before bind() — use class attribute
        HTTPServer.allow_reuse_address = True
        self.server = HTTPServer(("0.0.0.0", port), AdminRequestHandler)
        self._server_port = port

        def serve_with_recovery():
            """Run server with exception handling and auto-restart."""
            import sys
            import time
            import traceback

            while True:
                try:
                    print(f"[admin_api] Server thread starting on port {port}", file=sys.stderr, flush=True)
                    self.server.serve_forever()
                    # serve_forever only returns if shutdown() is called
                    print("[admin_api] Server shut down cleanly", file=sys.stderr, flush=True)
                    break
                except Exception as e:
                    print(f"[admin_api] CRASHED: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                    # Attempt restart after brief delay
                    time.sleep(1)
                    try:
                        self.server = HTTPServer(("0.0.0.0", port), AdminRequestHandler)
                        print("[admin_api] Restarting after crash", file=sys.stderr, flush=True)
                    except Exception as restart_err:
                        print(
                            f"[admin_api] Restart FAILED: {type(restart_err).__name__}: {restart_err}",
                            file=sys.stderr,
                            flush=True,
                        )
                        traceback.print_exc(file=sys.stderr)
                        break

        self.server_thread = threading.Thread(
            target=serve_with_recovery,
            daemon=True,
            name="admin-api-server",
        )
        self.server_thread.start()

        log.info(f"Admin API listening on port {port}")

    def _discover_addons(self):
        """Find and wire up other addons."""
        discovered = {}

        if not hasattr(ctx, "master") or ctx.master is None:
            log.debug("Admin API: ctx.master not available, skipping addon discovery")
            return

        addons_obj = getattr(ctx.master, "addons", None)
        if not addons_obj:
            return

        credential_guard = addons_obj.get("credential-guard")
        if credential_guard is not None:
            AdminRequestHandler.credential_guard = credential_guard

        for addon in addons_obj.lookup.values():
            addon_name = getattr(addon, "name", None)
            if not addon_name:
                continue

            if hasattr(addon, "get_stats") and callable(addon.get_stats):
                discovered[addon_name] = addon
                log.debug(f"Admin API: found {addon_name} addon")

        AdminRequestHandler.addons_with_stats = discovered
        AdminRequestHandler._addons_obj = addons_obj
        log.info(f"Admin API: discovered {len(discovered)} addons with stats")

    def done(self):
        """Cleanup on shutdown."""
        if self.server:
            self.server.shutdown()
            log.info("Admin API stopped")


# add mitmproxy addon instance
addons = [AdminAPI()]
