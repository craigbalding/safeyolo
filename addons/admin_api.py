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
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from mitmproxy import ctx
from utils import sanitize_for_log, write_event

from audit_schema import EventKind, Severity
from pdp import get_policy_client

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
        write_event("admin.auth_failure",
            kind=EventKind.ADMIN,
            severity=Severity.HIGH,
            summary=f"Auth failure from {_sanitize_log(client_ip)} on {_sanitize_log(self.path)}",
            addon="admin-api",
            details={"client_ip": client_ip, "path": self.path, "reason": "invalid_or_missing_token"},
        )
        self._send_json({
            "error": "Unauthorized",
            "message": "Missing or invalid Bearer token",
            "hint": "Add header: Authorization: Bearer <token>"
        }, 401)
        return False

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
        """Read JSON from request body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return None
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            log.warning(f"Invalid JSON in request body: {type(e).__name__}: {e}")
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
        option_value = (mode == "block")

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
                    debug_info["script_loader_dir"] = [x for x in dir(addon) if not x.startswith('_')]
                    for attr in ['addons', 'scripts', 'script_paths', 'loaded']:
                        if hasattr(addon, attr):
                            val = getattr(addon, attr)
                            if hasattr(val, '__iter__') and not isinstance(val, str):
                                items = []
                                for item in val:
                                    item_info = {"type": type(item).__name__}
                                    if hasattr(item, 'addons'):
                                        item_info["addons"] = [
                                            {"type": type(a).__name__, "name": getattr(a, "name", None), "has_stats": hasattr(a, "get_stats")}
                                            for a in item.addons
                                        ]
                                    if hasattr(item, 'path'):
                                        item_info["path"] = str(item.path)
                                    if hasattr(item, 'name'):
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
        self._send_json({
            "baseline": baseline,
            "path": client.get_baseline_path()
        })

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
        self._send_json({
            "task_id": task_id,
            "policy": task_policy
        })

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

        result = client.add_credential_approval(
            destination=destination,
            cred_id=cred_id,
            tier=tier
        )

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        client_ip = self._get_client_ip()
        write_event("admin.approval_added",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Baseline approval added: {_sanitize_log(cred_id)} -> {_sanitize_log(destination)}",
            addon="admin-api",
            details={"client_ip": client_ip, "destination": destination, "cred_id": cred_id, "tier": tier},
        )
        safe_cred_id = _sanitize_log(cred_id)
        safe_destination = _sanitize_log(destination)
        log.info(f"Baseline approval added: {safe_cred_id} -> {safe_destination}")

        self._send_json({
            "status": "added",
            "destination": destination,
            "cred_id": cred_id,
            "tier": tier,
            "permission_count": result.get("permission_count", 1)
        })

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
        write_event("admin.denial",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Credential denied: {_sanitize_log(cred_id)} -> {_sanitize_log(destination)}",
            addon="admin-api",
            details={"client_ip": client_ip, "destination": destination, "cred_id": cred_id, "reason": reason},
        )
        safe_cred_id = _sanitize_log(cred_id)
        safe_destination = _sanitize_log(destination)
        log.info(f"Credential denied: {safe_cred_id} -> {safe_destination} ({reason})")

        self._send_json({
            "status": "logged",
            "destination": destination,
            "cred_id": cred_id,
            "reason": reason,
        })

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
        write_event("admin.budgets_reset",
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
            "/admin/budgets/reset": self._handle_post_budgets_reset,
        }

        if path in static_handlers:
            return static_handlers[path]()

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
        write_event("admin.mode_change",
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
            write_event("admin.mode_change",
                kind=EventKind.ADMIN,
                severity=Severity.MEDIUM,
                summary=f"{_sanitize_log(addon_name)} mode changed to {mode}",
                addon="admin-api",
                details={"client_ip": client_ip, "target_addon": addon_name, "old_mode": old_mode_value, "new_mode": mode},
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
        write_event("admin.baseline_update",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Baseline policy updated: {result.get('permission_count', 0)} permissions",
            addon="admin-api",
            details={"client_ip": client_ip, "permission_count": result.get("permission_count", 0)},
        )
        log.info(f"Baseline policy updated: {result.get('permission_count', 0)} permissions")

        self._send_json({
            "status": "updated",
            "permission_count": result.get("permission_count", 0),
            "message": "Baseline policy updated"
        })

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
        write_event("admin.task_policy_update",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Task policy '{_sanitize_log(task_id)}' updated: {permission_count} permissions",
            addon="admin-api",
            details={"client_ip": client_ip, "task_id": task_id, "permission_count": permission_count},
        )
        log.info(f"Task policy '{_sanitize_log(task_id)}' updated: {permission_count} permissions")

        self._send_json({
            "status": "updated",
            "task_id": task_id,
            "permission_count": permission_count,
            "message": "Task policy updated"
        })

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
        if self.server is None and not hasattr(self, '_start_scheduled'):
            self._start_scheduled = True

            def delayed_start():
                import time
                # Wait for mitmproxy to fully initialize
                for attempt in range(10):
                    time.sleep(1)
                    if self.server is not None:
                        return  # Already started
                    if hasattr(ctx, 'options') and hasattr(ctx, 'master'):
                        try:
                            self._start_server()
                            return
                        except Exception as e:
                            log.error(f"Admin server start attempt {attempt+1} failed: {type(e).__name__}: {e}")
                    else:
                        log.debug(f"Admin server waiting for ctx (attempt {attempt+1})")
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
                        print(f"[admin_api] Restart FAILED: {type(restart_err).__name__}: {restart_err}", file=sys.stderr, flush=True)
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

        if not hasattr(ctx, 'master') or ctx.master is None:
            log.debug("Admin API: ctx.master not available, skipping addon discovery")
            return

        addons_obj = getattr(ctx.master, 'addons', None)
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
        log.info(f"Admin API: discovered {len(discovered)} addons with stats")

    def done(self):
        """Cleanup on shutdown."""
        if self.server:
            self.server.shutdown()
            log.info("Admin API stopped")


# add mitmproxy addon instance
addons = [AdminAPI()]
