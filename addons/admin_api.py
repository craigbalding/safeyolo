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
import unicodedata
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from mitmproxy import ctx
from pdp import get_admin_client
from utils import write_event

log = logging.getLogger("safeyolo.admin")


# Safe unicode categories for logging (letters, numbers, punctuation, symbols, space)
_SAFE_CATEGORIES = frozenset({"Lu", "Ll", "Lt", "Lm", "Lo",  # Letters
                              "Nd", "Nl", "No",              # Numbers
                              "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",  # Punctuation
                              "Sm", "Sc", "Sk", "So",        # Symbols
                              "Zs"})                         # Space (but not Zl/Zp line seps)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# Explicit blocklist: ASCII control chars + Unicode line/paragraph separators
_BLOCKED_CODEPOINTS = frozenset(range(0x20)) | {0x7F, 0x2028, 0x2029}


def _is_safe_char(c: str) -> bool:
    """Check if character is safe for logging."""
    cp = ord(c)
    if cp in _BLOCKED_CODEPOINTS:
        return False
    return unicodedata.category(c) in _SAFE_CATEGORIES


def _sanitize_log(value: str, max_len: int = 200) -> str:
    """Sanitize user input for safe logging (prevent log injection).

    Uses Unicode category whitelist plus explicit codepoint blocklist.
    Replaces unsafe chars with '?' to make sanitization visible.
    """
    if value is None:
        return ""
    # Strip ANSI escapes first
    text = _ANSI_ESCAPE_RE.sub("?", str(value))
    # Replace unsafe characters with '?' (makes sanitization visible in logs)
    sanitized = "".join(c if _is_safe_char(c) else "?" for c in text)
    # Collapse repeated '?' to single '?'
    sanitized = re.sub(r"\?+", "?", sanitized)
    return sanitized[:max_len] + "..." if len(sanitized) > max_len else sanitized


class AdminRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for admin API requests."""

    # Reference to addon instances (set by AdminAPI)
    credential_guard = None
    addons_with_stats: dict = {}  # name -> addon instance
    admin_token = None  # Bearer token for authentication (set by AdminAPI)


    # Addons that support mode switching: name -> option_name
    # All options now use consistent "block" semantics: True=block, False=warn
    MODE_SWITCHABLE = {
        "network-guard": "network_guard_block",
        "credential-guard": "credguard_block",
        "pattern-scanner": "pattern_block_input",
        "yara-scanner": "yara_block_on_match",
        "prompt-injection": "injection_block",
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
            addon="admin-api",
            client_ip=client_ip,
            path=self.path,
            reason="invalid_or_missing_token"
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

        option_name = self.MODE_SWITCHABLE[addon_name]
        try:
            option_value = getattr(ctx.options, option_name)
            mode = "block" if option_value else "warn"
            return {
                "addon": addon_name,
                "mode": mode,
                "option": option_name,
                "option_value": option_value,
            }
        except AttributeError:
            return {"addon": addon_name, "mode": "unknown", "error": "option not available"}

    def _set_addon_mode(self, addon_name: str, mode: str) -> dict | None:
        """Set mode for an addon. Returns result dict or None if addon not found."""
        if addon_name not in self.MODE_SWITCHABLE:
            return None

        option_name = self.MODE_SWITCHABLE[addon_name]
        option_value = (mode == "block")

        try:
            setattr(ctx.options, option_name, option_value)
            log.info(f"Mode changed: {addon_name} -> {_sanitize_log(mode)} ({option_name}={option_value})")
            return {
                "addon": addon_name,
                "mode": mode,
                "option": option_name,
                "option_value": option_value,
                "status": "updated",
            }
        except Exception as e:
            log.error(f"Failed to set mode for {addon_name}: {type(e).__name__}: {e}")
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
        client = get_admin_client()
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
        client = get_admin_client()
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
        client = get_admin_client()
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
        client = get_admin_client()

        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        destination = data.get("destination")
        credential = data.get("credential")
        tier = data.get("tier", "explicit")

        if not destination:
            self._send_json({"error": "missing 'destination' field"}, 400)
            return
        if not credential:
            self._send_json({"error": "missing 'credential' field"}, 400)
            return

        result = client.add_credential_approval(
            destination=destination,
            credential=credential,
            tier=tier
        )

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        client_ip = self._get_client_ip()
        write_event("admin.baseline_approval_added",
            addon="admin-api",
            client_ip=client_ip,
            destination=destination,
            credential=credential,
            tier=tier
        )
        log.info(f"Baseline approval added: {_sanitize_log(credential)} -> {_sanitize_log(destination)}")  # lgtm[py/log-injection] sanitized

        self._send_json({
            "status": "added",
            "destination": destination,
            "credential": credential,
            "tier": tier,
            "permission_count": result.get("permission_count", 1)
        })

    def _handle_post_budgets_reset(self) -> None:
        """POST /admin/budgets/reset - Reset budget counters."""
        client = get_admin_client()

        data = self._read_json() or {}
        resource = data.get("resource")  # Optional: reset specific resource

        result = client.reset_budgets(resource=resource)

        if result.get("status") == "error":
            log.error(f"Failed to reset budgets: {result.get('error')}")
            self._send_json({"error": result.get("error")}, 500)
            return

        client_ip = self._get_client_ip()
        write_event("admin.budgets_reset",
            addon="admin-api",
            client_ip=client_ip,
            resource=resource
        )
        log.info(f"Budget counters reset: {_sanitize_log(resource) or 'all'}")
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
            addon="admin-api",
            client_ip=client_ip,
            target_addon="all",
            old_modes=old_modes,
            new_mode=mode
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
                addon="admin-api",
                client_ip=client_ip,
                target_addon=addon_name,
                old_mode=old_mode_value,
                new_mode=mode
            )
            self._send_json(result)

    def _handle_put_policy_baseline(self) -> None:
        """PUT /admin/policy/baseline - Update baseline policy."""
        client = get_admin_client()

        data = self._read_json()
        if not data:
            self._send_json({"error": "missing request body"}, 400)
            return

        policy_data = data.get("policy")
        if policy_data is None:
            self._send_json({"error": "missing 'policy' field in request body"}, 400)
            return

        result = client.update_baseline(policy_data)

        if result.get("status") == "error":
            self._send_json({"error": result.get("error")}, 400)
            return

        client_ip = self._get_client_ip()
        write_event("admin.baseline_update",
            addon="admin-api",
            client_ip=client_ip,
            permission_count=result.get("permission_count", 0)
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

        client = get_admin_client()

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
            addon="admin-api",
            client_ip=client_ip,
            task_id=task_id,
            permission_count=permission_count
        )
        log.info(f"Task policy '{task_id}' updated: {permission_count} permissions")

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

        # Start server after a delay (let other addons load first for discovery)
        def delayed_start():
            import time
            time.sleep(1)
            if self.server is None:
                try:
                    self._start_server()
                except Exception as e:
                    log.error(f"Failed to start admin server: {type(e).__name__}: {e}")

        threading.Thread(target=delayed_start, daemon=True).start()

    def configure(self, updates):
        """Handle configuration updates (server started via delayed_start in load())."""
        pass  # Server startup moved to delayed_start thread in load()

    def running(self):
        """Called when proxy is fully running - start admin server (backup for non-TUI mode)."""
        if self.server is not None:
            return  # Already started via configure()

        self._start_server()

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
        log.info(f"Admin API: discovered {len(AdminRequestHandler.addons_with_stats)} addons with stats")

        # Start HTTP server in background thread
        self.server = HTTPServer(("0.0.0.0", port), AdminRequestHandler)

        self.server_thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.server_thread.start()

        log.info(f"Admin API listening on port {port}")

    def _discover_addons(self):
        """Find and wire up other addons."""
        # Scripts loaded via -s are wrapped: AddonManager -> ScriptLoader -> Script -> module
        # The module has an 'addons' attribute containing actual addon class instances
        discovered = {}

        addons_obj = getattr(ctx.master, 'addons', None)
        if not addons_obj:
            return

        # Find ScriptLoader in the chain
        for chain_addon in addons_obj.chain:
            if type(chain_addon).__name__ != "ScriptLoader":
                continue

            # ScriptLoader.addons contains Script objects
            for script in getattr(chain_addon, 'addons', []):
                # Each Script has .addons which contains the loaded module
                for module in getattr(script, 'addons', []):
                    # The module has an 'addons' attribute with actual instances
                    module_addons = getattr(module, 'addons', [])
                    for addon in module_addons:
                        addon_name = getattr(addon, "name", None)
                        if not addon_name:
                            continue

                        # Special reference for credential guard
                        if addon_name == "credential-guard":
                            AdminRequestHandler.credential_guard = addon

                        # Collect any addon with get_stats() method
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


# mitmproxy addon instance
addons = [AdminAPI()]
