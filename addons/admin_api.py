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
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlparse, parse_qs

from mitmproxy import ctx

try:
    from .utils import write_event
    from .policy_engine import get_policy_engine, init_policy_engine
except ImportError:
    from utils import write_event
    from policy_engine import get_policy_engine, init_policy_engine

log = logging.getLogger("safeyolo.admin")


class AdminRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for admin API requests."""

    # Reference to addon instances (set by AdminAPI)
    credential_guard = None
    addons_with_stats: dict = {}  # name -> addon instance
    admin_token = None  # Bearer token for authentication (set by AdminAPI)


    # Addons that support mode switching: name -> option_name
    # All options now use consistent "block" semantics: True=block, False=warn
    MODE_SWITCHABLE = {
        "credential-guard": "credguard_block",
        "rate-limiter": "ratelimit_block",
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

    def _read_json(self) -> Optional[dict]:
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

    def _get_addon_mode(self, addon_name: str) -> Optional[dict]:
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

    def _set_addon_mode(self, addon_name: str, mode: str) -> Optional[dict]:
        """Set mode for an addon. Returns result dict or None if addon not found."""
        if addon_name not in self.MODE_SWITCHABLE:
            return None

        option_name = self.MODE_SWITCHABLE[addon_name]
        option_value = (mode == "block")

        try:
            setattr(ctx.options, option_name, option_value)
            log.info(f"Mode changed: {addon_name} -> {mode} ({option_name}={option_value})")
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

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Health endpoint exempt from auth (for monitoring)
        if path == "/health":
            self._send_json({"status": "healthy", "proxy": "safeyolo"})
            return

        # All other endpoints require auth
        if not self._require_auth():
            return

        if path == "/stats":
            stats = {"proxy": "safeyolo"}
            for name, addon in self.addons_with_stats.items():
                try:
                    stats[name] = addon.get_stats()
                except Exception as e:
                    stats[name] = {"error": f"{type(e).__name__}: {e}"}
            self._send_json(stats)

        elif path == "/debug/addons":
            # Debug endpoint to inspect addon discovery
            debug_info = {"discovered": list(self.addons_with_stats.keys())}
            try:
                addons_obj = ctx.master.addons
                debug_info["addons_type"] = type(addons_obj).__name__

                # Script addons are wrapped - look for ScriptLoader
                for addon in addons_obj.chain:
                    if type(addon).__name__ == "ScriptLoader":
                        debug_info["script_loader_dir"] = [x for x in dir(addon) if not x.startswith('_')]
                        # Check what attributes exist
                        for attr in ['addons', 'scripts', 'script_paths', 'loaded']:
                            if hasattr(addon, attr):
                                val = getattr(addon, attr)
                                if hasattr(val, '__iter__') and not isinstance(val, str):
                                    items = []
                                    for item in val:
                                        item_info = {"type": type(item).__name__}
                                        # Script objects have .addons attribute with actual addon instances
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

        elif path == "/modes":
            # Get current mode for all switchable addons
            modes = self._get_all_modes()
            self._send_json({"modes": modes})

        elif path.startswith("/plugins/") and path.endswith("/mode"):
            # GET /plugins/{name}/mode
            addon_name = path[9:-5]  # strip "/plugins/" and "/mode"
            mode_info = self._get_addon_mode(addon_name)
            if mode_info is None:
                self._send_json({"error": f"addon '{addon_name}' not found or doesn't support mode switching"}, 404)
            else:
                self._send_json(mode_info)

        elif path == "/admin/policy/baseline":
            # GET /admin/policy/baseline - Read baseline policy
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return
            policy = engine.get_baseline()
            if policy is None:
                self._send_json({"error": "No baseline policy loaded"}, 404)
                return
            self._send_json({
                "baseline": policy.model_dump(),
                "path": str(engine.baseline_path) if engine.baseline_path else None
            })

        elif path.startswith("/admin/policy/task/"):
            # GET /admin/policy/task/{id} - Read task policy
            task_id = path[19:]  # strip "/admin/policy/task/"
            if not task_id:
                self._send_json({"error": "missing task_id"}, 400)
                return
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return
            task_policy = engine.get_task_policy(task_id)
            if task_policy is None:
                self._send_json({"error": f"Task policy '{task_id}' not found"}, 404)
                return
            self._send_json({
                "task_id": task_id,
                "policy": task_policy.model_dump()
            })

        elif path == "/admin/budgets":
            # GET /admin/budgets - Current budget usage
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return
            budget_stats = engine.get_budget_stats()
            self._send_json(budget_stats)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        """Handle POST requests."""
        # All POST endpoints require auth
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/admin/policy/validate":
            # POST /admin/policy/validate - Validate YAML content
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

        elif path == "/admin/policy/baseline/approve":
            # POST /admin/policy/baseline/approve - Add credential permission
            # Destination-first: specify what credentials can access a destination
            #
            # Request format:
            #   destination: str - destination pattern (e.g., "api.example.com")
            #   credential: str | list[str] - credential type(s) or HMAC(s)
            #                (e.g., "openai:*", "hmac:a1b2c3d4", ["openai:*", "anthropic:*"])
            #   tier: str - "explicit" or "inferred" (default: "explicit")
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return

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

            try:
                result = engine.add_credential_approval(
                    destination=destination,
                    credential=credential,
                    tier=tier
                )

                client_ip = self._get_client_ip()
                write_event("admin.baseline_approval_added",
                    addon="admin-api",
                    client_ip=client_ip,
                    destination=destination,
                    credential=credential,
                    tier=tier
                )
                log.info(f"Baseline approval added: {credential} -> {destination}")

                self._send_json({
                    "status": "added",
                    "destination": destination,
                    "credential": credential,
                    "tier": tier,
                    "permission_count": result.get("permission_count", 1)
                })

            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
            except Exception as e:
                log.error(f"Failed to add approval: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to add approval: {type(e).__name__}: {e}"}, 500)

        elif path == "/admin/budgets/reset":
            # POST /admin/budgets/reset - Reset budget counters
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return

            data = self._read_json() or {}
            resource = data.get("resource")  # Optional: reset specific resource

            try:
                result = engine.reset_budgets(resource=resource)
                client_ip = self._get_client_ip()
                write_event("admin.budgets_reset",
                    addon="admin-api",
                    client_ip=client_ip,
                    resource=resource
                )
                log.info(f"Budget counters reset: {resource or 'all'}")
                self._send_json(result)
            except Exception as e:
                log.error(f"Failed to reset budgets: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to reset budgets: {type(e).__name__}: {e}"}, 500)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_PUT(self):
        """Handle PUT requests."""
        # All PUT endpoints require auth
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/modes":
            # PUT /modes - set mode for all addons at once
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

        elif path.startswith("/plugins/") and path.endswith("/mode"):
            # PUT /plugins/{name}/mode
            addon_name = path[9:-5]  # strip "/plugins/" and "/mode"

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

        elif path == "/admin/policy/baseline":
            # PUT /admin/policy/baseline - Update baseline policy
            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return

            data = self._read_json()
            if not data:
                self._send_json({"error": "missing request body"}, 400)
                return

            policy_data = data.get("policy")
            if policy_data is None:
                self._send_json({"error": "missing 'policy' field in request body"}, 400)
                return

            try:
                result = engine.update_baseline(policy_data)

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

            except ValueError as e:
                self._send_json({"error": f"Invalid policy: {e}"}, 400)
            except Exception as e:
                log.error(f"Failed to update baseline: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to update baseline: {type(e).__name__}: {e}"}, 500)

        elif path.startswith("/admin/policy/task/"):
            # PUT /admin/policy/task/{id} - Create/update task policy
            task_id = path[19:]  # strip "/admin/policy/task/"
            if not task_id:
                self._send_json({"error": "missing task_id"}, 400)
                return

            engine = get_policy_engine()
            if engine is None:
                self._send_json({"error": "PolicyEngine not initialized"}, 501)
                return

            data = self._read_json()
            if not data:
                self._send_json({"error": "missing request body"}, 400)
                return

            policy_data = data.get("policy")
            if policy_data is None:
                self._send_json({"error": "missing 'policy' field in request body"}, 400)
                return

            try:
                result = engine.set_task_policy(task_id, policy_data)

                client_ip = self._get_client_ip()
                write_event("admin.task_policy_update",
                    addon="admin-api",
                    client_ip=client_ip,
                    task_id=task_id,
                    permission_count=result.get("permission_count", 0)
                )
                log.info(f"Task policy '{task_id}' updated: {result.get('permission_count', 0)} permissions")

                self._send_json({
                    "status": "updated",
                    "task_id": task_id,
                    "permission_count": result.get("permission_count", 0),
                    "message": "Task policy updated"
                })

            except ValueError as e:
                self._send_json({"error": f"Invalid policy: {e}"}, 400)
            except Exception as e:
                log.error(f"Failed to update task policy: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to update task policy: {type(e).__name__}: {e}"}, 500)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        """Handle DELETE requests."""
        # All DELETE endpoints require auth
        if not self._require_auth():
            return

        self._send_json({"error": "not found"}, 404)


class AdminAPI:
    """
    Native mitmproxy addon that provides admin HTTP API.

    Discovers other addons to expose their stats and control methods.
    """

    name = "admin-api"

    def __init__(self):
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

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
            log.info(f"Admin API: Authentication enabled (token: {token[:8]}...)")
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
