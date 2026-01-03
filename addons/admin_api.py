"""
admin_api.py - HTTP API addon for runtime control

Provides REST endpoints for:
- Temporary allowlist management (credential guard)
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
except ImportError:
    from utils import write_event

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

        elif path == "/plugins/credential-guard/allowlist":
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return
            entries = self.credential_guard.get_temp_allowlist()
            self._send_json({"allowlist": entries})

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

        elif path.startswith("/admin/policy/"):
            # GET /admin/policy/{project} - Read project policy file
            project_id = path[14:]  # strip "/admin/policy/"
            if not project_id:
                self._send_json({"error": "missing project_id"}, 400)
                return
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return
            if not hasattr(self.credential_guard, 'policy_store') or not self.credential_guard.policy_store:
                self._send_json({"error": "policy store not available"}, 501)
                return
            policy = self.credential_guard.policy_store.get_policy(project_id)
            self._send_json({"project": project_id, "policy": policy})

        elif path == "/admin/policies":
            # GET /admin/policies - List all policies
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return
            if not hasattr(self.credential_guard, 'policy_store') or not self.credential_guard.policy_store:
                self._send_json({"error": "policy store not available"}, 501)
                return
            ps = self.credential_guard.policy_store
            policies = list(ps._policies.keys()) if hasattr(ps, '_policies') else []
            self._send_json({"policies": policies, "policy_dir": str(ps.policy_dir)})

        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        """Handle POST requests."""
        # All POST endpoints require auth
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/plugins/credential-guard/allowlist":
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return

            data = self._read_json()
            if not data:
                self._send_json({"error": "missing request body"}, 400)
                return

            prefix = data.get("prefix")
            host = data.get("host")
            duration = data.get("duration_minutes", 5)

            if not prefix or not host:
                self._send_json({"error": "missing prefix or host"}, 400)
                return

            self.credential_guard.add_temp_allowlist(prefix, host, duration * 60)
            self._send_json({
                "status": "added",
                "prefix": prefix,
                "host": host,
                "duration_minutes": duration,
            })

        elif path == "/admin/policy/validate":
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

        elif path.startswith("/admin/policy/") and path.endswith("/approve"):
            # POST /admin/policy/{project}/approve - Add approval rule to policy
            # Path: /admin/policy/{project}/approve
            project_id = path[14:-8]  # strip "/admin/policy/" and "/approve"
            if not project_id:
                self._send_json({"error": "missing project_id"}, 400)
                return
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return
            if not hasattr(self.credential_guard, 'policy_store') or not self.credential_guard.policy_store:
                self._send_json({"error": "policy store not available"}, 501)
                return

            data = self._read_json()
            if not data:
                self._send_json({"error": "missing request body"}, 400)
                return

            # Required fields
            token_hmac = data.get("token_hmac")
            hosts = data.get("hosts", [])
            paths = data.get("paths", ["/**"])
            name = data.get("name", "")

            if not token_hmac:
                self._send_json({"error": "missing 'token_hmac' field"}, 400)
                return
            if not hosts:
                self._send_json({"error": "missing 'hosts' field"}, 400)
                return

            ps = self.credential_guard.policy_store
            policy_path = ps.policy_dir / f"{project_id}.yaml"

            try:
                import yaml
                import tempfile
                import shutil
                from datetime import datetime

                # Load existing policy
                policy = ps.get_policy(project_id) or {}
                approved = policy.get("approved", [])

                # Check for duplicate
                for rule in approved:
                    if rule.get("token_hmac") == token_hmac:
                        if set(rule.get("hosts", [])) == set(hosts):
                            self._send_json({
                                "status": "exists",
                                "message": "Approval rule already exists"
                            })
                            return

                # Add new rule
                new_rule = {
                    "token_hmac": token_hmac,
                    "hosts": hosts,
                    "paths": paths,
                    "added": datetime.now().isoformat(),
                }
                if name:
                    new_rule["name"] = name

                approved.append(new_rule)
                policy["approved"] = approved

                # Atomic write
                content = yaml.safe_dump(policy, default_flow_style=False, allow_unicode=True)
                ps.policy_dir.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.yaml', dir=ps.policy_dir, delete=False
                ) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                shutil.move(tmp_path, policy_path)

                # Log
                client_ip = self._get_client_ip()
                write_event("admin.approval_added",
                    addon="admin-api",
                    client_ip=client_ip,
                    project_id=project_id,
                    token_hmac=token_hmac[:16],
                    hosts=hosts
                )
                log.info(f"Approval added to '{project_id}': hmac:{token_hmac[:16]} -> {hosts}")

                self._send_json({
                    "status": "added",
                    "project": project_id,
                    "token_hmac": token_hmac[:16] + "...",
                    "hosts": hosts,
                    "approved_count": len(approved),
                    "message": "Approval added. File watcher will reload within 1s."
                })

            except Exception as e:
                log.error(f"Failed to add approval: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to add approval: {type(e).__name__}: {e}"}, 500)

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

        elif path.startswith("/admin/policy/"):
            # PUT /admin/policy/{project} - Write/update project policy
            project_id = path[14:]  # strip "/admin/policy/"
            if not project_id:
                self._send_json({"error": "missing project_id"}, 400)
                return
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return
            if not hasattr(self.credential_guard, 'policy_store') or not self.credential_guard.policy_store:
                self._send_json({"error": "policy store not available"}, 501)
                return

            data = self._read_json()
            if not data:
                self._send_json({"error": "missing request body"}, 400)
                return

            policy = data.get("policy")
            if policy is None:
                self._send_json({"error": "missing 'policy' field in request body"}, 400)
                return

            # Write policy to file (atomic write)
            ps = self.credential_guard.policy_store
            policy_path = ps.policy_dir / f"{project_id}.yaml"

            try:
                import yaml
                import tempfile
                import shutil

                # Validate YAML can be serialized
                content = yaml.safe_dump(policy, default_flow_style=False, allow_unicode=True)

                # Atomic write: write to temp file, then rename
                ps.policy_dir.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.yaml', dir=ps.policy_dir, delete=False
                ) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                shutil.move(tmp_path, policy_path)

                # Log the write
                client_ip = self._get_client_ip()
                write_event("admin.policy_write",
                    addon="admin-api",
                    client_ip=client_ip,
                    project_id=project_id,
                    approved_count=len(policy.get("approved", []))
                )
                log.info(f"Policy '{project_id}' written: {len(policy.get('approved', []))} approved rules")

                self._send_json({
                    "status": "written",
                    "project": project_id,
                    "approved_count": len(policy.get("approved", [])),
                    "message": "Policy written. File watcher will reload within 1s."
                })

            except yaml.YAMLError as e:
                self._send_json({"error": f"Invalid policy YAML: {e}"}, 400)
            except Exception as e:
                log.error(f"Failed to write policy: {type(e).__name__}: {e}")
                self._send_json({"error": f"Failed to write policy: {type(e).__name__}: {e}"}, 500)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        """Handle DELETE requests."""
        # All DELETE endpoints require auth
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/plugins/credential-guard/allowlist":
            if not self.credential_guard:
                self._send_json({"error": "credential-guard not loaded"}, 404)
                return

            # Clear all entries
            self.credential_guard.temp_allowlist.clear()
            self._send_json({"status": "cleared"})

        else:
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
