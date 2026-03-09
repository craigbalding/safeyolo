"""
agent_relay.py - Read-only PDP query relay for agent self-service

Intercepts requests to virtual hostname _safeyolo.proxy.internal,
validates readonly bearer token, and returns PDP data as synthetic responses.
The request never goes upstream.

Loading order: Layer 0, after admin_shield, before loop_guard.
This ensures:
  - admin_shield already blocked port 9090 access
  - network_guard/credential_guard don't see relay requests
  - Sets flow.response + flow.metadata["blocked_by"] so downstream addons skip

Does NOT inherit SecurityAddon - this is an internal service endpoint,
not a security sensor. Follows the simpler AdminShield/LoopGuard pattern.

Usage:
    mitmdump -s addons/agent_relay.py --set admin_api_token=<token>
"""

import hmac
import json
import logging
import re

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.agent-relay")

RELAY_HOST = "_safeyolo.proxy.internal"
_REQUEST_ID_PATTERN = re.compile(r"^req-[a-f0-9]{12}$")
MAX_EXPLAIN_LINES = 10000


class AgentRelay:
    """Read-only PDP relay accessible through the proxy via virtual hostname."""

    name = "agent-relay"

    def load(self, loader):
        loader.add_option(
            name="agent_relay_enabled",
            typespec=bool,
            default=True,
            help="Enable agent relay endpoint on _safeyolo.proxy.internal",
        )

    def running(self):
        if ctx.options.agent_relay_enabled:
            log.info(f"Agent relay active on {RELAY_HOST}")
        else:
            log.info("Agent relay disabled")

    def request(self, flow: http.HTTPFlow):
        """Intercept requests to the relay virtual host."""
        if not ctx.options.agent_relay_enabled:
            return

        if flow.request.host != RELAY_HOST:
            return

        # This is a relay request - handle it entirely here
        path = flow.request.path.split("?")[0].rstrip("/") or "/"
        method = flow.request.method

        # Only GET allowed
        if method != "GET":
            self._respond(flow, 405, {"error": "Method Not Allowed", "allowed": ["GET"]})
            return

        # Validate token
        admin_token = self._get_admin_token()
        if not admin_token:
            log.warning("Agent relay: no admin token configured")
            self._respond(flow, 503, {"error": "Relay not configured"})
            return

        auth_header = flow.request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            self._respond(flow, 401, {"error": "Authorization required", "hint": "Bearer <token>"})
            return

        bearer_token = auth_header[7:]

        from pathlib import Path

        from pdp.tokens import read_active_token, validate_readonly_token

        # Check signature + expiry
        payload = validate_readonly_token(bearer_token, admin_token)
        if payload is None:
            self._respond(flow, 401, {"error": "Invalid or expired token"})
            return

        # Must match the current on-disk token (deleted on restart = instant revocation)
        active_token = read_active_token(Path("/safeyolo/data/readonly_token"))
        if active_token is None or not hmac.compare_digest(bearer_token, active_token):
            self._respond(flow, 401, {"error": "Token revoked or expired"})
            return

        # Route to handler
        handlers = {
            "/health": self._handle_health,
            "/status": self._handle_status,
            "/policy": self._handle_policy,
            "/budgets": self._handle_budgets,
            "/config": self._handle_config,
            "/explain": self._handle_explain,
            "/memory": self._handle_memory,
            "/circuits": self._handle_circuits,
        }

        handler = handlers.get(path)
        if handler is None:
            self._respond(flow, 404, {
                "error": "Not Found",
                "endpoints": list(handlers.keys()),
            })
            return

        try:
            handler(flow)
        except Exception as exc:
            log.error(f"Relay handler error: {type(exc).__name__}: {exc}")
            self._respond(flow, 500, {"error": f"Internal error: {type(exc).__name__}"})

    def _get_admin_token(self) -> str | None:
        """Get admin token from mitmproxy options, env var, or file."""
        # Try mitmproxy option first (set by admin_api addon)
        try:
            token = ctx.options.admin_api_token
            if token:
                return token
        except AttributeError as exc:
            # ctx.options may not have admin_api_token (addon not loaded or option renamed);
            # fall back to environment / file-based token sources.
            log.debug(f"admin_api_token option not available on ctx.options: {exc}")
        # Fallback to environment / file
        import os
        from pathlib import Path

        token = os.environ.get("ADMIN_API_TOKEN", "")
        if token:
            return token
        token_path = Path("/safeyolo/data/admin_token")
        if token_path.exists():
            return token_path.read_text().strip()
        return None

    def _get_policy_client(self):
        """Get PolicyClient, returning None if not configured."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                return None
            return get_policy_client()
        except Exception:
            return None

    def _respond(self, flow: http.HTTPFlow, status: int, body: dict):
        """Send synthetic JSON response."""
        flow.response = http.Response.make(
            status,
            json.dumps(body).encode(),
            {
                "Content-Type": "application/json",
                "X-SafeYolo-Relay": "true",
            },
        )
        flow.metadata["blocked_by"] = self.name

    def _find_addon(self, addon_name: str):
        """Find an addon by registered mitmproxy addon name."""
        # Check cache first
        cache = getattr(self, "_addon_cache", None)
        if cache is None:
            self._addon_cache = {}
            cache = self._addon_cache

        if addon_name in cache:
            return cache[addon_name]

        try:
            addons_obj = getattr(getattr(ctx, "master", None), "addons", None)
            addon = addons_obj.get(addon_name) if addons_obj else None
            if addon is not None:
                cache[addon_name] = addon
                return addon
        except Exception as exc:
            log.debug(f"Addon lookup failed: {type(exc).__name__}: {exc}")

        return None

    def _handle_circuits(self, flow: http.HTTPFlow):
        """GET /circuits - Circuit breaker state per domain."""
        cb = self._find_addon("circuit-breaker")
        if not cb:
            self._respond(flow, 503, {"error": "circuit-breaker addon not loaded"})
            return
        self._respond(flow, 200, cb.get_stats())

    def _handle_memory(self, flow: http.HTTPFlow):
        """GET /memory - Process memory and connection state."""
        monitor = self._find_addon("memory-monitor")
        if not monitor:
            self._respond(flow, 503, {"error": "memory-monitor addon not loaded"})
            return
        self._respond(flow, 200, monitor.get_stats())

    def _handle_health(self, flow: http.HTTPFlow):
        """GET /health - PDP health + relay alive."""
        client = self._get_policy_client()
        pdp_healthy = client.health_check() if client else False
        self._respond(flow, 200, {
            "relay": "ok",
            "pdp": "ok" if pdp_healthy else "unavailable",
        })

    def _handle_status(self, flow: http.HTTPFlow):
        """GET /status - PDP stats."""
        client = self._get_policy_client()
        if not client:
            self._respond(flow, 503, {"error": "PDP not available"})
            return
        stats = client.get_stats()
        self._respond(flow, 200, stats)

    def _handle_policy(self, flow: http.HTTPFlow):
        """GET /policy - Current baseline policy."""
        client = self._get_policy_client()
        if not client:
            self._respond(flow, 503, {"error": "PDP not available"})
            return
        baseline = client.get_baseline()
        self._respond(flow, 200, {"policy": baseline})

    def _handle_budgets(self, flow: http.HTTPFlow):
        """GET /budgets - Budget usage per domain."""
        client = self._get_policy_client()
        if not client:
            self._respond(flow, 503, {"error": "PDP not available"})
            return
        budget_stats = client.get_budget_stats()
        self._respond(flow, 200, budget_stats)

    def _handle_config(self, flow: http.HTTPFlow):
        """GET /config - Credential rules, scan patterns."""
        client = self._get_policy_client()
        if not client:
            self._respond(flow, 503, {"error": "PDP not available"})
            return
        config = client.get_sensor_config()
        self._respond(flow, 200, config)

    def _handle_explain(self, flow: http.HTTPFlow):
        """GET /explain?request_id=X - All events for a request ID."""
        query = flow.request.query
        request_id = query.get("request_id", "")
        if not request_id or not _REQUEST_ID_PATTERN.match(request_id):
            self._respond(flow, 400, {
                "error": "Invalid or missing request_id",
                "usage": "/explain?request_id=req-<12hex>",
            })
            return

        # Search JSONL log for matching events
        from pathlib import Path

        log_path = Path("/app/logs/safeyolo.jsonl")
        if not log_path.exists():
            self._respond(flow, 200, {"request_id": request_id, "events": []})
            return

        events = []
        truncated = False
        try:
            # Stream through file, retaining only last N lines (constant memory)
            from collections import deque

            with open(log_path) as fh:
                total_lines = 0
                scan_lines = deque(maxlen=MAX_EXPLAIN_LINES)
                for line in fh:
                    total_lines += 1
                    scan_lines.append(line)
                truncated = total_lines > MAX_EXPLAIN_LINES

            for line in scan_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("request_id") == request_id:
                        events.append(entry)
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            log.error(f"Explain search error: {type(exc).__name__}: {exc}")

        result = {"request_id": request_id, "events": events}
        if truncated:
            result["truncated"] = True
            result["searched_lines"] = MAX_EXPLAIN_LINES
        self._respond(flow, 200, result)


addons = [AgentRelay()]
