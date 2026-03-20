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

import base64
import hmac
import json
import logging
import re
import urllib.parse

from flow_store import is_text_like_content_type
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

        # Method validation: GET for most routes, POST/DELETE allowed for /api/flows/ prefix
        if method not in ("GET", "POST", "DELETE"):
            self._respond(flow, 405, {"error": "Method Not Allowed", "allowed": ["GET", "POST", "DELETE"]})
            return
        if method in ("POST", "DELETE") and not path.startswith("/api/flows"):
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
            "/agents": self._handle_agents,
            "/circuits": self._handle_circuits,
            "/gateway/services": self._handle_gateway_services,
        }

        # POST handlers for flow store API
        post_handlers = {
            "/api/flows/search": self._handle_flow_search,
            "/api/flows/endpoints": self._handle_flow_endpoints,
            "/api/flows/body-search": self._handle_flow_body_search,
            "/api/flows/diff": self._handle_flow_diff,
            "/api/flows/request-body-search": self._handle_flow_request_body_search,
        }

        handler = handlers.get(path)

        # Check POST handlers
        if handler is None and method == "POST":
            handler = post_handlers.get(path)

        # Check parameterized routes: /api/flows/{id}[/request-body|/response-body|/tag[/{name}]]
        if handler is None:
            m = re.match(r"^/api/flows/(\d+)(/request-body|/response-body|/tag(?:/([^/]+))?)?$", path)
            if m:
                flow_id = int(m.group(1))
                suffix = m.group(2)
                tag_name = m.group(3)
                if suffix == "/request-body":
                    def handler(f, _fid=flow_id):
                        self._handle_flow_request_body(f, _fid)
                elif suffix == "/response-body":
                    def handler(f, _fid=flow_id):
                        self._handle_flow_response_body(f, _fid)
                elif suffix is not None and suffix.startswith("/tag"):
                    if method == "POST" and tag_name is None:
                        def handler(f, _fid=flow_id):
                            self._handle_flow_tag_add(f, _fid)
                    elif method == "DELETE" and tag_name is not None:
                        def handler(f, _fid=flow_id, _tn=tag_name):
                            self._handle_flow_tag_delete(f, _fid, _tn)
                    else:
                        handler = None  # will fall through to 404
                else:
                    def handler(f, _fid=flow_id):
                        self._handle_flow_detail(f, _fid)

        if handler is None:
            all_endpoints = list(handlers.keys()) + list(post_handlers.keys()) + [
                "/api/flows/{id}", "/api/flows/{id}/request-body", "/api/flows/{id}/response-body",
                "/api/flows/{id}/tag (POST)", "/api/flows/{id}/tag/{name} (DELETE)",
            ]
            self._respond(flow, 404, {
                "error": "Not Found",
                "endpoints": all_endpoints,
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

    def _handle_gateway_services(self, flow: http.HTTPFlow):
        """GET /gateway/services - Get this agent's service bindings.

        Resolves the calling agent via service_discovery (client IP → agent name),
        then returns that agent's service bindings (host + token) from the gateway.
        """
        # Resolve caller identity via service_discovery
        sd = self._find_addon("service-discovery")
        if not sd:
            self._respond(flow, 503, {"error": "service-discovery addon not loaded"})
            return

        from utils import get_client_ip
        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        if not agent_name or agent_name == "default":
            self._respond(flow, 403, {"error": "Could not identify agent", "client_ip": client_ip})
            return

        gw = self._find_addon("service-gateway")
        if not gw:
            self._respond(flow, 503, {"error": "service-gateway addon not loaded"})
            return

        all_services = gw.get_agent_services()
        agent_services = all_services.get(agent_name, {})

        self._respond(flow, 200, {
            "agent": agent_name,
            "services": agent_services,
        })

    def _handle_agents(self, flow: http.HTTPFlow):
        """GET /agents - Discovered agents and last-seen timestamps."""
        sd = self._find_addon("service-discovery")
        if not sd:
            self._respond(flow, 503, {"error": "service-discovery addon not loaded"})
            return
        self._respond(flow, 200, sd.get_agents())

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

    # ---- Flow Store API routes ----

    def _read_json_body(self, flow: http.HTTPFlow) -> dict | None:
        """Parse request body as JSON. Returns None on failure."""
        content = flow.request.content
        if not content:
            return {}
        try:
            return json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _get_flow_store(self):
        """Get FlowStore from the flow-recorder addon."""
        recorder = self._find_addon("flow-recorder")
        if recorder is None or recorder.store is None:
            return None
        return recorder.store

    def _handle_flow_search(self, flow: http.HTTPFlow):
        """POST /api/flows/search - Search flows by filter criteria."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        results = store.search_flows(body)
        self._respond(flow, 200, {"flows": results, "count": len(results)})

    def _handle_flow_detail(self, flow: http.HTTPFlow, flow_id: int):
        """GET /api/flows/{id} - Get flow metadata."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        result = store.get_flow(flow_id)
        if result is None:
            self._respond(flow, 404, {"error": "Flow not found"})
            return
        self._respond(flow, 200, result)

    def _handle_flow_request_body(self, flow: http.HTTPFlow, flow_id: int):
        """GET /api/flows/{id}/request-body - Get decompressed request body."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        result = store.get_request_body(flow_id)
        if result is None:
            self._respond(flow, 404, {"error": "Flow not found"})
            return
        # Convert body bytes to base64 for JSON transport
        body_bytes = result.pop("body", b"")
        result["body_base64"] = base64.b64encode(body_bytes).decode("ascii")
        result["body_length"] = len(body_bytes)
        # Try to include text representation for text-like content
        ct = result.get("request_content_type", "")
        if is_text_like_content_type(ct):
            result["body_text"] = body_bytes.decode("utf-8", errors="replace")
        self._respond(flow, 200, result)

    def _handle_flow_response_body(self, flow: http.HTTPFlow, flow_id: int):
        """GET /api/flows/{id}/response-body - Get decompressed response body."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        result = store.get_response_body(flow_id)
        if result is None:
            self._respond(flow, 404, {"error": "Flow not found"})
            return
        body_bytes = result.pop("body", b"")
        result["body_base64"] = base64.b64encode(body_bytes).decode("ascii")
        result["body_length"] = len(body_bytes)
        ct = result.get("response_content_type", "")
        if is_text_like_content_type(ct):
            result["body_text"] = body_bytes.decode("utf-8", errors="replace")
        self._respond(flow, 200, result)

    def _handle_flow_endpoints(self, flow: http.HTTPFlow):
        """POST /api/flows/endpoints - Get distinct endpoints with counts."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        results = store.get_endpoints(body)
        self._respond(flow, 200, {"endpoints": results, "count": len(results)})

    def _handle_flow_body_search(self, flow: http.HTTPFlow):
        """POST /api/flows/body-search - Full-text search over response bodies."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        if not body.get("engagement_id"):
            self._respond(flow, 400, {"error": "engagement_id required"})
            return
        if not body.get("query"):
            self._respond(flow, 400, {"error": "query required"})
            return
        results = store.search_bodies(body)
        self._respond(flow, 200, {"flows": results, "count": len(results)})


    def _handle_flow_diff(self, flow: http.HTTPFlow):
        """POST /api/flows/diff - Compare two flow response bodies."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        try:
            id_a = int(body["flow_id_a"])
            id_b = int(body["flow_id_b"])
        except (KeyError, TypeError, ValueError):
            self._respond(flow, 400, {"error": "flow_id_a and flow_id_b (integers) required"})
            return
        result = store.diff_flows(id_a, id_b)
        if result is None:
            self._respond(flow, 404, {"error": "One or both flows not found"})
            return
        self._respond(flow, 200, result)

    def _handle_flow_request_body_search(self, flow: http.HTTPFlow):
        """POST /api/flows/request-body-search - Full-text search over request bodies."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        if not body.get("engagement_id"):
            self._respond(flow, 400, {"error": "engagement_id required"})
            return
        if not body.get("query"):
            self._respond(flow, 400, {"error": "query required"})
            return
        results = store.search_request_bodies(body)
        self._respond(flow, 200, {"flows": results, "count": len(results)})

    def _handle_flow_tag_add(self, flow: http.HTTPFlow, flow_id: int):
        """POST /api/flows/{id}/tag - Add or update a tag on a flow."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        tag = body.get("tag")
        if not tag:
            self._respond(flow, 400, {"error": "tag required"})
            return
        value = body.get("value", "")
        result = store.tag_flow(flow_id, tag, value)
        self._respond(flow, 200, result)

    def _handle_flow_tag_delete(self, flow: http.HTTPFlow, flow_id: int, tag_name: str):
        """DELETE /api/flows/{id}/tag/{name} - Remove a tag from a flow."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        tag = urllib.parse.unquote(tag_name)
        deleted = store.untag_flow(flow_id, tag)
        if not deleted:
            self._respond(flow, 404, {"error": "Tag not found"})
            return
        self._respond(flow, 200, {"deleted": True, "flow_id": flow_id, "tag": tag})


addons = [AgentRelay()]
