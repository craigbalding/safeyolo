"""
agent_api.py - Read-only PDP query API for agent self-service

Intercepts requests to virtual hostname _safeyolo.proxy.internal,
validates readonly bearer token, and returns PDP data as synthetic responses.
The request never goes upstream.

Loading order: Layer 0, after admin_shield, before loop_guard.
This ensures:
  - admin_shield already blocked port 9090 access
  - network_guard/credential_guard don't see agent API requests
  - Sets flow.response + flow.metadata["blocked_by"] so downstream addons skip

Does NOT inherit SecurityAddon - this is an internal service endpoint,
not a security sensor. Follows the simpler AdminShield/LoopGuard pattern.

Usage:
    mitmdump -s addons/agent_api.py --set admin_api_token=<token>
"""

import base64
import hmac
import json
import logging
import re
import urllib.parse

from flow_store import is_text_like_content_type
from mitmproxy import ctx, http
from utils import sanitize_for_log, write_event

from audit_schema import ApprovalRequest, Decision, EventKind, Severity

log = logging.getLogger("safeyolo.agent-api")

AGENT_API_HOST = "_safeyolo.proxy.internal"
_REQUEST_ID_PATTERN = re.compile(r"^req-[a-f0-9]{12}$")
MAX_EXPLAIN_LINES = 10000


class AgentAPI:
    """Read-only PDP API accessible through the proxy via virtual hostname."""

    name = "agent-api"

    def load(self, loader):
        loader.add_option(
            name="agent_api_enabled",
            typespec=bool,
            default=True,
            help="Enable agent API endpoint on _safeyolo.proxy.internal",
        )

    def running(self):
        if ctx.options.agent_api_enabled:
            log.info(f"Agent API active on {AGENT_API_HOST}")
        else:
            log.info("Agent API disabled")

    def request(self, flow: http.HTTPFlow):
        """Intercept requests to the agent API virtual host."""
        if not ctx.options.agent_api_enabled:
            return

        if flow.request.host != AGENT_API_HOST:
            return

        # This is an agent API request - handle it entirely here
        path = flow.request.path.split("?")[0].rstrip("/") or "/"
        method = flow.request.method

        # Method validation: GET for most routes, POST/DELETE allowed for /api/flows/ prefix
        if method not in ("GET", "POST", "DELETE"):
            self._respond(flow, 405, {"error": "Method Not Allowed", "allowed": ["GET", "POST", "DELETE"]})
            return
        if method in ("POST", "DELETE") and not (path.startswith("/api/flows") or path.startswith("/gateway/")):
            self._respond(flow, 405, {"error": "Method Not Allowed", "allowed": ["GET"]})
            return

        # Validate token
        auth_header = flow.request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            self._respond(flow, 401, {"error": "Authorization required", "hint": "Bearer <token>"})
            return

        bearer_token = auth_header[7:]

        from pathlib import Path

        from pdp.tokens import read_active_token

        active_token = read_active_token(Path("/safeyolo/data/agent_token"))
        if active_token is None:
            self._respond(flow, 503, {"error": "Agent token not configured"})
            return
        if not hmac.compare_digest(bearer_token, active_token):
            from utils import get_client_ip

            client_ip = get_client_ip(flow)
            write_event(
                "security.agent_auth_failed",
                kind=EventKind.SECURITY,
                severity=Severity.HIGH,
                summary=f"Agent API auth failed from {sanitize_for_log(client_ip)}",
                addon="agent-api",
                decision=Decision.DENY,
                details={"client_ip": client_ip, "path": sanitize_for_log(path)},
            )
            self._respond(flow, 401, {"error": "Invalid agent token"})
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
            "/api/flows/search": self._handle_flow_search,
        }

        # POST handlers for flow store API and gateway
        post_handlers = {
            "/api/flows/search": self._handle_flow_search,  # also accepts POST
            "/api/flows/endpoints": self._handle_flow_endpoints,
            "/api/flows/body-search": self._handle_flow_body_search,
            "/api/flows/diff": self._handle_flow_diff,
            "/api/flows/request-body-search": self._handle_flow_request_body_search,
            "/gateway/request-access": self._handle_gateway_request_access,
            "/gateway/submit-binding": self._handle_gateway_submit_binding,
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
            all_endpoints = (
                list(handlers.keys())
                + list(post_handlers.keys())
                + [
                    "/api/flows/{id}",
                    "/api/flows/{id}/request-body",
                    "/api/flows/{id}/response-body",
                    "/api/flows/{id}/tag (POST)",
                    "/api/flows/{id}/tag/{name} (DELETE)",
                ]
            )
            self._respond(
                flow,
                404,
                {
                    "error": "Not Found",
                    "endpoints": all_endpoints,
                },
            )
            return

        try:
            handler(flow)
        except Exception as exc:
            log.error(f"Agent API handler error: {type(exc).__name__}: {exc}")
            self._respond(flow, 500, {"error": f"Internal error: {type(exc).__name__}"})

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
                "X-SafeYolo-Agent-API": "true",
            },
        )
        flow.metadata["blocked_by"] = self.name

    def _find_addon(self, addon_name: str):
        """Find an addon by registered mitmproxy addon name.

        Always looks up via ctx.master.addons to survive addon hot reloads.
        """
        try:
            addons_obj = getattr(getattr(ctx, "master", None), "addons", None)
            if addons_obj:
                return addons_obj.get(addon_name)
        except Exception as exc:
            log.debug(f"Addon lookup failed: {type(exc).__name__}: {exc}")

        return None

    def _handle_gateway_services(self, flow: http.HTTPFlow):
        """GET /gateway/services - Get this agent's authorized + available services.

        Resolves the calling agent via service_discovery (client IP → agent name),
        then returns authorized services (with capability, account, host, token) and
        available services (all services with their capabilities).
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

        # Build available services list from registry
        available = []
        from service_loader import get_service_registry

        registry = get_service_registry()
        if registry:
            authorized_names = set(agent_services.keys())
            for svc in registry.list_services():
                if svc.name not in authorized_names:
                    caps = [{"name": name, "description": cap.description} for name, cap in svc.capabilities.items()]
                    available.append(
                        {
                            "name": svc.name,
                            "description": svc.description,
                            "capabilities": caps,
                        }
                    )

        self._respond(
            flow,
            200,
            {
                "agent": agent_name,
                "authorized": agent_services,
                "available": available,
            },
        )

    def _handle_gateway_request_access(self, flow: http.HTTPFlow):
        """POST /gateway/request-access - Agent requests access to a service capability.

        Body: {"service": "gmail", "capability": "read_and_send", "reason": "Need to read inbox"}

        If the capability has a contract template:
        - Not grantable → returns contract_not_enforceable
        - Grantable → returns needs_contract_binding with template/bindings/operations
        - No contract → existing 202 pending behavior
        """
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return

        service_name = body.get("service")
        capability = body.get("capability")
        reason = body.get("reason", "")

        if not service_name or not capability:
            self._respond(flow, 400, {"error": "service and capability are required"})
            return

        # Resolve caller identity
        sd = self._find_addon("service-discovery")
        if not sd:
            self._respond(flow, 503, {"error": "service-discovery addon not loaded"})
            return

        from utils import get_client_ip

        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        if not agent_name or agent_name == "default":
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        # Validate service and capability exist
        from service_loader import get_service_registry

        registry = get_service_registry()
        if not registry:
            self._respond(flow, 503, {"error": "Service registry not available"})
            return

        svc = registry.get_service(service_name)
        if not svc:
            self._respond(flow, 404, {"error": f"Service '{service_name}' not found"})
            return

        cap_obj = svc.capabilities.get(capability)
        if not cap_obj:
            self._respond(flow, 404, {"error": f"Capability '{capability}' not found in service '{service_name}'"})
            return

        # Contract check: if capability has a contract, handle contract flow
        if cap_obj.contract is not None:
            contract = cap_obj.contract
            if not contract.is_grantable:
                self._respond(
                    flow,
                    200,
                    {
                        "decision": "contract_not_enforceable",
                        "service": service_name,
                        "capability": capability,
                        "missing_tiers": contract.ungrantable_tiers(),
                    },
                )
                return

            # Grantable: return binding challenge
            bindings_info = {}
            for name, b in contract.bindings.items():
                bindings_info[name] = {
                    "source": b.source,
                    "type": b.type,
                    "visible_to_operator": b.visible_to_operator,
                }
                if b.options:
                    bindings_info[name]["options"] = b.options
                if b.pattern:
                    bindings_info[name]["pattern"] = b.pattern
                if b.required_if:
                    bindings_info[name]["required_if"] = b.required_if

            grantable_ops = [
                {"name": op.name, "method": op.method, "path": op.path} for op in contract.grantable_operations()
            ]

            self._respond(
                flow,
                200,
                {
                    "decision": "needs_contract_binding",
                    "service": service_name,
                    "capability": capability,
                    "template": contract.template,
                    "bindings": bindings_info,
                    "grantable_operations": grantable_ops,
                },
            )
            return

        # No contract: existing behavior — write approval event
        write_event(
            "gateway.request_access",
            kind=EventKind.GATEWAY,
            severity=Severity.CRITICAL,
            summary=f"{agent_name} requests {service_name}/{capability}: {reason}"
            if reason
            else f"{agent_name} requests {service_name}/{capability}",
            decision=Decision.REQUIRE_APPROVAL,
            host=svc.default_host or "",
            agent=agent_name,
            addon=self.name,
            approval=ApprovalRequest(
                required=True,
                approval_type="service",
                key=f"{agent_name}:{service_name}",
                target=service_name,
                scope_hint={
                    "service": service_name,
                    "capability": capability,
                    "description": svc.description,
                    "capability_description": cap_obj.description,
                    "reason": reason,
                    "proposed_lifetime": "session",
                },
            ),
        )
        log.info(
            "Access request: agent=%s service=%s capability=%s",
            sanitize_for_log(agent_name),
            sanitize_for_log(service_name),
            sanitize_for_log(capability),
        )

        self._respond(
            flow,
            202,
            {
                "status": "pending",
                "agent": agent_name,
                "service": service_name,
                "capability": capability,
                "reason": reason,
                "message": "Access request submitted. Operator will review in watch.",
            },
        )

    def _handle_gateway_submit_binding(self, flow: http.HTTPFlow):
        """POST /gateway/submit-binding - Agent submits contract binding values.

        Body: {"service": "gmail", "capability": "read_messages",
               "bindings": {"approved_category": "CATEGORY_PROMOTIONS"},
               "purpose_code": "summarise", "note": "optional audit note"}
        """
        body = self._read_json_body(flow)
        if body is None:
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return

        service_name = body.get("service")
        capability = body.get("capability")
        bindings = body.get("bindings", {})
        purpose_code = body.get("purpose_code", "")
        note = body.get("note", "")

        if not service_name or not capability:
            self._respond(flow, 400, {"error": "service and capability are required"})
            return
        if not isinstance(bindings, dict) or not bindings:
            self._respond(flow, 400, {"error": "bindings must be a non-empty object"})
            return

        # Resolve caller
        sd = self._find_addon("service-discovery")
        if not sd:
            self._respond(flow, 503, {"error": "service-discovery addon not loaded"})
            return

        from utils import get_client_ip

        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        if not agent_name or agent_name == "default":
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        # Validate service/capability/contract
        from service_loader import get_service_registry

        registry = get_service_registry()
        if not registry:
            self._respond(flow, 503, {"error": "Service registry not available"})
            return

        svc = registry.get_service(service_name)
        if not svc:
            self._respond(flow, 404, {"error": f"Service '{service_name}' not found"})
            return

        cap_obj = svc.capabilities.get(capability)
        if not cap_obj:
            self._respond(flow, 404, {"error": f"Capability '{capability}' not found"})
            return

        if not cap_obj.contract:
            self._respond(flow, 400, {"error": f"Capability '{capability}' has no contract"})
            return

        contract = cap_obj.contract
        if not contract.is_grantable:
            self._respond(
                flow,
                200,
                {
                    "decision": "contract_not_enforceable",
                    "missing_tiers": contract.ungrantable_tiers(),
                },
            )
            return

        # Validate each binding value
        import re as re_mod

        errors = []
        for var_name, var_def in contract.bindings.items():
            value = bindings.get(var_name)

            # Check required_if
            if var_def.required_if:
                required = all(bindings.get(k) == v for k, v in var_def.required_if.items())
                if required and value is None:
                    errors.append(f"'{var_name}' is required")
                    continue

            if value is None:
                continue

            if var_def.type == "enum":
                if value not in var_def.options:
                    errors.append(f"'{var_name}' must be one of: {', '.join(var_def.options)}")
            elif var_def.type == "integer":
                if not isinstance(value, int):
                    try:
                        int(value)
                    except (ValueError, TypeError):
                        errors.append(f"'{var_name}' must be an integer")
            elif var_def.type == "boolean":
                if not isinstance(value, bool):
                    errors.append(f"'{var_name}' must be a boolean")
            elif var_def.type == "string":
                if not isinstance(value, str):
                    errors.append(f"'{var_name}' must be a string")
                elif var_def.pattern:
                    if not re_mod.match(var_def.pattern, value):
                        errors.append(f"'{var_name}' does not match pattern")
            elif var_def.type == "string_list":
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    errors.append(f"'{var_name}' must be a list of strings")

        # Check for unknown bindings
        for var_name in bindings:
            if var_name not in contract.bindings:
                errors.append(f"Unknown binding variable '{var_name}'")

        if errors:
            self._respond(
                flow,
                200,
                {
                    "decision": "denied_out_of_scope",
                    "errors": errors,
                },
            )
            return

        # Build grantable operations list
        grantable_ops = [op.name for op in contract.grantable_operations()]

        # Write approval event
        scope_hint = {
            "service": service_name,
            "capability": capability,
            "template": contract.template,
            "bindings": bindings,
            "grantable_operations": grantable_ops,
        }
        if purpose_code:
            scope_hint["purpose_code"] = purpose_code

        write_event(
            "gateway.submit_binding",
            kind=EventKind.GATEWAY,
            severity=Severity.CRITICAL,
            summary=f"{agent_name} submits contract binding for {service_name}/{capability}",
            decision=Decision.REQUIRE_APPROVAL,
            host=svc.default_host or "",
            agent=agent_name,
            addon=self.name,
            approval=ApprovalRequest(
                required=True,
                approval_type="contract_binding",
                key=f"{agent_name}:{service_name}:{capability}",
                target=service_name,
                scope_hint=scope_hint,
            ),
            details={
                "bindings": bindings,
                "purpose_code": purpose_code,
                "note": note,
            },
        )

        log.info(
            "Binding submitted: agent=%s service=%s capability=%s bindings=%s",
            sanitize_for_log(agent_name),
            sanitize_for_log(service_name),
            sanitize_for_log(capability),
            sanitize_for_log(str(bindings)),
        )

        self._respond(
            flow,
            202,
            {
                "status": "pending",
                "agent": agent_name,
                "service": service_name,
                "capability": capability,
                "bindings": bindings,
                "message": "Contract binding submitted. Operator will review in watch.",
            },
        )

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
        """GET /health - PDP health + agent API alive."""
        client = self._get_policy_client()
        pdp_healthy = client.health_check() if client else False
        self._respond(
            flow,
            200,
            {
                "agent_api": "ok",
                "pdp": "ok" if pdp_healthy else "unavailable",
            },
        )

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
            self._respond(
                flow,
                400,
                {
                    "error": "Invalid or missing request_id",
                    "usage": "/explain?request_id=req-<12hex>",
                },
            )
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
        """GET|POST /api/flows/search - Search flows by filter criteria.

        GET with query params for simple searches:
            /api/flows/search?host=httpbin.org&limit=5
        POST with JSON body for complex queries:
            {"host": "httpbin.org", "status_class": "4xx", "limit": 50}
        """
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return

        if flow.request.method == "GET":
            # Build filters from query params
            filters = dict(flow.request.query)
            # Convert numeric params
            for key in ("limit", "offset", "status_code", "status_min", "status_max"):
                if key in filters:
                    try:
                        filters[key] = int(filters[key])
                    except (ValueError, TypeError):
                        pass  # Leave non-numeric filter values as strings
        else:
            filters = self._read_json_body(flow)
            if filters is None:
                self._respond(flow, 400, {"error": "Invalid JSON body"})
                return

        results = store.search_flows(filters)
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


addons = [AgentAPI()]
