"""
agent_api.py - Authenticated agent self-service API

Intercepts requests to virtual hostname _safeyolo.proxy.internal,
validates the agent bearer token, and returns PDP data as synthetic responses.
The request never goes upstream. In addition to read-only PDP queries this
endpoint exposes action-oriented routes (gateway access, plumb collaboration,
and the declared test-context lifecycle).

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
import os
import re
import urllib.parse

from mitmproxy import ctx, http
from request_id import REQUEST_ID_PATTERN as _REQUEST_ID_PATTERN

from safeyolo.core.audit_schema import ApprovalRequest, Decision, EventKind, Severity
from safeyolo.core.utils import sanitize_for_log, write_event
from safeyolo.storage.flow_store import is_text_like_content_type
from safeyolo.test_context_contract import TestContextError, parse_test_context

log = logging.getLogger("safeyolo.agent-api")

AGENT_API_HOST = "_safeyolo.proxy.internal"
MAX_EXPLAIN_LINES = 10000


class AgentAPI:
    """Authenticated agent self-service API, reached through the proxy via a virtual hostname."""

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

    async def request(self, flow: http.HTTPFlow):
        """Intercept requests to the agent API virtual host.

        Async so the /plumb/* long-poll can `await` PlumbService.read_messages
        without blocking the shared event loop. All existing handlers are
        synchronous and called normally; only the plumb path awaits.
        """
        if not ctx.options.agent_api_enabled:
            return

        if flow.request.host != AGENT_API_HOST:
            return

        # This is an agent API request - handle it entirely here
        from safeyolo.core.flow_cache import path_no_query
        path = path_no_query(flow).rstrip("/") or "/"
        method = flow.request.method

        # Method validation: GET for most routes, POST/DELETE allowed for /api/flows/ prefix
        if method not in ("GET", "POST", "DELETE"):
            self._respond(flow, 405, {"error": "Method Not Allowed", "allowed": ["GET", "POST", "DELETE"]})
            return
        if method in ("POST", "DELETE") and not (
            path.startswith("/api/flows")
            or path.startswith("/gateway/")
            or path.startswith("/plumb")
            or path == "/api/test-context/current"
        ):
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

        data_dir = os.environ.get("SAFEYOLO_DATA_DIR", "/safeyolo/data")
        active_token = read_active_token(Path(data_dir) / "agent_token")
        if active_token is None:
            self._respond(flow, 503, {"error": "Agent token not configured"})
            return
        if not hmac.compare_digest(bearer_token, active_token):
            from safeyolo.core.utils import get_client_ip

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

        # Plumb: host-mediated agent-to-agent collaboration. Handled async
        # (long-poll capable) before the sync handler table.
        if path.startswith("/plumb"):
            await self._handle_plumb(flow, path, method)
            return

        # Route to handler
        handlers = {
            "/health": self._handle_health,
            "/status": self._handle_status,
            "/policy": self._handle_policy,
            "/lookup": self._handle_lookup,
            "/budgets": self._handle_budgets,
            "/config": self._handle_config,
            "/explain": self._handle_explain,
            "/trace": self._handle_trace,
            "/memory": self._handle_memory,
            "/agents": self._handle_agents,
            "/circuits": self._handle_circuits,
            "/gateway/services": self._handle_gateway_services,
            "/api/flows/search": self._handle_flow_search,
            # One handler for all methods; it switches on flow.request.method.
            # Must NOT also appear in post_handlers — the dispatcher resolves
            # handlers.get(path) first, so a duplicate would shadow POST dispatch.
            "/api/test-context/current": self._handle_test_context_current,
        }

        # POST handlers for flow store API and gateway
        post_handlers = {
            "/api/flows/search": self._handle_flow_search,  # also accepts POST
            "/api/flows/endpoints": self._handle_flow_endpoints,
            "/api/flows/facets": self._handle_flow_facets,
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

    def _resolve_agent_id(self, flow: http.HTTPFlow) -> str | None:
        """Resolve calling agent name from the request's source IP.

        Used by flow-inspection endpoints to scope results to the
        calling agent — without this, any agent can search/read any
        other agent's flows (cross-agent info disclosure).

        Returns agent name string, or None if unresolvable (caller
        should 403).
        """
        sd = self._find_addon("service-discovery")
        if not sd:
            return None
        from safeyolo.core.utils import get_client_ip
        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        # service_discovery returns "unknown" for an unmapped source; both
        # "unknown" and "default" are non-identities and must not scope results.
        if not agent_name or agent_name in ("unknown", "default"):
            return None
        return agent_name

    def _handle_test_context_current(self, flow: http.HTTPFlow):
        """GET|POST|DELETE /api/test-context/current.

        Manage this agent's current declared test context, used to attribute and
        record header-less (mobile app) traffic to a target host. Identity is
        always source-derived: the caller never supplies the trusted agent or
        source id in the request body.
        """
        method = flow.request.method

        # Common prerequisites for every method.
        agent = self._resolve_agent_id(flow)
        if agent is None:
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        from safeyolo.core.utils import get_client_ip

        source_id = get_client_ip(flow)
        if not source_id or source_id == "unknown":
            self._respond(flow, 403, {"error": "Could not identify source"})
            return

        tc = self._find_addon("test-context")
        if tc is None:
            self._respond(flow, 503, {"error": "test-context addon not loaded"})
            return

        if method == "GET":
            self._test_context_get(flow, tc, agent, source_id)
        elif method == "POST":
            self._test_context_post(flow, tc, agent, source_id)
        elif method == "DELETE":
            self._test_context_delete(flow, tc, agent, source_id)
        else:
            # Outer method validation already restricts this, but stay defensive.
            self._respond(
                flow,
                405,
                {"error": "Method Not Allowed", "allowed": ["GET", "POST", "DELETE"]},
            )

    def _test_context_get(self, flow, tc, agent, source_id):
        """Return the caller's active declaration + remaining TTL, or null."""
        rec = tc.get_declaration(source_id, agent)
        if rec is None:
            self._respond(flow, 200, {"context": None})
            return
        context, expires_in = rec
        self._respond(
            flow,
            200,
            {"agent": agent, "context": context, "expires_in": expires_in},
        )

    def _test_context_post(self, flow, tc, agent, source_id):
        """Set the caller's declared context from a canonical X-SafeYolo-Test-Context string."""
        body = self._read_json_body(flow)
        if body is None or not isinstance(body, dict):
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return

        context_str = body.get("context")
        if type(context_str) is not str:
            self._respond(
                flow,
                400,
                {
                    "error": "context must be a string",
                    "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
                },
            )
            return

        try:
            parsed = parse_test_context(context_str)
        except TestContextError as exc:
            self._respond(
                flow,
                400,
                {
                    "error": "Invalid test context",
                    "detail": str(exc),
                    "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
                    "example": "run=sec1;agent=idor;test=IDOR-003;intent=probe;expect=blocked",
                },
            )
            return

        # Optional TTL: reject anything that is not a positive int. bool is a
        # subclass of int, so `type(ttl) is not int` excludes True/False.
        ttl = body.get("ttl")
        if ttl is not None and (type(ttl) is not int or ttl <= 0):
            self._respond(flow, 400, {"error": "ttl must be a positive integer (seconds)"})
            return

        # The TestContext owner performs the authoritative maximum-TTL bound.
        try:
            granted = tc.set_declaration(source_id, agent, parsed, ttl)
        except ValueError as exc:
            self._respond(flow, 400, {"error": str(exc)})
            return

        declared_agent = parsed.get("agent")
        write_event(
            "security.test_context_declared",
            kind=EventKind.SECURITY,
            severity=Severity.LOW,
            summary=f"Declared test context for agent {sanitize_for_log(agent)}",
            host=AGENT_API_HOST,
            request_id=flow.metadata.get("request_id"),
            agent=agent,
            addon=self.name,
            details={
                "source_id": source_id,
                "trusted_agent": agent,
                "declared_agent": declared_agent,
                "test_agent_match": (
                    (declared_agent == agent) if declared_agent is not None else None
                ),
                "context": parsed,
                "requested_ttl": ttl,
                "granted_ttl": granted,
            },
        )

        self._respond(
            flow,
            200,
            {"status": "set", "agent": agent, "expires_in": granted, "context": parsed},
        )

    def _test_context_delete(self, flow, tc, agent, source_id):
        """Clear the caller's declaration. Idempotent (absent → still 200)."""
        existed = tc.clear_declaration(source_id)
        write_event(
            "security.test_context_cleared",
            kind=EventKind.SECURITY,
            severity=Severity.LOW,
            summary=f"Cleared test context for agent {sanitize_for_log(agent)}",
            host=AGENT_API_HOST,
            request_id=flow.metadata.get("request_id"),
            agent=agent,
            addon=self.name,
            details={
                "source_id": source_id,
                "trusted_agent": agent,
                "had_declaration": existed,
            },
        )
        self._respond(flow, 200, {"status": "cleared"})

    def _plumb_respond(self, flow: http.HTTPFlow, res: dict):
        """Translate a PlumbService result dict into an HTTP response.

        The service returns {"status": <int>, ...body}; we use `status` as the
        HTTP code and return the remaining fields as the JSON body.
        """
        status = res.pop("status", 200)
        self._respond(flow, status, res)

    async def _handle_plumb(self, flow: http.HTTPFlow, path: str, method: str):
        """Route /plumb/* to the process-level PlumbService.

        Sender identity is resolved from service-discovery attribution, NEVER
        from the request body. This handler only translates HTTP<->service;
        all mailbox state lives in PlumbService (single owner).
        """
        agent = self._resolve_agent_id(flow)
        if agent is None:
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        from safeyolo.core.plumb_service import get_plumb_service

        svc = get_plumb_service()

        def _body() -> dict:
            try:
                txt = flow.request.get_text() or ""
                return json.loads(txt) if txt.strip() else {}
            except (ValueError, UnicodeDecodeError):
                return {}

        # POST /plumb/request-chat
        if method == "POST" and path == "/plumb/request-chat":
            b = _body()
            res = await svc.request_chat(
                requester=agent,
                participants=b.get("participants", []),
                topic=b.get("topic", ""),
                note=b.get("reason", b.get("note", "")),
                ttl_seconds=b.get("ttl_seconds", 0),
            )
            self._plumb_respond(flow, res)
            return

        # GET /plumb/conversations
        if method == "GET" and path == "/plumb/conversations":
            self._respond(flow, 200, {"conversations": svc.list_conversations(agent)})
            return

        # /plumb/conversations/{id}/(messages|leave)
        m = re.match(r"^/plumb/conversations/([^/]+)/(messages|leave)$", path)
        if m:
            conv_id, tail = m.group(1), m.group(2)
            if method == "GET" and tail == "messages":
                after = flow.request.query.get("after")
                try:
                    wait_i = int(flow.request.query.get("wait", "0"))
                except (TypeError, ValueError):
                    wait_i = 0
                try:
                    limit_i = int(flow.request.query.get("limit", "0"))
                except (TypeError, ValueError):
                    limit_i = 0
                res = await svc.read_messages(agent, conv_id, after, wait_i, limit_i)
                self._plumb_respond(flow, res)
                return
            if method == "POST" and tail == "messages":
                b = _body()
                refs = (b.get("metadata") or {}).get("references")
                res = await svc.post_message(agent, conv_id, str(b.get("body", "")), refs)
                self._plumb_respond(flow, res)
                return
            if method == "POST" and tail == "leave":
                self._plumb_respond(flow, await svc.leave(agent, conv_id))
                return

        self._respond(
            flow,
            404,
            {
                "error": "Not Found",
                "endpoints": [
                    "/plumb/request-chat (POST)",
                    "/plumb/conversations (GET)",
                    "/plumb/conversations/{id}/messages (GET long-poll ?after=&wait=&limit=, POST)",
                    "/plumb/conversations/{id}/leave (POST)",
                ],
            },
        )

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

        from safeyolo.core.utils import get_client_ip

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
        from safeyolo.core.service_loader import get_service_registry

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

        from safeyolo.core.utils import get_client_ip

        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        if not agent_name or agent_name == "default":
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        # Validate service and capability exist
        from safeyolo.core.service_loader import get_service_registry

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

        from safeyolo.core.utils import get_client_ip

        client_ip = get_client_ip(flow)
        agent_name = sd.get_client_for_ip(client_ip)
        if not agent_name or agent_name == "default":
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        # Validate service/capability/contract
        from safeyolo.core.service_loader import get_service_registry

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

    def _handle_lookup(self, flow: http.HTTPFlow):
        """GET /lookup?host=X - Check what would happen for a host.

        Uses the calling agent's identity (from service discovery),
        not a user-supplied parameter. Agents can only look up their
        own access.
        """
        query = flow.request.query
        host = query.get("host", "")
        agent = flow.metadata.get("agent")  # from service_discovery, not query

        if not host:
            self._respond(flow, 400, {
                "error": "Missing 'host' parameter",
                "usage": "/lookup?host=example.com",
            })
            return

        client = self._get_policy_client()
        if not client:
            self._respond(flow, 503, {"error": "PDP not available"})
            return

        # Navigate to engine for direct evaluation
        pdp = getattr(client, "_pdp", None)
        engine = getattr(pdp, "_engine", None) if pdp else None
        if not engine:
            self._respond(flow, 503, {"error": "Policy engine not available"})
            return

        decision = engine.evaluate_request(host=host, agent=agent)
        self._respond(flow, 200, {
            "host": host,
            "agent": agent,
            "effect": decision.effect,
            "reason": decision.reason,
        })

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
        # config_cache returns the same shape as get_sensor_config() and
        # invalidates on policy reload, so this stays current without the
        # per-request PDP roundtrip.
        import safeyolo.core.config_cache as config_cache
        config = config_cache.get()
        if not config:
            self._respond(flow, 503, {"error": "PDP not available"})
            return
        self._respond(flow, 200, config)

    def _handle_explain(self, flow: http.HTTPFlow):
        """GET /explain?request_id=X - Audit events for a request ID.

        Agent-scoped: only events attributed to the caller are returned. A
        request_id owned by another agent looks identical to a nonexistent
        one (empty events list) so caller cannot use the response as an
        existence oracle.

        Retention: scans the current audit file plus configured rotated
        backups. If the scanned window was truncated for either file the
        response reports `status: "incomplete_search"` so caller can
        distinguish "genuinely nothing" from "some retention not fully
        searched".

        Freshness: audit writes are asynchronous. Before returning an
        empty result the handler drains the writer queue for a bounded
        interval and re-scans, so a caller who queries immediately after
        the request completes does not silently see `events: []` when
        the events are merely still enqueued.

        Response `status` values:
            complete           - retained set fully scanned, events accurate
            incomplete_search  - retention bound hit; some events may exist
                                 outside the scanned window
            pending            - writer still holds events after drain
                                 timeout; retry may yield more
            error              - read/parse failure; caller should treat
                                 result as unreliable
        """
        query = flow.request.query
        request_id = query.get("request_id", "")
        if not request_id or not _REQUEST_ID_PATTERN.match(request_id):
            self._respond(
                flow,
                400,
                {
                    "error": "Invalid or missing request_id",
                    "usage": "/explain?request_id=req-<32hex>",
                },
            )
            return

        agent_id = self._resolve_agent_id(flow)
        if agent_id is None:
            # Fail-closed on unresolvable identity: /explain used to return
            # any agent's events to any caller who knew the id (issue #213).
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        from pathlib import Path

        # Freshness contract (issue #213 third-pass review): if the writer
        # reports ANY pending events — not just the empty-result case — we
        # attempt a bounded drain BEFORE the authoritative scan. The old
        # "only drain when empty" logic returned partial sets as complete
        # when e.g. the request event was on disk but its response event
        # was still queued.
        pending_after_drain = False
        try:
            from safeyolo.core.audit_writer import get_writer
            writer = get_writer()
            if writer.pending_count() > 0:
                if not writer.wait_for_drain(timeout_s=0.5):
                    pending_after_drain = True
        except Exception as exc:  # noqa: BLE001 — freshness is best-effort
            log.warning(
                "Explain freshness drain failed: %s: %s",
                type(exc).__name__, exc,
            )

        # Recompute the retained-file list AFTER the drain so first-write
        # cases (file created by the drain itself) are visible to the scan.
        current_log = Path(os.environ.get("SAFEYOLO_LOG_PATH", "/app/logs/safeyolo.jsonl"))
        search_files = self._retained_audit_files(current_log)

        events, incomplete, read_error = self._scan_audit_files(
            search_files, request_id, agent_id
        )

        # Status precedence:
        # - error: any read/parse failure — result is unreliable regardless
        #   of what got returned.
        # - pending: writer still holds events after drain — retry may yield
        #   more.
        # - incomplete_search: retention bound hit — retained set larger
        #   than the per-file scan window.
        # - complete: retained set fully scanned, events accurate.
        if read_error:
            status = "error"
        elif pending_after_drain:
            status = "pending"
        elif incomplete:
            status = "incomplete_search"
        else:
            status = "complete"

        result: dict = {
            "request_id": request_id,
            "status": status,
            "events": events,
        }
        if incomplete:
            result["searched_lines_per_file"] = MAX_EXPLAIN_LINES
        self._respond(flow, 200, result)

    def _retained_audit_files(self, current: "Path") -> list["Path"]:  # noqa: F821
        """Return the current audit file plus any rotated backups, newest first.

        Rotation lives in `utils._rotate_jsonl_if_needed`: current →
        `.jsonl.1`, `.1` → `.2`, ..., up to `SAFEYOLO_LOG_BACKUPS`. Scan
        order is newest-to-oldest so events written just before rotation
        are found before their older neighbours.
        """
        files: list = []
        if current.exists():
            files.append(current)
        # Late import to avoid pulling utils' mitmproxy dependency chain
        # on module load; agent_api may be imported in contexts where
        # utils.write_event's audit_writer plumbing is not yet ready.
        from safeyolo.core import utils as _utils
        for i in range(1, _utils.SAFEYOLO_LOG_BACKUPS + 1):
            rotated = current.with_suffix(f".jsonl.{i}")
            if rotated.exists():
                files.append(rotated)
        return files

    def _scan_audit_files(
        self,
        files: list,
        request_id: str,
        agent_id: str,
    ) -> tuple[list, bool, bool]:
        """Scan `files` for events matching `(request_id, agent_id)`.

        Returns `(events, incomplete, read_error)`.

        - `incomplete`: any file exceeded the per-file `MAX_EXPLAIN_LINES`
          window. The caller reports `status=incomplete_search` so a "no
          match" result isn't silently promoted to "definitely no events".
        - `read_error`: an OSError was raised while reading a file. The
          caller reports `status=error` — distinct from `incomplete_search`,
          which means the search bound was hit but the read itself was
          fine. Issue #213 promises both statuses; conflating them into
          `incomplete_search` (the previous behaviour) made a genuine read
          failure indistinguishable from a legitimate retention overflow.

        Agent scope: strict match on the event's recorded agent field.
        Events without an agent field are dropped (fail-closed). Callers
        are expected to populate agent on every request-id-correlated
        write_event() site.
        """
        from collections import deque

        events: list = []
        incomplete = False
        read_error = False
        for path in files:
            try:
                with open(path) as fh:
                    total_lines = 0
                    scan_lines: deque = deque(maxlen=MAX_EXPLAIN_LINES)
                    for line in fh:
                        total_lines += 1
                        scan_lines.append(line)
                    if total_lines > MAX_EXPLAIN_LINES:
                        incomplete = True
                for line in scan_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("request_id") != request_id:
                        continue
                    if entry.get("agent") != agent_id:
                        continue
                    events.append(entry)
            except OSError as exc:
                log.warning(
                    "Explain read failed for %s: %s: %s",
                    path, type(exc).__name__, exc,
                )
                read_error = True
        return events, incomplete, read_error

    def _handle_trace(self, flow: http.HTTPFlow):
        """GET /trace?request_id=X - Opt-in execution trace for one request.

        Returns the ordered pipeline steps recorded for a request that opted
        into tracing via `X-SafeYolo-Trace: 1`. Scoped strictly to the
        originating agent: a foreign or unknown request_id returns the same
        404 as a missing record so caller cannot use response shape as an
        existence oracle for another agent's traces (issue #213).

        Response payload:
            {
                "request_id": "req-...",
                "agent_id":   "<agent>",
                "created_at": <epoch>,
                "truncated":  bool,
                "steps": [
                    {"addon": "...", "hook": "request", "state": "evaluated",
                     "outcome": "no_detection", "duration_us": 83, ...},
                    ...
                ],
                "not_loaded": [
                    {"addon": "...", "state": "not_loaded"},
                    ...
                ]
            }
        """
        query = flow.request.query
        request_id = query.get("request_id", "")
        if not request_id or not _REQUEST_ID_PATTERN.match(request_id):
            self._respond(
                flow,
                400,
                {
                    "error": "Invalid or missing request_id",
                    "usage": "/trace?request_id=req-<32hex>",
                },
            )
            return

        agent_id = self._resolve_agent_id(flow)
        if agent_id is None:
            # Fail-closed on unresolvable identity — trace never leaks to an
            # anonymous caller, matches the /api/flows/* posture.
            self._respond(flow, 403, {"error": "Could not identify agent"})
            return

        from safeyolo.core.trace import get_store

        record = get_store().get(request_id, agent_id)
        if record is None:
            # Same 404 for missing vs wrong-agent so callers cannot distinguish.
            self._respond(
                flow,
                404,
                {"error": "No trace for request_id", "request_id": request_id},
            )
            return

        self._respond(flow, 200, get_store().serialise(record))

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
            filters = dict(flow.request.query)
        else:
            filters = self._read_json_body(flow)
            if filters is None:
                self._respond(flow, 400, {"error": "Invalid JSON body"})
                return
            if not isinstance(filters, dict):
                self._respond(flow, 400, {"error": "Search filters must be a JSON object"})
                return

        # Scope to calling agent — prevent cross-agent info disclosure.
        agent_id = self._resolve_agent_id(flow)
        if agent_id:
            filters["agent_id"] = agent_id

        try:
            results = store.search_flows(filters)
        except ValueError as exc:
            self._respond(flow, 400, {"error": str(exc)})
            return
        self._respond(flow, 200, {"flows": results, "count": len(results)})

    def _verify_flow_ownership(self, flow: http.HTTPFlow,
                               flow_record: dict) -> bool:
        """Check that a fetched flow belongs to the calling agent.

        Returns True if ownership verified (or if service-discovery is
        unavailable, in which case we fail-open to avoid breaking
        single-agent setups without service-discovery).
        """
        agent_id = self._resolve_agent_id(flow)
        if agent_id is None:
            # Can't resolve caller — fail-open for backwards compat.
            return True
        record_agent = flow_record.get("agent_id", "")
        return record_agent == agent_id

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
        if not self._verify_flow_ownership(flow, result):
            self._respond(flow, 404, {"error": "Flow not found"})
            return
        self._respond(flow, 200, result)

    def _handle_flow_request_body(self, flow: http.HTTPFlow, flow_id: int):
        """GET /api/flows/{id}/request-body - Get decompressed request body."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        # Ownership check: fetch metadata first to get agent_id, then
        # body only if it belongs to this agent.
        meta = store.get_flow(flow_id)
        if meta is None or not self._verify_flow_ownership(flow, meta):
            self._respond(flow, 404, {"error": "Flow not found"})
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
        meta = store.get_flow(flow_id)
        if meta is None or not self._verify_flow_ownership(flow, meta):
            self._respond(flow, 404, {"error": "Flow not found"})
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
        agent_id = self._resolve_agent_id(flow)
        if agent_id:
            body["agent_id"] = agent_id
        results = store.get_endpoints(body)
        self._respond(flow, 200, {"endpoints": results, "count": len(results)})

    def _handle_flow_facets(self, flow: http.HTTPFlow):
        """POST /api/flows/facets - Get scoped evidence selector counts."""
        store = self._get_flow_store()
        if not store:
            self._respond(flow, 503, {"error": "Flow store not available"})
            return
        body = self._read_json_body(flow)
        if body is None or not isinstance(body, dict):
            self._respond(flow, 400, {"error": "Invalid JSON body"})
            return
        agent_id = self._resolve_agent_id(flow)
        if agent_id:
            body["agent_id"] = agent_id
        try:
            facets = store.get_facets(body)
        except ValueError as exc:
            self._respond(flow, 400, {"error": str(exc)})
            return
        self._respond(flow, 200, {"facets": facets})

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
        agent_id = self._resolve_agent_id(flow)
        if agent_id:
            body["agent_id"] = agent_id
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
        # Ownership check: both flows must belong to the calling agent.
        for fid in (id_a, id_b):
            meta = store.get_flow(fid)
            if meta is None or not self._verify_flow_ownership(flow, meta):
                self._respond(flow, 404, {"error": "One or both flows not found"})
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
        agent_id = self._resolve_agent_id(flow)
        if agent_id:
            body["agent_id"] = agent_id
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
        meta = store.get_flow(flow_id)
        if meta is None or not self._verify_flow_ownership(flow, meta):
            self._respond(flow, 404, {"error": "Flow not found"})
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
        meta = store.get_flow(flow_id)
        if meta is None or not self._verify_flow_ownership(flow, meta):
            self._respond(flow, 404, {"error": "Flow not found"})
            return
        tag = urllib.parse.unquote(tag_name)
        deleted = store.untag_flow(flow_id, tag)
        if not deleted:
            self._respond(flow, 404, {"error": "Tag not found"})
            return
        self._respond(flow, 200, {"deleted": True, "flow_id": flow_id, "tag": tag})


addons = [AgentAPI()]
