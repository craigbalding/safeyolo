"""
flow_recorder.py - Record HTTP flows to SQLite for agent queryability

Mitmproxy addon that captures completed/blocked/errored HTTP flows and
writes them to the FlowStore. Runs as Layer 3 (Observability), after
all security addons.

Scope gate: Only records flows that have flow.metadata["ccapt_context"]
(set by test_context.py for target host traffic with valid X-Test-Context).

Does NOT extend SecurityAddon — this is observability, not a security gate.

Usage:
    mitmdump -s addons/flow_recorder.py --set flow_store_enabled=true
"""

import json
import logging
import time

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.flow-recorder")

AGENT_API_HOST = "_safeyolo.proxy.internal"


class FlowRecorder:
    """Record HTTP flows to SQLite via FlowStore."""

    name = "flow-recorder"

    def __init__(self):
        self.store = None
        self._stats = {"recorded": 0, "errors": 0, "skipped": 0}

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="flow_store_enabled",
            typespec=bool,
            default=True,
            help="Enable flow recording to SQLite",
        )
        loader.add_option(
            name="flow_store_db_path",
            typespec=str,
            default="/app/logs/flows.sqlite3",
            help="Path to flow store SQLite database",
        )
        loader.add_option(
            name="flow_store_record_all",
            typespec=bool,
            default=False,
            help="Record all flows, not just ccapt_context-tagged ones "
                 "(for security audit blackbox testing)",
        )

    def running(self):
        """Initialize FlowStore on startup."""
        if not ctx.options.flow_store_enabled:
            log.info("Flow recorder disabled")
            return

        from flow_store import FlowStore

        db_path = ctx.options.flow_store_db_path

        # Try to load config from PDP
        config = {}
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if is_policy_client_configured():
                sensor_config = get_policy_client().get_sensor_config()
                config = sensor_config.get("addons", {}).get("flow_store", {})
        except Exception as exc:
            log.debug(f"Could not load flow_store config from PDP: {exc}")

        if config.get("db_path"):
            db_path = config["db_path"]

        self.store = FlowStore(
            db_path=db_path,
            max_request_body_bytes=config.get("max_request_body_bytes", 1_048_576),
            max_response_body_bytes=config.get("max_response_body_bytes", 4_194_304),
            preview_text_chars=config.get("preview_text_chars", 8192),
            compress_bodies=config.get("compress_bodies", True),
        )
        self.store.init_db()
        log.info(f"Flow recorder active, db={db_path}")

    def _should_record(self, flow: http.HTTPFlow) -> bool:
        """Check scope gate: record flows per configured scope."""
        if not ctx.options.flow_store_enabled:
            return False
        if self.store is None:
            return False
        # Skip agent API internal traffic regardless of mode
        if flow.request.host == AGENT_API_HOST:
            return False
        # record_all mode: capture every flow (for security audit
        # blackbox testing where the ccapt_context header isn't
        # present). Without this, the flow store stays empty and
        # cross-agent isolation tests can't exercise the scoping fix.
        if ctx.options.flow_store_record_all:
            return True
        # Default: only record flows with test context
        if "ccapt_context" not in flow.metadata:
            return False
        return True

    def _build_record(self, flow: http.HTTPFlow, flow_state: str) -> dict:
        """Extract flow data into a record dict for FlowStore."""
        from flow_store import headers_to_json
        from utils import get_client_ip

        context = flow.metadata.get("ccapt_context", {})
        start_time = flow.metadata.get("start_time")
        ts_start = int(start_time * 1000) if start_time else int(time.time() * 1000)
        ts_end = int(time.time() * 1000)
        duration_ms = ts_end - ts_start

        # Identity
        agent = flow.metadata.get("agent", "unknown")
        engagement_id = agent
        agent_id = agent
        source_id = get_client_ip(flow)

        # URL parts
        url = flow.request.url
        scheme = flow.request.scheme
        host = flow.request.host
        port = flow.request.port
        method = flow.request.method
        path = flow.request.path.split("?")[0]
        query_string = flow.request.query.to_dict() if flow.request.query else None
        query_str = json.dumps(query_string) if query_string else None

        # Request info — redact gateway-injected credential header
        redact = None
        injected = flow.metadata.get("gateway_injected_header")
        if injected:
            redact = {injected}
        req_ct = flow.request.headers.get("content-type", "")
        req_headers = headers_to_json(flow.request.headers, redact_headers=redact)
        req_body = flow.request.content or b""

        # Response info
        resp_ct = ""
        resp_headers = "[]"
        resp_body = b""
        status_code = None
        reason = None

        if flow.response:
            resp_ct = flow.response.headers.get("content-type", "")
            resp_headers = headers_to_json(flow.response.headers)
            resp_body = flow.response.content or b""
            status_code = flow.response.status_code
            reason = flow.response.reason if hasattr(flow.response, "reason") else None

        # For blocked flows, capture the block reason
        if flow_state == "blocked":
            reason = flow.metadata.get("blocked_by", reason)

        # For error flows
        if flow_state == "error" and flow.error:
            reason = flow.error.msg

        # Context
        context_json = json.dumps(context) if context else None

        return {
            "request_id": flow.metadata.get("request_id"),
            "ts_start": ts_start,
            "ts_end": ts_end,
            "duration_ms": duration_ms,
            "engagement_id": engagement_id,
            "agent_id": agent_id,
            "source_id": source_id,
            "run": context.get("run"),
            "test": context.get("test"),
            "role": context.get("role"),
            "context_json": context_json,
            "source_type": None,
            "flow_state": flow_state,
            "scheme": scheme,
            "host": host,
            "port": port,
            "method": method,
            "path": path,
            "query_string": query_str,
            "full_url": url,
            "status_code": status_code,
            "reason": reason,
            "request_content_type": req_ct,
            "response_content_type": resp_ct,
            "is_websocket": flow.metadata.get("is_websocket", False),
            "request_headers_json": req_headers,
            "response_headers_json": resp_headers,
            "request_body": req_body,
            "response_body": resp_body,
        }

    def _derive_flow_state(self, flow: http.HTTPFlow) -> str:
        """Determine flow state from flow metadata."""
        if flow.metadata.get("blocked_by"):
            return "blocked"
        return "completed"

    def response(self, flow: http.HTTPFlow):
        """Record completed or blocked flows (mitmproxy calls this for both)."""
        if not self._should_record(flow):
            self._stats["skipped"] += 1
            return

        flow_state = self._derive_flow_state(flow)

        try:
            record = self._build_record(flow, flow_state)
            self.store.record_flow(record)
            self._stats["recorded"] += 1
        except Exception as exc:
            self._stats["errors"] += 1
            log.warning(f"Failed to record flow: {type(exc).__name__}: {exc}")

    def error(self, flow: http.HTTPFlow):
        """Record transport errors (upstream unreachable, DNS failure, timeout)."""
        if not self._should_record(flow):
            self._stats["skipped"] += 1
            return

        try:
            record = self._build_record(flow, "error")
            self.store.record_flow(record)
            self._stats["recorded"] += 1
        except Exception as exc:
            self._stats["errors"] += 1
            log.warning(f"Failed to record error flow: {type(exc).__name__}: {exc}")

    def get_stats(self) -> dict:
        """Return recording statistics."""
        return dict(self._stats)

    def done(self):
        """Close store on shutdown."""
        if self.store:
            self.store.close()


addons = [FlowRecorder()]
