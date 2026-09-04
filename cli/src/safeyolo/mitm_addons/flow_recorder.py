"""
flow_recorder.py - Record HTTP flows to SQLite for agent queryability

Mitmproxy addon that captures completed/blocked/errored HTTP flows and
writes them to the FlowStore. Runs as Layer 3 (Observability), after
all security addons.

Scope gate: Only records flows that have flow.metadata["test_context"]
(set by test_context.py for any valid X-SafeYolo-Test-Context header, or
an inherited declaration for header-less mobile traffic).

Does NOT extend SecurityAddon — this is observability, not a security gate.

Usage:
    mitmdump -s addons/flow_recorder.py --set flow_store_enabled=true
"""

import json
import logging
import time

from mitmproxy import ctx, http

from safeyolo.core.identity import (
    LATE_ATTRIBUTION_CHANGE_KEY,
    AttributionQuarantined,
    TrafficAttribution,
    flow_attribution,
)
from safeyolo.core.internal_api import AGENT_API_HOST as AGENT_API_HOST
from safeyolo.core.internal_api import is_agent_api_host

log = logging.getLogger("safeyolo.flow-recorder")


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

    def running(self):
        """Initialize FlowStore on startup."""
        if not ctx.options.flow_store_enabled:
            log.info("Flow recorder disabled")
            return

        from safeyolo.storage.flow_store import FlowStore

        db_path = ctx.options.flow_store_db_path

        # Pull flow_store settings from the shared config cache. Returns
        # {} if the PDP isn't configured yet, which is fine — FlowStore
        # below defaults every field.
        import safeyolo.core.config_cache as config_cache
        config = config_cache.addon_section("flow_store")

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
        # Wrap the store with the async writer so record_flow doesn't
        # run on the mitmproxy hook thread. Producer-side is a single
        # `put_nowait`; compression + SQLite INSERT happens on a
        # dedicated daemon thread.
        import safeyolo.core.flow_writer as flow_writer
        flow_writer.install(self.store)
        log.info(f"Flow recorder active, db={db_path}")

    def _should_record(self, flow: http.HTTPFlow) -> bool:
        """Check scope gate: only record flows with test_context."""
        if not ctx.options.flow_store_enabled:
            return False
        if self.store is None:
            return False
        # Skip doctor pipeline-probe flows (issue #213 B4). Doctor sends a
        # valid X-SafeYolo-Test-Context so test_context runs its normal
        # parse/apply path — that would satisfy the test_context gate
        # below and pull every doctor run into FlowStore as evidence. The
        # early marker (set by probe_sink's requestheaders BEFORE
        # test_context runs) short-circuits before test_context is even
        # considered, so suppression works whether the flow eventually
        # reaches the sink or gets synthetically blocked by a
        # pathological pre-sink addon. Strict `is True` (not truthiness)
        # — the contract is a boolean marker set by probe_sink; an
        # accidental truthy value in a collision-adjacent metadata key
        # must not silently suppress non-probe flows (issue #213 review,
        # second-pass cleanup).
        if flow.metadata.get("safeyolo_probe") is True:
            return False
        # Must have test context (set by test_context.py for valid headers
        # or an inherited declaration; see #282).
        if "test_context" not in flow.metadata:
            return False
        # Skip agent API internal traffic
        if is_agent_api_host(flow.request.host):
            return False
        # Evidence must never be assigned from caller-controlled metadata.
        # Reconcile the trusted UDS/IP-map sources here even if an earlier
        # addon failed to stamp identity; unresolved and conflicting flows
        # cannot safely be placed in an agent-scoped evidence store.
        attribution = self._attribution(flow, check_late_change=True)
        if not attribution.evidence_owner or LATE_ATTRIBUTION_CHANGE_KEY in flow.metadata:
            return False
        return True

    @staticmethod
    def _attribution(
        flow: http.HTTPFlow,
        *,
        check_late_change: bool = False,
    ) -> TrafficAttribution:
        """Read the stable attribution shared by audit and storage."""
        from safeyolo.core.utils import find_addon

        return flow_attribution(
            flow,
            find_addon("service-discovery"),
            check_late_change=check_late_change,
        )

    def _build_record(self, flow: http.HTTPFlow, flow_state: str) -> dict:
        """Extract flow data into a record dict for FlowStore."""
        from safeyolo.core.utils import get_client_ip
        from safeyolo.storage.flow_store import headers_to_json

        context = flow.metadata.get("test_context", {})
        start_time = flow.metadata.get("start_time")
        ts_start = int(start_time * 1000) if start_time else int(time.time() * 1000)
        ts_end = int(time.time() * 1000)
        duration_ms = ts_end - ts_start

        # Identity. _should_record captured the request-boundary attribution;
        # consume that snapshot again and check for a late change before the
        # record enters an agent partition.
        attribution = self._attribution(flow, check_late_change=True)
        if (
            attribution.evidence_owner is None
            or LATE_ATTRIBUTION_CHANGE_KEY in flow.metadata
        ):
            raise AttributionQuarantined(
                "trusted attribution changed before flow persistence"
            )
        agent = attribution.evidence_owner
        engagement_id = agent
        agent_id = agent
        source_id = get_client_ip(flow)

        # URL parts — pretty_host returns the Host header value (the
        # logical destination) rather than the connection target, which
        # may differ when an addon rewrites flow.request.host (e.g.
        # sinkhole router in test mode).
        url = flow.request.url
        scheme = flow.request.scheme
        host = flow.request.pretty_host
        port = flow.request.port
        method = flow.request.method
        from safeyolo.core.flow_cache import path_no_query
        path = path_no_query(flow)
        query_string = dict(flow.request.query) if flow.request.query else None
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

        record = {
            "request_id": flow.metadata.get("request_id"),
            "ts_start": ts_start,
            "ts_end": ts_end,
            "duration_ms": duration_ms,
            "engagement_id": engagement_id,
            "agent_id": agent_id,
            "evidence_owner": attribution.evidence_owner,
            "trusted_transport_identity": attribution.trusted_transport_identity,
            "initiator": attribution.initiator.value,
            "attribution_status": attribution.status.value,
            "attribution_provenance_json": json.dumps(attribution.provenance),
            "source_id": source_id,
            "run": context.get("run"),
            "test": context.get("test"),
            "role": context.get("role"),
            "test_agent": context.get("agent"),
            "suite": context.get("suite"),
            "subject": context.get("subject"),
            "step": context.get("step"),
            "intent": context.get("intent"),
            "expect": context.get("expect"),
            "context_json": context_json,
            "source_type": flow.metadata.get("origin"),
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
        if flow.metadata.get("origin") == "operator":
            record["provenance_tags"] = {
                "operator_action": str(flow.metadata.get("operator_action", "")),
                "source_flow_id": str(flow.metadata.get("source_flow_id", flow.id)),
            }
        return record

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
        except AttributionQuarantined as exc:
            # A late source change is an intentional quarantine, not a record
            # construction failure.  The linked operator-only audit event is
            # already emitted by flow_attribution().
            self._stats["skipped"] += 1
            log.warning("Quarantined flow record: %s", exc)
            return
        except Exception as exc:
            # Build-record failures stay on the hook (cheap, bounded).
            # Writer-thread errors are tracked via flow_writer stats.
            self._stats["errors"] += 1
            log.warning(f"Failed to build flow record: {type(exc).__name__}: {exc}")
            return

        # Hand off to the background writer. put_record is a single
        # queue.put_nowait; compression + SQLite INSERT happens off-hook.
        import safeyolo.core.flow_writer as flow_writer
        flow_writer.put_record(record)
        self._stats["recorded"] += 1

    def error(self, flow: http.HTTPFlow):
        """Record transport errors (upstream unreachable, DNS failure, timeout)."""
        if not self._should_record(flow):
            self._stats["skipped"] += 1
            return

        try:
            record = self._build_record(flow, "error")
        except AttributionQuarantined as exc:
            self._stats["skipped"] += 1
            log.warning("Quarantined error flow record: %s", exc)
            return
        except Exception as exc:
            self._stats["errors"] += 1
            log.warning(f"Failed to build error flow record: {type(exc).__name__}: {exc}")
            return

        import safeyolo.core.flow_writer as flow_writer
        flow_writer.put_record(record)
        self._stats["recorded"] += 1

    def get_stats(self) -> dict:
        """Return recording statistics.

        Includes writer-side counters (queue drops, on-error drops) so
        operators see backpressure and persistent-write failures in
        the same pane as the addon's own skip/record/error counts.
        """
        stats = dict(self._stats)
        import safeyolo.core.flow_writer as flow_writer
        writer = flow_writer.get_writer()
        if writer is not None:
            stats["queue_dropped"] = writer.dropped_queue_full
            stats["write_errors"] = writer.dropped_on_error
        return stats

    def done(self):
        """Drain the writer, then close the store on shutdown.

        The writer's atexit hook also flushes, but closing the store
        before that runs would race the background thread. Explicit
        order here: stop the writer first, close the DB after.
        """
        import safeyolo.core.flow_writer as flow_writer
        writer = flow_writer.get_writer()
        if writer is not None:
            writer._shutdown()  # noqa: SLF001 — owns its thread
        if self.store:
            self.store.close()


addons = [FlowRecorder()]
