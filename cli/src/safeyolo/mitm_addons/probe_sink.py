"""
probe_sink.py - Local terminator for the reserved pipeline-probe host (#213 B2)

Doctor's traced probe target — `_safeyolo.probe.internal` — never resolves,
never egresses, never has an upstream. This addon terminates it locally
with a synthetic 200 AFTER every expected security addon has evaluated,
so `/trace` records real evidence for the whole request-hook pipeline
before the flow completes.

Two hooks, one addon, one file:

1. `requestheaders(flow)` — runs early. If the request is for the probe
   host, set `flow.metadata["safeyolo_probe"] = True`. Nothing else. The
   marker is:
     - informational-only for tracing/logging/observability code paths;
     - the trigger for `flow_recorder`'s FlowStore suppression (B4);
     - the signal the transport-boundary guard (B3) reads to refuse
       upstream connect if for any reason the flow escapes the sink.

2. `request(flow)` — loaded LAST in `ADDON_CHAIN`. If the marker is set
   and no earlier addon has already responded, synthesise a local 200.
   All the security addons above have already run their request hooks;
   their trace evidence is now on record.

Deliberate non-behaviour (issue #213 second-pass review):

- Security addons MUST NOT branch on `safeyolo_probe`. This module
  reads and writes the marker, `flow_recorder` reads it, the transport
  guard reads it — nothing else. `tests/test_probe_sink.py` and the
  existing grep-style hygiene tests enforce this.
- The sink does NOT set `flow.metadata["blocked_by"]`. This is
  successful local termination, not a policy block. Trace records
  `evaluated/probe_terminated`, distinct from `blocked`.
- The sink does NOT call `SecurityAddon.block` and is not a
  `SecurityAddon` — it emits its own trace step via the standalone
  `trace_evaluated` helper.

Loading position: absolute last in `ADDON_CHAIN` after `admin_api.py`.
Any addon loaded after the sink would run AFTER the synthetic 200 was
set and would need to inspect `safeyolo_probe` to avoid misinterpreting
the flow — see the "do not branch" rule above.
"""

from __future__ import annotations

import json
import logging

from mitmproxy import http

from safeyolo.core.probe import PROBE_HOST, is_probe_host
from safeyolo.core.trace import trace_addon_hook, trace_evaluated

log = logging.getLogger("safeyolo.probe-sink")

# Trace outcome vocabulary (issue #213)
OUTCOME_PROBE_TERMINATED = "probe_terminated"       # sink synthesised the 200
OUTCOME_PROBE_PREEMPTED = "probe_preempted"         # earlier addon responded; sink did nothing


class ProbeSink:
    """Marks probe flows early and terminates them locally at the very end."""

    name = "probe-sink"

    def requestheaders(self, flow: http.HTTPFlow):
        """Early marker for the probe host. Does not touch flow.response.

        Runs before every `request` hook (including security addons).
        `is_probe_host` handles case-insensitivity so a manipulated Host
        header cannot dodge the marker on casing.
        """
        if is_probe_host(flow.request.host):
            flow.metadata["safeyolo_probe"] = True

    @trace_addon_hook("request")
    def request(self, flow: http.HTTPFlow):
        """Terminate probe flows locally after the security pipeline has run.

        Loaded last in `ADDON_CHAIN` so every expected addon's request
        hook has already recorded its trace evidence.
        """
        if not flow.metadata.get("safeyolo_probe"):
            return

        if flow.response is not None:
            # An earlier addon (or the transport-boundary guard) already
            # responded for this probe. Record explicit evidence so the
            # doctor's trace read can distinguish "sink terminated normally"
            # from "sink was preempted". Do NOT overwrite flow.response.
            trace_evaluated(
                flow,
                addon=self.name,
                outcome=OUTCOME_PROBE_PREEMPTED,
                preempted_by=flow.metadata.get("blocked_by"),
            )
            return

        request_id = flow.metadata.get("request_id")
        body = {
            "probe_ok": True,
            "host": PROBE_HOST,
            "request_id": request_id,
        }
        # http.Response.make (not make_block_response) — this is successful
        # local termination, not a policy block. No X-Blocked-By header.
        # X-SafeYolo-Request-Id is stamped by RequestIdGenerator.response()
        # if we don't add it here; adding it now for symmetry with any
        # future response-hook ordering surprise.
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if request_id:
            headers["X-SafeYolo-Request-Id"] = request_id
        flow.response = http.Response.make(
            200,
            json.dumps(body).encode(),
            headers,
        )
        trace_evaluated(
            flow,
            addon=self.name,
            outcome=OUTCOME_PROBE_TERMINATED,
            host=PROBE_HOST,
        )


addons = [ProbeSink()]
