"""Tests for probe_sink addon (#213 B2).

The sink is the local terminator for the reserved doctor pipeline-probe
host. These tests pin three properties:

- The early `requestheaders` marker is set for the probe host and only
  the probe host.
- The late `request` hook synthesises a 200 iff no earlier addon has
  responded. It does NOT set `blocked_by` and does NOT call
  `SecurityAddon.block` — the trace outcome is `probe_terminated`, not
  `blocked`.
- No security addon reads `safeyolo_probe`. Verified by grep — the
  marker is informational only for probe-sink, flow-recorder, and the
  transport-boundary guard. Security addons must not branch on it.
"""

from __future__ import annotations

import json
from pathlib import Path

from mitmproxy import http as mitm_http
from mitmproxy.test import taddons, tflow

from safeyolo.core.probe import PROBE_HOST
from safeyolo.core.trace import get_store, reset_store_for_tests


def _addon():
    from probe_sink import ProbeSink
    return ProbeSink()


def _probe_flow(traced: bool = True) -> mitm_http.HTTPFlow:
    flow = tflow.tflow()
    flow.request.host = PROBE_HOST
    flow.request.path = "/__pipeline_probe"
    flow.metadata["request_id"] = "req-probe000000000000000000000000000"
    flow.metadata["agent"] = "doctor-probe"
    if traced:
        flow.metadata["trace"] = True
    return flow


class TestEarlyMarker:
    """`requestheaders` marker semantics."""

    def test_marks_probe_host(self):
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)
        assert flow.metadata.get("safeyolo_probe") is True

    def test_ignores_non_probe_host(self):
        addon = _addon()
        flow = tflow.tflow()
        flow.request.host = "example.com"
        addon.requestheaders(flow)
        assert "safeyolo_probe" not in flow.metadata

    def test_probe_host_check_case_insensitive(self):
        addon = _addon()
        flow = tflow.tflow()
        flow.request.host = "_SAFEYOLO.PROBE.INTERNAL"
        addon.requestheaders(flow)
        assert flow.metadata.get("safeyolo_probe") is True


class TestLateSink:
    """`request` hook terminates probe flows locally with a synthetic 200."""

    def test_synthesises_200_for_probe_flow(self):
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)

        with taddons.context(addon):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert body["probe_ok"] is True
        assert body["host"] == PROBE_HOST
        assert body["request_id"] == flow.metadata["request_id"]

    def test_sink_does_not_set_blocked_by(self):
        """Successful local termination is not a policy block. `blocked_by`
        signals "an addon blocked this flow"; the sink must not lie about
        that or downstream observability will misclassify probe traffic.
        """
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)

        with taddons.context(addon):
            addon.request(flow)

        assert "blocked_by" not in flow.metadata

    def test_sink_does_not_use_x_blocked_by_header(self):
        """The 200 response must not carry X-Blocked-By — that header is
        contract shorthand for "an addon blocked this". The sink used
        `http.Response.make` directly (not make_block_response) so the
        header should be absent.
        """
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)

        with taddons.context(addon):
            addon.request(flow)

        assert "X-Blocked-By" not in flow.response.headers

    def test_sink_stamps_request_id_on_response(self):
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)

        with taddons.context(addon):
            addon.request(flow)

        assert flow.response.headers.get("X-SafeYolo-Request-Id") == flow.metadata["request_id"]

    def test_sink_ignores_non_probe_flow(self):
        addon = _addon()
        flow = tflow.tflow()
        flow.request.host = "example.com"
        # No marker, no metadata['safeyolo_probe'].
        with taddons.context(addon):
            addon.request(flow)
        assert flow.response is None

    def test_sink_preempted_when_earlier_addon_responded(self):
        """If an earlier addon set flow.response (e.g. a policy block on
        the probe host in a pathological setup), the sink must not
        overwrite it — trace records `probe_preempted` instead of
        `probe_terminated` so doctor can distinguish the two.
        """
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)
        flow.response = mitm_http.Response.make(403, b'{"error":"policy"}', {})
        flow.metadata["blocked_by"] = "some-earlier-addon"
        prior = flow.response

        with taddons.context(addon):
            addon.request(flow)

        # Response unchanged.
        assert flow.response is prior
        # Trace records the preemption.
        rec = get_store().get(flow.metadata["request_id"], flow.metadata["agent"])
        assert rec is not None
        step = rec.steps[-1]
        assert step.addon == "probe-sink"
        assert step.outcome == "probe_preempted"
        assert step.details["preempted_by"] == "some-earlier-addon"

    def test_sink_records_probe_terminated_in_trace(self):
        reset_store_for_tests()
        addon = _addon()
        flow = _probe_flow()
        addon.requestheaders(flow)

        with taddons.context(addon):
            addon.request(flow)

        rec = get_store().get(flow.metadata["request_id"], flow.metadata["agent"])
        assert rec is not None
        assert rec.steps
        step = rec.steps[-1]
        assert step.addon == "probe-sink"
        assert step.state == "evaluated"
        assert step.outcome == "probe_terminated"


class TestProbeMarkerAllowlist:
    """Enforce the boundary the sink relies on: only an explicit
    allowlist of addons may read `safeyolo_probe`. Every other file in
    `mitm_addons/*.py` must not mention the marker — this is inverted
    from the previous hand-maintained security-addon list (issue #213
    B10) so a future addon dropped into the directory can't silently
    start branching on the marker.

    The marker is informational only, consumed by:
      - probe_sink.py     (owner: sets it in requestheaders)
      - flow_recorder.py  (B4 suppression)
      - transport_guard.py (B3 no-egress boundary — may key on it later)
    """

    # Files allowed to reference the marker. Update ONLY when a legitimate
    # new reader is introduced; must not include any security-decision
    # addon (network_guard, credential_guard, pattern_scanner,
    # circuit_breaker, test_context, service_gateway, loop_guard, etc.).
    ALLOWED_READERS = {
        "probe_sink.py",
        "flow_recorder.py",
        "transport_guard.py",
    }

    def test_no_addon_outside_allowlist_reads_safeyolo_probe_marker(self):
        import re

        mitm_dir = Path(__file__).resolve().parents[1] / "cli/src/safeyolo/mitm_addons"
        pattern = re.compile(r"safeyolo_probe")

        offenders = []
        # Scan EVERY .py in mitm_addons/ — the reviewer's inverted-test
        # request. Previous version hand-maintained a security-addon
        # subset and missed anything new.
        for path in sorted(mitm_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            if path.name in self.ALLOWED_READERS:
                continue
            try:
                text = path.read_text()
            except OSError:
                continue
            if pattern.search(text):
                offenders.append(path.name)

        assert not offenders, (
            f"Addons outside the allowlist must not reference "
            f"`safeyolo_probe`: {offenders}. "
            f"Allowlist: {sorted(self.ALLOWED_READERS)}. "
            f"Add to ALLOWED_READERS only if the new reader is an "
            f"informational consumer (never a security-decision branch)."
        )

    def test_allowlist_readers_actually_exist(self):
        """Guard against the allowlist referencing a file that was
        removed — that would silently hide an offender.
        """
        mitm_dir = Path(__file__).resolve().parents[1] / "cli/src/safeyolo/mitm_addons"
        missing = [name for name in self.ALLOWED_READERS if not (mitm_dir / name).exists()]
        assert not missing, (
            f"ALLOWED_READERS references non-existent files: {missing}. "
            "Remove them so the scan-all check remains meaningful."
        )
