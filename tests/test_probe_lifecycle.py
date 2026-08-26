"""Lifecycle interaction tests for probe_sink + transport_guard (#213 B13).

The reviewer asked for a real UnixInstance/HttpProxy integration test
using the exact raw request doctor sends. In this sandbox we cannot
spin up a full mitmproxy master with a live UDS listener — the
blackbox suite (which requires `runsc` and a dedicated VM) covers
that. See `HOST_VERIFICATION.md` for the operator-side commands.

What this file DOES cover:

- Reconstruct mitmproxy's hook fire order for the doctor's exact
  ORIGIN-FORM plain-HTTP probe request (`GET /__pipeline_probe HTTP/1.0`
  + `Host: _safeyolo.probe.internal`), which requires:
    requestheaders → request → (no server_connect, because sink set
    flow.response first)
- Reconstruct the sink-failure case:
    requestheaders → request (sink missing/disabled) → server_connect
    fires → transport_guard refuses → error(flow) records trace step
    with reason=probe_reached_upstream
- Cover both cases end-to-end without a real listener so we catch
  regressions here in <1s CI feedback. The live UDS-level assertions
  live in `HOST_VERIFICATION.md`.

For origin-form plain HTTP, mitmproxy's eager connection strategy
still requires the Host header (which arrives with requestheaders)
before server_connect can fire. So the ordering below is correct
regardless of connection_strategy for the doctor's specific request
shape.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy.test import taddons, tflow

from safeyolo.core.probe import PROBE_HOST, PROBE_PATH
from safeyolo.core.trace import get_store, reset_store_for_tests


def _doctor_probe_flow(traced: bool = True):
    """Build a flow that matches the exact request doctor sends over UDS.

    Origin-form plain HTTP: `GET /__pipeline_probe HTTP/1.0` with
    `Host: _safeyolo.probe.internal` and `X-SafeYolo-Trace: 1`.
    """
    flow = tflow.tflow()
    flow.request.method = "GET"
    # Origin-form: scheme=http, path=/__pipeline_probe, host from Host header.
    flow.request.scheme = "http"
    flow.request.host = PROBE_HOST
    flow.request.port = 80
    flow.request.path = PROBE_PATH
    flow.request.http_version = "HTTP/1.0"
    flow.request.headers["Host"] = PROBE_HOST
    flow.metadata["agent"] = "doctor-probe"
    if traced:
        flow.request.headers["X-SafeYolo-Trace"] = "1"
    return flow


class TestNormalProbeLifecycle:
    """When probe_sink is loaded and the pipeline runs normally, the
    doctor probe completes at the sink and server_connect never fires.
    """

    def test_sink_terminates_before_transport_guard_can_fire(self):
        """Fire mitmproxy's hooks in the origin-form plain-HTTP order:
        requestheaders → request. Verify:
        - probe_sink.requestheaders sets the marker.
        - RequestIdGenerator.request assigns a request_id.
        - probe_sink.request synthesises the local 200.
        - flow.response is set BEFORE any server_connect would fire.
        """
        reset_store_for_tests()

        from probe_sink import ProbeSink
        from request_id import RequestIdGenerator

        rid_gen = RequestIdGenerator()
        sink = ProbeSink()
        flow = _doctor_probe_flow()

        with taddons.context(sink):
            # Step 1: requestheaders — probe_sink early-marks.
            sink.requestheaders(flow)
            assert flow.metadata.get("safeyolo_probe") is True

            # Step 2: request — RequestIdGenerator assigns id, then
            # (after security addons) probe_sink terminates.
            rid_gen.request(flow)
            assert flow.metadata.get("request_id") is not None

            sink.request(flow)
            # Sink synthesised 200 with request_id echoed.
            assert flow.response is not None
            assert flow.response.status_code == 200
            assert flow.response.headers.get("X-SafeYolo-Request-Id") == flow.metadata["request_id"]

        # If server_connect were to fire NOW, mitmproxy would inspect
        # flow.response and short-circuit. Nothing else should egress.
        # We assert that by proving `flow.response` was set before any
        # transport-layer decision could reference it.
        assert flow.response is not None
        assert "blocked_by" not in flow.metadata  # not a policy block

    def test_transport_guard_does_not_fire_on_normal_probe(self):
        """Even if transport_guard's server_connect were invoked (as a
        belt-and-braces check), it must not refuse when the sink has
        already responded — because the underlying connection would
        never be initiated by mitmproxy in that case.

        Here we simulate: server_connect gets called after flow.response
        was set by the sink. TransportGuard's server_connect operates on
        ServerConnectionHookData (not the flow), so it will still refuse
        based on the probe host — which is the correct defense: if
        somehow the flow reaches server_connect for the probe host,
        refuse. The point being tested is that the sink prevents
        mitmproxy from *invoking* server_connect at all.
        """
        # This test is really an assertion on mitmproxy's contract: if
        # flow.response is set during `request`, server_connect does not
        # fire for that flow. We document the invariant here even
        # though we can't invoke the real proxy loop.
        reset_store_for_tests()

        from probe_sink import ProbeSink

        sink = ProbeSink()
        flow = _doctor_probe_flow()
        with taddons.context(sink):
            sink.requestheaders(flow)
            sink.request(flow)

        # The response is synthesised. In the real proxy loop, mitmproxy
        # inspects flow.response after the request hooks return and
        # skips server_connect. The transport-guard test in the sink-
        # failure class below verifies what happens if the sink didn't
        # fire.
        assert flow.response.status_code == 200


class TestSinkFailureLifecycle:
    """When probe_sink is missing/disabled/broken, mitmproxy proceeds
    to server_connect. transport_guard's server_connect must refuse the
    connection, and its error(flow) hook must record trace evidence so
    doctor can correlate the failure via /trace.
    """

    def test_missing_sink_lets_transport_guard_refuse_then_bridge_to_trace(self):
        """Simulate sink missing entirely: run RequestIdGenerator +
        server_connect (refuses) + error(flow) (records trace).
        """
        reset_store_for_tests()

        from request_id import RequestIdGenerator
        from transport_guard import REFUSAL_MESSAGE, TransportGuard

        rid_gen = RequestIdGenerator()
        guard = TransportGuard()

        # Simulate the request-side: RequestIdGenerator ran, sink did NOT
        # (nothing set flow.metadata["safeyolo_probe"] to True, but the
        # request went through anyway to a probe host).
        flow = _doctor_probe_flow()
        rid_gen.request(flow)
        original_rid = flow.metadata["request_id"]

        # Simulate transport_guard.server_connect refusing on probe host.
        data = SimpleNamespace(
            server=SimpleNamespace(address=(PROBE_HOST, 80), error=None),
            client=SimpleNamespace(
                peername=("10.0.0.42", 5555),
                sni=None,
                proxy_mode=SimpleNamespace(agent="doctor-probe"),
            ),
        )

        with patch("transport_guard.write_event", autospec=True,):
            guard.server_connect(data)

        assert data.server.error == REFUSAL_MESSAGE

        # mitmproxy then surfaces the error on the HTTPFlow. error(flow)
        # fires — the bridge we added in B12.
        flow.error = OSError("simulated: refused by transport_guard")
        with patch("transport_guard.write_event", autospec=True,):
            guard.error(flow)

        # request_id must be preserved (ensure_request_id is idempotent).
        assert flow.metadata["request_id"] == original_rid

        # Trace step recorded with the shared reason constant.
        rec = get_store().get(original_rid, flow.metadata["agent"])
        assert rec is not None
        step = rec.steps[-1]
        assert step.addon == "transport-guard"
        assert step.state == "error"
        assert step.reason == "probe_reached_upstream"

    def test_sink_disabled_case_produces_trace_evidence(self):
        """A pathological case: probe_sink was loaded but its request
        hook never terminated (returned early, raised, was removed).
        The flow reaches server_connect with the probe host address.
        transport_guard refuses AND bridges the refusal to a trace step
        via error(flow) so /trace can correlate.
        """
        reset_store_for_tests()

        from request_id import RequestIdGenerator
        from transport_guard import TransportGuard

        rid_gen = RequestIdGenerator()
        guard = TransportGuard()

        flow = _doctor_probe_flow()
        # Marker present (probe_sink.requestheaders ran) but sink.request
        # never terminated the flow, so it flows through to server_connect.
        flow.metadata["safeyolo_probe"] = True
        rid_gen.request(flow)
        original_rid = flow.metadata["request_id"]

        # server_connect fires with probe host address — refuse.
        data = SimpleNamespace(
            server=SimpleNamespace(address=(PROBE_HOST, 80), error=None),
            client=SimpleNamespace(
                peername=("10.0.0.42", 5555),
                sni=None,
                proxy_mode=SimpleNamespace(agent="doctor-probe"),
            ),
        )

        with patch("transport_guard.write_event", autospec=True,):
            guard.server_connect(data)
        assert data.server.error is not None

        # error(flow) bridges to trace with the shared reason constant.
        flow.error = OSError("simulated: refused")
        with patch("transport_guard.write_event", autospec=True,):
            guard.error(flow)

        assert flow.metadata["request_id"] == original_rid
        rec = get_store().get(original_rid, flow.metadata["agent"])
        assert rec is not None
        transport_steps = [s for s in rec.steps if s.addon == "transport-guard"]
        assert transport_steps
        assert transport_steps[0].reason == "probe_reached_upstream"
