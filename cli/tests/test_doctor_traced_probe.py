"""Tests for doctor's traced pipeline probe classification (#213 B5).

The disposition table is the decision surface the reviewer specified:

  evaluated/*                 -> PASS
  bypassed/addon_disabled     -> PASS, report state
  bypassed/policy_disabled    -> PASS, report state
  bypassed/prior_response     -> WARN, identify earlier responder
  not_loaded                  -> FAIL
  error/*                     -> FAIL
  truncated=true              -> FAIL
  trace unavailable           -> FAIL (covered elsewhere)

Ordering contract:
  - First-observed request-hook step per addon.
  - Every expected addon must have step or not_loaded entry.
  - Ordered first-observed subset must equal EXPECTED_ADDONS on a clean run.
  - Extra non-manifest steps are diagnostic only, not failures.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _patch_expected_addons():
    """Pin EXPECTED_ADDONS to a small deterministic set for these tests
    so a future manifest addition doesn't force test rewrites."""
    from safeyolo.core import trace as trace_mod

    original = list(trace_mod.EXPECTED_ADDONS)
    trace_mod.EXPECTED_ADDONS[:] = [
        "service-gateway",
        "network-guard",
        "credential-guard",
    ]
    yield
    trace_mod.EXPECTED_ADDONS[:] = original


def _step(addon, hook="request", state="evaluated", outcome=None, reason=None):
    step = {"addon": addon, "hook": hook, "state": state}
    if outcome is not None:
        step["outcome"] = outcome
    if reason is not None:
        step["reason"] = reason
    return step


def _classify(**overrides):
    """Call _classify_trace_steps with a canonical clean payload + overrides."""
    from safeyolo.commands.doctor import _classify_trace_steps

    payload = {
        "steps": [
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            _step("credential-guard", outcome="no_detection"),
        ],
        "not_loaded": [],
        "truncated": False,
    }
    payload.update(overrides)
    return _classify_trace_steps(payload)


class TestCleanRun:
    def test_clean_run_passes(self):
        verdict, findings, detail = _classify()
        assert verdict == "pass"
        # All three addons appear with `evaluated`; no warn/fail findings.
        addon_verdicts = [e for e in detail if "addon" in e]
        assert all(e.get("state") == "evaluated" for e in addon_verdicts)
        # No warn/fail explanations (only the probe-status note).
        assert not any("fail" in f.lower() or "warn" in f.lower() for f in findings)


class TestAddonDisabledIsPassWithReport:
    def test_addon_disabled_passes_and_is_reported(self):
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", state="bypassed", reason="addon_disabled"),
            _step("credential-guard", outcome="no_detection"),
        ])
        assert verdict == "pass"
        ng = next(e for e in detail if e.get("addon") == "network-guard")
        assert ng.get("verdict") == "pass_reported"
        assert any("network-guard: bypassed/addon_disabled" in f for f in findings)


class TestPolicyDisabledIsPassWithReport:
    def test_policy_disabled_passes_and_is_reported(self):
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            _step("credential-guard", state="bypassed", reason="policy_disabled"),
        ])
        assert verdict == "pass"
        cg = next(e for e in detail if e.get("addon") == "credential-guard")
        assert cg.get("verdict") == "pass_reported"
        assert any("credential-guard: bypassed/policy_disabled" in f for f in findings)


class TestPriorResponseIsWarn:
    def test_prior_response_warns(self):
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            _step("credential-guard", state="bypassed", reason="prior_response"),
        ])
        assert verdict == "warn"
        cg = next(e for e in detail if e.get("addon") == "credential-guard")
        assert cg.get("verdict") == "warn"
        assert any("credential-guard: bypassed/prior_response" in f for f in findings)


class TestErrorIsFail:
    def test_error_state_fails(self):
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", state="error", reason="RuntimeError"),
            _step("credential-guard", outcome="no_detection"),
        ])
        assert verdict == "fail"
        ng = next(e for e in detail if e.get("addon") == "network-guard")
        assert ng.get("verdict") == "fail"
        assert any("network-guard: error" in f for f in findings)


class TestNotLoadedIsFail:
    def test_not_loaded_addon_fails(self):
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            # credential-guard absent from steps but present in not_loaded
        ], not_loaded=[{"addon": "credential-guard", "state": "not_loaded"}])
        assert verdict == "fail"
        cg = next(e for e in detail if e.get("addon") == "credential-guard")
        assert cg.get("state") == "not_loaded"
        assert cg.get("verdict") == "fail"

    def test_missing_from_trace_entirely_fails(self):
        """Neither observed nor declared not_loaded — trace is incomplete
        for this addon. Equivalent to trace unavailable for that entry."""
        verdict, findings, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            # credential-guard missing entirely; not_loaded is empty
        ])
        assert verdict == "fail"
        cg = next(e for e in detail if e.get("addon") == "credential-guard")
        assert cg.get("state") == "missing_from_trace"


class TestTruncatedIsFail:
    def test_truncated_trace_fails(self):
        verdict, findings, _ = _classify(truncated=True)
        assert verdict == "fail"
        assert any("truncated" in f.lower() for f in findings)


class TestOrderingContract:
    def test_ordering_matches_manifest_passes(self):
        """First-observed subset in manifest order is the clean case."""
        verdict, _, _ = _classify()
        assert verdict == "pass"

    def test_ordering_divergence_warns(self):
        """Expected addons appearing in a different order from the manifest
        is a warn (not a fail) — ordering is meaningful but not fatal.
        """
        verdict, findings, _ = _classify(steps=[
            # network-guard before service-gateway swaps their positions
            _step("network-guard", outcome="allowed"),
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("credential-guard", outcome="no_detection"),
        ])
        assert verdict == "warn"
        assert any("ordering differs from manifest" in f for f in findings)

    def test_extra_non_manifest_addon_is_diagnostic_not_failure(self):
        """Non-manifest addons appearing in trace are noted but do not
        fail the check. Future diagnostic instrumentation must not break
        doctor.
        """
        verdict, _, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("some-future-diagnostic-addon", outcome="probe"),
            _step("network-guard", outcome="allowed"),
            _step("credential-guard", outcome="no_detection"),
        ])
        assert verdict == "pass"
        extras_entry = next((e for e in detail if "extras" in e), None)
        assert extras_entry is not None
        assert "some-future-diagnostic-addon" in extras_entry["extras"]


class TestFirstObservedStep:
    def test_only_first_step_per_addon_matters_for_verdict(self):
        """Trace can legitimately contain multiple steps per addon (extras
        added by future diagnostic instrumentation). The classification
        looks only at the FIRST observed request-hook step for each
        expected addon.
        """
        verdict, _, detail = _classify(steps=[
            _step("service-gateway", outcome="not_a_gateway_request"),
            _step("network-guard", outcome="allowed"),
            # Second network-guard step with a different outcome — must
            # not change the verdict for network-guard.
            _step("network-guard", outcome="secondary-observation"),
            _step("credential-guard", outcome="no_detection"),
        ])
        assert verdict == "pass"
        ng = next(e for e in detail if e.get("addon") == "network-guard")
        assert ng.get("outcome") == "allowed"


class TestHelperUtilities:
    def test_worst_precedence(self):
        from safeyolo.commands.doctor import _worst
        assert _worst("pass", "warn") == "warn"
        assert _worst("warn", "pass") == "warn"
        assert _worst("warn", "fail") == "fail"
        assert _worst("fail", "pass") == "fail"
        assert _worst("pass", "pass") == "pass"


def _production_sock_path(tmp_path, agent="agentx", ip="10.0.0.42"):
    """Build a socket path with SafeYolo's production layout:
    `<sockets_dir>/<ip>_<agent>/proxy.sock`. Uses `sockets.path_for` so
    the shape stays in step with the source of truth — reviewer flagged
    that hand-crafted `<ip>_<agent>.sock` paths hid the parse bug where
    doctor labelled every real agent as `proxy` (issue #213 B8).
    """
    from safeyolo import sockets as _sockets

    # Point sockets_dir at tmp_path so path_for lands under our tmp tree.
    with patch.object(_sockets, "sockets_dir", return_value=tmp_path):
        p = _sockets.path_for(agent, ip)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class TestProbeOneSocketNoResponse:
    def test_probe_missing_response_returns_fail(self, tmp_path):
        """When the UDS send raises OSError, doctor returns fail without
        even attempting to fetch /trace. Uses the production socket shape
        so doctor parses the real agent name (regression against #213 B8).
        """
        from safeyolo.commands import doctor

        sock = _production_sock_path(tmp_path, agent="agentx")
        with patch.object(doctor, "_send_uds_request", side_effect=OSError("no socket")):
            result = doctor._probe_one_socket(sock, token="tok")
        assert result.status == "fail"
        assert "agentx" in result.name
        # And critically NOT the literal filename stem:
        assert "proxy" not in result.name.split("traced, ")[1].split(")")[0]
        assert "UDS probe failed" in result.message

    def test_probe_response_missing_request_id_fails(self, tmp_path):
        """If the probe response lacks X-SafeYolo-Request-Id we can't
        correlate to /trace — hard fail.
        """
        from safeyolo.commands import doctor

        sock = _production_sock_path(tmp_path, agent="agentx")
        canned = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        with patch.object(doctor, "_send_uds_request", return_value=canned):
            result = doctor._probe_one_socket(sock, token="tok")
        assert result.status == "fail"
        assert "missing X-SafeYolo-Request-Id" in result.message

    def test_probe_success_delegates_to_classifier(self, tmp_path):
        """Happy path: probe returns request_id, /trace returns a clean
        payload, classifier verdict propagates.
        """
        from safeyolo.commands import doctor

        sock = _production_sock_path(tmp_path, agent="agentx")

        probe_response = (
            b"HTTP/1.0 200 OK\r\n"
            b"X-SafeYolo-Request-Id: req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
            b"Content-Type: application/json\r\n\r\n"
            b'{"probe_ok": true}'
        )
        clean_trace = {
            "steps": [
                _step("service-gateway", outcome="not_a_gateway_request"),
                _step("network-guard", outcome="allowed"),
                _step("credential-guard", outcome="no_detection"),
            ],
            "not_loaded": [],
            "truncated": False,
        }
        import json as _json
        trace_response = (
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"
            + _json.dumps(clean_trace).encode()
        )

        calls = {"n": 0}

        def fake_send(_path, _req, timeout=5.0):
            calls["n"] += 1
            return probe_response if calls["n"] == 1 else trace_response

        with patch.object(doctor, "_send_uds_request", side_effect=fake_send):
            result = doctor._probe_one_socket(sock, token="tok")

        assert result.status == "pass"
        assert "agentx" in result.name
        assert "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in result.message


class TestProbeSocketPathParse:
    def test_agent_hint_comes_from_directory_not_filename(self, tmp_path):
        """Regression against #213 B8: earlier code parsed sock_path.name
        as `<ip>_<agent>.sock` and split on `_`. The real invariant is
        `<sockets_dir>/<ip>_<agent>/proxy.sock` — the filename is
        literally `proxy.sock`, so every real agent got labelled `proxy`.
        Doctor now uses sockets.parse() and reports the actual agent.
        """
        from safeyolo.commands import doctor

        sock = _production_sock_path(tmp_path, agent="realagent", ip="10.9.8.7")
        assert sock.name == "proxy.sock"  # sanity: production layout
        with patch.object(doctor, "_send_uds_request", side_effect=OSError("boom")):
            result = doctor._probe_one_socket(sock, token="tok")
        # Real agent name in DiagResult label + no "proxy" leak.
        assert "traced, realagent" in result.name
        assert "traced, proxy" not in result.name
