"""Controls for interpreting the nested Docker fixture's outbound results.

These exercise the observer's refusal handling. They do not establish the
installed sandbox's network enforcement.
"""

import io
import json
import runpy
from email.message import Message
from pathlib import Path
from unittest.mock import create_autospec
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.response import addinfourl

import pytest

from tests.blackbox.installed_docker_preflight import verify_outbound

PROBE = Path(__file__).parent / "blackbox/fixtures/nested-docker/network_probe.py"


@pytest.mark.parametrize("refusal", ["policy", "missing-attribution", "approval", "reachable", "transport"])
def test_network_probe_requires_an_explicit_policy_denial(monkeypatch, capsys, refusal):
    headers = Message()
    headers["X-SafeYolo-Request-Id"] = "req-allowed"
    allowed = addinfourl(io.BytesIO(b"allowed"), headers, "https://example.com", 200)
    denied_headers = Message()
    denied_headers["X-SafeYolo-Request-Id"] = "req-denied"
    if refusal != "missing-attribution":
        denied_headers["X-Blocked-By"] = "network-guard"
    if refusal == "reachable":
        denied = addinfourl(io.BytesIO(b"unexpected origin"), Message(), "http://denied.invalid", 200)
    elif refusal == "transport":
        denied = URLError("proxy transport failed")
    else:
        status = 428 if refusal == "approval" else 403
        denied = HTTPError("http://denied.invalid", status, "refused", denied_headers, io.BytesIO(b"refused"))
    boundary = create_autospec(urlopen, spec_set=True, side_effect=[allowed, denied])
    monkeypatch.setattr("urllib.request.urlopen", boundary)
    monkeypatch.setenv("PROBE_PHASE", "build")
    if refusal == "policy":
        runpy.run_path(str(PROBE))
        rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert [(row["status"], row["request_id"]) for row in rows] == [(200, "req-allowed"), (403, "req-denied")]
    else:
        with pytest.raises(URLError if refusal == "transport" else AssertionError):
            runpy.run_path(str(PROBE))
    assert [call.args[0].full_url for call in boundary.call_args_list] == [
        "https://example.com", "http://denied.invalid"]


@pytest.mark.parametrize("deny_run", ["current", "recovered", "stopped", "foreign"])
def test_outbound_consumer_excludes_retained_other_generations(deny_run):
    report = {"runtime": {"agent_id": "ag-host", "run_id": "current"},
              "recovery": {"after": {"run_id": "recovered"}},
              "network_probes": [
                  {"request_id": "req-allowed", "destination": "example.com", "status": 200},
                  {"request_id": "req-denied", "destination": "denied.invalid", "status": 403}]}
    allowed = {"event": "traffic.response", "request_id": "req-allowed", "agent": "notes", "host": "example.com",
               "details": {"sandbox_run": {"agent_id": "ag-host", "run_id": "current"}}}
    denied = {"event": "security.network_guard", "request_id": "req-denied", "agent": "notes",
              "host": "denied.invalid", "decision": "deny", "details": {"sandbox_run": {
                  "agent_id": "ag-other" if deny_run == "foreign" else "ag-host", "run_id": deny_run}}}
    stopped = {**allowed, "details": {"sandbox_run": {"agent_id": "ag-host", "run_id": "stopped"}}}
    if deny_run in {"current", "recovered"}:
        verify_outbound([stopped, allowed, denied], report, reused_image=True)
        assert report["outbound"] == [{**{key: row.get(key) for key in (
            "event", "request_id", "agent", "host", "decision")}, "sandbox_run": row["details"]["sandbox_run"]}
            for row in (allowed, denied)]
    else:
        with pytest.raises(AssertionError, match="hosting-principal"):
            verify_outbound([stopped, allowed, denied], report, reused_image=True)
