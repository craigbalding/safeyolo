"""Shared live circuit state, local API reads and the real operator reset client.

The owned 127.0.0.2 peer is outside the source's localhost exclusions. Complete
fixed-length responses establish this workflow; parser timing, recovery timers
and persistence across restart have separate proofs. No circuit calls are mocked.
"""

import json
import socket
import threading
import time
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from safeyolo.api import AdminAPI
from tests.proxy_migration.harness import read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import Origin, OriginHandler
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import ALLOW, DENY, assert_rejection, policy_proxy
from tests.proxy_migration.test_operator_budgets import TOKEN, operator_wire

HOST = "127.0.0.2"
SETTINGS = """
[addons.circuit_breaker]
failure_threshold = 2
timeout_seconds = 120
use_exponential_backoff = false
jitter_factor = 0
"""
AUDITS = (
    "ops.circuit_breaker.open",
    "security.circuit_breaker",
    "ops.circuit_breaker.reset",
    "admin.circuit_breaker_reset",
)


class CircuitOrigin(Origin):
    def __init__(self):
        self.accepts = 0
        self.requests = []
        ThreadingHTTPServer.__init__(self, (HOST, 0), CircuitOriginHandler)


class CircuitOriginHandler(OriginHandler):
    def do_GET(self):
        self.server.requests.append({"method": self.command, "target": self.path})
        status = 500 if self.path == "/failure" else 200
        self.send_response(status)
        self.send_header("Content-Length", "5")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"hello")


@contextmanager
def circuit_proxy(backend, tmp_path, monkeypatch, *, enabled=True, policy=ALLOW):
    def no_operator_defaults():
        raise AssertionError("Only the explicitly owned operator endpoint and synthetic token may be used")

    monkeypatch.setattr("safeyolo.api.get_admin_token", no_operator_defaults)
    monkeypatch.setattr("safeyolo.api.load_config", no_operator_defaults)
    token_file = tmp_path / "operator-token"
    token_file.touch(mode=0o600)
    token_file.write_text(TOKEN + "\n")
    # Source shields its configured port. Reserve then release an owned port;
    # a failed child bind cannot satisfy the existing readiness assertion.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    assert port != 9090
    origin = CircuitOrigin()
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    directory = tmp_path / backend
    proxy = None
    try:
        with policy_proxy(
            backend,
            directory,
            policy + SETTINGS,
            agent_api=True,
            circuit_breaker_enabled=enabled,
            admin_port=port,
            admin_api_token_file=token_file,
        ) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            assert marker["pid"] == proxy.process.pid and marker["admin_port"] == port
            config = json.loads((directory / "proxy.json").read_text())
            assert config["circuit_state_file"] == str(directory / "circuit-state.json")
            client = AdminAPI(base_url=f"http://127.0.0.1:{port}", token=TOKEN, timeout=5)
            yield proxy, origin, client, port
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        if proxy is not None:
            assert proxy.process.poll() is not None and not proxy.readiness_file.exists()
            assert all(not Path(path).exists() for path in proxy.paths.values())
            for address in (("127.0.0.1", port), origin.server_address):
                with socket.socket() as closed:
                    closed.settimeout(1)
                    assert closed.connect_ex(address) != 0
            egress = proxy.events("proxy.egress")
            assert all((event["host"], event["port"]) == origin.server_address for event in egress)
            assert len(egress) == origin.accepts == len(origin.requests)
            for name in ("events.jsonl", "audit.jsonl", "process.log", "agent-api-wire.jsonl", "circuit-wire.jsonl"):
                path = directory / name
                if path.exists():
                    data = path.read_bytes()
                    assert TOKEN.encode() not in data and TOKEN.encode().hex().encode() not in data
            (directory / "circuit-lifecycle.json").write_text(
                json.dumps(
                    {
                        "pid": proxy.process.pid,
                        "returncode": proxy.process.returncode,
                        "admin_port": port,
                        "origin_address": origin.server_address,
                        "readiness_gone": True,
                        "agent_sockets_gone": True,
                        "admin_port_closed": True,
                        "origin_port_closed": True,
                        "origin_accepts": origin.accepts,
                        "egress_count": len(egress),
                        "unexpected_egress": 0,
                        "token_absent_from_diagnostics": True,
                    },
                    indent=2,
                )
                + "\n"
            )


def hit(proxy, origin, agent, path, expected):
    before = origin.accepts, len(proxy.events("proxy.egress"))
    result = send_request(proxy.paths[agent], f"http://{HOST}:{origin.server_address[1]}{path}")
    status, headers, body = result
    assert status == expected, body
    if expected in (200, 500):
        assert body == b"hello"
    contacted = int(expected in (200, 500))
    assert (origin.accepts, len(proxy.events("proxy.egress"))) == (before[0] + contacted, before[1] + contacted)
    with (proxy.event_log.parent / "circuit-wire.jsonl").open("a") as output:
        output.write(
            json.dumps(
                {
                    "agent": agent,
                    "path": path,
                    "status": status,
                    "headers": headers,
                    "body_hex": body.hex(),
                    "origin_contacts": contacted,
                }
            )
            + "\n"
        )
    return result


def read_circuits(
    proxy, origin, *, checks, opens, failure_count=None, state="closed", enabled=True, threshold=2, opened_after=None
):
    before = origin.accepts, len(proxy.events("proxy.egress"))
    for agent in ("alice", "bob"):
        body = assert_api_response(api_request(proxy, "/circuits", agent=agent), 200)
        assert list(body) == [
            "enabled",
            "failure_threshold",
            "timeout_seconds",
            "checks_total",
            "opens_total",
            "half_opens_total",
            "recoveries_total",
            "domains",
        ]
        assert {key: value for key, value in body.items() if key != "domains"} == {
            "enabled": enabled,
            "failure_threshold": threshold,
            "timeout_seconds": 120 if enabled else 60,
            "checks_total": checks,
            "opens_total": opens,
            "half_opens_total": 0,
            "recoveries_total": 0,
        }
        if failure_count is None:
            assert body["domains"] == {}
        else:
            assert list(body["domains"]) == [HOST]
            domain = body["domains"][HOST]
            assert list(domain) == ["state", "failure_count", "failure_streak", "time_until_half_open"]
            assert domain["state"] == state and domain["failure_count"] == failure_count
            assert domain["failure_streak"] == 0
            remaining = domain["time_until_half_open"]
            if state == "open":
                assert opened_after is not None
                assert 120 - (time.monotonic() - opened_after) - 1 <= remaining <= 120
            else:
                assert remaining is None
    assert (origin.accepts, len(proxy.events("proxy.egress"))) == before


def circuit_audits(proxy, backend):
    if backend == "python":
        return [event for event in read_events(proxy.event_log.parent / "audit.jsonl") if event["event"] in AUDITS]
    rows = [event for event in read_events(proxy.event_log) if event.get("audit_intent") in AUDITS]
    for event in rows:
        expected = "proxy.admin_api" if event["audit_intent"].startswith("admin.") else "proxy.circuit"
        assert event["event"] == expected
    return rows


def test_operator_reset_reopens_admission_for_shared_completed_failures(proxy_backend, tmp_path, monkeypatch):
    with circuit_proxy(proxy_backend, tmp_path, monkeypatch) as (proxy, origin, client, port):
        hit(proxy, origin, "alice", "/failure", 500)
        read_circuits(proxy, origin, checks=1, opens=0, failure_count=1)
        opened_after = time.monotonic()
        hit(proxy, origin, "bob", "/failure", 500)
        read_circuits(proxy, origin, checks=2, opens=1, failure_count=2, state="open", opened_after=opened_after)
        _, headers, body = hit(proxy, origin, "alice", "/retry", 503)
        headers = {name.lower(): value for name, value in headers.items()}
        assert headers["x-blocked-by"] == "circuit-breaker" and headers["x-circuit-state"] == "open"
        denied = json.loads(body)
        retry_after = denied["retry_after_seconds"]
        assert 120 - (time.monotonic() - opened_after) - 1 <= retry_after <= 120
        assert headers["retry-after"] == str(retry_after)
        assert denied == {
            "error": f"Service temporarily unavailable: {HOST}",
            "domain": HOST,
            "circuit_state": "open",
            "retry_after_seconds": retry_after,
            "message": f"Circuit breaker open for {HOST}. Service has failed 2 times. Will retry in {retry_after} seconds.",
        }
        read_circuits(proxy, origin, checks=3, opens=1, failure_count=2, state="open", opened_after=opened_after)
        before = origin.accepts, len(proxy.events("proxy.egress"))
        assert_api_response(api_request(proxy, "/circuits", auth=None), 401)
        unauthorized = operator_wire(
            proxy, port, "POST", "/admin/circuit-breaker/reset", body=json.dumps({"host": HOST}).encode(), token=None
        )
        assert len(unauthorized) == 1 and unauthorized[0]["status"] == 401
        read_circuits(proxy, origin, checks=3, opens=1, failure_count=2, state="open", opened_after=opened_after)
        assert client.reset_circuit(HOST) == {"status": "reset", "host": HOST}
        read_circuits(proxy, origin, checks=3, opens=1)
        assert (origin.accepts, len(proxy.events("proxy.egress"))) == before
        hit(proxy, origin, "bob", "/retry", 200)
        read_circuits(proxy, origin, checks=4, opens=1)
        audits = circuit_audits(proxy, proxy_backend)
        key = "event" if proxy_backend == "python" else "audit_intent"
        assert [event[key] for event in audits] == list(AUDITS)
        assert audits[0]["host"] == HOST and audits[0]["agent"] == "bob"
        assert audits[1]["host"] == HOST and audits[1]["agent"] == "alice"
        assert audits[1]["decision"] == "deny"
        assert origin.requests == [{"method": "GET", "target": path} for path in ("/failure", "/failure", "/retry")]


@pytest.mark.parametrize("control", ["global-disabled", "network-denied"])
def test_circuit_controls_do_not_count_failures(proxy_backend, tmp_path, monkeypatch, control):
    enabled = control != "global-disabled"
    with circuit_proxy(proxy_backend, tmp_path, monkeypatch, enabled=enabled, policy=DENY if enabled else ALLOW) as (
        proxy,
        origin,
        _client,
        _port,
    ):
        for agent in ("alice", "bob", "alice"):
            result = hit(proxy, origin, agent, "/failure", 403 if enabled else 500)
            if enabled:
                assert_rejection(*result, 403, HOST)
        read_circuits(proxy, origin, checks=0, opens=0, enabled=enabled, threshold=2 if enabled else 5)
        assert circuit_audits(proxy, proxy_backend) == []
