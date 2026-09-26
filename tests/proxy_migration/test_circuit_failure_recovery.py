"""Shared real-proxy circuit failure and recovery through an owned parent."""

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from tests.proxy_migration.harness import read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.test_circuit_completion import circuits
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy

FAILING_HOST = "failure.invalid"
HEALTHY_HOST = "healthy.invalid"
POLICY = (
    ALLOW
    + """
[addons.circuit_breaker]
failure_threshold = 2
success_threshold = 1
timeout_seconds = 4
use_exponential_backoff = false
jitter_factor = 0
"""
)


class CircuitParent(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.accepts = 0
        self.requests = []
        self.request_heads = []
        self.failing = True
        super().__init__(("127.0.0.1", 0), CircuitParentHandler)

    def get_request(self):
        connection = super().get_request()
        self.accepts += 1
        return connection


class CircuitParentHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        host = urlsplit(self.path).hostname
        assert host in {FAILING_HOST, HEALTHY_HOST}, self.path
        status = 500 if host == FAILING_HOST and self.server.failing else 200
        body = b"failed" if status == 500 else b"ready"
        self.server.request_heads.append(self.raw_requestline + self.headers.as_bytes())
        self.server.requests.append({"target": self.path, "host": host, "status": status})
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def circuit_parent():
    parent = CircuitParent()
    thread = threading.Thread(target=parent.serve_forever)
    thread.start()
    try:
        yield parent
    finally:
        parent.shutdown()
        parent.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "owned parent did not stop"


def circuit_audits(proxy, backend):
    if backend == "python":
        rows = read_events(proxy.event_log.parent / "audit.jsonl")
        return [(row["event"], row) for row in rows if row["event"].startswith("ops.circuit_breaker.")
                or row["event"] == "security.circuit_breaker"]
    rows = read_events(proxy.event_log)
    return [(row["audit_intent"], row) for row in rows if row.get("audit_intent", "").startswith(
        "ops.circuit_breaker."
    ) or row.get("audit_intent") == "security.circuit_breaker"]


def test_parent_failure_opens_only_its_host_and_half_open_probe_recovers(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    observations = []
    with circuit_parent() as parent:
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        with policy_proxy(
            proxy_backend, directory, POLICY, parent_proxy=parent_url,
            agent_api=True, circuit_breaker_enabled=True,
        ) as proxy:
            def hit(agent, host, path, expected, *, forwarded):
                target = f"http://{host}/{path}"
                before = (parent.accepts, len(parent.requests), len(parent.request_heads),
                          len(proxy.events("proxy.egress")))
                status, headers, body = send_request(
                    proxy.paths[agent], target,
                    headers={"X-Fixture-Canary": "circuit-failure-recovery"},
                )
                after = (parent.accepts, len(parent.requests), len(parent.request_heads),
                         len(proxy.events("proxy.egress")))
                assert status == expected, (target, status, body)
                assert after == tuple(value + int(forwarded) for value in before)
                if forwarded:
                    assert parent.requests[-1] == {"target": target, "host": host, "status": expected}
                    assert parent.request_heads[-1].startswith(f"GET {target} HTTP/1.1\r\n".encode())
                    assert b"X-Fixture-Canary: circuit-failure-recovery\n" in parent.request_heads[-1]
                    assert body == (b"failed" if expected == 500 else b"ready")
                else:
                    normalized = {key.lower(): value for key, value in headers.items()}
                    assert normalized["x-blocked-by"] == "circuit-breaker"
                    assert normalized["x-circuit-state"] == "open"
                    blocked = json.loads(body)
                    assert blocked["domain"] == host and blocked["circuit_state"] == "open"
                    assert normalized["retry-after"] == str(blocked["retry_after_seconds"])
                identifier = next(value for key, value in headers.items()
                                  if key.lower() == "x-safeyolo-request-id")
                assert identifier.startswith("req-")
                observations.append({
                    "agent": agent, "target": target, "status": status, "headers": headers,
                    "body_hex": body.hex(), "request_id": identifier,
                    "parent_before": before, "parent_after": after,
                })
                return identifier

            hit("alice", HEALTHY_HOST, "before", 200, forwarded=True)
            hit("alice", FAILING_HOST, "failure-one", 500, forwarded=True)
            hit("bob", FAILING_HOST, "failure-two", 500, forwarded=True)
            opened = circuits(proxy)
            assert opened["timeout_seconds"] == 4
            assert opened["opens_total"] == 1
            assert opened["domains"][FAILING_HOST]["state"] == "open"
            assert opened["domains"][FAILING_HOST]["failure_count"] == 2
            hit("alice", FAILING_HOST, "blocked", 503, forwarded=False)
            hit("bob", HEALTHY_HOST, "during", 200, forwarded=True)
            parent.failing = False
            hit("bob", FAILING_HOST, "still-blocked", 503, forwarded=False)
            deadline = time.monotonic() + 6
            while True:
                half_open = circuits(proxy)
                if half_open["domains"][FAILING_HOST]["state"] == "half_open":
                    break
                assert time.monotonic() < deadline, half_open
                time.sleep(0.1)
            hit("alice", FAILING_HOST, "recovered", 200, forwarded=True)
            hit("bob", HEALTHY_HOST, "after", 200, forwarded=True)
            recovered = circuits(proxy)
            assert recovered["domains"][FAILING_HOST]["state"] == "closed"
            assert recovered["domains"][FAILING_HOST]["failure_count"] == 0
            assert recovered["half_opens_total"] == recovered["recoveries_total"] == 1
            assert (parent.accepts == len(parent.requests) == len(parent.request_heads)
                    == len(proxy.events("proxy.egress")) == 6)
            egress = proxy.events("proxy.egress")
            if proxy_backend == "rust":
                assert all(row["route"] == "parent" and row["host"] in {FAILING_HOST, HEALTHY_HOST}
                           for row in egress)
            else:
                assert all((row["host"], row["port"]) == parent.server_address for row in egress)
            requests = [row for row in proxy.events("proxy.request")
                        if row["host"] in {FAILING_HOST, HEALTHY_HOST}]
            assert [(row["agent"], row["host"], row["status"], row["request_id"]) for row in requests] == [
                (item["agent"], urlsplit(item["target"]).hostname, item["status"], item["request_id"])
                for item in observations
            ]
            audits = circuit_audits(proxy, proxy_backend)
            assert [name for name, _ in audits] == [
                "ops.circuit_breaker.open", "security.circuit_breaker",
                "security.circuit_breaker", "ops.circuit_breaker.half_open",
                "ops.circuit_breaker.close",
            ]
            assert all(row["host"] == FAILING_HOST for _, row in audits)
            assert [row.get("agent") for _, row in audits] == ["bob", "alice", "bob", None, "alice"]
            assert audits[0][1]["details"]["failure_count"] == 2
            assert audits[-1][1]["details"]["success_count"] == 1
            assert all(row["decision"] == "deny" and row["details"]["circuit_state"] == "open"
                       for _, row in audits[1:3])
            assert audits[0][1]["request_id"] == observations[2]["request_id"]
            assert [row["request_id"] for _, row in audits[1:3]] == [
                observations[3]["request_id"], observations[5]["request_id"],
            ]
            assert audits[-1][1]["request_id"] == observations[6]["request_id"]
