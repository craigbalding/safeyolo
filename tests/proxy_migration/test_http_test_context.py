"""Ordinary native HTTP provenance, using owned parent sockets and UDS agents.

The historical launcher does not load TestContext. Source hook/body ordering is
retained in the core oracles; these cases test the actual joined native proxy.
"""

import hashlib
import io
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.proxy_migration.harness import connection, request
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID
from tests.proxy_migration.test_agent_api_test_context import declare
from tests.proxy_migration.test_native_network_policy import policy_proxy

HEADER = "X-SafeYolo-Test-Context"
CLAIM = "run=owned;agent=claimed;test=T1"
HOST = "context.invalid"
PATH = "/ordinary?part=one&part=two%2Fthree"
URL = f"http://{HOST}:8123{PATH}"
THRESHOLD = 10 * 1024 * 1024


class BodyParent(ThreadingHTTPServer):
    """Read ordinary fixed/chunked fixture bodies, or send an early response."""

    def __init__(self, *, response_body=b"reply", response_encoding=None, early=False):
        self.accepts = 0
        self.requests = []
        self.errors = []
        self.response_body = response_body
        self.response_encoding = response_encoding
        self.early = early
        super().__init__(("127.0.0.1", 0), BodyHandler)

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        result[0].settimeout(10)
        return result


class BodyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                line = self.rfile.readline()
                assert line.endswith(b"\r\n"), "owned request ended before chunk size"
                size = int(line.strip(), 16)
                if size == 0:
                    assert self.rfile.readline() == b"\r\n", "fixture sends no request trailers"
                    return bytes(body)
                part = self.rfile.read(size)
                assert len(part) == size
                body.extend(part)
                assert self.rfile.read(2) == b"\r\n"
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        assert len(body) == size
        return body

    def do_POST(self):
        try:
            body = None if self.server.early else self.read_body()
            self.server.requests.append({
                "target": self.path,
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": body,
            })
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.server.response_body)))
            self.send_header("Content-Type", "application/octet-stream")
            if self.server.response_encoding is not None:
                self.send_header("Content-Encoding", self.server.response_encoding)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(self.server.response_body)
            self.wfile.flush()
        except (AssertionError, OSError, ValueError) as error:
            self.server.errors.append(error)
        finally:
            self.close_connection = True


@contextmanager
def parent_server(**options):
    parent = BodyParent(**options)
    thread = threading.Thread(target=parent.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield parent
    finally:
        parent.shutdown()
        parent.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "owned parent did not finish"
        assert not parent.errors, parent.errors


@contextmanager
def context_proxy(backend, directory, parent):
    if backend != "rust":
        pytest.skip("Native HTTP TestContext integration; historical launcher leaves this addon unloaded")
    policy = json.dumps({
        "hosts": {"*": {"egress": "allow"}},
        "addons": {"test_context": {
            "target_hosts": [HOST], "inject_declared": True, "declared_ttl_max": 900,
        }},
    })
    with policy_proxy(
        "rust", directory, policy, policy_format="json", agent_api=True,
        parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        circuit_breaker_enabled=False, circuit_state_file="",
    ) as proxy:
        yield proxy
    assert proxy.process.returncode == 0
    assert not proxy.readiness_file.exists()
    assert all(not Path(path).exists() for path in proxy.paths.values())


def send(proxy, body, *, agent="alice", claim=CLAIM, encoding=None):
    headers = {"X-SafeYolo-Request-Id": FORGED_REQUEST_ID, "X-SafeYolo-Agent": "forged"}
    if claim is not None:
        headers[HEADER] = claim
    if encoding is not None:
        headers["Content-Encoding"] = encoding
    status, headers, raw = request(proxy.paths[agent], URL, method="POST", headers=headers, body=body)
    headers = {name.lower(): value for name, value in headers.items()}
    assert headers["x-safeyolo-request-id"] != FORGED_REQUEST_ID
    return status, headers, raw


def request_events(proxy, identifier):
    return [event for event in proxy.events("security.test_context") if event["request_id"] == identifier]


def assert_phases(events, phases, *, context=None):
    assert [event["details"].get("phase") for event in events] == phases
    for event in events:
        assert event["event"] == "security.test_context"
        assert event["kind"] == "security" and event["severity"] == "low"
        assert event["addon"] == "test-context" and event["host"] == HOST
        assert event["agent"] == "alice"
        assert event["details"]["trusted_agent"] == "alice"
        assert event["details"]["test_agent_match"] is False
        assert event["details"]["method"] == "POST" and event["details"]["path"] == PATH
        if context is not None:
            assert event["details"]["context"] == context


def assert_parent_request(parent, body):
    assert parent.accepts == len(parent.requests) == 1
    observed = parent.requests[0]
    assert observed["target"] == URL
    assert HEADER.lower() not in observed["headers"]
    assert observed["body"] == body


def test_missing_context_blocks_before_parent_accept_without_waiting_for_body(proxy_backend, tmp_path):
    with parent_server() as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            client = connection(proxy.paths["alice"])
            try:
                client.putrequest("POST", URL)
                client.putheader("Content-Length", str(THRESHOLD + 1))
                client.putheader("Connection", "close")
                client.endheaders()  # Intentionally no request body yet.
                response = client.getresponse()
                assert response.status == 428
                assert response.getheader("X-Blocked-By") == "test-context"
                assert json.loads(response.read())["type"] == "missing_context"
            finally:
                client.close()
            assert proxy.events("proxy.egress") == []
        assert parent.accepts == 0 and parent.requests == []
        events = proxy.events("security.test_context")
        assert len(events) == 1 and events[0]["decision"] == "deny"
        assert events[0]["details"]["reason"] == "missing_context"


def test_valid_explicit_context_preserves_bodies_and_trusted_source_phases(proxy_backend, tmp_path):
    payload = b"request\x00payload"
    reply = b"reply\x00\xff"
    with parent_server(response_body=reply) as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            status, headers, raw = send(proxy, payload)
            assert status == 200 and raw == reply
        assert_parent_request(parent, payload)
        events = request_events(proxy, headers["x-safeyolo-request-id"])
        assert_phases(events, ["request", "response"], context={"run": "owned", "agent": "claimed", "test": "T1"})
        assert all(event["details"]["test_context_source"] == "header" for event in events)
        assert events[0]["details"]["request_body_snippet"] == payload.decode()
        assert events[1]["details"]["response_body_snippet"] == reply.decode(errors="replace")
        assert isinstance(events[1]["details"]["duration_ms"], int)
        assert len(proxy.events("proxy.egress")) == 1


def test_declared_context_stays_in_its_trusted_slot_and_malformed_header_cannot_fall_back(proxy_backend, tmp_path):
    with parent_server() as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            declaration = declare(proxy, run="wire-declared")
            status, headers, raw = send(proxy, b"declared", claim=None)
            assert status == 200 and raw == b"reply"
            bob_status, bob_headers, bob_body = send(proxy, b"", agent="bob", claim=None)
            assert bob_status == 428 and json.loads(bob_body)["type"] == "missing_context"
            bad_status, bad_headers, bad_body = send(proxy, b"", claim="malformed")
            assert bad_status == 428 and json.loads(bad_body)["type"] == "malformed_context"
        assert_parent_request(parent, b"declared")
        events = request_events(proxy, headers["x-safeyolo-request-id"])
        assert_phases(events, ["request", "response"], context=declaration.body["context"])
        assert all(event["details"]["test_context_source"] == "declared" for event in events)
        for response_headers, agent in [(bob_headers, "bob"), (bad_headers, "alice")]:
            denial = request_events(proxy, response_headers["x-safeyolo-request-id"])
            assert len(denial) == 1 and denial[0]["decision"] == "deny"
            assert denial[0]["agent"] == agent and "phase" not in denial[0]["details"]
        assert len(proxy.events("proxy.egress")) == 1


@pytest.mark.parametrize("invalid_phase", ["request", "response"])
def test_content_decode_failure_preserves_wire_bytes_and_reached_event_phase(proxy_backend, tmp_path, invalid_phase):
    payload = b"invalid" if invalid_phase == "request" else b"normal"
    reply = b"invalid" if invalid_phase == "response" else b"normal"
    with parent_server(response_body=reply, response_encoding="gzip" if invalid_phase == "response" else None) as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            status, headers, raw = send(proxy, payload, encoding="gzip" if invalid_phase == "request" else None)
            assert status == 200 and raw == reply
        assert_parent_request(parent, payload)
        phases = ["response"] if invalid_phase == "request" else ["request"]
        assert_phases(request_events(proxy, headers["x-safeyolo-request-id"]), phases)
        assert len(proxy.events("proxy.egress")) == 1


@pytest.mark.parametrize("known_length", [True, False], ids=["known-length", "unknown-length"])
def test_completed_large_request_preserves_bytes_and_has_both_provenance_phases(proxy_backend, tmp_path, known_length):
    payload = b"x" * (THRESHOLD + 1)
    with parent_server() as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            body = payload if known_length else io.BytesIO(payload)
            status, headers, raw = send(proxy, body)
            assert status == 200 and raw == b"reply"
        assert parent.accepts == len(parent.requests) == 1
        observed = parent.requests[0]
        assert observed["target"] == URL and HEADER.lower() not in observed["headers"]
        assert len(observed["body"]) == len(payload)
        assert hashlib.sha256(observed["body"]).digest() == hashlib.sha256(payload).digest()
        events = request_events(proxy, headers["x-safeyolo-request-id"])
        assert_phases(events, ["request", "response"])
        assert events[0]["details"]["request_body_snippet"] == ""
        assert events[1]["details"]["response_body_snippet"] == "reply"


def test_ordinary_early_response_before_request_eom_has_no_provenance(proxy_backend, tmp_path):
    with parent_server(response_body=b"early", early=True) as parent:
        with context_proxy(proxy_backend, tmp_path / "proxy", parent) as proxy:
            client = connection(proxy.paths["alice"])
            try:
                client.putrequest("POST", URL)
                client.putheader("Content-Length", str(THRESHOLD + 1))
                client.putheader(HEADER, CLAIM)
                client.putheader("Connection", "close")
                client.endheaders()  # Source-streamed request; no EOM or body yet.
                response = client.getresponse()
                assert response.status == 200 and response.read() == b"early"
            finally:
                client.close()
        assert parent.accepts == len(parent.requests) == 1
        assert parent.requests[0]["body"] is None
        assert HEADER.lower() not in parent.requests[0]["headers"]
        assert proxy.events("security.test_context") == []
        assert len(proxy.events("proxy.egress")) == 1
