"""Configured parent routing at the real Python and Rust proxy boundary."""

import socket
import socketserver
import threading
from contextlib import contextmanager

from tests.proxy_migration.harness import launch_proxy, read_events, request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_tunnel_contract import read_all, read_exact, read_until

HTTP_HOST = "parent-http.invalid"
TUNNEL_HOST = "parent-tunnel.invalid"
TUNNEL_AUTHORITY = f"{TUNNEL_HOST}:9443"
HTTP_BODY = b"signed=one%2Ftwo&signed=three"
TUNNEL_PAYLOAD = b"client-tunnel-payload\x00\xff"
TUNNEL_FIRST_BYTES = b"parent-first-bytes\x00\xfe"
TUNNEL_REPLY = b"parent-reply:" + TUNNEL_PAYLOAD

POLICY = """budget = 12000
[[permissions]]
action = "network:request"
resource = "parent-http.invalid/*"
effect = "allow"
condition = { agent = "alice" }
[[permissions]]
action = "network:request"
resource = "parent-tunnel.invalid/*"
effect = "allow"
condition = { agent = "alice", method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "localhost/*"
effect = "allow"
condition = { agent = "alice" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
"""


class Parent(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.accepts = 0
        self.requests = []
        self.errors = []
        super().__init__(("127.0.0.1", 0), ParentRequest)

    def get_request(self):
        connection = super().get_request()
        self.accepts += 1
        return connection


class ParentRequest(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            head = read_until(self.request, b"\r\n\r\n")
            first_line = head.split(b"\r\n", 1)[0]
            observation = {"head": head, "body": b""}
            self.server.requests.append(observation)
            if first_line == f"POST http://{HTTP_HOST}:18080/signed?x=one&x=two%2Fthree HTTP/1.1".encode():
                assert f"Host: {HTTP_HOST}:18080\r\n".encode().lower() in head.lower()
                assert b"content-length: 29\r\n" in head.lower(), head
                observation["body"] = read_exact(self.request, len(HTTP_BODY))
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nparent-http-ok"
                )
            elif first_line == f"CONNECT {TUNNEL_AUTHORITY} HTTP/1.1".encode():
                assert f"Host: {TUNNEL_AUTHORITY}\r\n".encode().lower() in head.lower()
                # The status and initial tunnel bytes deliberately share one write.
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + TUNNEL_FIRST_BYTES)
                observation["body"] = read_exact(self.request, len(TUNNEL_PAYLOAD))
                self.request.sendall(TUNNEL_REPLY)
            elif first_line.startswith(b"GET http://localhost:") and first_line.endswith(b"/failure HTTP/1.1"):
                self.request.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 18\r\nConnection: close\r\n\r\nparent-http-failed"
                )
            elif first_line.startswith(b"CONNECT localhost:") and first_line.endswith(b" HTTP/1.1"):
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                raise AssertionError(f"Unexpected parent request: {first_line!r}")
        except Exception as error:
            self.server.errors.append(error)


@contextmanager
def configured_parent():
    parent = Parent()
    thread = threading.Thread(target=parent.serve_forever)
    thread.start()
    try:
        yield parent
    finally:
        parent.shutdown()
        parent.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert parent.errors == [], parent.errors


def connect(path, authority):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(5)
    try:
        stream.connect(path)
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        return stream, read_until(stream, b"\r\n\r\n")
    except Exception:
        stream.close()
        raise


def test_configured_parent_http_connect_failure_and_direct_control(proxy_backend, tmp_path):
    """Logical authorization survives parent routing and failures never dial the origin."""
    directory = tmp_path / proxy_backend
    with origin_server() as direct_origin, configured_parent() as parent:
        direct_port = direct_origin.server_address[1]
        direct_authority = f"localhost:{direct_port}"
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        # Establish that the canary accepts a direct route before the parent
        # refusal and denial cases use it as a forbidden-egress observer.
        with launch_proxy(proxy_backend, directory / "direct", POLICY, native_policy=True) as proxy:
            status, _, body = request(proxy.paths["alice"], f"http://{direct_authority}/direct")
            assert (status, body) == (200, b"hello")
            assert direct_origin.accepts == 1
            assert direct_origin.requests == [{"method": "GET", "target": "/direct"}]
            assert parent.accepts == 0

        with launch_proxy(
            proxy_backend,
            directory / "parent",
            POLICY,
            parent_proxy=parent_url,
            ignore_hosts=[TUNNEL_AUTHORITY, direct_authority],
            eager_connect=True,
            native_policy=True,
        ) as proxy:
            assert proxy.policy_process is None
            http_url = f"http://{HTTP_HOST}:18080/signed?x=one&x=two%2Fthree"
            status, _, body = request(proxy.paths["alice"], http_url, method="POST", body=HTTP_BODY)
            assert (status, body) == (200, b"parent-http-ok")
            assert direct_origin.accepts == 1
            assert parent.requests[0]["body"] == HTTP_BODY

            stream, head = connect(proxy.paths["alice"], TUNNEL_AUTHORITY)
            with stream:
                assert head.startswith(b"HTTP/1.1 200"), head
                stream.sendall(TUNNEL_PAYLOAD)
                assert read_exact(stream, len(TUNNEL_FIRST_BYTES + TUNNEL_REPLY)) == (TUNNEL_FIRST_BYTES + TUNNEL_REPLY)
            assert parent.requests[1]["body"] == TUNNEL_PAYLOAD
            assert direct_origin.accepts == 1

            failure_url = f"http://{direct_authority}/failure"
            status, _, body = request(proxy.paths["alice"], failure_url)
            assert (status, body) == (502, b"parent-http-failed")
            assert direct_origin.accepts == 1

            stream, head = connect(proxy.paths["alice"], direct_authority)
            with stream:
                if proxy_backend == "rust":
                    assert head.startswith(b"HTTP/1.1 502"), head
                else:
                    # The Python comparator sends its own 200 before it opens
                    # the parent; its later refusal closes that admitted tunnel.
                    assert head.startswith(b"HTTP/1.1 200"), head
                    stream.sendall(b"trigger-parent-connect")
                    assert TUNNEL_FIRST_BYTES not in read_all(stream)
            assert direct_origin.accepts == 1

            before = parent.accepts
            egress_before = len(proxy.events("proxy.egress"))
            for path, target, method in (
                (proxy.paths["alice"], parent_url + "/physical-denied", "GET"),
                (proxy.paths["bob"], http_url, "GET"),
                (proxy.paths["bob"], TUNNEL_AUTHORITY, "CONNECT"),
            ):
                status, headers, _ = request(path, target, method=method)
                assert status == 403
                assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
                assert parent.accepts == before and direct_origin.accepts == 1
                assert len(proxy.events("proxy.egress")) == egress_before

            assert parent.accepts == 4
            assert egress_before == 4
            if proxy_backend == "rust":
                assert [(row["host"], row["route"]) for row in proxy.events("proxy.egress")] == [
                    (HTTP_HOST, "parent"),
                    (TUNNEL_HOST, "parent"),
                    ("localhost", "parent"),
                    ("localhost", "parent"),
                ]
            else:
                assert [(row["host"], row["port"]) for row in proxy.events("proxy.egress")] == [
                    parent.server_address
                ] * 4
            assert len(parent.requests) == 4
            assert [row["head"].split(b"\r\n", 1)[0] for row in parent.requests] == [
                f"POST {http_url} HTTP/1.1".encode(),
                f"CONNECT {TUNNEL_AUTHORITY} HTTP/1.1".encode(),
                f"GET {failure_url} HTTP/1.1".encode(),
                f"CONNECT {direct_authority} HTTP/1.1".encode(),
            ]
            guard = [
                row
                for row in read_events(directory / "parent" / "audit.jsonl")
                if row["event"] == "security.network_guard"
            ]
            assert [(row["agent"], row["host"], row["details"]["method"], row["decision"]) for row in guard] == [
                ("alice", TUNNEL_HOST, "CONNECT", "allow"),
                ("alice", "localhost", "CONNECT", "allow"),
                ("alice", "127.0.0.1", "GET", "deny"),
                ("bob", HTTP_HOST, "GET", "deny"),
                ("bob", TUNNEL_HOST, "CONNECT", "deny"),
            ]
            assert direct_origin.requests == [{"method": "GET", "target": "/direct"}]
            assert proxy.process.poll() is None
