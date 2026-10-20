"""Configured parent routing at the native proxy's real transport boundary."""

import http.client
import socket
import socketserver
import ssl
import threading
from contextlib import contextmanager

import pytest

from safeyolo.rust_proxy import _ensure_signing_ca
from tests.proxy_contracts import test_authority_consistency as authority_fixture
from tests.proxy_contracts.harness import launch_proxy, read_events, request
from tests.proxy_contracts.scenarios import origin_server, wait_for_reserved_audit
from tests.proxy_contracts.test_http2_contract import origin_certificate
from tests.proxy_contracts.test_tunnel_contract import read_all, read_exact, read_until

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

MIXED_POLICY = """budget = 12000
[[permissions]]
action = "network:request"
resource = "localhost/*"
effect = "allow"
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
"""


class Parent(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, tunnel_authority=None):
        self.accepts = 0
        self.requests = []
        self.errors = []
        self.tunnel_authority = tunnel_authority
        self.refuse_connect = False
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
            elif first_line in {
                f"CONNECT {TUNNEL_AUTHORITY} HTTP/1.1".encode(),
                f"CONNECT {self.server.tunnel_authority} HTTP/1.1".encode(),
            }:
                authority = first_line.split(b" ")[1]
                assert b"host: " + authority.lower() + b"\r\n" in head.lower()
                if self.server.refuse_connect:
                    self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                # The status and initial tunnel bytes deliberately share one write.
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + TUNNEL_FIRST_BYTES)
                observation["body"] = read_exact(self.request, len(TUNNEL_PAYLOAD))
                self.request.sendall(TUNNEL_REPLY)
            elif first_line.startswith(b"GET http://localhost:") and first_line.endswith(b"/route HTTP/1.1"):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nparent-http-ok"
                )
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
def configured_parent(tunnel_authority=None):
    parent = Parent(tunnel_authority)
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


def connect(path, authority, *, headers=None):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(5)
    try:
        stream.connect(path)
        extra = "".join(f"{name}: {value}\r\n" for name, value in (headers or {}).items())
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n".encode())
        return stream, read_until(stream, b"\r\n\r\n")
    except Exception:
        stream.close()
        raise


@pytest.mark.parametrize("hosts", [None, [HTTP_HOST, TUNNEL_HOST, "localhost"]], ids=["agents-only", "both-filters"])
def test_configured_parent_http_connect_failure_and_direct_control(proxy_backend, tmp_path, hosts):
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
            parent_proxy_agents=["alice"],
            parent_proxy_hosts=hosts,
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
            egress_before = len(proxy.events("traffic.egress"))
            audit_path = directory / "parent" / "audit.jsonl"
            for path, target, method in (
                (proxy.paths["alice"], parent_url + "/physical-denied", "GET"),
                (proxy.paths["bob"], http_url, "GET"),
                (proxy.paths["bob"], TUNNEL_AUTHORITY, "CONNECT"),
            ):
                before_audit = len(read_events(audit_path))
                status, headers, _ = request(path, target, method=method)
                assert status == 403
                response_headers = {name.lower(): value for name, value in headers.items()}
                assert response_headers["x-blocked-by"] == "network-guard"
                assert parent.accepts == before and direct_origin.accepts == 1
                assert len(proxy.events("traffic.egress")) == egress_before
                wait_for_reserved_audit(
                    audit_path, before_audit, "security.network_guard",
                    request_id=response_headers["x-safeyolo-request-id"],
                )

            assert parent.accepts == 4
            assert egress_before == 4
            if proxy_backend == "rust":
                assert [(row["host"], row["details"]["route"]) for row in proxy.events("traffic.egress")] == [
                    (HTTP_HOST, "parent"),
                    (TUNNEL_HOST, "parent"),
                    ("localhost", "parent"),
                    ("localhost", "parent"),
                ]
            else:
                assert [(row["host"], row["details"]["port"]) for row in proxy.events("traffic.egress")] == [
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
                for row in read_events(audit_path)
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


@pytest.mark.parametrize("hosts", [None, [], ["LOCALHOST."]], ids=["agents-only", "hosts-empty", "both-filters"])
def test_selected_parent_mixed_agents_http_connect_and_spoofed_headers(proxy_backend, tmp_path, hosts):
    """Listener identity selects the shared parent or direct origin for one destination."""
    with origin_server(capture_heads=True) as origin:
        authority = f"localhost:{origin.server_address[1]}"
        url = f"http://{authority}/route"
        with configured_parent(authority) as parent, launch_proxy(
            proxy_backend, tmp_path / "mixed", MIXED_POLICY,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
            parent_proxy_agents=["alice"], ignore_hosts=[authority], native_product=True,
            parent_proxy_hosts=hosts,
        ) as proxy:
            for spoof in (False, True):
                for agent, other in (("alice", "bob"), ("bob", "alice")):
                    headers = {"X-SafeYolo-Agent": other, "X-Agent-Id": other} if spoof else {}
                    status, _, body = request(proxy.paths[agent], url, headers=headers)
                    assert (status, body) == (200, b"parent-http-ok" if agent == "alice" else b"hello")
                    stream, head = connect(proxy.paths[agent], authority, headers=headers)
                    with stream:
                        assert head.startswith(b"HTTP/1.1 200"), head
                        if agent == "alice":
                            stream.sendall(TUNNEL_PAYLOAD)
                            assert read_exact(stream, len(TUNNEL_FIRST_BYTES + TUNNEL_REPLY)) == (
                                TUNNEL_FIRST_BYTES + TUNNEL_REPLY
                            )
                        else:
                            stream.sendall(
                                f"GET /tunnel HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
                            )
                            reply = read_all(stream)
                            assert reply.startswith(b"HTTP/1.1 200") and reply.endswith(b"hello"), reply
                    assert parent.accepts == 2 * (spoof + 1)
                    assert origin.accepts == (2 * (spoof + 1) if agent == "bob" else 2 * spoof)

            assert [row["method"] for row in origin.requests] == ["GET"] * 4
            assert [row["target"] for row in origin.requests] == ["/route", "/tunnel"] * 2
            assert all(head.startswith(b"GET /") for head in origin.request_heads)
            assert [(row["agent"], row["details"]["route"]) for row in proxy.events("traffic.egress")] == [
                ("alice", "parent"), ("alice", "parent"), ("bob", "direct"), ("bob", "direct"),
            ] * 2

            # The origin is known to accept this exact destination. A selected
            # parent's refusal must not retry that direct route.
            parent.refuse_connect = True
            stream, head = connect(proxy.paths["alice"], authority)
            with stream:
                assert head.startswith(b"HTTP/1.1 502"), head
            assert parent.accepts == 5 and origin.accepts == 4

            for agent in ("alice", "bob"):
                for method, target in (("GET", "http://denied.invalid/"), ("CONNECT", "denied.invalid:443")):
                    status, headers, _ = request(proxy.paths[agent], target, method=method)
                    assert status == 403
                    assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
                    assert parent.accepts == 5 and origin.accepts == 4


@pytest.mark.parametrize("agents", [None, []], ids=["omitted", "empty"])
@pytest.mark.parametrize("hosts", [None, []], ids=["hosts-omitted", "hosts-empty"])
def test_parent_agent_filter_default_keeps_global_parent(proxy_backend, tmp_path, agents, hosts):
    """Removing the last selected name restores parent routing for every agent."""
    with origin_server() as origin:
        authority = f"localhost:{origin.server_address[1]}"
        with configured_parent(authority) as parent, launch_proxy(
            proxy_backend, tmp_path / "unfiltered", MIXED_POLICY,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
            parent_proxy_agents=agents, ignore_hosts=[authority], native_product=True,
            parent_proxy_hosts=hosts,
        ) as proxy:
            for agent in ("alice", "bob"):
                status, _, body = request(proxy.paths[agent], f"http://{authority}/route")
                assert (status, body) == (200, b"parent-http-ok")
                stream, head = connect(proxy.paths[agent], authority)
                with stream:
                    assert head.startswith(b"HTTP/1.1 200"), head
                    stream.sendall(TUNNEL_PAYLOAD)
                    assert read_exact(stream, len(TUNNEL_FIRST_BYTES + TUNNEL_REPLY)) == (
                        TUNNEL_FIRST_BYTES + TUNNEL_REPLY
                    )
            assert parent.accepts == 4 and origin.accepts == 0


@pytest.mark.parametrize("parent_configured", [False, True], ids=["no-parent", "unavailable-parent"])
@pytest.mark.parametrize("hosts", [None, ["localhost"]], ids=["agents-only", "both-filters"])
def test_selected_parent_connection_failure_has_no_direct_fallback(proxy_backend, tmp_path, parent_configured, hosts):
    """A configured but unavailable parent fails only selected routes; no parent ignores the filter."""
    with origin_server() as origin:
        # Darwin times out on a bound, non-listening socket. Close the chosen
        # port before dialing to exercise connection refusal on both platforms.
        with socket.socket() as unavailable_parent:
            unavailable_parent.bind(("127.0.0.1", 0))
            parent_url = f"http://127.0.0.1:{unavailable_parent.getsockname()[1]}" if parent_configured else None
        authority = f"localhost:{origin.server_address[1]}"
        with launch_proxy(
            proxy_backend, tmp_path / "unavailable", MIXED_POLICY,
            parent_proxy=parent_url, parent_proxy_agents=["alice"],
            ignore_hosts=[authority], native_product=True,
            parent_proxy_hosts=hosts,
        ) as proxy:
            direct_accepts = 0
            for agent in ("alice", "bob"):
                failed = parent_configured and agent == "alice"
                status, _, body = request(proxy.paths[agent], f"http://{authority}/route")
                assert status == (502 if failed else 200)
                if not failed:
                    assert body == b"hello"
                stream, head = connect(proxy.paths[agent], authority)
                with stream:
                    assert head.startswith(b"HTTP/1.1 502" if failed else b"HTTP/1.1 200"), head
                    if not failed:
                        stream.sendall(
                            f"GET /tunnel HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
                        )
                        assert read_all(stream).endswith(b"hello")
                if not failed:
                    direct_accepts += 2
                assert origin.accepts == direct_accepts
            assert [(row["agent"], row["details"]["route"]) for row in proxy.events("traffic.egress")] == [
                ("alice", "parent" if parent_configured else "direct"),
                ("alice", "parent" if parent_configured else "direct"),
                ("bob", "direct"), ("bob", "direct"),
            ]


HOST_POLICY = '''budget = 12000
[hosts."denied.invalid"]
egress = "deny"
[hosts."*"]
egress = "allow"
'''


def https_request(proxy, agent, host, port, *, inner_host=None, outer_host=None):
    """Complete verified TLS and HTTP inside an admitted CONNECT."""
    ca = proxy.readiness_file.parent / "ca/mitmproxy-ca-cert.pem"
    status, stream = authority_fixture._connect(
        proxy.paths[agent], f"{host}:{port}".encode(), host, ca,
        outer_host=outer_host,
    )
    assert status == 200
    with stream:
        client = http.client.HTTPConnection(host, timeout=5)
        client.sock = stream
        try:
            client.request("GET", "/route", headers={"Host": inner_host or f"{host}:{port}"})
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()


@pytest.mark.parametrize("agents", [None, [], ["alice"]], ids=["hosts-only", "empty-agents", "both-filters"])
def test_destination_filter_mixed_http_and_verified_https(proxy_backend, tmp_path, agents):
    """Two named parent destinations and direct traffic keep separate real connections."""
    directory = tmp_path / "mixed-hosts"
    directory.mkdir()
    _ensure_signing_ca(directory / "proxy/ca")
    pem, public = origin_certificate(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem)
    with authority_fixture._peers(directory / "peers") as (parent, peers, trust), \
         origin_server(capture_heads=True) as direct_http, \
         authority_fixture._server(authority_fixture.Origin("direct-tls", tls_context=context)) as direct_tls:
        trust.write_bytes(trust.read_bytes() + public.read_bytes())
        with launch_proxy(
            proxy_backend, directory / "proxy", HOST_POLICY, native_product=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
            parent_proxy_agents=agents,
            parent_proxy_hosts=[authority_fixture.ALLOWED, authority_fixture.FORBIDDEN,
                                "denied.invalid", "_safeyolo.proxy.internal"],
            tls=True, upstream_ca=trust,
        ) as proxy:
            expected_events = []
            for agent in ("alice", "bob") if not agents else ("alice",):
                for host, http_origin, tls_origin in (
                    (authority_fixture.ALLOWED, peers[0], peers[2]),
                    (authority_fixture.FORBIDDEN, peers[1], peers[3]),
                ):
                    before = (parent.accepts, http_origin.accepts, tls_origin.accepts)
                    status, _, body = request(proxy.paths[agent], f"http://{host}/route")
                    assert (status, body) == (200, http_origin.name.encode())
                    assert (parent.accepts, http_origin.accepts, tls_origin.accepts) == (
                        before[0] + 1, before[1] + 1, before[2],
                    )
                    assert https_request(proxy, agent, host, 443) == (200, tls_origin.name.encode())
                    assert (parent.accepts, http_origin.accepts, tls_origin.accepts) == (
                        before[0] + 2, before[1] + 1, before[2] + 1,
                    )
                    expected_events.extend([(agent, host, "parent")] * 2)

            parent_before = parent.accepts
            for agent in ("alice", "bob"):
                spoof = {
                    "Host": authority_fixture.ALLOWED, "X-SafeYolo-Agent": "alice",
                    "X-Agent-Id": "alice", "X-Forwarded-Host": authority_fixture.ALLOWED,
                    "X-Original-URL": f"http://{authority_fixture.ALLOWED}/route",
                }
                status, _, body = request(
                    proxy.paths[agent], f"http://localhost:{direct_http.server_address[1]}/route",
                    headers=spoof,
                )
                assert (status, body) == (200, b"hello")
                assert https_request(
                    proxy, agent, "localhost", direct_tls.server_address[1],
                    outer_host=b"allowed.invalid:443",
                ) == (200, b"direct-tls")
                assert parent.accepts == parent_before
                expected_events.extend([(agent, "localhost", "direct")] * 2)
            assert direct_http.accepts == direct_tls.accepts == 2
            assert all(head.startswith(b"GET /route HTTP/1.1\r\n") for head in direct_http.request_heads)
            assert [(row["agent"], row["host"], row["details"]["route"]) for row in proxy.events("traffic.egress")] == expected_events
            assert [row["kind"] for row in parent.requests] == ["http", "connect"] * (4 if not agents else 2)
            assert all(row["target"].startswith(b"http://") for row in parent.requests if row["kind"] == "http")

            # Denied and reserved targets stop before contacting either route.
            before = (parent.accepts, direct_http.accepts, direct_tls.accepts)
            for agent in ("alice", "bob"):
                for host in ("denied.invalid", "_safeyolo.proxy.internal"):
                    for method, target in (("GET", f"http://{host}/"), ("CONNECT", f"{host}:443")):
                        status, _, _ = request(proxy.paths[agent], target, method=method)
                        assert status == (503 if host == "_safeyolo.proxy.internal" and method == "GET" else 403)
                        assert (parent.accepts, direct_http.accepts, direct_tls.accepts) == before
            assert len(proxy.events("traffic.egress")) == len(expected_events)


def test_exact_destination_boundaries_and_connect_authority(proxy_backend, tmp_path):
    """Case and root dots match; other authorities cannot select or reuse the parent."""
    directory = tmp_path / "boundaries"
    _ensure_signing_ca(directory / "proxy/ca")
    with authority_fixture._peers(directory / "peers") as (parent, peers, trust):
        parent.http[authority_fixture.ALLOWED + "."] = peers[0]
        parent.tls[authority_fixture.ALLOWED + "."] = peers[2]
        parent.http[authority_fixture.IDN_WIRE] = peers[0]
        # The parent hostname must not participate in logical destination selection.
        with launch_proxy(
            proxy_backend, directory / "proxy", HOST_POLICY, native_product=True,
            parent_proxy=f"http://localhost:{parent.server_address[1]}",
            parent_proxy_agents=["alice"], parent_proxy_hosts=["ALLOWED.INVALID.", authority_fixture.IDN_NAME],
            tls=True, upstream_ca=trust,
        ) as proxy:
            for host in ("allowed.invalid", "ALLOWED.INVALID", "allowed.invalid."):
                status, _, body = request(proxy.paths["alice"], f"http://{host}:8080/route")
                assert (status, body) == (200, b"allowed-http")
            assert parent.accepts == peers[0].accepts == 3
            status, _, body = request(proxy.paths["alice"], f"http://{authority_fixture.IDN_WIRE}/route")
            assert (status, body) == (200, b"allowed-http")
            assert parent.accepts == peers[0].accepts == 4
            for host in (
                "evil-allowed.invalid", "allowed.invalid.attacker.invalid", "sub.allowed.invalid",
                "allowecl.invalid", authority_fixture.FORBIDDEN,
            ):
                for method, target in (("GET", f"http://{host}/route"), ("CONNECT", f"{host}:443")):
                    status, _, _ = request(proxy.paths["alice"], target, method=method,
                                           headers={"Host": "allowed.invalid", "X-Forwarded-Host": "allowed.invalid"})
                    assert status == 502
                    assert parent.accepts == 4
            # A different trusted agent cannot select a listed destination.
            status, _, _ = request(proxy.paths["bob"], "http://allowed.invalid/route",
                                   headers={"X-SafeYolo-Agent": "alice", "X-Agent-Id": "alice"})
            assert status == 502 and parent.accepts == 4

            # CONNECT's admitted target wins over the conflicting outer Host.
            assert https_request(proxy, "alice", "allowed.invalid", 443,
                                 outer_host=b"forbidden.invalid:443") == (200, b"allowed-tls")
            assert parent.accepts == 5 and peers[2].accepts == 1
            for inner_host in ("forbidden.invalid:443", "allowed.invalid:444", "allowed.invalid.:443"):
                before = (parent.accepts, peers[2].accepts, peers[3].accepts)
                status, _ = https_request(proxy, "alice", "allowed.invalid", 443, inner_host=inner_host)
                assert status == 400
                assert (parent.accepts, peers[2].accepts, peers[3].accepts) == (before[0] + 1, before[1] + 1, before[2])
            assert len(peers[2].requests) == 1 and peers[3].requests == []


def test_selected_parent_tls_failure_and_unmatched_direct_control(proxy_backend, tmp_path):
    """A TLS failure at the selected parent cannot dial a working origin."""
    with origin_server() as origin, origin_server() as plaintext_parent, launch_proxy(
        proxy_backend, tmp_path / "bad-parent-tls", HOST_POLICY, native_product=True,
        parent_proxy=f"https://localhost:{plaintext_parent.server_address[1]}",
        parent_proxy_hosts=["localhost"],
        ignore_hosts=[f"localhost:{origin.server_address[1]}", f"127.0.0.1:{origin.server_address[1]}"],
    ) as proxy:
        for method, target in (("GET", f"http://localhost:{origin.server_address[1]}/route"),
                               ("CONNECT", f"localhost:{origin.server_address[1]}")):
            status, _, _ = request(proxy.paths["alice"], target, method=method)
            assert status == 502
            assert origin.accepts == 0
        assert plaintext_parent.accepts == 2
        status, _, body = request(proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/route")
        assert (status, body) == (200, b"hello")
        assert origin.accepts == 1 and plaintext_parent.accepts == 2
        assert [(row["host"], row["details"]["route"]) for row in proxy.events("traffic.egress")] == [
            ("localhost", "parent"), ("localhost", "parent"), ("127.0.0.1", "direct"),
        ]
