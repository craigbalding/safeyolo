"""HTTP/2 through trusted UDS and TLS, using an independent Python h2 peer."""

import concurrent.futures
import http.client
import ipaddress
import socket
import socketserver
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import h2.config
import h2.connection
import h2.events
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy

POLICY = '''budget = 12000
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "allow"
condition = { agent = "alice" }
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "allow"
condition = { agent = "bob", method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "deny"
condition = { agent = "bob" }
'''


def origin_certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                   .sign(key, hashes.SHA256()))
    pem = directory / "origin.pem"
    pem.touch(mode=0o600)
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()) + certificate.public_bytes(serialization.Encoding.PEM))
    public = directory / "origin-ca.pem"
    public.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return pem, public


class Origin(socketserver.ThreadingTCPServer):
    def __init__(self, pem, protocols):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(pem)
        self.context.set_alpn_protocols(protocols)
        self.protocols = protocols
        self.requests = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), OriginHandler)

    @property
    def authority(self):
        return f"127.0.0.1:{self.server_address[1]}"


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as stream:
                stream.settimeout(5)
                if stream.selected_alpn_protocol() == "h2":
                    connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
                        client_side=False, header_encoding="utf-8"))
                    connection.initiate_connection()
                    stream.sendall(connection.data_to_send())
                    requests = {}
                    while data := stream.recv(65536):
                        for event in connection.receive_data(data):
                            if isinstance(event, h2.events.RequestReceived):
                                record = dict(event.headers)
                                record["body"] = bytearray()
                                requests[event.stream_id] = record
                                with self.server.lock:
                                    self.server.requests.append(record)
                            elif isinstance(event, h2.events.StreamEnded):
                                connection.send_headers(event.stream_id, [(":status", "200"), ("content-length", "5")])
                                connection.send_data(event.stream_id, b"hello", end_stream=True)
                            elif isinstance(event, h2.events.DataReceived):
                                requests[event.stream_id]["body"].extend(event.data)
                                connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        if output := connection.data_to_send():
                            stream.sendall(output)
                elif "http/1.1" in self.server.protocols:
                    head = b""
                    while not head.endswith(b"\r\n\r\n"):
                        byte = stream.recv(1)
                        if not byte:
                            return
                        head += byte
                    with self.server.lock:
                        self.server.requests.append({"head": head.decode("latin1")})
                    stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        except (ConnectionError, ssl.SSLError, TimeoutError):
            # Closing the proxy owns cancellation of its origin TLS sockets.
            # Assertions check application requests and exact response bodies.
            return


@contextmanager
def origin_server(pem, protocols=("h2",)):
    server = Origin(pem, list(protocols))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def tls_tunnel(path, authority, ca, offers=("h2", "http/1.1")):
    raw = socket.socket(socket.AF_UNIX)
    raw.settimeout(5)
    try:
        raw.connect(path)
        raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        response = http.client.HTTPResponse(raw)
        response.begin()
        assert response.status == 200
        response.close()
        context = ssl.create_default_context(cafile=ca)
        context.set_alpn_protocols(list(offers))
        return context.wrap_socket(raw, server_hostname="127.0.0.1")
    except BaseException:
        raw.close()
        raise


def h2_requests(stream, requests, *, allow_rejection=False):
    connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
        client_side=True, header_encoding="utf-8", validate_outbound_headers=False,
        normalize_outbound_headers=False))
    connection.initiate_connection()
    pending = set()
    results = {}
    for index, headers in enumerate(requests):
        identifier = index * 2 + 1
        pending.add(identifier)
        results[identifier] = {"headers": {}, "body": b""}
        connection.send_headers(identifier, headers, end_stream=True)
    stream.sendall(connection.data_to_send())
    while pending:
        data = stream.recv(65536)
        if not data and allow_rejection:
            for identifier in pending:
                results[identifier]["closed"] = True
            break
        assert data, (pending, results)
        for event in connection.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                results[event.stream_id]["headers"] = dict(event.headers)
            elif isinstance(event, h2.events.DataReceived):
                results[event.stream_id]["body"] += event.data
                connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                pending.remove(event.stream_id)
            elif isinstance(event, h2.events.StreamReset):
                assert allow_rejection, event
                results[event.stream_id]["reset"] = int(event.error_code)
                pending.discard(event.stream_id)
            elif isinstance(event, h2.events.ConnectionTerminated):
                assert allow_rejection, event
                for identifier in pending:
                    results[identifier]["goaway"] = int(event.error_code)
                pending.clear()
        if output := connection.data_to_send():
            stream.sendall(output)
    return list(results.values())


def headers(authority, path, extra=()):
    return [(":method", "GET"), (":scheme", "https"), (":authority", authority), (":path", path), *extra]


def test_http2_upload_preserves_binary_body_across_flow_control(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    payload = bytes(range(256)) * 1025
    with origin_server(pem) as origin, launch_proxy(proxy_backend, directory, POLICY, tls=True, upstream_ca=public) as proxy:
        with tls_tunnel(proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem") as stream:
            connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
                client_side=True, header_encoding="utf-8"))
            connection.initiate_connection()
            connection.send_headers(1, [
                (":method", "POST"), (":scheme", "https"), (":authority", origin.authority),
                (":path", "/upload?part=one&part=two%2Fthree"), ("content-type", "application/octet-stream"),
            ])
            offset = 0
            status = None
            response = bytearray()
            ended = False
            while not ended:
                while offset < len(payload):
                    count = min(connection.local_flow_control_window(1), connection.max_outbound_frame_size,
                                len(payload) - offset)
                    if not count:
                        break
                    connection.send_data(1, payload[offset:offset + count], end_stream=offset + count == len(payload))
                    offset += count
                stream.sendall(connection.data_to_send())
                data = stream.recv(65536)
                assert data, "HTTP/2 upload ended before its response"
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = dict(event.headers)[":status"]
                    elif isinstance(event, h2.events.DataReceived):
                        response.extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        ended = True
                    elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                        pytest.fail(f"HTTP/2 upload failed: {event}")
            assert offset == len(payload)
            assert status == "200"
            assert response == b"hello"
        assert len(origin.requests) == 1
        assert origin.requests[0]["body"] == payload
        assert origin.requests[0][":path"] == "/upload?part=one&part=two%2Fthree"


def test_concurrent_http2_streams_keep_agent_and_request_identity(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, launch_proxy(proxy_backend, directory, POLICY, tls=True, upstream_ca=public) as proxy:
        def run(agent):
            with tls_tunnel(proxy.paths[agent], origin.authority, directory / "ca/mitmproxy-ca-cert.pem") as stream:
                assert stream.selected_alpn_protocol() == "h2"
                return h2_requests(stream, [headers(origin.authority, f"/signed?part=one&part=two%2Fthree&n={index}", [
                    ("x-safeyolo-agent", "bob" if agent == "alice" else "alice"),
                    ("x-safeyolo-request-id", "req-" + "f" * 32),
                ]) for index in range(12)])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            alice, bob = list(pool.map(run, ["alice", "bob"]))
        assert [row["headers"][":status"] for row in alice] == ["200"] * 12
        assert [row["body"] for row in alice] == [b"hello"] * 12
        assert [row["headers"][":status"] for row in bob] == ["403"] * 12
        identifiers = {row["headers"]["x-safeyolo-request-id"] for row in alice + bob}
        assert len(identifiers) == 24
        assert "req-" + "f" * 32 not in identifiers
        assert sorted(row[":path"] for row in origin.requests) == sorted(
            f"/signed?part=one&part=two%2Fthree&n={index}" for index in range(12))
        events = {row["request_id"]: row for row in proxy.events("proxy.request")}
        for agent, responses in [("alice", alice), ("bob", bob)]:
            assert len({events[row["headers"]["x-safeyolo-request-id"]]["connection_id"] for row in responses}) == 1
            for row in responses:
                assert events[row["headers"]["x-safeyolo-request-id"]]["agent"] == agent


@pytest.mark.parametrize("protocols", [("h2",), ("http/1.1",)])
def test_https_protocol_negotiation_delivers_allowed_request(proxy_backend, tmp_path, protocols):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    with origin_server(pem, protocols) as origin, launch_proxy(proxy_backend, directory, POLICY, tls=True, upstream_ca=public) as proxy:
        with tls_tunnel(proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem") as stream:
            if stream.selected_alpn_protocol() == "h2":
                response = h2_requests(stream, [headers(origin.authority, "/hello")])[0]
                assert response["headers"][":status"] == "200"
                assert response["body"] == b"hello"
            else:
                stream.sendall(f"GET /hello HTTP/1.1\r\nHost: {origin.authority}\r\nConnection: close\r\n\r\n".encode())
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200
                assert response.read() == b"hello"
                response.close()
        assert len(origin.requests) == 1


@pytest.mark.parametrize("mutation", ["authority_host", "authority_port", "host_header", "duplicate_host"])
def test_http2_inner_authorities_cannot_change_destination(proxy_backend, tmp_path, request, mutation):
    if proxy_backend == "python" and mutation.startswith("authority_"):
        request.node.add_marker(pytest.mark.xfail(
            strict=True, reason="Existing H2 tunnel overwrites policy host/port while forwarding changed :authority"))
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, origin_server(pem) as other:
        with launch_proxy(proxy_backend, directory, POLICY, tls=True, upstream_ca=public) as proxy:
            authority = origin.authority
            extra = []
            if mutation == "authority_host":
                authority = f"localhost:{origin.server_address[1]}"
            elif mutation == "authority_port":
                authority = other.authority
            elif mutation == "host_header":
                extra = [("host", "forbidden.invalid")]
            else:
                extra = [("host", authority), ("host", authority)]
            with tls_tunnel(proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem") as stream:
                response = h2_requests(stream, [headers(authority, "/forbidden", extra)], allow_rejection=True)[0]
            # The old stack sends GOAWAY on Host disagreement; native rejects
            # the request with 400. Preserve that visible difference while
            # checking the shared no-application-request boundary.
            if proxy_backend == "rust":
                assert response["headers"][":status"] == "400", response
            else:
                assert response.get("goaway") == 1 or response.get("reset") == 1, response
            assert origin.requests == []
            assert other.requests == []
