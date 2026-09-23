"""HTTP/2 through trusted UDS and TLS, using an independent Python h2 peer."""

import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import socket
import socketserver
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import h2.config
import h2.connection
import h2.errors
import h2.events
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy, read_events
from tests.proxy_migration.run import proxy_identity, runtime_resources

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


class H2CancellationOrigin(socketserver.ThreadingTCPServer):
    """A TLS HTTP/2 peer that holds one response until another is reset."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, pem):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(pem)
        self.context.set_alpn_protocols(["h2"])
        self.requests = []
        self.alpn = []
        self.cancel_started = threading.Event()
        self.reset_seen = threading.Event()
        self.keep_completed = threading.Event()
        self.handler_finished = threading.Event()
        self.handler_errors = []
        self.active_handlers = 0
        self.cancel_reset_code = None
        self.cancel_response_bytes = 0
        self.keep_response_bytes = 0
        self.next_connection_id = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), H2CancellationOriginHandler)

    @property
    def authority(self):
        return f"127.0.0.1:{self.server_address[1]}"


class H2CancellationOriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        with server.lock:
            if server.active_handlers == 0:
                server.handler_finished.clear()
            server.active_handlers += 1
            server.next_connection_id += 1
            connection_id = server.next_connection_id
        try:
            with server.context.wrap_socket(self.request, server_side=True) as stream:
                stream.settimeout(5)
                with server.lock:
                    server.alpn.append(stream.selected_alpn_protocol())
                connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
                    client_side=False, header_encoding="utf-8"))
                connection.initiate_connection()
                stream.sendall(connection.data_to_send())
                keep_stream_id = None
                while data := stream.recv(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            headers = dict(event.headers)
                            record = {
                                "stream_id": event.stream_id,
                                "connection_id": connection_id,
                                ":method": headers.get(":method"),
                                ":path": headers.get(":path"),
                                "request_body_bytes": 0,
                            }
                            with server.lock:
                                server.requests.append(record)
                            if record[":path"] == "/h2-cancel":
                                connection.send_headers(event.stream_id, [(":status", "200")])
                                partial = b"cancel-partial"
                                connection.send_data(event.stream_id, partial)
                                with server.lock:
                                    server.cancel_response_bytes += len(partial)
                                server.cancel_started.set()
                            elif record[":path"] == "/h2-keep":
                                connection.send_headers(event.stream_id, [(":status", "200")])
                                keep_stream_id = event.stream_id
                        elif isinstance(event, h2.events.DataReceived):
                            for record in server.requests:
                                if (record["connection_id"] == connection_id
                                        and record["stream_id"] == event.stream_id):
                                    record["request_body_bytes"] += len(event.data)
                                    break
                            connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, h2.events.StreamReset):
                            if any(record["connection_id"] == connection_id and record[":path"] == "/h2-cancel"
                                   for record in server.requests):
                                server.cancel_reset_code = int(event.error_code)
                                server.reset_seen.set()
                    if output := connection.data_to_send():
                        stream.sendall(output)
                    if keep_stream_id is not None:
                        if not server.reset_seen.wait(timeout=5):
                            raise TimeoutError("cancel stream reset was not observed")
                        self._finish_keep(connection, keep_stream_id)
                        keep_stream_id = None
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError) as error:
            # A downstream reset and subsequent TLS close are expected. Preserve
            # any unexpected error for the test to report after the handler exits.
            if not server.reset_seen.is_set() and not isinstance(error, (ConnectionError, ssl.SSLError)):
                with server.lock:
                    server.handler_errors.append(repr(error))
        except Exception as error:  # pragma: no cover - asserted through state
            with server.lock:
                server.handler_errors.append(repr(error))
        finally:
            with server.lock:
                server.active_handlers -= 1
                if server.active_handlers == 0:
                    server.handler_finished.set()

    def _finish_keep(self, connection, stream_id):
        server = self.server
        if server.keep_completed.is_set():
            return
        body = b"keep-complete"
        connection.send_data(stream_id, body, end_stream=True)
        with server.lock:
            server.keep_response_bytes += len(body)
        server.keep_completed.set()


@contextmanager
def h2_cancellation_origin(pem):
    server = H2CancellationOrigin(pem)
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
            try:
                stream.sendall(output)
            except (BrokenPipeError, ConnectionResetError):
                if not allow_rejection:
                    raise
                # A rejecting peer can close before our SETTINGS ACK; keep
                # reading to record its GOAWAY or closed connection.
    return list(results.values())


@pytest.mark.parametrize("write_error", [BrokenPipeError, ConnectionResetError])
def test_h2_requests_rejection_closes_before_settings_ack(write_error):
    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    server.initiate_connection()
    settings = server.data_to_send()
    server.close_connection(error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR)
    goaway = server.data_to_send()

    class ClosedAckStream:
        def __init__(self):
            self.replies = iter((settings, goaway))
            self.writes = []

        def sendall(self, data):
            self.writes.append(data)
            if len(self.writes) == 2:
                assert data == b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
                raise write_error("peer closed after rejecting the request")

        def recv(self, size):
            return next(self.replies)

    request_headers = [headers("127.0.0.1:443", "/forbidden")]
    allowed = ClosedAckStream()
    response = h2_requests(allowed, request_headers, allow_rejection=True)[0]
    assert response["goaway"] == int(h2.errors.ErrorCodes.PROTOCOL_ERROR)
    assert len(allowed.writes) == 2

    strict = ClosedAckStream()
    with pytest.raises(write_error):
        h2_requests(strict, request_headers)
    assert len(strict.writes) == 2


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


def test_http2_cancelled_stream_does_not_cancel_independent_stream(proxy_backend, tmp_path, request):
    """Reset one response after partial data while a sibling stream completes."""
    if proxy_backend == "python":
        # Keep the comparator's known cancellation gap visible; --runxfail
        # must fail this test instead of hiding it behind an xfail.
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason="Python comparator does not satisfy the H2 cancellation/reset witness",
        ))
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    with h2_cancellation_origin(pem) as origin, launch_proxy(
        proxy_backend,
        directory,
        POLICY,
        tls=True,
        upstream_ca=public,
        native_policy=proxy_backend == "rust",
    ) as proxy:
        with tls_tunnel(
            proxy.paths["alice"],
            origin.authority,
            directory / "ca/mitmproxy-ca-cert.pem",
            offers=("h2",),
        ) as stream:
            client_alpn = stream.selected_alpn_protocol()
            assert client_alpn == "h2"
            connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
                client_side=True, header_encoding="utf-8"))
            connection.initiate_connection()
            connection.send_headers(1, headers(origin.authority, "/h2-cancel"), end_stream=True)
            connection.send_headers(3, headers(origin.authority, "/h2-keep"), end_stream=True)
            stream.sendall(connection.data_to_send())
            results = {
                1: {"path": "/h2-cancel", "status": None, "body": bytearray(), "reset_sent": False},
                3: {"path": "/h2-keep", "status": None, "body": bytearray(), "ended": False},
            }
            before_reset = runtime_resources(proxy)
            while not results[3]["ended"]:
                data = stream.recv(65536)
                assert data, results
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        results[event.stream_id]["status"] = dict(event.headers)[":status"]
                    elif isinstance(event, h2.events.DataReceived):
                        results[event.stream_id]["body"].extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        if event.stream_id == 1 and not results[1]["reset_sent"]:
                            assert bytes(event.data) == b"cancel-partial"
                            connection.reset_stream(1, error_code=h2.errors.ErrorCodes.CANCEL)
                            results[1]["reset_sent"] = True
                    elif isinstance(event, h2.events.StreamEnded):
                        assert event.stream_id == 3, event
                        results[3]["ended"] = True
                    elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                        pytest.fail(
                            f"unexpected H2 termination while sibling stream was live: {event}; "
                            f"origin_requests={origin.requests!r} reset_seen={origin.reset_seen.is_set()} "
                            f"keep_completed={origin.keep_completed.is_set()} origin_errors={origin.handler_errors!r}"
                        )
                if output := connection.data_to_send():
                    stream.sendall(output)
            after_reset = runtime_resources(proxy)
            assert results[1]["status"] == "200"
            assert bytes(results[1]["body"]) == b"cancel-partial"
            assert results[1]["reset_sent"] is True
            assert results[3]["status"] == "200"
            assert bytes(results[3]["body"]) == b"keep-complete"
        after_close = runtime_resources(proxy)
        assert origin.reset_seen.wait(timeout=5)
        assert origin.cancel_started.is_set()
        assert origin.keep_completed.is_set()
        assert origin.handler_finished.wait(timeout=5)
        assert origin.active_handlers == 0, {
            "active_handlers": origin.active_handlers,
            "alpn": origin.alpn,
            "requests": origin.requests,
            "handler_errors": origin.handler_errors,
        }
        assert origin.handler_errors == [], origin.handler_errors
        assert len(origin.alpn) == 2
        assert set(origin.alpn) == {"h2"}
        assert origin.cancel_reset_code == int(h2.errors.ErrorCodes.CANCEL)
        assert origin.cancel_response_bytes == len(b"cancel-partial")
        assert origin.keep_response_bytes == len(b"keep-complete")
        assert len(origin.requests) == 2
        assert {row[":path"] for row in origin.requests} == {"/h2-cancel", "/h2-keep"}
        assert {row[":method"] for row in origin.requests} == {"GET"}
        assert {row["request_body_bytes"] for row in origin.requests} == {0}
        assert len({row["connection_id"] for row in origin.requests}) == 2
        assert {row["stream_id"] for row in origin.requests} == {1}
        events = [event for event in read_events(proxy.event_log) if event.get("event") == "proxy.request"]
        assert len(events) == 3  # CONNECT plus the two independently proxied streams.
        inner_events = [event for event in events
                        if event.get("coverage") == "native_network_guard_circuits_and_test_context"]
        assert len(inner_events) == 2
        assert {int(event.get("status", 0)) for event in events} == {200}
        evidence = {
            "backend": proxy_backend,
            "alpn": {"client_to_origin": client_alpn, "origin": origin.alpn},
            "outcomes": {
                "cancel": {
                    "downstream_stream_id": 1,
                    "status": results[1]["status"],
                    "body_sha256": hashlib.sha256(results[1]["body"]).hexdigest(),
                    "reset_code": int(h2.errors.ErrorCodes.CANCEL),
                },
                "keep": {
                    "downstream_stream_id": 3,
                    "status": results[3]["status"],
                    "body_sha256": hashlib.sha256(results[3]["body"]).hexdigest(),
                    "completed": results[3]["ended"],
                },
            },
            "origin": {
                "requests": origin.requests,
                "cancel_reset_code": origin.cancel_reset_code,
                "cancel_response_bytes": origin.cancel_response_bytes,
                "keep_response_bytes": origin.keep_response_bytes,
                "active_handlers_after_close": origin.active_handlers,
            },
            "proxy_events": events,
            "runtime_resources": {
                "before_reset": before_reset,
                "after_reset": after_reset,
                "after_close": after_close,
            },
            "proxy_identity": proxy_identity(proxy),
        }
        (directory / "h2-cancel-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


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
