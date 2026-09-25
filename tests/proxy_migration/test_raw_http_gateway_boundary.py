"""Raw HTTP parsing at the service gateway's real Python/Rust proxy boundary."""

import http.client
import json
import socket
import socketserver
import threading
from contextlib import contextmanager
from urllib.parse import urlsplit

from tests.proxy_migration.harness import launch_proxy, read_events
from tests.proxy_migration.test_gateway_redirect import (
    VAULT_CREDENTIAL,
    VAULT_NAME,
    _fixture_state,
    _gateway_token,
)

ALLOWED = "allowed.invalid"
FORBIDDEN = "forbidden.invalid"
SIGNED_TARGET = b"/v1/signed?part=one&part=two%2Fthree&empty="
ORDINARY_SIGNED_TARGET = b"/signed/%2F?part=one&part=two%2Fthree&empty="
SIGNED_BODY = b"part=one%2Ftwo&part=three\x00signed"
SERVICE = f"""\
schema_version: 1
name: redirect
default_host: {ALLOWED}
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  reader:
    routes:
      - methods: [POST]
        path: /v1/signed
      - methods: [GET]
        path: /v1/read
"""
POLICY = f'''budget = 12000
[hosts."{ALLOWED}"]
service = "redirect"
egress = "allow"
[hosts."{FORBIDDEN}"]
egress = "deny"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.alice.services.redirect]
capability = "reader"
token = "{VAULT_NAME}"
[agents.bob]
'''


def _read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        assert part, "request ended inside its framed body"
        result.extend(part)
    return bytes(result)


def _read_line(stream):
    line = bytearray()
    while not line.endswith(b"\r\n"):
        line.extend(_read_exact(stream, 1))
        assert len(line) < 65536, "line exceeded fixture limit"
    return bytes(line)


def _read_request(stream):
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head.extend(_read_exact(stream, 1))
        assert len(head) < 65536, "head exceeded fixture limit"
    head = bytes(head)
    fields = [(name.lower(), value.strip()) for line in head.split(b"\r\n")[1:-2]
              for name, separator, value in [line.partition(b":")] if separator]
    lengths = [int(value) for name, value in fields if name == b"content-length"]
    transfers = [value.lower() for name, value in fields if name == b"transfer-encoding"]
    wire_body = bytearray()
    body = bytearray()
    if transfers and transfers[-1].endswith(b"chunked"):
        while True:
            size_line = _read_line(stream)
            wire_body.extend(size_line)
            size = int(size_line[:-2].split(b";", 1)[0], 16)
            if size == 0:
                while True:
                    trailer = _read_line(stream)
                    wire_body.extend(trailer)
                    if trailer == b"\r\n":
                        break
                break
            chunk = _read_exact(stream, size)
            body.extend(chunk)
            delimiter = _read_exact(stream, 2)
            assert delimiter == b"\r\n", "chunk delimiter was not CRLF"
            wire_body.extend(chunk + delimiter)
    elif lengths:
        wire_body.extend(_read_exact(stream, lengths[0]))
        body.extend(wire_body)
    return {"head": head, "wire_body": bytes(wire_body), "body": bytes(body),
            "lengths": lengths, "transfers": transfers}


class _WireServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, name, handler):
        self.name = name
        self.accepts = 0
        self.requests = []
        self.errors = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), handler)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepts += 1
        return result


class _OriginRequest(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            observed = _read_request(self.request)
            with self.server.lock:
                self.server.requests.append(observed)
            payload = self.server.name.encode()
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                                 + str(len(payload)).encode()
                                 + b"\r\nConnection: close\r\n\r\n" + payload)
        except Exception as error:
            self.server.errors.append(error)


class _ParentRequest(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            observed = _read_request(self.request)
            first = observed["head"].split(b"\r\n", 1)[0]
            observed["target"] = first.split(b" ", 2)[1]
            hosts = [line.split(b":", 1)[1].strip() for line in observed["head"].split(b"\r\n")
                     if line.lower().startswith(b"host:")]
            assert len(hosts) == 1, hosts
            host = urlsplit("http://" + hosts[0].decode("ascii")).hostname
            origin = self.server.origins[host]
            observed["route"] = origin.name
            with self.server.lock:
                self.server.requests.append(observed)
            absolute_target = observed["target"].decode("utf-8")
            path = urlsplit(absolute_target)
            target = (path.path + ("?" + path.query if "?" in absolute_target
                                   else "")).encode("utf-8")
            forwarded = first.split(b" ", 1)[0] + b" " + target + b" HTTP/1.1\r\n"
            forwarded += observed["head"].split(b"\r\n", 1)[1] + observed["wire_body"]
            with socket.create_connection(origin.server_address, timeout=5) as upstream:
                upstream.sendall(forwarded)
                while part := upstream.recv(65536):
                    self.request.sendall(part)
        except Exception as error:
            self.server.errors.append(error)


@contextmanager
def _servers():
    peers = [_WireServer("allowed", _OriginRequest), _WireServer("forbidden", _OriginRequest)]
    parent = _WireServer("parent", _ParentRequest)
    parent.origins = dict(zip((ALLOWED, FORBIDDEN), peers, strict=True))
    threads = [threading.Thread(target=peer.serve_forever, daemon=True)
               for peer in (*peers, parent)]
    for thread in threads:
        thread.start()
    try:
        yield parent, *peers
    finally:
        for peer in (*peers, parent):
            peer.shutdown()
            peer.server_close()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        for peer in (*peers, parent):
            assert peer.errors == [], (peer.name, peer.errors)


def _send(path, target, fields, body=b"", method=b"GET", authority=ALLOWED):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(path)
        head = method + b" http://" + authority.encode() + target + b" HTTP/1.1\r\n"
        head += b"".join(name + b": " + value + b"\r\n" for name, value in fields)
        stream.sendall(head + b"\r\n" + body)
        response = http.client.HTTPResponse(stream)
        response.begin()
        return response.status, dict(response.getheaders()), response.read()


def test_raw_headers_framing_and_gateway_route_agree_with_forwarded_bytes(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(SERVICE)
    with _servers() as (parent, allowed, forbidden):
        with launch_proxy(proxy_backend, directory, POLICY, native_policy=True, agent_api=True,
                          gateway_services_dir=directory / "services",
                          gateway_builtin_services_dir=directory / "builtin",
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            token = _gateway_token(proxy).encode()
            auth = (b"Authorization", b"Bearer " + token)
            path = proxy.paths["alice"]

            signed = _send(path, SIGNED_TARGET,
                           [(b"Host", ALLOWED.encode()), auth,
                            (b"Content-Length", str(len(SIGNED_BODY)).encode())],
                           SIGNED_BODY, b"POST")
            assert signed[0] == 200 and signed[2] == b"allowed", signed
            assert parent.requests[-1]["target"] == b"http://" + ALLOWED.encode() + SIGNED_TARGET
            assert parent.requests[-1]["body"] == SIGNED_BODY
            assert parent.requests[-1]["lengths"] == [len(SIGNED_BODY)]
            assert parent.requests[-1]["transfers"] == []
            assert allowed.requests[-1]["head"].split(b"\r\n", 1)[0] == b"POST " + SIGNED_TARGET + b" HTTP/1.1"
            assert allowed.requests[-1]["body"] == SIGNED_BODY
            auth_values = [line.partition(b":")[2].strip()
                           for line in allowed.requests[-1]["head"].split(b"\r\n")
                           if line.lower().startswith(b"authorization:")]
            assert auth_values == [b"Bearer " + VAULT_CREDENTIAL.encode()]
            assert token not in allowed.requests[-1]["head"]

            read = _send(path, b"/v1/read", [(b"Host", ALLOWED.encode()), auth])
            assert read[0] == 200 and read[2] == b"allowed", read
            assert parent.requests[-1]["target"] == b"http://allowed.invalid/v1/read"
            assert b"Bearer " + VAULT_CREDENTIAL.encode() in allowed.requests[-1]["head"]

            # The gateway restriction does not alter an ordinary signed URL.
            ordinary = _send(path, ORDINARY_SIGNED_TARGET,
                             [(b"Host", ALLOWED.encode()),
                              (b"Content-Length", str(len(SIGNED_BODY)).encode())],
                             SIGNED_BODY, b"POST")
            assert ordinary[0] == 200 and ordinary[2] == b"allowed", ordinary
            assert parent.requests[-1]["target"] == b"http://" + ALLOWED.encode() + ORDINARY_SIGNED_TARGET
            assert allowed.requests[-1]["head"].split(b"\r\n", 1)[0] == (
                b"POST " + ORDINARY_SIGNED_TARGET + b" HTTP/1.1")
            assert parent.requests[-1]["body"] == allowed.requests[-1]["body"] == SIGNED_BODY
            assert VAULT_CREDENTIAL.encode() not in allowed.requests[-1]["head"]

            before = (parent.accepts, allowed.accepts, forbidden.accepts)
            denied = _send(path, b"/v1/read", [(b"Host", FORBIDDEN.encode()), auth],
                           authority=FORBIDDEN)
            assert denied[0] in (403, 503), denied
            denied = _send(proxy.paths["bob"], b"/v1/read",
                           [(b"Host", ALLOWED.encode()), auth])
            assert denied[0] == 403, denied
            assert (parent.accepts, allowed.accepts, forbidden.accepts) == before

            for fields in (
                [(b"Host", ALLOWED.encode()), auth,
                 (b"authorization", b"Bearer harmless-second-value")],
                [(b"Host", ALLOWED.encode()), (b"hOst", FORBIDDEN.encode()), auth],
            ):
                before = (parent.accepts, allowed.accepts, forbidden.accepts)
                status, _, _ = _send(path, b"/v1/read", fields)
                assert status >= 400, status
                assert (parent.accepts, allowed.accepts, forbidden.accepts) == before

            for target in (b"/v1/%72ead", b"/v1//read", b"/v1%2Fread", b"/v1/./read",
                           b"/v1/read/", b"/v1/read/?x=1"):
                before = (parent.accepts, allowed.accepts, forbidden.accepts)
                status, response_headers, body = _send(
                    path, target, [(b"Host", ALLOWED.encode()), auth])
                assert status == 403, (target, status, body)
                assert {name.lower(): value for name, value in response_headers.items()}[
                    "x-blocked-by"] == "service-gateway"
                payload = json.loads(body)
                assert "TRANSPORT_PATH_TRICK" in payload.get(
                    "reason_codes", [payload.get("error")]), (target, payload)
                assert (parent.accepts, allowed.accepts, forbidden.accepts) == before, target

            for target in ("/v1/reａd".encode(), "/v1/ｒead".encode()):
                before = (parent.accepts, allowed.accepts, forbidden.accepts)
                status, response_headers, body = _send(
                    path, target, [(b"Host", ALLOWED.encode()), auth])
                if proxy_backend == "rust":
                    assert status == 403, (target, status, body)
                    assert {name.lower(): value for name, value in response_headers.items()}[
                        "x-blocked-by"] == "service-gateway"
                    payload = json.loads(body)
                    assert payload["error"] == "TRANSPORT_PATH_TRICK", payload
                else:
                    assert status == 400, (target, status, body)
                assert (parent.accepts, allowed.accepts, forbidden.accepts) == before, target

            chunk = b"4\r\nDATA\r\n0\r\n\r\n"
            before = (parent.accepts, allowed.accepts, forbidden.accepts)
            framed = _send(path, SIGNED_TARGET,
                           [(b"Host", ALLOWED.encode()), auth,
                            (b"Content-Length", b"0"), (b"Transfer-Encoding", b"chunked")],
                           chunk, b"POST")
            if framed[0] < 400:
                assert framed[0] == 200 and framed[2] == b"allowed", framed
                assert (parent.accepts, allowed.accepts, forbidden.accepts) == (
                    before[0] + 1, before[1] + 1, before[2])
                assert parent.requests[-1]["lengths"] == []
                assert allowed.requests[-1]["lengths"] == []
                assert parent.requests[-1]["body"] == allowed.requests[-1]["body"] == b"DATA"
            else:
                assert (parent.accepts, allowed.accepts, forbidden.accepts) == before

            audit = read_events(directory / "audit.jsonl")
            path_denials = [row for row in audit if row["event"] == "gateway.deny"
                            and row.get("details", {}).get("code") == "TRANSPORT_PATH_TRICK"]
            if proxy_backend == "python":
                assert len(path_denials) == 6, path_denials
                assert framed[0] == 400, framed
            else:
                assert framed[0] == 200, framed
            assert len(proxy.events("proxy.egress")) == parent.accepts
            for secret in (token, VAULT_CREDENTIAL.encode()):
                assert secret not in (directory / "audit.jsonl").read_bytes()
                assert secret not in (directory / "events.jsonl").read_bytes()
            assert forbidden.accepts == 0 and forbidden.requests == []

        # This observer really routes a conflicting Host to another physical
        # origin; it cannot make a leaked credential look safely contained.
        with socket.create_connection(parent.server_address, timeout=5) as direct:
            direct.sendall(b"GET http://allowed.invalid/observer-control HTTP/1.1\r\n"
                           b"Host: forbidden.invalid\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(direct)
            response.begin()
            assert response.status == 200 and response.read() == b"forbidden"
        assert parent.requests[-1]["route"] == "forbidden"
        assert forbidden.accepts == 1 and len(forbidden.requests) == 1
        assert VAULT_CREDENTIAL.encode() not in forbidden.requests[0]["head"]
