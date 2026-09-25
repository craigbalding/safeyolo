"""Client-followed service-gateway redirect at the real Python and Rust UDS boundary."""

from __future__ import annotations

import hashlib
import http.client
import json
import socketserver
import threading
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from safeyolo.core.vault import Vault, VaultCredential
from tests.blackbox.host.uds_transport import UDSProxyTransport
from tests.proxy_migration.harness import launch_proxy, request

AGENT_API = "http://_safeyolo.proxy.internal"
AGENT_TOKEN = "fixture-agent-api-token-one"
VAULT_PASSPHRASE = "synthetic-gateway-redirect-passphrase"
VAULT_CREDENTIAL = "synthetic-gateway-redirect-credential"
VAULT_NAME = "redirect-secret"

SERVICE = """\
schema_version: 1
name: redirect
default_host: 127.0.0.1
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /v1/redirect
"""


class _OwnedOrigin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str):
        self.accepts = 0
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.redirect_to = ""
        super().__init__((host, 0), _OriginRequest)

    def get_request(self):
        connection, address = super().get_request()
        with self.lock:
            self.accepts += 1
        return connection, address


class _OriginRequest(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        wire = bytearray()
        while b"\r\n\r\n" not in wire:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            wire.extend(chunk)
            assert len(wire) < 65536, "fixture request head exceeded limit"
        head, body = bytes(wire).split(b"\r\n\r\n", 1)
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.lower() == b"content-length":
                length = int(value.strip())
        while len(body) < length:
            chunk = self.request.recv(length - len(body))
            if not chunk:
                return
            body += chunk
        wire = head + b"\r\n\r\n" + body[:length]
        target = head.split(b"\r\n", 1)[0].split(b" ")[1].decode("ascii")
        record = {
            "wire_hex": wire.hex(),
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "request_target": target,
            "accepted_local": list(self.request.getsockname()),
            "accepted_peer": list(self.request.getpeername()),
        }
        if target.startswith(("/v1/redirect", "/plain-redirect")):
            location = self.server.redirect_to + (
                "/stolen?next=%252F" if target.startswith("/v1/") else "/plain?marker=control"
            )
            response_body = b"redirect"
            response = (
                f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n"
                f"Content-Length: {len(response_body)}\r\nConnection: close\r\n\r\n"
            ).encode() + response_body
        else:
            response_body = b"untrusted-observer"
            response = (
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + response_body
        record["response_wire_hex"] = response.hex()
        record["response_wire_sha256"] = hashlib.sha256(response).hexdigest()
        with self.server.lock:
            self.server.requests.append(record)
        self.request.sendall(response)


@contextmanager
def _origin(host: str):
    server = _OwnedOrigin(host)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def _authorization(wire: bytes) -> list[bytes]:
    head = wire.split(b"\r\n\r\n", 1)[0]
    return [line.split(b":", 1)[1].strip() for line in head.split(b"\r\n")[1:]
            if line.split(b":", 1)[0].lower() == b"authorization"]


def _wire(record: dict) -> bytes:
    return bytes.fromhex(record["wire_hex"])


def _assert_untrusted_wire_has_no_gateway_secret(wire: bytes, gateway_token: str) -> None:
    assert VAULT_CREDENTIAL.encode() not in wire
    assert gateway_token.encode() not in wire


def _policy(owned_port: int, untrusted_port: int) -> str:
    return f'''[hosts."127.0.0.1"]
service = "redirect"
[hosts."127.0.0.1:{owned_port}"]
egress = "allow"
[hosts."127.0.0.2:{untrusted_port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.alice.services.redirect]
capability = "reader"
token = "{VAULT_NAME}"
[agents.bob]
'''


def _fixture_state(directory: Path) -> None:
    (directory / "builtin").mkdir(parents=True)
    (directory / "services").mkdir()
    (directory / "services/redirect.yaml").write_text(SERVICE)
    data = directory / "data"
    data.mkdir()
    agent_token = data / "agent_token"
    agent_token.write_text(AGENT_TOKEN)
    agent_token.chmod(0o600)
    key = data / "vault.key"
    key.write_text(VAULT_PASSPHRASE)
    key.chmod(0o600)
    vault = Vault(data / "vault.yaml.enc")
    vault.unlock(VAULT_PASSPHRASE)
    vault.store(VaultCredential(VAULT_NAME, "bearer", VAULT_CREDENTIAL))


def _gateway_token(proxy) -> str:
    status, _, body = request(
        proxy.paths["alice"], AGENT_API + "/gateway/services",
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert status == 200, (status, body)
    view = json.loads(body)
    assert view["agent"] == "alice"
    assert view["authorized"]["redirect"]["capability"] == "reader"
    token = view["authorized"]["redirect"]["token"]
    assert token.startswith("sgw_")
    return token


def test_client_followed_gateway_redirect_keeps_vault_credential_at_owned_origin(
    proxy_backend, tmp_path,
):
    """An actual client follows both a gateway redirect and a nonsecret control.

    The owned origin receives the vaulted credential after gateway-token
    consumption. A different authority observes the client's followed request
    without that credential. Replaying the gateway token at the redirect URL
    and using it from another agent or path are denied before origin contact.
    """
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    with _origin("127.0.0.1") as owned, _origin("127.0.0.2") as untrusted:
        owned_port = owned.server_address[1]
        untrusted_port = untrusted.server_address[1]
        owned.redirect_to = f"http://127.0.0.2:{untrusted_port}"
        policy = _policy(owned_port, untrusted_port)
        with launch_proxy(proxy_backend, directory, policy, native_policy=True,
                          agent_api=True, gateway_services_dir=directory / "services",
                          gateway_builtin_services_dir=directory / "builtin",
                          network_guard_enabled=True, network_guard_block=True) as proxy:
            token = _gateway_token(proxy)
            owned_url = f"http://127.0.0.1:{owned_port}"
            with httpx.Client(transport=UDSProxyTransport(proxy.paths["alice"]),
                              follow_redirects=True, timeout=5) as client:
                followed = client.get(
                    owned_url + "/v1/redirect?next=%252F",
                    headers={"Authorization": f"Bearer {token}",
                             "X-Fixture-Request": "gateway-follow"},
                )
                assert [response.status_code for response in followed.history] == [302]
                assert followed.status_code == 200 and followed.content == b"untrusted-observer"
                assert str(followed.url) == owned.redirect_to + "/stolen?next=%252F"
                assert "authorization" not in followed.request.headers
                assert owned.accepts == len(owned.requests) == 1
                assert untrusted.accepts == len(untrusted.requests) == 1
                authorized_wire = _wire(owned.requests[0])
                untrusted_wire = _wire(untrusted.requests[0])
                assert _authorization(authorized_wire) == [f"Bearer {VAULT_CREDENTIAL}".encode()]
                assert token.encode() not in authorized_wire
                assert owned.requests[0]["accepted_local"] == ["127.0.0.1", owned_port]
                assert untrusted.requests[0]["accepted_local"] == ["127.0.0.2", untrusted_port]
                assert _authorization(untrusted_wire) == []
                _assert_untrusted_wire_has_no_gateway_secret(untrusted_wire, token)

                # The same client really can follow an allowed, nonsecret
                # redirect to the second authority through this proxy path.
                control = client.get(
                    owned_url + "/plain-redirect",
                    headers={"X-Fixture-Request": "nonsecret-follow"},
                )
                assert [response.status_code for response in control.history] == [302]
                assert control.status_code == 200 and control.content == b"untrusted-observer"
                assert str(control.url) == owned.redirect_to + "/plain?marker=control"
                assert untrusted.accepts == len(untrusted.requests) == 2
                assert b"x-fixture-request: nonsecret-follow" in _wire(untrusted.requests[1]).lower()

            # A direct, harmless observer probe proves that this raw-wire
            # recorder sees Authorization if one arrives. It is distinct from
            # the proxy-follow path and cannot weaken either proxy's guard.
            observer_control = http.client.HTTPConnection("127.0.0.2", untrusted_port, timeout=5)
            try:
                observer_control.request(
                    "GET", "/observer-control",
                    headers={"Authorization": "Bearer harmless-observer-control"},
                )
                observer_response = observer_control.getresponse()
                assert observer_response.status == 200
                assert observer_response.read() == b"untrusted-observer"
            finally:
                observer_control.close()
            assert _authorization(_wire(untrusted.requests[2])) == [b"Bearer harmless-observer-control"]
            with pytest.raises(AssertionError):
                _assert_untrusted_wire_has_no_gateway_secret(
                    _wire(untrusted.requests[2]) + VAULT_CREDENTIAL.encode(), token,
                )

            before = (owned.accepts, untrusted.accepts)
            denials = []
            for agent, url in (
                ("alice", owned.redirect_to + "/stolen?next=%252F"),
                ("alice", owned_url + "/v1/out-of-scope"),
                ("bob", owned_url + "/v1/redirect"),
            ):
                status, response_headers, body = request(
                    proxy.paths[agent], url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                if agent == "alice" and url.startswith(owned.redirect_to):
                    # Neither gateway can resolve service metadata at this
                    # unmapped host. Their response schemas differ, but both
                    # return the same local configuration-error code.
                    payload = json.loads(body)
                    assert status == 503 and (
                        payload.get("error") == "GATEWAY_CONFIGURATION_ERROR"
                        or payload.get("reason_codes") == ["GATEWAY_CONFIGURATION_ERROR"]
                    )
                else:
                    assert status == 403, (agent, url, status, body)
                denials.append({"agent": agent, "url": url, "status": status,
                                "response_headers": response_headers,
                                "body_hex": body.hex()})
            assert (owned.accepts, untrusted.accepts) == before
            for observed in untrusted.requests:
                _assert_untrusted_wire_has_no_gateway_secret(_wire(observed), token)
            assert [(row["host"], row["port"]) for row in proxy.events("proxy.egress")] == [
                ("127.0.0.1", owned_port),
                ("127.0.0.2", untrusted_port),
                ("127.0.0.1", owned_port),
                ("127.0.0.2", untrusted_port),
            ]

            audit = (directory / "audit.jsonl").read_bytes()
            events = (directory / "events.jsonl").read_bytes()
            assert sum(json.loads(line)["event"] == "gateway.allow"
                       for line in audit.splitlines()) == 1
            for secret in (VAULT_CREDENTIAL.encode(), token.encode()):
                assert secret not in audit and secret not in events
            (directory / "gateway-redirect-observation.json").write_text(json.dumps({
                "backend": proxy_backend,
                "logical_owned_authority": f"127.0.0.1:{owned_port}",
                "logical_redirect_authority": f"127.0.0.2:{untrusted_port}",
                "gateway_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "vault_credential_sha256": hashlib.sha256(VAULT_CREDENTIAL.encode()).hexdigest(),
                "client_follow": {
                    "request_method": followed.history[0].request.method,
                    "request_url": owned_url + "/v1/redirect?next=%252F",
                    "request_header_names": sorted(followed.history[0].request.headers),
                    "redirect_status": followed.history[0].status_code,
                    "redirect_location": followed.history[0].headers["location"],
                    "redirect_response_headers": dict(followed.history[0].headers),
                    "redirect_body_hex": followed.history[0].content.hex(),
                    "follow_request_method": followed.request.method,
                    "follow_request_header_names": sorted(followed.request.headers),
                    "final_status": followed.status_code,
                    "final_url": str(followed.url),
                    "final_response_headers": dict(followed.headers),
                    "final_body_hex": followed.content.hex(),
                },
                "control_follow_status": control.status_code,
                "denials": denials,
                "owned_accepts": owned.accepts,
                "owned_requests": owned.requests,
                "untrusted_accepts": untrusted.accepts,
                "untrusted_requests": untrusted.requests,
            }, indent=2) + "\n")
