"""Selected endpoints keep the TLS and HTTP name through an installed proxy."""

import http.client
import json
import os
import pwd
import shutil
import socket
import socketserver
import subprocess
import time
import uuid
from contextlib import ExitStack, contextmanager

import pytest

from safeyolo.rust_proxy import _ensure_signing_ca
from tests.proxy_contracts.harness import child_process, launch_proxy, request
from tests.proxy_contracts.test_authority_consistency import (
    ALLOWED,
    SECRET,
    Origin,
    ParentRequest,
    _certificate,
    _host,
    _server,
)
from tests.proxy_contracts.test_native_policy_cli import native_instance

pytestmark = pytest.mark.skipif(os.uname().sysname != "Linux", reason="Installed Linux/Squid proof")

POLICY = f'''budget = 12000
[hosts]
"*" = {{egress="allow", unknown_creds="prompt"}}
[hosts."{ALLOWED}"]
egress = "allow"
allow = ["synthetic-selected-ip:*"]
[credential.synthetic-selected-ip]
match = ["{SECRET.decode()}"]
allowed_hosts = ["{ALLOWED}"]
headers = ["authorization"]
[controls.credentials]
use_default_credential_rules = false
'''


class CurlProxy(socketserver.ThreadingTCPServer):
    """Adapt curl's TCP proxy connection to the attributed native UDS."""

    daemon_threads = True

    def __init__(self, path):
        self.path = path
        self.errors = []
        super().__init__(("127.0.0.1", 0), CurlProxyRequest)


class CurlProxyRequest(ParentRequest):
    def handle(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(5)
                upstream.connect(self.server.path)
                # Reuse the existing bounded byte relay. This fixture changes
                # the client transport only; native CONNECT owns the request.
                self._relay(upstream)
        except (ConnectionResetError, BrokenPipeError):
            # Refused TLS and aborted curl requests can reset either side.
            return
        except Exception as error:
            self.server.errors.append(error)


@contextmanager
def ordinary_squid(directory, port):
    """Run the distribution's unchanged Squid with an owned loopback listener."""
    executable = shutil.which("squid")
    assert executable is not None, "Install ordinary Squid for the selected-IP parent proof"
    directory.mkdir()
    access = directory / "access.log"
    config = directory / "squid.conf"
    config.write_text(
        f"http_port 127.0.0.1:{port}\n"
        "http_access allow all\ncache deny all\npid_filename none\n"
        f"cache_effective_user {pwd.getpwuid(os.geteuid()).pw_name}\n"
        "pinger_enable off\nshutdown_lifetime 0 seconds\n"
        f"cache_log {directory / 'cache.log'}\ncache_store_log none\n"
        "logformat selected_ip %rm %ru %>Hs\nbuffered_logs off\n"
        f"access_log stdio:{access} selected_ip\n"
    )
    command = [executable, "-N", "-n", "selectedip" + uuid.uuid4().hex[:20], "-f", str(config)]
    with child_process(command, directory, os.environ.copy()) as process:
        deadline = time.monotonic() + 5
        while True:
            assert process.poll() is None, ((directory / "process.log").read_text()
                                          + ((directory / "cache.log").read_text()
                                             if (directory / "cache.log").exists() else ""))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except (ConnectionRefusedError, TimeoutError):
                assert time.monotonic() < deadline, (directory / "process.log").read_text()
                time.sleep(0.02)
        yield f"http://127.0.0.1:{port}", access


@pytest.mark.parametrize("route", ["direct", "squid"])
def test_installed_curl_selected_ipv4_keeps_tls_http_and_credential_name(tmp_path, unused_tcp_port, route):
    context, certificate = _certificate(tmp_path, ALLOWED)
    trust = tmp_path / "origin-roots.pem"
    trust.write_bytes(certificate)
    ca = tmp_path / "ca"
    _ensure_signing_ca(ca)
    extra = (f'tls_ca_file = {json.dumps(str(ca / "mitmproxy-ca.pem"))}\n'
             f'upstream_ca_file = {json.dumps(str(trust))}\n')
    with ExitStack() as stack:
        origin = stack.enter_context(_server(Origin("selected-ip-origin", tls_context=context)))
        parent, access = stack.enter_context(ordinary_squid(tmp_path / "squid", unused_tcp_port)) if route == "squid" else (None, None)
        if parent:
            extra += f'parent_proxy_hosts = ["{ALLOWED}"]\n'
        instance = stack.enter_context(native_instance(tmp_path, POLICY, agent_api=True, extra_config=extra, parent_proxy=parent))
        bridge = stack.enter_context(_server(CurlProxy(instance.paths["alice"])))
        port = origin.server_address[1]
        curl = shutil.which("curl")
        assert curl is not None, "This installed boundary requires real curl"
        result = subprocess.run(
            [curl, "--silent", "--show-error", "--max-time", "5", "--http1.1",
             "--proxy", f"http://127.0.0.1:{bridge.server_address[1]}",
             "--cacert", str(ca / "mitmproxy-ca-cert.pem"),
             "--connect-to", f"{ALLOWED}:{port}:127.0.0.1:{port}",
             "--header", "Authorization: Bearer " + SECRET.decode(),
             "--dump-header", str(tmp_path / "curl-headers.txt"),
             f"https://{ALLOWED}:{port}/selected-ip"],
            capture_output=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b"selected-ip-origin"
        assert origin.accepts == 1
        assert origin.sni == [ALLOWED]
        assert len(origin.requests) == 1
        head = origin.requests[0]["head"]
        assert _host(head) == f"{ALLOWED}:{port}"
        assert SECRET in head
    if access:
        # Squid writes this result when the CONNECT tunnel ends. The owned
        # proxy and Squid have both stopped before this observation.
        assert f"CONNECT 127.0.0.1:{port} 200" in access.read_text().splitlines()


def test_connect_explain_uses_actual_descendants_and_keeps_agent_scope(tmp_path):
    """An inner lookup includes its CONNECT, without another inner exchange."""
    with _server(Origin("linked-http")) as origin, \
         launch_proxy("rust", tmp_path / "proxy", POLICY, native_product=True, agent_api=True) as proxy:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        client = http.client.HTTPConnection("fixture", timeout=5)
        client.sock = socket.socket(socket.AF_UNIX)
        client.sock.settimeout(5)
        children = []
        try:
            client.sock.connect(proxy.paths["alice"])
            client.sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                byte = client.sock.recv(1)
                assert byte, "CONNECT closed before its response"
                head.extend(byte)
                assert len(head) < 65536
            assert head.startswith(b"HTTP/1.1 200"), head
            outer = next(line.split(":", 1)[1].strip() for line in head.decode().splitlines()
                         if line.lower().startswith("x-safeyolo-request-id:"))
            for path in ("/first", "/second"):
                client.request("GET", path, headers={"Host": authority})
                response = client.getresponse()
                assert response.status == 200 and response.read() == b"linked-http"
                children.append(response.getheader("X-SafeYolo-Request-Id"))
        finally:
            client.close()

        def explain(agent, request_id):
            status, _, content = request(
                proxy.paths[agent], "http://_safeyolo.proxy.internal/explain?request_id=" + request_id,
                headers={"Authorization": "Bearer fixture-agent-api-token-one", "X-SafeYolo-Agent": "alice"},
            )
            assert status == 200, content
            return json.loads(content)

        all_events = explain("alice", outer)
        first = explain("alice", children[0])
        assert all_events["status"] == first["status"] == "complete"
        assert {row["request_id"] for row in all_events["events"]} == {outer, *children}
        assert {row["request_id"] for row in first["events"]} == {outer, children[0]}
        for request_id in (outer, *children):
            assert explain("bob", request_id)["events"] == []
        assert len(origin.requests) == 2
