"""Selected endpoints keep the TLS and HTTP name through an installed proxy."""

import http.client
import json
import os
import pwd
import shutil
import socket
import socketserver
import ssl
import subprocess
import time
import uuid
from contextlib import ExitStack, contextmanager

import pytest

from safeyolo.rust_proxy import _ensure_signing_ca
from tests.proxy_contracts.harness import child_process, launch_proxy, read_events, request
from tests.proxy_contracts.test_authority_consistency import (
    ALLOWED,
    SECRET,
    Origin,
    ParentRequest,
    _certificate,
    _host,
    _server,
)
from tests.proxy_contracts.test_http2_contract import origin_certificate, origin_server
from tests.proxy_contracts.test_native_policy_cli import native_instance
from tests.proxy_contracts.test_outbound_effects import _completed_connect_trace, _outbound_ip_addresses

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


def _curl_selected(path, ca, output, *, host, port, ip=None, http2=False, secret=True, capture=False):
    curl = shutil.which("curl")
    assert curl is not None, "This boundary requires real curl"
    with _server(CurlProxy(path)) as bridge:
        command = [curl, "--silent", "--show-error", "--max-time", "5",
                   "--http2" if http2 else "--http1.1",
                   "--proxy", f"http://127.0.0.1:{bridge.server_address[1]}",
                   "--cacert", str(ca), "--dump-header", str(output)]
        if ip is not None:
            address = f"[{ip}]" if ":" in ip else ip
            command += ["--connect-to", f"{host}:{port}:{address}:{port}"]
        if secret:
            command += ["--header", "Authorization: Bearer " + SECRET.decode()]
        if capture:
            command += ["--header", "X-SafeYolo-Test-Context: run=selected-ip;agent=alice"]
        command += [f"https://{host}:{port}/selected-ip"]
        result = subprocess.run(command, capture_output=True, timeout=10)
        assert not bridge.errors, bridge.errors
    ids = [line.split(":", 1)[1].strip() for line in output.read_text().splitlines()
           if line.lower().startswith("x-safeyolo-request-id:")]
    return result, ids


def _explain(paths, agent, request_id, token="fixture-agent-api-token-one"):
    status, _, content = request(
        paths[agent], "http://_safeyolo.proxy.internal/explain?request_id=" + request_id,
        headers={"Authorization": "Bearer " + token},
    )
    assert status == 200, content
    return json.loads(content)


def test_numeric_connect_selects_hostname_parent_and_linked_explain(tmp_path, unused_tcp_port):
    """An ambiguous numeric CONNECT waits, selects Squid, and retains both IDs."""
    context, certificate = _certificate(tmp_path, ALLOWED)
    trust = tmp_path / "origin-roots.pem"
    trust.write_bytes(certificate)
    directory = tmp_path / "proxy"
    _ensure_signing_ca(directory / "ca")
    with _server(Origin("selected-ip-origin", tls_context=context)) as origin, \
         ordinary_squid(tmp_path / "squid", unused_tcp_port) as (parent, access), \
         launch_proxy("rust", directory, POLICY, native_product=True, agent_api=True,
                      tls=True, upstream_ca=trust, parent_proxy=parent,
                      parent_proxy_hosts=[ALLOWED]) as proxy:
        port = origin.server_address[1]
        result, ids = _curl_selected(proxy.paths["alice"], directory / "ca/mitmproxy-ca-cert.pem",
                                     tmp_path / "headers", host=ALLOWED, port=port, ip="127.0.0.1")
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b"selected-ip-origin"
        assert len(ids) == 2 and ids[0] != ids[1], ids
        outer, inner = ids
        explanation = _explain(proxy.paths, "alice", outer)
        assert explanation["status"] == "complete"
        facts = [row["details"] for row in explanation["events"] if row["event"] == "traffic.connection"]
        assert any(row["stage"] == "route_wait" and row["outbound"] == "not_attempted" for row in facts)
        selected = next(row for row in facts if row["stage"] == "parent_connect")
        assert selected["logical_host"] == ALLOWED and selected["requested_ip"] == "127.0.0.1"
        assert selected["effective_ip"] == "127.0.0.1" and selected["selection_source"] == "client_connect"
        assert selected["parent_requested_target"] == f"127.0.0.1:{port}"
        assert selected["parent_connect_status"] == 200 and selected["direct_peer"] is None
        assert any(row["stage"] == "origin_tls" and row.get("certificate_verified") is True for row in facts)
        assert any(row["stage"] == "http_response" and row["http_status"] == 200 for row in facts)
        assert {row["request_id"] for row in explanation["events"]} == {outer, inner}
        assert _explain(proxy.paths, "bob", outer)["events"] == []
        assert origin.accepts == 1 and origin.sni == [ALLOWED]
        assert _host(origin.requests[0]["head"]) == f"{ALLOWED}:{port}"
        assert SECRET in origin.requests[0]["head"]
    assert f"CONNECT 127.0.0.1:{port} 200" in access.read_text().splitlines()


def _raw_connect(path, authority):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(40)
    try:
        stream.connect(path)
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        assert response.status == 200, response.read()
        return stream, response.getheader("X-SafeYolo-Request-Id")
    except BaseException:
        stream.close()
        raise


@pytest.mark.parametrize("ending", ["client_close", "timeout", "shutdown"])
def test_ambiguous_connect_ends_without_any_outbound_attempt(tmp_path, ending):
    """A bounded wait ends without contacting either route, including DNS."""
    directory = tmp_path / "proxy"
    trace = tmp_path / "connect.trace"
    with _server(Origin("must-not-connect")) as origin, _server(Origin("observer-control")) as control, \
         launch_proxy("rust", directory, POLICY, native_product=True, agent_api=True,
                      parent_proxy="http://127.0.0.1:1", parent_proxy_hosts=[ALLOWED],
                      connect_trace_path=trace) as proxy:
        port = origin.server_address[1]
        control_port = control.server_address[1]
        assert request(proxy.paths["alice"], f"http://127.0.0.1:{control_port}/control")[0] == 200
        assert control.accepts == 1
        stream, outer = _raw_connect(proxy.paths["alice"], f"127.0.0.1:{port}")
        try:
            initial = _explain(proxy.paths, "alice", outer)
            assert any(row["details"].get("stage") == "route_wait"
                       and row["details"]["outbound"] == "not_attempted" for row in initial["events"])
            assert origin.accepts == 0
            if ending == "client_close":
                stream.close()
            elif ending == "shutdown":
                proxy.process.terminate()
                proxy.process.wait(timeout=10)
            else:
                assert stream.recv(1) == b""
        finally:
            stream.close()
        if ending != "shutdown":
            # The authenticated reader flushes the canonical writer.
            events = _explain(proxy.paths, "alice", outer)["events"]
        else:
            events = read_events(proxy.audit_log)
        terminal = [row["details"] for row in events if row.get("request_id") == outer
                    and row["event"] == "traffic.connection" and row["details"].get("stage") == "route_wait"
                    and row["details"]["outcome"] != "pending"]
        assert terminal and terminal[-1]["outbound"] == "not_attempted", terminal
        assert terminal[-1]["outcome"] == ("timeout" if ending == "timeout" else "cancelled")
        assert origin.accepts == 0
    addresses = _outbound_ip_addresses(_completed_connect_trace(trace, proxy.process.pid))
    assert len(addresses) == 1 and f"htons({control_port})" in addresses[0], addresses


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
def ordinary_squid(directory, port, *, deny_connect=False):
    """Run the distribution's unchanged Squid with an owned loopback listener."""
    executable = shutil.which("squid")
    assert executable is not None, "Install ordinary Squid for the selected-IP parent proof"
    directory.mkdir()
    access = directory / "access.log"
    config = directory / "squid.conf"
    config.write_text(
        f"http_port 127.0.0.1:{port}\n"
        + ("acl CONNECT method CONNECT\nhttp_access deny CONNECT\n" if deny_connect else "")
        + "http_access allow all\ncache deny all\npid_filename none\n"
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


@pytest.mark.parametrize("selection", ["client", "operator"])
@pytest.mark.parametrize("route,ip,http2", [
    ("direct", "127.0.0.1", False), ("squid", "127.0.0.1", True),
    ("squid", "::1", False), ("direct", "::1", True),
])
def test_installed_curl_selected_ip_keeps_tls_http_credential_and_evidence(tmp_path, unused_tcp_port, route, ip, http2, selection):
    _context, certificate = _certificate(tmp_path, ALLOWED)
    trust = tmp_path / "origin-roots.pem"
    trust.write_bytes(certificate)
    ca = tmp_path / "ca"
    _ensure_signing_ca(ca)
    extra = (f'tls_ca_file = {json.dumps(str(ca / "mitmproxy-ca.pem"))}\n'
             f'upstream_ca_file = {json.dumps(str(trust))}\n')
    if selection == "operator":
        extra += f'target_ip_mappings = [{{host="{ALLOWED}",ip="{ip}",agents=["alice"]}}]\n'
    with ExitStack() as stack:
        origin = stack.enter_context(origin_server(tmp_path / f"{ALLOWED}.pem", protocols=("h2", "http/1.1"), host=ip))
        parent, access = stack.enter_context(ordinary_squid(tmp_path / "squid", unused_tcp_port)) if route == "squid" else (None, None)
        if parent:
            extra += f'parent_proxy_hosts = ["{ALLOWED}"]\n'
        instance = stack.enter_context(native_instance(tmp_path, POLICY, agent_api=True, capture=True,
                                                        extra_config=extra, parent_proxy=parent))
        port = origin.server_address[1]
        result, ids = _curl_selected(instance.paths["alice"], ca / "mitmproxy-ca-cert.pem", tmp_path / "curl-headers.txt",
                                     host=ALLOWED, port=port, ip=ip if selection == "client" else None,
                                     http2=http2, capture=True)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b"hello"
        assert origin.accepts == 1 and origin.sni == [ALLOWED]
        assert origin.negotiated_alpn == ["h2" if http2 else "http/1.1"]
        assert len(origin.requests) == 1
        if http2:
            assert origin.requests[0][":authority"] == f"{ALLOWED}:{port}"
            assert origin.requests[0]["authorization"] == "Bearer " + SECRET.decode()
        else:
            head = origin.requests[0]["head"].encode("latin1")
            assert _host(head) == f"{ALLOWED}:{port}" and SECRET in head
        assert len(ids) == 2
        outer, inner = ids
        explanation = instance.agent_api("alice", "/explain?request_id=" + inner)
        assert explanation["status"] == "complete"
        assert {row["request_id"] for row in explanation["events"]} == {outer, inner}
        assert instance.agent_api("bob", "/explain?request_id=" + inner)["events"] == []
        deadline = time.monotonic() + 5
        while True:
            flows = instance.agent_api("alice", "/api/flows/search?run=selected-ip")["flows"]
            if flows:
                break
            assert time.monotonic() < deadline, explanation
            time.sleep(0.02)
        flow = next(row for row in flows if row["request_id"] == inner)
        connection = json.loads(flow["connection_json"])
        target = connection["target"]
        assert connection["connect_request_id"] == outer and connection["route"] == route.replace("squid", "parent")
        assert target["logical_host"] == ALLOWED and target["effective_ip"] == ip
        assert target["requested_ip"] == (ip if selection == "client" else None)
        assert target["selection_source"] == ("client_connect" if selection == "client" else "operator_mapping")
        assert target["tls_verification_name"] == ALLOWED and target["tls_result"] == "certificate_verified"
        assert flow["evidence_owner"] == "alice"
        if route == "squid":
            expected = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            assert target["parent_requested_target"] == expected and target["parent_connect_status"] == 200
            assert connection["peer"] is None and target["direct_peer"] is None
        else:
            assert target["direct_peer"] == connection["peer"]
            assert target["direct_peer"] == (f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}")
    if access:
        expected = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        assert f"CONNECT {expected} 200" in access.read_text().splitlines()


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


def test_literal_ip_tls_without_dns_sni_can_select_its_numeric_route(tmp_path):
    pem, trust = origin_certificate(tmp_path)
    directory = tmp_path / "proxy"
    _ensure_signing_ca(directory / "ca")
    with origin_server(pem, protocols=("http/1.1",)) as origin, \
         launch_proxy("rust", directory, POLICY, native_product=True, tls=True, upstream_ca=trust,
                      agent_api=True, parent_proxy="http://127.0.0.1:1", parent_proxy_hosts=[ALLOWED]) as proxy:
        port = origin.server_address[1]
        raw, outer = _raw_connect(proxy.paths["alice"], f"127.0.0.1:{port}")
        context = ssl.create_default_context(cafile=directory / "ca/mitmproxy-ca-cert.pem")
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as stream:
            stream.sendall(f"GET /literal HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
            response = http.client.HTTPResponse(stream)
            response.begin()
            assert response.status == 200 and response.read() == b"hello"
        events = _explain(proxy.paths, "alice", outer)["events"]
        assert any(row["event"] == "traffic.connection" and row["details"]["stage"] == "origin_tls"
                   and row["details"].get("certificate_verified") is True
                   and row["details"]["verification_name"] == "127.0.0.1" for row in events)
        assert origin.sni == [None]
        assert [row["details"]["route"] for row in proxy.events("traffic.egress")] == ["direct"]


@pytest.mark.parametrize("failure", ["refused", "unavailable"])
def test_selected_parent_failure_never_contacts_origin_or_loses_explain_id(tmp_path, unused_tcp_port, failure):
    context, certificate = _certificate(tmp_path, ALLOWED)
    trust = tmp_path / "origin-roots.pem"
    trust.write_bytes(certificate)
    directory = tmp_path / "proxy"
    _ensure_signing_ca(directory / "ca")
    trace = tmp_path / "connect.trace"
    with ExitStack() as stack:
        origin = stack.enter_context(_server(Origin("must-not-connect", tls_context=context)))
        port = origin.server_address[1]
        parent = f"http://127.0.0.1:{unused_tcp_port}"
        if failure == "refused":
            parent, _access = stack.enter_context(ordinary_squid(tmp_path / "squid", unused_tcp_port, deny_connect=True))
        proxy = stack.enter_context(launch_proxy("rust", directory, POLICY, native_product=True, tls=True,
                                   upstream_ca=trust, agent_api=True, parent_proxy=parent,
                                   parent_proxy_hosts=[ALLOWED], connect_trace_path=trace))
        result, ids = _curl_selected(proxy.paths["alice"], directory / "ca/mitmproxy-ca-cert.pem", tmp_path / "headers",
                                     host=ALLOWED, port=port, ip="127.0.0.1")
        assert result.returncode != 0 and len(ids) == 1, (result, ids)
        assert origin.accepts == 0 and origin.requests == []
        events = _explain(proxy.paths, "alice", ids[0])["events"]
        if failure == "refused":
            assert any(row["event"] == "traffic.connection" and row["details"]["stage"] == "parent_connect"
                       and row["details"]["parent_connect_status"] == 403 for row in events)
        else:
            assert any(row["event"] == "traffic.connection" and row["details"]["stage"] == "parent_tcp"
                       and row["details"]["outcome"] == "failed" for row in events)
        assert _explain(proxy.paths, "bob", ids[0])["events"] == []
    addresses = _outbound_ip_addresses(_completed_connect_trace(trace, proxy.process.pid))
    assert len(addresses) == 1 and f"htons({unused_tcp_port})" in addresses[0], addresses


@pytest.mark.parametrize("route", ["direct", "squid"])
def test_selected_origin_certificate_failure_remains_explainable(tmp_path, unused_tcp_port, route):
    context, certificate = _certificate(tmp_path, "wrong.invalid")
    trust = tmp_path / "origin-roots.pem"
    trust.write_bytes(certificate)
    directory = tmp_path / "proxy"
    _ensure_signing_ca(directory / "ca")
    with ExitStack() as stack:
        origin = stack.enter_context(_server(Origin("must-not-receive-http", tls_context=context)))
        parent, _access = stack.enter_context(ordinary_squid(tmp_path / "squid", unused_tcp_port)) if route == "squid" else (None, None)
        proxy = stack.enter_context(launch_proxy("rust", directory, POLICY, native_product=True, tls=True,
                                   upstream_ca=trust, agent_api=True, parent_proxy=parent,
                                   parent_proxy_hosts=[ALLOWED] if parent else []))
        result, ids = _curl_selected(proxy.paths["alice"], directory / "ca/mitmproxy-ca-cert.pem", tmp_path / "headers",
                                     host=ALLOWED, port=origin.server_address[1], ip="127.0.0.1")
        assert result.returncode == 0 and len(ids) == 2, (result, ids)
        assert b"502" in (tmp_path / "headers").read_bytes()
        facts = [row["details"] for row in _explain(proxy.paths, "alice", ids[0])["events"]
                 if row["event"] == "traffic.connection"]
        assert any(row["stage"] == "origin_tls" and row["outcome"] == "failed"
                   and row["verification_name"] == ALLOWED for row in facts)
        assert not any(row["stage"] == "http_response" for row in facts)
        assert origin.accepts == 1 and origin.sni == [ALLOWED] and origin.requests == []
