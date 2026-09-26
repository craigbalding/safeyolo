"""Independent Linux socket-attempt observations for local proxy decisions."""

import errno
import json
import re
import shutil
import socket
import sys
import time
import uuid
from contextlib import ExitStack, contextmanager

import pytest

from tests.proxy_migration.dns_server import dns_server
from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.scenarios import POLICY, origin_server


def _completed_connect_trace(path, proxy_pid):
    """Read after the traced proxy exits, including the tracer's final line."""
    exit_line = re.compile(rf"^{proxy_pid}[ \t]+\+\+\+ (?:exited with|killed by)", re.MULTILINE)
    deadline = time.monotonic() + 3
    while True:
        trace = path.read_text() if path.exists() else ""
        if exit_line.search(trace):
            return trace
        if time.monotonic() >= deadline:
            raise AssertionError(f"Connect trace did not report exit for proxy pid {proxy_pid}")
        time.sleep(0.01)


def _ip_connect_addresses(trace):
    """Return IP socket destinations attempted by the traced process."""
    calls = [line for line in trace.splitlines() if re.search(r"\bconnect\(", line)]
    assert calls, "The positive control did not exercise the syscall observer"
    assert all("sa_family=" in line for line in calls), calls
    addresses = re.findall(
        r"\bconnect\(-?\d+, \{sa_family=AF_INET6?\b([^}]*)\}", trace,
    )
    return addresses


def _outbound_ip_addresses(trace):
    """Find IP destinations in connect and datagram-send system calls."""
    addresses = []
    for line in trace.splitlines():
        if not re.search(r"\b(?:connect|sendto|sendmsg|sendmmsg)\(", line):
            continue
        if "sa_family=AF_INET" not in line:
            continue
        address = re.search(r"\{sa_family=AF_INET6?\b([^}]*)\}", line)
        assert address is not None, line
        addresses.append(address.group(1))
    assert addresses, "The positive control did not exercise the network syscall observer"
    return addresses


def _reserved_spelling(host, nonce):
    """Give each reserved request a distinct case spelling and DNS root dot."""
    bits = int(nonce, 16)
    return "".join(character.upper() if character.isalpha() and bits & (1 << index)
                   else character for index, character in enumerate(host)) + "."


@contextmanager
def _bound_dns_server(names):
    """Report an unavailable local DNS bind as an unsupported test host."""
    with ExitStack() as stack:
        try:
            answers = stack.enter_context(dns_server(names))
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EADDRINUSE):
                pytest.skip(f"Loopback DNS port 53 is unavailable: {error}")
            raise
        yield answers


@pytest.mark.parametrize(("proxy_pid", "padding", "exit_status"), [
    (6056, "  ", "exited with 0"),
    (14057, " ", "killed by SIGTERM"),
])
def test_completed_connect_trace_accepts_padded_pid(tmp_path, proxy_pid, padding, exit_status):
    trace_path = tmp_path / "connect.trace"
    trace = f"{proxy_pid}{padding}+++ {exit_status} +++\n"
    trace_path.write_text(trace)
    assert _completed_connect_trace(trace_path, proxy_pid) == trace


@pytest.mark.parametrize("api_enabled", [False, True], ids=["api-unavailable", "api-enabled"])
def test_reserved_and_denied_requests_make_no_ip_connect(
    proxy_backend, tmp_path, api_enabled,
):
    """Two live parent dials bracket local denials on the same real process."""
    if sys.platform != "linux" or shutil.which("strace") is None:
        pytest.skip("Independent IP connect observation requires Linux strace")

    directory = tmp_path / proxy_backend
    trace_path = directory / "connect.trace"
    with origin_server(capture_heads=True) as parent:
        parent_port = parent.server_address[1]
        with launch_proxy(
            proxy_backend, directory, POLICY,
            parent_proxy=f"http://127.0.0.1:{parent_port}",
            native_policy=True, agent_api=api_enabled, eager_connect=True,
            connect_trace_path=trace_path,
        ) as proxy:
            proxy_pid = proxy.process.pid
            control_url = "http://control.invalid/ordinary?owned=control"

            def send_control(expected_accepts):
                status, _, body = request(proxy.paths["alice"], control_url)
                assert (status, body) == (200, b"hello")
                assert parent.accepts == expected_accepts

            send_control(1)

            for host in ("_safeyolo.proxy.internal", "_safeyolo.proxy.internal."):
                status, _, body = request(
                    proxy.paths["alice"], f"http://{host}/health?owned=reserved",
                    headers={"Authorization": "Bearer fixture-wrong-token"},
                )
                assert status == (401 if api_enabled else 503), body
                authority = f"{host}:443"
                status, headers, body = request(
                    proxy.paths["alice"], authority, method="CONNECT",
                    headers={"Host": authority},
                )
                assert status == 403, body
                assert {key.lower(): value for key, value in headers.items()}[
                    "x-blocked-by"] == "transport-guard"

            for host in ("_safeyolo.probe.internal", "_safeyolo.probe.internal."):
                status, _, body = request(
                    proxy.paths["alice"], f"http://{host}/__pipeline_probe",
                )
                assert status == 200 and json.loads(body)["probe_ok"] is True

            status, _, _ = request(
                proxy.paths["alice"], "http://_safeyolo.proxy.internal../health",
            )
            assert status == 400
            authority = "denied.invalid:9443"
            status, headers, body = request(
                proxy.paths["bob"], authority, method="CONNECT",
                headers={"Host": authority},
            )
            assert status == 403, body
            assert {key.lower(): value for key, value in headers.items()}[
                "x-blocked-by"] == "network-guard"
            status, headers, body = request(
                proxy.paths["bob"], "http://denied.invalid:8123/private",
            )
            assert status == 403, body
            assert {key.lower(): value for key, value in headers.items()}[
                "x-blocked-by"] == "network-guard"
            assert parent.accepts == 1 and len(parent.requests) == 1
            send_control(2)

        trace = _completed_connect_trace(trace_path, proxy_pid)
        ip_attempts = _ip_connect_addresses(trace)
        assert len(ip_attempts) == 2, ip_attempts
        assert all(
            f"sin_port=htons({parent_port})" in attempt
            and 'sin_addr=inet_addr("127.0.0.1")' in attempt
            for attempt in ip_attempts
        ), ip_attempts
        assert parent.accepts == 2 and len(parent.requests) == 2
        assert all(b"control.invalid" in head for head in parent.request_heads)
        assert all(b"reserved" not in head and b"denied.invalid" not in head
                   for head in parent.request_heads)


def test_reserved_and_denied_requests_make_no_dns_query(
    proxy_backend, tmp_path,
):
    """Live direct DNS controls expose lookups before checking local denials."""
    if sys.platform != "linux" or shutil.which("strace") is None:
        pytest.skip("Independent DNS syscall observation requires Linux strace")
    if shutil.which("named") is None or shutil.which("named-checkconf") is None:
        pytest.skip("Authoritative DNS fixture requires BIND named and named-checkconf")

    nonce = uuid.uuid4().hex
    control_before = f"allow-before-{nonce}.dns-fixture.test"
    control_after = f"allow-after-{nonce}.dns-fixture.test"
    runner_control = f"runner-{nonce}.dns-fixture.test"
    denied_http = f"denied-http-{nonce}.dns-fixture.test"
    denied_connect = f"denied-connect-{nonce}.dns-fixture.test"
    reserved_api = _reserved_spelling("_safeyolo.proxy.internal", nonce)
    reserved_probe = _reserved_spelling("_safeyolo.probe.internal", nonce[::-1])
    names = {runner_control, control_before, control_after, denied_http,
             denied_connect, reserved_api, reserved_probe}
    directory = tmp_path / proxy_backend
    trace_path = directory / "network.trace"

    with _bound_dns_server(names) as dns:
        # A runner control first proves that this guest's getaddrinfo really
        # uses the bound loopback resolver. Other hosts may need a different
        # process-local route; an unsupported route is not a no-DNS result.
        try:
            resolved = socket.getaddrinfo(runner_control, 80, type=socket.SOCK_STREAM)
        except socket.gaierror:
            if not dns.queries():
                pytest.skip("getaddrinfo did not reach the loopback DNS fixture")
            raise
        assert any(address[4][0] == "127.0.0.1" for address in resolved), resolved
        assert any(name == runner_control and qtype == 1
                   for name, qtype, _ in dns.queries()), dns.queries()
        unknown = f"unknown-{nonce}.dns-fixture.test"
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo(unknown, 80, type=socket.SOCK_STREAM)
        assert any(name == unknown for name, _, _ in dns.queries()), dns.queries()
        dns.clear_queries()

        with origin_server(capture_heads=True) as origin:
            origin_port = origin.server_address[1]
            with launch_proxy(
                proxy_backend, directory, POLICY, native_policy=True,
                eager_connect=True, connect_trace_path=trace_path,
            ) as proxy:
                proxy_pid = proxy.process.pid

                def control(host, expected_accepts):
                    status, _, body = request(
                        proxy.paths["alice"], f"http://{host}:{origin_port}/control",
                    )
                    assert (status, body) == (200, b"hello")
                    assert origin.accepts == expected_accepts

                control(control_before, 1)
                assert any(name == control_before and qtype == 1
                           for name, qtype, _ in dns.queries()), dns.queries()
                before_denials = dns.queries()

                status, _, body = request(
                    proxy.paths["alice"], f"http://{reserved_api}/health?nonce={nonce}",
                    headers={"Authorization": "Bearer fixture-wrong-token"},
                )
                assert status == 503, body
                status, _, body = request(
                    proxy.paths["alice"], f"http://{reserved_probe}/__pipeline_probe?nonce={nonce}",
                )
                assert status == 200 and json.loads(body)["probe_ok"] is True
                authority = f"{reserved_api}:443"
                status, headers, body = request(
                    proxy.paths["alice"], authority, method="CONNECT",
                    headers={"Host": authority},
                )
                assert status == 403, body
                assert {key.lower(): value for key, value in headers.items()}[
                    "x-blocked-by"] == "transport-guard"

                for host, method, port in ((denied_http, "GET", origin_port),
                                           (denied_connect, "CONNECT", origin_port)):
                    authority = f"{host}:{port}"
                    target = f"http://{authority}/private" if method == "GET" else authority
                    status, headers, body = request(
                        proxy.paths["bob"], target, method=method,
                        headers={"Host": authority},
                    )
                    assert status == 403, body
                    assert {key.lower(): value for key, value in headers.items()}[
                        "x-blocked-by"] == "network-guard"

                assert dns.queries() == before_denials, dns.queries()
                assert origin.accepts == 1 and len(origin.requests) == 1
                control(control_after, 2)

            trace = _completed_connect_trace(trace_path, proxy_pid)
            destinations = _outbound_ip_addresses(trace)
            dns_attempts = [address for address in destinations
                            if "sin_port=htons(53)" in address]
            origin_attempts = [address for address in destinations
                               if f"sin_port=htons({origin_port})" in address]
            assert dns_attempts and all('sin_addr=inet_addr("127.0.0.1")' in address
                                        for address in dns_attempts), destinations
            assert len(origin_attempts) == 2 and all(
                'sin_addr=inet_addr("127.0.0.1")' in address
                for address in origin_attempts
            ), destinations
            assert len(destinations) == len(dns_attempts) + len(origin_attempts), destinations
            assert {name for name, _, _ in dns.queries()} == {
                control_before, control_after,
            }, dns.queries()
            assert all(b"/control" in head for head in origin.request_heads)
