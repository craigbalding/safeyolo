"""Opaque CONNECT contracts through both implementations and owned endpoints."""

import hashlib
import json
import os
import pwd
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy
from tests.proxy_migration.test_http2_contract import POLICY, origin_certificate, origin_server

INNER_DENY_POLICY = '''[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "allow"
condition = { method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "deny"
condition = { method = "GET" }
'''

DIRECT_CONNECT_HALF_CLOSE_POLICY = '''budget = 12000
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "allow"
condition = { agent = "alice", method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "deny"
condition = { agent = "bob", method = "CONNECT" }
'''

PASSTHROUGH_LIFECYCLE_POLICY = '''budget = 12000
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { agent = "alice", method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
condition = { agent = "bob", method = "CONNECT" }
'''

PARENT_CONNECT_POLICY = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { agent = "alice", method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
condition = { agent = "bob" }
'''


def tunnel(path, authority):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(5)
    try:
        stream.connect(path)
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            byte = stream.recv(1)
            assert byte, "CONNECT closed before response"
            head.extend(byte)
        assert head.split(b" ", 2)[1] == b"200", bytes(head)
        return stream
    except BaseException:
        stream.close()
        raise


def read_exact(stream, size):
    received = bytearray()
    while len(received) < size:
        part = stream.recv(size - len(received))
        assert part, f"stream closed after {len(received)} of {size} bytes"
        received.extend(part)
    return bytes(received)


def read_until(stream, marker):
    received = bytearray()
    while not received.endswith(marker):
        part = stream.recv(1)
        assert part, "stream closed before expected marker"
        received.extend(part)
    return bytes(received)


def read_all(stream):
    received = bytearray()
    while part := stream.recv(65536):
        received.extend(part)
    return bytes(received)


def _parent_connect_control_fixture(phases=("positive", "failure")):
    """Serve one successful and one refused CONNECT with raw observations."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    observations = []
    failure = []

    def serve():
        try:
            for phase in phases:
                stream, peer = listener.accept()
                with stream:
                    stream.settimeout(5)
                    request = read_until(stream, b"\r\n\r\n")
                    if phase == "positive":
                        stream.sendall(
                            b"HTTP/1.1 200 Connection Established\r\n"
                            b"Connection: keep-alive\r\n\r\n"
                            b"parent-control-server-first"
                        )
                        payload = read_all(stream)
                    else:
                        stream.sendall(
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Connection: close\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        payload = b""
                    observations.append({
                        "phase": phase,
                        "peer": list(peer),
                        "request": request,
                        "payload": payload,
                    })
        except BaseException as error:  # report fixture failures in the test thread
            failure.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    return listener, observations, failure, thread


def test_parent_connect_failure_never_falls_back_to_direct_origin(
    proxy_backend, tmp_path, request
):
    """A parent CONNECT refusal is returned; the target origin stays untouched."""
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason=(
                "Python comparator opens the configured parent after its own CONNECT 200, "
                "so it cannot provide the parent server-first marker before client data"
            ),
        ))
    positive_authority = "parent-control.invalid:23456"
    parent, observations, failure, thread = _parent_connect_control_fixture()
    parent_url = f"http://127.0.0.1:{parent.getsockname()[1]}"
    directory = tmp_path / proxy_backend
    directory.mkdir()
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.25)
        refused_authority = f"127.0.0.1:{origin.getsockname()[1]}"
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                PARENT_CONNECT_POLICY,
                parent_proxy=parent_url,
                ignore_hosts=[positive_authority, refused_authority],
                eager_connect=True,
                native_policy=True,
            ) as proxy:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(proxy.paths["alice"])
                    client.sendall(
                        f"CONNECT {positive_authority} HTTP/1.1\r\n"
                        f"Host: {positive_authority}\r\nConnection: close\r\n\r\n".encode()
                    )
                    positive_head = read_until(client, b"\r\n\r\n")
                    assert positive_head.startswith(b"HTTP/1.1 200"), positive_head
                    assert client.recv(len(b"parent-control-server-first")) == (
                        b"parent-control-server-first"
                    )
                    client.sendall(b"parent-control-payload")
                    client.shutdown(socket.SHUT_WR)
                    assert read_all(client) == b""

                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(proxy.paths["alice"])
                    client.sendall(
                        f"CONNECT {refused_authority} HTTP/1.1\r\n"
                        f"Host: {refused_authority}\r\n"
                        "X-Direct-Egress-Canary: must-not-reach-origin\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    refused_response = read_until(client, b"\r\n\r\n")
                assert refused_response.startswith(b"HTTP/1.1 502"), refused_response

                with pytest.raises(socket.timeout):
                    origin.accept()
                assert proxy.process.poll() is None
                if proxy_backend == "rust":
                    provenance = json.loads(
                        (directory / "native-policy-provenance.json").read_text()
                    )
                    assert provenance == {
                        "backend": "rust",
                        "policy_mode": "native",
                        "policy_file": str(directory / "policy.toml"),
                        "temporary_policy_socket": None,
                        "temporary_policy_adapter": False,
                    }
                (directory / "parent-connect-failure.json").write_text(
                    json.dumps(
                        {
                            "backend": proxy_backend,
                            "parent_url": parent_url,
                            "positive_authority": positive_authority,
                            "refused_authority": refused_authority,
                            "positive_client_response_head_hex": positive_head.hex(),
                            "refused_client_response_head_hex": refused_response.hex(),
                            "parent_observations": [
                                {
                                    "phase": item["phase"],
                                    "peer": item["peer"],
                                    "request_hex": item["request"].hex(),
                                    "payload_hex": item["payload"].hex(),
                                }
                                for item in observations
                            ],
                            "direct_origin_accepts": 0,
                            "proxy_egress_events": proxy.events("proxy.egress"),
                            "native_policy_provenance": (
                                provenance if proxy_backend == "rust" else None
                            ),
                            "limits": [
                                "The parent observer handles one successful and one refused CONNECT sequentially.",
                                "The direct-origin canary records acceptance only; no origin application bytes are expected after zero accepts.",
                                "This does not establish parent retry, alternate-parent selection or long-duration failure recovery.",
                            ],
                        },
                        indent=2,
                    )
                    + "\n"
                )
        finally:
            parent.close()
            thread.join(timeout=6)
    assert not thread.is_alive()
    assert not failure, failure
    assert [item["phase"] for item in observations] == ["positive", "failure"]
    assert observations[0]["request"].startswith(
        f"CONNECT {positive_authority} HTTP/1.1\r\n".encode()
    )
    assert observations[0]["payload"] == b"parent-control-payload"
    assert observations[1]["request"].startswith(
        f"CONNECT {refused_authority} HTTP/1.1\r\n".encode()
    )
    assert b"X-Direct-Egress-Canary" not in observations[1]["request"]


def test_parent_connect_failure_recovers_on_later_parent_request(
    proxy_backend, tmp_path, request
):
    """A refused parent request does not poison the next parent-routed request."""
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason=(
                "Python comparator opens the configured parent after its own CONNECT 200, "
                "so it cannot provide the parent server-first marker before client data"
            ),
        ))
    positive_authority = "parent-recovery.invalid:23457"
    parent, observations, failure, thread = _parent_connect_control_fixture(
        phases=("failure", "positive")
    )
    parent_url = f"http://127.0.0.1:{parent.getsockname()[1]}"
    directory = tmp_path / proxy_backend
    directory.mkdir()
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.25)
        refused_authority = f"127.0.0.1:{origin.getsockname()[1]}"
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                PARENT_CONNECT_POLICY,
                parent_proxy=parent_url,
                ignore_hosts=[positive_authority, refused_authority],
                eager_connect=True,
                native_policy=True,
            ) as proxy:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(proxy.paths["alice"])
                    client.sendall(
                        f"CONNECT {refused_authority} HTTP/1.1\r\n"
                        f"Host: {refused_authority}\r\n"
                        "X-Direct-Egress-Canary: must-not-reach-origin\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    refused_response = read_until(client, b"\r\n\r\n")
                assert refused_response.startswith(b"HTTP/1.1 502"), refused_response
                with pytest.raises(socket.timeout):
                    origin.accept()

                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(proxy.paths["alice"])
                    client.sendall(
                        f"CONNECT {positive_authority} HTTP/1.1\r\n"
                        f"Host: {positive_authority}\r\nConnection: close\r\n\r\n".encode()
                    )
                    positive_head = read_until(client, b"\r\n\r\n")
                    assert positive_head.startswith(b"HTTP/1.1 200"), positive_head
                    assert client.recv(len(b"parent-control-server-first")) == (
                        b"parent-control-server-first"
                    )
                    client.sendall(b"parent-recovery-payload")
                    client.shutdown(socket.SHUT_WR)
                    assert read_all(client) == b""

                assert proxy.process.poll() is None
                if proxy_backend == "rust":
                    provenance = json.loads(
                        (directory / "native-policy-provenance.json").read_text()
                    )
                    assert provenance == {
                        "backend": "rust",
                        "policy_mode": "native",
                        "policy_file": str(directory / "policy.toml"),
                        "temporary_policy_socket": None,
                        "temporary_policy_adapter": False,
                    }
                (directory / "parent-connect-recovery.json").write_text(
                    json.dumps(
                        {
                            "backend": proxy_backend,
                            "parent_url": parent_url,
                            "sequence": ["failure", "positive"],
                            "refused_authority": refused_authority,
                            "positive_authority": positive_authority,
                            "refused_client_response_head_hex": refused_response.hex(),
                            "positive_client_response_head_hex": positive_head.hex(),
                            "parent_observations": [
                                {
                                    "phase": item["phase"],
                                    "peer": item["peer"],
                                    "request_hex": item["request"].hex(),
                                    "payload_hex": item["payload"].hex(),
                                }
                                for item in observations
                            ],
                            "direct_origin_accepts": 0,
                            "proxy_egress_events": proxy.events("proxy.egress"),
                            "native_policy_provenance": (
                                provenance if proxy_backend == "rust" else None
                            ),
                            "limits": [
                                "The recovery is a later independent request through the same configured parent after one refused CONNECT.",
                                "The direct-origin canary records acceptance only; no origin application bytes are expected after zero accepts.",
                                "The single parent_proxy setting supplies no alternate-parent or same-request retry contract; those remain unproven.",
                            ],
                        },
                        indent=2,
                    )
                    + "\n"
                )
        finally:
            parent.close()
            thread.join(timeout=6)
    assert not thread.is_alive()
    assert not failure, failure
    assert [item["phase"] for item in observations] == ["failure", "positive"]
    assert observations[0]["request"].startswith(
        f"CONNECT {refused_authority} HTTP/1.1\r\n".encode()
    )
    assert b"X-Direct-Egress-Canary" not in observations[0]["request"]
    assert observations[1]["request"].startswith(
        f"CONNECT {positive_authority} HTTP/1.1\r\n".encode()
    )
    assert observations[1]["payload"] == b"parent-recovery-payload"


def _process_fd_targets(pid):
    """Return the live child descriptor targets without attaching to it."""
    result = {}
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            result[descriptor.name] = os.readlink(descriptor)
        except FileNotFoundError:
            # A descriptor may close between directory enumeration and readlink.
            continue
    return result


def _process_resources(pid):
    """Capture external process resources for the bounded CONNECT workload."""
    status = Path(f"/proc/{pid}/status")
    if not status.exists():
        pytest.skip("CONNECT resource workload requires Linux /proc measurements")
    values = {}
    for line in status.read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"VmRSS", "VmHWM", "Threads"}:
            values[key] = int(value.strip().split()[0])
    try:
        fd_targets = _process_fd_targets(pid)
        executable = str(Path(f"/proc/{pid}/exe").resolve())
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
            b"\0", b" "
        ).decode(errors="replace").strip()
    except FileNotFoundError:
        fd_targets = {}
        executable = command = None
    return {
        "pid": pid,
        "rss_kib": values.get("VmRSS"),
        "hwm_kib": values.get("VmHWM"),
        "threads": values.get("Threads"),
        "fd_count": len(fd_targets),
        "fd_targets": fd_targets,
        "executable": executable,
        "command": command,
    }


def passthrough_audit(directory):
    audit = directory / "audit.jsonl"
    if not audit.exists():
        return []
    return [
        json.loads(line)
        for line in audit.read_text().splitlines()
        if line and json.loads(line).get("addon") == "ignored-host-logger"
    ]


def wait_for_passthrough_audit(directory, count):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = passthrough_audit(directory)
        if len(rows) == count:
            return rows
        assert len(rows) < count, f"duplicate passthrough events: {rows!r}"
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {count} passthrough events: {rows!r}")


def fragmented_tls_request(stream, authority, ca, first):
    context = ssl.create_default_context(cafile=ca)
    context.set_alpn_protocols(["http/1.1"])
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname="127.0.0.1")
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    hello = outgoing.read()
    if first:
        stream.sendall(hello[:first])
        time.sleep(0.05)
        stream.sendall(hello[first:])
    else:
        stream.sendall(hello)
    while True:
        try:
            client.do_handshake()
            break
        except ssl.SSLWantReadError:
            if data := outgoing.read():
                stream.sendall(data)
            data = stream.recv(65536)
            assert data, "TLS handshake closed early"
            incoming.write(data)
    if data := outgoing.read():
        stream.sendall(data)
    client.write(f"GET /denied HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode())
    stream.sendall(outgoing.read())
    response = bytearray()
    while True:
        try:
            data = client.read(65536)
            if not data:
                break
            response.extend(data)
            if b"\r\n\r\n" in response:
                head, body = response.split(b"\r\n\r\n", 1)
                lengths = [int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                           if line.lower().startswith(b"content-length:")]
                if lengths and len(body) >= lengths[0]:
                    break
        except ssl.SSLWantReadError:
            if data := outgoing.read():
                stream.sendall(data)
            data = stream.recv(65536)
            assert data, "HTTP response closed early"
            incoming.write(data)
    return int(response.split(b" ", 2)[1])


@pytest.mark.parametrize("first", [0, 1, 2, 3])
def test_fragmented_tls_keeps_the_inner_request_decision(proxy_backend, tmp_path, first, request):
    if proxy_backend == "python" and first in (1, 2):
        request.node.add_marker(pytest.mark.xfail(strict=True, reason="Existing short TLS prefix selects opaque forwarding before inner policy"))
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    pem, public = origin_certificate(directory)
    trusted = directory / "client-trust.pem"
    trusted.write_bytes(public.read_bytes() + (directory / "ca/mitmproxy-ca-cert.pem").read_bytes())
    with origin_server(pem, ("http/1.1",)) as origin:
        with launch_proxy(proxy_backend, directory, INNER_DENY_POLICY, tls=True, upstream_ca=public, eager_connect=True) as proxy:
            with tunnel(proxy.paths["alice"], origin.authority) as stream:
                assert fragmented_tls_request(stream, origin.authority, trusted, first) == 403
            assert origin.requests == []


@pytest.mark.parametrize("method, separator, leading", [
    ("SSH", " ", ""), ("SSHGET", " ", ""), ("SSH-EXT", " ", ""), ("SSH-2.0-test", " ", ""),
    ("GET", "\t", ""), ("GET", "\v", ""), ("GET", "\f", ""),
] + [("GET", " ", chr(byte)) for byte in (9, 11, 12, 28, 29, 30, 31, 32, 0x85, 0xa0)])
@pytest.mark.parametrize("first", [0, 1, 3])
def test_http_method_spelling_remains_inspected(proxy_backend, tmp_path, method, separator, leading, first, request):
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(strict=True, reason="Existing CONNECT classifier makes SSH prefixes or request-line whitespace opaque"))
    observed = []
    policy = INNER_DENY_POLICY.replace('method = "GET"', f'method = "{method}"')
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"

        def origin():
            stream, _ = listener.accept()
            with stream:
                stream.settimeout(5)
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    if not (part := stream.recv(8192)):
                        break
                    data.extend(part)
                observed.append(bytes(data))
                if data:
                    stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(proxy_backend, tmp_path / proxy_backend, policy, eager_connect=True) as proxy:
                with tunnel(proxy.paths["alice"], authority) as stream:
                    message = f"{leading}{method}{separator}/forbidden{separator}HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode("latin-1")
                    if first:
                        stream.sendall(message[:first])
                        time.sleep(0.025)
                    try:
                        stream.sendall(message[first:])
                    except BrokenPipeError:
                        # A parser can reject the leading byte before the rest
                        # arrives. Its terminal HTTP response is still required.
                        assert leading and first
                    response = bytearray()
                    while data := stream.recv(8192):
                        response.extend(data)
                    expected = b"HTTP/1.1 403" if separator == " " and not leading else b"HTTP/1.1 400"
                    assert response.startswith(expected), bytes(response)
            assert observed == [b""]
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


@pytest.mark.parametrize("first", ["client", "server"])
def test_connect_half_close_retains_the_opposite_direction(proxy_backend, tmp_path, first, request):
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(strict=True, reason="Existing CONNECT adapter turns TCP half-close into full close"))
    result = {}
    payload = bytes(range(256)) * 4096
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"

        def origin():
            try:
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(5)
                    if first == "server":
                        stream.sendall(b"server-first")
                        stream.shutdown(socket.SHUT_WR)
                    body = bytearray()
                    while data := stream.recv(65536):
                        body.extend(data)
                    result["body"] = bytes(body)
                    if first == "client":
                        stream.sendall(b"after-client-eof")
            except OSError as error:
                result["error"] = type(error).__name__

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY, eager_connect=True) as proxy:
                with tunnel(proxy.paths["alice"], authority) as stream:
                    if first == "server":
                        banner = bytearray()
                        while data := stream.recv(65536):
                            banner.extend(data)
                        assert banner == b"server-first"
                    stream.sendall(payload)
                    stream.shutdown(socket.SHUT_WR)
                    if first == "client":
                        reply = bytearray()
                        while data := stream.recv(65536):
                            reply.extend(data)
                        assert reply == b"after-client-eof"
                thread.join(timeout=5)
                assert not thread.is_alive()
                assert "error" not in result, result
                assert result["body"] == payload
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_connect_server_first_then_client_half_close_keeps_final_response(proxy_backend, tmp_path, request):
    """A raw server greeting survives while the client half-closes and awaits its reply."""
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason="Existing CONNECT adapter turns a client half-close into a full close",
        ))
    greeting = b"raw-server-first\x00v1\n"
    payload = bytes(range(256)) * 2048 + b"client-final-byte"
    final_response = b"raw-final-response\x00after-client-eof\n"
    observation = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"

        def origin():
            try:
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(5)
                    stream.sendall(greeting)
                    body = bytearray()
                    while data := stream.recv(65536):
                        body.extend(data)
                    observation["client_eof"] = True
                    observation["payload"] = bytes(body)
                    stream.sendall(final_response)
                    stream.shutdown(socket.SHUT_WR)
                    observation["server_eof"] = True
            except BaseException as error:  # report fixture failures in the test thread
                observation["error"] = f"{type(error).__name__}: {error}"

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend,
                tmp_path / proxy_backend,
                DIRECT_CONNECT_HALF_CLOSE_POLICY,
                eager_connect=True,
                native_policy=True,
            ) as proxy:
                with tunnel(proxy.paths["alice"], authority) as stream:
                    assert read_exact(stream, len(greeting)) == greeting
                    stream.sendall(payload)
                    stream.shutdown(socket.SHUT_WR)
                    observed_final = read_all(stream)
                    assert observed_final == final_response
                    client_eof = True
                thread.join(timeout=5)
                assert not thread.is_alive()
                assert observation == {
                    "client_eof": True,
                    "payload": payload,
                    "server_eof": True,
                }
                events = proxy.events("proxy.tunnel")
                if proxy_backend == "rust":
                    assert json.loads((tmp_path / proxy_backend / "native-policy-provenance.json").read_text()) == {
                        "backend": "rust",
                        "policy_mode": "native",
                        "policy_file": str(tmp_path / proxy_backend / "policy.toml"),
                        "temporary_policy_socket": None,
                        "temporary_policy_adapter": False,
                    }
                    assert len(events) == 1
                    assert events[0]["agent"] == "alice"
                    assert events[0]["host"] == "127.0.0.1"
                    assert events[0]["port"] == listener.getsockname()[1]
                    assert events[0]["coverage"] == "opaque"
                    assert events[0]["uploaded_bytes"] == len(payload)
                    assert events[0]["downloaded_bytes"] == len(greeting) + len(final_response)
                    assert events[0]["outcome"] == "completed"
                (tmp_path / proxy_backend / "lifecycle-observation.json").write_text(json.dumps({
                    "backend": proxy_backend,
                    "authority": authority,
                    "upstream": {
                        "greeting_hex": greeting.hex(),
                        "payload_length": len(payload),
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "payload_prefix_hex": payload[:32].hex(),
                        "payload_suffix_hex": payload[-32:].hex(),
                        "final_response_hex": final_response.hex(),
                    },
                    "client_observed": {
                        "greeting_hex": greeting.hex(),
                        "final_response_hex": observed_final.hex(),
                        "eof_after_final_response": client_eof,
                    },
                    "origin_observed": {
                        "payload_length": len(observation["payload"]),
                        "payload_sha256": hashlib.sha256(observation["payload"]).hexdigest(),
                        "client_write_eof": observation["client_eof"],
                        "origin_write_eof": observation["server_eof"],
                    },
                    "tunnel_events": events if proxy_backend == "rust" else [],
                }, indent=2) + "\n")
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_repeated_raw_connect_cancellation_reclaims_origin_and_process_resources(
    proxy_backend, tmp_path
):
    """Repeated abandoned raw CONNECTs close their origin and child resources."""
    sessions = 3
    directory = tmp_path / proxy_backend
    directory.mkdir()
    greeting = b"raw-cancel-server-first\x00v1\n"
    payloads = [
        (b"abandoned-connect-" + index.to_bytes(2, "big")) * 4096
        for index in range(sessions)
    ]
    observations = []
    origin_error = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"

        def origin():
            try:
                for index in range(sessions):
                    stream, peer = listener.accept()
                    with stream:
                        stream.settimeout(5)
                        stream.sendall(greeting)
                        body = bytearray()
                        while data := stream.recv(65536):
                            body.extend(data)
                        observations.append({
                            "index": index,
                            "peer": list(peer),
                            "payload": bytes(body),
                            "client_eof": True,
                        })
            except BaseException as error:  # surface thread failures in the test
                origin_error.append(f"{type(error).__name__}: {error}")

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                DIRECT_CONNECT_HALF_CLOSE_POLICY,
                eager_connect=True,
                native_policy=True,
            ) as proxy:
                batch_before = _process_resources(proxy.process.pid)
                samples = []
                for index, payload in enumerate(payloads):
                    before = _process_resources(proxy.process.pid)
                    before_targets = before["fd_targets"]
                    stream = tunnel(proxy.paths["alice"], authority)
                    try:
                        assert read_exact(stream, len(greeting)) == greeting
                        stream.sendall(payload)
                    finally:
                        # This is an abandoned client: it does not send a
                        # half-close or wait for an origin response.
                        stream.close()

                    deadline = time.monotonic() + 5
                    while len(observations) <= index:
                        assert time.monotonic() < deadline, (
                            "origin did not observe the abandoned CONNECT EOF"
                        )
                        time.sleep(0.01)
                    settle_started = time.monotonic()
                    settle_deadline = settle_started + 5
                    settle_attempts = 0
                    while True:
                        after = _process_resources(proxy.process.pid)
                        after_targets = after["fd_targets"]
                        new_targets = set(after_targets.values()) - set(before_targets.values())
                        new_sockets = sorted(
                            target for target in new_targets if target.startswith("socket:[")
                        )
                        retained_deleted = sorted(
                            target for target in new_targets if target.endswith(" (deleted)")
                        )
                        if not new_sockets and not retained_deleted:
                            break
                        assert time.monotonic() < settle_deadline, (
                            f"CONNECT {index} did not reclaim descriptors within 5s: "
                            f"sockets={new_sockets}, deleted={retained_deleted}"
                        )
                        settle_attempts += 1
                        time.sleep(0.005)
                    settle_seconds = time.monotonic() - settle_started
                    assert proxy.process.poll() is None
                    samples.append({
                        "index": index,
                        "before": before,
                        "after": after,
                        "new_socket_targets_after_close": new_sockets,
                        "retained_deleted_targets_after_close": retained_deleted,
                        "descriptor_settle_seconds": round(settle_seconds, 6),
                        "descriptor_settle_attempts": settle_attempts,
                    })

                thread.join(timeout=5)
                assert not thread.is_alive()
                assert not origin_error, origin_error
                assert len(observations) == sessions
                assert all(item["client_eof"] for item in observations)
                assert [item["payload"] for item in observations] == payloads
                batch_after = _process_resources(proxy.process.pid)
                events = proxy.events("proxy.tunnel")
                if proxy_backend == "rust":
                    provenance = json.loads(
                        (directory / "native-policy-provenance.json").read_text()
                    )
                    assert provenance == {
                        "backend": "rust",
                        "policy_mode": "native",
                        "policy_file": str(directory / "policy.toml"),
                        "temporary_policy_socket": None,
                        "temporary_policy_adapter": False,
                    }
                    deadline = time.monotonic() + 5
                    while len(events) < sessions:
                        assert time.monotonic() < deadline, (
                            "Rust CONNECT cancellation events did not settle"
                        )
                        time.sleep(0.01)
                        events = proxy.events("proxy.tunnel")
                    assert len(events) == sessions
                    assert all(event["agent"] == "alice" for event in events)
                    assert all(event["coverage"] == "opaque" for event in events)
                    assert [
                        (event["uploaded_bytes"], event["downloaded_bytes"])
                        for event in events
                    ] == [(len(payload), len(greeting)) for payload in payloads]
                (directory / "connect-cancellation-resources.json").write_text(
                    json.dumps(
                        {
                            "backend": proxy_backend,
                            "authority": authority,
                            "sessions": sessions,
                            "greeting_hex": greeting.hex(),
                            "payloads": [
                                {
                                    "length": len(payload),
                                    "sha256": hashlib.sha256(payload).hexdigest(),
                                    "prefix_hex": payload[:32].hex(),
                                    "suffix_hex": payload[-32:].hex(),
                                }
                                for payload in payloads
                            ],
                            "origin_observed": [
                                {
                                    "index": item["index"],
                                    "peer": item["peer"],
                                    "payload_length": len(item["payload"]),
                                    "payload_sha256": hashlib.sha256(
                                        item["payload"]
                                    ).hexdigest(),
                                    "client_eof": item["client_eof"],
                                }
                                for item in observations
                            ],
                            "resources": {
                                "batch_before": batch_before,
                                "sessions": samples,
                                "batch_after": batch_after,
                            },
                            "proxy_tunnel_events": events if proxy_backend == "rust" else [],
                            "native_policy_provenance": (
                                provenance if proxy_backend == "rust" else None
                            ),
                            "limits": [
                                "Three sequential raw CONNECT sessions with a server-first greeting and an abrupt client close after a bounded upload.",
                                "This measures closure and retained descriptor identity; it establishes no RSS/HWM ceiling, concurrency limit, long-duration stability, or OOM behavior.",
                                "The workload does not claim real SSH authentication or full production traffic coverage; those remain separate contract cases.",
                            ],
                        },
                        indent=2,
                    )
                    + "\n"
                )
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_configured_passthrough_server_first_half_close_keeps_canonical_lifecycle(proxy_backend, tmp_path):
    """A configured tunnel records one lifecycle pair over the physical socket lifetime."""
    if proxy_backend != "rust":
        pytest.skip("native policy provenance and canonical passthrough ownership are Rust evidence")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    greeting = b"configured-server-first\x00v1\n"
    payload = bytes(range(256)) * 512 + b"client-final-byte"
    final_response = b"configured-final-response\x00after-client-eof\n"
    observation = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        # The hostname is retained as the logical authority while the origin
        # observes the resolved loopback peer address.
        authority = f"localhost:{listener.getsockname()[1]}"

        def origin():
            try:
                stream, peer = listener.accept()
                observation["peer"] = peer
                with stream:
                    stream.settimeout(5)
                    stream.sendall(greeting)
                    body = bytearray()
                    while data := stream.recv(65536):
                        body.extend(data)
                    observation["payload"] = bytes(body)
                    observation["client_eof"] = True
                    stream.sendall(final_response)
                    stream.shutdown(socket.SHUT_WR)
                    observation["server_eof"] = True
            except BaseException as error:
                observation["error"] = f"{type(error).__name__}: {error}"

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                PASSTHROUGH_LIFECYCLE_POLICY,
                eager_connect=True,
                ignore_hosts=[authority],
                native_policy=True,
            ) as proxy:
                with tunnel(proxy.paths["alice"], authority) as stream:
                    assert read_exact(stream, len(greeting)) == greeting
                    stream.sendall(payload)
                    stream.shutdown(socket.SHUT_WR)
                    observed_final = read_all(stream)
                    assert observed_final == final_response
                thread.join(timeout=5)
                assert not thread.is_alive()
                assert "error" not in observation, observation
                assert observation["peer"][0] == "127.0.0.1"
                assert observation["payload"] == payload
                assert observation["client_eof"] is True
                assert observation["server_eof"] is True

                provenance = json.loads((directory / "native-policy-provenance.json").read_text())
                assert provenance["backend"] == "rust"
                assert provenance["policy_mode"] == "native"
                assert provenance["temporary_policy_adapter"] is False
                rows = wait_for_passthrough_audit(directory, 2)
                assert [row["event"] for row in rows] == [
                    "traffic.passthrough_start",
                    "traffic.passthrough_end",
                ]
                assert rows[0]["host"] == "localhost"
                assert rows[1]["host"] == "localhost"
                assert rows[0]["details"] == {
                    "port": listener.getsockname()[1],
                    "transport": "tcp",
                    "client": "10.0.0.2",
                }
                assert rows[1]["details"]["port"] == listener.getsockname()[1]
                assert rows[1]["details"]["transport"] == "tcp"
                assert rows[1]["details"]["client"] == "10.0.0.2"
                assert isinstance(rows[1]["details"]["duration_ms"], int)
                (directory / "passthrough-lifecycle.json").write_text(json.dumps({
                    "backend": proxy_backend,
                    "logical_authority": authority,
                    "physical_peer": list(observation["peer"]),
                    "upstream": {
                        "greeting_hex": greeting.hex(),
                        "payload_length": len(payload),
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "final_response_hex": final_response.hex(),
                    },
                    "client_observed": {
                        "greeting_hex": greeting.hex(),
                        "final_response_hex": observed_final.hex(),
                    },
                    "passthrough_events": rows,
                    "native_policy_provenance": provenance,
                }, indent=2) + "\n")
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_configured_passthrough_denied_agent_has_no_origin_contact(proxy_backend, tmp_path):
    """A policy denial remains before passthrough dialing, even when matched."""
    if proxy_backend != "rust":
        pytest.skip("native policy provenance and canonical passthrough ownership are Rust evidence")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.25)
        authority = f"localhost:{listener.getsockname()[1]}"
        with launch_proxy(
            proxy_backend,
            directory,
            PASSTHROUGH_LIFECYCLE_POLICY,
            eager_connect=True,
            ignore_hosts=[authority],
            native_policy=True,
        ) as proxy:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(proxy.paths["bob"])
                client.sendall(
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                    "X-Denied-Canary: must-not-egress\r\nConnection: close\r\n\r\n".encode()
                )
                response = read_until(client, b"\r\n\r\n")
            assert response.startswith(b"HTTP/1.1 403"), response
            with pytest.raises(socket.timeout):
                listener.accept()
            assert passthrough_audit(directory) == []
            assert proxy.events("proxy.egress") == []
            provenance = json.loads((directory / "native-policy-provenance.json").read_text())
            assert provenance["policy_mode"] == "native"
            (directory / "passthrough-denial.json").write_text(json.dumps({
                "backend": proxy_backend,
                "logical_authority": authority,
                "origin_accepts": 0,
                "response_head_hex": response.hex(),
                "passthrough_events": [],
                "proxy_egress_events": [],
                "native_policy_provenance": provenance,
            }, indent=2) + "\n")


def test_configured_passthrough_client_half_close_keeps_final_response(proxy_backend, tmp_path):
    """The client EOF does not discard a response still pending from the origin."""
    if proxy_backend != "rust":
        pytest.skip("native policy provenance and canonical passthrough ownership are Rust evidence")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    payload = bytes(range(256)) * 384 + b"client-final-byte"
    final_response = b"configured-response-after-client-eof\x00v2\n"
    observation = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"localhost:{listener.getsockname()[1]}"

        def origin():
            try:
                stream, peer = listener.accept()
                observation["peer"] = peer
                with stream:
                    stream.settimeout(5)
                    body = bytearray()
                    while data := stream.recv(65536):
                        body.extend(data)
                    observation["payload"] = bytes(body)
                    observation["client_eof"] = True
                    stream.sendall(final_response)
                    stream.shutdown(socket.SHUT_WR)
                    observation["server_eof"] = True
            except BaseException as error:
                observation["error"] = f"{type(error).__name__}: {error}"

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                PASSTHROUGH_LIFECYCLE_POLICY,
                eager_connect=True,
                ignore_hosts=[authority],
                native_policy=True,
            ) as proxy:
                with tunnel(proxy.paths["alice"], authority) as stream:
                    stream.sendall(payload)
                    stream.shutdown(socket.SHUT_WR)
                    observed_final = read_all(stream)
                    assert observed_final == final_response
                thread.join(timeout=5)
                assert not thread.is_alive()
                assert "error" not in observation, observation
                assert observation["peer"][0] == "127.0.0.1"
                assert observation["payload"] == payload
                assert observation["client_eof"] is True
                assert observation["server_eof"] is True

                provenance = json.loads((directory / "native-policy-provenance.json").read_text())
                assert provenance["policy_mode"] == "native"
                assert provenance["temporary_policy_adapter"] is False
                rows = wait_for_passthrough_audit(directory, 2)
                assert [row["event"] for row in rows] == [
                    "traffic.passthrough_start",
                    "traffic.passthrough_end",
                ]
                assert all(row["host"] == "localhost" for row in rows)
                assert all(row["details"]["port"] == listener.getsockname()[1] for row in rows)
                assert all(row["details"]["transport"] == "tcp" for row in rows)
                assert all(row["details"]["client"] == "10.0.0.2" for row in rows)
                assert isinstance(rows[1]["details"]["duration_ms"], int)
                (directory / "passthrough-opposite-half-close.json").write_text(json.dumps({
                    "backend": proxy_backend,
                    "logical_authority": authority,
                    "physical_peer": list(observation["peer"]),
                    "payload_length": len(payload),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "final_response_hex": final_response.hex(),
                    "client_observed_final_response_hex": observed_final.hex(),
                    "passthrough_events": rows,
                    "native_policy_provenance": provenance,
                }, indent=2) + "\n")
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_configured_passthrough_refusal_records_error_after_no_accept(proxy_backend, tmp_path):
    """A matched closed endpoint emits an error and never becomes a session."""
    if proxy_backend != "rust":
        pytest.skip("native policy provenance and canonical passthrough ownership are Rust evidence")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        authority = f"127.0.0.1:{listener.getsockname()[1]}"
    with launch_proxy(
        proxy_backend,
        directory,
        PASSTHROUGH_LIFECYCLE_POLICY,
        eager_connect=True,
        ignore_hosts=[authority],
        native_policy=True,
    ) as proxy:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(proxy.paths["alice"])
            client.sendall(
                f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
            )
            response = read_until(client, b"\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 502"), response
        rows = wait_for_passthrough_audit(directory, 1)
        assert [row["event"] for row in rows] == ["traffic.passthrough_error"]
        assert rows[0]["host"] == "127.0.0.1"
        assert rows[0]["details"]["port"] == int(authority.rsplit(":", 1)[1])
        assert rows[0]["details"]["transport"] == "tcp"
        assert rows[0]["details"]["client"] == "10.0.0.2"
        assert "refus" in rows[0]["details"]["error"].lower()
        provenance = json.loads((directory / "native-policy-provenance.json").read_text())
        assert provenance["policy_mode"] == "native"
        assert provenance["temporary_policy_adapter"] is False
        (directory / "passthrough-refusal.json").write_text(json.dumps({
            "backend": proxy_backend,
            "logical_authority": authority,
            "response_head_hex": response.hex(),
            "origin_listener": "closed-before-connect",
            "passthrough_events": rows,
            "native_policy_provenance": provenance,
        }, indent=2) + "\n")


def test_configured_passthrough_graceful_shutdown_releases_live_socket(proxy_backend, tmp_path):
    """SIGTERM closes an admitted passthrough socket before its end event."""
    if proxy_backend != "rust":
        pytest.skip("native policy provenance and canonical passthrough ownership are Rust evidence")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    greeting = b"shutdown-server-first\x00v1\n"
    observation = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        authority = f"localhost:{listener.getsockname()[1]}"

        def origin():
            try:
                stream, peer = listener.accept()
                observation["peer"] = peer
                with stream:
                    stream.settimeout(5)
                    stream.sendall(greeting)
                    observation["greeting_sent"] = True
                    observation["eof"] = stream.recv(1) == b""
            except BaseException as error:
                observation["error"] = f"{type(error).__name__}: {error}"

        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend,
                directory,
                PASSTHROUGH_LIFECYCLE_POLICY,
                eager_connect=True,
                ignore_hosts=[authority],
                native_policy=True,
            ) as proxy:
                stream = tunnel(proxy.paths["alice"], authority)
                with stream:
                    assert read_exact(stream, len(greeting)) == greeting
                    proxy.process.send_signal(signal.SIGTERM)
                    assert proxy.process.wait(timeout=5) == 0
                    assert stream.recv(1) == b""
                thread.join(timeout=5)
                assert not thread.is_alive()
                assert "error" not in observation, observation
                assert observation["peer"][0] == "127.0.0.1"
                assert observation["greeting_sent"] is True
                assert observation["eof"] is True
                rows = wait_for_passthrough_audit(directory, 2)
                assert [row["event"] for row in rows] == [
                    "traffic.passthrough_start",
                    "traffic.passthrough_end",
                ]
                assert all(row["host"] == "localhost" for row in rows)
                assert isinstance(rows[1]["details"]["duration_ms"], int)
                provenance = json.loads((directory / "native-policy-provenance.json").read_text())
                assert provenance["policy_mode"] == "native"
                assert provenance["temporary_policy_adapter"] is False
                (directory / "passthrough-shutdown.json").write_text(json.dumps({
                    "backend": proxy_backend,
                    "logical_authority": authority,
                    "physical_peer": list(observation["peer"]),
                    "greeting_hex": greeting.hex(),
                    "client_observed_eof": True,
                    "origin_observed_eof": observation["eof"],
                    "passthrough_events": rows,
                    "native_policy_provenance": provenance,
                }, indent=2) + "\n")
        finally:
            thread.join(timeout=6)
            assert not thread.is_alive()


def test_denied_connect_does_not_contact_raw_origin(proxy_backend, tmp_path):
    """The denied agent gets no tunnel and the raw listener sees no accept."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.25)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"
        with launch_proxy(
            proxy_backend,
            tmp_path / proxy_backend,
            DIRECT_CONNECT_HALF_CLOSE_POLICY,
            eager_connect=True,
            native_policy=True,
        ) as proxy:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(proxy.paths["bob"])
                client.sendall(
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                    "X-Denied-Canary: must-not-egress\r\nConnection: close\r\n\r\n".encode()
                )
                response = read_until(client, b"\r\n\r\n")
            assert response.startswith(b"HTTP/1.1 403"), response
            with pytest.raises(socket.timeout):
                listener.accept()
            assert proxy.events("proxy.egress") == []
            (tmp_path / proxy_backend / "denied-observation.json").write_text(json.dumps({
                "backend": proxy_backend,
                "authority": authority,
                "response_head_hex": response.hex(),
                "origin_accepts": 0,
                "proxy_egress_events": proxy.events("proxy.egress"),
                "canary_header": "X-Denied-Canary: must-not-egress",
            }, indent=2) + "\n")
            if proxy_backend == "rust":
                provenance = json.loads((tmp_path / proxy_backend / "native-policy-provenance.json").read_text())
                assert provenance["policy_mode"] == "native"
                assert provenance["temporary_policy_adapter"] is False


def test_incomplete_connect_client_half_close_does_not_dial_origin(
    proxy_backend, tmp_path, request
):
    """An EOF before CONNECT headers complete cannot create an origin leg."""
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason="Existing CONNECT adapter turns a client half-close into a full close",
        ))
    greeting = b"complete-connect-control\x00v1\n"
    final_response = b"complete-connect-final\x00v1\n"
    payload = b"complete-connect-payload\x00" * 128
    observations = []
    origin_error = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.25)
        authority = f"127.0.0.1:{listener.getsockname()[1]}"

        def origin():
            try:
                while len(observations) < 1:
                    stream, peer = listener.accept()
                    with stream:
                        stream.settimeout(5)
                        stream.sendall(greeting)
                        body = bytearray()
                        while data := stream.recv(65536):
                            body.extend(data)
                        observations.append({
                            "peer": list(peer),
                            "payload": bytes(body),
                        })
                        if body == payload:
                            stream.sendall(final_response)
                            stream.shutdown(socket.SHUT_WR)
            except BaseException as error:  # surface thread failures in the test
                origin_error.append(f"{type(error).__name__}: {error}")

        thread = None
        try:
            with launch_proxy(
                proxy_backend,
                tmp_path / proxy_backend,
                DIRECT_CONNECT_HALF_CLOSE_POLICY,
                eager_connect=True,
                native_policy=True,
            ) as proxy:
                with socket.socket(socket.AF_UNIX) as incomplete:
                    incomplete.settimeout(5)
                    incomplete.connect(proxy.paths["alice"])
                    incomplete.sendall(
                        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode()
                    )
                    incomplete.shutdown(socket.SHUT_WR)
                    # Closing immediately after the request-side EOF models a
                    # canceled client; it must not cause a speculative origin
                    # dial before a complete request exists.

                with pytest.raises(socket.timeout):
                    listener.accept()

                listener.settimeout(5)
                thread = threading.Thread(target=origin)
                thread.start()
                with tunnel(proxy.paths["alice"], authority) as complete:
                    assert read_exact(complete, len(greeting)) == greeting
                    complete.sendall(payload)
                    complete.shutdown(socket.SHUT_WR)
                    assert read_all(complete) == final_response

                thread.join(timeout=5)
                assert not thread.is_alive()
                assert not origin_error, origin_error
                assert len(observations) == 1
                assert observations[0]["payload"] == payload
                events = proxy.events("proxy.tunnel")
                if proxy_backend == "rust":
                    provenance = json.loads(
                        (tmp_path / proxy_backend / "native-policy-provenance.json").read_text()
                    )
                    assert provenance == {
                        "backend": "rust",
                        "policy_mode": "native",
                        "policy_file": str(tmp_path / proxy_backend / "policy.toml"),
                        "temporary_policy_socket": None,
                        "temporary_policy_adapter": False,
                    }
                    assert len(events) == 1
                    assert events[0]["agent"] == "alice"
                    assert events[0]["coverage"] == "opaque"
                    assert events[0]["uploaded_bytes"] == len(payload)
                    assert events[0]["downloaded_bytes"] == len(greeting) + len(final_response)
                    assert events[0]["outcome"] == "completed"
                (tmp_path / proxy_backend / "incomplete-connect-half-close.json").write_text(
                    json.dumps(
                        {
                            "backend": proxy_backend,
                            "authority": authority,
                            "incomplete_request": (
                                f"CONNECT {authority} HTTP/1.1\\r\\n"
                                f"Host: {authority}\\r\\n"
                            ),
                            "client_write_eof_before_headers_terminator": True,
                            "origin_accepts": len(observations),
                            "origin_payload_sha256": hashlib.sha256(
                                observations[0]["payload"]
                            ).hexdigest(),
                            "completed_control": {
                                "greeting_hex": greeting.hex(),
                                "payload_length": len(payload),
                                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                                "final_response_hex": final_response.hex(),
                            },
                            "proxy_tunnel_events": events if proxy_backend == "rust" else [],
                            "native_policy_provenance": (
                                provenance if proxy_backend == "rust" else None
                            ),
                            "limits": [
                                "One incomplete CONNECT request followed by one valid direct CONNECT control.",
                                "This proves no origin dial for the incomplete request; it does not establish a duration, concurrency, or resource-growth bound.",
                            ],
                        },
                        indent=2,
                    )
                    + "\n"
                )
        finally:
            if thread is not None:
                thread.join(timeout=6)
                assert not thread.is_alive()


@pytest.mark.skipif(os.environ.get("SAFEYOLO_RUN_SSH_CONTRACT") != "1", reason="Opt-in owned OpenSSH daemon; requires installed ssh, ssh-keygen and sshd")
@pytest.mark.parametrize("passthrough", [False, True])
def test_real_openssh_preserves_server_first_output_and_client_input(proxy_backend, tmp_path, passthrough):
    programs = {name: shutil.which(name) for name in ("ssh", "ssh-keygen", "sshd")}
    assert all(programs.values()), programs
    private = tmp_path / "ssh"
    private.mkdir(mode=0o700)
    for name in ("host", "client"):
        subprocess.run([programs["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", str(private / name)], check=True)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    username = pwd.getpwuid(os.getuid()).pw_name
    configuration = private / "sshd.conf"
    configuration.write_text("\n".join([
        "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {private / 'host'}",
        f"PidFile {private / 'sshd.pid'}", f"AuthorizedKeysFile {private / 'client.pub'}",
        "UsePAM yes", "StrictModes no", "PubkeyAuthentication yes", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PermitRootLogin no", "PrintMotd no", f"AllowUsers {username}",
    ]) + "\n")
    host_key = (private / "host.pub").read_text().split()
    known = private / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {host_key[0]} {host_key[1]}\n")
    with (private / "sshd.log").open("w") as log:
        server = subprocess.Popen([programs["sshd"], "-D", "-e", "-f", str(configuration)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None, (private / "sshd.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline
                    time.sleep(0.025)
            authority = f"127.0.0.1:{port}"
            with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY, eager_connect=True,
                              ignore_hosts=[authority] if passthrough else []) as proxy:
                proxy_command = shlex.join([sys.executable, "-m", "tests.proxy_migration.ssh_bridge", proxy.paths["alice"], authority])
                remote = "python3 -c 'import sys,hashlib; sys.stdout.buffer.write(b\"S\"*524288); sys.stdout.buffer.flush(); data=sys.stdin.buffer.read(); print(hashlib.sha256(data).hexdigest()); sys.stderr.write(\"owned-ssh-stderr\\n\")'"
                command = [programs["ssh"], "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                           "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
                           "-i", str(private / "client"), "-p", str(port), "-o", f"ProxyCommand={proxy_command}",
                           f"{username}@127.0.0.1", remote]
                payload = bytes(range(256)) * 4096
                completed = subprocess.run(command, input=payload, capture_output=True, timeout=20)
                assert completed.returncode == 0, completed.stderr.decode(errors="replace")
                assert completed.stdout[:524288] == b"S" * 524288
                assert completed.stdout[524288:].strip() == hashlib.sha256(payload).hexdigest().encode()
                assert b"owned-ssh-stderr" in completed.stderr
        finally:
            server.terminate()
            server.wait(timeout=5)
            for name in ("host", "client"):
                (private / name).unlink(missing_ok=True)
