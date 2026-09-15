"""Opaque CONNECT contracts through both implementations and owned endpoints."""

import hashlib
import os
import pwd
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

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


@pytest.mark.parametrize("method", ["SSH", "SSHGET", "SSH-EXT", "SSH-2.0-test"])
@pytest.mark.parametrize("first", [0, 1, 3])
def test_ssh_prefixed_http_methods_remain_inspected(proxy_backend, tmp_path, method, first, request):
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(strict=True, reason="Existing SSH-prefix classifier bypasses denied HTTP extension methods"))
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
                    message = f"{method} /forbidden HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
                    if first:
                        stream.sendall(message[:first])
                        time.sleep(0.025)
                    stream.sendall(message[first:])
                    response = bytearray()
                    while data := stream.recv(8192):
                        response.extend(data)
                    assert response.startswith(b"HTTP/1.1 403"), bytes(response)
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
