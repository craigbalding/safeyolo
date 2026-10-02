#!/usr/bin/env python3
"""Run the finite P2 clients from the installed SafeYolo Linux guest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from tests.blackbox.isolation.installed_ingress import (
    AGENT_API,
    GUEST_PROXY,
    GUEST_SOCKET,
    forwarder_identity,
    request,
)
from tests.proxy_contracts.websocket_peer import Peer, read_head

HOST = "failing.test"
PROXY = ("127.0.0.1", 8080)
PACKAGE = "safeyolo-p2-fixture"
PAYLOAD = Path("/usr/local/share/safeyolo-blackbox/p2-package")


def command(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    assert result.returncode == 0, f"{args[0]} exited {result.returncode}: {result.stderr[-600:]}"
    return result


def context(agent: str) -> str:
    return f"run=installed-p2;agent={agent}"


def proxy_get(path: str, agent: str) -> tuple[bytes, str]:
    connection = http.client.HTTPConnection(*PROXY, timeout=15)
    try:
        connection.request("GET", f"http://{HOST}{path}", headers={
            "Host": HOST, "X-SafeYolo-Trace": "1",
            "X-SafeYolo-Test-Context": context(agent),
        })
        response = connection.getresponse()
        assert response.status == 200, f"owned origin returned {response.status} for {path}"
        request_id = response.getheader("X-SafeYolo-Request-Id")
        assert request_id and request_id.startswith("req-"), "package fetch has no request ID"
        body = response.read(2_000_001)
        assert len(body) <= 2_000_000, "P2 package response exceeded its bound"
        token = Path("/app/agent_token").read_text().strip()
        traced = request(PROXY[0], PROXY[1], f"{AGENT_API}/trace?request_id={request_id}", {
            "Host": "_safeyolo.proxy.internal", "Authorization": f"Bearer {token}",
        })
        assert traced["status"] == 200, f"package trace returned {traced['status']}"
        trace = json.loads(bytes.fromhex(traced["body_hex"]))
        assert trace["agent_id"] == agent, f"package request attributed to {trace['agent_id']!r}"
        return body, request_id
    finally:
        connection.close()


def package_and_repo(marker: str, package_sha: str, repo_commit: str, agent: str) -> dict:
    for program in ("dpkg", "git"):
        assert shutil.which(program), f"guest requires {program}"
    with tempfile.TemporaryDirectory(prefix="safeyolo-p2-") as scratch:
        directory = Path(scratch)
        package = directory / f"{PACKAGE}.deb"
        body, request_id = proxy_get(f"/p2/package/{PACKAGE}.deb", agent)
        package.write_bytes(body)
        assert hashlib.sha256(package.read_bytes()).hexdigest() == package_sha
        try:
            command(["dpkg", "-i", str(package)])
            status = command(["dpkg-query", "-W", "-f=${Status}", PACKAGE]).stdout
            assert status == "install ok installed", status
            assert PAYLOAD.read_text() == f"package:{marker}\n"
        finally:
            command(["dpkg", "--purge", PACKAGE])
        assert not PAYLOAD.exists(), "fixture package payload survived purge"

        checkout = directory / "repository"
        command([
            "git", "-c", f"http.proxy={GUEST_PROXY}", "-c", "protocol.version=0",
            "-c", f"http.extraHeader=X-SafeYolo-Test-Context: {context(agent)}",
            "clone", f"http://{HOST}/p2/repo.git", str(checkout),
        ], timeout=45)
        assert command(["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.strip() == repo_commit
        assert (checkout / "P2-MARKER.txt").read_text() == f"repository:{marker}\n"
    return {"package_sha256": package_sha, "package_request_id": request_id,
            "trace_agent": agent, "package_installed": True, "package_purged": True,
            "repository_commit": repo_commit, "repository_marker": marker}


def _event(stream: socket.socket) -> bytes:
    message = bytearray()
    while not message.endswith(b"\n\n"):
        data = stream.recv(1)
        assert data, "SSE stream ended before the next event"
        message.extend(data)
        assert len(message) < 8192, "SSE event exceeded the P2 bound"
    return bytes(message)


def sse(marker: str, agent: str) -> dict:
    with socket.create_connection(PROXY, timeout=8) as stream:
        stream.settimeout(8)
        stream.sendall((f"GET http://{HOST}/p2/sse/{marker} HTTP/1.1\r\n"
                        f"Host: {HOST}\r\nX-SafeYolo-Test-Context: {context(agent)}\r\n"
                        "Connection: close\r\n\r\n").encode())
        head, headers = read_head(stream)
        assert head.split()[1] == "200" and headers["content-type"] == ["text/event-stream"]
        first = _event(stream)
        assert first == f"data: first:{marker}\n\n".encode()
        print("P2_SSE_FIRST=" + json.dumps({"marker": marker, "event": first.decode()}), flush=True)
        last = _event(stream)
        assert last == f"data: last:{marker}\n\n".encode()
        assert stream.recv(1) == b"", "SSE origin did not complete"
    return {"first": first.decode(), "last": last.decode()}


def websocket(marker: str, agent: str, *, tls: bool) -> dict:
    with socket.create_connection(PROXY, timeout=8) as raw:
        raw.settimeout(8)
        if tls:
            raw.sendall((f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n"
                         f"X-SafeYolo-Test-Context: {context(agent)}\r\n\r\n").encode())
            head, _ = read_head(raw)
            assert head.split()[1] == "200", head
            tls_context = ssl.create_default_context()
            stream = tls_context.wrap_socket(raw, server_hostname=HOST)
            target = f"/p2/ws/{marker}"
        else:
            stream = raw
            target = f"http://{HOST}/p2/ws/{marker}"
        with stream:
            key = base64.b64encode(os.urandom(16)).decode()
            stream.sendall((f"GET {target} HTTP/1.1\r\nHost: {HOST}\r\n"
                            f"X-SafeYolo-Test-Context: {context(agent)}\r\n"
                            "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            head, headers = read_head(stream)
            assert head.split()[1] == "101", head
            expected_accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()).decode()
            assert headers["sec-websocket-accept"] == [expected_accept]
            peer = Peer(stream, client=True, compressed=False)
            peer.send(1, f"client:{marker}".encode())
            assert peer.receive() == (1, f"server:{marker}".encode())
            peer.close()
            assert peer.receive()[0] == 8
    return {"scheme": "wss" if tls else "ws", "client": f"client:{marker}",
            "server": f"server:{marker}"}


def denied_websocket(marker: str, agent: str) -> dict:
    with socket.create_connection(PROXY, timeout=8) as stream:
        stream.settimeout(8)
        stream.sendall((f"GET http://evil.com/p2/ws/{marker}-blocked HTTP/1.1\r\n"
                        f"Host: evil.com\r\nX-SafeYolo-Test-Context: {context(agent)}\r\n"
                        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        head, headers = read_head(stream)
        assert head.split()[1] == "403", head
        assert headers.get("x-blocked-by") == ["network-guard"], headers
    return {"status": 403, "blocked_by": "network-guard"}


def ssh_command(marker: str, username: str, agent: str) -> dict:
    assert shutil.which("ssh"), "guest requires OpenSSH client"
    with tempfile.TemporaryDirectory(prefix="safeyolo-p2-ssh-") as scratch:
        key = Path(scratch) / "client"
        key.write_bytes(Path("/safeyolo/p2-client-key").read_bytes())
        key.chmod(0o600)
        known = Path("/safeyolo/p2-known-hosts")
        assert known.is_file(), "pinned P2 SSH host key is missing"
        bridge = shlex.join([
            "python3", "-m", "tests.proxy_contracts.ssh_bridge",
            "8080", f"{HOST}:22", "--tcp-proxy", "--test-context", context(agent),
        ])
        result = command([
            "ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=8", "-o", f"ProxyCommand={bridge}",
            "-i", str(key), f"{username}@{HOST}", f"p2-marker {marker}",
        ], timeout=25)
        assert result.stdout == f"ssh-server:{marker}", result.stdout
    return {"server": result.stdout, "pinned_host_key": True, "port": 22}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("package-repo", "sse", "wss-ssh"), required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--package-sha")
    parser.add_argument("--repo-commit")
    parser.add_argument("--ssh-user")
    args = parser.parse_args()
    assert args.marker.startswith("p2-") and len(args.marker) == 35
    assert os.environ["HTTP_PROXY"] == GUEST_PROXY
    assert GUEST_SOCKET.is_socket(), "installed per-agent proxy socket is missing"
    forwarder = forwarder_identity()

    if args.phase == "package-repo":
        assert args.package_sha and args.repo_commit
        result = package_and_repo(args.marker, args.package_sha, args.repo_commit, args.agent)
    elif args.phase == "sse":
        result = sse(args.marker, args.agent)
    else:
        assert args.ssh_user
        result = {
            "wss": websocket(args.marker, args.agent, tls=True),
            "blocked_canary": denied_websocket(args.marker, args.agent),
            "ssh": ssh_command(args.marker, args.ssh_user, args.agent),
        }
    print("P2_OBSERVATION=" + json.dumps({"phase": args.phase, "marker": args.marker,
                                         "guest_proxy": GUEST_PROXY, "forwarder": forwarder,
                                         "result": result}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
