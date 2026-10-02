#!/usr/bin/env python3
"""Send the KVM P1 controls from inside the real blackbox guest."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

REQUEST_ID = re.compile(r"req-[0-9a-f]{32}\Z")
GUEST_SOCKET = Path("/safeyolo/proxy/proxy.sock")
AGENT_API = "http://_safeyolo.proxy.internal"
GUEST_PROXY = "http://127.0.0.1:8080"


def is_mounted_forwarder(argv: list[str]) -> bool:
    """Recognize the guest listener and the mounted per-agent UDS route."""
    if len(argv) != 3 or Path(argv[0]).name != "socat":
        return False
    listener, *options = argv[1].split(",")
    return (
        listener == "TCP-LISTEN:8080"
        and "bind=127.0.0.1" in options
        and argv[2].split(",", 1)[0] == f"UNIX-CONNECT:{GUEST_SOCKET}"
    )


def forwarder_identity(proc_root: Path = Path("/proc")) -> dict:
    """Observe the running guest TCP-to-agent-UDS forwarder."""
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdecimal():
            continue
        try:
            argv = [part.decode() for part in (pid_dir / "cmdline").read_bytes().split(b"\0") if part]
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            # A process may exit while /proc is enumerated.
            continue
        if is_mounted_forwarder(argv):
            return {"pid": int(pid_dir.name), "argv": argv}
    raise AssertionError("guest localhost proxy has no running SafeYolo UDS forwarder")


def bridge(platform: str, proc_root: Path = Path("/proc")) -> dict:
    assert os.environ["HTTP_PROXY"] == GUEST_PROXY
    if platform == "vz":
        forwarder = None
        for directory in proc_root.iterdir():
            if not directory.name.isdecimal():
                continue
            try:
                argv = [part.decode() for part in (directory / "cmdline").read_bytes().split(b"\0") if part]
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if (
                len(argv) == 3
                and Path(argv[0]).name == "socat"
                and argv[1].startswith("TCP-LISTEN:8080,")
                and argv[2].startswith("VSOCK-CONNECT:2:1080,")
            ):
                forwarder = {"pid": int(directory.name), "argv": argv}
                break
        assert forwarder is not None, "guest localhost proxy has no VZ forwarder"
    else:
        forwarder = forwarder_identity(proc_root)
    argv = forwarder["argv"]
    if platform == "vz":
        assert argv[2].startswith("VSOCK-CONNECT:2:1080,"), argv
    else:
        assert GUEST_SOCKET.is_socket() and argv[2].startswith(f"UNIX-CONNECT:{GUEST_SOCKET},"), argv
    return forwarder



def request(proxy_host: str, proxy_port: int, target: str, headers: dict[str, str]) -> dict:
    """Use the configured guest proxy, with no alternate network path."""
    connection = http.client.HTTPConnection(proxy_host, proxy_port, timeout=10)
    try:
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        body = response.read(1_000_001)
        assert len(body) <= 1_000_000, "proxy response exceeded the P1 bound"
        return {
            "status": response.status,
            "headers": [(name.lower(), value) for name, value in response.getheaders()],
            "body_hex": body.hex(),
        }
    finally:
        connection.close()


def one_header(response: dict, name: str) -> str:
    values = [value for key, value in response["headers"] if key == name]
    assert len(values) == 1, f"expected one {name} header: {values!r}"
    return values[0]


def traced_request(
    proxy_host: str,
    proxy_port: int,
    agent: str,
    target: str,
    marker: str,
    token: str,
) -> dict:
    authority = urlsplit(target).netloc
    response = request(
        proxy_host,
        proxy_port,
        target,
        {
            "Host": authority,
            "X-SafeYolo-Trace": "1",
            "X-SafeYolo-Test-Context": f"run=kvm-p1;agent={agent}",
            "X-Probe-Marker": marker,
        },
    )
    identifier = one_header(response, "x-safeyolo-request-id")
    assert REQUEST_ID.fullmatch(identifier), f"invalid request ID: {identifier!r}"
    traced = request(
        proxy_host,
        proxy_port,
        f"{AGENT_API}/trace?request_id={identifier}",
        {"Host": "_safeyolo.proxy.internal", "Authorization": f"Bearer {token}"},
    )
    assert traced["status"] == 200, f"trace failed for {identifier}: {traced['status']}"
    trace = json.loads(bytes.fromhex(traced["body_hex"]))
    assert trace["request_id"] == identifier
    assert trace["agent_id"] == agent, f"request attributed to {trace['agent_id']!r}"
    guard = [step for step in trace["steps"] if step.get("addon") == "network-guard" and step.get("hook") == "request"]
    assert len(guard) == 1, f"network-guard trace missing for {identifier}"
    return {
        "status": response["status"],
        "body_hex": response["body_hex"],
        "blocked_by": next((value for key, value in response["headers"] if key == "x-blocked-by"), None),
        "request_id": identifier,
        "trace_agent": trace["agent_id"],
        "guard": {key: guard[0].get(key) for key in ("state", "outcome", "host", "port", "method")},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()
    assert re.fullmatch(r"p1-[0-9a-f]{32}", args.marker)

    proxy = urlsplit(os.environ["HTTP_PROXY"])
    assert os.environ["HTTP_PROXY"] == GUEST_PROXY
    assert proxy.scheme == "http" and proxy.hostname and proxy.port
    assert GUEST_SOCKET.is_socket(), f"missing guest bridge: {GUEST_SOCKET}"
    socket_stat = GUEST_SOCKET.stat()
    forwarder = forwarder_identity()
    token = Path("/app/agent_token").read_text().strip()
    assert token and "\n" not in token and "\r" not in token

    allowed = traced_request(
        proxy.hostname,
        proxy.port,
        args.agent,
        f"http://httpbin.org/{args.marker}",
        args.marker,
        token,
    )
    denied = traced_request(
        proxy.hostname,
        proxy.port,
        args.agent,
        f"http://evil.com/{args.marker}-denied",
        args.marker,
        token,
    )
    print(
        "P1_OBSERVATION="
        + json.dumps(
            {
                "guest_socket": str(GUEST_SOCKET),
                "guest_socket_mode": oct(stat.S_IMODE(socket_stat.st_mode)),
                "guest_proxy": os.environ["HTTP_PROXY"],
                "forwarder": forwarder,
                "allow": allowed,
                "deny": denied,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
