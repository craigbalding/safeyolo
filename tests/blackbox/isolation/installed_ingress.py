#!/usr/bin/env python3
"""Send installed ingress controls from inside a real gVisor guest."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import stat
from pathlib import Path
from urllib.parse import urlsplit

REQUEST_ID = re.compile(r"req-[0-9a-f]{32}\Z")
GUEST_SOCKET = Path("/safeyolo/proxy/proxy.sock")
AGENT_API = "http://_safeyolo.proxy.internal"
GUEST_PROXY = "http://127.0.0.1:8080"


def is_mounted_forwarder(argv: list[str]) -> bool:
    """Recognize the guest listener and the mounted per-agent UDS route."""
    if len(argv) != 3 or Path(argv[0]).name != "sy-proxy-relay":
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
                and Path(argv[0]).name == "sy-proxy-relay"
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
        assert len(body) <= 1_000_000, "proxy response exceeded the ingress bound"
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
    *,
    claimed_agent: str | None = None,
    claimed_source: str | None = None,
) -> dict:
    authority = urlsplit(target).netloc
    headers = {
        "Host": authority,
        "X-SafeYolo-Trace": "1",
        "X-SafeYolo-Test-Context": f"run=installed-ingress;agent={claimed_agent or agent}",
        "X-Probe-Marker": marker,
    }
    if claimed_agent is not None:
        headers["X-SafeYolo-Agent"] = claimed_agent
    if claimed_source is not None:
        headers.update({"X-SafeYolo-Source": claimed_source, "X-Forwarded-For": claimed_source,
                        "Forwarded": f"for={claimed_source}"})
    response = request(
        proxy_host,
        proxy_port,
        target,
        headers,
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
    guard = [step for step in trace["steps"] if step.get("control") == "network" and step.get("hook") == "request"]
    assert len(guard) == 1, f"native network control trace missing for {identifier}"
    return {
        "status": response["status"],
        "body_hex": response["body_hex"],
        "blocked_by": next((value for key, value in response["headers"] if key == "x-blocked-by"), None),
        "request_id": identifier,
        "trace_agent": trace["agent_id"],
        "guard": {key: guard[0].get(key) for key in ("state", "outcome", "host", "port", "method")},
    }


def peer_boundary(peer_socket: str, peer_state: str, own_state: str, value: str) -> dict:
    """Require working own mounts before probing the peer's real host paths."""
    assert Path(own_state).read_text() == value, "own persistent-home positive control failed"
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(3)
        control.connect(str(GUEST_SOCKET))
    refusals = []
    with socket.socket(socket.AF_UNIX) as other:
        other.settimeout(3)
        try:
            other.connect(peer_socket)
        except OSError as error:
            refusals.append({"socket": peer_socket, "errno": error.errno, "error": str(error)})
        else:
            raise AssertionError("guest reached the peer's private socket")
    try:
        Path(peer_state).read_bytes()
    except OSError as error:
        refusals.append({"state": peer_state, "errno": error.errno, "error": str(error)})
    else:
        raise AssertionError("guest read the peer's private state")
    return {"uid": os.geteuid(), "own_socket_connected": True, "own_state_read": True, "refusals": refusals}


def stopped_listener() -> dict:
    """Observe refusal through the same guest forwarder used by successful requests."""
    try:
        response = request("127.0.0.1", 8080, f"{AGENT_API}/health", {"Host": "_safeyolo.proxy.internal"})
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected) as error:
        return {"error_type": type(error).__name__, "error": str(error)}
    raise AssertionError(f"stopped listener returned a response: {response['status']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--claimed-agent")
    parser.add_argument("--claimed-source")
    parser.add_argument("--phase", choices=("requests", "boundary", "refused"), default="requests")
    parser.add_argument("--peer-socket")
    parser.add_argument("--peer-state")
    parser.add_argument("--own-state")
    parser.add_argument("--state-value")
    args = parser.parse_args()
    assert re.fullmatch(r"p1-[0-9a-f]{32}", args.marker)
    if args.phase != "requests":
        result = (peer_boundary(args.peer_socket, args.peer_state, args.own_state, args.state_value)
                  if args.phase == "boundary" else stopped_listener())
        print("P1_OBSERVATION=" + json.dumps(result, sort_keys=True))
        return

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
        claimed_agent=args.claimed_agent,
        claimed_source=args.claimed_source,
    )
    denied = traced_request(
        proxy.hostname,
        proxy.port,
        args.agent,
        f"http://evil.com/{args.marker}-denied",
        args.marker,
        token,
        claimed_agent=args.claimed_agent,
        claimed_source=args.claimed_source,
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
