"""Per-agent egress chain diagnostic.

Walks the hops from `curl inside the agent` out to `mitmproxy`, checking
each link in order. Used by `safeyolo agent diag <name>`.

Cross-platform with platform-specific probes where the implementations
differ (netns on Linux, lo0 aliases + VZ helper on macOS). Output is
line-per-check with a PASS/FAIL/WARN prefix; exit code 0 on all-pass,
1 on any failure.

Intentionally does NOT require the VM's guest side to be reachable.
The probes all target the host-visible artifacts + a fast UDS-level
roundtrip through mitmproxy's per-agent listener. If the agent's VM
is up we also check the platform sandbox presence; if not, that's
reported and the rest continues.
"""
from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from .config import get_agent_map_path, get_agents_dir
from .proxy import is_proxy_running
from .sockets import path_for as socket_path_for

console = Console()


@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | WARN
    message: str
    remediation: str = ""


def _print(result: Check) -> None:
    colour = {"PASS": "green", "FAIL": "red", "WARN": "yellow"}[result.status]
    console.print(f"  [{colour}]{result.status}[/{colour}]  {result.name}: {result.message}")
    if result.remediation:
        console.print(f"         [dim]→ {result.remediation}[/dim]")


def _check_agent_dir(name: str) -> Check:
    agent_dir = get_agents_dir() / name
    if not agent_dir.exists():
        return Check("Agent config", "FAIL",
                     f"{agent_dir} does not exist",
                     "safeyolo agent add {name} <folder>")
    return Check("Agent config", "PASS", str(agent_dir))


def _check_agent_map(name: str) -> tuple[Check, dict | None]:
    map_path = get_agent_map_path()
    if not map_path.exists():
        return Check("Agent map", "FAIL", f"{map_path} missing",
                     "safeyolo start"), None
    try:
        data = json.loads(map_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return Check("Agent map", "FAIL",
                     f"{type(exc).__name__}: {exc}"), None
    entry = data.get(name)
    if not entry:
        return Check("Agent map", "WARN",
                     f"no entry for '{name}' (agent not currently running)",
                     f"safeyolo agent run {name}"), None
    return Check("Agent map", "PASS",
                 f"ip={entry.get('ip','?')} socket={entry.get('socket','?')}"), entry


def _check_attribution_ip(entry: dict) -> Check:
    ip = entry.get("ip")
    if not ip:
        return Check("Attribution IP", "FAIL", "no 'ip' field in agent map entry")
    # Attribution IP is encoded into the per-agent UDS filename
    # (`<ip>_<agent>.sock`) and parsed by mitmproxy's UnixInstance at
    # bind time. No lo0 alias or kernel bind required.
    return Check("Attribution IP", "PASS", f"{ip} (UDS filename)")


def _check_proxy_socket(name: str, entry: dict) -> Check:
    sock_path_str = entry.get("socket")
    if sock_path_str:
        sock_path = Path(sock_path_str)
    else:
        ip = entry.get("ip")
        if not ip:
            return Check("Proxy socket", "FAIL", "no 'ip' in agent map entry")
        sock_path = socket_path_for(name, ip)
    if not sock_path.exists():
        return Check("Proxy socket", "FAIL",
                     f"{sock_path} missing",
                     "safeyolo stop --all && safeyolo start && safeyolo agent run "
                     f"{name}")
    try:
        st = sock_path.stat()
    except OSError as exc:
        return Check("Proxy socket", "FAIL",
                     f"stat failed: {type(exc).__name__}: {exc}")
    mode = st.st_mode & 0o777
    return Check("Proxy socket", "PASS",
                 f"{sock_path} mode={oct(mode)}")


def _check_proxy_process() -> Check:
    if not is_proxy_running():
        return Check("Proxy process", "FAIL",
                     "mitmdump not running",
                     "safeyolo start")
    return Check("Proxy process", "PASS",
                 "mitmdump running (owns per-agent UnixInstance listeners)")


def _check_sandbox_running(name: str) -> Check:
    from .platform import get_platform
    plat = get_platform()
    if plat.is_sandbox_running(name):
        return Check("Sandbox/VM", "PASS", "running")
    return Check("Sandbox/VM", "WARN",
                 "not running (end-to-end probe will still test the host chain)",
                 f"safeyolo agent run {name}")


def _check_end_to_end(name: str, entry: dict) -> Check:
    """Send a minimal HTTP request through the per-agent UDS.

    We don't need a 200 from upstream -- mitmproxy answering at all
    (even with 400 Bad Request for our empty Host header) proves the
    full chain: UDS accept → mitmproxy parsed the request. That's
    every host-side hop exercised.
    """
    sock_path_str = entry.get("socket") or str(
        socket_path_for(name, entry.get("ip", ""))
    )
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(sock_path_str)
        s.sendall(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
        buf = b""
        started = time.monotonic()
        while time.monotonic() - started < 5:
            try:
                chunk = s.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
        s.close()
    except OSError as exc:
        return Check("End-to-end probe", "FAIL",
                     f"{type(exc).__name__}: {exc}")
    if not buf:
        return Check("End-to-end probe", "FAIL",
                     "no response from mitmdump -- chain broken")
    first_line = buf.split(b"\n", 1)[0].decode(errors="replace").strip()
    if not first_line.startswith("HTTP/"):
        # Something responded but it's not HTTP -- something's wrong on
        # the other side (firewall mangling? wrong port?).
        return Check("End-to-end probe", "FAIL",
                     f"unexpected response (not HTTP): {first_line[:60]!r}")
    # We intentionally send an incomplete request (no Host header) so
    # mitmproxy rejects it with 400. A 400 *proves* the full host
    # chain works -- UDS accept + attribution-IP bind + TCP to mitmproxy
    # + reply back -- without touching any upstream or policy allowlist.
    # Operators: this is the expected outcome; PASS is PASS.
    return Check("End-to-end probe", "PASS",
                 f"mitmdump answered ({len(buf)}B, probe request rejected as expected)")


def run_agent_diag(name: str) -> int:
    """Run every check in order and print. Returns POSIX exit code."""
    console.print(f"\nSafeYolo diagnostic: [bold]{name}[/bold]\n")

    checks: list[Check] = []

    r1 = _check_agent_dir(name)
    checks.append(r1)
    _print(r1)
    if r1.status == "FAIL":
        return _summarise(checks)

    r2, entry = _check_agent_map(name)
    checks.append(r2)
    _print(r2)
    if entry is None:
        return _summarise(checks)

    for check_fn in (
        lambda: _check_attribution_ip(entry),
        lambda: _check_proxy_socket(name, entry),
        _check_proxy_process,
        lambda: _check_sandbox_running(name),
        lambda: _check_end_to_end(name, entry),
    ):
        c = check_fn()
        checks.append(c)
        _print(c)

    return _summarise(checks)


def _summarise(checks: list[Check]) -> int:
    n_pass = sum(1 for c in checks if c.status == "PASS")
    n_fail = sum(1 for c in checks if c.status == "FAIL")
    n_warn = sum(1 for c in checks if c.status == "WARN")
    console.print(f"\n  Summary: {n_pass} pass, {n_fail} fail, {n_warn} warn\n")
    # Non-zero exit if anything failed; warns are advisory.
    return 1 if n_fail > 0 else 0
