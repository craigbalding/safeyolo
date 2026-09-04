"""Per-agent egress chain diagnostic.

Walks the host-visible hops from a named agent's UDS to mitmproxy, then checks
the authenticated Agent API and its source-derived attribution separately.
Used by `safeyolo agent diag <name>`.

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
import re
import shlex
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from .config import (
    get_agent_map_path,
    get_agent_token_path,
    get_agents_dir,
    get_logs_dir,
)
from .proxy import is_proxy_running
from .sockets import path_for as socket_path_for

console = Console()

_HTTP_STATUS_RE = re.compile(
    rb"^HTTP/\d(?:\.\d)?[ \t]+([0-9]{3})(?:[ \t]+.*)?$"
)
_MAX_PROBE_RESPONSE_BYTES = 64 * 1024


class _HTTPResponseError(ValueError):
    """A bounded UDS response is not a complete HTTP response."""


@dataclass(frozen=True)
class _HTTPResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


def _parse_http_response(raw: bytes) -> _HTTPResponse:
    """Parse the status and headers needed by host-side UDS diagnostics."""
    if not raw:
        raise _HTTPResponseError("no response")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise _HTTPResponseError("incomplete HTTP headers")
    lines = head.split(b"\r\n")
    match = _HTTP_STATUS_RE.fullmatch(lines[0])
    if match is None:
        raise _HTTPResponseError("malformed HTTP status line")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not name.strip():
            raise _HTTPResponseError("malformed HTTP header")
        try:
            header_name = name.decode("ascii").strip().casefold()
            header_value = value.decode("iso-8859-1").strip()
        except UnicodeError as exc:
            raise _HTTPResponseError("malformed HTTP header") from exc
        headers[header_name] = header_value

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            expected = int(content_length)
        except ValueError as exc:
            raise _HTTPResponseError("invalid Content-Length") from exc
        if expected < 0 or len(body) < expected:
            raise _HTTPResponseError("partial HTTP body")
        body = body[:expected]

    return _HTTPResponse(
        status_code=int(match.group(1)),
        headers=headers,
        body=body,
    )


def _uds_roundtrip(
    sock_path: str,
    request: bytes,
    *,
    timeout: float = 5.0,
) -> bytes:
    """Send one bounded HTTP request over a named agent's UDS."""
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall(request)
            chunks: list[bytes] = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > _MAX_PROBE_RESPONSE_BYTES:
                    raise _HTTPResponseError("HTTP response exceeds diagnostic limit")
    except TimeoutError as exc:
        raise _HTTPResponseError("timed out waiting for HTTP response") from exc
    except OSError as exc:
        raise _HTTPResponseError(f"{type(exc).__name__}: {exc}") from exc
    return b"".join(chunks)


def _entry_socket_path(name: str, entry: dict) -> str:
    return entry.get("socket") or str(
        socket_path_for(name, entry.get("ip", ""))
    )


def _mitmproxy_log_remediation() -> str:
    log_path = get_logs_dir() / "mitmproxy.log"
    return f"tail -n 50 {shlex.quote(str(log_path))}"


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
    # Attribution IP is encoded into the per-agent UDS directory
    # (`<ip>_<agent>/proxy.sock`) and parsed by mitmproxy's UnixInstance at
    # bind time. No lo0 alias or kernel bind required.
    return Check("Attribution IP", "PASS", f"{ip} (UDS directory)")


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
                 "not running (UDS probes will still test the host chain)",
                 f"safeyolo agent run {name}")


def _check_command_supervisor(name: str) -> Check:
    """Report detached-command supervision without changing runtime state."""
    from .agent_command_supervisor import (
        SupervisorStateError,
        read_command_supervisor_state,
        sanitize_terminal_text,
        supervisor_process_is_live,
    )

    try:
        state = read_command_supervisor_state(name)
    except SupervisorStateError as exc:
        return Check(
            "Command supervisor",
            "FAIL",
            str(exc),
            f"safeyolo agent stop {name} && safeyolo agent run {name} --detach",
        )
    if state is None:
        return Check(
            "Command supervisor",
            "PASS",
            "no detached command configured",
        )

    lifecycle = state.get("state")
    if lifecycle == "running":
        if supervisor_process_is_live(state):
            return Check("Command supervisor", "PASS", "running")
        return Check(
            "Command supervisor",
            "FAIL",
            "state says running but the supervisor process is absent or its identity changed",
            f"safeyolo agent stop {name} && safeyolo agent run {name} --detach",
        )
    if lifecycle == "restarting":
        last_exit = state.get("last_exit_code")
        stderr = sanitize_terminal_text(str(state.get("last_stderr", ""))).strip().replace("\n", " | ")
        evidence = f"last exit={last_exit}"
        if stderr:
            evidence += f" stderr={stderr[:500]}"
        if state.get("last_stderr_truncated"):
            evidence += f" stderr_bytes={state.get('last_stderr_bytes', '?')} (tail truncated)"
        return Check(
            "Command supervisor",
            "WARN",
            f"restarting (attempt {state.get('restart_count', '?')}); {evidence}",
            f"safeyolo agent diag {name} or safeyolo agent stop {name}",
        )
    if lifecycle == "failed":
        stderr = sanitize_terminal_text(str(state.get("last_stderr", ""))).strip().replace("\n", " | ")
        evidence = f"exit={state.get('last_exit_code', state.get('last_exit_signal', '?'))}"
        if stderr:
            evidence += f" stderr={stderr[:500]}"
        if state.get("last_stderr_truncated"):
            evidence += f" stderr_bytes={state.get('last_stderr_bytes', '?')} (tail truncated)"
        return Check(
            "Command supervisor",
            "FAIL",
            f"crash loop exhausted restart budget; {evidence}",
            f"safeyolo agent stop {name} && safeyolo agent run {name} --detach",
        )
    if lifecycle == "stopped":
        return Check("Command supervisor", "PASS", "stopped intentionally")
    if lifecycle == "exited":
        return Check(
            "Command supervisor",
            "PASS",
            f"command exited normally (code {state.get('last_exit_code', 0)})",
        )
    return Check(
        "Command supervisor",
        "WARN",
        f"{lifecycle or 'starting'}",
        f"safeyolo agent diag {name}",
    )


def _check_proxy_transport(
    name: str,
    entry: dict,
    *,
    timeout: float = 5.0,
) -> Check:
    """Prove only UDS accept, mitmproxy parsing, and the return path.

    The deliberately hostless request should be rejected locally. Any complete
    HTTP response proves the transport contract, not Agent API health.
    """
    try:
        raw = _uds_roundtrip(
            _entry_socket_path(name, entry),
            b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
            timeout=timeout,
        )
        response = _parse_http_response(raw)
    except _HTTPResponseError as exc:
        return Check(
            "Proxy transport",
            "FAIL",
            str(exc),
            _mitmproxy_log_remediation(),
        )
    return Check(
        "Proxy transport",
        "PASS",
        f"mitmdump answered HTTP {response.status_code} ({len(raw)}B)",
    )


def _agent_api_request(path: str, token: str) -> bytes:
    """Build a request without putting the bearer in argv, URLs, or output."""
    return (
        f"GET {path} HTTP/1.0\r\n"
        "Host: _safeyolo.proxy.internal\r\n"
        f"Authorization: Bearer {token}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def _agent_api_response(
    sock_path: str,
    path: str,
    token: str,
    *,
    timeout: float,
) -> tuple[_HTTPResponse | None, Check | None]:
    try:
        raw = _uds_roundtrip(
            sock_path,
            _agent_api_request(path, token),
            timeout=timeout,
        )
        response = _parse_http_response(raw)
    except _HTTPResponseError as exc:
        return None, Check(
            "Agent API",
            "FAIL",
            f"{path}: {exc}",
            _mitmproxy_log_remediation(),
        )

    marker = response.headers.get("x-safeyolo-agent-api", "")
    if response.status_code != 200:
        remediation = (
            "safeyolo logs --tail 20"
            if response.status_code in {401, 403} and marker.casefold() == "true"
            else _mitmproxy_log_remediation()
        )
        return None, Check(
            "Agent API",
            "FAIL",
            f"{path}: HTTP {response.status_code}",
            remediation,
        )
    if marker.casefold() != "true":
        return None, Check(
            "Agent API",
            "FAIL",
            f"{path}: HTTP 200 without the Agent API handler marker",
            _mitmproxy_log_remediation(),
        )
    return response, None


def _check_agent_api(
    name: str,
    entry: dict,
    *,
    timeout: float = 5.0,
) -> Check:
    """Verify handler health and source-derived attribution over this UDS."""
    token_path = get_agent_token_path()
    try:
        token = token_path.read_text().strip()
    except FileNotFoundError:
        return Check(
            "Agent API",
            "FAIL",
            f"agent token missing at {token_path}",
            "safeyolo start",
        )
    except OSError as exc:
        return Check(
            "Agent API",
            "FAIL",
            f"cannot read agent token: {type(exc).__name__}",
            "safeyolo start",
        )
    if not token:
        return Check(
            "Agent API",
            "FAIL",
            f"agent token file is empty at {token_path}",
            "safeyolo stop && safeyolo start",
        )

    sock_path = _entry_socket_path(name, entry)
    _health, failure = _agent_api_response(
        sock_path,
        "/health",
        token,
        timeout=timeout,
    )
    if failure is not None:
        return failure

    identity, failure = _agent_api_response(
        sock_path,
        "/api/test-context/current",
        token,
        timeout=timeout,
    )
    if failure is not None:
        return failure
    assert identity is not None
    try:
        body = json.loads(identity.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return Check(
            "Agent API",
            "FAIL",
            "identity-scoped response is not JSON",
            _mitmproxy_log_remediation(),
        )
    attributed_agent = body.get("agent") if isinstance(body, dict) else None
    if attributed_agent != name:
        return Check(
            "Agent API",
            "FAIL",
            f"source attribution mismatch (expected {name!r}, got {attributed_agent!r})",
            _mitmproxy_log_remediation(),
        )

    return Check(
        "Agent API",
        "PASS",
        f"HTTP 200 with handler marker; source attributed as {name}",
    )


def run_agent_diag(name: str) -> int:
    """Run every check in order and print. Returns POSIX exit code."""
    console.print(f"\nSafeYolo diagnostic: [bold]{name}[/bold]\n")

    checks: list[Check] = []

    r1 = _check_agent_dir(name)
    checks.append(r1)
    _print(r1)
    if r1.status == "FAIL":
        return _summarise(checks)

    command_check = _check_command_supervisor(name)
    checks.append(command_check)
    _print(command_check)

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
        lambda: _check_proxy_transport(name, entry),
        lambda: _check_agent_api(name, entry),
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
