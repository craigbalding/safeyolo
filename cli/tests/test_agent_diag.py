"""Authoritative per-agent UDS diagnostic coverage (#399)."""

from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

import pytest

from safeyolo import agent_diag
from safeyolo.agent_diag import Check, _check_agent_api, _check_proxy_transport


@dataclass(frozen=True)
class _Exchange:
    chunks: tuple[bytes, ...] = ()
    delay: float = 0.0


@contextmanager
def _unix_http_server(path, *exchanges: _Exchange):
    """Serve bounded canned responses over a real AF_UNIX socket."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(len(exchanges) or 1)
    requests: list[bytes] = []
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            for exchange in exchanges:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(1)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    requests.append(request)
                    if exchange.delay:
                        time.sleep(exchange.delay)
                    for chunk in exchange.chunks:
                        try:
                            conn.sendall(chunk)
                        except BrokenPipeError:
                            break
        except BaseException as exc:  # surfaced in the foreground on exit
            failures.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield requests
    finally:
        server.close()
        thread.join(timeout=2)
        assert not thread.is_alive(), "UDS test server did not finish"
        assert not failures, failures


def _response(
    body: bytes = b"",
    *,
    status: int = 200,
    reason: str = "OK",
    marker: str | None = "true",
    marker_name: str = "X-SafeYolo-Agent-API",
) -> bytes:
    headers = [
        f"HTTP/1.1 {status} {reason}\r\n".encode(),
        f"Content-Length: {len(body)}\r\n".encode(),
    ]
    if marker is not None:
        headers.append(f"{marker_name}: {marker}\r\n".encode())
    return b"".join(headers) + b"\r\n" + body


def _entry(sock_path) -> dict:
    return {"ip": "10.200.0.7", "socket": str(sock_path)}


def _write_token(tmp_config_dir, token: str = "diagnostic-secret-token") -> None:
    (tmp_config_dir / "data" / "agent_token").write_text(token)


def test_proxy_transport_passes_on_complete_generic_http_response(tmp_path):
    sock_path = tmp_path / "transport.sock"
    response = _response(status=400, reason="Bad Request", marker=None)
    with _unix_http_server(sock_path, _Exchange((response,))) as requests:
        result = _check_proxy_transport("demo", _entry(sock_path), timeout=1)

    assert result == Check(
        "Proxy transport",
        "PASS",
        f"mitmdump answered HTTP 400 ({len(response)}B)",
    )
    assert requests == [b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n"]


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (b"", "no response"),
        (b"not-http\r\n\r\n", "malformed HTTP status"),
        (b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n", "incomplete"),
        (
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nab",
            "partial HTTP body",
        ),
    ],
)
def test_proxy_transport_rejects_empty_malformed_and_partial_responses(
    tmp_path, response, expected
):
    sock_path = tmp_path / "transport.sock"
    chunks = (response,) if response else ()
    with _unix_http_server(sock_path, _Exchange(chunks)):
        result = _check_proxy_transport("demo", _entry(sock_path), timeout=1)

    assert result.status == "FAIL"
    assert expected in result.message
    assert "mitmproxy.log" in result.remediation


def test_proxy_transport_timeout_is_a_failure(tmp_path):
    sock_path = tmp_path / "transport.sock"
    with _unix_http_server(
        sock_path,
        _Exchange((_response(status=400, marker=None),), delay=0.15),
    ):
        result = _check_proxy_transport("demo", _entry(sock_path), timeout=0.02)

    assert result.status == "FAIL"
    assert "timed out" in result.message


def test_agent_api_healthy_and_authoritatively_attributed(
    tmp_path, tmp_config_dir
):
    token = "diagnostic-secret-token"
    _write_token(tmp_config_dir, token)
    sock_path = tmp_path / "agent-api.sock"
    health = _response(
        b'{"agent_api":"ok","pdp":"ok"}',
        marker="TrUe",
        marker_name="x-sAfEyOlO-aGeNt-ApI",
    )
    identity = _response(b'{"agent":"demo","context":null}')
    transport_response = _response(status=400, reason="Bad Request", marker=None)
    with _unix_http_server(
        sock_path,
        _Exchange((transport_response,)),
        _Exchange((health[:17], health[17:])),
        _Exchange((identity,)),
    ) as requests:
        transport = _check_proxy_transport("demo", _entry(sock_path), timeout=1)
        result = _check_agent_api("demo", _entry(sock_path), timeout=1)

    assert transport.status == "PASS"
    assert result.status == "PASS"
    assert "source attributed as demo" in result.message
    assert token not in repr(result)
    assert requests[1].startswith(b"GET /health HTTP/1.0\r\n")
    assert requests[2].startswith(
        b"GET /api/test-context/current HTTP/1.0\r\n"
    )
    assert all(
        b"Authorization: Bearer " in request for request in requests[1:]
    )


def test_degraded_layers(tmp_config_dir):
    """Reproduce transport PASS while both real Agent API probes FAIL."""
    from safeyolo.commands.doctor import _check_pipeline_probe
    from safeyolo.sockets import path_for

    name = "demo"
    ip = "10.200.0.7"
    token = "degraded-secret-token"
    _write_token(tmp_config_dir, token)
    sock_path = path_for(name, ip)
    sock_path.parent.mkdir(parents=True)
    (tmp_config_dir / "data" / "agent_map.json").write_text(
        json.dumps({name: {"ip": ip, "socket": str(sock_path)}})
    )
    containment = _response(
        b'{"reason_code":"agent_api_unavailable"}',
        status=503,
        reason="Service Unavailable",
    )
    with _unix_http_server(
        sock_path,
        _Exchange((_response(status=400, reason="Bad Request", marker=None),)),
        _Exchange((containment,)),
        _Exchange((containment,)),
    ):
        transport = _check_proxy_transport(name, _entry(sock_path), timeout=1)
        agent_api = _check_agent_api(name, _entry(sock_path), timeout=1)
        doctor = _check_pipeline_probe()

    assert transport.status == "PASS"
    assert agent_api.status == "FAIL"
    assert "HTTP 503" in agent_api.message
    assert doctor.status == "fail"
    assert "HTTP 503" in doctor.message
    assert "mitmproxy.log" in doctor.remediation
    assert token not in repr((transport, agent_api, doctor))


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_response(marker=None), "without the Agent API handler marker"),
        (
            _response(
                b'{"reason_code":"agent_api_unavailable"}',
                status=503,
                reason="Service Unavailable",
            ),
            "HTTP 503",
        ),
        (b"HTTP/1.1 1200 Invalid\r\n\r\n", "malformed HTTP status"),
        (
            b"HTTP/1.1 200 OK\r\nBad-Header\r\n\r\n",
            "malformed HTTP header",
        ),
        (
            b"HTTP/1.1 200 OK\r\n"
            b"X-SafeYolo-Agent-API: true\r\n"
            b"Content-Length: 5\r\n\r\nab",
            "partial HTTP body",
        ),
    ],
)
def test_agent_api_rejects_generic_containment_malformed_and_partial_health(
    tmp_path, tmp_config_dir, response, expected
):
    token = "diagnostic-secret-token"
    _write_token(tmp_config_dir, token)
    sock_path = tmp_path / "agent-api.sock"
    with _unix_http_server(sock_path, _Exchange((response,))):
        result = _check_agent_api("demo", _entry(sock_path), timeout=1)

    assert result.status == "FAIL"
    assert expected in result.message
    assert token not in repr(result)
    assert "mitmproxy.log" in result.remediation


def test_agent_api_rejects_source_attribution_mismatch(tmp_path, tmp_config_dir):
    _write_token(tmp_config_dir)
    sock_path = tmp_path / "agent-api.sock"
    with _unix_http_server(
        sock_path,
        _Exchange((_response(b'{"agent_api":"ok","pdp":"ok"}'),)),
        _Exchange((_response(b'{"agent":"another","context":null}'),)),
    ):
        result = _check_agent_api("demo", _entry(sock_path), timeout=1)

    assert result.status == "FAIL"
    assert "source attribution mismatch" in result.message


@pytest.mark.parametrize(("token", "expected"), [(None, "missing"), ("  ", "empty")])
def test_agent_api_missing_or_empty_token_fails_without_exposure(
    tmp_path, tmp_config_dir, token, expected
):
    if token is not None:
        _write_token(tmp_config_dir, token)

    result = _check_agent_api(
        "demo",
        _entry(tmp_path / "socket-is-not-contacted"),
        timeout=0.01,
    )

    assert result.status == "FAIL"
    assert expected in result.message
    assert "Bearer" not in repr(result)


def test_agent_api_timeout_does_not_expose_token(tmp_path, tmp_config_dir):
    token = "timeout-secret-token"
    _write_token(tmp_config_dir, token)
    sock_path = tmp_path / "agent-api.sock"
    with _unix_http_server(
        sock_path,
        _Exchange((_response(),), delay=0.15),
    ):
        result = _check_agent_api("demo", _entry(sock_path), timeout=0.02)

    assert result.status == "FAIL"
    assert "timed out" in result.message
    assert token not in repr(result)


def test_run_agent_diag_reports_transport_and_agent_api_separately(monkeypatch):
    entry = {"ip": "10.200.0.7", "socket": "/tmp/demo.sock"}
    monkeypatch.setattr(
        agent_diag, "_check_agent_dir", lambda name: Check("Agent config", "PASS", name)
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_agent_map",
        lambda name: (Check("Agent map", "PASS", name), entry),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_attribution_ip",
        lambda value: Check("Attribution IP", "PASS", value["ip"]),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_proxy_socket",
        lambda name, value: Check("Proxy socket", "PASS", name),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_proxy_process",
        lambda: Check("Proxy process", "PASS", "running"),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_sandbox_running",
        lambda name: Check("Sandbox/VM", "PASS", name),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_proxy_transport",
        lambda name, value: Check("Proxy transport", "PASS", name),
    )
    monkeypatch.setattr(
        agent_diag,
        "_check_agent_api",
        lambda name, value: Check("Agent API", "FAIL", "HTTP 503"),
    )
    printed: list[Check] = []
    monkeypatch.setattr(agent_diag, "_print", printed.append)
    monkeypatch.setattr(agent_diag.console, "print", lambda *args, **kwargs: None)

    exit_code = agent_diag.run_agent_diag("demo")

    assert exit_code == 1
    assert [check.name for check in printed[-2:]] == [
        "Proxy transport",
        "Agent API",
    ]
