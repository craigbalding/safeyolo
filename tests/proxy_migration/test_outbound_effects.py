"""Independent Linux socket-attempt observations for local proxy decisions."""

import json
import re
import shutil
import sys
import time

import pytest

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
