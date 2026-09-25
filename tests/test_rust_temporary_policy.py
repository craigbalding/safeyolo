"""Exercise the temporary Rust migration adapter over its real private socket."""

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "tools/proxy_migration/temporary_policy.py"


@contextmanager
def adapter(tmp_path, policy):
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(policy)
    with tempfile.TemporaryDirectory(prefix="sy-pdp-") as directory:
        socket_path = Path(directory) / "policy.sock"
        with (tmp_path / "adapter.log").open("w+") as log:
            child = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--socket", str(socket_path), "--policy", str(policy_path)],
                env={**os.environ, "PYTHONPATH": os.pathsep.join([str(REPO), str(REPO / "cli/src")])},
                stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    assert child.poll() is None, (tmp_path / "adapter.log").read_text()
                    assert time.monotonic() < deadline
                    # Binding creates the pathname before the server starts listening.
                    if socket_path.exists():
                        with socket.socket(socket.AF_UNIX) as ready:
                            try:
                                ready.connect(str(socket_path))
                            except (ConnectionRefusedError, FileNotFoundError):
                                pass
                            else:
                                break
                    time.sleep(0.02)
                yield socket_path, policy_path
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            assert child.returncode == 0, (tmp_path / "adapter.log").read_text()
            assert not socket_path.exists()


def request(socket_path, **changes):
    metadata = {
        "agent_id": "alice", "request_id": "req-test", "connection_id": "conn-test",
        "method": "GET", "scheme": "http", "host": "example.invalid", "port": 80,
        "path": "/signed?key=a&key=b", "header_names": ["authorization"], "body_present": False,
        **changes,
    }
    client = http.client.HTTPConnection("adapter", timeout=5)
    client.sock = socket.socket(socket.AF_UNIX)
    client.sock.settimeout(5)
    client.sock.connect(str(socket_path))
    try:
        client.request("POST", "/decision", body=json.dumps(metadata), headers={"Content-Type": "application/json"})
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_agent_and_port_scope_and_shutdown(tmp_path):
    policy = '''budget = 10000
[hosts]
"*" = {egress = "deny"}
[agents.alice.hosts]
"example.invalid:80" = {egress = "allow"}
'''
    with adapter(tmp_path, policy) as (path, _):
        assert path.stat().st_mode & 0o777 == 0o600
        assert request(path)[1] == {"allow": True, "decision": "allow"}
        status, other_agent = request(path, agent_id="bob")
        assert status == 200
        assert (other_agent["allow"], other_agent["status"], other_agent["decision"]) == (False, 403, "deny")
        assert request(path, port=81)[1]["status"] == 403


def test_prompt_and_global_budget_use_existing_pdp(tmp_path):
    policy = '''budget = 1
[hosts]
"*" = {egress = "prompt"}
"example.invalid" = {egress = "allow"}
'''
    with adapter(tmp_path, policy) as (path, _):
        prompt = request(path, host="unconfigured.invalid")[1]
        assert (prompt["decision"], prompt["status"]) == ("require_approval", 428)
        assert request(path)[1]["allow"]
        # The current GCRA permits its initial request plus one burst request.
        assert request(path)[1]["allow"]
        exhausted = request(path, agent_id="bob")[1]
        assert (exhausted["decision"], exhausted["status"]) == ("budget_exceeded", 429)


@pytest.mark.parametrize("changes", [
    {"port": 0}, {"port": "80"}, {"agent_id": ""},
    {"headers": [["authorization", "synthetic-secret-must-not-log"]]},
    {"scheme": "ftp"}, {"scheme": ""},
    {"method": "CONNECT", "scheme": "https", "path": ""},
    {"method": "CONNECT", "scheme": "", "path": "/"},
])
def test_invalid_metadata_is_rejected_without_echo(tmp_path, changes):
    with adapter(tmp_path, '[hosts]\n"*" = {egress = "allow"}\n') as (path, _):
        status, body = request(path, **changes)
        assert status == 400
        assert body == {"error": "Invalid network metadata"}
    assert "synthetic-secret-must-not-log" not in (tmp_path / "adapter.log").read_text()


def test_invalid_startup_policy_never_creates_socket(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text("this is not valid TOML")
    path = tmp_path / "policy.sock"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--socket", str(path), "--policy", str(policy)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join([str(REPO), str(REPO / "cli/src")])},
        capture_output=True, timeout=10,
    )
    assert result.returncode != 0
    assert not path.exists()


def test_connect_metadata_preserves_actual_proxy_parser_target(tmp_path):
    from mitmproxy.net.http.http1.read import read_request_head

    parsed = read_request_head([
        b"CONNECT example.invalid:8443 HTTP/1.1",
        b"Host: example.invalid:8443",
    ])
    assert (parsed.scheme, parsed.path) == ("", "")
    with adapter(tmp_path, '[hosts]\n"*" = {egress = "allow"}\n') as (path, _):
        status, result = request(path, method=parsed.method, scheme=parsed.scheme,
                                 path=parsed.path, host=parsed.host, port=parsed.port)
        assert status == 200
        assert result == {"allow": True, "decision": "allow"}


def test_policy_reload_keeps_last_valid_decision(tmp_path):
    with adapter(tmp_path, '[hosts]\n"*" = {egress = "allow"}\n') as (path, policy):
        assert request(path)[1]["allow"]
        policy.write_text('[hosts]\n"*" = {egress = "deny"}\n')
        deadline = time.monotonic() + 5
        while request(path)[1]["allow"]:
            assert time.monotonic() < deadline
            time.sleep(0.1)
        policy.write_text("invalid TOML")
        time.sleep(1.1)
        assert request(path)[1]["status"] == 403


@pytest.mark.parametrize("wire", [
    b"POST /decision HTTP/1.1\r\nHost: adapter\r\nContent-Length: 100\r\n\r\n{",
    b"invalid request line\r\n\r\n",
])
def test_disconnected_peer_does_not_stop_adapter(tmp_path, wire):
    with adapter(tmp_path, '[hosts]\n"*" = {egress = "allow"}\n') as (path, _):
        with socket.socket(socket.AF_UNIX) as cancelled:
            cancelled.connect(str(path))
            cancelled.sendall(wire)
        assert request(path)[1]["allow"]


def test_policy_connection_error_is_still_fatal(tmp_path, monkeypatch):
    from tools.proxy_migration import temporary_policy

    def fail_policy(*args):
        raise BrokenPipeError("Synthetic policy failure")

    monkeypatch.setattr(temporary_policy, "decide", fail_policy)
    metadata = json.dumps({
        "agent_id": "alice", "request_id": "req-test", "connection_id": "conn-test",
        "method": "GET", "scheme": "http", "host": "example.invalid", "port": 80,
        "path": "/",
    }).encode()
    with tempfile.TemporaryDirectory(prefix="sy-pdp-fatal-") as directory:
        path = Path(directory) / "policy.sock"
        with temporary_policy.PolicyServer(path, None) as server, socket.socket(socket.AF_UNIX) as client:
            client.connect(str(path))
            client.sendall(
                f"POST /decision HTTP/1.1\r\nHost: adapter\r\nContent-Length: {len(metadata)}\r\n\r\n".encode()
                + metadata
            )
            with pytest.raises(RuntimeError, match="adapter request failed"):
                server.handle_request()
