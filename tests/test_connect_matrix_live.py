"""Real UDS attribution, policy/protocol matrix and CONNECT/HTTP trace evidence.

Every upstream is an ephemeral listener owned by this test. The proxy's Unix
listeners supply the real transport identity; request headers cannot select it.
"""

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.test_connect_live import Origin


@pytest.fixture
def origin():
    server = Origin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def attributed_proxy(tmp_path, policy_text):
    policy = tmp_path / "policy.toml"
    policy.write_text(policy_text)
    repo = Path(__file__).resolve().parents[1]
    # pytest's full test-name paths can exceed the platform UDS length limit.
    with tempfile.TemporaryDirectory(prefix="sy-connect-") as socket_root:
        paths = {name: str(Path(socket_root) / f"10.0.0.{index}_{name}" / "proxy.sock")
                 for index, name in enumerate(("alice", "bob"), start=2)}
        script = tmp_path / "run_proxy.py"
        script.write_text('''
import asyncio, json
from pathlib import Path
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from pdp import PolicyClientConfig, configure_policy_client, get_policy_client
from safeyolo.proxy_modes.unix_listener import ensure_registered
from safeyolo.mitm_addons.network_guard import NetworkGuard
from safeyolo.mitm_addons.request_id import RequestIdGenerator
from safeyolo.core.trace import get_store
from safeyolo.core.audit_writer import get_writer

class Evidence:
    def capture(self, flow):
        # Wait for the existing asynchronous writer before exposing a fixture
        # response whose receipt lets the parent terminate the test proxy.
        assert get_writer().wait_for_drain(timeout_s=2)
        store = get_store()
        rid, agent = flow.metadata.get('request_id'), flow.metadata.get('agent')
        record = store.get(rid, agent)
        if record:
            evidence = {'trace': store.serialise(record),
                        'wrong_agent_visible': store.get(rid, 'bob' if agent == 'alice' else 'alice') is not None,
                        'budgets': get_policy_client()._pdp._engine.get_budget_stats()}
            with Path(TRACE_PATH).open('a') as stream:
                stream.write(json.dumps(evidence) + '\\n')
    response = capture
    http_connected = capture
    http_connect_error = capture

async def main():
    ensure_registered()
    configure_policy_client(PolicyClientConfig(baseline_path=POLICY_PATH))
    options = Options(mode=MODES, confdir=CONF_DIR)
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.options.update(connection_strategy='lazy', ssl_insecure=True)
    master.addons.add(RequestIdGenerator(), NetworkGuard(), Evidence())
    await master.run()

''' + f"POLICY_PATH = {str(policy)!r}\nTRACE_PATH = {str(tmp_path / 'traces.jsonl')!r}\n"
             + f"CONF_DIR = {str(tmp_path / 'proxy-ca')!r}\nMODES = {[f'unix:{path}' for path in paths.values()]!r}\n"
             + "asyncio.run(main())\n")
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(repo / "cli/src"), str(repo)]),
               "SAFEYOLO_LOG_PATH": str(tmp_path / "audit.jsonl")}
        with (tmp_path / "proxy.log").open("w") as log:
            child = subprocess.Popen([sys.executable, str(script)], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while not all(Path(path).exists() for path in paths.values()):
                    assert child.poll() is None, (tmp_path / "proxy.log").read_text()
                    assert time.monotonic() < deadline, (tmp_path / "proxy.log").read_text()
                    time.sleep(0.05)
                yield paths
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


def connection(path):
    client = http.client.HTTPConnection("fixture", timeout=5)
    client.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.sock.settimeout(5)
    client.sock.connect(path)
    return client


def read_traces(tmp_path):
    path = tmp_path / "traces.jsonl"
    if not path.exists():
        return {}
    return {item["trace"]["request_id"]: item
            for line in path.read_text().splitlines() if (item := json.loads(line))}


def exercise(path, origin_port, protocol, expected, agent, *, denied_status=403):
    client = connection(path)
    headers = {"X-SafeYolo-Trace": "1", "X-SafeYolo-Agent": "bob" if agent == "alice" else "alice",
               "X-SafeYolo-Request-Id": "req-" + "f" * 32}
    target = f"127.0.0.1:{origin_port}"
    ids = []
    try:
        if protocol in {"https", "wss"}:
            # Parse CONNECT separately: HTTPConnection treats a successful
            # unframed response as close-delimited and discards its socket.
            wire_headers = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
            client.sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{wire_headers}\r\n".encode())
            admitted = http.client.HTTPResponse(client.sock)
            admitted.begin()
            ids.append(admitted.getheader("X-SafeYolo-Request-Id"))
            if not expected:
                assert admitted.status == denied_status
                admitted.read()
                return ids
            assert admitted.status == 200
            # Successful CONNECT has no HTTP response body.
            admitted.close()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            client.sock = context.wrap_socket(client.sock, server_hostname="localhost")
        websocket = protocol in {"ws", "wss"}
        if websocket:
            headers.update({"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})
        url = "/ws" if websocket else "/"
        if protocol in {"http", "ws"}:
            url = f"http://{target}{url}"
        client.request("GET", url, headers=headers)
        response = client.getresponse()
        ids.append(response.getheader("X-SafeYolo-Request-Id"))
        expected_status = (101 if websocket else 200) if expected else denied_status
        assert response.status == expected_status
        if expected and websocket:
            client.sock.sendall(b"\x81\x85\x00\x00\x00\x00hello")
            assert response.fp.read(7) == b"\x81\x05hello"
        else:
            body = response.read()
            assert body == b"hello" if expected else json.loads(body)
        return ids
    finally:
        client.close()


CASES = [
    ("default-allow", "allow", None, None, None, True, True),
    ("default-deny", "deny", None, None, None, False, False),
    ("host-allow", "deny", "allow", None, None, True, True),
    ("host-deny", "allow", "deny", None, None, False, False),
    ("agent-default-deny", "allow", None, "deny", None, False, True),
    ("agent-default-allow", "deny", None, "allow", None, True, False),
    ("agent-host-deny", "deny", "allow", None, "deny", False, True),
    ("agent-host-allow", "allow", "deny", None, "allow", True, False),
]


@pytest.mark.parametrize("protocol", ["http", "https", "ws", "wss"])
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_live_default_host_agent_matrix(tmp_path, origin, protocol, case):
    _, default, host_rule, agent_default, agent_host, alice, bob = case
    port = origin.server_address[1]
    policy = f'budget = 12000\n[hosts]\n"*" = {{ egress = "{default}" }}\n'
    if host_rule:
        policy += f'"127.0.0.1" = {{ egress = "{host_rule}" }}\n'
    if agent_default:
        policy += f'[agents.alice]\negress = "{agent_default}"\n'
    if agent_host:
        policy += f'[agents.alice.hosts]\n"127.0.0.1:{port}" = {{ egress = "{agent_host}" }}\n'
    if protocol in {"https", "wss"}:
        from mitmproxy.certs import CertStore

        CertStore.from_store(tmp_path / "origin-ca", "origin", 2048)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(tmp_path / "origin-ca/origin-ca.pem")
        origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    with attributed_proxy(tmp_path, policy) as paths:
        identifiers = {}
        for agent, allowed in [("alice", alice), ("bob", bob)]:
            before = origin.accepts
            identifiers[agent] = exercise(paths[agent], port, protocol, allowed, agent)
            assert origin.accepts - before == int(allowed)
    traces = read_traces(tmp_path)
    audit = {item["request_id"]: item for line in (tmp_path / "audit.jsonl").read_text().splitlines()
             if (item := json.loads(line)).get("event") == "security.network_guard"}
    for agent, allowed in [("alice", alice), ("bob", bob)]:
        ids = identifiers[agent]
        assert len(set(ids)) == len(ids)
        connection_ids = set()
        hooks = []
        for request_id in ids:
            assert request_id and request_id != "req-" + "f" * 32
            evidence = traces[request_id]
            assert not evidence["wrong_agent_visible"]
            record = evidence["trace"]
            assert record["agent_id"] == agent
            step, = [step for step in record["steps"] if step["addon"] == "network-guard"]
            assert step["host"] == "127.0.0.1" and step["port"] == port
            assert step["outcome"] == ("allowed" if allowed else "blocked")
            assert step["method"] == ("CONNECT" if step["hook"] == "http_connect" else "GET")
            connection_ids.add(step["connection_id"])
            hooks.append(step["hook"])
            if not allowed or step["hook"] == "http_connect":
                event = audit[request_id]
                assert event["agent"] == agent and event["host"] == step["host"]
                assert event["decision"] == ("allow" if allowed else "deny")
                assert event["details"]["port"] == step["port"]
                assert event["details"]["connection_id"] == step["connection_id"]
        assert len(connection_ids) == 1
        if protocol in {"https", "wss"} and allowed:
            assert hooks == ["http_connect", "request"]
            # Alice is the first transport client. Admission must not create
            # an HTTP quota entry; the enclosed request must create one.
            if agent == "alice":
                admission_budget = traces[ids[0]]["budgets"]["budgets"]
                request_budget = traces[ids[1]]["budgets"]["budgets"]
                assert "network:connect:__global__" in admission_budget
                assert "network:request:__global__" not in admission_budget
                assert "network:request:__global__" in request_budget


def test_pending_admission_audit_trace_and_port_scope(tmp_path, origin):
    port = origin.server_address[1]
    with socket.socket() as other:
        other.bind(("127.0.0.1", 0))
        other.listen()
        other.settimeout(0.1)
        tuples = [("alice", port), ("alice", other.getsockname()[1]), ("bob", port)]
        with attributed_proxy(tmp_path, 'budget = 12000\n[hosts]\n"*" = { egress = "prompt" }\n') as paths:
            ids = [exercise(paths[agent], destination_port, "https", False, agent, denied_status=428)[0]
                   for agent, destination_port in tuples]
        assert origin.accepts == 0
        with pytest.raises(TimeoutError):
            other.accept()
    traces = read_traces(tmp_path)
    decisions = {item["request_id"]: item for line in (tmp_path / "audit.jsonl").read_text().splitlines()
                 if (item := json.loads(line)).get("event") == "security.network_guard"}
    approval_keys = set()
    for request_id, (agent, destination_port) in zip(ids, tuples, strict=True):
        event = decisions[request_id]
        assert event["decision"] == "require_approval"
        assert event["agent"] == agent and event["details"]["port"] == destination_port
        approval_keys.add(event["approval"]["key"])
        record = traces[request_id]["trace"]
        assert record["agent_id"] == agent
        step, = record["steps"]
        assert step["hook"] == "http_connect" and step["method"] == "CONNECT"
        assert step["port"] == destination_port and step["outcome"] == "blocked"
        assert step["connection_id"] == event["details"]["connection_id"]
        assert not traces[request_id]["wrong_agent_visible"]
        assert not traces[request_id]["budgets"]["budgets"]
    assert len(approval_keys) == 3
