"""Challenge the listener observer with live sockets and wrong or missing controls."""

import http.client
import json
import os
import shlex
import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from tests.blackbox import installed_host_smoke
from tests.test_blackbox_sinkhole import _load_sinkhole_server

NODES = (
    "test_vm_isolation.py::TestHostAdjacentReachability::test_host_listener_unreachable",
    "test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable",
)


@pytest.fixture
def listener_probe(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "blackbox"))
    from tests.blackbox.host.lifecycle import test_host_listener as consumer

    root = tmp_path / "instance"
    agent = root / "agents/bbtest"
    share = agent / "config-share"
    share.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    host, port = listener.getsockname()
    (share / "host-listener-address").write_text(host)
    (share / "host-listener-port").write_text(str(port))
    status = {"name": "bbtest", "agent_id": "ag-owned", "run_id": "0" * 32, "runtime_state": "running"}
    (agent / "runtime.json").write_text(json.dumps({**status, "backend_pid": os.getpid(),
                                                   "backend_token": installed_host_smoke._process_start_token(os.getpid())}))
    artifacts = tmp_path / "reports"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_TEST_AGENT", "bbtest")
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_ARTIFACTS_DIR", str(artifacts))
    calls = []
    failure = {}

    def command(args, **kwargs):
        calls.append(args)
        if "status" in args:
            return SimpleNamespace(returncode=0, stdout=json.dumps(status), stderr="")
        assert args[-2] == "-c" and "test_host_listener_unreachable" in args[-1]
        assert "/usr/bin/python3 -m pytest" in args[-1]
        assert "test_proxy_reachable" in args[-1]
        if failure.get("dead-after"):
            listener.close()
        refusal = {"host": host, "port": port, "uid": 1000, "connected": False, "error": "refused"}
        refusal.update(failure.get("refusal", {}))
        return SimpleNamespace(returncode=failure.get("exit", 0), stderr="",
                               stdout="HOST_LISTENER_REFUSAL=" + json.dumps(refusal) + "\n" +
                               failure.get("result", "2 passed"))

    monkeypatch.setattr(consumer.subprocess, "run", command)
    try:
        yield consumer, listener, calls, failure, artifacts, host, port
    finally:
        listener.close()


def test_listener_observer_records_same_endpoint_and_live_controls(listener_probe):
    consumer, _, _, _, artifacts, host, port = listener_probe
    consumer.TestLiveHostListener().test_live_host_listener_refused("ordinary", False, NODES)
    report = json.loads((artifacts / "host-listener-ordinary.json").read_text())
    assert report["passed"] and report["guest_before"] == report["guest_after"]
    assert report["endpoint"] == {"host": host, "port": port}
    assert [row["peer"] for row in report["host_liveness"]] == [[host, port], [host, port]]


@pytest.mark.parametrize("defect", ["dead-before", "dead-after", "wrong-port", "reached", "wrong-user", "skipped", "failed"])
def test_listener_observer_refuses_false_isolation_claims(listener_probe, defect):
    consumer, listener, calls, failure, artifacts, _, port = listener_probe
    if defect == "dead-before":
        listener.close()
    elif defect == "dead-after":
        failure[defect] = True
    elif defect == "wrong-port":
        failure["refusal"] = {"port": port + 1}
    elif defect == "reached":
        failure["refusal"] = {"connected": True}
    elif defect == "wrong-user":
        failure["refusal"] = {"uid": 0}
    elif defect == "skipped":
        failure["result"] = "1 passed, 1 skipped"
    else:
        failure["exit"] = 1
    with pytest.raises((AssertionError, OSError)):
        consumer.TestLiveHostListener().test_live_host_listener_refused("ordinary", False, NODES)
    report = json.loads((artifacts / "host-listener-ordinary.json").read_text())
    assert "passed" not in report and report["endpoint"]["port"] == port
    if defect == "dead-before":
        assert not any("shell" in call for call in calls)


def test_guest_refusal_probe_rejects_an_actually_reachable_listener(listener_probe, monkeypatch):
    _, listener, _, _, _, host, port = listener_probe
    from harness import host_listener

    monkeypatch.setattr(host_listener, "listener_endpoint", lambda _directory: (host, port))
    with pytest.raises(AssertionError, match="guest reached"):
        host_listener.refuse_listener()
    listener.close()
    refused = host_listener.refuse_listener()
    assert refused["connected"] is False and (refused["host"], refused["port"]) == (host, port)


@pytest.mark.parametrize("platform", ["linux", "vz"])
@pytest.mark.parametrize("wrong_marker", [False, True])
def test_restart_traffic_control_uses_real_origin_echo(monkeypatch, platform, wrong_marker):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "blackbox"))
    from tests.blackbox.host.lifecycle.test_token_lifecycle import TestLiveAgentLifecycle

    server_module = _load_sinkhole_server()
    if platform == "vz":
        from tests.blackbox.harness.vz_fixture import Parent, VZRequest
        server = Parent(None, None, host="127.0.0.1", port=0, request_handler=VZRequest)
        server.p2_fixture = None
    else:
        server = server_module.NoReverseDNSThreadingHTTPServer(("127.0.0.1", 0), server_module.SinkholeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def guest_shell(*arguments, **kwargs):
        # The native guest transport is simulated; the actual maintained HTTP
        # producers receive the selected path and header over an owned socket.
        assert arguments[:4] == ("agent", "shell", "bbtest", "-c")
        fields = shlex.split(arguments[4])
        target = urlsplit(fields[-1])
        header, value = fields[fields.index("-H") + 1].split(": ", 1)
        assert value == "run=proxy-restart;agent=bbtest"
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            path = "/get/stale-marker" if wrong_marker else target.path
            client.request("GET", path, headers={"Host": target.hostname, header: value})
            response = client.getresponse()
            assert response.status == 200
            return SimpleNamespace(returncode=0, stdout=response.read().decode(), stderr="")
        finally:
            client.close()

    consumer = TestLiveAgentLifecycle()
    monkeypatch.setattr(consumer, "_safeyolo", guest_shell)
    try:
        if wrong_marker:
            with pytest.raises(AssertionError):
                consumer._allowed_traffic("bbtest", "owned-marker")
        else:
            assert consumer._allowed_traffic("bbtest", "owned-marker")["path"] == "/get/owned-marker"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
