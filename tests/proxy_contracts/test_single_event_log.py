"""Real route attempts must be visible through both supported audit readers."""

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import REPO, launch_proxy, request
from tests.proxy_contracts.scenarios import origin_server, scoped_api

POLICY = '''budget = 12000
[hosts]
"*" = { egress = "allow" }
[agents.bob]
egress = "deny"
'''


def operator_logs(directory, *, agent=None):
    binary = Path(os.environ.get("SAFEYOLO_NATIVE_CLI", REPO / "proxy/target/release/safeyolo"))
    command = [str(binary), "logs", "--lines", "100"]
    if agent:
        command += ["--agent", agent]
    result = subprocess.run(command, env=dict(os.environ, SAFEYOLO_NATIVE_CONFIG_PATH=str(directory / "config.toml")),
                            text=True, capture_output=True, check=True, timeout=10)
    return json.loads(result.stdout)["events"]


@pytest.mark.parametrize("filters", ["global", "agent", "destination"])
def test_selected_route_reaches_operator_logs_and_scoped_explain(tmp_path, filters):
    with origin_server(capture_heads=True) as origin, origin_server(capture_heads=True) as parent:
        port = origin.server_address[1]
        options = {"agent_api": True, "native_product": True, "agents": ("alice", "bob", "carol"),
                   "parent_proxy": f"http://127.0.0.1:{parent.server_address[1]}"}
        if filters == "agent":
            options["parent_proxy_agents"] = ["alice"]
        if filters == "destination":
            options["parent_proxy_hosts"] = ["parent.invalid"]
        # The CLI reads the same canonical path as the requesting process.
        # FlowStore stays disabled in the ordinary harness configuration.
        (tmp_path / "config.toml").write_text('audit_log_path="audit.jsonl"\npolicy_file="policy.toml"\n')
        with launch_proxy("rust", tmp_path, POLICY, **options) as proxy:
            cases = [("alice", "parent.invalid", 8123, "parent")]
            if filters == "agent":
                cases.append(("carol", "127.0.0.1", port, "direct"))
            elif filters == "destination":
                cases.append(("alice", "127.0.0.1", port, "direct"))
            for agent, host, selected_port, route in cases:
                before = origin.accepts, parent.accepts
                status, headers, body = request(proxy.paths[agent], f"http://{host}:{selected_port}/route?private=canary",
                                                headers={"X-SafeYolo-Agent": "bob", "X-SafeYolo-Request-Id": "req-" + "f" * 32})
                assert status == 200 and body == b"hello"
                assert (origin.accepts - before[0], parent.accepts - before[1]) == (int(route == "direct"), int(route == "parent"))
                identifier = headers["x-safeyolo-request-id"]
                explain = scoped_api(proxy, agent, f"/explain?request_id={identifier}")
                assert explain["status"] == "complete"
                event, = [row for row in explain["events"] if row["event"] == "traffic.egress"]
                assert event["schema_version"] == 1
                assert event["host"] == host and event["agent"] == agent
                assert event["details"]["route"] == route and event["details"]["port"] == selected_port
                assert event["details"]["connection_id"]
                assert event["details"]["attribution"]["trusted_transport_identity"] == agent
                assert "attempt" in event["summary"].lower() and "private=canary" not in json.dumps(event)
                outcome, = [row for row in explain["events"] if row["event"] == "traffic.request_outcome"]
                assert outcome["details"]["status"] == 200 and outcome["summary"] == "Proxy response prepared"
                assert event in operator_logs(tmp_path)
                assert event in operator_logs(tmp_path, agent=agent)
                assert event not in operator_logs(tmp_path, agent="bob")
                assert scoped_api(proxy, "bob", f"/explain?request_id={identifier}")["events"] == []
            before = origin.accepts, parent.accepts
            status, headers, _ = request(proxy.paths["bob"], f"http://127.0.0.1:{port}/denied")
            assert status == 403
            denied = scoped_api(proxy, "bob", f'/explain?request_id={headers["x-safeyolo-request-id"]}')
            assert not any(row["event"] == "traffic.egress" for row in denied["events"])
            assert (origin.accepts, parent.accepts) == before
        assert not (tmp_path / "events.jsonl").exists()
        assert not (tmp_path / "flows.sqlite3").exists()


def test_failed_direct_attempt_is_not_delivery_and_missing_evidence_has_no_route(tmp_path):
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
    (tmp_path / "config.toml").write_text('audit_log_path="audit.jsonl"\npolicy_file="policy.toml"\n')
    with launch_proxy("rust", tmp_path, POLICY, agent_api=True, native_product=True) as proxy:
        status, headers, _ = request(proxy.paths["alice"], f"http://127.0.0.1:{port}/failed")
        assert status == 502
        explain = scoped_api(proxy, "alice", f'/explain?request_id={headers["x-safeyolo-request-id"]}')
        event, = [row for row in explain["events"] if row["event"] == "traffic.egress"]
        assert event["details"]["route"] == "direct" and "attempt" in event["summary"].lower()
        assert "success" not in json.dumps(event).lower()
        assert event in operator_logs(tmp_path)
        missing = scoped_api(proxy, "alice", "/explain?request_id=req-" + "0" * 32)
        assert missing["events"] == [] and missing["status"] == "complete"


def test_retired_setting_does_not_touch_historical_files_during_reload(tmp_path):
    import signal
    import time

    historical = tmp_path / "events.jsonl"
    historical.write_text('historical diagnostic bytes\n')
    with origin_server() as origin:
        with launch_proxy("rust", tmp_path, POLICY, agent_api=True) as proxy:
            config_path = tmp_path / "proxy.json"
            config = json.loads(config_path.read_text())
            config["event_log"] = str(historical)
            config["reload_id"] = "single-stream-reload"
            config_path.write_text(json.dumps(config))
            proxy.process.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 5
            while json.loads(proxy.readiness_file.read_text()).get("reload_id") != config["reload_id"]:
                assert time.monotonic() < deadline, (tmp_path / "process.log").read_text()
                time.sleep(0.01)
            status, headers, _ = request(proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/after-reload")
            assert status == 200
            explained = scoped_api(proxy, "alice", f'/explain?request_id={headers["x-safeyolo-request-id"]}')
            assert any(row["event"] == "traffic.egress" for row in explained["events"])
    assert historical.read_text() == 'historical diagnostic bytes\n'
    assert {path.name for path in tmp_path.glob("*.jsonl")} == {"audit.jsonl", "events.jsonl"}
