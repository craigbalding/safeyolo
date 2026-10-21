"""Exercise shipped trace selectors against the native TOML/UDS boundary.

Reuse a prepared proxy executable; do not build it or allocate a guest here.
All policy, authentication and origin state is disposable and synthetic.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from tests.proxy_contracts.harness import child_process, request, wait_ready
from tests.proxy_contracts.scenarios import origin_server

REPO = Path(__file__).resolve().parents[2]
GRAPHS = REPO / "cli/src/safeyolo/agent_context/skills/safeyolo/references/graph"
TOKEN = "synthetic-native-skill-trace"


@pytest.mark.parametrize("mode", ["enabled", "disabled", "scope-exception", "truncated", "earlier-response", "no-match"])
def test_native_trace_selectors_and_disabled_control_routes(tmp_path, mode):
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", str(REPO / "proxy/target/release/safeyolo-proxy")))
    assert binary.is_file(), "Supply the prepared native proxy; unavailable execution is not a pass"
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    for directory in ("builtin-services", "services"):
        (tmp_path / directory).mkdir()
    token = data / "agent_token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    policy = '[hosts]\n"*"={egress="allow"}\n'
    if mode == "earlier-response":
        policy = '[hosts]\n"*"={egress="deny"}\n'
    if mode == "no-match":
        policy += '[[scan_patterns]]\nname="unmatched"\npattern="unmatched-canary"\ntarget="request"\nscope=["url"]\naction="block"\n'
    if mode == "disabled":
        policy += '[controls.network]\nenabled=false\n'
    if mode == "scope-exception":
        policy += '[hosts."trace.invalid"]\nexceptions=["network", "credentials"]\n'
    (tmp_path / "policy.toml").write_text(policy)
    # Keep UDS names short even when the disk-backed pytest parent is long.
    with tempfile.TemporaryDirectory(prefix="sy-guide-", dir=tmp_path.parent) as sockets, origin_server() as origin:
        paths = {name: str(Path(sockets) / f"{name}.sock") for name in ("alice", "bob")}
        configuration = (f'admin_port=0\nflow_store_enabled=false\nagent_api_enabled=true\n'
                         f'parent_proxy="http://127.0.0.1:{origin.server_address[1]}"\n')
        for name, path in paths.items():
            configuration += f'[[listeners]]\nagent_id="{name}"\nsocket_path={json.dumps(path)}\n'
        if mode == "truncated":
            configuration += '[trace]\nsteps_max=1\n'
        config = tmp_path / "config.toml"
        config.write_text(configuration)
        environment = dict(os.environ, PATH=str(binary.parent), SAFEYOLO_DATA_DIR=str(data))
        with child_process([str(binary), "--config", str(config)], tmp_path, environment) as process:
            readiness = data / "ready.json"
            wait_ready(process, [readiness, *map(Path, paths.values())], tmp_path / "process.log",
                       readiness_file=readiness, expected_backend="rust-m2")
            status, headers, _ = request(paths["alice"], "http://trace.invalid/native-guidance",
                                         headers={"X-SafeYolo-Trace": "1"})
            assert status == (403 if mode == "earlier-response" else 200)
            identifier = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")
            query = f"http://_safeyolo.proxy.internal/trace?request_id={identifier}"
            status, _, raw = request(paths["alice"], query, headers={"Authorization": f"Bearer {TOKEN}"})
            assert status == 200
            report = json.loads(raw)
            assert report["agent_id"] == "alice" and report["request_id"] == identifier
            assert all("control" in step and "addon" not in step for step in report["steps"] + report["not_loaded"])
            network = next(step for step in report["steps"] if step["control"] == "network" and step["hook"] == "request")
            general = yaml.safe_load((GRAPHS / "triage-request-failing.yaml").read_text())
            if mode in ("disabled", "scope-exception"):
                reason = "control_disabled" if mode == "disabled" else "policy_disabled"
                assert network["state"] == "bypassed" and network["reason"] == reason
                branch = next(edge["to"] for edge in general["edges"]
                              if edge["from"] == "ev.check_trace_request_id"
                              and f"reason={reason}" in edge.get("when", ""))
                ask = next(edge["to"] for edge in general["edges"] if edge["from"] == branch)
                node = next(node for node in general["nodes"] if node["id"] == ask)
                assert "safeyolo policy show" in node["label"]
                assert "controls.<name>.enabled" in node["label"]
            else:
                assert network["state"] == "evaluated"
                assert network["outcome"] == ("blocked" if mode == "earlier-response" else "allowed")
            credential = yaml.safe_load((GRAPHS / "triage-credential-guard.yaml").read_text())
            node = next(node for node in credential["nodes"] if node["id"] == "ev.credguard_check_trace_request_id")
            # Consume the selector the installed graph tells an agent to use.
            selector = re.search(r"control == '([^']+)' and hook ==\s*'([^']+)'", node["detail"])
            assert selector is not None
            control, hook = selector.groups()
            selected = [step for step in report["steps"] if step["control"] == control and step["hook"] == hook]
            if mode == "truncated":
                assert report["truncated"] is True and not selected
                assert report["incomplete"] is True and report["not_loaded"] == []
                missing = next(edge for edge in credential["edges"] if edge["to"] == "cls.credguard_trace_not_loaded")
                assert "truncated=false" in missing["when"]
                assert "incomplete-evidence" in node["detail"]
            else:
                assert report["truncated"] is False and len(selected) == 1
                if mode == "earlier-response":
                    assert selected[0]["state"] == "bypassed" and selected[0]["reason"] == "prior_response"
                    assert selected[0]["details"]["preempted_by"] == "network"
                    assert any(edge["from"] == "ev.credguard_check_trace_request_id"
                               and edge["to"] == "cls.credguard_trace_prior_response" for edge in credential["edges"])
                    assert report["not_loaded"] == [] and report["incomplete"] is False
                    assert origin.accepts == 0
                elif mode == "scope-exception":
                    assert selected[0]["state"] == "bypassed" and selected[0]["reason"] == "policy_disabled"
                    ask = next(edge["to"] for edge in credential["edges"]
                               if edge["from"] == "cls.credguard_trace_policy_disabled")
                    node = next(node for node in credential["nodes"] if node["id"] == ask)
                    assert "controls.credentials.enabled" in node["label"]
                else:
                    assert selected[0]["state"] == "evaluated" and selected[0]["outcome"] == "no_detection"
            foreign_status, _, foreign = request(paths["bob"], query, headers={"Authorization": f"Bearer {TOKEN}"})
            assert foreign_status == 404 and TOKEN.encode() not in foreign
            status, headers, _ = request(paths["alice"], "http://trace.invalid/untraced")
            assert status == (403 if mode == "earlier-response" else 200)
            if mode == "no-match":
                patterns = next(step for step in report["steps"] if step["control"] == "patterns" and step["hook"] == "request")
                assert patterns["state"] == "evaluated" and patterns["outcome"] == "no_match"
                assert isinstance(patterns["duration_us"], int)
            untraced = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")
            status, _, missing = request(paths["alice"], f"http://_safeyolo.proxy.internal/trace?request_id={untraced}",
                                         headers={"Authorization": f"Bearer {TOKEN}"})
            assert status == 404 and json.loads(missing)["error"] == json.loads(foreign)["error"]


@pytest.mark.parametrize("mode", ["healthy", "disabled", "truncated", "one-unavailable", "blocked"])
def test_doctor_command_runs_native_pipeline_for_every_agent(tmp_path, mode):
    """Run the shipped command with only native binaries on its PATH."""
    proxy = Path(os.environ.get("SAFEYOLO_RUST_PROXY", REPO / "proxy/target/release/safeyolo-proxy"))
    cli = Path(os.environ.get("SAFEYOLO_NATIVE_CLI", proxy.with_name("safeyolo")))
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for source, name in ((proxy, "safeyolo-proxy"), (cli, "safeyolo")):
        shutil.copy2(source, binaries / name)
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    token = data / "agent_token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    for directory in ("builtin-services", "services"):
        (tmp_path / directory).mkdir()
    policy = '[hosts]\n"*"={egress="deny"}\n'
    if mode == "disabled":
        policy += '[controls.patterns]\nenabled=false\n'
    if mode == "blocked":
        policy += ('[[scan_patterns]]\nname="probe-block"\npattern="__pipeline_probe"\n'
                   'target="request"\nscope=["url"]\naction="block"\n[controls.patterns]\nrequest="block"\n')
    (tmp_path / "policy.toml").write_text(policy)
    with tempfile.TemporaryDirectory(prefix="sy-doctor-", dir=tmp_path.parent) as sockets, origin_server() as parent:
        paths = {name: Path(sockets) / f"{name}.sock" for name in ("alice", "bob")}
        settings = (f'admin_port=0\nflow_store_enabled=false\n'
                    f'parent_proxy="http://127.0.0.1:{parent.server_address[1]}"\n')
        if mode == "truncated":
            settings += '[trace]\nsteps_max=1\n'
        for index, (name, path) in enumerate(paths.items(), 10):
            settings += (f'[[listeners]]\nagent_id="{name}"\nsource_id="192.0.2.{index}"\n'
                         f'socket_path={json.dumps(str(path))}\n')
        config = tmp_path / "config.toml"
        config.write_text(settings)
        environment = dict(os.environ, PATH=str(binaries))
        with child_process([str(binaries / "safeyolo-proxy"), "--config", str(config)], tmp_path, environment) as process:
            readiness = data / "ready.json"
            wait_ready(process, [readiness, *paths.values()], tmp_path / "process.log",
                       readiness_file=readiness, expected_backend="rust-m2")
            if mode == "one-unavailable":
                paths["bob"].unlink()
            result = subprocess.run([str(binaries / "safeyolo"), "--config", str(config), "doctor"],
                                    cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20)
            assert result.returncode == (1 if mode in ("truncated", "one-unavailable", "blocked") else 0), result.stderr
            report = json.loads(result.stdout)["pipeline"]
            assert report["verdict"] == ("fail" if result.returncode else "pass"), report
            assert [agent["agent"] for agent in report["agents"]] == ["alice", "bob"]
            if mode == "one-unavailable":
                assert [agent["verdict"] for agent in report["agents"]] == ["pass", "fail"]
                assert "unavailable" in str(report["agents"][1]["findings"])
            elif mode == "blocked":
                for agent in report["agents"]:
                    assert agent["probe_status"] == 403 and agent["verdict"] == "fail"
                    patterns = next(step for step in agent["steps"] if step["control"] == "patterns")
                    assert patterns["state"] == "evaluated" and patterns["outcome"] == "match_blocked"
                    assert any(step["control"] == "probe-sink" and step["outcome"] == "probe_preempted" for step in agent["steps"])
            elif mode == "truncated":
                assert all("incomplete or truncated" in str(agent["findings"]) for agent in report["agents"])
            else:
                for agent in report["agents"]:
                    assert agent["probe_status"] == 200 and agent["verdict"] == "pass"
                    steps = [step for step in agent["steps"] if step["hook"] == "request"]
                    assert [step["control"] for step in steps] == [
                        "network", "circuits", "credentials", "services", "patterns", "test_context", "probe-sink",
                    ]
                    patterns = next(step for step in steps if step["control"] == "patterns")
                    if mode == "disabled":
                        assert patterns["state"] == "bypassed" and patterns["reason"] == "control_disabled"
                    else:
                        assert patterns["state"] == "evaluated" and patterns["outcome"] == "no_rules"
                        assert isinstance(patterns["duration_us"], int)
            assert parent.accepts == 0 and parent.requests == []
            assert TOKEN not in result.stdout + result.stderr


@pytest.mark.skipif("SAFEYOLO_TRACE_OVERHEAD_BASELINE" not in os.environ,
                    reason="manual ordinary-request comparison needs a prepared baseline executable")
def test_untraced_request_timing_against_prepared_baseline(tmp_path):
    """Report an alternating real-UDS sample without a product timing threshold."""
    candidate = Path(os.environ.get("SAFEYOLO_RUST_PROXY", REPO / "proxy/target/release/safeyolo-proxy"))
    baseline = Path(os.environ["SAFEYOLO_TRACE_OVERHEAD_BASELINE"])
    samples = {"baseline": [], "candidate": []}
    for index, (label, binary) in enumerate((("baseline", baseline), ("candidate", candidate),
                                             ("candidate", candidate), ("baseline", baseline))):
        root = tmp_path / str(index)
        root.mkdir()
        for name in ("data", "builtin-services", "services"):
            (root / name).mkdir()
        (root / "data/agent_token").write_text(TOKEN)
        (root / "policy.toml").write_text('[hosts]\n"*"={egress="allow"}\n')
        with tempfile.TemporaryDirectory(prefix="sy-timing-", dir=tmp_path.parent) as sockets, origin_server() as origin:
            path = Path(sockets) / "alice.sock"
            config = root / "config.toml"
            config.write_text(f'admin_port=0\nflow_store_enabled=false\nparent_proxy="http://127.0.0.1:{origin.server_address[1]}"\n'
                              f'[[listeners]]\nagent_id="alice"\nsocket_path={json.dumps(str(path))}\n')
            environment = dict(os.environ, PATH=str(binary.parent), TOKIO_WORKER_THREADS="2")
            with child_process([str(binary), "--config", str(config)], root, environment) as process:
                readiness = root / "data/ready.json"
                wait_ready(process, [readiness, path], root / "process.log",
                           readiness_file=readiness, expected_backend="rust-m2")
                for _ in range(20):
                    assert request(str(path), "http://timing.invalid/ordinary")[0] == 200
                for _ in range(5):
                    started = time.perf_counter_ns()
                    for _ in range(100):
                        status, headers, _ = request(str(path), "http://timing.invalid/ordinary")
                        assert status == 200
                    samples[label].append((time.perf_counter_ns() - started) / 100)
                identifier = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")
                assert request(str(path), f"http://_safeyolo.proxy.internal/trace?request_id={identifier}",
                               headers={"Authorization": f"Bearer {TOKEN}"})[0] == 404
                assert len(origin.requests) == 520
    measured = {label: statistics.median(values) / 1000 for label, values in samples.items()}
    print(f"ordinary UDS requests, 10 batches of 100 each: {json.dumps(measured)} microseconds/request")
