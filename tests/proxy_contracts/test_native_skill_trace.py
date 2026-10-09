"""Exercise shipped trace selectors against the native TOML/UDS boundary.

Reuse a prepared proxy executable; do not build it or allocate a guest here.
All policy, authentication and origin state is disposable and synthetic.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

import pytest
import yaml

from tests.proxy_contracts.harness import child_process, request, wait_ready
from tests.proxy_contracts.scenarios import origin_server

REPO = Path(__file__).resolve().parents[2]
GRAPHS = REPO / "cli/src/safeyolo/agent_context/skills/safeyolo/references/graph"
TOKEN = "synthetic-native-skill-trace"


@pytest.mark.parametrize("mode", ["enabled", "disabled", "scope-exception", "truncated"])
def test_native_trace_selectors_and_disabled_control_routes(tmp_path, mode):
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", str(REPO / "proxy/target/debug/safeyolo-proxy")))
    assert binary.is_file(), "Supply the prepared native proxy; unavailable execution is not a pass"
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    for directory in ("builtin-services", "services"):
        (tmp_path / directory).mkdir()
    token = data / "agent_token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    policy = '[hosts]\n"*"={egress="allow"}\n'
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
            assert status == 200
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
                assert network["state"] == "evaluated" and network["outcome"] == "allowed"
            credential = yaml.safe_load((GRAPHS / "triage-credential-guard.yaml").read_text())
            node = next(node for node in credential["nodes"] if node["id"] == "ev.credguard_check_trace_request_id")
            # Consume the selector the installed graph tells an agent to use.
            selector = re.search(r"control == '([^']+)' and hook ==\s*'([^']+)'", node["detail"])
            assert selector is not None
            control, hook = selector.groups()
            selected = [step for step in report["steps"] if step["control"] == control and step["hook"] == hook]
            if mode == "truncated":
                assert report["truncated"] is True and not selected
                assert {"control": control, "state": "not_loaded"} in report["not_loaded"]
                missing = next(edge for edge in credential["edges"] if edge["to"] == "cls.credguard_trace_not_loaded")
                assert "truncated=false" in missing["when"]
                assert "incomplete-evidence" in node["detail"]
            else:
                assert report["truncated"] is False and len(selected) == 1
                if mode == "scope-exception":
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
            assert status == 200
            untraced = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")
            status, _, missing = request(paths["alice"], f"http://_safeyolo.proxy.internal/trace?request_id={untraced}",
                                         headers={"Authorization": f"Bearer {TOKEN}"})
            assert status == 404 and json.loads(missing)["error"] == json.loads(foreign)["error"]
