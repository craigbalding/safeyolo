"""Shared native callers refuse raw running state when runtime proof is absent.

The installed fixture runs real CLI and Admin calls with a filtered PATH. It
starts no sandbox or model. Guest clock/process checks run in guest/command.
"""

from __future__ import annotations

import json
import sys
import time

import pytest
import tomlkit

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_native_policy_cli import native_instance

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Local native caller control selects Linux")


def test_installed_callers_keep_unavailable_managed_state_unverified(tmp_path):
    with native_instance(tmp_path) as instance:
        created = instance.cli("agent", "create", "marker", "--workspace", str(tmp_path),
                               "--launcher", "supervisor")
        assert created.returncode == 0, created.stderr
        agent_id = json.loads(created.stdout)["configuration"]["id"]
        directory = instance.root / "agents/marker"
        # Unknown backend evidence cannot become running from guest-writable
        # state, even when that state claims a fresh host-time heartbeat.
        (directory / "runtime.json").write_bytes(b"{")
        launch = {"name": "marker", "agent_id": agent_id, "launch_id": "launch-current",
                  "launcher": {"kind": "supervisor"}, "state": "managed", "command": "exec marker"}
        (directory / "current-launch.json").write_text(json.dumps(launch))
        state = directory / "home/.safeyolo-command-supervisor.json"
        state.parent.mkdir(exist_ok=True)
        state.write_text(json.dumps({"schema_version": 1, "name": "marker", "state": "running",
                                     "command": "exec marker", "runtime_owner": "guest-pid1",
                                     "generation": "0123456789abcdef0123456789abcdef",
                                     "supervision_id": "launch-current", "heartbeat_at": time.time()}))
        original = state.read_bytes()
        observations = []
        for arguments in [("agent", "status", "marker"), ("agent", "diagnostics", "marker"),
                          ("status",), ("doctor",)]:
            result = instance.cli(*arguments)
            assert result.returncode == 0, result.stderr
            value = json.loads(result.stdout)
            observations.append(value["agents"][0] if "agents" in value else value)
        observations.extend(instance.admin("GET", "/admin/agents")["agents"])
        for observed in observations:
            assert observed["agent_id"] == agent_id and observed["launch_id"] == "launch-current"
            assert observed["runtime_state"] == observed["agent_state"] == "unknown"
        refused = instance.cli("agent", "start", "marker")
        assert refused.returncode != 0 and "unknown" in refused.stderr
        # The approval view uses the same authenticated Admin inventory.
        policy = tomlkit.parse(instance.policy.read_text())
        policy["hosts"]["*"]["egress"] = "prompt"
        instance.apply(tomlkit.dumps(policy))
        status, _, _ = request(instance.paths["alice"], "http://helper.invalid/marker")
        assert status == 428
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        assert len(pending) == 1
        shared = instance.cli("approvals", "share", pending[0]["request_id"], "--helper", "marker")
        assert shared.returncode == 0, shared.stderr
        helper = json.loads(shared.stdout)["helper_session"]
        assert helper["available"] is False and helper["state"]["agent_state"] == "unknown"
        assert state.read_bytes() == original
        assert json.loads((directory / "current-launch.json").read_text()) == launch
