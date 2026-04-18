"""Host-side agent identity tests.

Validates the agent_map and PROXY protocol v2 identity chain after
an agent starts. Runs on the host (not inside the VM) with a running
sandbox.
"""

import json
import os
from pathlib import Path

import pytest

_CONFIG_DIR = Path(os.environ.get(
    "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
))
_AGENT_NAME = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")


class TestAgentMap:
    """Verify agent_map.json has correct entries for running agents."""

    def test_agent_map_has_entry(self):
        """After agent start, agent_map.json must contain an entry for
        the agent with attribution_ip and socket path.
        """
        map_path = _CONFIG_DIR / "data" / "agent_map.json"
        if not map_path.exists():
            pytest.fail(f"agent_map.json not found at {map_path}")

        data = json.loads(map_path.read_text())
        assert _AGENT_NAME in data, (
            f"Agent '{_AGENT_NAME}' not in agent_map.json. "
            f"Entries: {list(data.keys())}"
        )

    def test_agent_map_has_attribution_ip(self):
        """The agent_map entry must have a valid attribution IP."""
        map_path = _CONFIG_DIR / "data" / "agent_map.json"
        if not map_path.exists():
            pytest.skip("agent_map.json not found")
        data = json.loads(map_path.read_text())
        entry = data.get(_AGENT_NAME)
        if not entry:
            pytest.skip(f"Agent '{_AGENT_NAME}' not in agent_map")

        ip = entry.get("ip", "")
        assert ip, f"No attribution IP for agent '{_AGENT_NAME}'"
        # Attribution IPs are in the 10.200.x.y range
        assert ip.startswith("10.200."), (
            f"Attribution IP '{ip}' not in expected 10.200.x.y range"
        )

    def test_agent_map_has_socket(self):
        """The agent_map entry must reference a bridge socket that exists."""
        map_path = _CONFIG_DIR / "data" / "agent_map.json"
        if not map_path.exists():
            pytest.skip("agent_map.json not found")
        data = json.loads(map_path.read_text())
        entry = data.get(_AGENT_NAME)
        if not entry:
            pytest.skip(f"Agent '{_AGENT_NAME}' not in agent_map")

        sock = entry.get("socket", "")
        assert sock, f"No bridge socket for agent '{_AGENT_NAME}'"
        assert Path(sock).is_socket(), (
            f"Bridge socket does not exist: {sock}"
        )
