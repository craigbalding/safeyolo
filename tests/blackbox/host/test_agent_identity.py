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
    """Agent identity is registered in agent_map.json after start.

    Why: Every request the proxy sees is attributed to an agent by
    looking up the client IP in agent_map.json. If an agent is not
    registered, service_discovery can't name it and downstream addons
    (flow_recorder, network_guard scoping) fall back to 'unknown' —
    cross-agent isolation collapses.
    """

    def test_agent_map_has_entry(self):
        """agent_map.json contains an entry for the running agent.

        What: Reads ~/.safeyolo/data/agent_map.json and asserts the
        agent name is a key.
        Why: Without the entry, service_discovery can't map the
        agent's PROXY-v2 attribution IP back to a name.
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
        """Attribution IP is in the 10.200.0.0/16 range.

        What: Reads the agent's entry and asserts the 'ip' field
        starts with '10.200.'.
        Why: The attribution IP range is load-bearing — the PROXY-v2
        parser and service_discovery both assume this prefix. An IP
        outside the range indicates network_guard isolation was
        misconfigured and traffic would be unattributable.
        """
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
        """Bridge socket referenced in the entry exists on disk.

        What: Reads the 'socket' field and asserts the path is a
        live Unix domain socket (Path.is_socket()).
        Why: The bridge socket is the only egress path for the agent.
        A missing or stale socket means every agent request fails with
        ENOENT — effectively a denial of service, not a security
        issue, but a strong signal that the identity chain is broken.
        """
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
