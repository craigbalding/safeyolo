"""Host-side agent identity tests.

Validates the agent_map and PROXY protocol v2 identity chain after
an agent starts. Runs on the host (not inside the VM) with a running
sandbox.
"""

import json
import os
import sys
import tomllib
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
        """Per-agent proxy socket referenced in the entry exists on disk.

        What: Reads the 'socket' field and asserts the path is a
        live Unix domain socket (Path.is_socket()).
        Why: The per-agent UDS (bound by mitmproxy's
        UnixInstance) is the only egress path for the agent. A missing or
        stale socket means every agent request fails with ENOENT —
        effectively a denial of service, not a security issue, but a strong
        signal that the identity chain is broken.
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


class TestRootlessUidMapping:
    """Linux sandbox identities map to non-root host identities.

    Why: SafeYolo intentionally permits namespace-root for package
    installation. Its host safety depends on the enclosing user
    namespace mapping sandbox uid 0 to a subordinate uid while mapping
    sandbox uid 1000 to the operator for workspace access.
    """

    def test_sandbox_root_maps_to_subordinate_host_uid(self):
        """Sandbox root maps to the selected subordinate UID and GID.

        What: Read the live namespace holder's UID and GID maps. Check
        that root uses the prepared bases and guest ID 1000 uses the
        host account. Retain the original mapping for older packages.
        Why: If sandbox uid 0 mapped to host uid 0, setpriv or a package
        maintainer script would gain real host root. If uid 1000 did
        not map to the operator, normal workspace ownership would fail.
        """
        if sys.platform != "linux":
            pytest.skip("Linux rootless user namespaces only")

        pid_path = _CONFIG_DIR / "agents" / _AGENT_NAME / "userns.pid"
        assert pid_path.exists(), f"Userns holder PID not found: {pid_path}"
        try:
            pid = int(pid_path.read_text().strip())
        except ValueError as exc:
            pytest.fail(f"Invalid userns holder PID in {pid_path}: {exc}")

        linux = tomllib.loads((_CONFIG_DIR / "config.toml").read_text()).get("linux")
        for kind, operator in (("uid", os.getuid()), ("gid", os.getgid())):
            base = linux[f"{kind}_base"] if linux else 100000
            assert base != 0, f"selected {kind} base maps to host root"
            map_path = Path(f"/proc/{pid}/{kind}_map")
            assert map_path.exists(), f"live {kind} map missing for holder PID {pid}"
            mappings = [tuple(map(int, line.split())) for line in map_path.read_text().splitlines() if line.strip()]
            expected = [(0, base, 1000), (1000, operator, 1), (1001, base + 1001, 64535)]
            legacy = [*expected[:2], (1001, base + 1001, 64534)]
            assert mappings == expected or not linux and mappings == legacy, (
                f"live {kind} map differs from the selected rootless mapping: {mappings}"
            )
