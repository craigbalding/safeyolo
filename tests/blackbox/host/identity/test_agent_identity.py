"""Host-side agent identity tests.

Validates the host listener identity after
an agent starts. Runs on the host (not inside the VM) with a running
sandbox.
"""

import os
import sys
import tomllib
from pathlib import Path

import pytest

_CONFIG_DIR = Path(os.environ.get(
    "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
))
_AGENT_NAME = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")


class TestAgentListener:
    """Host-owned Unix domain sockets supply each agent's request identity.

    Why: A missing or shared listener can break guest egress or attribute
    requests to the wrong agent. Policy and evidence need the correct identity.
    """

    @staticmethod
    def listener():
        from installed_host_smoke import _agent_listeners

        listeners = [entry for entry in _agent_listeners(_CONFIG_DIR) if entry["agent_id"] == _AGENT_NAME]
        assert len(listeners) == 1, f"Expected one listener for {_AGENT_NAME}: {listeners}"
        return listeners[0]

    def test_agent_listener_has_entry(self):
        """The running agent has a configured listener.

        What: Read the host's native listener configuration and find the agent.
        Why: Listener ownership determines policy and evidence attribution.
        """
        assert self.listener()["agent_id"] == _AGENT_NAME

    def test_agent_listener_has_attribution_ip(self):
        """The managed listener retains its attribution IP.

        What: Check the listener source address is in 10.200.0.0/16.
        Why: Host lifecycle operations reserve this range for managed agents.
        """
        assert self.listener()["ip"].startswith("10.200.")

    def test_agent_listener_has_socket(self):
        """The configured proxy socket is present.

        What: Check that the configured listener path is a Unix domain socket.
        Why: Each guest needs its host-owned socket for proxy egress.
        """
        assert Path(self.listener()["path"]).is_socket()


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
