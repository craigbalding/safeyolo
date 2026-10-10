"""Live-agent lifecycle test — verify egress survives proxy restart.

The agent_token is copied into the guest at staging time and again by
guest-init on boot; there is no live-update channel back to the sandbox
after the proxy regenerates the token or the UDS inode. The token- and
socket-refresh path has to be reproduced correctly on every proxy
restart, and any regression only shows up when a running sandbox tries
to use the agent API after the restart.

This test exercises the full lifecycle:
1. Start proxy (token generated)
2. Boot agent, verify agent API works
3. Restart proxy (token may regenerate)
4. Verify the recreated UDS is reachable from the SAME running sandbox

This catches stale token copies and stale UDS inode references.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from guest_exec import guest_command_args
from installed_host_smoke import _agent_map, _native_config, _runtime_observation


@pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "Proxy restart under a live macOS VZ sandbox is deliberately skipped: "
        "the VZ helper + snapshot/restore dance is sensitive to proxy-side "
        "state changes mid-flight. Linux gVisor can cycle the proxy cleanly "
        "while the sandbox stays up; macOS coverage for the token-copy path "
        "is exercised by the sandbox-boot flow itself."
    ),
)
class TestLiveAgentLifecycle:
    """Agent egress survives proxy restart without restarting its sandbox.

    Why: The agent_token authenticates the sandbox's requests to the
    agent API. If a proxy restart regenerates the token but the
    sandbox still holds the old value, the agent gets 401 on every
    diagnostic call — breaking `safeyolo explain`, credential
    approval UX, and any other observability feature the agent
    exposes to itself. Token- and UDS-inode refresh across a proxy
    restart is the common regression point this test catches.
    """

    def _safeyolo(self, *args, **kwargs):
        env = {
            **os.environ,
            "SAFEYOLO_CONFIG_DIR": os.environ.get("SAFEYOLO_CONFIG_DIR", ""),
            "SAFEYOLO_SUBNET_BASE": os.environ.get("SAFEYOLO_SUBNET_BASE", "75"),
            "SAFEYOLO_LOGS_DIR": os.environ.get("SAFEYOLO_LOGS_DIR", ""),
        }
        command = (guest_command_args("safeyolo", args[2], args[4])
                   if args[:2] == ("agent", "shell") else ["safeyolo", *args])
        return subprocess.run(
            command,
            capture_output=True, text=True, env=env,
            timeout=kwargs.get("timeout", 30),
        )

    def _agent_api_health(self, agent_name: str) -> int:
        """Hit agent API /health from inside the sandbox, return HTTP status."""
        result = self._safeyolo(
            "agent", "shell", agent_name, "-c",
            '(agent_token=$(cat /app/agent_token) || exit; '
            'printf \'Authorization: Bearer %s\\n\' "$agent_token" | '
            'curl -s -o /dev/null -w "%{http_code}" --header @- '
            '--max-time 5 http://_safeyolo.proxy.internal/health)',
            timeout=15,
        )
        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    def test_agent_api_survives_proxy_restart(self):
        """Agent API stays reachable from the sandbox across proxy restart.

        What: Verify agent API /health returns 200 from inside the
        sandbox; stop + start the test proxy; assert /health still
        returns 200 from the same running sandbox.
        Why: A recreated token or Unix socket must remain reachable from
        the same sandbox. File-binding the old socket inode made every
        reconnect fail even though the host pathname had been recreated.
        """
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))
        agent_name = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")
        listener = next(row for row in _agent_map(config_dir) if row["agent_id"] == agent_name)
        socket_path = Path(listener["path"])
        socket_directory_inode = socket_path.parent.stat().st_ino
        config_path = config_dir / "config.toml"
        runtime_before = _runtime_observation(
            config_dir, _native_config(config_path, config_dir), config_dir / "bin/safeyolo-proxy",
            config_path=config_path, working_directory=config_dir,
            require_running=True, require_authenticated_identity=True,
        )
        agent_before = self._safeyolo("agent", "status", agent_name)
        assert agent_before.returncode == 0, agent_before.stderr
        sandbox_before = json.loads(agent_before.stdout)
        assert sandbox_before["runtime_state"] == "running", "selected sandbox is not running"
        assert sandbox_before["name"] == agent_name and sandbox_before["agent_id"] and sandbox_before["run_id"]

        # 1. Verify sandbox is running and agent API works
        status = self._agent_api_health(agent_name)
        assert status == 200, (
            f"Agent API returned {status} before proxy restart — "
            f"baseline broken, can't test lifecycle"
        )

        # 2. Record current token
        token_file = config_dir / "data" / "agent_token"
        token_before = token_file.read_text().strip()
        assert token_before, "selected native instance has no agent token"

        # 3. Restart proxy
        stopped = self._safeyolo("stop", timeout=15)
        assert stopped.returncode == 0, stopped.stderr
        started = self._safeyolo("start", timeout=15)
        assert started.returncode == 0, started.stderr
        # Native start waits for readiness. Authenticate the new incarnation
        # instead of polling an inherited Admin URL from the retired launcher.
        runtime_after = _runtime_observation(
            config_dir, _native_config(config_path, config_dir), config_dir / "bin/safeyolo-proxy",
            config_path=config_path, working_directory=config_dir,
            require_running=True, require_authenticated_identity=True,
        )
        assert runtime_after["receipt"]["start_token"] != runtime_before["receipt"]["start_token"], (
            "proxy restart did not replace the selected native process"
        )
        agent_after = self._safeyolo("agent", "status", agent_name)
        assert agent_after.returncode == 0, agent_after.stderr
        sandbox_after = json.loads(agent_after.stdout)
        assert sandbox_after["runtime_state"] == "running", "selected sandbox stopped during proxy restart"
        assert all(sandbox_after[key] == sandbox_before[key] for key in ("name", "agent_id", "run_id")), (
            "proxy restart changed the selected sandbox identity"
        )

        # 4. Check if token changed
        token_after = token_file.read_text().strip()
        token_changed = token_before != token_after

        # 5. Verify agent API still works from the SAME running sandbox
        status = self._agent_api_health(agent_name)
        assert status == 200, (
            f"Agent API returned {status} after proxy restart "
            f"(token {'changed' if token_changed else 'unchanged'}) — "
            f"token lifecycle regression: the sandbox holds a stale "
            f"copy of the agent token or the UDS inode was not refreshed."
        )
        assert socket_path.is_socket(), "proxy restart did not recreate the agent UDS"
        assert socket_path.parent.stat().st_ino == socket_directory_inode, (
            "proxy restart replaced the stable per-agent socket directory"
        )
