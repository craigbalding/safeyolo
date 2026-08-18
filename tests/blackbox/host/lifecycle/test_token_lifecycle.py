"""Live-agent lifecycle test — verify egress survives proxy restart.

In the Docker era, the agent_token file was bind-mounted into the
container, so the proxy could regenerate it on restart and the
container immediately saw the new value. The microVM migration
replaced the bind mount with a copy (shutil.copy2 at staging time +
cp in guest-init), breaking the live-update path.

This test exercises the full lifecycle:
1. Start proxy (token generated)
2. Boot agent, verify agent API works
3. Restart proxy (token may regenerate)
4. Verify the recreated UDS is reachable from the SAME running sandbox

This catches both stale token copies and stale bind-mounted UDS inodes.
"""

import json
import os
import subprocess
import sys
import time

import pytest


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
    exposes to itself. In the Docker stack this worked via bind-mount;
    the microVM migration introduced a copy step that is the common
    regression point.
    """

    def _safeyolo(self, *args, **kwargs):
        env = {
            **os.environ,
            "SAFEYOLO_CONFIG_DIR": os.environ.get("SAFEYOLO_CONFIG_DIR", ""),
            "SAFEYOLO_SUBNET_BASE": os.environ.get("SAFEYOLO_SUBNET_BASE", "75"),
            "SAFEYOLO_LOGS_DIR": os.environ.get("SAFEYOLO_LOGS_DIR", ""),
        }
        return subprocess.run(
            ["safeyolo"] + list(args),
            capture_output=True, text=True, env=env,
            timeout=kwargs.get("timeout", 30),
        )

    def _agent_api_health(self, agent_name: str) -> int:
        """Hit agent API /health from inside the sandbox, return HTTP status."""
        result = self._safeyolo(
            "agent", "shell", agent_name, "-c",
            'curl -s -o /dev/null -w "%{http_code}" '
            '-H "Authorization: Bearer $(cat /app/agent_token)" '
            '--max-time 5 '
            'http://_safeyolo.proxy.internal/health',
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
        from pathlib import Path
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))
        agent_name = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")
        from safeyolo.sockets import path_for
        map_data = json.loads(
            (config_dir / "data" / "agent_map.json").read_text()
        )
        socket_path = path_for(agent_name, map_data[agent_name]["ip"])
        socket_directory_inode = socket_path.parent.stat().st_ino

        # 1. Verify sandbox is running and agent API works
        status = self._agent_api_health(agent_name)
        if status == 0:
            pytest.skip(f"Agent '{agent_name}' not running or agent API unreachable")
        assert status == 200, (
            f"Agent API returned {status} before proxy restart — "
            f"baseline broken, can't test lifecycle"
        )

        # 2. Record current token
        token_file = config_dir / "data" / "agent_token"
        token_before = token_file.read_text().strip() if token_file.exists() else ""

        # 3. Restart proxy
        self._safeyolo("stop", timeout=15)
        time.sleep(1)
        self._safeyolo("start", "--test", "--no-wait", timeout=15)

        # Wait for proxy health
        for _ in range(15):
            try:
                import httpx
                admin_url = os.environ.get("ADMIN_URL", "http://127.0.0.1:9190")
                token_path = config_dir / "data" / "admin_token"
                admin_token = token_path.read_text().strip() if token_path.exists() else ""
                r = httpx.get(
                    f"{admin_url}/health",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=2,
                )
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(1)

        # 4. Check if token changed
        token_after = token_file.read_text().strip() if token_file.exists() else ""
        token_changed = token_before != token_after

        # 5. Verify agent API still works from the SAME running sandbox
        status = self._agent_api_health(agent_name)
        assert status == 200, (
            f"Agent API returned {status} after proxy restart "
            f"(token {'changed' if token_changed else 'unchanged'}) — "
            f"this is the Docker→microVM token lifecycle regression. "
            f"The sandbox holds a stale copy of the agent token."
        )
        assert socket_path.is_socket(), "proxy restart did not recreate the agent UDS"
        assert socket_path.parent.stat().st_ino == socket_directory_inode, (
            "proxy restart replaced the stable per-agent socket directory"
        )
