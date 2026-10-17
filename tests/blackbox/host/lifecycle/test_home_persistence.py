"""Persistent /home/agent test — verify writes survive sandbox restart.

On macOS (VZ), /home/agent has been persistent since PR #176 via a
VirtioFS bind-mount from ~/.safeyolo/agents/<name>/home/. On Linux
(gVisor), that same host-side directory was created and populated by
host scripts but never mounted into the sandbox, so writes landed in
gVisor's in-memory rootfs overlay and vanished on `agent stop`. This
test is the canary for the Linux OCI bind-mount that closes that gap:
write a marker to /home/agent, stop the sandbox, start the sandbox,
read the marker back.
"""

import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest
from guest_exec import guest_command_args, prepare_guest_tests


class TestAgentHomePersistence:
    """Writes to /home/agent persist across `agent stop` and `agent run`.

    Why: The persistent home is where mise installs, shell history,
    host-script-staged auth (e.g. ~/.claude.json), and any user state
    live. If it doesn't survive a sandbox restart, every `agent run`
    is effectively a fresh install — no auth, no cached tools, no
    shell history. On Linux the memory-backed overlay silently
    discarded those writes before the OCI bind-mount landed; this
    test guards against a regression to that behavior.
    """

    def _safeyolo(self, *args, timeout: int = 30) -> subprocess.CompletedProcess:
        """Run the safeyolo CLI against the test instance.

        Inherits SAFEYOLO_CONFIG_DIR / SAFEYOLO_SUBNET_BASE / SAFEYOLO_LOGS_DIR
        from the run-tests.sh environment so the test instance is
        targeted rather than the operator's production install.
        """
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
            timeout=timeout,
        )

    def _wait_for_shell(self, agent_name: str, timeout: int = 60) -> bool:
        """Poll the selected native guest shell until it succeeds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self._safeyolo(
                "agent", "shell", agent_name, "-c", "true", timeout=10,
            )
            if result.returncode == 0:
                return True
            time.sleep(1)
        return False

    @pytest.fixture
    def restarted_agent(self, request):
        """Prepare the restart with bounded commands before timing readback."""
        agent_name = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")

        # Baseline: sandbox must be running before we start. run-tests.sh
        # boots a fresh sandbox before calling pytest, so if this fails
        # it means the sandbox didn't come up (skip rather than fail to
        # avoid masking upstream boot issues).
        if not self._wait_for_shell(agent_name, timeout=10):
            pytest.skip(f"Agent '{agent_name}' not reachable; sandbox not running")

        marker_path = "/home/agent/.safeyolo-home-persist-probe"
        marker_token = secrets.token_hex(16)
        workspace_name = f".safeyolo-persist-{marker_token}"
        host_marker = Path(__file__).resolve().parents[4] / workspace_name
        request.addfinalizer(lambda: host_marker.unlink(missing_ok=True))
        tool = self._safeyolo(
            "agent", "shell", agent_name, "-c",
            "mise use -g node@22 >&2 && node --version && command -v node", timeout=300,
        )
        assert tool.returncode == 0, tool.stderr
        assert tool.stdout.splitlines()[0].startswith("v22."), tool.stdout
        assert tool.stdout.splitlines()[1].startswith("/home/agent/.mise/"), tool.stdout

        # 1. Write marker from inside the agent.
        write = self._safeyolo(
            "agent", "shell", agent_name, "-c",
            f"printf '%s' '{marker_token}' > {marker_path} && "
            f"printf '%s' '{marker_token}' > /workspace/{workspace_name}",
            timeout=15,
        )
        assert write.returncode == 0, (
            f"Failed to write marker inside agent: rc={write.returncode} "
            f"stdout={write.stdout!r} stderr={write.stderr!r}"
        )
        assert host_marker.read_text() == marker_token

        # 2. Stop the sandbox.
        stop = self._safeyolo("agent", "stop", agent_name, timeout=30)
        assert stop.returncode == 0, (
            f"agent stop failed: rc={stop.returncode} "
            f"stderr={stop.stderr!r}"
        )

        # 3. Start a fresh sandbox for the same agent.
        start = self._safeyolo(
            "agent", "start", agent_name, "--sandbox-only", timeout=60,
        )
        assert start.returncode == 0, (
            f"agent start --sandbox-only failed: rc={start.returncode} "
            f"stderr={start.stderr!r}"
        )
        prepare_guest_tests("safeyolo", agent_name)
        assert self._wait_for_shell(agent_name, timeout=60), (
            f"Agent '{agent_name}' did not become reachable within 60s "
            f"after restart — can't verify persistence"
        )
        return agent_name, marker_path, marker_token, workspace_name, host_marker, tool.stdout

    @pytest.mark.timeout(120, func_only=True)
    def test_home_persists_across_restart(self, restarted_agent):
        """Home, workspace and a deferred mise tool survive stop/start.

        What: Install Node through mise, write markers to the home and
        workspace, and check both markers and the same tool after restart.
        Read the workspace marker on the host too.
        Why: A missing file or mismatched content means writes to
        /home/agent landed somewhere ephemeral (the memory overlay
        on Linux, or an un-mounted location on either platform) —
        the OCI bind-mount is broken or was never wired. Host-script
        auth staging, mise installs, and shell history all rely on
        this invariant.
        """
        # Test provisioning can take its existing 300-second bound. Keep it
        # outside the readback timer; stop/start/shell retain their own limits.
        agent_name, marker_path, marker_token, workspace_name, host_marker, tool_stdout = restarted_agent

        # 4. Read marker back.
        read = self._safeyolo(
            "agent", "shell", agent_name, "-c", f"cat {marker_path}",
            timeout=15,
        )
        assert read.returncode == 0, (
            f"Marker file missing after restart — /home/agent writes "
            f"are not persisting. rc={read.returncode} "
            f"stderr={read.stderr!r}. This is the Linux OCI bind-mount "
            f"regression: either /home/agent isn't mounted from "
            f"~/.safeyolo/agents/<name>/home/ or the mount is broken."
        )
        assert read.stdout.strip() == marker_token, (
            f"Marker content mismatch after restart: "
            f"wrote={marker_token!r} read={read.stdout!r} — "
            f"/home/agent is persisting the wrong bytes (cross-agent "
            f"leak? stale cache? inode reuse?)"
        )
        workspace = self._safeyolo(
            "agent", "shell", agent_name, "-c", f"cat /workspace/{workspace_name}", timeout=15,
        )
        assert workspace.returncode == 0 and workspace.stdout == marker_token, workspace.stderr
        assert host_marker.read_text() == marker_token
        restored_tool = self._safeyolo(
            "agent", "shell", agent_name, "-c", "node --version && command -v node", timeout=15,
        )
        assert restored_tool.returncode == 0 and restored_tool.stdout == tool_stdout, restored_tool.stderr
