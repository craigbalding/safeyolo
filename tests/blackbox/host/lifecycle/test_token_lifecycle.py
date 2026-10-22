"""Live-agent lifecycle test — verify egress survives proxy restart.

The native proxy and guest have separate lifetimes. Proxy replacement must
preserve the running guest, its persistent home and authenticated access.
The test records the proxy incarnation and live backend birth before stop,
while the proxy is stopped, and after start. Guest health and marked allowed
traffic must work on both sides of that replacement.

This catches stale tokens and Unix-domain socket references without replacing
the guest or its installed boot inputs.
"""

import json
import os
import shlex
import subprocess
import uuid
from pathlib import Path

from guest_exec import guest_command_args
from installed_host_smoke import _agent_listeners, _native_config, _runtime_observation
from installed_lifecycle import running_guest


class TestLiveAgentLifecycle:
    """Agent egress survives proxy restart without restarting its sandbox.

    Why: A running guest must retain authenticated Agent API and proxy access
    after proxy replacement. Boot-time health cannot prove that the same
    guest reconnects to the recreated socket with its current token.
    """

    def _safeyolo(self, *args, **kwargs):
        env = {
            **os.environ,
            "SAFEYOLO_CONFIG_DIR": os.environ.get("SAFEYOLO_CONFIG_DIR", ""),
            "SAFEYOLO_SUBNET_BASE": os.environ.get("SAFEYOLO_SUBNET_BASE", "75"),
            "SAFEYOLO_LOGS_DIR": os.environ.get("SAFEYOLO_LOGS_DIR", ""),
        }
        cli = os.environ.get("SAFEYOLO_NATIVE_CLI", "safeyolo")
        command = (guest_command_args(cli, args[2], args[4])
                   if args[:2] == ("agent", "shell") else [cli, "--root", env["SAFEYOLO_CONFIG_DIR"], *args])
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
        assert result.returncode == 0, result.stderr
        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    def _sandbox(self, config_dir: Path, agent_name: str) -> dict:
        status = self._safeyolo("agent", "status", agent_name)
        assert status.returncode == 0, status.stderr
        return running_guest(config_dir, agent_name, json.loads(status.stdout))

    def _allowed_traffic(self, agent_name: str, marker: str) -> dict:
        # Both maintained origins echo parsed.path, without its query string.
        path = f"/get/{marker}"
        command = shlex.join([
            "curl", "-fsS", "--max-time", "10", "-H",
            f"X-SafeYolo-Test-Context: run=proxy-restart;agent={agent_name}",
            "http://httpbin.org" + path,
        ])
        result = self._safeyolo("agent", "shell", agent_name, "-c", command, timeout=20)
        assert result.returncode == 0, result.stderr
        response = json.loads(result.stdout)
        assert response["received"] is True and response["host"] == "httpbin.org" and response["path"] == path
        return response

    def test_agent_api_survives_proxy_restart(self):
        """Agent API stays reachable from the sandbox across proxy restart.

        What: Verify agent API /health returns 200 from inside the
        sandbox and deliver a marked proxy request. Stop and start the proxy.
        Require the same guest/backend birth, health, traffic and home state.
        Why: A recreated token or Unix socket must remain reachable from
        the same sandbox. File-binding the old socket inode made every
        reconnect fail even though the host pathname had been recreated.
        """
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))
        agent_name = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")
        artifacts = Path(os.environ.get("SAFEYOLO_BLACKBOX_ARTIFACTS_DIR", str(config_dir / "logs")))
        artifacts.mkdir(parents=True, exist_ok=True)
        report = {"config_dir": str(config_dir), "agent": agent_name}
        output = artifacts / "proxy-restart.json"

        def save():
            output.write_text(json.dumps(report, indent=2) + "\n")

        save()
        try:
            self._restart(config_dir, agent_name, report, save)
        finally:
            save()

    def _restart(self, config_dir: Path, agent_name: str, report: dict, save) -> None:
        listener = next(row for row in _agent_listeners(config_dir) if row["agent_id"] == agent_name)
        socket_path = Path(listener["path"])
        socket_directory_inode = socket_path.parent.stat().st_ino
        config_path = config_dir / "config.toml"
        runtime_before = _runtime_observation(
            config_dir, _native_config(config_path, config_dir), config_dir / "bin/safeyolo-proxy",
            config_path=config_path, working_directory=config_dir,
            require_running=True, require_authenticated_identity=True,
        )
        sandbox_before = self._sandbox(config_dir, agent_name)
        report.update(proxy_before=runtime_before, guest_before=sandbox_before,
                      socket=str(socket_path), socket_directory_inode=socket_directory_inode)
        save()
        marker = "proxy-restart-" + uuid.uuid4().hex
        filename = ".safeyolo-blackbox-" + marker
        home_file = config_dir / "agents" / agent_name / "home" / filename
        written = self._safeyolo("agent", "shell", agent_name, "-c",
                                 f"printf '%s' {shlex.quote(marker)} > /home/agent/{filename}")
        assert written.returncode == 0, written.stderr
        assert home_file.read_text() == marker, "guest write did not reach its persistent host home"
        home_before = home_file.stat()
        report["home"] = {"path": str(home_file), "marker": marker}

        # 1. Verify sandbox is running and agent API works
        status = self._agent_api_health(agent_name)
        report["health_before"] = status
        save()
        assert status == 200, (
            f"Agent API returned {status} before proxy restart — "
            f"baseline broken, can't test lifecycle"
        )
        report["traffic_before"] = self._allowed_traffic(agent_name, marker + "-before")
        save()

        # 2. Record current token
        token_file = config_dir / "data" / "agent_token"
        token_before = token_file.read_text().strip()
        assert token_before, "selected native instance has no agent token"

        # 3. Restart proxy
        stopped = self._safeyolo("stop", timeout=15)
        assert stopped.returncode == 0, stopped.stderr
        report["guest_without_proxy"] = self._sandbox(config_dir, agent_name)
        save()
        assert report["guest_without_proxy"] == sandbox_before, "proxy stop changed the selected sandbox identity"
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
        assert runtime_after["authenticated_runtime_identity"]["instance_id"] != runtime_before["authenticated_runtime_identity"]["instance_id"], (
            "proxy restart retained the previous authenticated instance"
        )
        report["proxy_after"] = runtime_after
        sandbox_after = self._sandbox(config_dir, agent_name)
        report["guest_after"] = sandbox_after
        save()
        assert sandbox_after == sandbox_before, (
            "proxy restart changed the selected sandbox identity"
        )

        # 4. Check if token changed
        token_after = token_file.read_text().strip()
        token_changed = token_before != token_after
        report["token_changed"] = token_changed

        # 5. Verify agent API still works from the SAME running sandbox
        status = self._agent_api_health(agent_name)
        report["health_after"] = status
        save()
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
        report["traffic_after"] = self._allowed_traffic(agent_name, marker + "-after")
        read = self._safeyolo("agent", "shell", agent_name, "-c", f"cat /home/agent/{filename}")
        assert read.returncode == 0 and read.stdout == marker, "guest lost its persistent home marker"
        home_after = home_file.stat()
        assert home_file.read_text() == marker, "proxy restart lost persistent host home state"
        report["home"].update(before={"device": home_before.st_dev, "inode": home_before.st_ino},
                              after={"device": home_after.st_dev, "inode": home_after.st_ino})
        report["passed"] = True
        home_file.unlink()
