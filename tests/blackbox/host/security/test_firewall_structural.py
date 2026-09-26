"""Host-side process security tests.

Verifies the proxy process doesn't leak secrets via its command line,
observable by local users via `ps` or `/proc/PID/cmdline`.
"""

import json
import os
import subprocess

import pytest


class TestProcessSecrecy:
    """Proxy process doesn't leak SafeYolo tokens via its cmdline.

    Why: Process command lines are readable by any local user via
    `ps aux` or `/proc/PID/cmdline`. If SafeYolo tokens appear in
    the mitmdump invocation, a non-root user on the host (or a
    process that escaped the sandbox) can read them and gain full
    admin control. Tokens must be passed via file or env var instead.
    """

    def test_no_tokens_in_process_cmdline(self):
        """Admin and agent tokens do not appear in the selected proxy cmdline.

        What: Inspect the native receipt's PID or the retained mitmdump
        process command line; assert neither token is a substring.
        Why: A token in the cmdline is readable by any local user —
        full admin access leaks to anyone with shell on the host.
        """
        from pathlib import Path
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))

        # Read the actual admin token from file for comparison
        admin_token_file = config_dir / "data" / "admin_token"
        if not admin_token_file.exists():
            if os.environ.get("SAFEYOLO_BLACKBOX_PROXY_BACKEND") == "rust":
                pytest.fail("Selected native instance has no admin token file")
            pytest.skip("Admin token file not found")
        admin_token = admin_token_file.read_text().strip()
        assert len(admin_token) > 10, "Admin token suspiciously short"

        # The native lane names the actual process in its owned receipt.
        # The retained Python lane uses its existing mitmdump observation.
        if os.environ.get("SAFEYOLO_BLACKBOX_PROXY_BACKEND") == "rust":
            receipt = json.loads((config_dir / "data" / "proxy-rust.json").read_text())
            pid = receipt["pid"]
            if os.path.exists(f"/proc/{pid}/cmdline"):
                cmdline = (Path(f"/proc/{pid}/cmdline").read_bytes()
                           .replace(b"\0", b" ").decode())
            else:
                result = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "command="],
                    capture_output=True, text=True, timeout=5,
                )
                assert result.returncode == 0, f"native proxy PID {pid} is unavailable"
                cmdline = result.stdout
            assert "safeyolo-proxy" in cmdline
        else:
            result = subprocess.run(
                ["pgrep", "-a", "-f", "mitmdump"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0 or not result.stdout.strip():
                pytest.skip("mitmdump process not found")
            cmdline = result.stdout
        assert admin_token not in cmdline, "Admin API token appears in the proxy command line"

        # Also check agent token
        agent_token_file = config_dir / "data" / "agent_token"
        if agent_token_file.exists():
            agent_token = agent_token_file.read_text().strip()
            assert agent_token not in cmdline, (
                "Agent token appears in the proxy process cmdline!"
            )
