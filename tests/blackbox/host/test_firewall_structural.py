"""Host-side process security tests.

Verifies the proxy process doesn't leak secrets via its cmdline or
environment — observable by any local user via `ps aux` or
`/proc/PID/cmdline`.
"""

import os
import subprocess

import pytest


class TestProcessSecrecy:
    """Verify the proxy process doesn't leak secrets via its cmdline."""

    def test_no_tokens_in_process_cmdline(self):
        """The mitmdump/proxy process cmdline (visible via ps aux or
        /proc/PID/cmdline to any user on the host) must not contain
        tokens or secrets. If the admin token appears there, any
        local user (or an agent that escapes the sandbox) can read it
        and gain full SafeYolo admin control.
        """
        from pathlib import Path
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))

        # Read the actual admin token from file for comparison
        admin_token_file = config_dir / "data" / "admin_token"
        if not admin_token_file.exists():
            pytest.skip("Admin token file not found")
        admin_token = admin_token_file.read_text().strip()
        assert len(admin_token) > 10, "Admin token suspiciously short"

        # Find the proxy process and read its cmdline
        result = subprocess.run(
            ["pgrep", "-a", "-f", "mitmdump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0 or not result.stdout.strip():
            pytest.skip("mitmdump process not found")

        cmdline = result.stdout
        assert admin_token not in cmdline, (
            f"Admin API token appears in the mitmdump process cmdline! "
            f"Any local user can read it via `ps aux`. The token should "
            f"be passed via file or environment variable, not CLI arg.\n"
            f"Token (first 8 chars): {admin_token[:8]}...\n"
            f"Found in: {cmdline[:200]}..."
        )

        # Also check agent token
        agent_token_file = config_dir / "data" / "agent_token"
        if agent_token_file.exists():
            agent_token = agent_token_file.read_text().strip()
            assert agent_token not in cmdline, (
                "Agent token appears in the mitmdump process cmdline!"
            )
