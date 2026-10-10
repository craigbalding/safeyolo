"""Host-side process security tests.

Verifies the proxy process doesn't leak secrets via its command line,
observable by local users via `ps` or `/proc/PID/cmdline`.
"""

import os
from pathlib import Path

from installed_host_smoke import (
    _native_config,
    _process_command_line,
    _process_start_token,
    _runtime_observation,
)


class TestProcessSecrecy:
    """Proxy process doesn't leak SafeYolo tokens via its cmdline.

    Why: Process command lines are readable by any local user via
    `ps aux` or `/proc/PID/cmdline`. If SafeYolo tokens appear in
    the native proxy invocation, a non-root user on the host (or a
    process that escaped the sandbox) can read them and gain full
    admin control. Tokens must be passed via file or env var instead.
    """

    def test_no_tokens_in_process_cmdline(self):
        """Admin and agent tokens do not appear in the selected proxy cmdline.

        What: Bind the native receipt to its live process and configuration,
        then inspect its command line; assert neither token is a substring.
        Why: A token in the cmdline is readable by any local user —
        full admin access leaks to anyone with shell on the host.
        """
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))

        config_path = config_dir / "config.toml"
        native = _native_config(config_path, config_dir)
        # Read the effective native admin token file, including an override.
        admin_token_file = Path(native["raw"]["admin_api_token_file"])
        admin_token = admin_token_file.read_text().strip()
        assert admin_token, "Selected native instance has no admin token"

        runtime = _runtime_observation(
            config_dir, native,
            config_dir / "bin/safeyolo-proxy", config_path=config_path,
            working_directory=config_dir, require_running=True, require_authenticated_identity=True,
        )
        cmdline = b" ".join(_process_command_line(runtime["pid"]))
        assert _process_start_token(runtime["pid"]) == runtime["receipt"]["start_token"], (
            "native process identity changed during command-line inspection"
        )
        if admin_token.encode() in cmdline:
            # Keep a discovered secret out of pytest's assertion-value output.
            raise AssertionError("Admin API token appears in the proxy command line")

        # Also check agent token
        agent_token_file = config_dir / "data" / "agent_token"
        agent_token = agent_token_file.read_text().strip()
        assert agent_token, "Selected native instance has no agent token"
        if agent_token.encode() in cmdline:
            raise AssertionError("Agent token appears in the proxy process cmdline!")
