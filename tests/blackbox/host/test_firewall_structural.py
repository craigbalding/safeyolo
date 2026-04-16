"""Host-side firewall structural tests.

These run on the HOST (not inside the VM) and inspect the actual
iptables/pf rule shape, not just the observable effect from inside
the sandbox. The effect tests live in isolation/test_vm_isolation.py;
these verify the mechanism itself.

Why both? The in-VM tests prove "can't reach host:9090" which passes
even if the firewall is misconfigured but the service isn't listening.
The structural tests prove "the chain is shaped so that NOTHING except
the proxy port can be reached" — a stronger invariant that catches
misconfigurations even when no service is listening to exploit them.
"""

import os
import subprocess
import sys
import time

import pytest


def _get_agent_name():
    return os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")


def _get_proxy_port():
    proxy_url = os.environ.get("PROXY_URL", "http://127.0.0.1:8080")
    # Extract port from URL
    return int(proxy_url.rsplit(":", 1)[-1].rstrip("/"))


def _get_admin_port():
    admin_url = os.environ.get("ADMIN_URL", "http://127.0.0.1:9090")
    return int(admin_url.rsplit(":", 1)[-1].rstrip("/"))


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


@pytest.mark.skipif(sys.platform != "linux", reason="iptables is Linux-only")
class TestIptablesChainStructure:
    """Verify the SAFEYOLO iptables chain is shaped for default-deny."""

    def _get_chain_rules(self) -> str:
        """Dump the SAFEYOLO chain rules."""
        chain = os.environ.get("SAFEYOLO_FW_CHAIN", "SAFEYOLO")
        result = subprocess.run(
            ["sudo", "iptables", "-nvL", chain, "--line-numbers"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            pytest.skip(f"SAFEYOLO chain not found: {result.stderr}")
        return result.stdout

    def test_chain_ends_with_drop_all(self):
        """The SAFEYOLO chain must end with a DROP rule that catches all
        traffic not matched by earlier ACCEPT rules. Without this,
        traffic to un-mentioned ports passes through to the default
        FORWARD/INPUT policy — which might be ACCEPT on permissive
        hosts.
        """
        rules = self._get_chain_rules()
        lines = [ln.strip() for ln in rules.strip().split("\n") if ln.strip()]
        # Find numbered rule lines (start with a digit)
        rule_lines = [ln for ln in lines if ln and ln[0].isdigit()]
        assert rule_lines, "SAFEYOLO chain has no rules"
        last_rule = rule_lines[-1]
        assert "DROP" in last_rule and "0.0.0.0/0" in last_rule, (
            f"Last rule in SAFEYOLO chain is not a catch-all DROP:\n"
            f"  {last_rule}\n"
            f"Full chain:\n{rules}"
        )

    def test_chain_has_proxy_accept(self):
        """The chain must have an ACCEPT rule for the proxy port."""
        rules = self._get_chain_rules()
        proxy_port = _get_proxy_port()
        assert f"dpt:{proxy_port}" in rules and "ACCEPT" in rules, (
            f"No ACCEPT rule for proxy port {proxy_port} in SAFEYOLO chain:\n{rules}"
        )

    def test_chain_has_admin_drop(self):
        """The chain must have an explicit DROP for the admin port
        (belt-and-braces — the final DROP catches it too, but an
        explicit DROP documents the intent and survives if someone
        reorders rules).
        """
        rules = self._get_chain_rules()
        admin_port = _get_admin_port()
        # Look for a DROP rule mentioning the admin port
        for line in rules.split("\n"):
            if "DROP" in line and f"dpt:{admin_port}" in line:
                return
        pytest.fail(
            f"No explicit DROP rule for admin port {admin_port} in "
            f"SAFEYOLO chain:\n{rules}"
        )

    def test_input_chain_has_proxy_accept(self):
        """INPUT chain must ACCEPT sandbox→host:proxy_port. On hosts
        with default-deny INPUT (e.g. Ubuntu + UFW), the SAFEYOLO
        FORWARD rules aren't enough — sandbox→host traffic hits INPUT,
        not FORWARD. This was the root cause of the first Linux boot
        failure (PR #158).
        """
        result = subprocess.run(
            ["sudo", "iptables", "-nvL", "INPUT", "--line-numbers"],
            capture_output=True, text=True, timeout=10,
        )
        proxy_port = _get_proxy_port()
        assert f"dpt:{proxy_port}" in result.stdout and "ACCEPT" in result.stdout, (
            f"No INPUT ACCEPT rule for proxy port {proxy_port}. "
            f"Sandbox→host:proxy traffic will be dropped by default-deny INPUT policy.\n"
            f"INPUT chain:\n{result.stdout}"
        )


@pytest.mark.skipif(sys.platform != "linux", reason="iptables is Linux-only")
class TestFirewallCrashResilience:
    """Verify iptables rules survive the proxy process dying.

    If the proxy crashes or is killed, the agent sandbox must remain
    isolated. iptables rules are kernel state and should persist — but
    a well-meaning signal handler or cleanup hook might flush them.
    This test proves they stay.
    """

    def test_rules_survive_proxy_kill(self):
        """Kill the proxy, verify the SAFEYOLO chain still exists with
        its rules intact, then restart the proxy.
        """
        from pathlib import Path
        config_dir = Path(os.environ.get(
            "SAFEYOLO_CONFIG_DIR", str(Path.home() / ".safeyolo"),
        ))
        pid_file = config_dir / "data" / "proxy.pid"

        if not pid_file.exists():
            pytest.skip("Proxy PID file not found")

        pid = int(pid_file.read_text().strip())
        chain = os.environ.get("SAFEYOLO_FW_CHAIN", "SAFEYOLO")

        # Snapshot rules before kill
        before = subprocess.run(
            ["sudo", "iptables", "-nvL", chain],
            capture_output=True, text=True, timeout=5,
        )
        if before.returncode != 0:
            pytest.skip("SAFEYOLO chain not present before test")
        before_rules = before.stdout

        try:
            # Kill the proxy hard (SIGKILL, no cleanup hooks)
            subprocess.run(["sudo", "kill", "-9", str(pid)],
                           capture_output=True, timeout=5)
            time.sleep(1)

            # Verify chain survived
            after = subprocess.run(
                ["sudo", "iptables", "-nvL", chain],
                capture_output=True, text=True, timeout=5,
            )
            assert after.returncode == 0, (
                "SAFEYOLO chain disappeared after proxy kill"
            )
            # Rule count should be identical
            before_count = before_rules.count("\n")
            after_count = after.stdout.count("\n")
            assert after_count == before_count, (
                f"SAFEYOLO chain rule count changed after proxy kill: "
                f"before={before_count} after={after_count}\n"
                f"Before:\n{before_rules}\nAfter:\n{after.stdout}"
            )
        finally:
            # Restart proxy so subsequent tests aren't broken.
            # Use safeyolo start which is idempotent.
            subprocess.run(
                ["safeyolo", "start", "--test", "--no-wait"],
                capture_output=True, timeout=30,
                env={**os.environ, "SAFEYOLO_CONFIG_DIR": str(config_dir)},
            )
            # Wait for proxy to be healthy
            for _ in range(15):
                try:
                    import httpx
                    admin_url = os.environ.get("ADMIN_URL", "http://127.0.0.1:9090")
                    admin_token_path = config_dir / "data" / "admin_token"
                    token = admin_token_path.read_text().strip() if admin_token_path.exists() else ""
                    r = httpx.get(
                        f"{admin_url}/health",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=2,
                    )
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(1)
