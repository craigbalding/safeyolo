"""Linux blackbox test harness.

Uses gVisor (runsc) + veth + iptables for agent isolation.
The test harness delegates to the platform layer — the same code
that `safeyolo agent run` uses.
"""

import logging
import subprocess
from pathlib import Path

from .base import BlackboxHarness

log = logging.getLogger("blackbox.harness.linux")

REPO_ROOT = Path(__file__).resolve().parents[3]
BLACKBOX_DIR = REPO_ROOT / "tests" / "blackbox"
SINKHOLE_DIR = BLACKBOX_DIR / "sinkhole"
CERTS_DIR = BLACKBOX_DIR / "certs"

SINKHOLE_HTTP_PORT = 18080
SINKHOLE_HTTPS_PORT = 18443
SINKHOLE_CONTROL_PORT = 19999


class LinuxHarness(BlackboxHarness):
    """Linux-specific blackbox test harness using gVisor."""

    def __init__(self):
        self._sinkhole_proc = None

    def start_sinkhole(self) -> None:
        """Start sinkhole server as a background process."""
        key_path = Path.home() / ".safeyolo" / "test-certs" / "sinkhole.key"
        self._sinkhole_proc = subprocess.Popen(
            [
                "python3", str(SINKHOLE_DIR / "server.py"),
                "--http-port", str(SINKHOLE_HTTP_PORT),
                "--https-port", str(SINKHOLE_HTTPS_PORT),
                "--control-port", str(SINKHOLE_CONTROL_PORT),
                "--cert", str(CERTS_DIR / "sinkhole.crt"),
                "--key", str(key_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        log.info("Sinkhole started (pid=%d)", self._sinkhole_proc.pid)

    def start_proxy(self) -> None:
        """Start SafeYolo proxy in test mode."""
        subprocess.run(
            ["safeyolo", "start", "--test", "--no-wait"],
            check=True,
        )
        log.info("Proxy started in test mode")

    def start_vm(self) -> None:
        """Start a test agent sandbox."""
        # Create agent if not exists
        subprocess.run(
            ["safeyolo", "agent", "add", "bbtest", "byoa", str(REPO_ROOT), "--no-run"],
            capture_output=True,
        )
        # Boot in detach mode
        subprocess.run(
            ["safeyolo", "agent", "run", "bbtest", "--detach"],
            check=True,
        )
        log.info("Test agent sandbox started")

    def run_tests(self, suite: str = "all") -> int:
        """Run blackbox test suites."""
        results = []

        if suite in ("all", "proxy"):
            result = subprocess.run(
                ["pytest", "-v", "--tb=short", "--timeout=60",
                 str(BLACKBOX_DIR / "host" / "test_credential_guard.py"),
                 str(BLACKBOX_DIR / "host" / "test_network_guard.py")],
            )
            results.append(result.returncode)

        if suite in ("all", "isolation"):
            result = subprocess.run(
                ["safeyolo", "agent", "shell", "bbtest", "-c",
                 "cd /workspace/tests/blackbox/isolation && "
                 "SAFEYOLO_BLACKBOX_ISOLATION=1 pytest -v --tb=short --timeout=60"],
            )
            results.append(result.returncode)

        return max(results) if results else 0

    def teardown(self) -> None:
        """Stop all test infrastructure."""
        subprocess.run(["safeyolo", "agent", "stop", "bbtest"], capture_output=True)
        subprocess.run(["safeyolo", "stop"], capture_output=True)
        if self._sinkhole_proc:
            self._sinkhole_proc.terminate()
            self._sinkhole_proc.wait(timeout=5)
        log.info("Test infrastructure torn down")
