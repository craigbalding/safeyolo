"""macOS blackbox test harness.

Manages: sinkhole (host process), mitmdump (host process),
microVM (Virtualization.framework via safeyolo-vm), and
feth + pf network isolation.
"""

import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .base import BlackboxHarness

log = logging.getLogger("blackbox.harness.macos")

# Paths relative to the repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
BLACKBOX_DIR = REPO_ROOT / "tests" / "blackbox"
SINKHOLE_DIR = BLACKBOX_DIR / "sinkhole"
RUNNER_DIR = BLACKBOX_DIR / "runner"
CERTS_DIR = BLACKBOX_DIR / "certs"
HARNESS_DIR = BLACKBOX_DIR / "harness"

# Ports (non-privileged, avoid conflicts)
SINKHOLE_HTTP_PORT = 18080
SINKHOLE_HTTPS_PORT = 18443
SINKHOLE_CONTROL_PORT = 19999
PROXY_PORT = 8080
ADMIN_PORT = 9090


class MacOSHarness(BlackboxHarness):
    """macOS-specific blackbox test harness."""

    def __init__(self):
        self._sinkhole_proc: subprocess.Popen | None = None
        self._proxy_proc_started = False

    def start_sinkhole(self) -> None:
        """Start sinkhole as a host background process."""
        log.info("Starting sinkhole server...")
        self._sinkhole_proc = subprocess.Popen(
            [
                sys.executable,
                str(SINKHOLE_DIR / "server.py"),
                "--http-port", str(SINKHOLE_HTTP_PORT),
                "--https-port", str(SINKHOLE_HTTPS_PORT),
                "--control-port", str(SINKHOLE_CONTROL_PORT),
                "--cert", str(CERTS_DIR / "sinkhole.crt"),
                "--key", str(Path.home() / ".safeyolo" / "test-certs" / "sinkhole.key"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for sinkhole to be ready
        import urllib.request
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{SINKHOLE_CONTROL_PORT}/health",
                    timeout=1,
                ):
                    break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("Sinkhole failed to start")

        log.info("Sinkhole ready on ports %d/%d/%d",
                 SINKHOLE_HTTP_PORT, SINKHOLE_HTTPS_PORT, SINKHOLE_CONTROL_PORT)

    def start_proxy(self) -> None:
        """Start mitmdump with sinkhole router addon."""
        log.info("Starting proxy with sinkhole routing...")

        env = os.environ.copy()
        env["SAFEYOLO_CA_CERT"] = str(CERTS_DIR / "ca.crt")
        env["SAFEYOLO_BLOCK"] = "true"
        env["SAFEYOLO_SINKHOLE_ROUTER"] = str(HARNESS_DIR / "sinkhole_router.py")
        env["SAFEYOLO_SINKHOLE_HOST"] = "127.0.0.1"
        env["SAFEYOLO_SINKHOLE_HTTP_PORT"] = str(SINKHOLE_HTTP_PORT)
        env["SAFEYOLO_SINKHOLE_HTTPS_PORT"] = str(SINKHOLE_HTTPS_PORT)

        # Use the CLI's proxy module to start
        subprocess.run(
            [sys.executable, "-m", "safeyolo.proxy", "start",
             "--port", str(PROXY_PORT), "--admin-port", str(ADMIN_PORT)],
            env=env,
            check=True,
            timeout=30,
        )
        self._proxy_proc_started = True
        log.info("Proxy started on port %d", PROXY_PORT)

    def start_vm(self) -> None:
        """Boot a BYOA microVM for testing.

        The VM is configured with:
        - Test runner files on a VirtioFS share
        - Firewall rules allowing proxy + sinkhole control ports
        - Test environment variables
        """
        log.info("Starting test VM...")
        # Implementation depends on CLI integration — delegates to
        # safeyolo agent add/start with BYOA template and test overrides.
        # This is a skeleton; the full VM boot sequence uses the CLI.
        raise NotImplementedError(
            "VM boot integration pending — requires safeyolo CLI "
            "to support test-mode agent with extra VirtioFS shares"
        )

    def run_tests(self, suite: str = "all") -> int:
        """SSH into the VM and run pytest."""
        log.info("Running tests (suite=%s)...", suite)
        # Implementation: SSH into VM, run pytest from /tests mount
        raise NotImplementedError("Test execution pending VM boot integration")

    def teardown(self) -> None:
        """Stop all processes and clean up."""
        log.info("Tearing down...")

        if self._sinkhole_proc:
            self._sinkhole_proc.send_signal(signal.SIGTERM)
            try:
                self._sinkhole_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._sinkhole_proc.kill()
            self._sinkhole_proc = None

        if self._proxy_proc_started:
            try:
                subprocess.run(
                    [sys.executable, "-m", "safeyolo.proxy", "stop"],
                    timeout=10,
                )
            except Exception:
                pass
            self._proxy_proc_started = False

        log.info("Teardown complete")
