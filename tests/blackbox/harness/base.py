"""Abstract harness interface for blackbox tests.

The harness manages the platform-specific lifecycle: starting the
sinkhole, proxy, VM, running tests, and tearing everything down.
Test files are platform-independent; only the harness differs.
"""

from abc import ABC, abstractmethod


class BlackboxHarness(ABC):
    """Base class for platform-specific blackbox test harnesses."""

    @abstractmethod
    def start_sinkhole(self) -> None:
        """Start the sinkhole server as a host background process."""

    @abstractmethod
    def start_proxy(self) -> None:
        """Start mitmdump with the full addon chain + sinkhole router."""

    @abstractmethod
    def start_vm(self) -> None:
        """Boot a microVM with test configuration."""

    @abstractmethod
    def run_tests(self, suite: str = "all") -> int:
        """Run pytest inside the VM. Returns exit code."""

    @abstractmethod
    def teardown(self) -> None:
        """Stop VM, proxy, sinkhole. Tear down network isolation."""

    def run(self, suite: str = "all") -> int:
        """Full test lifecycle: start, run, teardown."""
        try:
            self.start_sinkhole()
            self.start_proxy()
            self.start_vm()
            return self.run_tests(suite)
        finally:
            self.teardown()
