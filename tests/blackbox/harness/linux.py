"""Linux blackbox test harness (stub).

Will use KVM + tap/veth + iptables/nftables for network isolation.
"""

from .base import BlackboxHarness


class LinuxHarness(BlackboxHarness):
    """Linux-specific blackbox test harness — not yet implemented."""

    def start_sinkhole(self) -> None:
        raise NotImplementedError("Linux harness not yet implemented")

    def start_proxy(self) -> None:
        raise NotImplementedError("Linux harness not yet implemented")

    def start_vm(self) -> None:
        raise NotImplementedError("Linux harness not yet implemented")

    def run_tests(self, suite: str = "all") -> int:
        raise NotImplementedError("Linux harness not yet implemented")

    def teardown(self) -> None:
        raise NotImplementedError("Linux harness not yet implemented")
