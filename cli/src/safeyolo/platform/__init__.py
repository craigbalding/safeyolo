"""Platform abstraction for agent sandbox lifecycle.

Each platform implements the same interface:
  - macOS: Virtualization.framework microVM + feth + pf
  - Linux: gVisor (runsc) container + veth + iptables

The platform is auto-detected at runtime. All platform-specific code
lives behind this interface — agent.py, lifecycle.py, and the rest of
the CLI never import platform-specific modules directly.
"""

import platform as _platform
from abc import ABC, abstractmethod
from pathlib import Path


class AgentPlatform(ABC):
    """Platform-specific agent sandbox operations."""

    @abstractmethod
    def setup_networking(self, agent_index: int) -> dict:
        """Create network isolation for an agent.

        Returns dict with at minimum: host_ip, guest_ip, subnet.
        Platform-specific keys (feth_vm, netns, veth_host, etc.) are
        also included for the platform's own use.
        """

    @abstractmethod
    def teardown_networking(self, agent_index: int) -> None:
        """Remove network isolation for an agent."""

    @abstractmethod
    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        """Load firewall rules allowing only proxy egress."""

    @abstractmethod
    def unload_firewall_rules(self) -> None:
        """Remove all firewall rules for this instance."""

    @abstractmethod
    def prepare_rootfs(self, name: str) -> Path:
        """Create agent rootfs from base image. Returns rootfs path."""

    @abstractmethod
    def start_sandbox(
        self,
        name: str,
        workspace_path: str,
        config_share: Path,
        fw_alloc: dict,
        cpus: int,
        memory_mb: int,
        extra_shares: list[tuple[str, str, bool]] | None,
        background: bool,
    ) -> int:
        """Start an agent sandbox. Returns PID."""

    @abstractmethod
    def stop_sandbox(self, name: str) -> None:
        """Stop an agent sandbox and clean up."""

    @abstractmethod
    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        """Execute a command in a running sandbox. Returns exit code."""

    @abstractmethod
    def is_sandbox_running(self, name: str) -> bool:
        """Check if an agent sandbox is running."""

    @abstractmethod
    def cleanup_all(self, agents_dir: Path) -> None:
        """Clean up all networking/interfaces for this instance.

        Called by `safeyolo stop --all`. Only cleans up resources
        belonging to this instance (respects SUBNET_BASE scoping).
        """


def get_platform() -> AgentPlatform:
    """Auto-detect and return the platform implementation."""
    system = _platform.system()
    if system == "Darwin":
        from .darwin import DarwinPlatform
        return DarwinPlatform()
    elif system == "Linux":
        from .linux import LinuxPlatform
        return LinuxPlatform()
    else:
        raise RuntimeError(
            f"Unsupported platform: {system}. "
            f"SafeYolo requires macOS (Virtualization.framework) or Linux (gVisor)."
        )
