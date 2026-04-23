"""Platform abstraction for agent sandbox lifecycle.

Each platform implements the same interface:
  - macOS: Virtualization.framework microVM; egress via vsock → host UDS
           → proxy_bridge (structural isolation, no kernel firewall)
  - Linux: gVisor (runsc) container in a loopback-only netns; egress via
           bind-mounted UDS → proxy_bridge; iptables rules block any
           stray outbound traffic from the netns

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

        Returns dict with at minimum: attribution_ip, host_ip, guest_ip,
        needs_bridge_socket. Platform-specific keys (netns, veth_host,
        etc.) are also included for the platform's own use.
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
    def agent_rootfs_path(self, name: str) -> Path:
        """Expected on-disk path for an agent's rootfs.

        Returns the path whether or not it exists — callers use this to
        check whether `prepare_rootfs` has run for this agent.
        Darwin: a file (ext4 disk image). Linux: a directory (overlayfs).
        """

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
        snapshot_capture_path: Path | None = None,
        restore_from_path: Path | None = None,
        ephemeral: bool = False,
    ) -> int:
        """Start an agent sandbox. Returns PID.

        snapshot_capture_path / restore_from_path are macOS-only (VZ
        save/restore). Linux ignores them until PR 5 adds gVisor
        checkpoint support.

        ephemeral=True: boot with a tmpfs overlay upper (writes to /
        are discarded on stop). macOS VZ honors this via kernel
        cmdline + omitting --overlay; Linux honors this once the
        disk-backed-overlay task lands (currently the Linux memory
        overlay is ephemeral-by-default so this flag is structurally
        a no-op there).
        """

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
        belonging to this instance (respects SAFEYOLO_SUBNET_BASE
        scoping on Linux).
        """

    @abstractmethod
    def remove_agent_dir(self, name: str) -> None:
        """Delete an agent's on-disk directory.

        Darwin: all artifacts are user-owned, so shutil.rmtree works.
        Linux: overlayfs leaves root-owned work/ subdirectories behind
        after unmount, and the container's writes to upper/ may also
        be root-owned — so rmtree-as-user fails with EPERM. The Linux
        implementation unmounts any stale overlay then sudo-removes
        the dir.
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
