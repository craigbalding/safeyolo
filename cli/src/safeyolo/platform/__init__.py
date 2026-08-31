"""Platform abstraction for agent sandbox lifecycle.

Each platform implements the same interface:
  - macOS: Virtualization.framework microVM; egress via vsock → host UDS
           → mitmproxy's per-agent UnixInstance (structural isolation,
           no kernel firewall)
  - Linux: gVisor (runsc) container in a loopback-only netns; egress via
           bind-mounted UDS → mitmproxy's per-agent UnixInstance;
           `--host-uds=open` + no external netif block any stray
           outbound traffic

The platform is auto-detected at runtime. All platform-specific code
lives behind this interface — agent.py, lifecycle.py, and the rest of
the CLI never import platform-specific modules directly.
"""

import platform as _platform
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, Protocol


class BinaryRelay(Protocol):
    """Bidirectional byte stream with the lifecycle used by preview."""

    stdin: BinaryIO | None
    stdout: BinaryIO | None
    returncode: int | None

    def poll(self) -> int | None:
        raise NotImplementedError

    def wait(self, timeout: float | None = None) -> int:
        raise NotImplementedError

    def terminate(self) -> None:
        raise NotImplementedError

    def kill(self) -> None:
        raise NotImplementedError


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
        """Apply any platform egress controls.

        Current platforms use structural isolation and implement this as a
        no-op. The method remains part of the lifecycle interface.
        """

    @abstractmethod
    def unload_firewall_rules(self) -> None:
        """Remove platform egress controls, if the platform created any."""

    @abstractmethod
    def agent_rootfs_path(self, name: str) -> Path:
        """Expected on-disk path for an agent's rootfs.

        Returns the path whether or not it exists — callers use this to
        check whether `prepare_rootfs` has run for this agent.
        Darwin returns a per-agent ext4 image. Linux returns the shared
        unpacked tree or a custom per-agent tree.
        """

    @abstractmethod
    def prepare_rootfs(self, name: str) -> Path:
        """Select or create the platform rootfs and return its path."""

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

        extra_shares entries are (host_path, guest_destination, read_only).
        Guest destinations are absolute paths validated by the CLI.

        snapshot_capture_path / restore_from_path are macOS-only (VZ
        save/restore). Linux ignores them until PR 5 adds gVisor
        checkpoint support.

        ephemeral=True selects a temporary overlay upper. Writes to / are
        discarded on stop. macOS VZ selects tmpfs through the kernel command
        line and omits --overlay. Linux selects gVisor's
        --overlay2=root:memory mode.

        ephemeral=False is the default. Both platforms select a per-agent
        disk-backed or file-backed overlay, and writes to / persist across
        stop and run.
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
    def popen_in_sandbox(
        self,
        name: str,
        command: str,
        user: str = "agent",
    ) -> subprocess.Popen[str]:
        """Start a non-interactive command in a running sandbox with pipes."""

    @abstractmethod
    def popen_binary_in_sandbox(
        self,
        name: str,
        command: str,
        user: str = "agent",
    ) -> subprocess.Popen[bytes]:
        """Start a non-interactive command in a running sandbox with binary pipes."""

    def popen_port_forward(
        self,
        name: str,
        guest_port: int,
        user: str = "agent",
    ) -> BinaryRelay:
        """Open one host byte stream to a listening guest TCP port.

        Platforms may override this with a native transport. The default is
        the existing guest-side socat relay, used by the macOS VM path.
        """
        command = f"exec socat - TCP:127.0.0.1:{guest_port}"
        return self.popen_binary_in_sandbox(name, command, user=user)

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
        be subordinate-uid-owned — so rmtree-as-user can fail with EPERM.
        The Linux implementation retries cleanup as mapped root in a
        short-lived rootless user namespace.
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
