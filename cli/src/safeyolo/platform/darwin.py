"""macOS platform: Virtualization.framework microVM + vsock UDS bridge.

Guest has no external network interface. Egress goes guest → vsock:1080 →
safeyolo-vm's VSockProxyRelay → per-agent host UDS → proxy_bridge → mitmproxy.
Shell access (`safeyolo agent shell`) goes via a second per-agent UDS →
VSockShellBridge → vsock:2220 → guest-shell-bridge → sshd. No host firewall
rules — the sandbox has no other path out.
"""

import shutil
import subprocess
from pathlib import Path

from ..config import get_agents_dir, get_data_dir, get_ssh_key_path
from ..vm import (
    create_agent_rootfs,
    get_agent_rootfs_path,
    is_vm_running,
    start_vm,
    stop_vm,
)
from . import AgentPlatform


def _shell_socket_path(name: str) -> Path:
    """Per-agent UDS the host-side shell bridge listens on. Symmetric
    with proxy_bridge's socket_path_for(), different subdir so the
    bridge daemon doesn't accidentally pick it up as a proxy listener."""
    return get_data_dir() / "shell-sockets" / f"{name}.sock"


class DarwinPlatform(AgentPlatform):
    """macOS agent isolation via Virtualization.framework microVMs."""

    def setup_networking(self, agent_index: int) -> dict:
        # attribution_ip is a per-agent identity carried to mitmproxy
        # via port-based identity. The bridge binds to a deterministic
        # port; the port-identity addon rewrites peername with this IP.
        # The IP is pure bookkeeping — it never touches a kernel
        # interface.
        offset = agent_index + 2  # 0 → 2, reserving 127.0.0.1
        attribution_ip = f"127.0.{offset // 256}.{offset % 256}"

        return {
            "attribution_ip": attribution_ip,
            "needs_bridge_socket": True,
            "host_ip": "127.0.0.1",
            "guest_ip": "127.0.0.1",
        }

    def teardown_networking(self, agent_index: int) -> None:
        # No lo0 aliases to clean up — identity is conveyed via
        # PROXY protocol, not kernel interface configuration.
        pass

    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        # Structural isolation: agent has no external interface, host
        # bridge stamps identity. No pf rules needed.
        return

    def unload_firewall_rules(self) -> None:
        return

    def agent_rootfs_path(self, name: str) -> Path:
        return get_agent_rootfs_path(name)

    def prepare_rootfs(self, name: str) -> Path:
        return create_agent_rootfs(name)

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
    ) -> int:
        # Thread the per-agent bridge socket through to safeyolo-vm so
        # VSockProxyRelay can connect() to it on each guest-initiated
        # flow. Also allocate a shell-bridge UDS so `safeyolo agent shell`
        # can reach the VM's sshd over vsock.
        from ..proxy_bridge import socket_path_for as _sock_for  # noqa: PLC0415
        proxy_socket = str(_sock_for(name))
        shell_path = _shell_socket_path(name)
        shell_path.parent.mkdir(parents=True, exist_ok=True)
        shell_path.parent.chmod(0o700)
        # Clear any stale socket from a previous run — safeyolo-vm's
        # own bind() would fail otherwise.
        shell_path.unlink(missing_ok=True)
        shell_socket = str(shell_path)

        proc = start_vm(
            name=name,
            workspace_path=workspace_path,
            cpus=cpus,
            memory_mb=memory_mb,
            extra_shares=extra_shares,
            background=background,
            snapshot_capture_path=snapshot_capture_path,
            restore_from_path=restore_from_path,
            proxy_socket_path=proxy_socket,
            shell_socket_path=shell_socket,
        )
        return proc.pid

    def stop_sandbox(self, name: str) -> None:
        stop_vm(name)

    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        """Execute via SSH. The VM has no TCP interface, so we
        ProxyCommand through the per-agent shell-bridge UDS —
        safeyolo-vm accepts on that UDS and forwards to vsock:2220
        where guest-shell-bridge pumps into guest sshd.
        """
        key_path = get_ssh_key_path()
        ssh_user = "root" if user == "root" else "agent"
        shell_sock = _shell_socket_path(name)
        if not shell_sock.exists():
            raise RuntimeError(
                f"Shell bridge socket {shell_sock} not found — "
                f"is the VM running?"
            )

        cmd = [
            "ssh",
            "-i", str(key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", f"ProxyCommand=nc -U {shell_sock}",
        ]
        target = f"{ssh_user}@sandbox"  # hostname is cosmetic

        if interactive and not command:
            cmd.append("-t")
        cmd.append(target)
        if command:
            cmd.append(command)

        result = subprocess.run(cmd)
        return result.returncode

    def is_sandbox_running(self, name: str) -> bool:
        return is_vm_running(name)

    def cleanup_all(self, agents_dir: Path) -> None:
        """Clean up agent resources for this instance.

        No lo0 aliases to remove — identity is conveyed via PROXY protocol.
        vsock state and bridge sockets are process-scoped and get cleaned
        up with the respective daemons.
        """
        pass

    def remove_agent_dir(self, name: str) -> None:
        """Delete the agent's on-disk directory (Darwin: all user-owned)."""
        agent_dir = get_agents_dir() / name
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
