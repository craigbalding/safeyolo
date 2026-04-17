"""macOS platform: Virtualization.framework microVM + feth + pf.

Wraps the existing vm.py and firewall.py code behind the AgentPlatform
interface. No new functionality — just delegation.
"""

import shutil
import subprocess
from pathlib import Path

from ..config import get_agents_dir, get_ssh_key_path
from ..firewall import (
    allocate_subnet,
    load_rules,
    setup_feth,
    teardown_feth,
    unload_rules,
)
from ..vm import (
    create_agent_rootfs,
    get_agent_config_share_dir,
    get_agent_rootfs_path,
    is_vm_running,
    start_vm,
    stop_vm,
)
from . import AgentPlatform


class DarwinPlatform(AgentPlatform):
    """macOS agent isolation via Virtualization.framework microVMs."""

    firewall_name = "pf"

    def setup_networking(self, agent_index: int) -> dict:
        import os as _os  # noqa: PLC0415
        # SAFEYOLO_MACOS_NETWORK selects the macOS data path:
        #   vsock  — vsock→UDS→bridge→TCP. Cross-platform parity with
        #            Linux; identity stamped by the host proxy_bridge.
        #   feth   — legacy veth + pf anchor path. Kept as a fallback
        #            while Phase 2 is in progress.
        # Default is the legacy path until Phase 2 deletes it.
        network_mode = _os.environ.get("SAFEYOLO_MACOS_NETWORK", "feth")

        if network_mode == "vsock":
            # Allocate only what the shared code path needs — no feth
            # interfaces, no subnet. attribution_ip is synthetic 127.0.0.X
            # exactly like Linux; the host-side bridge binds upstream TCP
            # to this address before reaching mitmproxy.
            attribution_ip = f"127.0.0.{agent_index + 2}"

            # macOS quirk: Linux auto-routes the whole 127.0.0.0/8
            # loopback range, but Darwin only owns 127.0.0.1 by default.
            # The bridge's bind() to 127.0.0.X fails with EADDRNOTAVAIL
            # unless we explicitly alias the address onto lo0 first.
            # Idempotent — re-aliasing is a no-op.
            subprocess.run(
                ["sudo", "-n", "ifconfig", "lo0", "alias",
                 f"{attribution_ip}/32"],
                capture_output=True, check=False,
            )

            return {
                "attribution_ip": attribution_ip,
                "needs_bridge_socket": True,
                "host_ip": "127.0.0.1",
                "guest_ip": "127.0.0.1",
                # Subnet / placeholders kept non-empty so the firewall
                # rules path (still active for feth callers) doesn't
                # KeyError until Phase 2b fully removes it.
                "subnet": f"{attribution_ip}/32",
            }

        alloc = setup_feth(agent_index)
        # Legacy macOS path: the per-agent feth IP is what mitmproxy
        # sees directly, so it doubles as the attribution IP.
        alloc["attribution_ip"] = alloc["guest_ip"]
        return alloc

    def teardown_networking(self, agent_index: int) -> None:
        import os as _os  # noqa: PLC0415
        if _os.environ.get("SAFEYOLO_MACOS_NETWORK") == "vsock":
            # Mirror of setup_networking — drop the lo0 alias we added.
            attribution_ip = f"127.0.0.{agent_index + 2}"
            subprocess.run(
                ["sudo", "-n", "ifconfig", "lo0", "-alias", attribution_ip],
                capture_output=True, check=False,
            )
            return
        teardown_feth(agent_index)

    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        import os as _os  # noqa: PLC0415
        if _os.environ.get("SAFEYOLO_MACOS_NETWORK") == "vsock":
            # vsock arch: isolation is structural (agent has no feth,
            # bridge stamps identity). No pf rules needed.
            return
        load_rules(proxy_port=proxy_port, admin_port=admin_port,
                   active_subnets=active_subnets)

    def unload_firewall_rules(self) -> None:
        import os as _os  # noqa: PLC0415
        if _os.environ.get("SAFEYOLO_MACOS_NETWORK") == "vsock":
            return
        unload_rules()

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
        # vsock mode: thread the per-agent bridge socket through to
        # safeyolo-vm so VSockProxyRelay can connect() to it on each
        # guest-initiated flow.
        proxy_socket = None
        if fw_alloc.get("needs_bridge_socket"):
            from ..proxy_bridge import socket_path_for as _sock_for  # noqa: PLC0415
            proxy_socket = str(_sock_for(name))

        proc = start_vm(
            name=name,
            workspace_path=workspace_path,
            cpus=cpus,
            memory_mb=memory_mb,
            extra_shares=extra_shares,
            feth_vm=fw_alloc.get("feth_vm", ""),
            background=background,
            snapshot_capture_path=snapshot_capture_path,
            restore_from_path=restore_from_path,
            proxy_socket_path=proxy_socket,
        )
        return proc.pid

    def stop_sandbox(self, name: str) -> None:
        stop_vm(name)

    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        """Execute via SSH (macOS VMs have their own network stack)."""
        ip_file = get_agent_config_share_dir(name) / "vm-ip"
        if not ip_file.exists():
            raise RuntimeError(f"Cannot find VM IP for '{name}'")
        ip = ip_file.read_text().strip()

        key_path = get_ssh_key_path()
        ssh_user = "root" if user == "root" else "agent"

        cmd = [
            "ssh",
            "-i", str(key_path),
            "-p", "22",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        ]
        if interactive and not command:
            cmd.append("-t")
        cmd.append(f"{ssh_user}@{ip}")
        if command:
            cmd.append(command)

        result = subprocess.run(cmd)
        return result.returncode

    def is_sandbox_running(self, name: str) -> bool:
        return is_vm_running(name)

    def cleanup_all(self, agents_dir: Path) -> None:
        """Clean up feth interfaces and bridges for this instance."""
        if not agents_dir.exists():
            return

        for idx, agent_dir in enumerate(sorted(agents_dir.iterdir())):
            if agent_dir.is_dir():
                alloc = allocate_subnet(idx)
                for feth in (alloc["feth_vm"], alloc["feth_host"]):
                    try:
                        subprocess.run(["pkill", "-f", f"feth-bridge.*{feth}"],
                                       capture_output=True)
                    except Exception:
                        # pkill missing or no matches — nothing more to do.
                        pass
                    try:
                        subprocess.run(["sudo", "ifconfig", feth, "destroy"],
                                       capture_output=True)
                    except Exception:
                        # Interface may already be gone or sudo unavailable.
                        pass

    def remove_agent_dir(self, name: str) -> None:
        """Delete the agent's on-disk directory (Darwin: all user-owned)."""
        agent_dir = get_agents_dir() / name
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
