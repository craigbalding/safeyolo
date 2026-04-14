"""macOS platform: Virtualization.framework microVM + feth + pf.

Wraps the existing vm.py and firewall.py code behind the AgentPlatform
interface. No new functionality — just delegation.
"""

import subprocess
from pathlib import Path

from ..config import get_ssh_key_path
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
    is_vm_running,
    start_vm,
    stop_vm,
)
from . import AgentPlatform


class DarwinPlatform(AgentPlatform):
    """macOS agent isolation via Virtualization.framework microVMs."""

    def setup_networking(self, agent_index: int) -> dict:
        return setup_feth(agent_index)

    def teardown_networking(self, agent_index: int) -> None:
        teardown_feth(agent_index)

    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        load_rules(proxy_port=proxy_port, admin_port=admin_port,
                   active_subnets=active_subnets)

    def unload_firewall_rules(self) -> None:
        unload_rules()

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
