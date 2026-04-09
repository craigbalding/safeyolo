"""Linux platform: gVisor (runsc) container + veth + iptables.

Auto-detects KVM availability for best isolation:
  - /dev/kvm accessible → runsc --platform=kvm (hardware isolation)
  - otherwise → runsc --platform=systrap (seccomp-bpf interception)

No Docker, containerd, or other daemon required. Only needs:
  - runsc binary (single Go binary)
  - iptables (standard)
  - iproute2 (standard)
"""

from pathlib import Path

from . import AgentPlatform


class LinuxPlatform(AgentPlatform):
    """Linux agent isolation via gVisor (runsc)."""

    def setup_networking(self, agent_index: int) -> dict:
        raise NotImplementedError("Linux networking not yet implemented")

    def teardown_networking(self, agent_index: int) -> None:
        raise NotImplementedError("Linux networking not yet implemented")

    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        raise NotImplementedError("Linux firewall not yet implemented")

    def unload_firewall_rules(self) -> None:
        raise NotImplementedError("Linux firewall not yet implemented")

    def prepare_rootfs(self, name: str) -> Path:
        raise NotImplementedError("Linux rootfs not yet implemented")

    def start_sandbox(self, name, workspace_path, config_share, fw_alloc,
                      cpus, memory_mb, extra_shares, background) -> int:
        raise NotImplementedError("Linux sandbox not yet implemented")

    def stop_sandbox(self, name: str) -> None:
        raise NotImplementedError("Linux sandbox not yet implemented")

    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        raise NotImplementedError("Linux exec not yet implemented")

    def is_sandbox_running(self, name: str) -> bool:
        raise NotImplementedError("Linux sandbox not yet implemented")

    def cleanup_all(self, agents_dir: Path) -> None:
        raise NotImplementedError("Linux cleanup not yet implemented")
