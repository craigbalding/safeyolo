"""Linux platform: gVisor (runsc) container + veth + iptables.

Auto-detects KVM availability for best isolation:
  - /dev/kvm accessible → runsc --platform=kvm (hardware isolation)
  - otherwise → runsc --platform=systrap (seccomp-bpf interception)

No Docker, containerd, or other daemon required. Only needs:
  - runsc binary (single Go binary, ~30MB)
  - iptables (standard)
  - iproute2 (standard)
  - root/sudo for networking and container lifecycle
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from ..config import get_agents_dir, get_share_dir
from ..firewall import SUBNET_BASE, allocate_subnet
from . import AgentPlatform

log = logging.getLogger("safeyolo.platform.linux")

# iptables chain name, scoped for multi-instance isolation
CHAIN_NAME = os.environ.get("SAFEYOLO_FW_CHAIN", "SAFEYOLO")

# runsc state directory
RUNSC_ROOT = "/run/safeyolo"


def _sudo(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command with sudo."""
    return subprocess.run(
        ["sudo"] + cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def _run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command without sudo."""
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def _detect_outbound_interface() -> str:
    """Detect the primary outbound network interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5,
        )
        # Output: "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2"
        for token in result.stdout.split():
            if token == "dev":
                idx = result.stdout.split().index("dev")
                return result.stdout.split()[idx + 1]
    except (subprocess.SubprocessError, OSError, IndexError):
        # `ip route` unavailable or output shape unexpected — fall back
        # to the conventional eth0.
        pass
    return "eth0"


def _detect_runsc_platform() -> str:
    """Detect best runsc platform: kvm if available, otherwise systrap."""
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm"
    return "systrap"


def _find_runsc() -> str:
    """Find the runsc binary."""
    path = shutil.which("runsc")
    if path:
        return path
    # Common install locations
    for p in ["/usr/local/bin/runsc", "/usr/bin/runsc"]:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    raise RuntimeError(
        "runsc not found. Install gVisor:\n"
        "  curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg\n"
        '  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] '
        'https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list\n'
        "  sudo apt update && sudo apt install -y runsc"
    )


def _detect_cgroup_version() -> int:
    """Detect cgroup version (1 or 2)."""
    try:
        with open("/proc/mounts") as f:
            for line in f:
                if "cgroup2" in line and "/sys/fs/cgroup" in line:
                    return 2
        return 1
    except FileNotFoundError:
        return 2  # assume modern


def _container_id(name: str) -> str:
    """Derive runsc container ID from agent name."""
    return f"safeyolo-{name}"


def _netns_name(name: str) -> str:
    """Derive network namespace name from agent name."""
    return f"safeyolo-{name}"


def _veth_host_name(agent_index: int) -> str:
    """Derive host-side veth interface name from agent index."""
    return f"veth-sy{SUBNET_BASE - 65 + agent_index}"


# ---------------------------------------------------------------------------
# AgentPlatform implementation
# ---------------------------------------------------------------------------

class LinuxPlatform(AgentPlatform):
    """Linux agent isolation via gVisor (runsc)."""

    # --- Networking ---

    def setup_networking(self, agent_index: int) -> dict:
        """Create veth pair + network namespace for an agent."""
        alloc = allocate_subnet(agent_index)
        netns = _netns_name(f"idx{agent_index}")
        veth_host = _veth_host_name(agent_index)
        veth_guest = "eth0"

        # Create network namespace
        _sudo(["ip", "netns", "add", netns], check=False)  # may already exist

        # Create veth pair
        _sudo(["ip", "link", "del", veth_host], check=False)  # clean up stale
        _sudo(["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_guest])

        # Move guest end into namespace
        _sudo(["ip", "link", "set", veth_guest, "netns", netns])

        # Configure host side
        _sudo(["ip", "addr", "add", f"{alloc['host_ip']}/24", "dev", veth_host])
        _sudo(["ip", "link", "set", veth_host, "up"])

        # Configure guest side (inside netns)
        _sudo(["ip", "netns", "exec", netns, "ip", "addr", "add",
               f"{alloc['guest_ip']}/24", "dev", veth_guest])
        _sudo(["ip", "netns", "exec", netns, "ip", "link", "set", veth_guest, "up"])
        _sudo(["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"])
        _sudo(["ip", "netns", "exec", netns, "ip", "route", "add",
               "default", "via", alloc["host_ip"]])

        # Enable IP forwarding
        _sudo(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        alloc["netns"] = netns
        alloc["veth_host"] = veth_host

        log.info("Network namespace %s created: %s <-> %s (host=%s)",
                 netns, veth_host, veth_guest, alloc["host_ip"])
        return alloc

    def teardown_networking(self, agent_index: int) -> None:
        """Remove network namespace (auto-removes veth pair)."""
        netns = _netns_name(f"idx{agent_index}")
        _sudo(["ip", "netns", "del", netns], check=False)
        log.info("Network namespace %s removed", netns)

    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        """Load iptables rules: allow only proxy egress per subnet."""
        outbound_if = _detect_outbound_interface()

        # Create chain (ignore if exists)
        _sudo(["iptables", "-N", CHAIN_NAME], check=False)

        for subnet in active_subnets:
            host_ip = subnet.replace(".0/24", ".1")

            # Allow proxy port to host
            _sudo(["iptables", "-A", CHAIN_NAME, "-s", subnet,
                   "-d", host_ip, "-p", "tcp", "--dport", str(proxy_port),
                   "-j", "ACCEPT"])
            # Block admin port
            _sudo(["iptables", "-A", CHAIN_NAME, "-s", subnet,
                   "-d", host_ip, "-p", "tcp", "--dport", str(admin_port),
                   "-j", "DROP"])
            # Block everything else from this subnet
            _sudo(["iptables", "-A", CHAIN_NAME, "-s", subnet, "-j", "DROP"])

            # Wire chain into FORWARD
            _sudo(["iptables", "-I", "FORWARD", "-s", subnet, "-j", CHAIN_NAME])

            # NAT for proxy upstream connections
            _sudo(["iptables", "-t", "nat", "-A", "POSTROUTING",
                   "-s", subnet, "-o", outbound_if, "-j", "MASQUERADE"])

        log.info("iptables rules loaded for chain %s", CHAIN_NAME)

    def unload_firewall_rules(self) -> None:
        """Flush and delete iptables chain."""
        # Remove references from FORWARD
        while True:
            result = _sudo(["iptables", "-D", "FORWARD", "-j", CHAIN_NAME], check=False)
            if result.returncode != 0:
                break  # No more references

        # Flush and delete chain
        _sudo(["iptables", "-F", CHAIN_NAME], check=False)
        _sudo(["iptables", "-X", CHAIN_NAME], check=False)

        # Clean up NAT rules (remove all MASQUERADE rules for our subnets)
        # This is best-effort — stale rules are harmless
        for idx in range(10):
            alloc = allocate_subnet(idx)
            _sudo(["iptables", "-t", "nat", "-D", "POSTROUTING",
                   "-s", alloc["subnet"], "-j", "MASQUERADE"], check=False)

        log.info("iptables rules unloaded for chain %s", CHAIN_NAME)

    # --- Rootfs ---

    def prepare_rootfs(self, name: str) -> Path:
        """Create agent rootfs using overlayfs on extracted base.

        The base rootfs is extracted from ext4 once and shared read-only.
        Each agent gets an overlayfs upper layer for writes.
        """
        share_dir = get_share_dir()
        base_dir = share_dir / "rootfs-base"

        # One-time: extract base rootfs from ext4 image
        if not base_dir.exists():
            ext4 = share_dir / "rootfs-base.ext4"
            if not ext4.exists():
                raise RuntimeError(
                    f"Base rootfs not found at {ext4}\n"
                    f"Build guest images first: cd guest && ./build-all.sh"
                )
            log.info("Extracting base rootfs from %s...", ext4)
            mnt = Path("/tmp/safeyolo-rootfs-mnt")
            mnt.mkdir(exist_ok=True)
            _sudo(["mount", "-o", "loop,ro", str(ext4), str(mnt)])
            try:
                _sudo(["cp", "-a", f"{mnt}/.", str(base_dir)])
            finally:
                _sudo(["umount", str(mnt)])
            mnt.rmdir()

        agent_dir = get_agents_dir() / name
        upper = agent_dir / "rootfs-upper"
        work = agent_dir / "rootfs-work"
        merged = agent_dir / "rootfs"

        if merged.exists() and any(merged.iterdir()):
            return merged  # Already mounted

        for d in (upper, work, merged):
            d.mkdir(parents=True, exist_ok=True)

        _sudo(["mount", "-t", "overlay", "overlay",
               "-o", f"lowerdir={base_dir},upperdir={upper},workdir={work}",
               str(merged)])

        log.info("Overlayfs mounted for agent '%s'", name)
        return merged

    # --- Sandbox lifecycle ---

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
        """Start a gVisor sandbox via runsc."""
        runsc = _find_runsc()
        platform = _detect_runsc_platform()
        cgroup_v = _detect_cgroup_version()

        agent_dir = get_agents_dir() / name
        rootfs = agent_dir / "rootfs"
        cid = _container_id(name)
        netns = fw_alloc.get("netns", "")

        # Build OCI config
        config = self._generate_oci_config(
            name=name,
            rootfs_path=rootfs,
            workspace_path=workspace_path,
            config_share=config_share,
            fw_alloc=fw_alloc,
            cpus=cpus,
            memory_mb=memory_mb,
            extra_shares=extra_shares,
            netns=netns,
            cgroup_version=cgroup_v,
        )

        config_path = agent_dir / "config.json"
        config_path.write_text(json.dumps(config, indent=2))

        # Ensure runsc root dir exists
        _sudo(["mkdir", "-p", RUNSC_ROOT])

        # Create container
        _sudo([runsc, "--root", RUNSC_ROOT, f"--platform={platform}",
               "create", "--bundle", str(agent_dir), cid])

        # Start container
        _sudo([runsc, "--root", RUNSC_ROOT, "start", cid])

        # Get PID
        state = json.loads(
            _sudo([runsc, "--root", RUNSC_ROOT, "state", cid]).stdout
        )
        pid = state.get("pid", 0)

        # Write PID file for is_sandbox_running
        pid_path = agent_dir / "container.pid"
        pid_path.write_text(str(pid))

        # Write container IP for compatibility with existing code
        ip_file = config_share / "vm-ip"
        ip_file.write_text(fw_alloc["guest_ip"])

        log.info("Container %s started (pid=%d, platform=%s)", cid, pid, platform)
        return pid

    def stop_sandbox(self, name: str) -> None:
        """Stop a running gVisor sandbox."""
        cid = _container_id(name)
        agent_dir = get_agents_dir() / name

        # Graceful stop
        _sudo([_find_runsc(), "--root", RUNSC_ROOT, "kill", cid, "SIGTERM"], check=False)
        time.sleep(5)

        # Force kill
        _sudo([_find_runsc(), "--root", RUNSC_ROOT, "kill", "--all", cid, "SIGKILL"], check=False)
        time.sleep(1)

        # Delete container
        _sudo([_find_runsc(), "--root", RUNSC_ROOT, "delete", cid], check=False)

        # Teardown networking
        agents_dir = get_agents_dir()
        existing = sorted(d.name for d in agents_dir.iterdir() if d.is_dir()) if agents_dir.exists() else []
        agent_index = existing.index(name) if name in existing else -1
        if agent_index >= 0:
            self.teardown_networking(agent_index)

        # Unmount overlayfs
        merged = agent_dir / "rootfs"
        if merged.exists():
            _sudo(["umount", str(merged)], check=False)

        # Clean up PID file
        pid_path = agent_dir / "container.pid"
        pid_path.unlink(missing_ok=True)

        # Update agent map
        from ..vm import _update_agent_map
        _update_agent_map(name, remove=True)

        log.info("Container %s stopped and cleaned up", cid)

    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        """Execute a command in a running sandbox via runsc exec."""
        cid = _container_id(name)
        uid = "0:0" if user == "root" else "1000:1000"

        cmd = [
            "sudo", _find_runsc(), "--root", RUNSC_ROOT, "exec",
            "--user", uid,
            "--cwd", "/home/agent/workspace",
            cid, "--",
        ]
        if command:
            cmd.extend(["/bin/bash", "-c", command])
        else:
            cmd.extend(["/bin/bash", "-l"])

        result = subprocess.run(cmd)
        return result.returncode

    def is_sandbox_running(self, name: str) -> bool:
        """Check if a gVisor sandbox is running."""
        cid = _container_id(name)
        try:
            result = _sudo(
                [_find_runsc(), "--root", RUNSC_ROOT, "state", cid],
                check=False,
            )
            if result.returncode != 0:
                return False
            state = json.loads(result.stdout)
            return state.get("status") == "running"
        except (json.JSONDecodeError, FileNotFoundError):
            return False

    def cleanup_all(self, agents_dir: Path) -> None:
        """Clean up all networking for this instance."""
        if not agents_dir.exists():
            return

        for idx, agent_dir in enumerate(sorted(agents_dir.iterdir())):
            if agent_dir.is_dir():
                netns = _netns_name(f"idx{idx}")
                _sudo(["ip", "netns", "del", netns], check=False)

    # --- OCI config generation ---

    def _generate_oci_config(
        self,
        name: str,
        rootfs_path: Path,
        workspace_path: str,
        config_share: Path,
        fw_alloc: dict,
        cpus: int,
        memory_mb: int,
        extra_shares: list[tuple[str, str, bool]] | None,
        netns: str,
        cgroup_version: int,
    ) -> dict:
        """Generate an OCI runtime spec for runsc."""
        proxy_port = 8080
        try:
            from ..config import load_config
            cfg = load_config()
            proxy_port = cfg.get("proxy", {}).get("port", 8080)
        except Exception:
            # Config unreadable (missing, malformed) — keep the 8080 default
            # we initialised above. Spec generation must still succeed.
            pass

        proxy_url = f"http://{fw_alloc['host_ip']}:{proxy_port}"
        ca_cert_path = "/usr/local/share/ca-certificates/safeyolo.crt"

        # Environment variables matching what guest-init.sh would set
        env = [
            f"HTTP_PROXY={proxy_url}",
            f"HTTPS_PROXY={proxy_url}",
            f"http_proxy={proxy_url}",
            f"https_proxy={proxy_url}",
            "NO_PROXY=localhost,127.0.0.1",
            "no_proxy=localhost,127.0.0.1",
            f"SSL_CERT_FILE={ca_cert_path}",
            f"REQUESTS_CA_BUNDLE={ca_cert_path}",
            f"NODE_EXTRA_CA_CERTS={ca_cert_path}",
            "NO_UPDATE_NOTIFIER=1",
            "npm_config_update_notifier=false",
            "HOME=/home/agent",
            "USER=agent",
            "TERM=xterm-256color",
            "PATH=/opt/mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "BASH_ENV=/etc/mise-activate.sh",
        ]

        # Add agent-specific env from config share
        agent_env_file = config_share / "agent.env"
        if agent_env_file.exists():
            for line in agent_env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("export "):
                    # export KEY="VALUE" → KEY=VALUE
                    kv = line[7:]
                    kv = kv.replace('"', '')
                    if "=" in kv:
                        env.append(kv)

        # Mounts
        mounts = [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "nodev", "mode=1777"]},
            # Workspace (rw)
            {"destination": "/home/agent/workspace", "type": "bind",
             "source": os.path.abspath(workspace_path),
             "options": ["rbind", "rw"]},
            # Config share (ro)
            {"destination": "/safeyolo", "type": "bind",
             "source": str(config_share),
             "options": ["rbind", "ro"]},
        ]

        # CA cert bind mount into trust store
        ca_cert_src = config_share / "mitmproxy-ca-cert.pem"
        if ca_cert_src.exists():
            mounts.append({
                "destination": ca_cert_path,
                "type": "bind",
                "source": str(ca_cert_src),
                "options": ["bind", "ro"],
            })

        # Extra shares (host config dirs)
        if extra_shares:
            for host_path, tag, read_only in extra_shares:
                home = Path.home()
                try:
                    rel = Path(host_path).relative_to(home)
                    guest_path = f"/home/agent/{rel}"
                except ValueError:
                    guest_path = f"/mnt/{tag}"
                mounts.append({
                    "destination": guest_path,
                    "type": "bind",
                    "source": os.path.abspath(host_path),
                    "options": ["rbind", "ro" if read_only else "rw"],
                })

        # Namespaces
        namespaces = [
            {"type": "pid"},
            {"type": "ipc"},
            {"type": "uts"},
            {"type": "mount"},
        ]
        if netns:
            namespaces.append({"type": "network", "path": f"/var/run/netns/{netns}"})
        else:
            namespaces.append({"type": "network"})

        # Resource limits
        memory_bytes = memory_mb * 1024 * 1024
        cpu_quota = cpus * 100000  # period is 100000
        cgroups_path = f"/safeyolo/{name}" if cgroup_version == 2 else f"safeyolo/{name}"

        return {
            "ociVersion": "1.0.0",
            "root": {"path": str(rootfs_path), "readonly": False},
            "hostname": f"safeyolo-{name}",
            "process": {
                "terminal": False,
                "user": {"uid": 1000, "gid": 1000},
                "args": ["/bin/sleep", "infinity"],
                "env": env,
                "cwd": "/home/agent",
                "capabilities": {
                    "bounding": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                    "effective": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                    "permitted": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                    "ambient": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                },
                "rlimits": [
                    {"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536},
                ],
                "noNewPrivileges": True,
            },
            "mounts": mounts,
            "linux": {
                "namespaces": namespaces,
                "resources": {
                    "memory": {"limit": memory_bytes},
                    "cpu": {"quota": cpu_quota, "period": 100000},
                    "pids": {"limit": 4096},
                },
                "cgroupsPath": cgroups_path,
            },
        }
