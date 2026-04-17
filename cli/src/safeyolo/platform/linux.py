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
import tempfile
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


def _sudo(
    cmd: list[str],
    check: bool = True,
    capture: bool = True,
    detach: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command with sudo.

    detach=True: for commands that fork daemons (notably `runsc create`,
    which spawns runsc-sandbox and runsc-gofer as long-lived children of
    init). Daemon children inherit any pipe we opened for sudo's
    stdout/stderr, and subprocess.run's communicate() then blocks until
    EOF — which never comes while the daemon holds the pipe open.
    detach swaps stderr onto a real tempfile rather than a pipe: regular
    files have no "EOF-blocks-until-all-writers-close" semantics, so
    daemon inheritance is harmless. stdout is discarded (runsc create
    prints nothing useful on success anyway); errors still come through
    via stderr exactly like the non-detach path, both on the returned
    CompletedProcess and on CalledProcessError.
    """
    if detach:
        # tempfile.TemporaryFile unlinks on close; fd is inheritable.
        # Unbuffered so the runsc-cli's stderr lands on disk before
        # it exits, even if daemon children are still writing.
        stderr_file = tempfile.TemporaryFile(mode="w+b", buffering=0)
        try:
            result = subprocess.run(
                ["sudo"] + cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                check=False,  # handle manually so we can attach stderr text
            )
            stderr_file.seek(0)
            err_text = stderr_file.read().decode(errors="replace")
        finally:
            stderr_file.close()
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, ["sudo"] + cmd, output=None, stderr=err_text,
            )
        # Preserve the CompletedProcess shape callers expect.
        return subprocess.CompletedProcess(
            args=result.args, returncode=result.returncode,
            stdout=None, stderr=err_text,
        )
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


def _netns_offset(agent_index: int) -> int:
    """Global slot number for an agent, offsetting by SUBNET_BASE so that
    multiple SafeYolo instances (production SUBNET_BASE=65 + blackbox test
    SUBNET_BASE=75 + any future sibling) don't collide in the kernel's
    flat namespace. Mirror of the formula in _veth_host_name — keep them
    in lockstep.
    """
    return SUBNET_BASE - 65 + agent_index


def _netns_name(agent_index: int) -> str:
    """Derive network namespace name from agent index.

    Must be namespaced by SUBNET_BASE because netns names live in a
    single host-wide namespace. Without the offset, production idx0
    and blackbox-test idx0 both resolve to `safeyolo-idx0`; the second
    instance's `ip link add ... netns safeyolo-idx0` then fails because
    the eth0 peer already exists in the first instance's netns.
    """
    return f"safeyolo-idx{_netns_offset(agent_index)}"


def _veth_host_name(agent_index: int) -> str:
    """Derive host-side veth interface name from agent index."""
    return f"veth-sy{_netns_offset(agent_index)}"


# ---------------------------------------------------------------------------
# AgentPlatform implementation
# ---------------------------------------------------------------------------

class LinuxPlatform(AgentPlatform):
    """Linux agent isolation via gVisor (runsc)."""

    firewall_name = "iptables"

    # --- Networking ---

    def setup_networking(self, agent_index: int) -> dict:
        """Create veth pair + network namespace for an agent."""
        alloc = allocate_subnet(agent_index)
        netns = _netns_name(agent_index)
        veth_host = _veth_host_name(agent_index)
        veth_guest = "eth0"

        # Create network namespace
        _sudo(["ip", "netns", "add", netns], check=False)  # may already exist

        # Create veth pair with the guest end spawned DIRECTLY in the target
        # netns. Without `netns <netns>` on the peer spec, the kernel creates
        # both ends in the root namespace, which collides with the host's own
        # `eth0` (the typical primary NIC name on a Linux server) and fails
        # with RTNETLINK EEXIST.
        _sudo(["ip", "link", "del", veth_host], check=False)  # clean up stale
        _sudo(["ip", "link", "add", veth_host, "type", "veth",
               "peer", "name", veth_guest, "netns", netns])

        # Configure host side
        _sudo(["ip", "addr", "add", f"{alloc['host_ip']}/24", "dev", veth_host])
        _sudo(["ip", "link", "set", veth_host, "up"])

        # Configure guest side (inside netns).
        # Uses `ip -n <ns>` instead of `ip netns exec <ns> ip ...` so the
        # sudoers rule can grant `ip -n safeyolo-*` without also granting
        # `ip netns exec` (which allows running arbitrary binaries as root).
        _sudo(["ip", "-n", netns, "addr", "add",
               f"{alloc['guest_ip']}/24", "dev", veth_guest])
        _sudo(["ip", "-n", netns, "link", "set", veth_guest, "up"])
        _sudo(["ip", "-n", netns, "link", "set", "lo", "up"])
        _sudo(["ip", "-n", netns, "route", "add",
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
        netns = _netns_name(agent_index)
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

            # INPUT chain: sandbox → host:proxy_port is destined for a local
            # IP (the feth host side), so it hits INPUT, not FORWARD. On
            # hosts with default-deny INPUT (e.g. Ubuntu with UFW active)
            # the FORWARD rule above isn't enough — the packet gets dropped
            # before ever reaching mitmproxy. Also explicitly DROP admin
            # port on INPUT so a permissive INPUT policy doesn't let the
            # agent reach it. Use -I so these land ahead of any drop rule.
            _sudo(["iptables", "-I", "INPUT", "-s", subnet, "-d", host_ip,
                   "-p", "tcp", "--dport", str(admin_port), "-j", "DROP"])
            _sudo(["iptables", "-I", "INPUT", "-s", subnet, "-d", host_ip,
                   "-p", "tcp", "--dport", str(proxy_port), "-j", "ACCEPT"])

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

        # Clean up NAT + INPUT rules. Best-effort — stale rules are harmless.
        for idx in range(10):
            alloc = allocate_subnet(idx)
            host_ip = alloc["subnet"].replace(".0/24", ".1")
            _sudo(["iptables", "-t", "nat", "-D", "POSTROUTING",
                   "-s", alloc["subnet"], "-j", "MASQUERADE"], check=False)
            # We don't know the proxy/admin ports at teardown time (they
            # come from runtime config), so loop the known defaults + a
            # small range of likely overrides. Each -D is a no-op if the
            # rule doesn't exist. Keeps teardown self-contained.
            for port in (8080, 8090, 9090):
                _sudo(["iptables", "-D", "INPUT", "-s", alloc["subnet"],
                       "-d", host_ip, "-p", "tcp", "--dport", str(port),
                       "-j", "ACCEPT"], check=False)
                _sudo(["iptables", "-D", "INPUT", "-s", alloc["subnet"],
                       "-d", host_ip, "-p", "tcp", "--dport", str(port),
                       "-j", "DROP"], check=False)

        log.info("iptables rules unloaded for chain %s", CHAIN_NAME)

    # --- Rootfs ---

    def agent_rootfs_path(self, name: str) -> Path:
        """Return the overlayfs merged-dir path for this agent's rootfs.

        On Linux the rootfs is a directory (overlayfs merge of a shared
        read-only base + a per-agent upper layer), not an ext4 image file.
        """
        return get_agents_dir() / name / "rootfs"

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

        # Check for an actual overlay mount, not just dir-has-contents.
        # After stop_sandbox (before the fix that stopped unmounting),
        # merged/ could contain leftover skeleton dirs from the upper
        # layer with no overlay backing them — iterdir saw entries and
        # the old logic shortcut to "already mounted", leaving the
        # next boot without /bin/bash.
        if merged.exists() and os.path.ismount(merged):
            return merged  # Genuinely already mounted

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
        snapshot_capture_path: Path | None = None,  # noqa: ARG002 — PR 5
        restore_from_path: Path | None = None,      # noqa: ARG002 — PR 5
    ) -> int:
        """Start a gVisor sandbox via runsc.

        snapshot_capture_path / restore_from_path are accepted for
        interface parity with DarwinPlatform but ignored here; PR 5 will
        add runsc checkpoint/restore.
        """
        runsc = _find_runsc()
        platform = _detect_runsc_platform()
        cgroup_v = _detect_cgroup_version()

        agent_dir = get_agents_dir() / name
        rootfs = agent_dir / "rootfs"
        cid = _container_id(name)
        netns = fw_alloc.get("netns", "")

        # Ensure the overlay is mounted for this run. prepare_rootfs is
        # idempotent (checks ismount) and originally only runs at
        # `agent add` time — but a host reboot, an accidental umount,
        # or a buggy stop_sandbox umount (now fixed) can leave the
        # overlay off between runs. Without this call, runsc create
        # would see only rootfs-upper skeletons and start would fail
        # with "failed to load /bin/bash: no such file or directory".
        self.prepare_rootfs(name)

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

        # Ensure the workspace bind-mount target exists inside the
        # rootfs. The base rootfs doesn't ship `/workspace`; without
        # this, `runsc start` fails to attach the workspace bind mount
        # and the container lands in `stopped` state before guest-init
        # ever runs. Creating it in rootfs-upper makes it visible via
        # the overlay without mutating the shared base image.
        # rootfs-upper is user-owned (created at prepare_rootfs time),
        # so no sudo needed here.
        os.makedirs(agent_dir / "rootfs-upper" / "workspace", exist_ok=True)

        # Clear any stale state entry for this cid before create. runsc
        # create fails with ID-already-exists if a previous run's state
        # is still in the root dir (e.g. `stopped` after a failed boot,
        # or leftover from an un-clean shutdown). --force makes delete
        # a no-op when the container doesn't exist, so this is safe on
        # a clean slate.
        _sudo([runsc, "--root", RUNSC_ROOT, "delete", "--force", cid],
              check=False)

        # Create container. detach=True: `runsc create` forks the sandbox
        # and gofer as daemons that inherit our stdout pipe — without
        # detach, Python blocks forever in communicate() waiting for EOF
        # on a pipe the daemons hold open for the container's lifetime.
        _sudo([runsc, "--root", RUNSC_ROOT, f"--platform={platform}",
               "create", "--bundle", str(agent_dir), cid], detach=True)

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
        runsc = _find_runsc()

        # Probe state so we only pay for the graceful-kill cycle when a
        # live init exists. `stopped` and `created` both mean "runsc has
        # state dir entries that need cleanup" but no process to signal.
        state_result = _sudo(
            [runsc, "--root", RUNSC_ROOT, "state", cid], check=False,
        )
        has_state = state_result.returncode == 0
        is_running = False
        if has_state:
            try:
                is_running = json.loads(state_result.stdout).get("status") == "running"
            except json.JSONDecodeError:
                pass

        if is_running:
            # Graceful then forced.
            _sudo([runsc, "--root", RUNSC_ROOT, "kill", cid, "SIGTERM"], check=False)
            time.sleep(5)
            _sudo([runsc, "--root", RUNSC_ROOT, "kill", "--all", cid, "SIGKILL"], check=False)
            time.sleep(1)

        if has_state:
            # --force so delete works on created/stopped/running alike.
            # Without --force runsc errors on non-running states, leaving
            # stale entries that break the next `runsc create`.
            _sudo([runsc, "--root", RUNSC_ROOT, "delete", "--force", cid],
                  check=False)

        # Teardown networking
        agents_dir = get_agents_dir()
        existing = sorted(d.name for d in agents_dir.iterdir() if d.is_dir()) if agents_dir.exists() else []
        agent_index = existing.index(name) if name in existing else -1
        if agent_index >= 0:
            self.teardown_networking(agent_index)

        # Intentionally do NOT unmount the overlay here. stop_sandbox
        # is called for graceful halts that expect a subsequent
        # restart — if we umount, the next `runsc create` finds only
        # rootfs-upper's leftover skeletons and fails at "/bin/bash:
        # no such file or directory" before guest-init ever runs. The
        # overlay is torn down in remove_agent_dir when the agent is
        # actually being deleted.

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

        # No `--` separator before the command — runsc exec parses the
        # first non-flag arg as the container ID and everything after
        # it as the command, without treating `--` as a flag terminator.
        # Including `--` makes runsc try to exec `--` itself and fail
        # with "error finding executable \"--\" in PATH".
        cmd = [
            "sudo", _find_runsc(), "--root", RUNSC_ROOT, "exec",
            "--user", uid,
            "--cwd", "/workspace",
            cid,
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
                netns = _netns_name(idx)
                _sudo(["ip", "netns", "del", netns], check=False)

    def remove_agent_dir(self, name: str) -> None:
        """Delete the agent's on-disk directory.

        overlayfs leaves a root-owned work/ subdirectory inside
        rootfs-work/ after unmount, and the container's writes land in
        rootfs-upper/ as root too — so a plain shutil.rmtree from the
        user account fails with EPERM. Defensively unmount any stale
        overlay (no-op if not mounted) and then sudo rm -rf.
        """
        agent_dir = get_agents_dir() / name
        if not agent_dir.exists():
            return
        merged = agent_dir / "rootfs"
        if merged.exists():
            _sudo(["umount", str(merged)], check=False)
        _sudo(["rm", "-rf", str(agent_dir)])

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
        except (OSError, KeyError, ValueError):
            # Config unreadable (missing, malformed) — keep the 8080 default
            # we initialised above. Spec generation must still succeed.
            pass

        proxy_url = f"http://{fw_alloc['host_ip']}:{proxy_port}"
        ca_cert_path = "/usr/local/share/ca-certificates/safeyolo.crt"

        # Environment variables matching what guest-init.sh would set.
        # SAFEYOLO_DETACH=1 routes guest-init-per-run into its "stay alive
        # for SSH access" branch (`exec sleep infinity`) instead of trying
        # to launch vsock-term (which is macOS-only). The container then
        # stays up and `exec_in_sandbox` uses `runsc exec` to open shells.
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
            "SAFEYOLO_DETACH=1",
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
            {"destination": "/workspace", "type": "bind",
             "source": os.path.abspath(workspace_path),
             "options": ["rbind", "rw"]},
            # Config share — mounted RW during boot so guest-init can write
            # /safeyolo/vm-ip (the host's readiness signal) and vm-status.
            # guest-init-per-run:108 remounts it `ro` before going to sleep,
            # matching the macOS microVM behaviour.
            {"destination": "/safeyolo", "type": "bind",
             "source": str(config_share),
             "options": ["rbind", "rw"]},
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

        # Init process: run the guest-init orchestrator as PID 1 (as root,
        # with a Docker-ish cap set) so it can do the same setup it does on
        # the macOS microVM path — mounts, CA trust install, sshd, writing
        # /safeyolo/vm-ip (the host-side readiness signal) — before the
        # SAFEYOLO_DETACH branch leaves the container sleeping for
        # `runsc exec` sessions to land in.
        #
        # Shell/agent sessions come in via `exec_in_sandbox`, which passes
        # `--user 1000:1000` to `runsc exec` — so actual user-facing
        # activity is scoped to the `agent` user even though PID 1 is root.
        # Docker-default capability set. CAP_SYS_ADMIN is included because
        # guest-init-per-run.sh needs `mount -o remount,ro /safeyolo` and
        # gVisor DOES enforce the cap check for mount operations (verified:
        # dropping it breaks the remount, leaving /safeyolo writable).
        #
        # Known residual: unshare(CLONE_NEWUSER) succeeds inside gVisor
        # regardless of this cap set — gVisor's sentry emulates namespace
        # creation in its own user-space kernel without checking the OCI
        # capability bitmask. We cannot block it via seccomp either (gVisor
        # ignores OCI seccomp profiles). The risk is mitigated by gVisor's
        # own sandbox boundary: the new userns exists entirely within the
        # sentry, not on the host kernel, so capabilities gained there are
        # scoped to gVisor's emulated environment and don't grant host
        # access. Filed as an accepted risk with a blackbox test that
        # documents the behaviour.
        root_caps = [
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SYS_CHROOT",
            "CAP_SYS_ADMIN",  # needed for mount -o remount,ro /safeyolo
            "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP",
        ]
        return {
            "ociVersion": "1.0.0",
            "root": {"path": str(rootfs_path), "readonly": False},
            "hostname": f"safeyolo-{name}",
            "process": {
                "terminal": False,
                "user": {"uid": 0, "gid": 0},
                # Capture guest-init stdout+stderr to a log file in the
                # rootfs overlay upper layer — accessible post-mortem from
                # the host at ~/.safeyolo/agents/<name>/rootfs-upper/var/log/
                # safeyolo-boot.log even if the container exits. Without this,
                # runsc swallows the streams and a boot crash is invisible.
                "args": [
                    "/bin/bash", "-c",
                    "mkdir -p /var/log && exec /safeyolo/guest-init >> /var/log/safeyolo-boot.log 2>&1",
                ],
                "env": env,
                "cwd": "/",
                "capabilities": {
                    "bounding": root_caps,
                    "effective": root_caps,
                    "permitted": root_caps,
                    "ambient": root_caps,
                },
                "rlimits": [
                    {"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536},
                ],
                "noNewPrivileges": False,
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
                # Minimal seccomp profile: block syscalls whose default
                # behaviour is an escape vector in a containerised
                # context. Default-allow (we don't replicate Docker's
                # ~44-syscall blocklist here; gVisor's user-space
                # kernel already rejects most of them) with targeted
                # denials for the cases blackbox tests proved were
                # reachable otherwise.
                # Minimal seccomp profile: block syscalls whose default
                # behaviour is an escape vector. Default-allow — we
                # don't replicate Docker's 44-syscall blocklist here
                # because gVisor's user-space kernel already rejects
                # most of them (blackbox tests confirm). Target only
                # what the probes proved reachable.
                #
                # Note: gVisor does NOT honour SCMP_CMP_MASKED_EQ arg
                # filters (as of 20260416-release); per-arg rules are
                # silently ignored so we must block the entire syscall,
                # not just specific flag combinations.
                "seccomp": {
                    "defaultAction": "SCMP_ACT_ALLOW",
                    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
                    "syscalls": [
                        {
                            # unshare: user/mount/pid/net namespace
                            # creation. Inside a fresh userns the agent
                            # appears as uid 0 with a full cap set,
                            # enabling escape attempts the other controls
                            # didn't anticipate. Historical escape
                            # vehicle (CVE-2013-1956 and others).
                            # guest-init doesn't use unshare at all
                            # (verified via grep); safe to block entirely.
                            "names": ["unshare"],
                            "action": "SCMP_ACT_ERRNO",
                            "errnoRet": 1,  # EPERM
                        },
                    ],
                },
            },
        }
