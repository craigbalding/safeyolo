"""Linux platform: gVisor (runsc) containers in unprivileged user namespaces.

Auto-detects KVM availability for best isolation:
  - /dev/kvm accessible → runsc --platform=kvm (hardware isolation)
  - otherwise → runsc --platform=systrap (seccomp-bpf interception)

No Docker, containerd, sudo, or other daemon required. Only needs:
  - runsc binary (single Go binary, ~30MB)
  - iproute2 (standard)
  - systemd user session (resource limits via cgroup delegation)
  - AppArmor profile for runsc (one-time install, allows user namespaces)
  - EROFS rootfs image (built by guest/build-all.sh)

Network isolation is structural: each agent runs in its own user
namespace with a loopback-only network namespace. The only egress
path is a bind-mounted UDS routed through the proxy bridge.
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
from . import AgentPlatform

log = logging.getLogger("safeyolo.platform.linux")

# AppArmor profile name — must match the installed profile.
AA_PROFILE = "safeyolo-runsc"

# runsc state directory — user-writable, no sudo needed.
RUNSC_ROOT_DEFAULT = str(Path.home() / ".safeyolo" / "run")


def _runsc_root() -> str:
    """Return the runsc state directory, creating it if needed.

    Derives from SAFEYOLO_CONFIG_DIR so parallel instances (production
    + blackbox tests) don't collide in the state directory.
    """
    explicit = os.environ.get("SAFEYOLO_RUNSC_ROOT")
    if explicit:
        root = explicit
    else:
        config_dir = os.environ.get("SAFEYOLO_CONFIG_DIR",
                                    str(Path.home() / ".safeyolo"))
        root = str(Path(config_dir) / "run")
    os.makedirs(root, exist_ok=True)
    return root


def _run(
    cmd: list[str],
    check: bool = True,
    capture: bool = True,
    detach: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command without sudo.

    detach=True: for commands that fork daemons (runsc create spawns
    sandbox + gofer). Uses a tempfile for stderr to avoid blocking on
    inherited pipes.
    """
    if detach:
        stderr_file = tempfile.TemporaryFile(mode="w+b", buffering=0)
        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                check=False,
            )
            stderr_file.seek(0)
            err_text = stderr_file.read().decode(errors="replace")
        finally:
            stderr_file.close()
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, output=None, stderr=err_text,
            )
        return subprocess.CompletedProcess(
            args=result.args, returncode=result.returncode,
            stdout=None, stderr=err_text,
        )
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def _detect_runsc_platform() -> str:
    """Detect best runsc platform.

    KVM provides hardware isolation and is preferred. It requires
    /dev/kvm access for both the operator (who has it via group/ACL)
    and the subordinate root uid (100000, granted via setfacl during
    setup). If either is missing, falls back to systrap.
    """
    if not os.path.exists("/dev/kvm"):
        return "systrap"
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "systrap"
    # Check if the subordinate uid (100000) has access via ACL
    try:
        result = subprocess.run(
            ["getfacl", "/dev/kvm"],
            capture_output=True, text=True, check=False, timeout=3,
        )
        if "user:100000:rw" not in result.stdout:
            log.info("KVM available but subordinate uid lacks access, using systrap")
            return "systrap"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "systrap"
    return "kvm"


def _find_runsc() -> str:
    """Find the runsc binary."""
    path = shutil.which("runsc")
    if path:
        return path
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


def _container_id(name: str) -> str:
    """Derive runsc container ID from agent name."""
    return f"safeyolo-{name}"


def _has_aa_exec() -> bool:
    """Check if aa-exec is available."""
    return shutil.which("aa-exec") is not None


def _has_apparmor_profile() -> bool:
    """Check if the SafeYolo AppArmor profile is installed."""
    try:
        result = subprocess.run(
            ["aa-status", "--json"],
            capture_output=True, text=True, check=False,
        )
        return AA_PROFILE in result.stdout
    except FileNotFoundError:
        return False


def _needs_apparmor() -> bool:
    """Check if AppArmor restricts unprivileged user namespaces."""
    try:
        val = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
        return val == "1"
    except (FileNotFoundError, PermissionError):
        return False


def _userns_pid_file(name: str) -> Path:
    """Path to the file storing the userns holder PID for an agent."""
    return get_agents_dir() / name / "userns.pid"


def _start_userns(name: str) -> int:
    """Create a user namespace with proper uid mapping and return its PID.

    The userns holder is a `sleep` process that keeps the namespace
    alive. The sandbox, started via nsenter, outlives this process
    (T3 confirmed), but we need it for nsenter into exec/kill/delete.

    uid mapping: container 0 → host subordinate (100000+), container
    1000 → host operator uid. This gives the agent proper file
    ownership: workspace and /home/agent are owned by container uid
    1000 = host operator = the person who owns those files.
    """
    aa_prefix = []
    if _needs_apparmor() and _has_aa_exec():
        aa_prefix = ["aa-exec", "-p", AA_PROFILE, "--"]

    # Start the userns holder
    proc = subprocess.Popen(
        aa_prefix + ["unshare", "-Un", "sleep", "86400"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    if proc.poll() is not None:
        raise RuntimeError("userns holder exited immediately")

    upid = proc.pid

    # Write uid/gid maps: container 0 → host subordinate, container 1000 → host operator
    host_uid = os.getuid()
    host_gid = os.getgid()
    try:
        subprocess.run(
            ["newuidmap", str(upid),
             "0", "100000", "1000",
             "1000", str(host_uid), "1",
             "1001", "101001", "64534"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["newgidmap", str(upid),
             "0", "100000", "1000",
             "1000", str(host_gid), "1",
             "1001", "101001", "64534"],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        proc.kill()
        raise RuntimeError(f"newuidmap/newgidmap failed: {e.stderr}") from e

    # Persist the PID
    _userns_pid_file(name).write_text(str(upid))
    log.info("userns created for %s (holder pid=%d)", name, upid)
    return upid


def _get_userns_pid(name: str) -> int | None:
    """Read the userns holder PID, verify it's alive."""
    pid_file = _userns_pid_file(name)
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # check alive
        return pid
    except (ValueError, ProcessLookupError, OSError):
        pid_file.unlink(missing_ok=True)
        return None


def _nsenter_cmd(userns_pid: int) -> list[str]:
    """Build nsenter prefix for entering the userns."""
    return ["nsenter", "--user", "--net", "--target", str(userns_pid), "--"]


def _kill_userns(name: str) -> None:
    """Kill the userns holder process."""
    pid_file = _userns_pid_file(name)
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 9)
    except (ValueError, ProcessLookupError, OSError):
        pass
    pid_file.unlink(missing_ok=True)



def _wrap_in_systemd_scope(
    cmd: list[str],
    name: str,
    memory_mb: int,
    cpus: int,
) -> list[str]:
    """Wrap a command in a systemd user scope for resource limits."""
    memory_max = f"{memory_mb}M"
    cpu_quota = f"{cpus * 100}%"
    return [
        "systemd-run", "--user", "--scope",
        "-p", "Delegate=yes",
        "-p", f"MemoryMax={memory_max}",
        "-p", f"CPUQuota={cpu_quota}",
        "-p", f"Description=safeyolo-{name}",
        "--",
    ] + cmd


# ---------------------------------------------------------------------------
# AgentPlatform implementation
# ---------------------------------------------------------------------------

class LinuxPlatform(AgentPlatform):
    """Linux agent isolation via gVisor (runsc) in unprivileged user namespaces."""

    # --- Networking ---

    def setup_networking(self, agent_index: int) -> dict:
        """Compute the agent's identity. No host-side setup needed.

        Network isolation is handled at container start time via
        unshare -Urn (user namespace + loopback-only network namespace).
        The agent IP is configured on the guest's loopback by guest-init.
        """
        offset = agent_index + 1  # 0 → 10.200.0.1
        attribution_ip = f"10.200.{offset // 256}.{offset % 256}"

        return {
            "host_ip": "127.0.0.1",
            "guest_ip": "127.0.0.1",
            "attribution_ip": attribution_ip,
            "needs_bridge_socket": True,
        }

    def teardown_networking(self, agent_index: int) -> None:
        """No-op: network namespace is owned by the unshare process and
        cleaned up automatically when the sandbox exits."""
        pass

    def load_firewall_rules(self, proxy_port: int, admin_port: int,  # noqa: ARG002
                            active_subnets: list[str]) -> None:  # noqa: ARG002
        """No-op: structural isolation, no firewall rules."""
        pass

    def unload_firewall_rules(self) -> None:
        """No-op."""
        pass

    def _status_dir(self, name: str) -> Path:
        from ..vm import get_agent_status_dir  # noqa: PLC0415
        return get_agent_status_dir(name)

    # --- Rootfs ---

    def agent_rootfs_path(self, name: str) -> Path:
        """Return the overlayfs merged-dir path for this agent's rootfs."""
        return get_agents_dir() / name / "rootfs"

    def prepare_rootfs(self, name: str) -> Path:
        """Verify the EROFS rootfs image exists.

        With EROFS, gVisor mounts the image directly in its sentry and
        handles the writable overlay internally (memory-backed). No
        fuse-overlayfs, no per-agent copies, no uid remapping needed.
        All agents share one read-only EROFS image.
        """
        share_dir = get_share_dir()
        erofs = share_dir / "rootfs-base.erofs"
        if not erofs.exists():
            raise RuntimeError(
                f"EROFS rootfs image not found at {erofs}\n"
                f"Build guest images first: cd guest && ./build-all.sh\n"
                f"Requires: sudo apt install erofs-utils"
            )

        # The OCI spec's root.path must point to a directory (OCI
        # requirement), even though EROFS replaces it via annotations.
        # Create an empty placeholder.
        agent_dir = get_agents_dir() / name
        rootfs_dir = agent_dir / "rootfs"
        rootfs_dir.mkdir(parents=True, exist_ok=True)
        return rootfs_dir

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
        snapshot_capture_path: Path | None = None,  # noqa: ARG002
        restore_from_path: Path | None = None,      # noqa: ARG002
    ) -> int:
        """Start a gVisor sandbox in an unprivileged user namespace."""
        runsc = _find_runsc()
        platform = _detect_runsc_platform()
        root = _runsc_root()

        agent_dir = get_agents_dir() / name
        rootfs = agent_dir / "rootfs"
        cid = _container_id(name)
        agent_ip = fw_alloc.get("attribution_ip", "")

        self.prepare_rootfs(name)

        os.makedirs(rootfs / "workspace", exist_ok=True)

        # Make state dir world-accessible so nsenter'd processes
        # (running as the subordinate root uid) can write state.
        os.chmod(root, 0o777)

        # Clean stale state from previous run. Create a temporary
        # userns if needed — runsc state is owned by uid 100000.
        old_upid = _get_userns_pid(name)
        if old_upid:
            _run(_nsenter_cmd(old_upid) +
                 [runsc, "--root", root, "delete", "--force", cid],
                 check=False)
            _kill_userns(name)

        # Create user namespace — we need the PID for the OCI
        # spec's network namespace path.
        upid = _start_userns(name)

        # Force-delete any stale state using the new userns (covers
        # the case where the old userns holder was already dead).
        _run(_nsenter_cmd(upid) +
             [runsc, "--root", root, "delete", "--force", cid],
             check=False)
        _run(_nsenter_cmd(upid) +
             ["rm", "-f", f"/tmp/runsc-{cid}.sock"],
             check=False)

        config = self._generate_oci_config(
            name=name,
            rootfs_path=rootfs,
            workspace_path=workspace_path,
            config_share=config_share,
            fw_alloc=fw_alloc,
            cpus=cpus,
            memory_mb=memory_mb,
            extra_shares=extra_shares,
            userns_pid=upid,
        )

        config_path = agent_dir / "config.json"
        config_path.write_text(json.dumps(config, indent=2))

        # Configure networking inside the userns. lo gets configured
        # in the userns's netns; the OCI spec points gVisor at this
        # netns via /proc/<holder>/ns/net so gVisor's sandbox netstack
        # imports the loopback (with agent IP) into its internal stack.
        setup = "ip link set lo up"
        if agent_ip:
            setup += f" && ip addr add {agent_ip}/32 dev lo"

        netns_path = f"/proc/{upid}/ns/net"

        inner = (
            f"{setup} && "
            f"{runsc} --root {root} --host-uds=open --ignore-cgroups "
            f"--network=sandbox --platform={platform} "
            f"create --bundle {agent_dir} {cid} && "
            f"{runsc} --ignore-cgroups --root {root} "
            f"start {cid}"
        )

        cmd = _wrap_in_systemd_scope(
            _nsenter_cmd(upid) + ["bash", "-c", inner],
            name, memory_mb, cpus,
        )

        with tempfile.TemporaryFile(mode="w+b") as stderr_file:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                check=False,
            )
            stderr_file.seek(0)
            err_text = stderr_file.read().decode(errors="replace")

        if result.returncode != 0:
            _kill_userns(name)
            log.error("Container start failed (rc=%d): %s",
                      result.returncode, err_text)
            raise RuntimeError(f"Failed to start container {cid}: {err_text}")

        # Get PID — nsenter into userns for state query
        state_result = _run(
            _nsenter_cmd(upid) + [runsc, "--root", root, "state", cid],
            check=False,
        )
        pid = 0
        if state_result.returncode == 0:
            try:
                pid = json.loads(state_result.stdout).get("pid", 0)
            except json.JSONDecodeError:
                pass

        pid_path = agent_dir / "container.pid"
        pid_path.write_text(str(pid))

        log.info("Container %s started (pid=%d, platform=%s, rootless=true)",
                 cid, pid, platform)
        return pid

    def stop_sandbox(self, name: str) -> None:
        """Stop a running gVisor sandbox."""
        cid = _container_id(name)
        agent_dir = get_agents_dir() / name
        runsc = _find_runsc()
        root = _runsc_root()

        upid = _get_userns_pid(name)

        # If the userns holder is dead, create a temporary one for
        # cleanup. The state dir is owned by uid 100000 — we need
        # to be in a userns where we're that uid to access it.
        temp_userns = False
        if not upid:
            try:
                upid = _start_userns(name)
                temp_userns = True
            except RuntimeError:
                # Can't create userns — best-effort cleanup without it
                upid = None

        prefix = _nsenter_cmd(upid) if upid else []

        state_result = _run(
            prefix + [runsc, "--root", root, "state", cid], check=False,
        )
        has_state = state_result.returncode == 0
        is_running = False
        if has_state:
            try:
                is_running = json.loads(state_result.stdout).get("status") == "running"
            except json.JSONDecodeError:
                pass

        if is_running:
            _run(prefix + [runsc, "--root", root, "kill", cid, "SIGTERM"], check=False)
            time.sleep(5)
            _run(prefix + [runsc, "--root", root, "kill", "--all", cid, "SIGKILL"], check=False)
            time.sleep(1)

        if has_state:
            _run(prefix + [runsc, "--root", root, "delete", "--force", cid], check=False)
        else:
            # State query failed — force delete anyway in case files exist
            _run(prefix + [runsc, "--root", root, "delete", "--force", cid], check=False)

        # Clean stale control socket from /tmp. gVisor creates it as
        # the userns root (uid 100000) so the operator can't delete it
        # directly — use the userns prefix.
        sock_path = f"/tmp/runsc-{cid}.sock"
        _run(prefix + ["rm", "-f", sock_path], check=False)

        _kill_userns(name)
        if temp_userns:
            _kill_userns(name)

        pid_path = agent_dir / "container.pid"
        pid_path.unlink(missing_ok=True)

        from ..vm import _update_agent_map  # noqa: PLC0415
        _update_agent_map(name, remove=True)

        log.info("Container %s stopped", cid)

    def exec_in_sandbox(self, name: str, command: str | None,
                        user: str = "agent",
                        interactive: bool = True) -> int:
        """Execute a command in a running sandbox via runsc exec.

        Requires nsenter into the userns because the runsc state dir
        is owned by the mapped root (host uid from subordinate range).
        """
        cid = _container_id(name)
        uid = "0:0" if user == "root" else "1000:1000"
        root = _runsc_root()

        upid = _get_userns_pid(name)
        prefix = _nsenter_cmd(upid) if upid else []

        cmd = prefix + [
            _find_runsc(), "--root", root, "exec",
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
        root = _runsc_root()
        upid = _get_userns_pid(name)
        prefix = _nsenter_cmd(upid) if upid else []
        try:
            result = _run(
                prefix + [_find_runsc(), "--root", root, "state", cid],
                check=False,
            )
            if result.returncode != 0:
                return False
            state = json.loads(result.stdout)
            return state.get("status") == "running"
        except (json.JSONDecodeError, FileNotFoundError):
            return False

    def cleanup_all(self, agents_dir: Path) -> None:
        """Clean up all containers and userns holders for this instance."""
        root = _runsc_root()
        runsc = _find_runsc()
        if not agents_dir.exists():
            return

        for agent_dir in sorted(agents_dir.iterdir()):
            if not agent_dir.is_dir():
                continue
            name = agent_dir.name
            cid = _container_id(name)
            upid = _get_userns_pid(name)
            prefix = _nsenter_cmd(upid) if upid else []
            _run(prefix + [runsc, "--root", root, "delete", "--force", cid],
                 check=False)
            _kill_userns(name)

    def remove_agent_dir(self, name: str) -> None:
        """Delete the agent's on-disk directory."""
        agent_dir = get_agents_dir() / name
        if not agent_dir.exists():
            return
        shutil.rmtree(agent_dir)

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
        userns_pid: int | None = None,
    ) -> dict:
        """Generate an OCI runtime spec for rootless runsc."""
        guest_proxy_port = 8080
        proxy_url = f"http://{fw_alloc['host_ip']}:{guest_proxy_port}"
        ca_cert_path = "/usr/local/share/ca-certificates/safeyolo.crt"

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
                    kv = line[7:].replace('"', '')
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
            {"destination": "/workspace", "type": "bind",
             "source": os.path.abspath(workspace_path),
             "options": ["rbind", "rw", "nosuid", "nodev"]},
            {"destination": "/safeyolo", "type": "bind",
             "source": str(config_share),
             "options": ["rbind", "ro"]},
            {"destination": "/safeyolo-status", "type": "bind",
             "source": str(self._status_dir(name)),
             "options": ["rbind", "rw"]},
        ]

        # Per-agent proxy UDS
        from ..proxy_bridge import socket_path_for as _proxy_sock_for  # noqa: PLC0415
        proxy_sock = _proxy_sock_for(name)
        if proxy_sock.exists():
            mounts.append({
                "destination": "/safeyolo/proxy.sock",
                "type": "bind",
                "source": str(proxy_sock),
                "options": ["bind", "rw"],
            })

        # CA cert
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

        namespaces = [
            {"type": "pid"},
            {"type": "ipc"},
            {"type": "uts"},
            {"type": "mount"},
        ]
        # Point gVisor at the userns holder's netns so sandbox
        # networking imports the loopback (with agent IP) into its
        # internal netstack.
        if userns_pid:
            namespaces.append({
                "type": "network",
                "path": f"/proc/{userns_pid}/ns/net",
            })

        # Capabilities: CAP_CHOWN for guest-init to chown /home/agent
        # to uid 1000 (gVisor's sentry handles this internally).
        # CAP_NET_ADMIN for ip addr add (agent IP on lo).
        root_caps = [
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT",
            "CAP_NET_ADMIN",
            "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP",
        ]
        # EROFS annotations — gVisor mounts the image directly in its
        # sentry with an in-memory writable overlay. The OCI root.path
        # is a placeholder directory; the actual rootfs comes from the
        # EROFS image.
        erofs_path = str(get_share_dir() / "rootfs-base.erofs")
        annotations = {
            "dev.gvisor.spec.rootfs.source": erofs_path,
            "dev.gvisor.spec.rootfs.type": "erofs",
            "dev.gvisor.spec.rootfs.overlay": "memory",
        }

        return {
            "ociVersion": "1.0.0",
            "root": {"path": str(rootfs_path), "readonly": False},
            "hostname": f"safeyolo-{name}",
            "annotations": annotations,
            "process": {
                "terminal": False,
                "user": {"uid": 0, "gid": 0},
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
                "seccomp": {
                    "defaultAction": "SCMP_ACT_ALLOW",
                    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
                    "syscalls": [
                        {
                            "names": ["unshare"],
                            "action": "SCMP_ACT_ERRNO",
                            "errnoRet": 1,
                        },
                    ],
                },
            },
        }
