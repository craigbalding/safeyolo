"""Linux platform: gVisor (runsc) containers in unprivileged user namespaces.

Auto-detects KVM availability for best isolation:
  - /dev/kvm accessible → runsc --platform=kvm (hardware isolation)
  - otherwise → runsc --platform=systrap (seccomp-bpf interception)

No daemon required. Only needs:
  - runsc binary (single Go binary, ~30MB)
  - iproute2 (standard)
  - systemd user session (resource limits via cgroup delegation)
  - AppArmor profile for runsc (one-time install, allows user namespaces)
  - EROFS rootfs image (built by guest/build-all.sh)

Network isolation is structural: each agent runs in its own user
namespace with a loopback-only network namespace. The only egress
path is a bind-mounted UDS on which mitmproxy's per-agent
`UnixInstance` is listening — no bridge process, identity comes
from the socket directory name.
"""

import json
import logging
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ..config import get_agents_dir
from ..timing import enter as _profile_enter
from ..timing import phase as _profile_phase
from ..vm import ensure_agent_persistent_dirs, get_agent_home_dir
from . import AgentPlatform, BinaryRelay

log = logging.getLogger("safeyolo.platform.linux")

# AppArmor profile name -- must match the installed profile.
AA_PROFILE = "safeyolo-runsc"

# runsc state directory -- user-writable, no sudo needed.
RUNSC_ROOT_DEFAULT = str(Path.home() / ".safeyolo" / "run")
PORT_FORWARD_TIMEOUT_SECONDS = 10
GRACEFUL_STOP_TIMEOUT_SECONDS = 5.0
STOP_POLL_INTERVAL_SECONDS = 0.05
USERNS_START_TIMEOUT_SECONDS = 2.0
USERNS_POLL_INTERVAL_SECONDS = 0.005

# Diagnostic-only overrides used by the archived ETXTBSY experiment. Keeping
# these out of policy.toml makes it difficult to accidentally turn an
# experiment into a persistent security/performance setting. The workspace
# override also accepts "default" to reproduce gVisor's pre-fix mount default.
EXPERIMENT_WORKSPACE_DCACHE_ENV = "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE"
EXPERIMENT_RUNSC_DCACHE_ENV = "SAFEYOLO_EXPERIMENT_RUNSC_DCACHE"
EXPERIMENT_RUNSC_DIRECTFS_ENV = "SAFEYOLO_EXPERIMENT_RUNSC_DIRECTFS"
RUNSC_PLATFORM_ENV = "SAFEYOLO_RUNSC_PLATFORM"


class _SocketReader:
    """Minimal binary reader over one native runsc port-forward socket."""

    def __init__(self, stream: socket.socket):
        self._stream = stream
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            return b""
        if size < 0:
            chunks = []
            while chunk := self._stream.recv(64 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        return self._stream.recv(size)

    def close(self) -> None:
        self.closed = True


class _SocketWriter:
    """Minimal binary writer whose close preserves TCP half-close semantics."""

    def __init__(self, stream: socket.socket):
        self._stream = stream
        self.closed = False

    def write(self, data: bytes) -> int:
        if self.closed:
            raise ValueError("write to closed relay")
        self._stream.sendall(data)
        return len(data)

    def flush(self) -> None:
        if self.closed:
            raise ValueError("flush of closed relay")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._stream.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # The peer may already have closed during relay teardown.


class _SocketRelay:
    """Popen-shaped owner of a connected native runsc stream."""

    def __init__(self, stream: socket.socket):
        self._stream = stream
        self.stdin = _SocketWriter(stream)
        self.stdout = _SocketReader(stream)
        self.returncode: int | None = None
        self._lock = threading.Lock()

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002
        self._close()
        return 0

    def terminate(self) -> None:
        self._close()

    def kill(self) -> None:
        self._close()

    def _close(self) -> None:
        with self._lock:
            if self.returncode is not None:
                return
            self.stdin.close()
            self.stdout.close()
            try:
                self._stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # The socket may already be disconnected or shut down.
            self._stream.close()
            self.returncode = 0


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


def _experiment_nonnegative_int(name: str) -> int | None:
    """Read a diagnostic non-negative integer without shell metacharacters."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    if not raw or not raw.isascii() or not raw.isdecimal():
        raise RuntimeError(f"{name} must be a non-negative integer, got {raw!r}")
    return int(raw)


def _experiment_bool(name: str) -> bool | None:
    """Read a diagnostic boolean using a deliberately narrow vocabulary."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    raise RuntimeError(f"{name} must be true/false or 1/0, got {raw!r}")


def _workspace_dcache_option() -> str | None:
    """Return the production workspace cache option or a diagnostic override."""
    raw = os.environ.get(EXPERIMENT_WORKSPACE_DCACHE_ENV)
    if raw == "default":
        return None
    value = _experiment_nonnegative_int(EXPERIMENT_WORKSPACE_DCACHE_ENV)
    return f"dcache={0 if value is None else value}"


def _experiment_runsc_flags() -> list[str]:
    """Return validated runsc flags for the ETXTBSY experiment harness."""
    flags: list[str] = []
    dcache = _experiment_nonnegative_int(EXPERIMENT_RUNSC_DCACHE_ENV)
    if dcache is not None:
        flags.append(f"--dcache={dcache}")
    directfs = _experiment_bool(EXPERIMENT_RUNSC_DIRECTFS_ENV)
    if directfs is not None:
        flags.append(f"--directfs={'true' if directfs else 'false'}")
    return flags


def _wrap_runsc_command(command: str) -> str:
    """Load guest runtime environment without losing mise's shim path.

    ``/etc/environment`` contains the proxy and CA variables required by
    commands launched through ``runsc exec``, but its base PATH intentionally
    omits per-user tools. Source the mise activation file afterwards so its
    persistent data directories and shims win.
    """
    return (
        ". /etc/environment 2>/dev/null; "
        "if [ -f /etc/mise-activate.sh ]; then "
        ". /etc/mise-activate.sh; "
        "fi; "
        f"{command}"
    )


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


def _apply_runsc_platform_override(info: dict) -> dict:
    """Apply the explicit software-isolation selection used by operators/CI.

    KVM remains auto-detected because claiming hardware isolation without
    proving both operator and subordinate-uid access would produce false test
    evidence. Selecting systrap makes its acceptance lane deterministic even
    on a host which happens to expose /dev/kvm.
    """
    requested = os.environ.get(RUNSC_PLATFORM_ENV, "").strip().lower()
    if requested in {"", "auto"}:
        return info
    if requested != "systrap":
        raise RuntimeError(
            f"{RUNSC_PLATFORM_ENV} must be 'auto' or 'systrap', got {requested!r}"
        )

    info["platform"] = "systrap"
    info["forced"] = True
    info["reason"] = f"forced by {RUNSC_PLATFORM_ENV}"
    return info


def detect_runsc_platform() -> dict:
    """Detect best runsc platform with diagnostic detail.

    Returns a dict with keys:
      platform: "kvm" or "systrap"
      kvm_exists: bool
      kvm_operator_access: bool
      kvm_subordinate_access: bool
      kvm_group: str  (group name owning /dev/kvm, or "" / gid str if unresolved)
      kvm_group_has_rw: bool  (group bits on /dev/kvm include rw)
      operator_in_kvm_group: bool  (current process is in the owning group)
      forced: bool  (systrap was selected explicitly instead of auto-detected)
      reason: human-readable explanation
    """
    info: dict = {
        "platform": "systrap",
        "kvm_exists": os.path.exists("/dev/kvm"),
        "kvm_operator_access": False,
        "kvm_subordinate_access": False,
        "kvm_group": "",
        "kvm_group_has_rw": False,
        "operator_in_kvm_group": False,
        "forced": False,
        "reason": "",
    }
    if not info["kvm_exists"]:
        info["reason"] = "/dev/kvm not found"
        return _apply_runsc_platform_override(info)

    # Group/mode facts are useful for targeted remediation even when the
    # operator does have rw access, so capture them unconditionally.
    try:
        st = os.stat("/dev/kvm")
        info["kvm_group_has_rw"] = bool(
            st.st_mode & stat.S_IRGRP and st.st_mode & stat.S_IWGRP
        )
        try:
            import grp
            info["kvm_group"] = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            info["kvm_group"] = str(st.st_gid)
        info["operator_in_kvm_group"] = st.st_gid in os.getgroups() or st.st_gid == os.getgid()
    except OSError:
        pass

    info["kvm_operator_access"] = os.access("/dev/kvm", os.R_OK | os.W_OK)
    if not info["kvm_operator_access"]:
        info["reason"] = "/dev/kvm exists but operator lacks rw access"
        return _apply_runsc_platform_override(info)
    try:
        result = subprocess.run(
            ["getfacl", "/dev/kvm"],
            capture_output=True, text=True, check=False, timeout=3,
        )
        info["kvm_subordinate_access"] = "user:100000:rw" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # getfacl missing or hung -- assume no subordinate access
        # and fall back to systrap (the safe default).
        pass
    if not info["kvm_subordinate_access"]:
        info["reason"] = "subordinate uid 100000 lacks /dev/kvm ACL"
        return _apply_runsc_platform_override(info)
    info["platform"] = "kvm"
    info["reason"] = "KVM available with full access"
    return _apply_runsc_platform_override(info)


def _detect_runsc_platform() -> str:
    """Internal: return just the platform string."""
    return detect_runsc_platform()["platform"]


def find_runsc() -> str | None:
    """Find the runsc binary. Returns path or None."""
    path = shutil.which("runsc")
    if path:
        return path
    for p in ["/usr/local/bin/runsc", "/usr/bin/runsc"]:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return None


def _find_runsc() -> str:
    """Internal: find runsc or raise."""
    path = find_runsc()
    if not path:
        raise RuntimeError(
            "runsc not found. Install gVisor:\n"
            "  curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg\n"
            '  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] '
            'https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list\n'
            "  sudo apt update && sudo apt install -y runsc"
        )
    return path


def _container_id(name: str) -> str:
    """Derive runsc container ID from agent name."""
    return f"safeyolo-{name}"


def _runsc_container_status(
    prefix: list[str], runsc: str, root: str, cid: str
) -> str | None:
    """Return the OCI status, or None once runsc has no readable state."""
    result = _run(
        prefix + [runsc, "--root", root, "state", cid],
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        status = json.loads(result.stdout).get("status")
    except (json.JSONDecodeError, AttributeError):
        return "unknown"
    return status if isinstance(status, str) else "unknown"


def _wait_for_runsc_stop(
    prefix: list[str],
    runsc: str,
    root: str,
    cid: str,
    *,
    timeout: float = GRACEFUL_STOP_TIMEOUT_SECONDS,
) -> bool:
    """Poll until the container is stopped/absent; return False on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        status = _runsc_container_status(prefix, runsc, root, cid)
        if status is None or status not in {"running", "unknown"}:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(STOP_POLL_INTERVAL_SECONDS, remaining))


def has_aa_exec() -> bool:
    """Check if aa-exec is available."""
    return shutil.which("aa-exec") is not None


def has_apparmor_profile() -> bool:
    """Check if the SafeYolo AppArmor profile is loaded in the kernel.

    Probes functionally: runs `aa-exec -p safeyolo-runsc -- true`.
    Succeeds only if the profile is loaded and usable by the current
    user. No root needed.
    """
    if not has_aa_exec():
        return False
    try:
        result = subprocess.run(
            ["aa-exec", "-p", AA_PROFILE, "--", "true"],
            capture_output=True, check=False, timeout=3,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def needs_apparmor() -> bool:
    """Check if AppArmor restricts unprivileged user namespaces."""
    try:
        val = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
        return val == "1"
    except (FileNotFoundError, PermissionError):
        return False


def check_userns_prerequisites() -> dict:
    """Check user namespace prerequisites for rootless gVisor.

    Returns a dict with keys:
      newuidmap: bool -- newuidmap binary available
      newgidmap: bool -- newgidmap binary available
      subuid: bool -- /etc/subuid has entry for current user
      subgid: bool -- /etc/subgid has entry for current user
      setfacl: bool -- setfacl available (grants runsc state dir to uid 100000)
      apparmor_restricts: bool -- kernel restricts unprivileged userns
      apparmor_profile_loaded: bool -- safeyolo-runsc profile loaded
    """
    import getpass
    username = getpass.getuser()

    info = {
        "newuidmap": shutil.which("newuidmap") is not None,
        "newgidmap": shutil.which("newgidmap") is not None,
        "subuid": False,
        "subgid": False,
        "setfacl": shutil.which("setfacl") is not None,
        "apparmor_restricts": needs_apparmor(),
        "apparmor_profile_loaded": False,
    }

    for fname, key in [("/etc/subuid", "subuid"), ("/etc/subgid", "subgid")]:
        try:
            content = Path(fname).read_text()
            info[key] = any(
                line.startswith(f"{username}:") for line in content.splitlines()
            )
        except (FileNotFoundError, PermissionError):
            # subuid/subgid not provisioned or unreadable -- leave
            # info[key] False so doctor reports "not configured".
            pass

    if info["apparmor_restricts"]:
        info["apparmor_profile_loaded"] = has_apparmor_profile()

    return info


def _userns_pid_file(name: str) -> Path:
    """Path to the file storing the userns holder PID for an agent."""
    return get_agents_dir() / name / "userns.pid"


def _wait_for_userns_ready(
    proc: subprocess.Popen,
    *,
    timeout: float = USERNS_START_TIMEOUT_SECONDS,
) -> None:
    """Wait until ``unshare`` has entered both requested namespaces.

    ``Popen`` returning only proves that the child was forked; calling
    ``newuidmap`` before the child completes ``unshare(CLONE_NEWUSER)`` races
    against the child and can target its original namespace. Namespace inode
    transitions are the kernel-visible readiness condition we actually need.
    """
    parent_userns = os.stat("/proc/self/ns/user").st_ino
    parent_netns = os.stat("/proc/self/ns/net").st_ino
    deadline = time.monotonic() + timeout
    user_ready = False
    net_ready = False

    while True:
        returncode = proc.poll()
        if returncode is not None:
            raise RuntimeError(
                f"userns holder exited before namespace setup (status {returncode})"
            )

        try:
            user_ready = (
                os.stat(f"/proc/{proc.pid}/ns/user").st_ino != parent_userns
            )
            net_ready = (
                os.stat(f"/proc/{proc.pid}/ns/net").st_ino != parent_netns
            )
        except OSError:
            # The process may be between fork and its /proc entries becoming
            # visible. Liveness and the deadline below decide whether to retry.
            user_ready = False
            net_ready = False

        if user_ready and net_ready:
            return

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass  # Best effort after kill; later cleanup handles a lingering holder.
            raise RuntimeError(
                "userns holder did not enter its user and network namespaces "
                f"within {timeout:g}s (user={user_ready}, net={net_ready})"
            )
        time.sleep(min(USERNS_POLL_INTERVAL_SECONDS, remaining))


def _start_userns(name: str, *, persist_pid: bool = True) -> int:
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
    if needs_apparmor() and has_aa_exec():
        aa_prefix = ["aa-exec", "-p", AA_PROFILE, "--"]

    # Start the userns holder
    proc = subprocess.Popen(
        aa_prefix + ["unshare", "-Un", "sleep", "86400"],  # DOC: docs/security-verification.md, README.md, SECURITY.md
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _wait_for_userns_ready(proc)

    upid = proc.pid

    # Write uid/gid maps: container 0 → host subordinate, container 1000 → host operator
    host_uid = os.getuid()
    host_gid = os.getgid()
    try:
        subprocess.run(
            ["newuidmap", str(upid),  # DOC: docs/security-verification.md, README.md, SECURITY.md
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

    # Runtime namespaces must survive this call, so persist their holder PID.
    # One-shot maintenance namespaces (for example agent-dir cleanup) are
    # killed by their caller and deliberately leave no state behind.
    if persist_pid:
        try:
            _userns_pid_file(name).write_text(str(upid))
        except OSError:
            proc.kill()
            raise
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


def _direct_rootfs_target_state(path: Path, expected: str) -> bool | None:
    """Return target validity, or None when host DAC prevents inspection."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return False
    except PermissionError:
        return None
    if expected == "directory":
        return stat.S_ISDIR(mode)
    return stat.S_ISREG(mode)


def _kill_userns(name: str) -> None:
    """Kill the userns holder process."""
    pid_file = _userns_pid_file(name)
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 9)
    except (ValueError, ProcessLookupError, OSError):
        # Stale/corrupt PID file or process already gone -- either
        # way, unlinking below is the correct next step.
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
        attribution_ip = f"10.200.{offset // 256}.{offset % 256}"  # DOC: SECURITY.md, README.md, docs/ARCHITECTURE.md, docs/security-verification.md

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
        """Return the directory gVisor uses as OCI root.path for this agent.

        Points at the shared tree in ~/.safeyolo/share/rootfs-tree
        (produced by guest/build-rootfs.sh). Overridden by a per-agent
        rootfs directory at ~/.safeyolo/agents/<name>/rootfs/ when a
        custom --rootfs-script has populated one.
        """
        from ..vm import get_base_rootfs_tree_path  # noqa: PLC0415
        per_agent_dir = get_agents_dir() / name / "rootfs"
        per_agent_erofs = get_agents_dir() / name / "rootfs.erofs"
        if per_agent_erofs.exists():
            raise RuntimeError(
                f"Per-agent rootfs image at {per_agent_erofs} is EROFS-format.\n"
                f"The Linux runtime switched from rootfs.source=erofs annotation\n"
                f"to OCI root.path = directory tree, so --rootfs-script now\n"
                f"needs to emit an unpacked tree at ~/.safeyolo/agents/{name}/\n"
                f"rootfs/ (not .erofs). Update your rootfs script (skopeo+umoci\n"
                f"output the tree natively; contrib/alpine-minimal is the\n"
                f"canonical template) or remove the per-agent .erofs to fall\n"
                f"back to the shared base."
            )
        # The tree's contents may deliberately be private to subordinate uid
        # 100000.  Selecting it must only require statting the tree itself;
        # prepare_rootfs validates its contents through the runtime uid map.
        if per_agent_dir.is_dir():
            return per_agent_dir
        return get_base_rootfs_tree_path()

    def prepare_rootfs(self, name: str) -> Path:
        """Verify the Linux rootfs tree exists for this agent.

        gVisor consumes the tree directly as OCI root.path — no
        per-agent copy, no EROFS image, no placeholder directory.
        All agents share the single tree at
        ~/.safeyolo/share/rootfs-tree (produced by build-rootfs.sh);
        writes go to the per-agent overlay upper (dir= medium on
        --overlay2).

        A per-agent rootfs/ directory under ~/.safeyolo/agents/<name>/
        overrides the shared base when present — that's the
        --rootfs-script path (custom distro).
        """
        # agent_rootfs_path centralizes the .erofs-detection error and
        # the shared/per-agent selection. Reusing it keeps the two
        # paths in lockstep.
        path = self.agent_rootfs_path(name)
        # agent_rootfs_path returned the shared tree — check it's actually
        # populated, so "build guest images first" fires here (at agent
        # add time) rather than later on start_sandbox failure.
        from ..vm import get_base_rootfs_tree_path  # noqa: PLC0415
        if path == get_base_rootfs_tree_path() and not (
            path.is_dir() and (path / "etc").is_dir()
        ):
            raise RuntimeError(
                f"Rootfs tree not found at {path}\n"
                f"Build guest images first: cd guest && ./build-all.sh\n"
                f"Then install: sudo cp -a guest/out/rootfs-tree ~/.safeyolo/share/"
            )

        # Rootless gVisor maps container uid 0 → host uid 100000
        # (hardcoded in _start_userns). Inside the sandbox, files
        # owned by host uid 0 appear as `nobody` and sandbox-root
        # cannot modify them — apt-get install dies on dpkg lock
        # EACCES. Check and error early with a concrete fix command
        # rather than letting the agent hit an obscure runtime
        # failure. build-rootfs.sh already chowns its output to
        # 100000; this catches the case where the tree was installed
        # before that change landed.
        tree_uid = path.stat().st_uid
        if tree_uid != 100000:
            raise RuntimeError(
                f"Rootfs tree {path} is owned by uid {tree_uid}, "
                f"expected 100000 (SafeYolo's sandbox-root in the "
                f"rootless uid map).\n"
                f"Runtime writes from inside the sandbox (apt-get "
                f"install etc.) would fail on permission denied.\n"
                f"Fix: sudo chown -R 100000:100000 {path}"
            )

        # Bind destinations must be part of the built tree.  A custom Linux
        # tree is deliberately owned by subordinate uid 100000, so the
        # unprivileged host launcher cannot create a missing directory at run
        # time.  guest/install-guest-common.sh and the default rootfs hook both
        # establish these targets before uid remapping.
        checks = [
            (path / relative, "directory")
            for relative in (
                "etc", "workspace", "safeyolo", "safeyolo-status", "home/agent",
            )
        ]
        checks.append((
            path / "usr/local/share/ca-certificates/safeyolo.crt", "file",
        ))
        direct_states = [
            _direct_rootfs_target_state(target, expected)
            for target, expected in checks
        ]
        inaccessible_paths = [
            target
            for (target, _expected), state in zip(checks, direct_states, strict=True)
            if state is None
        ]
        if inaccessible_paths:
            rendered = ", ".join(
                f"/{target.relative_to(path)}" for target in inaccessible_paths
            )
            raise RuntimeError(
                f"Rootfs tree {path} is not host-traversable at: {rendered}.\n"
                "The builder must leave the root and required target parents "
                "mode 0755 before remapping ownership."
            )
        missing_paths = [
            target
            for (target, _expected), state in zip(checks, direct_states, strict=True)
            if not state
        ]
        if missing_paths:
            missing_targets = [
                f"/{target.relative_to(path)}" for target in missing_paths
            ]
            rendered = ", ".join(missing_targets)
            raise RuntimeError(
                f"Rootfs tree {path} is missing required SafeYolo bind-mount "
                f"target(s): {rendered}.\n"
                f"Rebuild it with the current guest/install-guest-common.sh "
                f"helper."
            )
        return path

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
        ephemeral: bool = False,
    ) -> int:
        """Start a gVisor sandbox in an unprivileged user namespace.

        ephemeral=True selects gVisor's tmpfs-backed overlay
        (--overlay2=root:memory): writes to / discarded on stop.

        ephemeral=False (default) selects a per-agent file-backed
        overlay (--overlay2=root:dir=<path>): writes to / persist
        in a host-side directory across agent stop/run. Matches the
        macOS VZ semantics.

        The switch from EROFS-sourced rootfs to OCI root.path =
        unpacked-tree unblocked the dir= overlay medium (PR #12337
        skipped filestore creation for EROFS-sourced rootfs; tree-
        sourced has no such restriction).
        """
        with _profile_phase("start_sandbox: resolve runtime and validate rootfs"):
            runsc = _find_runsc()
            platform = _detect_runsc_platform()
            root = _runsc_root()

            agent_dir = get_agents_dir() / name
            cid = _container_id(name)
            agent_ip = fw_alloc.get("attribution_ip", "")

            # prepare_rootfs returns the actual directory gVisor should use
            # as OCI root.path — shared base tree, or a per-agent tree from
            # --rootfs-script. The older hardcoded `agent_dir / "rootfs"`
            # placeholder (empty dir) was only correct when gVisor got its
            # rootfs from the EROFS annotation, not from root.path.
            rootfs = self.prepare_rootfs(name)

            # Backfill the per-agent host-side /home/agent source for
            # agents created before the persistent-home feature. `agent
            # add` already runs this, but an existing agent created on an
            # older build won't have it until first run after upgrade.
            # Idempotent; matches the Darwin pattern at vm.py:start_vm.
            ensure_agent_persistent_dirs(name)

            # runsc inside the userns operates as subordinate uid 100000
            # on the host filesystem and needs rwx on its state dir.
            # Scope the grant tightly via ACL to that single uid rather
            # than widening the mode bits. setfacl ships in the same
            # `acl` package as getfacl, which we already depend on.
            try:
                subprocess.run(
                    ["setfacl", "-m", "u:100000:rwx", str(root)],
                    check=True, capture_output=True,
                )
            except FileNotFoundError as err:
                raise RuntimeError(
                    "setfacl not found. Install the `acl` package "
                    "(Debian/Ubuntu: `sudo apt-get install acl`)."
                ) from err
            except subprocess.CalledProcessError as err:
                raise RuntimeError(
                    f"setfacl failed on {root}: {err.stderr.decode(errors='replace')}"
                ) from err

        with _profile_phase("start_sandbox: clean state and create user namespace"):
            # Clean stale state from previous run. Create a temporary
            # userns if needed -- runsc state is owned by uid 100000.
            old_upid = _get_userns_pid(name)
            if old_upid:
                _run(_nsenter_cmd(old_upid) +
                     [runsc, "--root", root, "delete", "--force", cid],
                     check=False)
                _kill_userns(name)

            # Create user namespace -- we need the PID for the OCI
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

        with _profile_phase("start_sandbox: generate and write OCI config"):
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
                ephemeral=ephemeral,
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

        # Overlay medium. `--overlay2=root:<medium>` applies to both
        # rootfs and gofer-backed mounts uniformly — no medium clash
        # between them (which was the EROFS-era failure mode).
        #
        #   ephemeral=False (default) -> root:dir=<per-agent>
        #     Disk-backed overlay stored as a filestore file inside
        #     the supplied directory. Writes to /etc, /usr, /var
        #     persist across agent stop/run.
        #
        #   ephemeral=True -> root:memory
        #     Tmpfs-backed overlay; writes discarded on stop. For
        #     one-shot sandboxes.
        if ephemeral:
            overlay2_flag = "--overlay2=root:memory"
        else:
            overlay_dir = get_agents_dir() / name / "overlay"
            overlay_dir.mkdir(parents=True, exist_ok=True)
            overlay2_flag = f"--overlay2=root:dir={overlay_dir}"

        # Opt-in runsc debug logging: SAFEYOLO_RUNSC_DEBUG=1 in the
        # environment adds --debug --debug-log=/tmp/runsc-<cid>.log
        # to the create invocation. Off by default — the logs are
        # chatty and only matter when diagnosing a sandbox crash.
        if os.environ.get("SAFEYOLO_RUNSC_DEBUG") == "1":
            debug_flags = f"--debug --debug-log=/tmp/runsc-{cid}.log "
        else:
            debug_flags = ""

        experiment_flags = " ".join(_experiment_runsc_flags())
        if experiment_flags:
            experiment_flags += " "

        inner = (
            f"{setup} && "
            f"{runsc} {debug_flags}{experiment_flags}--root {root} {overlay2_flag} --host-uds=open --ignore-cgroups "
            f"--network=sandbox --platform={platform} "
            f"create --bundle {agent_dir} {cid} && "
            f"{runsc} --ignore-cgroups --root {root} "
            f"start {cid}"
        )

        cmd = _wrap_in_systemd_scope(
            _nsenter_cmd(upid) + ["bash", "-c", inner],
            name, memory_mb, cpus,
        )

        with _profile_phase("start_sandbox: runsc create and start"):
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

        with _profile_phase("start_sandbox: query state and record container PID"):
            # Get PID -- nsenter into userns for state query
            state_result = _run(
                _nsenter_cmd(upid) + [runsc, "--root", root, "state", cid],
                check=False,
            )
            pid = 0
            if state_result.returncode == 0:
                try:
                    pid = json.loads(state_result.stdout).get("pid", 0)
                except json.JSONDecodeError:
                    # runsc state returned non-JSON (shouldn't happen
                    # on a healthy runsc) -- leave pid=0 and move on.
                    pass

            pid_path = agent_dir / "container.pid"
            pid_path.write_text(str(pid))

        log.info("Container %s started (pid=%d, platform=%s, rootless=true)",
                 cid, pid, platform)
        return pid

    def stop_sandbox(self, name: str) -> None:
        """Stop a running gVisor sandbox."""
        _profile_enter("agent stop: resolve gVisor runtime and user namespace")
        cid = _container_id(name)
        agent_dir = get_agents_dir() / name
        runsc = _find_runsc()
        root = _runsc_root()

        upid = _get_userns_pid(name)

        # If the userns holder is dead, create a temporary one for
        # cleanup. The state dir is owned by uid 100000 -- we need
        # to be in a userns where we're that uid to access it.
        temp_userns = False
        if not upid:
            try:
                upid = _start_userns(name)
                temp_userns = True
            except RuntimeError:
                # Can't create userns -- best-effort cleanup without it
                upid = None

        prefix = _nsenter_cmd(upid) if upid else []

        _profile_enter("agent stop: query gVisor container state")
        status = _runsc_container_status(prefix, runsc, root, cid)
        has_state = status is not None
        is_running = status == "running"

        if is_running:
            _profile_enter("agent stop: SIGTERM grace period")
            _run(prefix + [runsc, "--root", root, "kill", cid, "SIGTERM"], check=False)
            if not _wait_for_runsc_stop(prefix, runsc, root, cid):
                _profile_enter("agent stop: force remaining gVisor processes")
                _run(
                    prefix
                    + [runsc, "--root", root, "kill", "--all", cid, "SIGKILL"],
                    check=False,
                )

        _profile_enter("agent stop: delete container state and sockets")
        if has_state:
            _run(prefix + [runsc, "--root", root, "delete", "--force", cid], check=False)
        else:
            # State query failed -- force delete anyway in case files exist
            _run(prefix + [runsc, "--root", root, "delete", "--force", cid], check=False)

        # Clean stale control socket from /tmp. gVisor creates it as
        # the userns root (uid 100000) so the operator can't delete it
        # directly -- use the userns prefix.
        sock_path = f"/tmp/runsc-{cid}.sock"
        _run(prefix + ["rm", "-f", sock_path], check=False)

        _kill_userns(name)
        if temp_userns:
            _kill_userns(name)

        pid_path = agent_dir / "container.pid"
        pid_path.unlink(missing_ok=True)

        _profile_enter("agent stop: remove attribution mapping")
        from ..vm import _update_agent_map  # noqa: PLC0415
        _update_agent_map(name, remove=True)

        log.info("Container %s stopped", cid)

    def exec_in_sandbox(self, name: str, command: str | None,  # DOC: README.md
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
            # -lc sources the login profile (mise shims on PATH). We also
            # explicitly source /etc/environment so HTTP_PROXY, SSL_CERT_FILE,
            # etc. reach the user's command -- under `runsc exec` there's
            # no PAM path that would otherwise load /etc/environment.
            wrapped = _wrap_runsc_command(command)
            cmd.extend(["/bin/bash", "-lc", wrapped])
        else:
            cmd.extend(["/bin/bash", "-l"])

        result = subprocess.run(cmd)
        return result.returncode

    def popen_in_sandbox(
        self,
        name: str,
        command: str,
        user: str = "agent",
    ) -> subprocess.Popen[str]:
        """Start a non-interactive command via runsc exec with pipes."""
        cid = _container_id(name)
        uid = "0:0" if user == "root" else "1000:1000"
        root = _runsc_root()

        upid = _get_userns_pid(name)
        prefix = _nsenter_cmd(upid) if upid else []

        wrapped = _wrap_runsc_command(command)
        cmd = prefix + [
            _find_runsc(), "--root", root, "exec",
            "--user", uid,
            "--cwd", "/workspace",
            cid,
            "/bin/bash", "-lc", wrapped,
        ]
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

    def popen_binary_in_sandbox(
        self,
        name: str,
        command: str,
        user: str = "agent",
    ) -> subprocess.Popen[bytes]:
        """Start a non-interactive command via runsc exec with binary pipes."""
        cid = _container_id(name)
        uid = "0:0" if user == "root" else "1000:1000"
        root = _runsc_root()

        upid = _get_userns_pid(name)
        prefix = _nsenter_cmd(upid) if upid else []

        wrapped = _wrap_runsc_command(command)
        cmd = prefix + [
            _find_runsc(), "--root", root, "exec",
            "--user", uid,
            "--cwd", "/workspace",
            cid,
            "/bin/bash", "-lc", wrapped,
        ]
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

    def popen_port_forward(
        self,
        name: str,
        guest_port: int,
        user: str = "agent",
    ) -> BinaryRelay:
        """Open one stream with gVisor's native connected-FD donation.

        Stream mode connects to an operator-owned UDS and passes that
        connected descriptor into the sentry. It does not bind a host TCP
        listener and does not start a process inside the sandbox.
        """
        del user  # Native port forwarding targets the container network stack.
        temporary = tempfile.TemporaryDirectory(prefix="safeyolo-port-forward-")
        stream_path = Path(temporary.name) / "relay.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(PORT_FORWARD_TIMEOUT_SECONDS)
        connection: socket.socket | None = None
        process: subprocess.Popen[bytes] | None = None
        try:
            listener.bind(str(stream_path))
            listener.listen(1)

            upid = _get_userns_pid(name)
            prefix = _nsenter_cmd(upid) if upid else []
            command = prefix + [
                _find_runsc(),
                "--root",
                _runsc_root(),
                "port-forward",
                "--stream",
                str(stream_path),
                _container_id(name),
                str(guest_port),
            ]
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            connection, _ = listener.accept()
            stdout, stderr = process.communicate(timeout=PORT_FORWARD_TIMEOUT_SECONDS)
            if process.returncode != 0:
                detail = (stderr or stdout).decode(errors="replace").strip()
                raise RuntimeError(
                    f"runsc port-forward exited {process.returncode}: "
                    f"{detail or '<no output>'}"
                )
            return _SocketRelay(connection)
        except Exception:
            if connection is not None:
                connection.close()
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            raise
        finally:
            listener.close()
            temporary.cleanup()

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
        """Delete the agent's on-disk directory.

        Custom rootfs trees and files created by sandbox root are owned by
        host subordinate uid 100000. If ordinary deletion encounters one,
        retry from a short-lived user namespace with the runtime's normal uid
        map. Namespace uid 0 then owns those files, without host sudo or any
        change to their containment-preserving ownership.
        """
        agent_dir = get_agents_dir() / name
        if not agent_dir.exists():
            return
        try:
            shutil.rmtree(agent_dir)
            return
        except PermissionError:
            # rmtree may already have removed all operator-owned siblings.
            # The exact agent path remains fixed as an argv element; rm does
            # not traverse symlink targets during recursive deletion.
            if not agent_dir.exists():
                return

        upid = _start_userns(name, persist_pid=False)
        try:
            result = _run(
                _nsenter_cmd(upid) + [
                    "setpriv", "--reuid=0", "--regid=0", "--clear-groups",
                    "rm", "-rf", "--", str(agent_dir),
                ],
                check=False,
            )
            if result.returncode != 0 or agent_dir.exists():
                detail = (result.stderr or "").strip()
                suffix = f": {detail}" if detail else ""
                raise RuntimeError(
                    f"Could not remove subordinate-owned agent directory "
                    f"{agent_dir}{suffix}"
                )
        finally:
            try:
                os.kill(upid, 9)
            except (ProcessLookupError, OSError):
                # The one-shot holder may already have exited after cleanup.
                pass

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
        ephemeral: bool = False,
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
            "MISE_DATA_DIR=/home/agent/.mise",
            "MISE_CONFIG_DIR=/home/agent/.mise",
            "MISE_CACHE_DIR=/home/agent/.mise/cache",
            "PATH=/home/agent/.mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
        proxy_mountpoint = config_share / "proxy"
        proxy_mountpoint.mkdir(parents=True, exist_ok=True)
        workspace_options = ["rbind", "rw", "nosuid", "nodev"]
        workspace_dcache = _workspace_dcache_option()
        if workspace_dcache is not None:
            workspace_options.append(workspace_dcache)

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
             "options": workspace_options},
            {"destination": "/safeyolo", "type": "bind",  # DOC: docs/security-verification.md
             "source": str(config_share),
             "options": ["rbind", "ro"]},
            {"destination": "/safeyolo-status", "type": "bind",
             "source": str(self._status_dir(name)),
             "options": ["rbind", "rw"]},
            # Persistent /home/agent. Without this, writes to
            # /home/agent land in gVisor's memory-backed rootfs overlay
            # and vanish on sandbox stop -- mise installs, shell
            # history, .claude.json, host-script-staged auth. The host
            # source is per-agent so cross-agent isolation is preserved
            # structurally (each agent's own dir, no sharing).
            # guest-init-static.sh seeds /etc/skel on first boot when
            # this dir is empty; subsequent boots skip the seed.
            {"destination": "/home/agent", "type": "bind",
             "source": str(get_agent_home_dir(name)),
             "options": ["rbind", "rw", "nosuid", "nodev"]},
        ]

        # Mount the private per-agent directory, not the socket inode.
        # Mitmproxy can replace proxy.sock across restarts and a running
        # sandbox resolves the new inode through this stable mount.
        from ..sockets import directory_for as _proxy_dir_for  # noqa: PLC0415
        proxy_dir = _proxy_dir_for(name, fw_alloc.get("attribution_ip", ""))
        if proxy_dir.exists():
            mounts.append({
                "destination": "/safeyolo/proxy",
                "type": "bind",
                "source": str(proxy_dir),
                "options": ["rbind", "ro", "nosuid", "nodev"],
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

        # Package cache bind mounts (Linux bridge). gVisor's dir=
        # overlay is silently ignored for tree root.path, so writes to
        # /var/cache/apt etc. land in the memory overlay and vanish on
        # stop. Each path in <agent_dir>/cache-paths.txt (seeded from
        # the rootfs-script's SAFEYOLO_ROOTFS_OUT_CACHE_PATHS output or
        # the default-base's share/cache-paths.txt) is bound to a
        # per-agent host dir so `apt install` hits a warm cache after
        # restart. Per-agent (not shared) for isolation — a prompt-
        # injected agent can't corrupt another's cache.
        from ..vm import get_agent_cache_dir, read_agent_cache_paths  # noqa: PLC0415
        for in_rootfs_path in read_agent_cache_paths(name):
            host_cache_dir = get_agent_cache_dir(name, in_rootfs_path)
            host_cache_dir.mkdir(parents=True, exist_ok=True)
            # The runner may have a restrictive umask. Apt drops privileges to
            # `_apt`, which needs to traverse this mount root before using its
            # own partial/ directory. The parent agent directory remains
            # private and caches contain only public package artifacts.
            host_cache_dir.chmod(0o755)
            mounts.append({
                "destination": in_rootfs_path,
                "type": "bind",
                "source": str(host_cache_dir),
                "options": ["rbind", "rw"],
            })

        # Extra shares (host config dirs)
        if extra_shares:
            agent_home = get_agent_home_dir(name)
            for host_path, guest_path, read_only in extra_shares:
                try:
                    rel = Path(guest_path).relative_to("/home/agent")
                    # /home/agent is an OCI bind to the host-side agent
                    # home dir (possibly empty on first boot). gVisor
                    # requires nested bind destinations to pre-exist on
                    # the host; create the mount point here so runsc
                    # finds it when consuming the spec.
                    (agent_home / rel).mkdir(parents=True, exist_ok=True)
                except ValueError:
                    pass  # Only nested /home/agent shares need host mount points.
                options = [
                    "rbind",
                    "ro" if read_only else "rw",
                    "nosuid",
                    "nodev",
                ]
                if not read_only:
                    # Writable operator shares have the same guest-edit/host-
                    # execute contract as /workspace. Release gVisor's idle
                    # writable host FD immediately after the guest closes it.
                    options.append("dcache=0")
                mounts.append({
                    "destination": guest_path,
                    "type": "bind",
                    "source": os.path.abspath(host_path),
                    "options": options,
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
        # CAP_SYS_PTRACE lets guest-root (via `sudo` or
        # `setpriv --reuid=0`) bypass Linux YAMA's ptrace-relationship
        # check on non-parent same-uid attach. Ordinary agent uid 1000
        # does NOT hold this cap; agents needing it opt in through the
        # existing setpriv path. Blast radius: this sandbox only --
        # gVisor's sentry never gives capabilities to the host kernel.
        root_caps = [  # DOC: docs/security-verification.md, SECURITY.md
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT",
            "CAP_NET_ADMIN",
            "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP",
            "CAP_SYS_PTRACE",
        ]
        # Rootfs is the directory tree at OCI root.path — gVisor reads
        # the tree directly. No dev.gvisor.spec.rootfs.source /
        # rootfs.type annotations needed (those only apply when the
        # rootfs comes from an image file like EROFS).
        #
        # Overlay medium is selected by the --overlay2 flag on the
        # runsc command line below — `root:dir=<path>` or `root:memory`
        # depending on the ephemeral flag. Annotation is intentionally
        # unset: with tree-based rootfs + --overlay2 flag, gVisor's
        # createGoferFilestore path has what it needs (host directory
        # available for the filestore file), so the PR #12337
        # "skip filestore for EROFS" restriction no longer applies.
        annotations: dict[str, str] = {}

        # /safeyolo-status is a host bind-mount (see mounts list above) —
        # writing the boot log there means it survives sandbox exit and
        # lives at ~/.safeyolo/agents/<name>/status/boot.log on the host.
        # Without this, the log lands in gVisor's memory overlay and
        # vanishes the moment guest-init fails, which was exactly how
        # pre-boot failures became invisible.
        #
        # Extracted to a named variable rather than an implicitly-
        # concatenated sequence of string literals inside the args list —
        # the latter reads as ambiguous (Python's "" "" joining can hide a
        # missing comma bug) and CodeQL flags it accordingly.
        boot_cmd = (
            "mkdir -p /var/log /safeyolo-status && "
            ": > /safeyolo-status/boot.log && "
            "ln -sf /safeyolo-status/boot.log /var/log/safeyolo-boot.log && "
            "exec /safeyolo/guest-init >> /safeyolo-status/boot.log 2>&1"
        )

        return {
            "ociVersion": "1.0.0",
            # readonly=false, not true. Under gVisor, readonly=true on a
            # tree root.path silently disables overlay writes to the
            # tree's own paths — boot_cmd's
            # `ln -sf /safeyolo-status/boot.log /var/log/safeyolo-boot.log`
            # fails with EROFS because /var/log is in the tree and the
            # runsc --overlay2 flag is ignored for write routing when
            # the root is marked readonly. Behaviour confirmed on devstack
            # (linux-amd64, gVisor release-20260413.0) with runsc
            # --debug logs: task 3 (ln -sf) exits non-zero, task 1
            # (bash) exits, boot.log stays 0 bytes. Flipping to false
            # restores the overlay write path; guest-init proceeds
            # normally.
            #
            # Cross-agent contamination is still blocked: (1) tree files
            # are real-root-owned and the gofer runs as a subordinate
            # uid (can't write the lower); (2) each agent has its own
            # overlay upper so writes never escape to the shared tree.
            "root": {"path": str(rootfs_path), "readonly": False},
            "hostname": f"safeyolo-{name}",
            "annotations": annotations,
            "process": {
                "terminal": False,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/bash", "-c", boot_cmd],
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
