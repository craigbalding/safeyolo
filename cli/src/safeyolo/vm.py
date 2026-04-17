"""MicroVM lifecycle management for SafeYolo.

Replaces Docker container management with Apple Virtualization.framework
microVMs via the safeyolo-vm Swift helper binary.
"""

import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .config import (
    get_agent_map_path,
    get_agents_dir,
    get_config_dir,
    get_share_dir,
    get_ssh_key_path,
)

log = logging.getLogger("safeyolo.vm")

VM_HELPER_NAME = "safeyolo-vm"


class VMError(Exception):
    """VM operation failed."""
    pass


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def find_vm_helper() -> Path:
    """Find the safeyolo-vm binary."""
    # Dev override: SAFEYOLO_VM_HELPER lets you point a single agent run
    # at a test binary without replacing ~/.safeyolo/bin/safeyolo-vm.
    # Essential for testing VM helper changes without disrupting running agents.
    override = os.environ.get("SAFEYOLO_VM_HELPER")
    if override:
        override_path = Path(override)
        if override_path.exists() and os.access(override_path, os.X_OK):
            return override_path

    # Check ~/.safeyolo/bin/ first
    local = get_config_dir() / "bin" / VM_HELPER_NAME
    if local.exists() and os.access(local, os.X_OK):
        return local

    # Check PATH
    result = shutil.which(VM_HELPER_NAME)
    if result:
        return Path(result)

    # Check repo layout (for development)
    repo_bin = Path(__file__).resolve().parents[3] / "vm" / ".build" / "release" / VM_HELPER_NAME
    if repo_bin.exists() and os.access(repo_bin, os.X_OK):
        return repo_bin

    raise VMError(
        f"Cannot find {VM_HELPER_NAME}. Install with:\n"
        f"  cd vm && make install"
    )


def get_kernel_path() -> Path:
    return get_share_dir() / "Image"


def get_initrd_path() -> Path:
    return get_share_dir() / "initramfs.cpio.gz"


def get_base_rootfs_path() -> Path:
    return get_share_dir() / "rootfs-base.ext4"


def get_agent_rootfs_path(name: str) -> Path:
    return get_agents_dir() / name / "rootfs.ext4"


def get_agent_pid_path(name: str) -> Path:
    return get_agents_dir() / name / "vm.pid"


def get_agent_config_share_dir(name: str) -> Path:
    return get_agents_dir() / name / "config-share"


# ---------------------------------------------------------------------------
# Rootfs management
# ---------------------------------------------------------------------------

def create_agent_rootfs(name: str) -> Path:
    """Clone the base rootfs for a new agent.

    Uses cp (APFS reflink on macOS for fast CoW copies).
    """
    base = get_base_rootfs_path()
    if not base.exists():
        raise VMError(
            f"Base rootfs not found at {base}\n"
            f"Build guest images first: cd guest && ./build-all.sh"
        )

    agent_dir = get_agents_dir() / name
    agent_dir.mkdir(parents=True, exist_ok=True)
    dest = agent_dir / "rootfs.ext4"

    if dest.exists():
        return dest  # Already created

    log.info("Cloning base rootfs for agent '%s'...", name)
    # Use cp -c for APFS clone (instant, CoW) with fallback to regular copy
    result = subprocess.run(
        ["cp", "-c", str(base), str(dest)],
        capture_output=True,
    )
    if result.returncode != 0:
        # Fallback: regular copy (non-APFS filesystems)
        shutil.copy2(str(base), str(dest))

    return dest


# ---------------------------------------------------------------------------
# Config share (VirtioFS directory mounted read-only in the guest)
# ---------------------------------------------------------------------------

def prepare_config_share(
    name: str,
    workspace_path: str,
    agent_binary: str = "",
    mise_package: str = "",
    agent_args: str = "",
    extra_env: dict[str, str] | None = None,
    proxy_port: int = 8080,
    host_mounts: list[tuple[str, str, bool]] | None = None,
    host_config_files: list[str] | None = None,
    instructions_content: str = "",
    instructions_path: str = "",
    auto_args: str = "",
    gateway_ip: str = "192.168.65.1",
    guest_ip: str = "192.168.65.2",
    pre_write_per_run_go: bool = True,
    debug_mode: bool = False,
) -> Path:
    """Create the config share directory for a VM.

    The guest init script reads files from this directory to configure
    proxy settings, CA trust, SSH access, and agent environment.
    """
    config_dir = get_config_dir()
    share_dir = get_agent_config_share_dir(name)
    share_dir.mkdir(parents=True, exist_ok=True)

    # Guest init scripts — served from config share, not baked into rootfs.
    # Changes here take effect on next agent run without rootfs rebuild.
    # Three scripts split the boot into a snapshottable static phase and
    # a per-run phase; the orchestrator gates between them on per-run-go.
    #
    # guest-proxy-forwarder.py bridges the agent's HTTP_PROXY (localhost
    # TCP) to the host-side proxy (UDS on Linux / vsock on macOS). Started
    # by guest-init before the agent.
    for src_name, dst_name in [
        ("guest-init.sh", "guest-init"),
        ("guest-init-static.sh", "guest-init-static"),
        ("guest-init-per-run.sh", "guest-init-per-run"),
        ("guest-proxy-forwarder.py", "guest-proxy-forwarder"),
    ]:
        src = Path(__file__).parent / src_name
        dst = share_dir / dst_name
        shutil.copy2(str(src), str(dst))
        dst.chmod(0o755)

    # Pre-write the per-run gate so the orchestrator falls straight through
    # to per-run after static. CAPTURE / RESTORE callers disable this and
    # write per-run-go themselves at the right moment (after snapshot
    # completes, or after restore succeeds). Without a pre-write or an
    # explicit write from the CLI, the guest would wait 30s before
    # continuing on every cold boot.
    per_run_go = share_dir / "per-run-go"
    if pre_write_per_run_go:
        per_run_go.write_text("")
    else:
        # CAPTURE mode needs a clean slate — a stale per-run-go from an
        # earlier passthrough run would let the guest skip past the
        # snapshot point before we get a chance to SIGUSR1.
        per_run_go.unlink(missing_ok=True)
    # Ensure no stale per-boot markers from a prior run mask progress —
    # the guest writes these fresh on every boot. The CLI polls for
    # per-run-started specifically as a definitive "restore succeeded"
    # signal; a stale copy would make a failed restore look successful.
    for marker in ("static-init-done", "per-run-started"):
        (share_dir / marker).unlink(missing_ok=True)

    # Debug-mode marker — presence enables per-iteration guest tracing.
    # Checked by guest-init orchestrator (which runs before agent.env is
    # sourced, so a file marker is cleaner than an env var).
    debug_marker = share_dir / "debug-mode"
    if debug_mode:
        debug_marker.write_text("")
    else:
        debug_marker.unlink(missing_ok=True)

    # vsock-term binary — cross-compiled, served from config share
    vsock_term_src = config_dir / "bin" / "vsock-term"
    if vsock_term_src.exists():
        shutil.copy2(str(vsock_term_src), str(share_dir / "vsock-term"))
        (share_dir / "vsock-term").chmod(0o755)

    # Proxy environment variables.
    # gateway_ip comes from the platform's setup_networking:
    #   - Linux (new arch): 127.0.0.1 — guest-proxy-forwarder listens here
    #     and relays to the host via bind-mounted UDS.
    #   - macOS (feth): the host veth IP; traffic flows through feth-bridge + pf.
    proxy_url = f"http://{gateway_ip}:{proxy_port}"
    proxy_env = (
        f'export HTTP_PROXY="{proxy_url}"\n'
        f'export HTTPS_PROXY="{proxy_url}"\n'
        f'export http_proxy="{proxy_url}"\n'
        f'export https_proxy="{proxy_url}"\n'
        'export NO_PROXY="localhost,127.0.0.1"\n'
        'export no_proxy="localhost,127.0.0.1"\n'
        'export SSL_CERT_FILE="/usr/local/share/ca-certificates/safeyolo.crt"\n'
        'export REQUESTS_CA_BUNDLE="/usr/local/share/ca-certificates/safeyolo.crt"\n'
        'export NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/safeyolo.crt"\n'
        'export NO_UPDATE_NOTIFIER=1\n'
        'export npm_config_update_notifier=false\n'
        'export HOME=/home/agent\n'
    )
    (share_dir / "proxy.env").write_text(proxy_env)

    # Agent environment
    agent_env_lines = []
    if agent_binary:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_BINARY="{agent_binary}"')
        agent_env_lines.append(f'export SAFEYOLO_AGENT_CMD="{agent_binary}"')
    if mise_package:
        agent_env_lines.append(f'export SAFEYOLO_MISE_PACKAGE="{mise_package}"')
    if agent_args:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_ARGS="{agent_args}"')
    if instructions_path:
        agent_env_lines.append(f'export SAFEYOLO_INSTRUCTIONS_PATH="{instructions_path}"')
    if auto_args:
        agent_env_lines.append(f'export SAFEYOLO_AUTO_ARGS="{auto_args}"')
    if extra_env:
        for k, v in extra_env.items():
            agent_env_lines.append(f'export {k}="{v}"')
    (share_dir / "agent.env").write_text("\n".join(agent_env_lines) + "\n")

    # Instructions file (e.g., CLAUDE.md for Claude Code)
    if instructions_content and instructions_path:
        (share_dir / "instructions.md").write_text(instructions_content)

    # Network config for static IP (used by initramfs init)
    (share_dir / "network.env").write_text(
        f"GUEST_IP={guest_ip}\n"
        f"GATEWAY_IP={gateway_ip}\n"
        f"NETMASK=255.255.255.0\n"
    )

    # Agent name → guest hostname. Read by guest-init-static which calls
    # `hostname <name>` and writes /etc/hostname. Agents in the Docker
    # era inherited container name as hostname automatically; the
    # VM-based stack needs to set it explicitly.
    (share_dir / "agent-name").write_text(name)

    # CA certificate
    ca_cert = config_dir / "certs" / "mitmproxy-ca-cert.pem"
    if ca_cert.exists():
        shutil.copy2(str(ca_cert), str(share_dir / "mitmproxy-ca-cert.pem"))

    # SSH authorized keys
    _ensure_ssh_key()
    pub_key = get_ssh_key_path().with_suffix(".pub")
    if pub_key.exists():
        shutil.copy2(str(pub_key), str(share_dir / "authorized_keys"))

    # Agent token (for agent API access)
    agent_token = config_dir / "data" / "agent_token"
    if agent_token.exists():
        shutil.copy2(str(agent_token), str(share_dir / "agent_token"))

    # Host config mount manifest — tells the guest init which VirtioFS tags
    # to mount and where. Format: one line per mount, "tag:guest_path"
    if host_mounts:
        lines = []
        for host_path, tag, _read_only in host_mounts:
            # Derive guest path: ~/.claude → /home/agent/.claude
            host_p = Path(host_path)
            home = Path.home()
            try:
                rel = host_p.relative_to(home)
                guest_path = f"/home/agent/{rel}"
            except ValueError:
                guest_path = f"/mnt/{tag}"
            lines.append(f"{tag}:{guest_path}")
        (share_dir / "host-mounts").write_text("\n".join(lines) + "\n")

    # Host config files — copied into config share (not VirtioFS mounted,
    # since mounting the parent dir could expose $HOME)
    if host_config_files:
        files_dir = share_dir / "host-files"
        files_dir.mkdir(exist_ok=True)
        manifest_lines = []
        home = Path.home()
        for file_name in host_config_files:
            src = home / file_name
            if src.exists() and src.is_file():
                dest = files_dir / file_name.replace("/", "__")
                shutil.copy2(str(src), str(dest))
                manifest_lines.append(f"{dest.name}:/home/agent/{file_name}")
        if manifest_lines:
            (share_dir / "host-files-manifest").write_text("\n".join(manifest_lines) + "\n")

    return share_dir


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------

def _ensure_ssh_key() -> None:
    """Generate SSH key pair for VM access if not present."""
    key_path = get_ssh_key_path()
    if key_path.exists():
        return

    key_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"],
        check=True,
    )
    key_path.chmod(0o600)


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

def start_vm(
    name: str,
    workspace_path: str,
    cpus: int = 4,
    memory_mb: int = 4096,
    extra_shares: list[tuple[str, str, bool]] | None = None,
    feth_vm: str = "",
    background: bool = False,
    snapshot_capture_path: Path | None = None,
    restore_from_path: Path | None = None,
) -> subprocess.Popen:
    """Start a VM and return the Popen handle.

    If background=True, serial console goes to a log file instead of
    stdin/stdout (for SSH-primary mode).

    snapshot_capture_path: if set, pass --snapshot-on-signal to the
        helper. The CLI sends SIGUSR1 once the guest's static phase has
        completed; the helper pauses the VM, saves memory state to this
        path, clones the rootfs beside it, and resumes.

    restore_from_path: if set, pass --restore-from to the helper and
        override --rootfs to point at the paired APFS clone. The helper
        restores VM memory from this path instead of cold-booting.
        Mutually exclusive with snapshot_capture_path.
    """
    if snapshot_capture_path and restore_from_path:
        raise VMError("snapshot_capture_path and restore_from_path are mutually exclusive")

    helper = find_vm_helper()
    rootfs = get_agent_rootfs_path(name)
    if not rootfs.exists():
        raise VMError(f"Agent rootfs not found: {rootfs}\nRun 'safeyolo agent add' first.")

    kernel = get_kernel_path()
    initrd = get_initrd_path()
    for path, label in [(kernel, "kernel"), (initrd, "initramfs")]:
        if not path.exists():
            raise VMError(f"{label} not found at {path}\nBuild guest images first.")

    # On restore, VZ requires the disk image to match byte-for-byte the
    # state it had at save time. snapshot.bin.rootfs is that pristine
    # clone — but during a restore session the guest writes to its
    # rootfs, and those writes would corrupt the pristine clone if we
    # passed it directly as --rootfs. Next restore would then hit EXT4
    # journal replay / inode bitmap inconsistencies against the memory
    # image's expected state.
    #
    # Solution: clone the pristine clone to a per-run working copy and
    # use that as --rootfs. APFS clonefile makes this ~instant (tens of
    # ms regardless of logical size). The working copy is disposable —
    # next restore starts from the pristine clone again.
    if restore_from_path is not None:
        pristine = Path(f"{restore_from_path}.rootfs")
        if not pristine.exists():
            raise VMError(
                f"Snapshot rootfs clone missing: {pristine}\n"
                f"Restore cannot proceed without the paired clone."
            )
        working = Path(f"{restore_from_path}.run")
        # Discard any residue from a previous restore session.
        working.unlink(missing_ok=True)
        # APFS clone (cp -c). Falls back to a deep copy on non-APFS.
        cp_result = subprocess.run(
            ["cp", "-c", str(pristine), str(working)],
            capture_output=True,
        )
        if cp_result.returncode != 0:
            try:
                shutil.copy2(str(pristine), str(working))
            except Exception as err:
                raise VMError(
                    f"Failed to prepare restore working copy at {working}: {err}"
                ) from err
        rootfs = working

    config_share = get_agent_config_share_dir(name)

    cmd = [
        str(helper), "run",
        "--kernel", str(kernel),
        "--initrd", str(initrd),
        "--rootfs", str(rootfs),
        "--cpus", str(cpus),
        "--memory", str(memory_mb),
        "--share", f"{workspace_path}:workspace:rw",
        "--share", f"{config_share}:config:rw",
        "--cmdline", "console=hvc0 root=/dev/vda rw quiet",
    ]

    if snapshot_capture_path is not None:
        cmd.extend(["--snapshot-on-signal", str(snapshot_capture_path)])
    if restore_from_path is not None:
        cmd.extend(["--restore-from", str(restore_from_path)])

    # feth-based networking
    if feth_vm:
        feth_bridge = get_config_dir() / "bin" / "feth-bridge"
        cmd.extend(["--feth", feth_vm])
        if feth_bridge.exists():
            cmd.extend(["--feth-bridge", str(feth_bridge)])

    # Additional shares
    if extra_shares:
        for host_path, tag, read_only in extra_shares:
            mode = "ro" if read_only else "rw"
            cmd.extend(["--share", f"{host_path}:{tag}:{mode}"])

    if background:
        cmd.append("--no-terminal")
        serial_log = get_agents_dir() / name / "serial.log"
        # `with` closes our parent-side handle on block exit; Popen has
        # already duplicated the fd into the child process, which
        # continues writing independently. Avoids the parent leaking an
        # fd for the lifetime of the VM.
        with open(serial_log, "w") as serial_fh:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=serial_fh,
                stderr=serial_fh,
            )
    else:
        proc = subprocess.Popen(cmd)

    # Write PID file
    pid_path = get_agent_pid_path(name)
    pid_path.write_text(str(proc.pid))

    return proc


def stop_vm(name: str) -> None:
    """Stop a running VM, its feth-bridge, and clean up network state."""
    pid_path = get_agent_pid_path(name)
    if not pid_path.exists():
        _cleanup_feth_bridge(name)
        _update_agent_map(name, remove=True)
        return

    pid = int(pid_path.read_text().strip())

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_path.unlink(missing_ok=True)
        _cleanup_feth_bridge(name)
        _update_agent_map(name, remove=True)
        return

    # Wait up to 10 seconds (VM needs time for graceful + force stop)
    for _ in range(100):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            break
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            # Process died between the SIGTERM wait loop and SIGKILL — fine.
            pass

    pid_path.unlink(missing_ok=True)
    _cleanup_feth_bridge(name)
    _update_agent_map(name, remove=True)


def _cleanup_feth_bridge(name: str) -> None:
    """Kill any stale feth-bridge processes and tear down feth interfaces."""
    # Kill feth-bridge processes associated with this agent's feth interface
    agents_dir = get_agents_dir()
    existing = sorted(d.name for d in agents_dir.iterdir() if d.is_dir()) if agents_dir.exists() else []
    agent_index = existing.index(name) if name in existing else -1

    # Kill any feth-bridge process on this agent's feth interface
    if agent_index >= 0:
        from .firewall import allocate_subnet
        feth_vm = allocate_subnet(agent_index)["feth_vm"]
        try:
            result = subprocess.run(
                ["pgrep", "-f", f"feth-bridge.*{feth_vm}"],
                capture_output=True, text=True,
            )
            for pid_str in result.stdout.strip().splitlines():
                try:
                    os.kill(int(pid_str), signal.SIGTERM)
                except (ProcessLookupError, ValueError):
                    # Process exited between pgrep and kill, or pgrep emitted
                    # a non-integer line — skip it and move on.
                    pass
        except subprocess.SubprocessError:
            # pgrep missing or errored — nothing to clean up from our side.
            pass

        # Tear down feth interfaces
        try:
            from .firewall import teardown_feth
            teardown_feth(agent_index)
        except Exception:
            # Best-effort: feth interfaces may already be gone, or ifconfig
            # may refuse. Not worth aborting the rest of cleanup.
            pass

    # Also kill any orphaned feth-bridge processes
    try:
        result = subprocess.run(
            ["pgrep", "-f", "feth-bridge"],
            capture_output=True, text=True,
        )
        for pid_str in result.stdout.strip().splitlines():
            try:
                pid = int(pid_str)
                # Check if the parent safeyolo-vm is still alive
                ppid_result = subprocess.run(
                    ["ps", "-o", "ppid=", "-p", str(pid)],
                    capture_output=True, text=True,
                )
                ppid = int(ppid_result.stdout.strip()) if ppid_result.stdout.strip() else 0
                if ppid <= 1:  # Orphaned (parent is init/launchd)
                    os.kill(pid, signal.SIGTERM)
                    log.info("Killed orphaned feth-bridge (pid=%d)", pid)
            except (ProcessLookupError, ValueError):
                # Raced with process exit, or ps emitted a non-integer — skip.
                pass
    except subprocess.SubprocessError:
        # pgrep missing or errored — no orphan cleanup this pass.
        pass


def is_vm_running(name: str) -> bool:
    """Check if a VM process is alive (and not a zombie)."""
    pid_path = get_agent_pid_path(name)
    if not pid_path.exists():
        return False

    pid = int(pid_path.read_text().strip())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pid_path.unlink(missing_ok=True)
        return False

    # os.kill(pid, 0) also succeeds for zombies — a Popen whose child has
    # exited but hasn't been waited on. Ask ps for the state letter; 'Z'
    # means zombie, which we treat as not running.
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            capture_output=True, text=True, timeout=2,
        )
        if result.stdout.strip().startswith("Z"):
            pid_path.unlink(missing_ok=True)
            return False
    except (subprocess.SubprocessError, OSError):
        # ps unavailable or errored — can't distinguish zombie from live.
        # os.kill already said the pid exists, so fall through to "running".
        pass

    return True


def get_vm_ip(name: str, timeout: int = 30) -> str | None:
    """Get the VM's IP address by polling the config share.

    The guest init writes its IP to /safeyolo/vm-ip (which is the
    config share VirtioFS mount).
    """
    ip_file = get_agent_config_share_dir(name) / "vm-ip"

    for _ in range(timeout * 2):  # Check every 0.5s
        if ip_file.exists():
            ip = ip_file.read_text().strip()
            if ip:
                return ip
        time.sleep(0.5)

    return None


def wait_for_ssh(name: str, timeout: int = 30) -> bool:
    """Wait for SSH to become available on the VM."""
    ip = get_vm_ip(name, timeout=timeout)
    if not ip:
        return False

    key_path = get_ssh_key_path()
    deadline = time.time() + timeout

    while time.time() < deadline:
        result = subprocess.run(
            [
                "ssh",
                "-i", str(key_path),
                "-p", "22",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=2",
                "-o", "BatchMode=yes",
                f"agent@{ip}",
                "true",
            ],
            capture_output=True,
        )
        if result.returncode == 0:
            return True
        time.sleep(1)

    return False


def ssh_into_vm(ip: str, command: str = "", user: str = "agent") -> int:
    """SSH into a VM. Returns the exit code."""
    key_path = get_ssh_key_path()
    cmd = [
        "ssh",
        "-i", str(key_path),
        "-p", "22",  # Explicit port to override ~/.ssh/config
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-t", "-t",  # Force PTY allocation
        f"{user}@{ip}",
    ]
    if command:
        cmd.append(command)
    result = subprocess.run(cmd)
    return result.returncode


def ssh_exec(name: str, command: str, user: str = "agent", timeout: int = 60) -> int:
    """Execute a command in a VM via SSH. Waits for SSH readiness first.

    Returns the command's exit code.
    """
    if not wait_for_ssh(name, timeout=timeout):
        raise VMError(f"SSH not available on VM '{name}' after {timeout}s")
    ip = get_vm_ip(name)
    return ssh_into_vm(ip, command=command, user=user)


# ---------------------------------------------------------------------------
# Agent map (for service_discovery addon)
# ---------------------------------------------------------------------------

def _update_agent_map(
    name: str,
    ip: str | None = None,
    socket: str | None = None,
    remove: bool = False,
) -> None:
    """Update the agent-IP map file.

    Read by two consumers:
      - addons/service_discovery.py (in mitmproxy) — uses `ip` to map
        request source IPs back to agent names for audit/policy/rate-limit.
      - safeyolo.proxy_bridge (on Linux) — uses `socket` to create a
        per-agent listener, and `ip` as the upstream TCP source address
        to stamp the agent's identity on flows to mitmproxy.
    """
    map_path = get_agent_map_path()
    map_path.parent.mkdir(parents=True, exist_ok=True)

    agent_map: dict = {}
    if map_path.exists():
        try:
            agent_map = json.loads(map_path.read_text())
        except (json.JSONDecodeError, OSError):
            agent_map = {}

    if remove:
        agent_map.pop(name, None)
    elif ip:
        entry = {
            "ip": ip,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if socket:
            entry["socket"] = socket
        agent_map[name] = entry

    map_path.write_text(json.dumps(agent_map, indent=2) + "\n")


def register_vm_ip(name: str) -> str | None:
    """Wait for VM IP and register it in the agent map."""
    ip = get_vm_ip(name)
    if ip:
        _update_agent_map(name, ip=ip)
    return ip


# ---------------------------------------------------------------------------
# Guest image checks
# ---------------------------------------------------------------------------

def check_guest_images() -> bool:
    """Check if required guest image artifacts exist.

    On macOS (Virtualization.framework) all three are required: kernel,
    initramfs, and rootfs. On Linux (gVisor) only the rootfs is needed —
    gVisor provides its own kernel.
    """
    if not get_base_rootfs_path().exists():
        return False
    if platform.system() == "Darwin":
        return get_kernel_path().exists() and get_initrd_path().exists()
    return True


def guest_image_status() -> dict[str, bool]:
    """Return existence status of each guest image artifact."""
    return {
        "kernel": get_kernel_path().exists(),
        "initramfs": get_initrd_path().exists(),
        "rootfs": get_base_rootfs_path().exists(),
    }
