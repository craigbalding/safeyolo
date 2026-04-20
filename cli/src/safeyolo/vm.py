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


def get_agent_status_dir(name: str) -> Path:
    """Writable share for guest→host status signals.

    Separate from the config share so the config share can be mounted
    read-only from the start.
    """
    d = get_agents_dir() / name / "status"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_agent_home_dir(name: str) -> Path:
    """Host-side backing for /home/agent inside the guest.

    Bind-mounted over the rootfs /home/agent via VirtioFS so writes
    survive the snapshot/restore dance on macOS (where restore clones
    a pristine rootfs image, wiping any in-rootfs writes) and the
    ephemeral memory overlay on Linux gVisor. MISE_DATA_DIR points at
    $HOME/.mise (set in /etc/profile.d/mise.sh and vsock-term), so
    mise installs land here too — first-run installs persist and the
    install block in guest-init-static is a no-op thereafter.
    """
    return get_agents_dir() / name / "home"


def ensure_agent_persistent_dirs(name: str) -> None:
    """Create per-agent host dirs used as persistent bind-mount sources.

    Idempotent so `agent add` and `agent run` can both call it without
    care — backfills agents created before the persistent-home design.
    """
    d = get_agent_home_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)


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
    agent_args: str = "",
    extra_env: dict[str, str] | None = None,
    proxy_port: int = 8080,
    host_mounts: list[tuple[str, str, bool]] | None = None,
    gateway_ip: str = "127.0.0.1",
    guest_ip: str = "127.0.0.1",
    attribution_ip: str = "",
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
        ("guest-shell-bridge.py", "guest-shell-bridge"),
        ("guest-diag.py", "guest-diag"),
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
    # the guest writes these fresh on every boot to the status share.
    # The CLI polls for per-run-started specifically as a definitive
    # "restore succeeded" signal; a stale copy would make a failed
    # restore look successful.
    status_dir = get_agent_status_dir(name)
    for marker in ("static-init-done", "per-run-started", "vm-status", "vm-ip"):
        (status_dir / marker).unlink(missing_ok=True)

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

    # Proxy environment variables. proxy_port is 8080 — the fixed port
    # where guest-proxy-forwarder listens inside the sandbox. The host
    # bridge (UDS on Linux, vsock on macOS) decouples it from whatever
    # port mitmproxy is on. gateway_ip is the guest-side loopback.
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

    # Agent environment. The template system is gone — host scripts set
    # up whatever the agent needs directly in the persistent home. The
    # only thing we still surface is extra_env (yolo / detach / host-
    # terminal flags) and user-supplied agent args.
    agent_env_lines = []
    if agent_args:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_ARGS="{agent_args}"')
    if extra_env:
        for k, v in extra_env.items():
            agent_env_lines.append(f'export {k}="{v}"')
    (share_dir / "agent.env").write_text("\n".join(agent_env_lines) + "\n")

    # Network config for static IP (used by initramfs init)
    net_env = (
        f"GUEST_IP={guest_ip}\n"
        f"GATEWAY_IP={gateway_ip}\n"
        f"NETMASK=255.255.255.0\n"
    )
    if attribution_ip:
        net_env += f"AGENT_IP={attribution_ip}\n"
    (share_dir / "network.env").write_text(net_env)

    # Agent name → guest hostname. Read by guest-init-static which calls
    # `hostname <name>` and writes /etc/hostname. Agents in the Docker
    # era inherited container name as hostname automatically; the
    # VM-based stack needs to set it explicitly.
    (share_dir / "agent-name").write_text(name)

    # CA certificate
    ca_cert = config_dir / "certs" / "mitmproxy-ca-cert.pem"
    if ca_cert.exists():
        dest = share_dir / "mitmproxy-ca-cert.pem"
        shutil.copy2(str(ca_cert), str(dest))
        dest.chmod(0o644)  # public cert, must be readable by agent user

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
    background: bool = False,
    snapshot_capture_path: Path | None = None,
    restore_from_path: Path | None = None,
    proxy_socket_path: str | None = None,
    shell_socket_path: str | None = None,
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

    # Per-agent persistent /home/agent. VirtioFS bind-mount from host
    # keeps state (mise installs, .claude.json, shell history) outside
    # the rootfs so it survives macOS snapshot restore (which rewinds
    # the rootfs to a pristine clone) and Linux overlay discard.
    ensure_agent_persistent_dirs(name)
    agent_home = get_agent_home_dir(name)

    cmd = [
        str(helper), "run",
        "--kernel", str(kernel),
        "--initrd", str(initrd),
        "--rootfs", str(rootfs),
        "--cpus", str(cpus),
        "--memory", str(memory_mb),
        "--share", f"{workspace_path}:workspace:rw",
        "--share", f"{config_share}:config:ro",
        "--share", f"{get_agent_status_dir(name)}:status:rw",
        "--share", f"{agent_home}:home:rw",
        "--cmdline", "console=hvc0 root=/dev/vda rw quiet",
    ]

    if snapshot_capture_path is not None:
        cmd.extend(["--snapshot-on-signal", str(snapshot_capture_path)])
    if restore_from_path is not None:
        cmd.extend(["--restore-from", str(restore_from_path)])

    # vsock→UDS relay. The cross-platform bridge stamps agent identity
    # on upstream TCP, matching the Linux data path.
    if proxy_socket_path:
        cmd.extend(["--proxy-socket", proxy_socket_path])

    # Shell bridge UDS (Phase 2). `safeyolo agent shell` uses SSH with
    # ProxyCommand=`nc -U <path>` to reach sshd inside a VM that has
    # no network interface.
    if shell_socket_path:
        cmd.extend(["--shell-socket", shell_socket_path])

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
        # Foreground mode: the vsock terminal's stdout is the agent's
        # interactive session — it must reach the user's terminal. But
        # stderr carries bridge relay logs (proxy-relay, shell-bridge)
        # which would corrupt the agent's TUI. Redirect stderr to the
        # serial log so diagnostics are captured without leaking into
        # the interactive session.
        serial_log = get_agents_dir() / name / "serial.log"
        with open(serial_log, "w") as serial_fh:
            proc = subprocess.Popen(cmd, stderr=serial_fh)

    # Write PID file
    pid_path = get_agent_pid_path(name)
    pid_path.write_text(str(proc.pid))

    return proc


def stop_vm(name: str) -> None:
    """Stop a running VM and clean up agent-map state."""
    pid_path = get_agent_pid_path(name)
    if not pid_path.exists():
        _update_agent_map(name, remove=True)
        return

    pid = int(pid_path.read_text().strip())

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_path.unlink(missing_ok=True)
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
    _update_agent_map(name, remove=True)


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


# ---------------------------------------------------------------------------
# Agent map (for service_discovery addon)
# ---------------------------------------------------------------------------

def _update_agent_map(
    name: str,
    ip: str | None = None,
    socket: str | None = None,
    port: int | None = None,
    remove: bool = False,
) -> None:
    """Update the agent-IP map file.

    Read by three consumers:
      - addons/service_discovery.py (in mitmproxy) — uses `ip` to map
        request source IPs back to agent names for audit/policy/rate-limit.
      - addons/proxy_protocol.py (in mitmproxy) — uses `port` to map
        the bridge's deterministic source port back to agent identity
        at connection time (client_connected hook).
      - safeyolo.proxy_bridge — uses `socket` to create a per-agent
        listener, and `port` as the deterministic source port to bind
        when connecting to mitmproxy.
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
        if port is not None:
            entry["port"] = port
        agent_map[name] = entry

    map_path.write_text(json.dumps(agent_map, indent=2) + "\n")


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
