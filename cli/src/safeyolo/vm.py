"""MicroVM lifecycle management for SafeYolo.

Replaces Docker container management with Apple Virtualization.framework
microVMs via the safeyolo-vm Swift helper binary.
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .config import (
    get_agents_dir,
    get_config_dir,
    get_data_dir,
    get_share_dir,
    get_ssh_key_path,
    get_agent_map_path,
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
) -> Path:
    """Create the config share directory for a VM.

    The guest init script reads files from this directory to configure
    proxy settings, CA trust, SSH access, and agent environment.
    """
    config_dir = get_config_dir()
    share_dir = get_agent_config_share_dir(name)
    share_dir.mkdir(parents=True, exist_ok=True)

    # Proxy environment variables
    # The guest uses HTTP_PROXY to route through host mitmproxy.
    # Gateway IP is typically 192.168.64.1 for VZNATNetworkDeviceAttachment.
    proxy_url = f"http://192.168.64.1:{proxy_port}"
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
    )
    (share_dir / "proxy.env").write_text(proxy_env)

    # Agent environment
    agent_env_lines = []
    if agent_binary:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_BINARY="{agent_binary}"')
    if mise_package:
        agent_env_lines.append(f'export SAFEYOLO_MISE_PACKAGE="{mise_package}"')
    if agent_args:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_ARGS="{agent_args}"')
    if agent_binary:
        agent_env_lines.append(f'export SAFEYOLO_AGENT_CMD="{agent_binary}"')
    if extra_env:
        for k, v in extra_env.items():
            agent_env_lines.append(f'export {k}="{v}"')
    (share_dir / "agent.env").write_text("\n".join(agent_env_lines) + "\n")

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
) -> subprocess.Popen:
    """Start a VM and return the Popen handle.

    The caller is responsible for waiting on the process (interactive)
    or storing the PID for later management (background).
    """
    helper = find_vm_helper()
    rootfs = get_agent_rootfs_path(name)
    if not rootfs.exists():
        raise VMError(f"Agent rootfs not found: {rootfs}\nRun 'safeyolo agent add' first.")

    kernel = get_kernel_path()
    initrd = get_initrd_path()
    for path, label in [(kernel, "kernel"), (initrd, "initramfs")]:
        if not path.exists():
            raise VMError(f"{label} not found at {path}\nBuild guest images first.")

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

    # Additional shares
    if extra_shares:
        for host_path, tag, read_only in extra_shares:
            mode = "ro" if read_only else "rw"
            cmd.extend(["--share", f"{host_path}:{tag}:{mode}"])

    proc = subprocess.Popen(cmd)

    # Write PID file
    pid_path = get_agent_pid_path(name)
    pid_path.write_text(str(proc.pid))

    return proc


def stop_vm(name: str) -> None:
    """Stop a running VM by sending SIGTERM to safeyolo-vm."""
    pid_path = get_agent_pid_path(name)
    if not pid_path.exists():
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
            pass

    pid_path.unlink(missing_ok=True)
    _update_agent_map(name, remove=True)


def is_vm_running(name: str) -> bool:
    """Check if a VM process is alive."""
    pid_path = get_agent_pid_path(name)
    if not pid_path.exists():
        return False

    pid = int(pid_path.read_text().strip())
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        pid_path.unlink(missing_ok=True)
        return False


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


# ---------------------------------------------------------------------------
# Agent map (for service_discovery addon)
# ---------------------------------------------------------------------------

def _update_agent_map(name: str, ip: str | None = None, remove: bool = False) -> None:
    """Update the agent-IP map file read by the service_discovery addon."""
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
        agent_map[name] = {
            "ip": ip,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

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
    """Check if all guest image artifacts exist."""
    return (
        get_kernel_path().exists()
        and get_initrd_path().exists()
        and get_base_rootfs_path().exists()
    )


def guest_image_status() -> dict[str, bool]:
    """Return existence status of each guest image artifact."""
    return {
        "kernel": get_kernel_path().exists(),
        "initramfs": get_initrd_path().exists(),
        "rootfs": get_base_rootfs_path().exists(),
    }
