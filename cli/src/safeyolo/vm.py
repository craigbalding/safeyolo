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
import tempfile
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
    # Shared read-only ext4 base image. macOS VZ boots from this
    # directly (initramfs mounts it `-o ro,noload`). All agents share
    # the single file; per-agent state lives in the overlay upper
    # (/dev/vdb) and /home/agent (virtiofs-bound).
    return get_share_dir() / "rootfs-base.ext4"


def get_agent_rootfs_path(name: str) -> Path:
    # No per-agent rootfs file. All agents share get_base_rootfs_path();
    # per-agent runtime state lives in the in-VM overlay upper
    # (persistent when /dev/vdb is attached, ephemeral via tmpfs when
    # safeyolo.ephemeral_upper=1) and the /home/agent virtiofs bind.
    # Kept as a function because callers expect a Path; points at the
    # shared base so any code that treats it as a read target works.
    return get_base_rootfs_path()


def get_agent_pid_path(name: str) -> Path:
    return get_agents_dir() / name / "vm.pid"


def get_agent_overlay_path(name: str) -> Path:
    """Per-agent writable overlay image (attached as /dev/vdb on macOS VZ).

    Linux gVisor doesn't use this — gVisor's own `--overlay2=root:dir=`
    manages its overlay in a per-agent directory (see the Linux
    platform module). This function is macOS-VZ-only.

    macOS VZ: a per-agent ext4 image layered on top of the shared
    read-only ext4 rootfs via overlayfs inside the guest. Runtime
    writes to /etc, /usr, /var, etc. persist here across agent
    stop/run — /home/agent remains a separate virtiofs bind for
    bulk user data.

    The file is created as a sparse 256 GiB `truncate`. The guest's
    initramfs detects the absent filesystem on first boot and runs
    `mkfs.ext4 -F -E lazy_itable_init=1` in-place; eager mkfs work
    is a few MiB of metadata (superblock, block-group descriptors,
    bitmaps) regardless of logical size.
    """
    return get_agents_dir() / name / "overlay.img"


# Default logical size for the per-agent overlay image.
#
# Chosen to be "plausibly unlimited" rather than a tight cap users can
# hit by accident. 256 GiB covers any realistic in-VM install pattern
# (multi-TB language toolchains, cached container images, debug dumps)
# while staying well under ext4's ~16 TiB limit at the default 4 KiB
# block size.
#
# Sparse-file semantics on APFS (macOS) and ext4 with extents (Linux):
# the file reports 256 GiB via `ls -l` and `df -h` inside the VM, but
# only written blocks consume physical disk. The real ceiling is host
# disk capacity — when the host fills, the in-VM write fails with
# ENOSPC (confusing-looking: "df says 200 GiB free" — but the error
# is genuine).
#
# mkfs.ext4 cost: `-E lazy_itable_init=1` keeps inode-table zeroing
# in a background kthread, so first-boot mkfs on a 256 GiB overlay
# writes only ~5 MiB of eager metadata (superblock copies, block-group
# descriptors, group bitmaps, journal header). Measured: well under
# a second.
_OVERLAY_IMAGE_SIZE_BYTES = 256 * 1024 * 1024 * 1024


def ensure_agent_overlay(name: str) -> Path:
    """Create the per-agent overlay image if missing. Returns its path.

    Idempotent; no-op if the file already exists at any nonzero size.
    Deliberately does NOT grow an existing smaller image to match the
    current default — bumping the sparse size would need a resize2fs
    on the guest side, which needs the VM stopped. Users who want the
    new size on an existing agent can `safeyolo agent remove && add`.
    """
    path = get_agent_overlay_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return path
    # Sparse allocation: the file reports _OVERLAY_IMAGE_SIZE_BYTES
    # logically but consumes ~0 physically until writes land.
    with open(path, "wb") as fh:
        fh.truncate(_OVERLAY_IMAGE_SIZE_BYTES)
    path.chmod(0o600)
    return path


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

    Bind-mounted over the rootfs /home/agent -- VirtioFS on macOS VZ,
    OCI bind-mount on Linux gVisor -- so writes survive the macOS
    snapshot/restore dance (restore clones a pristine rootfs image,
    wiping any in-rootfs writes) and Linux gVisor's ephemeral memory
    overlay. MISE_DATA_DIR points at $HOME/.mise (set in
    /etc/profile.d/mise.sh and vsock-term), so mise installs land here
    too -- first-run installs persist and the install block in
    guest-init-static is a no-op thereafter.
    """
    return get_agents_dir() / name / "home"


def ensure_agent_persistent_dirs(name: str) -> None:
    """Create per-agent host dirs used as persistent bind-mount sources.

    Idempotent so `agent add` and `agent run` can both call it without
    care -- backfills agents created before the persistent-home design.
    """
    d = get_agent_home_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)

    # Seed cache-paths.txt from the default-base share if the agent
    # doesn't already have one. Skipped when a rootfs-script wrote the
    # file directly (build_custom_rootfs clears+lets-the-script-write,
    # so a pre-existing file at this point is authoritative). The Linux
    # OCI spec reads this file at start_sandbox time and bind-mounts
    # each listed path to a persistent per-agent cache dir.
    agent_cache_paths = get_agents_dir() / name / "cache-paths.txt"
    share_cache_paths = get_share_dir() / "cache-paths.txt"
    if not agent_cache_paths.exists() and share_cache_paths.exists():
        shutil.copy2(share_cache_paths, agent_cache_paths)


def get_agent_cache_paths_file(name: str) -> Path:
    """Return the path to this agent's cache-paths.txt (may not exist)."""
    return get_agents_dir() / name / "cache-paths.txt"


def read_agent_cache_paths(name: str) -> list[str]:
    """Return the list of in-rootfs paths this agent wants cache-bound.

    Source of truth is <agent_dir>/cache-paths.txt — seeded from either
    (a) a rootfs-script's SAFEYOLO_ROOTFS_OUT_CACHE_PATHS output, or
    (b) the default base's <share>/cache-paths.txt (copied by
    ensure_agent_persistent_dirs). Each line is an absolute path inside
    the rootfs. Empty lines and `#` comments are ignored so future
    shares can document themselves without breaking parsers.
    """
    f = get_agent_cache_paths_file(name)
    if not f.exists():
        return []
    paths: list[str] = []
    for raw in f.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            log.warning("cache-paths.txt: ignoring non-absolute path %r", line)
            continue
        paths.append(line)
    return paths


def get_agent_cache_dir(name: str, in_rootfs_path: str) -> Path:
    """Return the host-side per-agent cache dir for a given rootfs path.

    Slug = path with leading slash stripped and remaining slashes
    replaced by `_`, so `/var/cache/apt` → `var_cache_apt`. Readable in
    `ls`, stable under repeated runs, no collision as long as the
    rootfs paths themselves don't collide post-slug (caller's
    responsibility to keep paths distinct).
    """
    slug = in_rootfs_path.lstrip("/").replace("/", "_")
    return get_agents_dir() / name / "cache" / slug


# ---------------------------------------------------------------------------
# Rootfs management
# ---------------------------------------------------------------------------

def create_agent_rootfs(name: str) -> Path:
    """Return the rootfs path this agent should boot from.

    There is no per-agent rootfs copy. The shared ext4 base is
    mounted read-only by every agent's VM (initramfs uses `-o ro,noload`);
    writes land in the overlay upper (ext4 on /dev/vdb persistent, or
    tmpfs ephemeral) and in /home/agent (virtiofs-bound, persistent).

    Ensures the per-agent directory exists because other code
    (config-share, status, overlay.img, ssh host keys) writes into it.
    """
    base = get_base_rootfs_path()
    if not base.exists():
        raise VMError(
            f"Base rootfs not found at {base}\n"
            f"Build guest images first: cd guest && ./build-all.sh"
        )
    (get_agents_dir() / name).mkdir(parents=True, exist_ok=True)
    return base


# ---------------------------------------------------------------------------
# Custom rootfs builder (--rootfs-script)
# ---------------------------------------------------------------------------
#
# build_custom_rootfs invokes a user-supplied shell script that produces a
# per-agent rootfs image. The script always runs on Linux -- either on the
# user's Linux host, or inside the shared safeyolo-builder Lima VM on macOS.
# Scripts receive env vars telling them where to write the output image;
# SafeYolo validates afterward. See contrib/ROOTFS_SCRIPT_GUIDE.md.

LIMA_VM_NAME = "safeyolo-builder"
LIMA_GUEST_MOUNT = "/build/guest"


def _host_target_arch() -> str:
    """Map the host's arch name to the DEB-style names scripts expect.

    On macOS the kernel is arm64 only; on Linux we match the host arch.
    """
    m = platform.machine()
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m in ("x86_64", "amd64"):
        return "amd64"
    raise VMError(f"Unsupported host architecture for rootfs build: {m}")


def _guest_src_dir() -> Path:
    """Return the repo's guest/ directory.

    cli/src/safeyolo/vm.py → parents[3] is the repo root.
    """
    return Path(__file__).resolve().parents[3] / "guest"


def build_custom_rootfs(name: str, script_path: Path) -> Path:
    """Invoke a user rootfs-script to produce a per-agent rootfs.

    Returns the output path. Raises VMError on failure.

    Env contract (see contrib/ROOTFS_SCRIPT_GUIDE.md):
      SAFEYOLO_AGENT_NAME
      SAFEYOLO_ROOTFS_OUT_EXT4          (set when target is Darwin — ext4 image)
      SAFEYOLO_ROOTFS_OUT_TREE          (set when target is Linux — directory tree)
      SAFEYOLO_ROOTFS_OUT_CACHE_PATHS   (file path — script writes one
                                         absolute in-rootfs cache path
                                         per line; SafeYolo bind-mounts
                                         persistent per-agent dirs onto
                                         these paths at sandbox start)
      SAFEYOLO_ROOTFS_WORK_DIR
      SAFEYOLO_GUEST_SRC_DIR
      SAFEYOLO_TARGET_ARCH
    """
    agent_dir = get_agents_dir() / name
    agent_dir.mkdir(parents=True, exist_ok=True)

    system = platform.system()
    if system == "Darwin":
        out_path = agent_dir / "rootfs.ext4"
        out_key = "SAFEYOLO_ROOTFS_OUT_EXT4"
        out_is_dir = False
    elif system == "Linux":
        # Linux runtime consumes a directory tree as OCI root.path.
        # Custom rootfs-scripts write the unpacked tree here; umoci
        # unpack does this natively, no extra conversion needed.
        out_path = agent_dir / "rootfs"
        out_key = "SAFEYOLO_ROOTFS_OUT_TREE"
        out_is_dir = True
    else:
        raise VMError(f"Unsupported platform for --rootfs-script: {system}")

    # Start with a clean output slot so a failed rebuild doesn't leave
    # a stale image around that a later agent-run picks up.
    if out_path.exists():
        if out_path.is_dir():
            shutil.rmtree(out_path, ignore_errors=True)
        else:
            out_path.unlink()

    # Cache-paths output: the script may write a list of absolute
    # in-rootfs paths (one per line) that SafeYolo bind-mounts to
    # persistent per-agent dirs at sandbox start. Pre-create an empty
    # file so the script's `[ -n "$VAR" ]` guard sees the variable and
    # writes unconditionally if it wants to; a missing file afterwards
    # means the script chose not to declare any caches.
    cache_paths_file = agent_dir / "cache-paths.txt"
    cache_paths_file.unlink(missing_ok=True)

    if system == "Linux":
        _run_rootfs_script_native(
            name, script_path, out_key, out_path, cache_paths_file,
        )
    else:
        _run_rootfs_script_lima(
            name, script_path, out_key, out_path, cache_paths_file,
        )

    if not out_path.exists():
        raise VMError(
            f"Rootfs script {script_path} did not produce {out_path}.\n"
            f"Scripts must write their output to ${out_key}."
        )
    if out_is_dir:
        # Tree must be non-empty with at least /etc.
        if not (out_path.is_dir() and (out_path / "etc").is_dir()):
            raise VMError(
                f"Rootfs script {script_path} produced {out_path} but it's not"
                f" a valid rootfs tree (missing /etc)."
            )
        size = sum(
            f.stat().st_size for f in out_path.rglob("*") if f.is_file()
        )
        log.info("Custom rootfs tree built for '%s': %s (%d bytes)",
                 name, out_path, size)
    else:
        if out_path.stat().st_size == 0:
            raise VMError(
                f"Rootfs script {script_path} produced an empty file at {out_path}."
            )
        log.info("Custom rootfs image built for '%s': %s (%d bytes)",
                 name, out_path, out_path.stat().st_size)
    return out_path


def _run_rootfs_script_native(
    name: str, script_path: Path, out_key: str, out_path: Path,
    cache_paths_file: Path,
) -> None:
    """Run the rootfs-script directly on the Linux host."""
    guest_src = _guest_src_dir()
    if not guest_src.is_dir():
        raise VMError(
            f"guest/ directory not found at {guest_src}. "
            f"SafeYolo must be run from a repo checkout or installed image."
        )

    work_dir = Path(tempfile.mkdtemp(prefix="safeyolo-rootfs-"))
    try:
        env = {
            **os.environ,
            "SAFEYOLO_AGENT_NAME": name,
            out_key: str(out_path),
            "SAFEYOLO_ROOTFS_OUT_CACHE_PATHS": str(cache_paths_file),
            "SAFEYOLO_ROOTFS_WORK_DIR": str(work_dir),
            "SAFEYOLO_GUEST_SRC_DIR": str(guest_src),
            "SAFEYOLO_TARGET_ARCH": _host_target_arch(),
        }
        log.info("Running rootfs script: %s", script_path)
        result = subprocess.run([str(script_path)], env=env, check=False)
        if result.returncode != 0:
            raise VMError(
                f"Rootfs script {script_path} exited with code "
                f"{result.returncode}."
            )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _run_rootfs_script_lima(
    name: str, script_path: Path, out_key: str, out_path: Path,
    cache_paths_file: Path,
) -> None:
    """Run the rootfs-script inside the shared safeyolo-builder Lima VM.

    Staging strategy: two-tier storage because macOS→VM VirtioFS confuses
    libext2fs's `mkfs.ext4 -d` walker (it ENOENTs on files like
    /etc/passwd- after useradd, which read fine on a regular Linux mount).

      - WORK dir: VM-local /tmp/safeyolo-rootfs-<uuid>/ -- every heavy
        operation (skopeo unpack, chroot+apt/apk, mkfs.ext4 -d reading
        the source tree) happens here, on a plain Linux filesystem.
      - STAGING dir: host guest/.scratch/<uuid>/ (virtiofs-mounted into
        the VM at /build/guest/.scratch/<uuid>/) -- holds only the final
        packed rootfs image. Script writes to $SAFEYOLO_ROOTFS_OUT_* here;
        host-side then plain-moves it to the agent dir.

    The script itself is staged into the staging dir (single small file,
    crossing virtiofs once is fine).

    Avoiding mutation of the Lima instance's mount list keeps the VM
    config reusable and avoids stop/start overhead.
    """
    import uuid

    limactl = shutil.which("limactl")
    if not limactl:
        raise VMError(
            "Lima is not installed. --rootfs-script on macOS needs Lima.\n"
            "Install: brew install lima\n"
            "See contrib/ROOTFS_SCRIPT_GUIDE.md."
        )

    guest_src = _guest_src_dir()
    if not guest_src.is_dir():
        raise VMError(f"guest/ directory not found at {guest_src}.")

    _ensure_lima_vm(limactl)

    run_id = uuid.uuid4().hex[:12]
    host_scratch = guest_src / ".scratch" / run_id
    host_scratch.mkdir(parents=True, exist_ok=False)
    vm_scratch = f"{LIMA_GUEST_MOUNT}/.scratch/{run_id}"
    vm_work_dir = f"/tmp/safeyolo-rootfs-{run_id}"

    try:
        # Stage the user's script into the (virtiofs) staging dir so the VM
        # sees it. Fixed name inside the VM keeps the command line predictable.
        staged_script = host_scratch / "rootfs-script"
        shutil.copy2(str(script_path), str(staged_script))
        staged_script.chmod(0o755)

        out_name = out_path.name  # rootfs.ext4 (Darwin) or rootfs (Linux tree)
        vm_script_path = f"{vm_scratch}/rootfs-script"
        vm_out_path = f"{vm_scratch}/{out_name}"
        vm_cache_paths = f"{vm_scratch}/cache-paths.txt"
        vm_guest_dir = LIMA_GUEST_MOUNT

        env_args = [
            f"SAFEYOLO_AGENT_NAME={name}",
            f"{out_key}={vm_out_path}",
            f"SAFEYOLO_ROOTFS_OUT_CACHE_PATHS={vm_cache_paths}",
            f"SAFEYOLO_ROOTFS_WORK_DIR={vm_work_dir}",
            f"SAFEYOLO_GUEST_SRC_DIR={vm_guest_dir}",
            f"SAFEYOLO_TARGET_ARCH={_host_target_arch()}",
        ]
        # --workdir=/ silences Lima's "cd: <cwd>: No such file or directory"
        # for callers whose host CWD isn't inside the VM's narrow mount set.
        # sudo -E: rootfs builders need root (chroot, mkfs, apt-get --install-root,
        # etc.); Lima's default user has NOPASSWD sudo. -E preserves the env
        # vars we already set so the script sees SAFEYOLO_* without re-plumbing.
        # Trap on the bash line cleans up the VM-local work dir even if the
        # script crashes mid-way.
        cmd = [
            limactl, "shell", "--workdir=/", LIMA_VM_NAME, "--",
            "sudo", "-E", "bash", "-c",
            f"mkdir -p {vm_work_dir} && "
            f"trap 'rm -rf {vm_work_dir}' EXIT && "
            f"env {' '.join(env_args)} {vm_script_path}"
        ]
        log.info("Running rootfs script in Lima VM %s: %s", LIMA_VM_NAME, script_path)
        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            raise VMError(
                f"Rootfs script {script_path} exited with code "
                f"{result.returncode} inside Lima VM."
            )

        # Pull the output back to the agent dir. The script wrote it into
        # the virtiofs-backed staging dir, so this is a plain filesystem move.
        produced = host_scratch / out_name
        if not produced.exists():
            raise VMError(
                f"Rootfs script {script_path} did not produce "
                f"${out_key} ({produced})."
            )
        shutil.move(str(produced), str(out_path))

        # Optional: the script may have emitted a cache-paths list.
        # Move it to the agent dir if present; harmless if not (macOS VZ
        # ignores it anyway — the disk-backed overlay persists writes).
        produced_cache = host_scratch / "cache-paths.txt"
        if produced_cache.exists():
            shutil.move(str(produced_cache), str(cache_paths_file))
    finally:
        # Host-side: staging dir cleanup is unconditional. VM-local work dir
        # is cleaned up by the bash trap above; if that didn't run (e.g.
        # SIGKILL from the host), it's under /tmp and the VM reboot will
        # clear it.
        shutil.rmtree(host_scratch, ignore_errors=True)
        # Stop the builder VM so it doesn't keep CPU/RAM pinned on the host
        # between builds. Boot cost on re-use is trivial.
        subprocess.run(
            [limactl, "stop", LIMA_VM_NAME],
            check=False, capture_output=True,
        )


def _ensure_lima_vm(limactl: str) -> None:
    """Make sure the safeyolo-builder Lima VM exists and is running.

    Creates it from guest/lima.yaml if missing. Starts it if stopped.
    Matches the pattern in guest/build-all.sh so the default-base and
    custom-rootfs flows share one VM, and the post-build stop() in
    _run_rootfs_script_lima doesn't leave the next run to trip over
    Lima 2.x's interactive "Do you want to start the instance now?"
    prompt on `limactl shell`.
    """
    # One list call, parsed locally. `limactl list --filter name=X` isn't
    # supported on all Lima versions (2.x returns exit 1), so we avoid it.
    listing = subprocess.run(
        [limactl, "list", "--format", "{{.Name}}\t{{.Status}}"],
        check=True, capture_output=True, text=True,
    )
    status_by_name: dict[str, str] = {}
    for line in listing.stdout.splitlines():
        name, _, status = line.partition("\t")
        if name:
            status_by_name[name] = status

    if LIMA_VM_NAME not in status_by_name:
        lima_yaml = _guest_src_dir() / "lima.yaml"
        if not lima_yaml.is_file():
            raise VMError(f"Missing {lima_yaml}; cannot create Lima VM.")
        repo_dir = _guest_src_dir().parent.resolve()
        log.info("Creating Lima VM '%s' (first run; ~2-3 min)", LIMA_VM_NAME)
        subprocess.run(
            [limactl, "start", f"--name={LIMA_VM_NAME}", "--tty=false",
             f"--set=.param.REPO_DIR = \"{repo_dir}\"", str(lima_yaml)],
            check=True,
        )
        return

    if status_by_name[LIMA_VM_NAME] != "Running":
        log.info("Starting Lima VM '%s'", LIMA_VM_NAME)
        subprocess.run(
            [limactl, "start", "--tty=false", LIMA_VM_NAME],
            check=True,
        )


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

    # Guest init scripts -- served from config share, not baked into rootfs.
    # Changes here take effect on next agent run without rootfs rebuild.
    # Three scripts split the boot into a snapshottable static phase and
    # a per-run phase; the orchestrator gates between them on per-run-go.
    #
    # guest-proxy-forwarder.sh bridges the agent's HTTP_PROXY (localhost
    # TCP) to the host-side proxy (UDS on Linux / vsock on macOS) via
    # socat. Started by guest-init before the agent. guest-shell-bridge.sh
    # mirrors in the other direction for `safeyolo agent shell`.
    # guest-diag.py is an opt-in user diagnostic and requires python3
    # in the rootfs (default base includes it? no -- users install if
    # needed, it's not on the boot path).
    for src_name, dst_name in [
        ("guest-init.sh", "guest-init"),
        ("guest-init-static.sh", "guest-init-static"),
        ("guest-init-per-run.sh", "guest-init-per-run"),
        ("guest-proxy-forwarder.sh", "guest-proxy-forwarder"),
        ("guest-shell-bridge.sh", "guest-shell-bridge"),
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
        # CAPTURE mode needs a clean slate -- a stale per-run-go from an
        # earlier passthrough run would let the guest skip past the
        # snapshot point before we get a chance to SIGUSR1.
        per_run_go.unlink(missing_ok=True)
    # Ensure no stale per-boot markers from a prior run mask progress --
    # the guest writes these fresh on every boot to the status share.
    # The CLI polls for per-run-started specifically as a definitive
    # "restore succeeded" signal; a stale copy would make a failed
    # restore look successful.
    status_dir = get_agent_status_dir(name)
    for marker in ("static-init-done", "per-run-started", "vm-status", "vm-ip"):
        (status_dir / marker).unlink(missing_ok=True)

    # Debug-mode marker -- presence enables per-iteration guest tracing.
    # Checked by guest-init orchestrator (which runs before agent.env is
    # sourced, so a file marker is cleaner than an env var).
    debug_marker = share_dir / "debug-mode"
    if debug_mode:
        debug_marker.write_text("")
    else:
        debug_marker.unlink(missing_ok=True)

    # vsock-term binary -- cross-compiled, served from config share
    vsock_term_src = config_dir / "bin" / "vsock-term"
    if vsock_term_src.exists():
        shutil.copy2(str(vsock_term_src), str(share_dir / "vsock-term"))
        (share_dir / "vsock-term").chmod(0o755)

    # Proxy environment variables. proxy_port is 8080 -- the fixed port
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

    # Agent environment. The template system is gone -- host scripts set
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

    # Host config mount manifest -- tells the guest init which VirtioFS tags
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
    ephemeral: bool = False,
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

    ephemeral: if True, don't attach a per-agent overlay disk. The
        kernel cmdline gets `safeyolo.ephemeral_upper=1` which tells the
        guest's initramfs to use tmpfs as the overlayfs upper. Writes
        to / are discarded on stop. /home/agent (virtiofs) still
        persists regardless.
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

    # Restore-time disk pairing. VZ requires every attached disk at
    # restore to match byte-for-byte the state it had at save time.
    #
    # Rootfs: shared read-only ext4. It doesn't change between save and
    # restore, so no pairing needed — we pass the same --rootfs as
    # cold-boot.
    #
    # Overlay (writable, per-agent /dev/vdb): the guest DOES write to
    # this between save and restore, so safeyolo-vm at save time clones
    # it to {snapshot}.overlay. On restore we clone that pristine copy
    # to a per-run working file ({snapshot}.overlay.run) and pass it as
    # --overlay, so live writes during the restore session land in the
    # working copy and the pristine is reusable for the next restore.
    # APFS clonefile makes this ~instant regardless of logical size.
    #
    # Ephemeral mode: no overlay was attached at save time, so no
    # pairing file was produced. start_vm below also omits --overlay
    # on restore; the tmpfs upper is carried inside the memory image.
    overlay_restore_working: Path | None = None
    if restore_from_path is not None and not ephemeral:
        pristine = Path(f"{restore_from_path}.overlay")
        if not pristine.exists():
            raise VMError(
                f"Snapshot overlay clone missing: {pristine}\n"
                f"Restore cannot proceed without the paired overlay clone.\n"
                f"(Snapshots captured with pre-schema-4 safeyolo-vm versions\n"
                f" pair to .rootfs, not .overlay — recapture the snapshot.)"
            )
        working = Path(f"{restore_from_path}.overlay.run")
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
        overlay_restore_working = working

    config_share = get_agent_config_share_dir(name)

    # Per-agent persistent /home/agent. VirtioFS bind-mount from host
    # keeps state (mise installs, .claude.json, shell history) outside
    # the rootfs so it survives macOS snapshot restore (which rewinds
    # the rootfs to a pristine clone) and Linux overlay discard.
    ensure_agent_persistent_dirs(name)
    agent_home = get_agent_home_dir(name)

    # Default kernel cmdline. Ephemeral mode appends the flag the
    # initramfs consumes to pick tmpfs-for-upper over /dev/vdb.
    cmdline = "console=hvc0 root=/dev/vda rw quiet"
    if ephemeral:
        cmdline += " safeyolo.ephemeral_upper=1"

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
        "--cmdline", cmdline,
    ]

    # Persistent mode (default): attach the per-agent writable overlay
    # disk as /dev/vdb. The guest's initramfs layers overlayfs over the
    # read-only ext4 base with this as the upper. Lazy-formatted on
    # first boot. In ephemeral mode we deliberately don't attach it;
    # the initramfs uses tmpfs instead. On restore, use the per-run
    # working copy of the paired pristine clone (see the restore block
    # above) so live writes don't corrupt the pristine.
    if not ephemeral:
        overlay_img = overlay_restore_working or ensure_agent_overlay(name)
        cmd.extend(["--overlay", str(overlay_img)])

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
        # interactive session -- it must reach the user's terminal. But
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
            # Process died between the SIGTERM wait loop and SIGKILL -- fine.
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

    # os.kill(pid, 0) also succeeds for zombies -- a Popen whose child has
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
        # ps unavailable or errored -- can't distinguish zombie from live.
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
      - addons/service_discovery.py (in mitmproxy) -- uses `ip` to map
        request source IPs back to agent names for audit/policy/rate-limit.
      - addons/proxy_protocol.py (in mitmproxy) -- uses `port` to map
        the bridge's deterministic source port back to agent identity
        at connection time (client_connected hook).
      - safeyolo.proxy_bridge -- uses `socket` to create a per-agent
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

def get_base_rootfs_tree_path() -> Path:
    """Directory tree used as OCI root.path on Linux gVisor.

    gVisor reads the tree directly — shared across all agents on the
    host (read-only from the container's perspective; the per-agent
    dir= overlay above it captures writes).

    Produced by guest/build-rootfs.sh as out/rootfs-tree/ alongside
    the ext4 output; installed to ~/.safeyolo/share/rootfs-tree/.
    """
    return get_share_dir() / "rootfs-tree"


def check_guest_images() -> bool:
    """Check if required guest image artifacts exist.

    Platform-specific — each platform checks the rootfs format its
    runtime actually consumes:

      - macOS (Virtualization.framework): ext4 rootfs + kernel + initramfs.
      - Linux (gVisor):                    unpacked tree (OCI root.path).
    """
    if platform.system() == "Darwin":
        return (
            get_base_rootfs_path().exists()
            and get_kernel_path().exists()
            and get_initrd_path().exists()
        )
    if platform.system() == "Linux":
        tree = get_base_rootfs_tree_path()
        # A valid tree is a non-empty directory with at least the
        # /etc hierarchy. Catches the "someone rm-rf'd its contents"
        # case that a plain is_dir() misses.
        return tree.is_dir() and (tree / "etc").is_dir()
    # Unsupported platform — treat the rootfs as the minimum needed.
    return get_base_rootfs_path().exists()


def guest_image_status() -> dict[str, bool]:
    """Return existence status of each guest image artifact.

    Status keys reflect what's on disk. Callers (doctor, setup) decide
    which to flag as missing per platform.
    """
    tree = get_base_rootfs_tree_path()
    return {
        "kernel": get_kernel_path().exists(),
        "initramfs": get_initrd_path().exists(),
        "rootfs-ext4": get_base_rootfs_path().exists(),
        "rootfs-tree": tree.is_dir() and (tree / "etc").is_dir(),
    }


# Which keys from guest_image_status() each platform actually needs.
# Used by `missing_guest_images` for a "missing: X, Y" list.
_PLATFORM_REQUIRED_ARTIFACTS = {
    "Darwin": ("kernel", "initramfs", "rootfs-ext4"),
    "Linux": ("rootfs-tree",),
}


def missing_guest_images() -> list[str]:
    """Return the artifacts this platform needs that aren't on disk yet."""
    status = guest_image_status()
    required = _PLATFORM_REQUIRED_ARTIFACTS.get(
        platform.system(), ("rootfs-ext4",)
    )
    return [k for k in required if not status.get(k, False)]
