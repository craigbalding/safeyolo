# SafeYolo Guest Image Builds

Builds the three artifacts SafeYolo needs to run agent microVMs:

- `out/Image` — Linux kernel (macOS Virtualization.framework only)
- `out/initramfs.cpio.gz` — minimal initramfs (macOS only)
- `out/rootfs-base.ext4` — Debian trixie rootfs with mise plus a small agent-oriented Unix toolkit

No Docker. Uses `mmdebstrap` for the rootfs and native cross-compile for the kernel/initramfs.

The default Debian rootfs intentionally keeps language ecosystems out of the
base image. Agents pull those in via `mise`. What is baked in are the things
agents need immediately on first boot and cannot sensibly replace with `mise`:
PTY/shared-memory correctness, SSH/socat plumbing, and a compact baseline of
search/debug/archive tools such as `ripgrep`, `fd-find`, `file`, `unzip`,
`zip`, `tmux`, `lsof`, `strace`, and Python venv support.

## Quick start

```bash
cd guest
./build-all.sh
```

On Linux this runs natively. On macOS it auto-shells into a Lima VM (see below).

Artifacts land in `guest/out/`. To use them:

```bash
mkdir -p ~/.safeyolo/share
cp guest/out/* ~/.safeyolo/share/
```

## macOS setup

```bash
brew install lima
```

That's it. The first `./build-all.sh` run creates a Lima VM named `safeyolo-builder` from `guest/lima.yaml` and provisions it with the required build tools (~2-3 min). Subsequent runs reuse the VM.

The same VM is reused by `safeyolo agent add --rootfs-script` on macOS when you build a custom per-agent rootfs. Its provisioning includes `mmdebstrap` + the kernel toolchain (for the default base) *and* `skopeo` + `umoci` + `erofs-utils` (for custom rootfs scripts — see `contrib/ROOTFS_SCRIPT_GUIDE.md`).

### Why Lima

`mmdebstrap` and `debootstrap` use Linux-specific syscalls and can't run natively on macOS. Docker Desktop worked because it's a hidden Linux VM — Lima makes the VM explicit and user-controlled. See `lima.yaml` for the config.

### Narrow mount scope

`guest/lima.yaml` mounts **only** `guest/` into the VM. It explicitly overrides Lima's default `~/` read-only home passthrough — your SSH keys, browser data, and credentials are **not** visible to the build environment. `build-all.sh` additionally verifies this before starting the build; a broken mount config aborts the build rather than silently exposing your home directory.

### VM lifecycle

```bash
limactl list                          # see the VM state
limactl stop safeyolo-builder         # shut it down between sessions
limactl start safeyolo-builder        # start it again
limactl delete safeyolo-builder       # remove it entirely (recreated on next build)
```

If the VM gets into a bad state, `limactl delete safeyolo-builder && ./build-all.sh` recreates it clean.

## Linux setup

Install the build dependencies:

```bash
sudo apt-get install \
    mmdebstrap \
    e2fsprogs \
    build-essential \
    bc \
    flex \
    bison \
    libelf-dev \
    libssl-dev \
    gcc-aarch64-linux-gnu \
    busybox-static \
    pax-utils \
    cpio \
    curl \
    xz-utils
```

`build-rootfs.sh` fetches a pinned + SHA256-verified `debian-archive-keyring` into `guest/out/.keyring-cache/` and passes it to `mmdebstrap --keyring=`, so the host's own keyring doesn't need to cover Debian trixie. (Ubuntu LTS ships a 2023-era keyring that predates trixie's signing keys — this way the build works regardless.)

On Linux, `./build-all.sh` skips kernel + initramfs by default (gVisor doesn't need them). Set `BUILD_KERNEL=1` to build all three (required when producing artifacts for macOS consumers).

## Architecture selection

The rootfs build supports both arm64 (default on Apple Silicon) and amd64:

```bash
./build-rootfs.sh                    # Host architecture
ARCH=amd64 ./build-rootfs.sh         # Force x86_64
ARCH=arm64 ./build-rootfs.sh         # Force ARM64
```

The kernel and initramfs are ARM64-only (macOS Virtualization.framework on Apple Silicon targets).

## Individual scripts

- `build-rootfs.sh` — Debian trixie rootfs via `mmdebstrap`
- `build-kernel.sh` — Linux kernel via native cross-compile (`aarch64-linux-gnu-gcc`)
- `build-initramfs.sh` — minimal initramfs via `busybox-static` + `lddtree`
- `build-all.sh` — platform-aware driver; calls the above three

All three scripts run on Linux only. On macOS, invoke them through `build-all.sh` which handles the Lima shell-in.

## Why sudo?

`build-rootfs.sh` invokes `mmdebstrap --mode=root` under `sudo`. Root is needed *inside* the bootstrap process for three things the kernel tightly gates:

1. `mknod` to create `/dev/` entries in the target rootfs
2. `chroot` into the rootfs and run Debian package maintainer scripts
3. Setting root-owned file ownership across the target `/` tree

mmdebstrap also supports `--mode=unshare`, which uses Linux user namespaces to fake root with zero real privilege — the preferred modern path. But Ubuntu 24.04 ships with `kernel.apparmor_restrict_unprivileged_userns=1` by default, which kills unprivileged user namespaces unless you flip that sysctl (a host-wide security posture change) or install an AppArmor profile for mmdebstrap. Neither is better UX than `sudo` for a quickstart, so we default to `--mode=root`.

Everything root touches is confined to a scratch directory under `/tmp/safeyolo-rootfs.*`. No persistent host state is modified — once `out/rootfs-base.ext4` is built and `chown`'d back to you, the `/tmp` tree is cleaned up.

If you want unshare mode on Noble: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (make persistent in `/etc/sysctl.d/` if you want), then patch `build-rootfs.sh` to drop `sudo` and change `--mode=root` to `--mode=unshare`. We may add this as a flag if there's demand.

## Troubleshooting

**`mkfs.ext4: No space left on device`**
Content exceeded the sized image. The script computes size with 20% + 50MB headroom, so this shouldn't happen in normal flow. If it does, shrink the rootfs package list or bump the headroom in `build-rootfs.sh`.

**Lima VM won't start**
```bash
limactl delete safeyolo-builder
./build-all.sh   # recreates the VM
```

**Build works on host Linux but not inside Lima**
`limactl shell safeyolo-builder -- bash` to drop into the VM and reproduce manually. Lima's `/build/guest` is the mount point (not `/workspace/safeyolo/guest`).
