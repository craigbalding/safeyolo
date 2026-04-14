# SafeYolo Guest Image Builds

Builds the three artifacts SafeYolo needs to run agent microVMs:

- `out/Image` — Linux kernel (macOS Virtualization.framework only)
- `out/initramfs.cpio.gz` — minimal initramfs (macOS only)
- `out/rootfs-base.ext4` — Debian trixie rootfs with mise + node@22

No Docker. Uses `mmdebstrap` for the rootfs and native cross-compile for the kernel/initramfs.

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

## Troubleshooting

**mmdebstrap fails with "Operation not permitted" around user namespaces**
Our scripts use `--mode=root` under `sudo`, which sidesteps AppArmor restrictions on newer Ubuntu runners. If you're running on a host without sudo, see mmdebstrap's [mode documentation](https://gitlab.mister-muffin.de/josch/mmdebstrap/blob/main/mmdebstrap.1.pod) for alternatives.

**`mkfs.ext4: No space left on device`**
Content exceeded the sized image. The script computes size with 20% + 50MB headroom, so this shouldn't happen in normal flow. If it does, shrink the rootfs package list or bump the headroom in `build-rootfs.sh`.

**Lima VM won't start**
```bash
limactl delete safeyolo-builder
./build-all.sh   # recreates the VM
```

**Build works on host Linux but not inside Lima**
`limactl shell safeyolo-builder -- bash` to drop into the VM and reproduce manually. Lima's `/build/guest` is the mount point (not `/workspace/safeyolo/guest`).
