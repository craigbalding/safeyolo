# SafeYolo Guest Image Builds

Builds the artifacts SafeYolo needs to run agent sandboxes:

- `out/Image` — Linux kernel (macOS Virtualization.framework only)
- `out/initramfs.cpio.gz` — minimal initramfs (macOS only)
- `out/rootfs-base.ext4` — Debian trixie rootfs (macOS VZ mounts this)
- `out/rootfs-base.erofs` — Debian trixie rootfs (Linux gVisor mounts this)

Every `build-rootfs.sh` run produces **both** rootfs images on Linux (natively or inside the Lima VM on macOS). The EROFS image is what gVisor loads on Linux hosts; without it, `safeyolo agent add` fails with "EROFS rootfs image not found".

No Docker. Uses `skopeo` + `umoci` to pull + unpack the official `debian:trixie` OCI image for the rootfs, and native cross-compile for the kernel/initramfs. Works on any Linux distro (Fedora, Arch, Alpine, Debian, Ubuntu) — no mmdebstrap/debootstrap on the build host.

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

The same VM is reused by `safeyolo agent add --rootfs-script` on macOS when you build a custom per-agent rootfs. Its provisioning includes `skopeo` + `umoci` + `e2fsprogs` + `erofs-utils` (for the default base and for custom rootfs scripts — see `contrib/ROOTFS_SCRIPT_GUIDE.md`) plus the kernel toolchain.

### Why Lima

`chroot`, `mkfs.ext4`, and `mkfs.erofs` are Linux-specific. Docker Desktop worked because it's a hidden Linux VM — Lima makes the VM explicit and user-controlled. See `lima.yaml` for the config.

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

Install the build dependencies. `skopeo` + `umoci` pull and unpack the Debian OCI image; `erofs-utils` builds the format gVisor mounts. If you only want to run `build-rootfs.sh` (the common path on a Linux host, since the kernel + initramfs are only needed for macOS VZ):

```bash
# Debian/Ubuntu:
sudo apt-get install skopeo umoci e2fsprogs erofs-utils curl

# Fedora/RHEL:
sudo dnf install skopeo umoci e2fsprogs erofs-utils curl

# Arch (umoci via AUR):
sudo pacman -S skopeo e2fsprogs erofs-utils curl && yay -S umoci

# Alpine:
apk add skopeo umoci e2fsprogs erofs-utils curl
```

For a full kernel + initramfs build (`BUILD_KERNEL=1`, or when producing artifacts for macOS consumers), add the kernel toolchain. On Debian/Ubuntu:

```bash
sudo apt-get install \
    skopeo umoci e2fsprogs erofs-utils curl \
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
    xz-utils
```

`build-rootfs.sh` doesn't need a Debian keyring — skopeo fetches the OCI image, not `.deb` packages, so the host's apt trust chain is irrelevant. Extras beyond the minbase image (ssh, socat, python3, the dev toolkit) are apt-installed **inside the unpacked rootfs tree** via chroot; those use the rootfs's own apt sources (debian:trixie's baked-in `deb.debian.org` mirror).

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

- `build-rootfs.sh` — Debian trixie rootfs via `skopeo` (pulls `docker://debian:trixie` OCI image) + `umoci` (unpacks to tree) + chroot apt-get (extras) + `rootfs-customize-hook.sh` (SafeYolo-specific bits); writes **both** `out/rootfs-base.ext4` (for macOS VZ) and `out/rootfs-base.erofs` (for Linux gVisor).
- `build-kernel.sh` — Linux kernel via native cross-compile (`aarch64-linux-gnu-gcc`)
- `build-initramfs.sh` — minimal initramfs via `busybox-static` + `lddtree`
- `build-all.sh` — platform-aware driver; calls the above three. Must be executed (`./build-all.sh`), not sourced.

All three scripts run on Linux only. On macOS, invoke them through `build-all.sh` which handles the Lima shell-in.

### Generate just the EROFS (Linux gVisor) rootfs

```bash
# From the repo root (or `cd guest`):
./guest/build-rootfs.sh
```

This produces both `out/rootfs-base.ext4` and `out/rootfs-base.erofs` in one pass — `build-rootfs.sh` does not split the two output formats. Re-run after deleting either output to rebuild both.

## Download cache

The build scripts keep a persistent cache of upstream downloads under `out/.download-cache/` so rebuilds don't re-fetch:

- `out/.download-cache/oci/` — skopeo OCI image layout for `docker://debian:trixie`. Re-using this on subsequent builds avoids the ~60-70 MiB re-pull.
- `out/.download-cache/linux-<ver>.tar.xz` — kernel source tarball
- `out/.download-cache/mise-v<ver>-linux-<arch>.tar.gz` — pinned mise release
- `out/.download-cache/gh_<ver>_linux_<arch>.tar.gz` — pinned gh CLI release

The chroot-apt-install step (~80 MiB of extras: ripgrep, build-essential, python3-pip, tmux, etc.) currently re-fetches on each rebuild — apt's own archive cache isn't preserved across builds in this pipeline. Previous mmdebstrap pipeline kept an `apt-archives/` cache; skopeo+chroot doesn't yet. Follow-up optimization.

To flush the cache (forces full re-download): `rm -rf guest/out/`. To flush artifacts but keep the cache: `rm guest/out/rootfs-base.{ext4,erofs} guest/out/Image guest/out/initramfs.cpio.gz`.

## Why sudo?

`build-rootfs.sh` uses `sudo` for four operations, all operating on a scratch directory under `/tmp/safeyolo-rootfs.*`:

1. `umoci unpack` — preserves real uid/gid ownership in the unpacked tree, which `mkfs.ext4 -d` needs to read back cleanly at packaging time.
2. `chroot ... apt-get install` — installs extras (socat, openssh-server, python3-pip, ripgrep, etc.) inside the unpacked tree. Package maintainer scripts need root-in-chroot semantics to mknod device nodes, chown root, and run their own install hooks.
3. `mkfs.erofs` and `mkfs.ext4 -d` on the packaged outputs — reads the root-owned tree.
4. The SafeYolo `rootfs-customize-hook.sh` (mise/gh install, sshd config, agent user creation, apt intercepts) — also needs root-in-chroot for the same reasons as (2).

No persistent host state is modified. Once `out/rootfs-base.{ext4,erofs}` are built and `chown`'d back to you, the `/tmp` tree is cleaned up.

Eliminating sudo entirely would require either a user-namespace chroot (rootless unshare, blocked on Ubuntu 24.04 by `kernel.apparmor_restrict_unprivileged_userns=1`) or `umoci --rootless` + xattr-aware packaging — the former needs a sysctl flip or an AppArmor profile, the latter isn't yet proven against our packaging step. We may add a rootless mode as a flag if there's demand.

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
