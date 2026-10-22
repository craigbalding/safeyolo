# SafeYolo Guest Image Builds

For host installation and prepared platform inputs, see the
[installation reference](../cli/README.md#installation). For default guest tools
and custom distributions, see the [rootfs guide](../contrib/ROOTFS_SCRIPT_GUIDE.md).

Builds the artifacts SafeYolo needs to run agent sandboxes:

- `out/Image` — Linux kernel (macOS Virtualization.framework only)
- `out/initramfs.cpio.gz` — minimal initramfs (macOS only)
- `out/rootfs-base.ext4` — Debian trixie base image (macOS VZ mounts this read-only as /dev/vda; runtime writes use a separate overlay)
- `out/rootfs-tree/` — Debian trixie rootfs as an unpacked directory (Linux gVisor uses this as OCI `root.path`; files are owned by uid 100000, the subuid-root for rootless userns)
- `out/cache-paths.txt` — absolute in-rootfs paths SafeYolo bind-mounts to persistent per-agent cache dirs (apt cache, etc.)
- `out/build-base.txt` — the actual digest-pinned Debian manifest used for OCI publication provenance

Every `build-rootfs.sh` run produces **both** the ext4 image and the tree on Linux (natively or inside the Lima VM on macOS). The tree is what gVisor uses on Linux hosts; without it, `safeyolo agent start` fails with a "Rootfs tree not found" error.

Uses `skopeo` and `umoci` to pull and unpack an architecture-specific,
digest-pinned official Debian trixie manifest. Docker is not required.
The kernel uses the native cross-compiler. The builder runs on Linux
(Fedora, Arch, Alpine, Debian or Ubuntu), without mmdebstrap or debootstrap.
The digest pins the OCI build input; packages installed later still use
Debian's signed repositories, rather than a fixed package snapshot.
The skopeo reference uses `docker://docker.io/library/debian@sha256:<digest>`;
combining the `trixie` tag with the digest is not supported by skopeo 1.18.0.

The default guest includes mise, fd, the GitHub CLI (`gh`), Git, curl, SSH
client/server support, and the packages needed for startup, proxy transport,
certificate trust and guest administration. Git is included so `gh repo clone`
and repository checks need no separate Git installation on first use or after
restart. The image includes Git's package size and acquisition cost.

Install language runtimes through mise. Its tools and configuration live in the
persistent agent home. Compilers, Python, Python test packages and optional
development tools are not installed in the default image. Install OS packages
with guest `sudo` when needed, or include them in a custom rootfs. Linux uses
a per-agent directory overlay by default. With `--ephemeral`, unpacked OS
packages disappear on stop and must be installed again; package downloads have
separate persistent caches. The [rootfs guide](../contrib/ROOTFS_SCRIPT_GUIDE.md) explains the
available choices. The blackbox runner installs its own Python test dependencies.

## Quick start

Use a source checkout and the [Linux prerequisites](#linux-setup), or install
Lima on macOS as described below. The builder needs Python 3.11+ and GnuPG for
shared resolution and upstream signature checks. These are builder tools; they
do not add Python to the default guest. If an instance uses earlier build
outputs, choose a new `OUTPUT_DIR` to preserve its referenced tree. On macOS,
`OUTPUT_DIR` must resolve inside `guest/` so the existing narrow Lima mount can
reach it. From the repository root:

```bash
cd guest
./build-all.sh
```

On Linux this runs natively (rootfs only by default; kernel + initramfs are
macOS-microVM artifacts, opted in via `BUILD_KERNEL=1`). On macOS it
auto-shells into a Lima VM (see below).

Each run resolves current stable inputs and builds fresh outputs. The scripts
replace their rootfs, kernel and initramfs outputs; existing files do not skip a
build. Downloads under `out/.download-cache/` are reused only after identity
verification. APT upgrades inherited packages within the signed Trixie suites.
The JSON input record and package/tool origins are retained under `out/provenance/`.
For a deliberate frozen-input build, set `GUEST_INPUTS` to a previously resolved
JSON file. Explicit software versions select official release metadata; they
never act as failure fallbacks. See the [nightly staging and promotion path](../docs/guest-oci.md#prepare-and-publish-a-default-guest-release).

Artifacts land in `guest/out/`. Return to the repository root, then provide
that directory to the installer at a fresh installation. This example
uses `$HOME/.safeyolo`; choose another explicit root if it already contains
instance configuration. It does not change an existing installation:

```sh
./install.sh --root "$HOME/.safeyolo" --runtime-artifacts /usr/bin --platform-assets "$PWD/guest/out"
```

Supply matching guest/VM artifacts as described in the
[build guide](../docs/installation.md#build-a-bundle).
The Ubuntu example uses prepared `/usr/bin/tmux`. On Linux the installer links
the prepared `rootfs-tree` without changing its UID 100000 ownership. Keep the
tree available and immutable for the instance's lifetime. On macOS it clones
Image, initramfs.cpio.gz and rootfs-base.ext4 into the instance's share.
A missing or incorrectly owned tree fails agent start.

## macOS setup

Lima is a Linux VM manager for macOS. Install it with whichever package manager you use:

```bash
# Homebrew (most common on macOS):
brew install lima

# Or MacPorts:
sudo port install lima

# Or mise (if you already manage runtimes with it):
mise use -g lima
```

That's it. The first `./build-all.sh` run creates a Lima VM named `safeyolo-builder` from `guest/lima.yaml` and provisions it with the required build tools (~2-3 min). Subsequent runs reuse the VM.

The same VM is reused by `contrib/ROOTFS_SCRIPT_GUIDE.md` on macOS when you build a custom per-agent rootfs. Its provisioning includes `skopeo` + `umoci` + `e2fsprogs` (for the default base and for custom rootfs scripts — see `contrib/ROOTFS_SCRIPT_GUIDE.md`) plus the kernel toolchain.

### Why Lima

`chroot` and `mkfs.ext4` are Linux-specific. Docker Desktop worked because it's a hidden Linux VM — Lima makes the VM explicit and user-controlled. See `lima.yaml` for the config.

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

Install the build dependencies. `skopeo` + `umoci` pull and unpack the Debian OCI image; `e2fsprogs` packs the ext4 image for macOS consumers. If you only want to run `build-rootfs.sh` (the common path on a Linux host, since the kernel + initramfs are only needed for macOS VZ):

```bash
# Debian/Ubuntu:
sudo apt-get install skopeo umoci e2fsprogs curl jq rsync python3 gnupg

# Fedora/RHEL:
sudo dnf install skopeo umoci e2fsprogs curl jq rsync python3 gnupg

# Arch (umoci via AUR):
sudo pacman -S skopeo e2fsprogs curl jq rsync python3 gnupg
yay -S umoci

# Alpine:
apk add skopeo umoci e2fsprogs curl jq rsync python3 gnupg
```

For a full kernel + initramfs build (`BUILD_KERNEL=1`, or when producing artifacts for macOS consumers), add the kernel toolchain. On Debian/Ubuntu:

```bash
sudo apt-get install \
    skopeo umoci e2fsprogs curl jq rsync python3 gnupg \
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

What each is for (expect a fair number of transitive deps on a fresh Debian install — the `-cross` packages in the suggested-installs list are the arm64 cross-toolchain pulled in by `gcc-aarch64-linux-gnu`, totalling ~170 MB):

- `build-essential`, `gcc-aarch64-linux-gnu` — host gcc + the arm64 cross-compiler for the kernel.
- `bc`, `bison`, `flex` — the Linux kernel's own build tooling requires them (`Kbuild`, DTS/DTB compilation, parser generation).
- `libelf-dev`, `libssl-dev` — kernel modules and signing.
- `busybox-static`, `pax-utils` — initramfs construction (BusyBox provides the userland; `lddtree` from pax-utils walks dynamic deps).
- `cpio`, `xz-utils` — initramfs packaging format.

`build-rootfs.sh` doesn't need a Debian keyring. skopeo fetches the OCI image,
not `.deb` packages. Extra packages, including SSH, Git and socat, are installed
inside the unpacked rootfs through chroot. They use the rootfs's own signed
Debian repositories.

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

- `build-rootfs.sh` — current official Debian Trixie resolved to a digest via `skopeo`, `umoci`, chroot apt and `rootfs-customize-hook.sh`; writes the ext4 image, UID 100000 tree, cache paths and actual build-base reference. `DEBIAN_IMAGE` overrides remain available for contributor builds. Floating tags and non-registry transports do not emit publication provenance. Each invocation builds fresh outputs.
- `archive-default.sh` — on a Linux builder with GNU tar, zstd and guest sudo, archives finished backend files with numeric owners, modes, links, extended attributes and sparse-image handling. Reports compressed bytes, apparent filesystem bytes and allocated disk bytes separately. A sparse ext4 image's apparent size includes its unused capacity. See the [OCI publication instructions](../docs/guest-oci.md#prepare-and-publish-a-default-guest-release).
- `build-kernel.sh` — Linux kernel via native cross-compile (`aarch64-linux-gnu-gcc`)
- `build-initramfs.sh` — minimal initramfs via `busybox-static` + `lddtree`
- `build-all.sh` — platform-aware driver; calls the above three. Must be executed (`./build-all.sh`), not sourced.

All three scripts run on Linux only. On macOS, invoke them through `build-all.sh` which handles the Lima shell-in.

### Generate just the rootfs

```bash
# From the repo root (or `cd guest`):
./guest/build-rootfs.sh
```

This produces `out/rootfs-base.ext4` (for macOS VZ) and `out/rootfs-tree/` (for Linux gVisor) in one pass — `build-rootfs.sh` does not split the two outputs. Re-run after deleting either output to rebuild both.

## Reduced Linux ARM64 guest size

The reduced guest retains Git and SSH client/server support. The
[normal release build](https://github.com/craigbalding/safeyolo/actions/runs/38975155518/job/117222709865)
at guest source `33224c9fc14beeb00be30eb71bdc09f91c5aa58b` produced these
Linux ARM64 sizes:

| Measurement | Bytes | Meaning |
| --- | ---: | --- |
| Compressed payload | 119,728,693 | Complete pax tar archive compressed with zstd; no additional Debian layer |
| Apparent filesystem size | 386,362,719 | Logical size of the rootfs tree and cache-paths file |
| Allocated disk usage | 406,540,288 | Filesystem blocks used by those inputs on the release builder |

Here, MB means 1,000,000 bytes; KiB means 1,024 bytes. The 119.73 MB payload
is about 46% smaller than the approximate 223 MB baseline in
[#1082](https://github.com/craigbalding/safeyolo/issues/1082). It is about
24.11 MB larger than that issue's 95.62 MB experimental prototype, which
omitted Git and Linux SSH. The prototype is a comparison, not a size limit.
SSH remains required on every supported platform, including Linux/gVisor.

### Retained packages and their cost

The retained hosted ARM64 archive uses Debian manifest
`sha256:b55910b579d6eb05ebd79fbc8468b974fa39bb0610d52e1f1390bb2177ab7614`,
mise 2026.8.8 and gh 2.98.0. Its layer digest is
`sha256:234c1b1fb58e58822315bf896fcfaba2618ff0bcb98e73372edcf9dccbd24aad`.
The table below comes from that archive's dpkg metadata and tar entries,
read without extracting or changing the rootfs.

The table groups all 148 installed Debian packages without overlap, using
the package lists in the earlier ordered removal logs.
`Installed-Size` is the sum of Debian's package size estimates in KiB. The
file-byte column sums the files and symlink text at each group's
dpkg-listed paths. It counts each hard-linked file once and excludes
directories and files removed by the build's documentation filter. Neither
column measures compressed download cost or allocated disk usage.

| Retained group | Role | Installed-Size (KiB) | Existing file bytes |
| --- | --- | ---: | ---: |
| Git and dependencies (12 packages) | Git-dependent gh commands and repository work; includes Perl and transfer libraries | 106,022 | 88,992,466 |
| OpenSSH and dependencies (11 packages) | SSH client, server and file transfers; includes Debian's selected systemd dependency | 30,244 | 27,059,223 |
| Ten explicit runtime packages listed below | Network tools, trust, downloads, search, diagnostics and guest administration | 31,055 | 21,828,190 |
| Other 115 base and shared dependency packages | Pinned Trixie base and shared libraries, including libc, shell, account and authentication tools, apt/dpkg and TLS libraries | 155,734 | 105,946,600 |
| mise executable, outside dpkg | Install language runtimes into the persistent agent home | — | 97,464,432 |
| gh executable, outside dpkg | GitHub workflows | — | 38,535,330 |

The ten explicit runtime packages are `ca-certificates` and `curl` for trusted
downloads; `iproute2` for network setup; `procps` for process diagnostics;
`socat` for proxy transport; `sudo` and `util-linux` for guest administration
and privilege helpers; `busybox-static` for applets and shutdown; `xz-utils`
for archive extraction; and `fd-find` for searches through the `fd` helper.
The package rows exclude paths outside dpkg file lists, including the
separately installed mise/gh files and licence notices. They do not total
all rootfs files. SafeYolo uses its own guest init; an installed systemd
dependency does not mean systemd runs as the guest's init.

The three OpenSSH packages at version `1:10.0p1-7+deb13u4` account for
9,020 KiB of package size estimates. The full SSH group is larger because
Debian selected `systemd`, `libsystemd-shared`, `libwtmpdb0`, `libedit2`,
`libfido2-1`, `libcbor0.10`, `runit-helper` and `ucf`. Git version
`1:2.47.3-0+deb13u1` alone accounts for 49,556 KiB. Its group also includes
`git-man`, Perl and the libraries removed with Git in the earlier probe.
Shared dependencies remain in the base/shared group. Git is already in the
payload, so first use and restart need no Git installation. Matched
acquisition-through-first-task timing remains separate evidence.

[Earlier local removal probes](https://github.com/craigbalding/safeyolo/pull/1086)
reported 7,239,959 fewer compressed bytes after removing SSH and unused
dependencies, then another 28,575,705 fewer bytes after removing Git and its
remaining unused dependencies. Those ordered probes reported an
83,913,225-byte remainder. They used a separate local sample, not the later
clean local archive or the hosted archive. The retained removal logs identify
the packages; the disposable probe copies are no longer retained.

The 83.91 MB probe remainder is about 11.71 MB below the prototype. The
prototype figure supplies no matched package inventory or archive settings
for this comparison. The records therefore cannot assign that difference to
specific files or packages. The 24.11 MB total increase over the prototype
must not be presented as the compressed cost of SSH and Git. The package
estimates and file sizes above explain what is retained without claiming
exact compressed attribution to the prototype.

## Download cache

The build scripts keep a persistent cache of upstream downloads under `out/.download-cache/` so rebuilds don't re-fetch:

- `out/.download-cache/oci/` — skopeo OCI image layout for the pinned Debian trixie input. Reusing the layout avoids downloading unchanged blobs.
- `out/.download-cache/linux-<ver>.tar.xz` — kernel source tarball
- `out/.download-cache/mise-<ver>-<arch>.tar.gz` — verified resolved mise release
- `out/.download-cache/gh-<ver>-<arch>.tar.gz` — verified resolved gh CLI release

The chroot package installation downloads Debian packages on each rebuild.
The builder does not preserve apt's archive cache between builds. This differs
from the per-agent runtime package caches.

To flush the cache (forces full re-download): `rm -rf guest/out/`. To flush artifacts but keep the download cache: `sudo rm -rf guest/out/rootfs-base.ext4 guest/out/rootfs-tree guest/out/Image guest/out/initramfs.cpio.gz` (sudo because the tree is owned by uid 100000).

## Why sudo?

`build-rootfs.sh` uses `sudo` for these operations in its owned scratch
directory under `TMPDIR` (or `/var/tmp` by default) and its selected output directory.
The publication workflow sets `TMPDIR` to disk-backed runner storage:

1. `umoci unpack` — preserves real uid/gid ownership in the unpacked tree, which `mkfs.ext4 -d` needs to read back cleanly at packaging time.
2. `chroot ... apt-get install` — installs runtime packages, including socat and openssh-server, inside the unpacked tree. Package maintainer scripts need root-in-chroot semantics to mknod device nodes, chown root, and run their own install hooks.
3. `mkfs.ext4 -d` on the packaged output — reads the root-owned tree.
4. The SafeYolo `rootfs-customize-hook.sh` (mise/gh install, sshd config, agent user creation, apt-proxy config) — also needs root-in-chroot for the same reasons as (2).
5. `chown -R 100000:100000` on the emitted `out/rootfs-tree/` — the tree ships pre-owned by the subuid-root so SafeYolo's rootless gVisor sandbox-root can write to tree paths via the overlay.

The selected output directory retains the finished artifacts and download
cache. The ext4 image is owned by the builder user, and the tree is owned by
UID/GID 100000. The temporary rootfs directory is removed on exit.

Eliminating sudo entirely would require either a user-namespace chroot (rootless unshare, blocked on Ubuntu 24.04 by `kernel.apparmor_restrict_unprivileged_userns=1`) or `umoci --rootless` + xattr-aware packaging — the former needs a sysctl flip or an AppArmor profile, the latter isn't yet proven against our packaging step. We may add a rootless mode as a flag if there's demand.

## Troubleshooting

**`mkfs.ext4: No space left on device`**
During a build, check free space on the build host and whether the staged
content fits the base image. The script defaults to a 2048 MiB ext4 (see
`ROOTFS_SIZE_MB` in `build-rootfs.sh`); override it with
`ROOTFS_SIZE_MB=4096 ./build-rootfs.sh` if you're staging a rootfs script that
adds bulky packages. Alternatively, trim the customize-hook or the extras
apt-installed at the top of `build-rootfs.sh`.
This build setting does not size an agent's writable root overlay or its
mounted home and workspace. See [runtime storage](../docs/microvm-architecture.md#persistence).

**Lima VM won't start**
```bash
limactl delete safeyolo-builder
./build-all.sh   # recreates the VM
```

**Build works on host Linux but not inside Lima**
`limactl shell safeyolo-builder -- bash` to drop into the VM and reproduce manually. Lima's `/build/guest` is the mount point (not `/workspace/safeyolo/guest`).
