# Rootfs scripts

Rootfs scripts replace SafeYolo's default Debian-trixie base rootfs with a
custom distribution. The source can be an Open Container Initiative (OCI)
image or a rootfs tarball. Prepare the custom image on a Linux builder with the shell inputs below,
then supply the result to an installed native instance. The native CLI does
not run a Python rootfs builder or accept the retired --rootfs-script flag.
Existing shell builders and guest support files remain usable.

## Why this is safe to skip for most users

The standard Debian-trixie image includes `ripgrep`, `fd-find`, `file`, `unzip`,
`zip`, `tmux`, `lsof`, `strace`, `jq`, `less`, Python virtual-environment support,
and BusyBox-backed `nc` and `hexdump` shims. Install project language runtimes
through mise.

You don't need a custom rootfs unless you actually want a different
distro. The default base (Debian trixie with `mise` plus a compact
agent-oriented Unix toolkit) covers the
common agent workflows and ships with SafeYolo. Reach for a rootfs-script
when you're building something specialised — a pentest toolbox, a
scientific-Python stack with native libs, a minimal shell over a weird
distro.

## The contract

Run your selected builder with these environment variables. The operator
chooses outputs and owns their temporary work directory and cleanup:

| Variable | Meaning |
|---|---|
| `SAFEYOLO_AGENT_NAME` | Name of the agent for which you prepare the image. |
| `SAFEYOLO_ROOTFS_OUT_EXT4` | Absolute path where the script must write the **ext4** image (set when the host running SafeYolo is macOS). Not set on Linux. |
| `SAFEYOLO_ROOTFS_OUT_TREE` | Absolute path where the script must populate the **unpacked rootfs tree** as a directory (set when the host is Linux). gVisor reads it as OCI root.path. Not set on macOS. |
| `SAFEYOLO_ROOTFS_WORK_DIR` | An empty disk-backed scratch directory owned by this build; clean it after the command finishes. |
| `SAFEYOLO_GUEST_SRC_DIR` | Absolute path to SafeYolo's guest support files: the source checkout's `guest/` directory with matching native guest support. Contains `safeyolo-guest-init`, `safeyolo-sudo`, and `install-guest-common.sh`. |
| `SAFEYOLO_TARGET_ARCH` | `arm64` or `amd64`. Your script must pull or build binaries for this arch. |
| `SAFEYOLO_ROOTFS_OUT_CACHE_PATHS` | Absolute path of a host-side file where the script declares per-distro package cache dirs (one absolute in-rootfs path per line, e.g. `/var/cache/apt`). SafeYolo bind-mounts each path to a persistent per-agent dir so runtime `apt install` / `apk add` doesn't re-download on restart. Write an empty file if the distro has no cache worth persisting. |

Exactly one output variable is set for each invocation:

- On macOS, `SAFEYOLO_ROOTFS_OUT_EXT4` names the ext4 image to create.
- On Linux, `SAFEYOLO_ROOTFS_OUT_TREE` names the unpacked directory tree to
  populate.

Handle both branches if the script supports both host platforms. Always create
`SAFEYOLO_ROOTFS_OUT_CACHE_PATHS`; write an empty file when no package cache
should persist.

For example, from the trusted source checkout on Linux, prepare an Alpine
tree for a fresh native installation. Select the architecture for the actual
runtime and keep host inputs separate from agent-writable files:

```sh
work=$(mktemp -d "$HOME/rootfs-build.XXXXXX")
mkdir -p "$work/scratch" "$work/platform"
SAFEYOLO_AGENT_NAME=work \
SAFEYOLO_TARGET_ARCH=amd64 \
SAFEYOLO_GUEST_SRC_DIR="$PWD/guest" \
SAFEYOLO_ROOTFS_WORK_DIR="$work/scratch" \
SAFEYOLO_ROOTFS_OUT_TREE="$work/platform/rootfs-tree" \
SAFEYOLO_ROOTFS_OUT_CACHE_PATHS="$work/platform/cache-paths.txt" \
  ./contrib/alpine-minimal/build-alpine-rootfs.sh
```

On failure, retain stderr and the build inputs; resolve the cause before retrying. Keep
privileged commands in the foreground and use an EXIT trap for owned mounts.
The builder must return zero and produce the expected nonempty image/tree.
Supply `--platform-assets "$work/platform"` to the native installer. The
existing Linux boot owner requires sandbox-root UID 100000 ownership and
host-traversable bind targets; the maintained builders perform that preparation.
Do not replace a tree in use by a running sandbox.

For a per-agent custom tree, prepare `ROOT/agents/NAME/rootfs` while that agent
is stopped; native `host_boot.rs` selects it before the shared default.
On macOS the existing VM owner selects `ROOT/agents/NAME/rootfs.ext4` before
`ROOT/share/rootfs-base.ext4`. Build ext4 on Linux using OUT_EXT4 rather than
OUT_TREE and provide the matching kernel/initramfs as ordinary platform inputs.
These paths reuse native boot selection and introduce no automatic conversion.

## What the rootfs must contain

SafeYolo boots the rootfs without the distribution's init system. The rootfs
must meet these requirements:

1. **`/usr/local/bin/safeyolo-guest-init`** — SafeYolo's boot orchestrator
   executes this file as process ID 1. On macOS, the initramfs reaches it through
   `switch_root`. On Linux, the OCI entrypoint executes it directly.
2. **A userland that runs on Linux 6.12** — glibc ≥ 2.17 or musl; any
   modern distro from 2018 onwards is fine.
3. **The right architecture** — use `$SAFEYOLO_TARGET_ARCH` to pull the
   matching image or bootstrap the right package set.
4. **These runtime packages**, which SafeYolo's boot scripts rely on:
   - `bash` (shebang on our init stubs + default shell)
   - `socat` 1.8+ (used by `guest-proxy-forwarder` and
     `guest-shell-bridge`; the 1.8 release added `VSOCK-LISTEN` /
     `VSOCK-CONNECT`, which these pumps require on macOS. Debian trixie,
     Alpine 3.20+, Fedora 40+, Arch, and RHEL 9 all ship ≥ 1.8.)
   - `openssh-server` (sshd — entrypoint for `safeyolo agent shell`)
   - `ca-certificates` (trust store — SafeYolo's man-in-the-middle certificate
     authority (CA) certificate is appended at
     boot by `guest-init-static`)
   - `shadow` or equivalent (provides `useradd`, `usermod`, and `groupadd`;
     these create the agent account and its `sudo` supplementary group)
   - `sudo` (the distro implementation used for standard command-line
     semantics and hardware-microVM guest elevation; it must include
     `visudo` so the generated policy can be validated)
   - `setpriv` and `prlimit` from `util-linux` (the SafeYolo sudo shim uses
     the agent's existing namespace capabilities on rootless Linux gVisor;
     PID 1 uses `prlimit` to set the open-file limit on its numeric process)

   Additional project tools can be installed in the guest. Native boot,
   control, terminal, Coord and diagnostics do not require a Python package.
   Use `safeyolo agent diagnostics NAME` on the host for the owned native hops.

Everything else (systemd, SELinux policy, unit files, distro-specific
boot choreography) is ignored because our init runs instead of the
distro's.

### The helper library

`install-guest-common.sh` installs the SafeYolo guest bits into an unpacked
rootfs tree. Source it from your script:

```sh
source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
install_safeyolo_mise /path/to/unpacked/rootfs "$SAFEYOLO_TARGET_ARCH"
install_safeyolo_guest_common /path/to/unpacked/rootfs
```

The helper also pre-creates SafeYolo's host bind-mount destinations before
Linux remaps the finished tree to its subordinate UID range. Custom builders
should not defer creation of `/workspace`, `/safeyolo`, `/safeyolo-status`, or
the CA certificate mount target to agent startup.

Use `install_safeyolo_mise` only for glibc-compatible rootfs trees. Alpine
should install its native musl-linked package instead:

```sh
apk add mise
```

This installs:

- optional pinned `mise` binary via `install_safeyolo_mise`
- `agent` user (uid 1000, shell `/bin/bash`, home `/home/agent`)
- `/usr/local/bin/safeyolo-guest-init`
- sshd pubkey-only config + host keys (for `safeyolo agent shell`)
- `/etc/profile.d/00-path.sh` + `/etc/environment` PATH glue so `sshd` and
  other `sbin` tools are visible in non-login shells
- the conventional `fd` command for Debian's `fdfind`, without replacing an
  existing `fd` binary or link
- global-only mise profile glue at `/etc/profile.d/mise.sh` plus the explicit
  `mise-project` opt-in (if `mise` is in the tree)
- BusyBox-backed `hexdump` / `nc` shims (if BusyBox is in the tree)
- `/usr/local/bin/sudo` compatibility shim and passwordless guest-root policy;
  the installer creates/uses the `sudo` group, adds `agent` to it, writes the
  direct user rule needed by already-running shells, sets `root:root`/0440,
  and validates the policy with `visudo`
- hostname = `safeyolo`

The helper is idempotent — safe to re-run. A custom rootfs that omits the
`sudo` package is explicitly not a sudo-capable image: the compatibility
helper is skipped, so its agents must not be documented as having
`sudo -n`. A rootfs that includes sudo but lacks its validation or account
tools fails during construction rather than producing a partially usable
image. Alpine may conventionally use `wheel`; SafeYolo still provisions the
named `sudo` group so fresh shells have a consistent contract, while the
direct user rule is what makes the capability work in pre-existing shells.

## Minimal example

See `contrib/alpine-minimal/build-alpine-rootfs.sh` — ~60 lines, pulls an
Alpine OCI image with `skopeo`, unpacks with `umoci`, adds the same small
agent-facing toolkit as the default base with `apk add`, calls
`install_safeyolo_guest_common`, packs to the
requested format. The Kali pentest example
(`contrib/kali-pentest/build-kali-rootfs.sh`) follows the same shape with
more packages.

## Building on macOS (Lima)

macOS needs a Linux builder for `umoci unpack`, chrooted apt/apk, and
`mkfs.ext4`. `guest/build-all.sh` creates the narrowly mounted
`safeyolo-builder` Lima VM for the default image.

One-time setup:

```sh
brew install lima
```

Run `guest/build-all.sh` for the default images. For a custom image, run the
selected script explicitly on an owned Linux builder, with the inputs from
this guide. Supply `SAFEYOLO_ROOTFS_OUT_EXT4` for the output image, then transfer
it to the stopped agent's `ROOT/agents/NAME/rootfs.ext4`. Reuse the separately
prepared kernel and initramfs. Native `agent add` does not invoke a custom
script or create a Lima builder.

On Linux, use an owned disk-backed scratch directory and the tree outputs
shown above. The bundled Kali example requests command-scoped `sudo` for
rootful `umoci unpack`, chrooted distro package installation, filesystem
staging, and UID-100000 ownership for rootless gVisor. Downloads and
orchestration remain unprivileged.

## Tooling cheat sheet, by approach

| You want… | Tools | Example |
|---|---|---|
| Any distro with an OCI image | `skopeo` + `umoci` | Alpine, Kali, default Debian examples |
| Debian / Ubuntu / Kali from scratch | `mmdebstrap` | User-supplied (default base switched to skopeo) |
| Arch Linux | `pacstrap` | User-supplied |
| Fedora / RHEL / Rocky | `dnf --installroot` | User-supplied |
| Alpine from upstream tarball | `curl` + `tar` | alt. to skopeo path |
| Anything truly custom | your shell, your rules | |

All produce a rootfs tree; the packaging tail (`install_safeyolo_guest_common`
then either `cp -a` into `$SAFEYOLO_ROOTFS_OUT_TREE` on Linux or
`mkfs.ext4 -d` into `$SAFEYOLO_ROOTFS_OUT_EXT4` on macOS) is identical
regardless of origin.

## Known kernel limitations

The rootfs runs under our kernel (macOS: `guest/defconfig`; Linux: gVisor's
sentry). These features are absent; userspace tools may be present but
will no-op:

- **SELinux / AppArmor / auditd** — no LSM is compiled in. Userspace tools
  report "disabled." Fedora/RHEL rootfs boot fine because our init doesn't
  load policy.
- **Loadable modules** — all drivers are built-in. `modprobe` has nothing
  to do.
- **NFS / CIFS / BTRFS / XFS / loop devices** — missing. Matters only if
  you need these inside the sandbox.

Kernel features can be added in a separate `guest/defconfig` patch if a
custom rootfs legitimately needs them.

## Idempotency

Rootfs scripts run explicitly on the selected builder. Re-run them only
against owned outputs and after their prior command has finished. Make yours reproducible: pin image digests, tool
versions, and git commit hashes so two builds produce byte-comparable
rootfs.

## Reusing a built custom rootfs

Prepared immutable platform assets can be shared by several fresh native
installations. Linux installations link the same prepared tree and keep each
agent's writable overlay, home, workspace, credentials and caches independent.
For separate custom per-agent trees, an operator can use an ownership-preserving
`sudo cp -a --reflink=auto` on Linux. On APFS use `cp -c` for an ext4 image so
the new file retains independent writes. Stop affected guests before replacing
boot inputs. Native installation does not copy another agent's mutable state.

## Using an agent to write rootfs scripts

Writing a rootfs script for a new distro is a good use of an existing
SafeYolo agent. Share this guide and the existing examples
(`contrib/alpine-minimal/`, `contrib/kali-pentest/`) with it and ask:

> Write a rootfs script for Arch Linux that pulls the official bootstrap
> tarball, uses `pacstrap` to install base + curl + git, sources
> `install-guest-common.sh`, and emits either ext4 (`$SAFEYOLO_ROOTFS_OUT_EXT4`)
> or an unpacked tree (`$SAFEYOLO_ROOTFS_OUT_TREE`) depending on which is set.

Review the script, save it in `contrib/<distro>/`, run it on the selected Linux
builder, and install its prepared outputs as described above.

## Security note

Run the custom script with your own permissions on the selected Linux builder.
The script may request privilege itself; the bundled Kali example uses
command-scoped `sudo` rather than
elevating the entire script. Its chrooted distro package manager still executes
signed package maintainer scripts as host root, and `chroot` is not a security
boundary. Downloads from other sources should remain unprivileged and be
staged before privileged installation. Don't run rootfs scripts from strangers
without reading them.
