# Rootfs scripts

Rootfs scripts replace SafeYolo's default Debian-trixie base rootfs with a
custom distribution. The source can be an Open Container Initiative (OCI)
image or a rootfs tarball. Prepare the custom image on a Linux builder with the shell inputs below,
then supply the result to an installed instance. The CLI does
not run a Python rootfs builder or accept the retired --rootfs-script flag.
Existing shell builders and guest support files remain usable.
The default builder resolves the current official Debian Trixie index and
freezes each architecture manifest by digest for that build. Its `DEBIAN_IMAGE` override remains available for
contributor builds. Only a digest-pinned registry input emits `build-base.txt`
for default-guest OCI publication. Kali records both its declared pinned input
and the architecture manifest actually unpacked.
Use a digest-only Docker reference for a pinned override: skopeo 1.18.0 rejects
references that combine a tag and digest.

## Why this is safe to skip for most users

The standard Debian-trixie image includes mise, `fd-find` with an `fd` command,
`gh`, Git, curl, SSH client/server support, guest `sudo`, and BusyBox-backed
`nc` and `hexdump` commands. It keeps the required Debian base packages and
runtime dependencies. Install project language runtimes through mise.

Inside an agent, use `mise use -g python@3.12` for Python or
`mise use -g ripgrep` for `rg`. Mise installs live in the persistent agent home.
For compilers and system libraries, use guest `sudo -n apt-get update` followed
by `sudo -n apt-get install -y build-essential pkg-config`. Linux uses a
per-agent directory overlay by default. With `--ephemeral`, unpacked OS
packages disappear on stop. Their download cache remains, so a later
installation repeats unpacking. A custom rootfs can include packages when
that repeated work is costly.

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
| `SAFEYOLO_ROOTFS_OUT_EXT4` | Absolute path where the script must write the **ext4** image for the macOS VZ runtime. The build runs on Linux, including a Linux builder VM on macOS. |
| `SAFEYOLO_ROOTFS_OUT_TREE` | Absolute path where the script must populate the **unpacked rootfs tree** for Linux gVisor. gVisor reads it as OCI root.path. |
| `SAFEYOLO_ROOTFS_WORK_DIR` | An empty disk-backed scratch directory owned by this build; clean it after the command finishes. |
| `SAFEYOLO_GUEST_SRC_DIR` | Absolute path to the source checkout's `guest/` directory. Contains `rootfs/safeyolo-guest-init`, `rootfs/safeyolo-sudo`, and `install-guest-common.sh`. |
| `SAFEYOLO_TARGET_ARCH` | `arm64` or `amd64`. Your script must pull or build binaries for this arch. |
| `SAFEYOLO_ROOTFS_BASE` | The profile runner's declared pinned registry input, without `docker://`. Kali uses this value ahead of its direct-shell `KALI_IMAGE` override. |
| `SAFEYOLO_ROOTFS_OUT_CACHE_PATHS` | Absolute path of a host-side file where the script declares per-distro package cache dirs (one absolute in-rootfs path per line, e.g. `/var/cache/apt`). SafeYolo bind-mounts each path to a persistent per-agent dir so runtime `apt install` / `apk add` doesn't re-download on restart. Write an empty file if the distro has no cache worth persisting. |

Exactly one output variable is set for each invocation:

- For macOS VZ, `SAFEYOLO_ROOTFS_OUT_EXT4` names the ext4 image to create.
- For Linux gVisor, `SAFEYOLO_ROOTFS_OUT_TREE` names the unpacked directory tree to
  populate.

Handle both branches if the script supports both host platforms. Always create
`SAFEYOLO_ROOTFS_OUT_CACHE_PATHS`; write an empty file when no package cache
should persist.

Both Alpine examples select Alpine 3.22 and its matching `main` and `community`
repositories. Do not upgrade a 3.20 tree by adding newer repositories.
The minimal variant supplies the common developer tools. The browser variant
also includes Chromium and the desktop packages.

For example, from the trusted source checkout on a matching-architecture Linux
builder, prepare an Alpine tree for a fresh installation. Install `skopeo`,
`umoci`, curl, tar and coreutils first. The builder uses sudo for unpacking,
chroot package installation and output ownership. The Alpine builders pass
configured `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`
and `no_proxy` values to APK explicitly, so build-host sudo can reset its
ordinary environment. If the build environment sets
`SSL_CERT_FILE` to a readable certificate file, the Alpine builders use a
temporary copy for HTTPS package downloads. They remove the copy before
packaging and on package-install failure. Select the architecture for
the actual runtime and keep host inputs separate from agent-writable files:

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
Supply `--platform-assets "$work/platform"` to the installer. The
Linux boot owner requires the installation's selected subordinate UID/GID
mapping and host-traversable bind targets. The Alpine examples emit the
canonical 100000 mapping. Kali's reusable workflow below preserves original
guest IDs until export, then uses the shared ownership preparation code.
Do not replace a tree in use by a running sandbox.

For a per-agent custom tree, prepare `ROOT/agents/NAME/rootfs` while that agent
is stopped; `host_boot.rs` selects it before the shared default.
On macOS the existing VM owner selects `ROOT/agents/NAME/rootfs.ext4` before
`ROOT/share/rootfs-base.ext4`. Build ext4 on Linux using OUT_EXT4 rather than
OUT_TREE and provide the matching kernel/initramfs as ordinary platform inputs.
These paths reuse boot selection and introduce no automatic conversion.

## Optional desktop

The Alpine browser and Kali builders include Xvfb, x11vnc, a window manager
and pinned noVNC web assets. The installed `safeyolo-guest` executable supplies
the bridge, so these builders do not install websockify or the distro noVNC
metapackage. An operator's Python applications and OS packages remain usable.

For another desktop-capable rootfs, install Xvfb, x11vnc, fluxbox or openbox,
`setsid` and `pkill` with that distribution's package manager. Before completing
the image, run this command from the matching source checkout on the Linux
builder. `TREE` is the stopped image's unpacked rootfs and `CACHE` is a
disk-backed download directory owned by the build; the command needs write
access to both:

```sh
bash guest/install-novnc-assets.sh "$TREE" "$CACHE"
```

This verifies noVNC 1.6.0 and installs its pages, JavaScript, images and license
notices under `/usr/share/novnc`. It excludes upstream launchers and build/test
tools. It does not install an interpreter or start a service. Supply the finished
image to the installation as described above, then start the agent.
On the host, open its authenticated desktop with `safeyolo agent present NAME`.
Inside that guest, `/safeyolo/guest-desktop check` reports missing inputs and
`/safeyolo/guest-desktop status` reports display, VNC and bridge readiness.

## What the rootfs must contain

SafeYolo boots the rootfs without the distribution's init system. The rootfs
must meet these requirements:

1. **`/usr/local/bin/safeyolo-guest-init`** — SafeYolo's boot orchestrator
   executes this file as process ID 1. On macOS, the initramfs reaches it through
   `switch_root`. On Linux, the OCI entrypoint executes it directly.
2. **Compatible guest executables** — boot stages `safeyolo-guest`;
   first-party host setups stage `safeyolo-coord` in the agent home. Current
   source builds link both guest helpers statically with musl. Earlier
   glibc-built helpers do not automatically load on Alpine. Test the installed
   guest executables as well as the image's shell and packages.
3. **The right architecture** — use `$SAFEYOLO_TARGET_ARCH` to pull the
   matching image or bootstrap the right package set.
4. **These runtime packages**, which SafeYolo's boot scripts rely on:
   - `bash` (shebang on our init stubs + default shell)
   - `socat` 1.8+ (used by `guest-proxy-forwarder` and
     `guest-shell-bridge`; the 1.8 release added `VSOCK-LISTEN` /
     `VSOCK-CONNECT`, which these pumps require on macOS. Debian trixie,
     Alpine 3.22, Fedora 40+, Arch, and RHEL 9 all ship ≥ 1.8.)
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

   Alpine 3.22 splits these tools into separate packages. Install `setpriv`
   for `/bin/setpriv` and `util-linux-misc` for `prlimit`. BusyBox's
   `setpriv` lacks the UID and GID options that the sudo shim needs.

   Additional project tools can be installed in the guest. Boot,
   control, terminal, Coord and diagnostics do not require a Python package.
   Use `safeyolo agent diagnostics NAME` on the host for the owned hops.

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

`install_safeyolo_mise` uses the same current-stable resolver as the default
builder. The Linux build host needs Python 3.11+ and GnuPG. The helper verifies
the official signed checksum before installation. An existing mise executable
does not skip resolution. Set `GUEST_INPUTS` to an explicit frozen build record
to reuse its identities; resolution or verification errors fail the build.

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

See `contrib/alpine-minimal/build-alpine-rootfs.sh`. It pulls an
Alpine OCI image with `skopeo`, unpacks with `umoci`, adds the same small
agent-facing toolkit as the default base with `apk add`, calls
`install_safeyolo_guest_common`, packs to the
requested format. The Kali pentest example
(`contrib/kali-pentest/build-kali-rootfs.sh`) follows the same shape with
more packages.

Both Alpine examples accept an `ALPINE_IMAGE` override. On the Linux builder,
set it to `oci:/absolute/path/to/layout:tag` to reuse an acquired Alpine 3.22
image for the selected architecture. Skopeo copies that input instead of
pulling the default registry tag. Package installation still uses the image's
Alpine repositories.

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
prepared kernel and initramfs. `agent add` does not invoke a custom
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

### Cached Kali builds

On an owned Linux builder, run these commands from the source checkout as
your ordinary account. Install skopeo, umoci, curl, Python 3.11+, GnuPG,
unzip, tar, and coreutils first. The selected architecture needs native
execution or configured binfmt support. Keep the existing proxy and CA
environment. Use disk-backed storage with room for the Kali base, package
installation, completed output and later exports.

Resolve mise once into a frozen record, then build the declared profile:

```sh
python3 guest/resolve_inputs.py resolve --tools mise --output "$HOME/kali-inputs.json"
python3 guest/build_profile.py --profile contrib/kali-pentest/profile.json \
  --architecture amd64 --guest-inputs "$HOME/kali-inputs.json" \
  --cache "$HOME/kali-profiles" > "$HOME/kali-build.json"
```

The result records `key`, `assets` and `cache_hit`. Repeat the second command
with the same inputs: `cache_hit` becomes `true`, and apt, image acquisition
and third-party installers do not run. `--force` performs a fresh build and
selects it only after success. Previous successful paths remain usable by
their readers. Changing the declared profile, architecture, output kind,
script/helper/assets, source modes or resolved input record changes the key.
This is completed-build reuse; upstream package snapshots and intermediate
build-stage resume are not provided.

The runner copies declared files before hashing and executing them. The
selected shell builder still owns command-scoped privilege and cleanup.
Kali uses a clean chroot PATH and UTF-8 locale, configured proxy variables
and a temporary copy of the build CA. It removes apt's temporary proc/sys/dev
mounts before unprivileged installers, which receive only null/zero/random/
urandom device binds. It removes those binds, placeholders and the build CA
before output. Signals run the same exit cleanup. An unmount or cleanup
failure prevents cache admission and leaves the unpublished work path in
stderr for diagnosis. Verify mounts are gone before removing failed work.
A chroot remains build plumbing, not isolation.

### Export and install

The completed Kali cache tree retains original guest ownership. Export a new
consumer directory instead of changing the cached tree. On Linux, use a
`safeyolo` executable built from this source revision. Set `SAFEYOLO_CLI` to
its absolute path. Set `HOST_BUNDLE` to a verified unpacked host package for
the consumer platform and compatible guest generation.
Host preparation explains its host changes and requests narrowly scoped
sudo; it writes the actual allocation for your account. Run on the consumer
host with the completed tree available:

```sh
KALI_BUILD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"])' "$HOME/kali-build.json")
"$SAFEYOLO_CLI" --root "$HOME/kali-instance" host prepare \
  --package-root "$HOST_BUNDLE" --installed-root "$HOME/kali-instance" \
  --write-settings "$HOME/kali-host.toml"
guest/export-profile.sh --build "$KALI_BUILD" --platform linux/amd64 \
  --output "$HOME/kali-platform" --native-cli "$SAFEYOLO_CLI" \
  --host-settings "$HOME/kali-host.toml"
./scripts/install_native.sh --bundle "$HOST_BUNDLE" --root "$HOME/kali-instance" \
  --platform-assets "$HOME/kali-platform"
```

Ownership preparation preserves distinct guest users, modes, links, access
control lists (ACLs) and extended attributes. Export without `--host-settings`
to obtain the canonical Linux archive mapping for publication. The OCI
installer remaps that archive to each consuming account's actual allocation.
Keep publication exports separate from exports already mapped to one host.

For Linux arm64, use `--architecture arm64` in the build command and
`--platform linux/arm64` in export. For macOS arm64, reuse that successful
arm64 tree on the Linux builder. Install e2fsprogs and export with
`--platform darwin/arm64 --kernel-assets DIRECTORY`; `DIRECTORY` must contain
qualified matching `Image` and `initramfs.cpio.gz`. Export creates a sparse
ext4 image with original guest IDs. Transfer the finished directory with
metadata-preserving tools, then use `--platform-assets` on the Mac. Tart or
a Linux builder can prepare inputs; VZ execution needs a physical Mac.

### Publish and select explicitly

Use the existing [OCI archive and publisher](../docs/guest-oci.md) with
`--profile kali-pentest`. Archive each canonical consumer export with
`guest/archive-default.sh` into its `linux-amd64`, `linux-arm64` or
`darwin-arm64` directory. The publisher records the profile, actual pinned
base and build-input digest. The archive also carries `build-inputs.json`.
Kali supports all three consumers; another custom profile can publish only
its declared supported consumers. Default guest releases still require all
three.

Publication requires the existing repository's authorized GHCR writer.
Keep the verified layout, immutable index digest and successful outputs.
Select that digest explicitly with the bundle installer’s
`--guest-index sha256:DIGEST`, or use `guest upgrade --index sha256:DIGEST`
for an installed instance. The host package must require the profile's
compatibility identifier. Neither path invokes the distro builder.
Stock guest discovery and promotion exclude custom profiles.

Prepared immutable platform assets can be shared by several fresh installations. Linux installations link the same prepared tree and keep each
agent's writable overlay, home, workspace, credentials and caches independent.
For separate custom per-agent trees, an operator can use an ownership-preserving
`sudo cp -a --reflink=auto` on Linux. On APFS use `cp -c` for an ext4 image so
the new file retains independent writes. Stop affected guests before replacing
boot inputs. Installation does not copy another agent's mutable state.

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
