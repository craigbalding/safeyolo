# Rootfs scripts

Rootfs scripts let you replace SafeYolo's default Debian-trixie base rootfs
with one you build yourself — Kali, Alpine, Fedora, Arch, whatever distro
publishes an OCI image or rootfs tarball. SafeYolo invokes them via:

```sh
safeyolo agent add <name> <folder> \
    --rootfs-script path/to/my-rootfs-builder.sh
```

The script is a plain shell script. Read it, edit it, run it on any Linux
box to reproduce what SafeYolo would run. No DSL, no templates.

## Why this is safe to skip for most users

You don't need `--rootfs-script` unless you actually want a different
distro. The default base (Debian trixie with `mise` plus a compact
agent-oriented Unix toolkit) covers the
common agent workflows and ships with SafeYolo. Reach for a rootfs-script
when you're building something specialised — a pentest toolbox, a
scientific-Python stack with native libs, a minimal shell over a weird
distro.

## The contract

Your script is called with these env vars set:

| Variable | Meaning |
|---|---|
| `SAFEYOLO_AGENT_NAME` | Instance name passed to `agent add`. |
| `SAFEYOLO_ROOTFS_OUT_EXT4` | Absolute path where the script must write the **ext4** image (set when the host running SafeYolo is macOS). Not set on Linux. |
| `SAFEYOLO_ROOTFS_OUT_TREE` | Absolute path where the script must populate the **unpacked rootfs tree** as a directory (set when the host is Linux). gVisor reads it as OCI root.path. Not set on macOS. |
| `SAFEYOLO_ROOTFS_WORK_DIR` | Guaranteed-empty scratch directory. Write intermediates here; SafeYolo cleans it up. |
| `SAFEYOLO_GUEST_SRC_DIR` | Absolute path to the repo's `guest/` directory. Contains `safeyolo-guest-init` and `install-guest-common.sh`. |
| `SAFEYOLO_TARGET_ARCH` | `arm64` or `amd64`. Your script must pull or build binaries for this arch. |
| `SAFEYOLO_ROOTFS_OUT_CACHE_PATHS` | Absolute path of a host-side file where the script declares per-distro package cache dirs (one absolute in-rootfs path per line, e.g. `/var/cache/apt`). SafeYolo bind-mounts each path to a persistent per-agent dir so runtime `apt install` / `apk add` doesn't re-download on restart. Write an empty file if the distro has no cache worth persisting. |

Exactly one of `_OUT_EXT4` / `_OUT_TREE` is set per invocation — the
others of the two match what the target runtime needs. Write your
script to handle whichever is set (see the examples).

Exit `0` → SafeYolo validates the expected output file exists, is non-empty,
and uses it for the agent. Non-zero → SafeYolo aborts `agent add`, prints
your stderr, and does not persist agent config. Fix the script and re-run
with `--force`.

## What the rootfs must contain

SafeYolo boots the rootfs you produce, bypassing the distro's own init.
What's required:

1. **`/usr/local/bin/safeyolo-guest-init`** — exec'd as PID 1 on macOS
   (via the initramfs `switch_root`) and as the OCI entrypoint on Linux.
   Handed over to by SafeYolo's boot orchestrator.
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
   - `ca-certificates` (trust store — SafeYolo's MITM CA is appended at
     boot by `guest-init-static`)
   - `shadow` or equivalent (provides `useradd` + `usermod`; the latter
     is used to unlock the agent account so OpenSSH accepts pubkey auth
     — Alpine's OpenSSH refuses locked accounts even for pubkey)

   Optional:
   - `python3` — only needed if you want `safeyolo agent shell <name>
     -- python3 /safeyolo/guest-diag` (an interactive egress-chain
     diagnostic). Nothing on the boot path depends on Python any more.

Everything else (systemd, SELinux policy, unit files, distro-specific
boot choreography) is ignored because our init runs instead of the
distro's.

### The helper library

`guest/install-guest-common.sh` installs the SafeYolo guest bits into an
unpacked rootfs tree. Source it from your script:

```sh
source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
install_safeyolo_guest_common /path/to/unpacked/rootfs
```

This installs:

- `agent` user (uid 1000, shell `/bin/bash`, home `/home/agent`)
- `/usr/local/bin/safeyolo-guest-init`
- sshd pubkey-only config + host keys (for `safeyolo agent shell`)
- `/etc/profile.d/00-path.sh` + `/etc/environment` PATH glue so `sshd` and
  other `sbin` tools are visible in non-login shells
- mise profile glue at `/etc/profile.d/mise.sh` (if `mise` is in the tree)
- BusyBox-backed `hexdump` / `nc` shims (if BusyBox is in the tree)
- `apt` / `apt-get` / `yum` / `dnf` / `apk` intercepts pointing to mise
  (agents must not install packages at runtime; egress doesn't go through
  the SafeYolo proxy)
- hostname = `safeyolo`

The helper is idempotent — safe to re-run.

## Minimal example

See `contrib/alpine-minimal/build-alpine-rootfs.sh` — ~60 lines, pulls an
Alpine OCI image with `skopeo`, unpacks with `umoci`, adds the same small
agent-facing toolkit as the default base with `apk add`, calls
`install_safeyolo_guest_common`, packs to the
requested format. The Kali pentest example
(`contrib/kali-pentest/build-kali-rootfs.sh`) follows the same shape with
more packages.

## Building on macOS (Lima)

macOS can't natively build Linux rootfs images — `mmdebstrap`,
`umoci unpack`, `mkfs.erofs`, and `mkfs.ext4` are all Linux-only syscalls
or binaries. SafeYolo handles this transparently by invoking your script
inside a Lima VM (the same `safeyolo-builder` VM that `guest/build-all.sh`
uses for the default base).

One-time setup:

```sh
brew install lima
```

The Lima VM is created on first `agent add --rootfs-script` run (or first
`guest/build-all.sh`) and pre-provisioned with `skopeo`, `umoci`,
`mmdebstrap`, `e2fsprogs`, `erofs-utils`, plus the kernel-build toolchain.
Your script runs inside that VM with the script directory and the target
agent directory mounted in. Output images land on the macOS host via the
bind mount.

Linux hosts skip Lima entirely and run the script natively.

## Tooling cheat sheet, by approach

| You want… | Tools | Example |
|---|---|---|
| Any distro with an OCI image | `skopeo` + `umoci` | Alpine, Kali examples in `contrib/` |
| Debian / Ubuntu / Kali from scratch | `mmdebstrap` | `guest/build-rootfs.sh` |
| Arch Linux | `pacstrap` | User-supplied |
| Fedora / RHEL / Rocky | `dnf --installroot` | User-supplied |
| Alpine from upstream tarball | `curl` + `tar` | alt. to skopeo path |
| Anything truly custom | your shell, your rules | |

All produce a rootfs tree; the packaging tail (`install_safeyolo_guest_common`
+ `mkfs.ext4` / `mkfs.erofs`) is identical regardless of origin.

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

Rootfs scripts run on `safeyolo agent add`. Re-running with `--force`
reruns the script. Make yours reproducible: pin image digests, tool
versions, and git commit hashes so two builds produce byte-comparable
rootfs.

## Using an agent to write rootfs scripts

Writing a rootfs script for a new distro is a good use of an existing
SafeYolo agent. Share this guide and the existing examples
(`contrib/alpine-minimal/`, `contrib/kali-pentest/`) with it and ask:

> Write a rootfs script for Arch Linux that pulls the official bootstrap
> tarball, uses `pacstrap` to install base + curl + git, sources
> `install-guest-common.sh`, and packs to ext4/erofs.

Review the script, save it in `contrib/<distro>/`, and wire it in via
`--rootfs-script`.

## Security note

The script runs with your permissions on your Linux host, or as root inside
your Lima VM. That's fine when the script is yours or from a source you
trust. Don't run rootfs scripts from strangers without reading them — same
rule as any shell script, with the added sharp edge that rootfs scripts
routinely invoke package managers and download tool binaries.
