# Guest tools and privilege

## Contents

- [Choose the installation path](#choose-the-installation-path)
- [Opt into project mise configuration](#opt-into-project-mise-configuration)
- [Use guest sudo](#use-guest-sudo)
- [Understand setpriv](#understand-setpriv)
- [Know what persists](#know-what-persists)
- [Handle failures](#handle-failures)

## Choose the installation path

Use mise for language runtimes and project CLIs. Its data lives under the
persistent `/home/agent/.mise` tree:

```sh
mise use -g python@3.12
mise use -g node@22
mise use -g npm:typescript
```

SafeYolo exposes those global tools to login shells, non-interactive shells,
harness commands, and Linux `runsc exec` without loading repository-local
`mise.toml` or `.tool-versions` files. A plain tool invocation and a plain
`mise` command therefore stay on the persistent global toolset even when the
current workspace contains untrusted project mise configuration.

Use the distro package manager for native libraries, headers, daemons, desktop
programs, and other system dependencies. On Alpine, prefer its musl-native
Node.js package over asking mise to compile Node from source.

## Opt into project mise configuration

Use `mise-project` when you deliberately want the current repository's mise
configuration:

```sh
mise-project install
mise-project exec -- COMMAND ARG...
mise-project run TASK
mise-project use TOOL@VERSION
```

The opt-in is command-scoped. `mise-project` clears SafeYolo's project-config
discovery guards only for that child process, while preserving the proxy, CA,
and persistent mise directory environment. Review and trust the repository
configuration before opting in; later ordinary commands remain global-only.

This behavior relies on the pinned mise release's early-init settings:

```sh
MISE_OVERRIDE_CONFIG_FILENAMES=/etc/safeyolo/mise-project-config-disabled.toml
MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none
```

The first replaces normal local config discovery with an absent path under
rootfs-owned `/etc`; the second disables `.tool-versions` discovery. Do not
unset them for an ordinary command. Use `mise-project` as the tested opt-in
path instead.

## Use guest sudo

SafeYolo rootfs images provide passwordless guest sudo. Use `-n` so an old or
incomplete rootfs fails immediately rather than prompting for a nonexistent
password:

```sh
# Debian, Ubuntu, or Kali
sudo -n apt-get update
sudo -n apt-get install -y PACKAGE

# Alpine
sudo -n apk add PACKAGE
```

The sudo policy preserves SafeYolo's proxy and CA variables, while bundled apt
images also configure apt's own proxy route. Package downloads remain subject
to the normal SafeYolo policy, budget, and approval flow. A network block is
not evidence that guest root failed; inspect the response before retrying.

Guest root is not host root. It can change the guest rootfs and the writable
mounts already exposed to the agent, including `/workspace`, but it cannot
turn `/safeyolo` writable, expose the host network, or access the host admin
API. Do not use sudo to attempt to disable the proxy or weaken SafeYolo.

## Understand setpriv

Rootless Linux gVisor mounts its rootfs with `nosuid`, so a conventional
setuid-only sudo transition cannot work there. SafeYolo installs
`/usr/local/bin/sudo`, which uses the agent's existing `CAP_SETUID` and
`CAP_SETGID` through `/usr/bin/setpriv`, then delegates argument parsing to the
distro's `/usr/bin/sudo`:

```sh
setpriv --reuid=0 --regid=0 --clear-groups COMMAND
```

That direct form is useful for diagnosing the Linux gVisor path; use `sudo -n`
for routine work. `sudo` is cross-platform, preserves the configured
environment, and falls through to ordinary distro sudo in a hardware microVM.
The direct setpriv transition is expected to fail in a hardware microVM.

On Linux, guest uid 0 maps through SafeYolo's outer user namespace to an
unprivileged subordinate host uid rather than host uid 0. The capability is
therefore a guest usability mechanism, not an additional security boundary or
host privilege.

## Know what persists

`/home/agent` and `/workspace` persist across ordinary stop/run cycles. mise
installs therefore persist. OS-package persistence is platform-dependent:

- Hardware microVMs normally retain package changes in their per-agent overlay.
- Linux gVisor discards rootfs-overlay changes when the sandbox stops. Its
  per-agent apt/apk download caches persist, so reinstalling is faster but
  still necessary.
- Ephemeral or snapshot modes may intentionally discard later changes.

Do not rely on a native package being present in a future run unless the task
controls the relevant image or startup provisioning.

## Handle failures

Start with a noninteractive capability check:

```sh
command -v sudo
sudo -n id -u
```

The expected output is `0`. If the command is missing, prompts for a password,
reports a setuid/nosuid error, or cannot find `/usr/bin/setpriv` on Linux, the
agent likely uses an older or incomplete rootfs. Report the exact error and
ask the operator to rebuild the image with the current SafeYolo guest helper.

`safeyolo agent shell AGENT --root` is an operator-mediated recovery route for
repairing a broken guest helper. It is not required for routine package
installation and is not a remedy for proxy policy, approval, or budget blocks.
