# Guest tools and privilege

## Contents

- [Choose the installation path](#choose-the-installation-path)
- [Opt into project mise configuration](#opt-into-project-mise-configuration)
- [Use guest sudo](#use-guest-sudo)
- [Understand setpriv](#understand-setpriv)
- [Know what persists](#know-what-persists)
- [Retain and restore guest changes](#retain-and-restore-guest-changes)
- [Handle failures](#handle-failures)

## Choose the installation path

Use mise for language runtimes and project CLIs. Its data lives under the
persistent `/home/agent/.mise` tree:

```sh
mise use -g python@3.12
mise use -g node@22
mise use -g npm:typescript
```

SafeYOLO exposes those global tools to login shells, non-interactive shells,
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

The opt-in is command-scoped. `mise-project` clears SafeYOLO's project-config
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

SafeYOLO rootfs images provide passwordless guest sudo. Use `-n` so an old or
incomplete rootfs fails immediately rather than prompting for a nonexistent
password:

```sh
# Debian, Ubuntu, or Kali
sudo -n apt-get update
sudo -n apt-get install -y PACKAGE

# Alpine
sudo -n apk add PACKAGE
```

The sudo policy preserves SafeYOLO's proxy and CA variables, while bundled apt
images also configure apt's own proxy route. Package downloads remain subject
to the normal SafeYOLO policy, budget, and approval flow. A network block is
not evidence that guest root failed; inspect the response before retrying.

Guest root is not host root. It can change the guest rootfs and the writable
mounts already exposed to the agent, including `/workspace`, but it cannot
turn `/safeyolo` writable, expose the host network, or access the host admin
API. Do not use sudo to attempt to disable the proxy or weaken SafeYOLO.

## Understand setpriv

Rootless Linux gVisor mounts its rootfs with `nosuid`, so a conventional
setuid-only sudo transition cannot work there. SafeYOLO installs
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

On Linux, guest uid 0 maps through SafeYOLO's outer user namespace to an
unprivileged subordinate host uid rather than host uid 0. The capability is
therefore a guest usability mechanism, not an additional security boundary or
host privilege.

## Know what persists

The standard Debian guest runs cron and at independently of the harness.
Use ordinary `crontab`, `atq` and `atrm`. Put `safeyolo-job` in entries to read
the current per-run environment, and read Agent API credentials at execution.
See [scheduling recipes](scheduling.md) before submitting work. The scheduler
log is `/var/log/safeyolo-scheduling.log`.

`/home/agent` and `/workspace` persist across ordinary stop/run cycles. mise
installs therefore persist. Keep task-authored code and retained data in the
assigned workspace folder, including scripts, downloads, configuration, analysis
and working files. Tool installations and runtime caches can remain in persistent
home.

`/tmp` is ephemeral and may be a RAM-backed filesystem. Do not rely on its contents
surviving a sandbox restart or recovery. Use a workspace-local `scratch/` directory
for task working files and direct retained outputs there explicitly. If recovering
misplaced files, copy and verify them before updating references; avoid moving live
browser/runtime state or repeating actions with uncertain external effects.

OS-package persistence is platform-dependent:

- Hardware microVMs normally retain package changes in their per-agent overlay.
- Linux gVisor discards rootfs package changes on stop in both overlay modes.
  Per-agent package-download caches persist, so repeated installs reuse downloads.
- Ephemeral or snapshot modes may intentionally discard later changes.

Do not rely on a native package being present in a future run unless the task
controls the relevant image or startup provisioning.

## Retain and restore guest changes

The standard Debian image records package requests and observations, selected
configuration contents and etckeeper history under
`/home/agent/.local/state/safeyolo-guest`. The private directory has mode 0700.
The existing guest sudo capability gives access to sensitive captured files;
do not publish their contents. Use secret references in task/setup notes.
Keep useful tool checks and setup purpose alongside the retained work.

The `safeyolo-guest-state` command uses the staged native guest helper and
noninteractive guest sudo. After startup or a selected guest upgrade, inspect
recovery state before ordinary work:

```sh
safeyolo-guest-state status
safeyolo-guest-state restore
```

`status` reports the originating and actual base identities, baseline knowledge,
coverage, watcher liveness, the last completed capture and failures. `state.json`
is the machine-readable package/configuration record. `history` lists
configuration commits; the private `configuration` directory contains the
captured files and etckeeper ownership/permission metadata. Use Git there when
specific contents/history need inspection. Do not paste private diffs into
room messages or public issues.

Each startup pauses capture until the agent checks restoration. This also
protects retained changes when gVisor recreates the same base. A new base cannot
silently replace the record. The shipped baseline covers `/etc` and
`/usr/local/etc`. If the original baseline is absent, `baseline_known` is false;
the discovered contents remain recovery information for review. Added paths
outside those default locations also have no original baseline. Their contents
are local recovery inputs, not established base defaults.

`restore` previews missing package actions and configuration changes. It compares
local changes with the old baseline and the actual files. If a new-base file
conflicts, the command preserves the retained copy and reports its path. Review
that file and reconcile the necessary local edit against the current default.
After editing the actual file, `resolve /absolute/file` retains that reviewed
resolution without replacing other saved files. Deletions can be resolved the
same way. Then preview restoration again.
Resolve unavailable packages, sources, pins and holds through their existing
owners. Inspect the actual installed state before retrying an interrupted
operation. After resolving the reported needs, apply the plan:

```sh
safeyolo-guest-state restore --apply
```

The command reuses satisfactory packages. It does not copy an old dpkg database
or execute historical commands. It verifies restored configuration metadata.
Verify the task's actual tools/configuration with its normal checks before
reporting readiness. A completed recovery record is not security assurance or
additional maintenance, guest or network authority. A denied download uses the
existing approval/policy flow. A failed restore remains unresolved work.

When an authorized maintenance decision supplies a Debian package constraint,
retain it independently of observations. For example, inside a Debian Trixie
guest, this records a minimum package version and an advisory reference:

```sh
safeyolo-guest-state require example-package ge 2.0 debian:trixie advisory:example
```

Use the actual package, Debian version, distribution and approved reference.
A base-provided older version does not satisfy that record. A satisfactory new
base avoids installation. A conflicting hold/pin or unavailable candidate is a
blocker. `forget PACKAGE` removes an adopted requirement only when the relevant
authority changes it. Capturing an install does not adopt a vulnerability policy
or freeze every dependency to its previous version.

To capture application configuration outside `/etc`, choose an actual
configuration directory. For an application using `/opt/example/config`:

```sh
safeyolo-guest-state paths add /opt/example/config
safeyolo-guest-state paths
safeyolo-guest-state capture
safeyolo-guest-state history
```

Inspect the resulting private copy at `configuration/opt/example/config`.
`paths remove /opt/example/config` stops future coverage. Coverage settings
persist in the record. Track configuration, not binaries, caches, logs or bulk
data. Generated SafeYOLO proxy settings, runtime identities/credentials and the
recorder's own bookkeeping are excluded. Symlinks are recorded without following
them. Restoration refuses a symlink parent rather than writing through it.

APT hooks retain planned package actions before execution. Direct dpkg hooks
retain invocation/status observations. Filesystem events also capture standalone
selection changes such as `apt-mark hold`. A post-hook is not exit-status proof:
`post_seen_exit_status_unknown` records exactly that limit. An absent post-hook
is reported as `interrupted_or_post_hook_absent` after the process exits.
Requested choices, observed packages and explicitly adopted requirements have
separate fields. The record retains the latest 16 transaction observations.

The watcher coalesces filesystem events for one second and serializes captures
with package transactions. It captures direct writes, atomic replacement,
deletions and metadata changes without a shutdown hook or periodic root scan.
Busy transactions and file copies can extend the uncommitted window. An
immediate kill can lose edits that have not completed capture. Check
`last_completed_capture`, `capture_error` and `watch_alive`; use explicit
`capture` after preparation when the next action may force-stop the guest.
Capture failures do not claim a completed checkpoint or block package commands.
The record's `configuration_commit` identifies the last completed history.
Recovery discards partial working-mirror copies and reads that completed snapshot.
Actual application files are preserved until an explicit restoration applies.

This integration requires the updated Debian image and matching staged helper.
Custom image authors may install etckeeper and use the shared
`install_safeyolo_guest_state` assembly function, then run
`/usr/local/lib/safeyolo/guest-state-base` at the end of image customization.
The baseline must precede runtime-generated identities. Other distributions keep
their own package mechanisms. If the harness cannot start, use existing operator
diagnostics/recovery; there is no separate pre-harness repair service.

## Handle failures

Start with a noninteractive capability check:

```sh
command -v sudo
sudo -n id -u
```

The expected output is `0`. If the command is missing, prompts for a password,
reports a setuid/nosuid error, or cannot find `/usr/bin/setpriv` on Linux, the
agent likely uses an older or incomplete rootfs. Report the exact error and
ask the operator to rebuild the image with the current SafeYOLO guest helper.

`agent shell` has no guest-root flag. `agent recover` runs a fixed health
probe through PID 1 as the ordinary guest account, without SSH. It cannot repair
a broken sudo helper or provide guest-root access. Rebuilding the guest image
is not a remedy for proxy policy, approval, or budget blocks.
