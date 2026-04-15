# VZ save/restore diagnostic scripts

These scripts exist to diagnose weird behavior in Apple Virtualization.framework's
`saveMachineStateTo` / `restoreMachineStateFrom` and how our guest-init scripts
interact with it. They're not run in CI and aren't part of the normal test
surface — they're here for the next time someone hits a VZ quirk.

None of them modify the repo. They all operate on an existing agent's on-disk
state (`~/.safeyolo/agents/<name>/`) and write diagnostic output to `/tmp/`.

## Enabling debug mode

Most of these scripts, and the `SAFEYOLO_RESTORE_SKIP_MARKER` bypass they rely
on, require `SAFEYOLO_DEBUG=1` in the host environment. Without it the bypass
is refused (the env var is gated so production runs can't accidentally ship a
release that skipped its readiness check). Setting `SAFEYOLO_DEBUG=1` also
tells `prepare_config_share` to write `/safeyolo/debug-mode` into the guest,
which unlocks per-iteration `[orch t=N]` tracing on `/dev/console`.

## Scripts

### `restore-debug.sh <agent>`

Captures a fresh snapshot, then runs a normal restore while tailing
`serial.log` across the CLI's fallback-to-cold-boot truncation. Dumps the
captured output plus the guest's `console.log` at the end.

Use when: you want to see the full guest-side log stream of a failing restore,
across both the failed-restore helper and the fallback-capture helper that the
CLI automatically runs after.

### `restore-layers.sh <agent>`

Captures, then restores with the `per-run-started` gate bypassed
(`SAFEYOLO_DEBUG=1 SAFEYOLO_RESTORE_SKIP_MARKER=1`), then probes the restored
guest layer-by-layer via SSH (network), rootfs access, virtiofs access, etc.
Tells you which subsystem actually survived the restore.

Use when: the guest comes up post-restore but doesn't do anything observable,
and you want to know whether network / virtiofs / rootfs / processes are
alive. Interpretation guide is printed at the end.

### `restore-hypothesis.sh <agent>`

Compares two teardown paths between capture and restore:

- **A**: `kill -9` the helper (no guest shutdown writes).
- **B**: `safeyolo agent stop` → graceful SIGTERM → guest shutdown → helper exit.

Use when: you suspect graceful shutdown is dirtying the rootfs clone in a way
that breaks the subsequent restore. (We used this in PR #136 development;
answer turned out to be no, it wasn't graceful shutdown.)

## Channels that survive save/restore — what to probe with what

Hard-won understanding from PR #136 dev:

| Channel | Post-restore state | Use as diagnostic |
|---|---|---|
| Serial console (`/dev/console` → `console.log`) | Reliable | Primary diagnostic channel. Phase boundary markers already write here. |
| Rootfs (ext4 block device) | Reliable | Exec, read, write all work. |
| tmpfs in guest | Reliable (part of memory image) | Use to stash anything that must be re-used post-restore. |
| Network (feth → virtio-net) | Reliable if MAC pinned | SSH works. `VZVirtioNetworkDeviceConfiguration.macAddress` must match save-time MAC. |
| VirtioFS (`/safeyolo`, `/workspace`) | **Partially broken** | `stat`/dentry works, `open+read` is unreliable, `>>` redirects from bash can fail with ENOENT. Don't exec virtiofs paths. Don't rely on writes from the pre-snapshot orchestrator process. |
| Memory balloon | Apparently fine in practice | Despite VirtualBox having documented issues with balloon + save/restore, we haven't observed VZ breakage. Left attached. |

## Historical context

These scripts caught three non-obvious bugs that PR #136's original design
would've shipped silently:

1. `VZGenericMachineIdentifier` defaults to random-per-process → pin in
   sidecar and restore. (Fixed earlier, PR #133.)
2. `VZVirtioNetworkDeviceConfiguration.macAddress` same — random per
   process → pin in sidecar. (Fixed in PR #136.)
3. `exec /safeyolo/<script>` fails post-restore with exit 127 → PID 1 dies
   → kernel panic. Work around by staging the script into tmpfs during
   static (pre-snapshot) and exec'ing from there. (Fixed in PR #136.)
