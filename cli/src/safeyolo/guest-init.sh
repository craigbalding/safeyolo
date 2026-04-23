#!/bin/bash
#
# SafeYolo guest-init orchestrator.
#
# Runs the two-phase boot that makes snapshot/restore work:
#
#   1. /safeyolo/guest-init-static   — network, mounts, CA trust, sshd,
#                                       VM-IP discovery. State that's
#                                       identical across every run of
#                                       this agent and therefore snapshottable.
#   2. wait on /safeyolo/per-run-go  — the host's signal that static setup
#                                       has been captured (if capturing) or
#                                       that it's safe to proceed (passthrough
#                                       / restore). Written by the CLI.
#   3. /safeyolo/guest-init-per-run  — hwclock resync, agent.env sourcing,
#                                       agent_token refresh, instructions
#                                       injection, remount ro, launch
#                                       agent. (The agent binary and mise
#                                       are baked into the rootfs at build
#                                       time, not installed per-run.)
#
# The CLI chooses the mode:
#   - passthrough: writes per-run-go into the config share before the VM
#     boots, so the wait completes on the first iteration.
#   - capture: waits for /safeyolo/static-init-done, takes a VM snapshot,
#     then writes per-run-go to unblock the guest.
#   - restore: restores a snapshot (guest wakes up in the wait loop),
#     then writes per-run-go.
#
# Diagnostics: phase-boundary markers are written to /dev/console (the
# only channel that survives a save/restore cycle cleanly — the VirtioFS
# config share becomes unreliable for writes post-resume). A host-side
# console.log captures these. With SAFEYOLO_DEBUG=1 (marker file
# /safeyolo/debug-mode), per-iteration tracing is also emitted.
#
# Served from the VirtioFS config share, not baked into the rootfs, so
# changes here take effect on the next agent run without a rootfs rebuild.
#
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[orch start] pid=$$ date=$(date 2>/dev/null || echo nodate)" > /dev/console 2>/dev/null || true

/safeyolo/guest-init-static

# Tell the host static setup is complete. Best-effort write — if the
# config share is already ro (shouldn't be at this point, but belt and
# braces) we still proceed to the wait and exec per-run.
echo "ready" > /safeyolo-status/static-init-done

# Wait up to ~30s for the host's per-run-go. Timeout is a safety net so
# a crashed CLI doesn't strand us with a running VM and no agent —
# per-run will be executed regardless so the agent at least tries to
# launch. 100ms polling keeps passthrough-mode overhead under 50ms in
# practice (per-run-go is typically pre-written by the CLI).
waited=0
while [ ! -f /safeyolo/per-run-go ] && [ "$waited" -lt 300 ]; do
    # Check the debug-mode marker inside the loop rather than once at
    # startup: on restore the orchestrator resumed from a capture-time
    # snapshot where debug mode may have been off, but the host may have
    # set SAFEYOLO_DEBUG=1 for this restore run — we want the tracing to
    # kick in on the restore side. One extra stat per 100ms is cheap.
    if [ -f /safeyolo/debug-mode ]; then
        echo "[orch t=${waited}]" > /dev/console 2>/dev/null || true
    fi
    sleep 0.1
    waited=$((waited + 1))
done
echo "[orch exit] waited=${waited} per-run-go=$([ -f /safeyolo/per-run-go ] && echo yes || echo no)" > /dev/console 2>/dev/null || true
if [ ! -f /safeyolo/per-run-go ]; then
    echo "Warning: /safeyolo/per-run-go did not appear within 30s, continuing" >&2
fi

# Prefer the tmpfs copy that static staged — it's in the captured memory
# image and thus readable post-restore even when VirtioFS file reads are
# unreliable (as observed: open+read of /safeyolo/guest-init-per-run
# returns ENOENT on some restores, which kills PID 1 via exec failure
# and kernel-panics with "Attempted to kill init").
PER_RUN_SCRIPT=/run/safeyolo/guest-init-per-run
if [ ! -x "$PER_RUN_SCRIPT" ]; then
    PER_RUN_SCRIPT=/safeyolo/guest-init-per-run
fi
echo "[orch exec] $PER_RUN_SCRIPT" > /dev/console 2>/dev/null || true
exec "$PER_RUN_SCRIPT"
