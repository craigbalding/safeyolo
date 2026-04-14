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
#                                       agent_token refresh, mise install,
#                                       remount ro, launch agent.
#
# The CLI chooses the mode:
#   - passthrough: writes per-run-go into the config share before the VM
#     boots, so the wait completes on the first iteration.
#   - capture: waits for /safeyolo/static-init-done, takes a VM snapshot,
#     then writes per-run-go to unblock the guest.
#   - restore: restores a snapshot (guest wakes up in the wait loop),
#     then writes per-run-go.
#
# Served from the VirtioFS config share, not baked into the rootfs, so
# changes here take effect on the next agent run without a rootfs rebuild.
#
set -e
export DEBIAN_FRONTEND=noninteractive

/safeyolo/guest-init-static

# Tell the host static setup is complete. Best-effort write — if the
# config share is already ro (shouldn't be at this point, but belt and
# braces) we still proceed to the wait and exec per-run.
echo "ready" > /safeyolo/static-init-done 2>/dev/null || true

# Wait up to ~30s for the host's per-run-go. Timeout is a safety net so
# a crashed CLI doesn't strand us with a running VM and no agent —
# per-run will be executed regardless so the agent at least tries to
# launch. 100ms polling keeps passthrough-mode overhead under 50ms in
# practice (per-run-go is typically pre-written by the CLI).
waited=0
while [ ! -f /safeyolo/per-run-go ] && [ "$waited" -lt 300 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
if [ ! -f /safeyolo/per-run-go ]; then
    echo "Warning: /safeyolo/per-run-go did not appear within 30s, continuing" >&2
fi

exec /safeyolo/guest-init-per-run
