#!/usr/bin/env bash
#
# Snapshot/restore smoke test for the safeyolo-vm helper.
#
# Validates the PR-1 primitives:
#   - cold-boot + SIGUSR1 → snapshot file + sidecar
#   - restore from snapshot → process comes up (alive or graceful exit)
#   - boundary: wrong --memory → exit 75 (fingerprint mismatch)
#
# Runs in vsock-term mode (no --no-terminal). Reason: SIGUSR1 dispatch
# sources don't fire reliably in --no-terminal mode (a known limitation
# of the current main-queue setup; see main.swift). PR 4's CLI
# orchestration uses vsock-term mode so this matches real usage anyway.
#
# Caveat: a snapshot taken AFTER the agent CLI has connected to vsock-term
# captures the live vsock connection state. On restore, the in-guest
# vsock-term sees its old host disappear, exits, guest-init runs poweroff,
# VM stops cleanly. That's a SUCCESSFUL restore (proven by exit 0), just
# with an immediate clean shutdown — fine for mechanism validation.
#
# Usage:
#   bash vm/test/snapshot-smoke.sh <agent-name>
#
# The agent must already exist with a populated config-share — e.g.
# `safeyolo agent run --detach <name> && safeyolo agent stop <name>`.
#
set -euo pipefail
set -m

AGENT="${1:-}"
if [[ -z "$AGENT" ]]; then
    echo "Usage: $0 <agent-name>" >&2
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HELPER="$VM_DIR/.build/release/safeyolo-vm"

if [[ ! -x "$HELPER" ]]; then
    cat >&2 <<EOF
ERROR: $HELPER not found.
Build first:
    cd vm
    swift build -c release
    codesign --entitlements safeyolo-vm.entitlements --force -s - .build/release/safeyolo-vm
EOF
    exit 1
fi

KERNEL="$HOME/.safeyolo/share/Image"
INITRD="$HOME/.safeyolo/share/initramfs.cpio.gz"
ROOTFS="$HOME/.safeyolo/agents/$AGENT/rootfs.ext4"
SHARE="$HOME/.safeyolo/agents/$AGENT/config-share"

for f in "$KERNEL" "$INITRD" "$ROOTFS"; do
    [[ -e "$f" ]] || { echo "missing: $f" >&2; exit 1; }
done
if [[ ! -d "$SHARE" ]]; then
    cat >&2 <<EOF
ERROR: $SHARE not present.
Run the agent once normally to populate the config-share, then re-run this test:
    safeyolo agent run --detach $AGENT
    safeyolo agent stop $AGENT
EOF
    exit 1
fi

SNAP="/tmp/sytest-${AGENT}.snap"
HELPER_PID=""
RESTORE_PID=""

cleanup() {
    local rc=$?
    set +e
    if [[ -n "$HELPER_PID" ]] && kill -0 "$HELPER_PID" 2>/dev/null; then
        kill -TERM "$HELPER_PID" 2>/dev/null
        wait "$HELPER_PID" 2>/dev/null
    fi
    if [[ -n "$RESTORE_PID" ]] && kill -0 "$RESTORE_PID" 2>/dev/null; then
        kill -TERM "$RESTORE_PID" 2>/dev/null
        wait "$RESTORE_PID" 2>/dev/null
    fi
    rm -f "$SNAP" "$SNAP.meta.json"
    if [[ "$rc" -eq 0 ]]; then
        echo
        echo "=== ALL PHASES PASSED ==="
    else
        echo
        echo "=== FAILED (exit $rc) ==="
    fi
    exit $rc
}
trap cleanup EXIT

# Run the helper in vsock-term mode (no --no-terminal). stdin is detached
# (</dev/null) since we're backgrounding and don't want the helper to
# block on terminal input.
run_helper_bg() {
    "$HELPER" run \
        --kernel "$KERNEL" \
        --initrd "$INITRD" \
        --rootfs "$ROOTFS" \
        --memory 4096 --cpus 4 \
        --share "$SHARE:config:rw" \
        "$@" </dev/null >/tmp/sytest-helper.log 2>&1 &
    echo $!
}

# ---------------------------------------------------------------------------
# Phase 1 — cold-boot + snapshot
# ---------------------------------------------------------------------------
echo "=== PHASE 1: cold-boot + snapshot ==="
rm -f "$SNAP" "$SNAP.meta.json"

HELPER_PID=$(run_helper_bg --snapshot-on-signal "$SNAP")
echo "  helper pid: $HELPER_PID"
echo "  waiting 15s for guest boot..."
sleep 15

if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    echo "  FAIL: helper exited during boot. Last 20 lines of helper log:"
    tail -20 /tmp/sytest-helper.log | sed 's/^/    /'
    exit 1
fi

echo "  sending SIGUSR1..."
kill -USR1 "$HELPER_PID"
sleep 8

[[ -f "$SNAP" ]] || { echo "  FAIL: $SNAP not written"; tail -10 /tmp/sytest-helper.log | sed 's/^/    /'; exit 1; }
[[ -f "$SNAP.meta.json" ]] || { echo "  FAIL: $SNAP.meta.json not written"; exit 1; }
echo "  PASS: snapshot $(ls -lh "$SNAP" | awk '{print $5}') logical / $(du -h "$SNAP" | awk '{print $1}') physical"

# Stop the cold-boot helper
kill -TERM "$HELPER_PID" 2>/dev/null
wait "$HELPER_PID" 2>/dev/null || true
HELPER_PID=""

# ---------------------------------------------------------------------------
# Phase 2 — restore (success = restore command didn't error during load)
# ---------------------------------------------------------------------------
echo
echo "=== PHASE 2: restore ==="

RESTORE_PID=$(run_helper_bg --restore-from "$SNAP")
echo "  restore pid: $RESTORE_PID"
sleep 5

# Two acceptable outcomes:
#   (a) helper still alive — restore worked, vsock-term attached
#   (b) helper exited 0 — restore worked, but vsock-term in guest saw the
#       old host disappear, agent exited, guest-init poweroff, VM stopped.
#       Both are successful restores.
# A FAIL is exit 75 (snapshot error) or exit 1 (other error).
if kill -0 "$RESTORE_PID" 2>/dev/null; then
    echo "  PASS: restored helper alive (vsock-term presumably attached)"
    kill -TERM "$RESTORE_PID" 2>/dev/null
    wait "$RESTORE_PID" 2>/dev/null || true
else
    set +e
    wait "$RESTORE_PID"
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
        echo "  PASS: restored helper exited cleanly (vsock disconnect → guest poweroff)"
    else
        echo "  FAIL: restored helper exited with rc=$rc. Last 20 lines of log:"
        tail -20 /tmp/sytest-helper.log | sed 's/^/    /'
        exit 1
    fi
fi
RESTORE_PID=""

# ---------------------------------------------------------------------------
# Phase 3 — boundary: wrong --memory must reject (exit 75)
# ---------------------------------------------------------------------------
echo
echo "=== PHASE 3: boundary (wrong --memory → exit 75) ==="

set +e
"$HELPER" run \
    --kernel "$KERNEL" --initrd "$INITRD" --rootfs "$ROOTFS" \
    --memory 8192 --cpus 4 \
    --share "$SHARE:config:rw" \
    --restore-from "$SNAP" </dev/null 2>&1 | sed 's/^/  /'
RC=$?
set -e

if [[ "$RC" != "75" ]]; then
    echo "  FAIL: expected exit 75, got $RC"
    exit 1
fi
echo "  PASS: rejected with exit 75"
