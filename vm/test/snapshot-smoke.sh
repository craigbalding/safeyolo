#!/usr/bin/env bash
#
# Snapshot/restore smoke test for the safeyolo-vm helper.
#
# Validates the PR-1 primitives end-to-end:
#   - cold-boot + SIGUSR1 → snapshot file + sidecar
#   - restore from snapshot → process stays alive
#   - liveness via second SIGUSR1 → second snapshot succeeds
#   - boundary: wrong --memory → exit 75 (fingerprint mismatch)
#
# Uses --no-terminal mode so vsock connection state doesn't interfere
# (the restored guest's vsock-term-attached agent would exit on
# connection drop, taking the VM down with it — that's a test artifact,
# not a snapshot bug). Verification is host-side only.
#
# Usage:
#   bash vm/test/snapshot-smoke.sh <agent-name>
#
# The agent must already exist with a populated config-share — e.g.
# `safeyolo agent run --detach <name> && safeyolo agent stop <name>`
# bootstraps both the rootfs and the config-share files.
#
set -euo pipefail
set -m  # job control: enables reliable kill of bg jobs

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

SNAP1="/tmp/sytest-${AGENT}-1.snap"
SNAP2="/tmp/sytest-${AGENT}-2.snap"
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
    rm -f "$SNAP1" "$SNAP1.meta.json" "$SNAP2" "$SNAP2.meta.json"
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

# Common helper invocation. Caller appends snapshot/restore flags.
run_helper() {
    "$HELPER" run \
        --kernel "$KERNEL" \
        --initrd "$INITRD" \
        --rootfs "$ROOTFS" \
        --memory 4096 --cpus 4 \
        --share "$SHARE:config:rw" \
        --no-terminal \
        "$@"
}

# ---------------------------------------------------------------------------
# Phase 1 — cold-boot + snapshot
# ---------------------------------------------------------------------------
echo "=== PHASE 1: cold-boot + snapshot ==="
rm -f "$SNAP1" "$SNAP1.meta.json"

run_helper --snapshot-on-signal "$SNAP1" &
HELPER_PID=$!
echo "  helper pid: $HELPER_PID"
echo "  waiting 15s for guest boot..."
sleep 15

if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    echo "  FAIL: helper exited during boot"
    exit 1
fi

echo "  sending SIGUSR1..."
kill -USR1 "$HELPER_PID"
sleep 8

[[ -f "$SNAP1" ]] || { echo "  FAIL: $SNAP1 not written"; exit 1; }
[[ -f "$SNAP1.meta.json" ]] || { echo "  FAIL: $SNAP1.meta.json not written"; exit 1; }
echo "  PASS: snapshot $(ls -lh "$SNAP1" | awk '{print $5}') logical / $(du -h "$SNAP1" | awk '{print $1}') physical"

# Stop the cold-boot helper before phase 2
kill -TERM "$HELPER_PID"
wait "$HELPER_PID" 2>/dev/null || true
HELPER_PID=""

# ---------------------------------------------------------------------------
# Phase 2 — restore + liveness check via second snapshot
# ---------------------------------------------------------------------------
echo
echo "=== PHASE 2: restore + liveness ==="
rm -f "$SNAP2" "$SNAP2.meta.json"

run_helper --restore-from "$SNAP1" --snapshot-on-signal "$SNAP2" &
RESTORE_PID=$!
echo "  restore pid: $RESTORE_PID"
sleep 5

if ! kill -0 "$RESTORE_PID" 2>/dev/null; then
    echo "  FAIL: helper exited after restore (check stderr for snapshot errors)"
    exit 1
fi
echo "  PASS: restored helper alive"

# Liveness via second snapshot — only succeeds if the VM is actually .running.
echo "  sending SIGUSR1 to test liveness..."
kill -USR1 "$RESTORE_PID"
sleep 8

[[ -f "$SNAP2" ]] || { echo "  FAIL: liveness snapshot not written (restored VM not running?)"; exit 1; }
[[ -f "$SNAP2.meta.json" ]] || { echo "  FAIL: liveness snapshot has no sidecar"; exit 1; }
echo "  PASS: liveness snapshot $(ls -lh "$SNAP2" | awk '{print $5}') logical / $(du -h "$SNAP2" | awk '{print $1}') physical"

kill -TERM "$RESTORE_PID"
wait "$RESTORE_PID" 2>/dev/null || true
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
    --no-terminal \
    --restore-from "$SNAP1" 2>&1 | sed 's/^/  /'
RC=$?
set -e

if [[ "$RC" != "75" ]]; then
    echo "  FAIL: expected exit 75, got $RC"
    exit 1
fi
echo "  PASS: rejected with exit 75"
