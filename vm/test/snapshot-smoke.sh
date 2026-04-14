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
# The agent must use the byoa template (or have no SAFEYOLO_AGENT_CMD)
# and have been run once with --detach so its config-share is populated
# and SAFEYOLO_DETACH=1 keeps guest-init's `exec sleep infinity` path
# alive without network. Setup:
#
#   mkdir -p ~/tmp/snaptest
#   safeyolo agent add snaptest byoa ~/tmp/snaptest --no-run
#   safeyolo agent run --detach snaptest
#   sleep 5
#   safeyolo agent stop snaptest
#
# Agents with an auto-launching CLI (claude-code, openai-codex) will fail
# this test because that CLI exits immediately without network and
# guest-init then powers off the VM, masking snapshot success.
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
    rm -f "$SNAP" "$SNAP.meta.json" "$SNAP.rootfs"
    rm -f "${SNAP2:-/dev/null}" "${SNAP2:-/dev/null}.meta.json" "${SNAP2:-/dev/null}.rootfs"
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

# Helper invocation as a flat command string we expand inline. We can't
# wrap it in a function returning $! via command substitution, because
# command substitution runs in a subshell — the backgrounded helper
# becomes a grandchild of the parent shell, and `wait` can't reap it.
# Inline it so $! refers to a direct child.
HELPER_ARGS=(
    "$HELPER" run
    --kernel "$KERNEL"
    --initrd "$INITRD"
    --rootfs "$ROOTFS"
    --memory 4096 --cpus 4
    --share "$SHARE:config:rw"
    --no-terminal
)

# ---------------------------------------------------------------------------
# Phase 1 — cold-boot + snapshot
# ---------------------------------------------------------------------------
echo "=== PHASE 1: cold-boot + snapshot ==="
rm -f "$SNAP" "$SNAP.meta.json"

"${HELPER_ARGS[@]}" --snapshot-on-signal "$SNAP" </dev/null >/tmp/sytest-helper.log 2>&1 &
HELPER_PID=$!
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

# Force-kill (not graceful) so the guest doesn't fsync/journal-flush
# the rootfs between snapshot and restore. VZ requires the disk image
# to be byte-identical to its state at save time, otherwise restore
# fails with "invalid argument". PR 4 will need to APFS-clone the
# rootfs at snapshot time to handle this for production use.
kill -KILL "$HELPER_PID" 2>/dev/null
wait "$HELPER_PID" 2>/dev/null || true
HELPER_PID=""

# ---------------------------------------------------------------------------
# Phase 2 — restore + liveness via second snapshot
# ---------------------------------------------------------------------------
echo
echo "=== PHASE 2: restore + liveness ==="

SNAP2="/tmp/sytest-${AGENT}-2.snap"
rm -f "$SNAP2" "$SNAP2.meta.json"

# Restore must use the cloned rootfs that was captured at snapshot time
# (the live $ROOTFS may have been modified by the cold-boot helper before
# we killed it — VZ requires byte-identical disk state).
SNAP_ROOTFS="$SNAP.rootfs"
[[ -f "$SNAP_ROOTFS" ]] || { echo "  FAIL: snapshot rootfs clone $SNAP_ROOTFS missing"; exit 1; }

# Build args with overridden --rootfs pointing at the clone.
RESTORE_ARGS=(
    "$HELPER" run
    --kernel "$KERNEL"
    --initrd "$INITRD"
    --rootfs "$SNAP_ROOTFS"
    --memory 4096 --cpus 4
    --share "$SHARE:config:rw"
    --no-terminal
)

"${RESTORE_ARGS[@]}" --restore-from "$SNAP" --snapshot-on-signal "$SNAP2" </dev/null >/tmp/sytest-helper.log 2>&1 &
RESTORE_PID=$!
echo "  restore pid: $RESTORE_PID"
sleep 5

if ! kill -0 "$RESTORE_PID" 2>/dev/null; then
    set +e; wait "$RESTORE_PID"; rc=$?; set -e
    echo "  FAIL: restored helper exited with rc=$rc. Last 20 lines of log:"
    tail -20 /tmp/sytest-helper.log | sed 's/^/    /'
    exit 1
fi
echo "  PASS: restored helper alive"

# Liveness via second snapshot — only succeeds if the VM is actually .running
echo "  sending SIGUSR1 for liveness snapshot..."
kill -USR1 "$RESTORE_PID"
sleep 8

[[ -f "$SNAP2" ]] || { echo "  FAIL: liveness snapshot not written (restored VM not running?)"; tail -10 /tmp/sytest-helper.log | sed 's/^/    /'; exit 1; }
[[ -f "$SNAP2.meta.json" ]] || { echo "  FAIL: liveness sidecar missing"; exit 1; }
echo "  PASS: liveness snapshot $(ls -lh "$SNAP2" | awk '{print $5}') logical / $(du -h "$SNAP2" | awk '{print $1}') physical"

kill -TERM "$RESTORE_PID" 2>/dev/null
wait "$RESTORE_PID" 2>/dev/null || true
RESTORE_PID=""

rm -f "$SNAP2" "$SNAP2.meta.json"

# ---------------------------------------------------------------------------
# Phase 3 — boundary: wrong --memory must reject (exit 75)
# ---------------------------------------------------------------------------
echo
echo "=== PHASE 3: boundary (wrong --memory → exit 75) ==="

set +e
"$HELPER" run \
    --kernel "$KERNEL" --initrd "$INITRD" --rootfs "$SNAP_ROOTFS" \
    --memory 8192 --cpus 4 \
    --share "$SHARE:config:rw" \
    --no-terminal \
    --restore-from "$SNAP" </dev/null 2>&1 | sed 's/^/  /'
RC=${PIPESTATUS[0]}
set -e

if [[ "$RC" != "75" ]]; then
    echo "  FAIL: expected exit 75, got $RC"
    exit 1
fi
echo "  PASS: rejected with exit 75"
