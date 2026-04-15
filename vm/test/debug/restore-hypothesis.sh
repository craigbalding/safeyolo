#!/usr/bin/env bash
#
# Isolates whether graceful (SIGTERM) shutdown between capture and restore
# is what breaks VZ restoreMachineStateFrom, as opposed to SIGKILL which
# the PR 1 snapshot-smoke.sh uses.
#
# Variant A: capture → SIGKILL helper → restore  (what PR 1 smoke test does)
# Variant B: capture → safeyolo agent stop → restore  (what PR 4 CLI does)
#
# If A works and B fails, the CLI's graceful shutdown path is dirtying
# something the restore depends on — investigate live-rootfs writes vs
# the APFS clone, or VZ state the graceful path perturbs.
#
# If both fail, the problem is elsewhere (capture itself, something in
# PR 2/3 that PR 1 smoke doesn't exercise).
#
# If both succeed, the race in CLI polling is masking a real issue
# somewhere else — unlikely given the serial.log evidence, but possible.
#
# Usage:
#   bash vm/test/restore-hypothesis.sh <agent-name>
#
# Requires the named agent to already have been bootstrapped with a
# byoa-style template (see snapshot-smoke.sh docstring).

set -uo pipefail

AGENT="${1:-}"
if [[ -z "$AGENT" ]]; then
    echo "Usage: $0 <agent-name>" >&2
    exit 64
fi

BASE=~/.safeyolo/agents/$AGENT

run_variant() {
    local label="$1"
    local teardown="$2"   # "sigkill" or "stop"

    echo
    echo "════════════════════════════════════════════════════════════════"
    echo " VARIANT: $label  (teardown: $teardown)"
    echo "════════════════════════════════════════════════════════════════"

    # Fresh state
    safeyolo agent stop "$AGENT" 2>/dev/null
    rm -rf "$BASE"/snapshot.*
    rm -f "$BASE"/serial.log

    echo
    echo "--- capture ---"
    if ! safeyolo agent run --detach "$AGENT"; then
        echo "FAIL: capture run failed"
        tail -20 "$BASE/serial.log" 2>/dev/null | sed 's/^/  /'
        return 1
    fi

    if [[ ! -f "$BASE/snapshot.bin" ]]; then
        echo "FAIL: snapshot.bin not created"
        tail -20 "$BASE/serial.log" 2>/dev/null | sed 's/^/  /'
        return 1
    fi
    echo "  snapshot.bin present ($(ls -lh "$BASE/snapshot.bin" | awk '{print $5}'))"
    echo "  snapshot.bin.rootfs present ($(ls -lh "$BASE/snapshot.bin.rootfs" | awk '{print $5}') logical, $(du -h "$BASE/snapshot.bin.rootfs" | awk '{print $1}') physical)"

    echo
    echo "--- teardown: $teardown ---"
    local helper_pid
    helper_pid=$(cat "$BASE/vm.pid" 2>/dev/null || echo "")
    if [[ -z "$helper_pid" ]]; then
        echo "FAIL: no vm.pid after capture"
        return 1
    fi

    if [[ "$teardown" == "sigkill" ]]; then
        # Kill the helper abruptly — no graceful shutdown, no live-rootfs
        # flush. Closest match to PR 1 snapshot-smoke.sh Phase 1.
        kill -KILL "$helper_pid" 2>/dev/null
        # Give the kernel a moment to reap before we poke anything else
        for _ in {1..20}; do
            kill -0 "$helper_pid" 2>/dev/null || break
            sleep 0.05
        done
        # Clean up PID file + feth-bridge since we bypassed safeyolo agent stop
        rm -f "$BASE/vm.pid"
        pkill -f "feth-bridge.*feth[0-9]+" 2>/dev/null
        sleep 1
    else
        # Graceful stop — what the CLI ordinarily does.
        safeyolo agent stop "$AGENT"
    fi

    echo
    echo "--- restore ---"
    local t_start=$(date +%s.%N)
    if safeyolo agent run --detach "$AGENT"; then
        local t_end=$(date +%s.%N)
        local dt=$(awk -v s="$t_start" -v e="$t_end" 'BEGIN{printf "%.2f", e-s}')
        echo "  CLI returned in ${dt}s"

        # Give the helper 2s to commit to restore (or crash)
        sleep 2
        local restore_pid
        restore_pid=$(cat "$BASE/vm.pid" 2>/dev/null || echo "")
        if [[ -n "$restore_pid" ]] && kill -0 "$restore_pid" 2>/dev/null; then
            echo "  RESULT: helper ALIVE 2s after restore — looks SUCCESSFUL"
            echo
            echo "--- liveness check: ssh command ---"
            if safeyolo agent shell "$AGENT" -c 'mount | grep " on /safeyolo "; echo TOKEN:$(stat -c %Y /app/agent_token 2>/dev/null)' 2>&1 | sed 's/^/  /'; then
                echo "  SSH OK"
            else
                echo "  SSH FAILED (helper alive but VM/ssh not working)"
            fi
            safeyolo agent stop "$AGENT" >/dev/null 2>&1
            echo "  → $label: PASS"
            return 0
        else
            echo "  RESULT: helper DEAD 2s after restore — FAILED"
        fi
    else
        echo "  CLI returned non-zero"
    fi

    echo
    echo "--- serial.log tail ---"
    tail -30 "$BASE/serial.log" 2>/dev/null | sed 's/^/  /'
    echo "  → $label: FAIL"
    return 1
}

A_RC=0
B_RC=0
run_variant "A (SIGKILL between capture and restore)" "sigkill" || A_RC=$?
run_variant "B (safeyolo agent stop between capture and restore)" "stop" || B_RC=$?

echo
echo "════════════════════════════════════════════════════════════════"
echo " SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo "  Variant A (SIGKILL):       $([[ $A_RC -eq 0 ]] && echo PASS || echo FAIL)"
echo "  Variant B (agent stop):    $([[ $B_RC -eq 0 ]] && echo PASS || echo FAIL)"
echo
if [[ $A_RC -eq 0 && $B_RC -ne 0 ]]; then
    echo "  → Graceful shutdown breaks restore. The clone is being perturbed"
    echo "    between capture and the next restore attempt, OR VZ state the"
    echo "    graceful path writes to the live rootfs is somehow visible"
    echo "    through the clone. Investigate FileManager.copyItem's APFS"
    echo "    clonefile semantics and what the graceful path flushes."
elif [[ $A_RC -ne 0 && $B_RC -ne 0 ]]; then
    echo "  → Restore fails regardless of teardown path. Not a graceful-"
    echo "    shutdown issue. Likely a capture-side regression since PR 1"
    echo "    smoke test last passed. Compare the VZ config between PR 1's"
    echo "    smoke test (vm/test/snapshot-smoke.sh) and PR 4's CLI path"
    echo "    (start_vm + DarwinPlatform.start_sandbox + extra workspace share)."
elif [[ $A_RC -eq 0 && $B_RC -eq 0 ]]; then
    echo "  → Both variants succeed; the race in polling was masking success."
    echo "    Pull the 1.5s settle wait into the CLI and call it good."
else
    echo "  → Unexpected: SIGKILL failed but graceful succeeded. Investigate."
fi
