#!/usr/bin/env bash
#
# Diagnostic: bypass the per-run-started gate on restore so the CLI
# accepts any helper-stays-alive-for-3s as success, then probe the
# restored guest layer-by-layer to work out what actually survived.
#
# Each probe targets a different plane:
#
#   echo        — SSH + shell responds at all
#   date        — rootfs binaries + process exec
#   ls /safeyolo       — VirtioFS config share
#   ls /workspace      — VirtioFS workspace share
#   ls /home/agent     — rootfs (unless host-cfg mounts added there)
#
# Any probe that times out points to the subsystem whose save/restore
# state didn't propagate across processes.
#
# Usage:
#   bash vm/test/restore-layers.sh <agent-name>
#
set -uo pipefail

AGENT="${1:-}"
if [[ -z "$AGENT" ]]; then
    echo "Usage: $0 <agent-name>" >&2
    exit 64
fi

BASE=~/.safeyolo/agents/$AGENT
PROBE_TIMEOUT=5

probe() {
    local label="$1"
    local cmd="$2"
    local t0 t1 rc
    t0=$(date +%s.%N)
    local out
    out=$(timeout "$PROBE_TIMEOUT" safeyolo agent shell "$AGENT" -c "$cmd" 2>&1)
    rc=$?
    t1=$(date +%s.%N)
    local dt
    dt=$(awk -v s="$t0" -v e="$t1" 'BEGIN{printf "%.2f", e-s}')

    local verdict
    if [[ $rc -eq 124 ]]; then
        verdict="TIMEOUT (${dt}s)"
    elif [[ $rc -eq 0 ]]; then
        verdict="OK (${dt}s)"
    else
        verdict="EXIT $rc (${dt}s)"
    fi
    printf "  %-24s  %s\n" "$label" "$verdict"
    if [[ -n "$out" ]]; then
        printf "    %s\n" "$(echo "$out" | head -3 | tr '\n' ' ' | sed 's/[[:space:]]\+$//')"
    fi
}

echo "=== Step 1: clean slate + fresh capture ==="
safeyolo agent stop "$AGENT" 2>/dev/null
rm -rf "$BASE"/snapshot.*
safeyolo agent run --detach "$AGENT" || { echo "capture failed"; exit 1; }
safeyolo agent stop "$AGENT"
if [[ ! -f "$BASE/snapshot.bin" ]]; then
    echo "FAIL: no snapshot.bin after capture"
    exit 1
fi
echo "  snapshot.bin: $(ls -lh "$BASE/snapshot.bin" | awk '{print $5}')"

echo
echo "=== Step 2: restore with per-run-started gate bypassed ==="
# Gate is only honored when SAFEYOLO_DEBUG=1 — both must be set together.
SAFEYOLO_DEBUG=1 SAFEYOLO_RESTORE_SKIP_MARKER=1 safeyolo agent run --detach "$AGENT" || {
    echo "CLI returned non-zero"
}

# Confirm the helper is actually alive before probing.
if ! safeyolo agent stop "$AGENT" --help >/dev/null 2>&1; then
    :  # noop; just use the CLI
fi
PID=$(cat "$BASE/vm.pid" 2>/dev/null || echo "")
if [[ -z "$PID" ]] || ! kill -0 "$PID" 2>/dev/null; then
    echo "FAIL: helper not alive after restore; nothing to probe."
    exit 1
fi
echo "  helper pid: $PID — alive"

echo
echo "=== Step 3: probe restored guest (each probe has ${PROBE_TIMEOUT}s timeout) ==="
probe "ssh echo"            'echo SSH_OK'
probe "rootfs date/uname"   'date -u; uname -r'
probe "rootfs ls /home"     'ls /home/agent'
probe "virtiofs /safeyolo"  'ls /safeyolo'
probe "virtiofs /workspace" 'ls /workspace'
probe "rootfs tmp-write"    'echo ok > /tmp/probe && cat /tmp/probe'
probe "process list"        'ps -o pid,pcpu,stat,comm 2>/dev/null | head -15 || ps aux | head -15'

echo
echo "=== Step 4: cleanup ==="
safeyolo agent stop "$AGENT"

echo
echo "=== Step 5: console.log (guest-side serial channel) ==="
if [[ -f "$BASE/console.log" ]]; then
    # Serial output contains a lot of kernel boot noise; filter to just
    # our markers plus any kernel errors/warnings that might hint at
    # what's broken post-restore.
    cat "$BASE/console.log" | grep -E '^\[(orch|static|per-run)|panic|Oops|stuck for|sched:' | sed 's/^/  /' || echo "  (no matches)"
    echo
    echo "  (last 20 lines raw, for context:)"
    tail -20 "$BASE/console.log" | sed 's/^/  | /'
else
    echo "  (no console.log — was the helper rebuilt with the serial-to-file patch?)"
fi

echo
echo "=== Interpretation guide ==="
cat <<'EOF'
  All probes OK             → restore is fully functional. The per-run-started
                              marker simply isn't propagating host-side; investigate
                              VirtioFS write ordering / daemon restart, but the VM
                              is usable today.

  ssh OK + rootfs OK +      → VirtioFS save/restore is broken specifically. Switch
  virtiofs TIMEOUT            the readiness signal to a non-VirtioFS channel (ssh
                              probe, vsock, feth-side tcp). Per-run state
                              injection (agent.env etc.) will need a different
                              mechanism on restore — big design question.

  ssh TIMEOUT               → Network plane is also broken. No easy out; the only
                              way forward is either a host-side trigger to the
                              guest via a device that does survive (vsock with
                              guest-side listener started from the memory image)
                              or giving up on save/restore for this stack.
EOF
