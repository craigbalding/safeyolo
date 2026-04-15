#!/usr/bin/env bash
#
# Diagnostic: capture a snapshot, attempt a restore via the CLI, and
# preserve serial.log across the CLI's fallback-to-cold-boot truncation
# by tailing the file in the background. Also reads the orchestrator's
# on-share diagnostic log if the readdir-trick orchestrator wrote one.
#
# Usage:
#   bash vm/test/restore-debug.sh <agent-name>
#
set -uo pipefail

AGENT="${1:-}"
if [[ -z "$AGENT" ]]; then
    echo "Usage: $0 <agent-name>" >&2
    exit 64
fi

BASE=~/.safeyolo/agents/$AGENT
SERIAL_CAPTURE=/tmp/restore-debug-serial.log

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
echo "=== Step 2: start tailing serial.log (captures across CLI truncation) ==="
: > "$SERIAL_CAPTURE"
# -F follows the file through truncation so we capture both the failed
# restore helper's output and any subsequent fallback-helper output.
tail -n +1 -F "$BASE/serial.log" > "$SERIAL_CAPTURE" 2>/dev/null &
TAIL_PID=$!
sleep 0.2   # let tail attach before anything writes

echo
echo "=== Step 3: restore (CLI fallback allowed; tail keeps both logs) ==="
safeyolo agent run --detach "$AGENT"
safeyolo agent stop "$AGENT" 2>/dev/null

# Give tail a beat to flush, then stop it.
sleep 0.3
kill "$TAIL_PID" 2>/dev/null
wait "$TAIL_PID" 2>/dev/null

echo
echo "=== Step 4: serial.log captured across restore + fallback ==="
echo "Written to $SERIAL_CAPTURE"
echo
echo "--- full contents ---"
cat "$SERIAL_CAPTURE" | sed 's/^/  /'

echo
echo "=== Step 5: console.log (guest-side serial channel) ==="
if [[ -f "$BASE/console.log" ]]; then
    echo "--- contents ---"
    cat "$BASE/console.log" | sed 's/^/  /'
else
    echo "  (no console.log — is the serial-to-file redirect in VMConfiguration.swift deployed?)"
fi
