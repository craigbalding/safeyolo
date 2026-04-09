#!/bin/bash
# Start the sinkhole server as a background process.
# Writes PID to ~/.config/safeyolo-test/sinkhole.pid for cleanup.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PID_DIR="$HOME/.config/safeyolo-test"
PID_FILE="$PID_DIR/sinkhole.pid"
LOG_FILE="$PID_DIR/sinkhole.log"

mkdir -p "$PID_DIR"

# Kill existing sinkhole if running
if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "Stopping existing sinkhole (PID $old_pid)..."
        kill "$old_pid" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

nohup python3 "$REPO_ROOT/tests/blackbox/sinkhole/server.py" \
    --http-port 18080 \
    --https-port 18443 \
    --control-port 19999 \
    --cert "$REPO_ROOT/tests/blackbox/certs/sinkhole.crt" \
    --key "$REPO_ROOT/tests/blackbox/certs/sinkhole.key" \
    > "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"
echo "Sinkhole started (PID $(cat "$PID_FILE"), log: $LOG_FILE)"
