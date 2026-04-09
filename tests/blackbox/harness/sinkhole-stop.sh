#!/bin/bash
# Stop the sinkhole server.
set -e

PID_FILE="$HOME/.config/safeyolo-test/sinkhole.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "Sinkhole not running (no PID file)"
    exit 0
fi

pid=$(cat "$PID_FILE")
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    echo "Sinkhole stopped (PID $pid)"
else
    echo "Sinkhole already dead (PID $pid)"
fi
rm -f "$PID_FILE"
