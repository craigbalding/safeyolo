#!/bin/bash
# test_proxy_bridge.sh — verify proxy_bridge.py daemon works standalone.
#
# Bridge is packaged inside the safeyolo CLI; this test runs the daemon
# mode directly (python3 -m safeyolo.proxy_bridge <sock> <host:port>)
# and proves:
#   1. It binds the UDS path
#   2. It forwards TCP bidirectionally to the upstream
#   3. It cleans up on SIGTERM
#
# Usage: bash test_proxy_bridge.sh

set -u

WORK_DIR="${HOME}/uds-networking-test/bridge-test"
SOCK="$WORK_DIR/proxy.sock"
UPSTREAM_PORT=18890
BRIDGE_LOG="$WORK_DIR/bridge.log"
ECHO_LOG="$WORK_DIR/echo.log"

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

cleanup() {
    kill $BRIDGE_PID 2>/dev/null
    kill $ECHO_PID 2>/dev/null
    wait 2>/dev/null
    rm -f "$SOCK"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"
rm -f "$SOCK" "$BRIDGE_LOG" "$ECHO_LOG"

# --- TCP echo server (simulates mitmproxy) ---
python3 -c "
import socket, threading, sys
def handle(c):
    data = c.recv(4096)
    c.sendall(b'ECHO:' + data)
    c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $UPSTREAM_PORT))
s.listen(4)
print('echo ready', flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
" > "$ECHO_LOG" 2>&1 &
ECHO_PID=$!
sleep 0.3

# --- Bridge daemon ---
# Run the daemon script directly. In production it's invoked as
# `python3 -m safeyolo.proxy_bridge`; here we run the file standalone
# which exercises the same `__main__` entrypoint without needing the
# package to be installed.
BRIDGE_SCRIPT="${HOME}/uds-networking-test/proxy_bridge.py"
python3 "$BRIDGE_SCRIPT" "$SOCK" "127.0.0.1:$UPSTREAM_PORT" > "$BRIDGE_LOG" 2>&1 &
BRIDGE_PID=$!
sleep 0.5

# --- Test 1: socket exists and is a UDS ---
if [ -S "$SOCK" ]; then
    pass "bridge created UDS at $SOCK"
else
    fail "bridge did not create socket"
    cat "$BRIDGE_LOG"
    exit 1
fi

# --- Test 2: client connects through UDS, gets echoed reply ---
REPLY=$(python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect('$SOCK')
s.sendall(b'HELLO_FROM_CLIENT')
data = s.recv(200)
s.close()
print(data.decode(errors='replace'))
" 2>&1)
if echo "$REPLY" | grep -q "ECHO:HELLO_FROM_CLIENT"; then
    pass "UDS -> TCP forward works ($REPLY)"
else
    fail "bridge did not forward correctly ($REPLY)"
    cat "$BRIDGE_LOG"
fi

# --- Test 3: concurrent clients ---
CLIENT_PIDS=()
for i in 1 2 3; do
    python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect('$SOCK')
s.sendall(b'CLIENT_${i}')
print(s.recv(200).decode(errors='replace'))
s.close()
" &
    CLIENT_PIDS+=("$!")
done
for p in "${CLIENT_PIDS[@]}"; do
    wait "$p"
done
pass "concurrent clients completed"

# --- Test 4: clean shutdown on SIGTERM ---
kill -TERM $BRIDGE_PID
sleep 0.5
if kill -0 $BRIDGE_PID 2>/dev/null; then
    fail "bridge still running after SIGTERM"
else
    pass "bridge stopped on SIGTERM"
fi
if [ ! -e "$SOCK" ]; then
    pass "bridge cleaned up its socket on shutdown"
else
    fail "socket still exists after shutdown"
fi

# === Results ===
echo ""
echo "=== RESULTS ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Bridge log:"
    cat "$BRIDGE_LOG"
    exit 1
fi
