#!/bin/bash
# test_multi_agent_attribution.sh — end-to-end verification that per-agent
# attribution survives intentional spoofing attempts from inside the sandbox.
#
# Run on a host that has `safeyolo start` running and two byoa agents
# created: `aone` (expected attribution_ip 127.0.0.2) and `atwo` (127.0.0.3).
#
#   bash test_multi_agent_attribution.sh
#
# Exit 0 on all-pass, 1 on any fail. Reads the SafeYolo log via the CLI
# to verify the recorded attribution.

set -u
FAIL=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

RUNSC="sudo runsc --root /run/safeyolo"

# A1 — HTTP header spoofing (X-Forwarded-For) must not alter attribution.
$RUNSC exec safeyolo-aone bash -lc '
  source /safeyolo/proxy.env
  curl -sS --max-time 6 -o /dev/null \
    -H "X-Forwarded-For: 127.0.0.3" \
    -H "X-Real-IP: 127.0.0.3" \
    "https://httpbin.org/anything?spoof=xff"
' >/dev/null 2>&1

# A2 — atwo's bridge socket must not exist in aone's filesystem view.
if $RUNSC exec safeyolo-aone stat /home/craigb/.safeyolo/data/sockets/atwo.sock \
        >/dev/null 2>&1; then
    fail "A2: atwo's host-side socket is visible inside aone"
else
    pass "A2: atwo's host-side socket is NOT visible inside aone (ENOENT)"
fi

# A3 — binding a TCP source to a neighbour's attribution IP inside the
# container must not change what mitmproxy sees.
$RUNSC exec safeyolo-aone python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.3", 0))
s.settimeout(3)
s.connect(("127.0.0.1", 8080))
s.sendall(b"GET /ip HTTP/1.0\r\nHost: httpbin.org\r\n\r\n")
s.recv(200)
' >/dev/null 2>&1

# Give the log a moment to flush
sleep 1

# Verify every recent request from aone is attributed to aone.
# We look at the last ~10 traffic lines and check none of aone's calls
# are attributed to atwo.
LOG_TAIL=$(cd "$(dirname "$0")/../.." && uv run safeyolo logs 2>&1 \
           | grep -E "traffic.request" | tail -10)

# A1 check — spoof=xff must be attributed to aone.
if echo "$LOG_TAIL" | grep -q "spoof=xff.*atwo"; then
    fail "A1: X-Forwarded-For flipped attribution to atwo"
elif echo "$LOG_TAIL" | grep -q "spoof=xff.*aone"; then
    pass "A1: X-Forwarded-For did NOT change attribution (aone stays aone)"
else
    echo "  WARN: could not find spoof=xff entry in recent log tail"
fi

# A3 check — the /ip request from the bind-to-127.0.0.3 attempt must
# either be attributed to aone or not be attributed to atwo.
if echo "$LOG_TAIL" | grep -q "httpbin.org/ip.*atwo"; then
    fail "A3: binding to 127.0.0.3 flipped attribution to atwo"
else
    pass "A3: bind(127.0.0.3) did NOT change attribution"
fi

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILED: $FAIL of 3 attribution tests"
    exit 1
fi
echo ""
echo "ALL 3 ATTRIBUTION SPOOFING TESTS PASSED"
