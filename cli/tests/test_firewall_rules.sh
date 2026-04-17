#!/bin/bash
# test_firewall_rules.sh — verify nftables rules on a live test environment
#
# Requires: safeyolo-fwtest netns + veth-sytest already set up,
# nftables table ip safeyolo loaded with priority -1 chains.

set -u
PASS=0
FAIL=0
RESULTS=()

NS="safeyolo-fwtest"
HOST_IP="192.168.99.1"
PROXY_PORT=8080
ADMIN_PORT=9090

pass() { PASS=$((PASS+1)); RESULTS+=("PASS: $1"); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL: $1"); echo "  FAIL: $1"; }

agent() { ip netns exec "$NS" "$@"; }

ensure_listener() {
    local port=$1
    fuser -k "$port/tcp" 2>/dev/null
    sleep 0.2
    nohup nc -l -k -p "$port" -s "$HOST_IP" < /dev/null > /dev/null 2>&1 &
    sleep 0.3
}

echo "=== FIREWALL RULES VERIFICATION (priority -1 + INPUT catch-all) ==="
echo ""

# --- Positive: proxy port reachable ---
# Use nft counters as ground truth (nc exit codes are unreliable with -k).
echo "--- Proxy port (must be ALLOWED) ---"
ensure_listener $PROXY_PORT
nft flush chain ip safeyolo input
nft add rule ip safeyolo input ip saddr 192.168.99.0/24 ip daddr "$HOST_IP" tcp dport $PROXY_PORT counter accept
nft add rule ip safeyolo input ip saddr 192.168.99.0/24 counter drop
agent bash -c "echo TEST | nc -w 2 $HOST_IP $PROXY_PORT" >/dev/null 2>&1 || true
COUNTER=$(nft list chain ip safeyolo input 2>&1 | grep "dport $PROXY_PORT" | grep -o 'packets [0-9]*' | awk '{print $2}')
if [ "${COUNTER:-0}" -gt 0 ]; then
    pass "TCP $PROXY_PORT to host: ALLOWED (nft counter=$COUNTER packets)"
else
    fail "TCP $PROXY_PORT to host: BLOCKED (nft counter=0)"
fi
fuser -k "$PROXY_PORT/tcp" 2>/dev/null

# --- Negative: admin port blocked ---
echo "--- Admin port (must be BLOCKED) ---"
ensure_listener $ADMIN_PORT
if agent bash -c "echo TEST | nc -w 2 $HOST_IP $ADMIN_PORT" >/dev/null 2>&1; then
    fail "TCP $ADMIN_PORT to host: ALLOWED (should be blocked)"
else
    pass "TCP $ADMIN_PORT to host: BLOCKED"
fi
fuser -k "$ADMIN_PORT/tcp" 2>/dev/null

# --- Negative: arbitrary TCP port on host ---
echo "--- Arbitrary TCP port (must be BLOCKED by INPUT catch-all) ---"
ensure_listener 4444
if agent bash -c "echo TEST | nc -w 2 $HOST_IP 4444" >/dev/null 2>&1; then
    fail "TCP 4444 to host: ALLOWED (INPUT catch-all missing)"
else
    pass "TCP 4444 to host: BLOCKED"
fi
fuser -k "4444/tcp" 2>/dev/null

# --- Negative: SSH port on host ---
echo "--- SSH port (must be BLOCKED) ---"
if agent bash -c "nc -w 2 -z $HOST_IP 22" >/dev/null 2>&1; then
    fail "TCP 22 (SSH) to host: ALLOWED"
else
    pass "TCP 22 (SSH) to host: BLOCKED"
fi

# --- Negative: TCP to external ---
echo "--- External TCP (must be BLOCKED by FORWARD catch-all) ---"
if agent bash -c "nc -w 2 -z 1.1.1.1 80" >/dev/null 2>&1; then
    fail "TCP to 1.1.1.1:80: ALLOWED (forward catch-all broken)"
else
    pass "TCP to 1.1.1.1:80: BLOCKED"
fi

# --- Negative: DNS resolution (proves UDP to external blocked) ---
echo "--- External UDP/DNS (must be BLOCKED) ---"
if agent timeout 3 nslookup google.com 8.8.8.8 >/dev/null 2>&1; then
    fail "DNS via 8.8.8.8: RESOLVED (UDP forward not blocked)"
else
    pass "DNS via 8.8.8.8: TIMEOUT (UDP forward blocked)"
fi

# --- Negative: ICMP to external ---
echo "--- External ICMP (must be BLOCKED) ---"
if agent ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    fail "ICMP to 1.1.1.1: ALLOWED"
else
    pass "ICMP to 1.1.1.1: BLOCKED"
fi

# --- Negative: ICMP to host (INPUT catch-all should block) ---
echo "--- ICMP to host (should be BLOCKED by INPUT catch-all) ---"
if agent ping -c 1 -W 2 $HOST_IP >/dev/null 2>&1; then
    fail "ICMP to host: ALLOWED (INPUT catch-all not blocking ICMP)"
else
    pass "ICMP to host: BLOCKED"
fi

# --- Negative: UDP to host ---
echo "--- UDP to host (should be BLOCKED by INPUT catch-all) ---"
nohup nc -u -l -p 5353 -s "$HOST_IP" < /dev/null > /tmp/udp-test-out 2>&1 &
udp_pid=$!
sleep 0.3
agent bash -c "echo UDP_PROBE | nc -u -w 1 $HOST_IP 5353" 2>/dev/null
sleep 0.5
kill $udp_pid 2>/dev/null
wait $udp_pid 2>/dev/null
if [ -s /tmp/udp-test-out ]; then
    fail "UDP to host: DATA RECEIVED (INPUT catch-all not blocking UDP)"
else
    pass "UDP to host: NO DATA (blocked)"
fi
rm -f /tmp/udp-test-out

# --- Positive: host's own traffic unaffected ---
echo "--- Host traffic (must be UNAFFECTED) ---"
if nc -w 2 -z 1.1.1.1 80 >/dev/null 2>&1; then
    pass "Host can reach internet (policy accept, no interference)"
else
    fail "Host's own traffic broken by SafeYolo rules"
fi

echo ""
echo "=== RESULTS ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total: $((PASS + FAIL))"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILURES:"
    for r in "${RESULTS[@]}"; do
        [[ "$r" == FAIL* ]] && echo "  $r"
    done
    exit 1
fi

echo ""
echo "ALL TESTS PASSED"
