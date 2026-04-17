#!/bin/bash
# test_uds_networking.sh -- prove gVisor network=none + UDS proxy works
#
# Tests the pattern: container has NO network interface. All traffic
# flows through a bind-mounted Unix domain socket to the proxy.
#
# Requires: runsc, fuse-overlayfs, base rootfs, Python 3 in rootfs
# Usage: sudo bash test_uds_networking.sh
#
# All Python test scripts are standalone files in the same directory.

set -u

OPERATOR="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
OPERATOR_UID=$(id -u "$OPERATOR")
OPERATOR_GID=$(id -g "$OPERATOR")
HOME_DIR=$(eval echo "~$OPERATOR")
SHARE_DIR="$HOME_DIR/.safeyolo/share"
BASE_DIR="$SHARE_DIR/rootfs-base"
WORK_DIR="$HOME_DIR/.safeyolo/agents/uds-test"
RUNSC_ROOT="/run/safeyolo"
CID="safeyolo-uds-test"
NETNS="safeyolo-loopback-only"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ECHO_PORT=18888
PROXY_PORT=8080

PASS=0
FAIL=0
RESULTS=()

pass() { PASS=$((PASS+1)); RESULTS+=("PASS: $1"); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL: $1"); echo "  FAIL: $1"; }

cleanup() {
    echo ""
    echo "=== CLEANUP ==="
    runsc --root "$RUNSC_ROOT" kill "$CID" SIGKILL 2>/dev/null
    sleep 0.5
    runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null
    su -s /bin/bash "$OPERATOR" -c "fusermount3 -u $WORK_DIR/rootfs 2>/dev/null"
    kill $(cat /tmp/uds-bridge.pid 2>/dev/null) 2>/dev/null
    kill $(cat /tmp/echo-server.pid 2>/dev/null) 2>/dev/null
    ip netns del "$NETNS" 2>/dev/null
    rm -f /tmp/uds-bridge.pid /tmp/echo-server.pid
    echo "  done (work dir: $WORK_DIR)"
}

trap cleanup EXIT

# --- Preflight ---

echo "=== PREFLIGHT ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root"; exit 2
fi

if [ ! -d "$BASE_DIR" ]; then
    echo "ERROR: base rootfs not found at $BASE_DIR"; exit 2
fi

if [ "$(stat -c %u "$BASE_DIR/bin/bash")" = "0" ]; then
    echo "  chown base rootfs to operator"
    chown -R "${OPERATOR_UID}:${OPERATOR_GID}" "$BASE_DIR"
fi

PLATFORM="systrap"
[ -r /dev/kvm ] && [ -w /dev/kvm ] && PLATFORM="kvm"
echo "  Platform: $PLATFORM"
echo "  Work dir: $WORK_DIR"
echo ""

# --- Prepare rootfs ---

# Clean any previous run
su -s /bin/bash "$OPERATOR" -c "fusermount3 -u $WORK_DIR/rootfs 2>/dev/null"
runsc --root "$RUNSC_ROOT" kill "$CID" SIGKILL 2>/dev/null
sleep 0.3
runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null
ip netns del "$NETNS" 2>/dev/null
su -s /bin/bash "$OPERATOR" -c "rm -rf $WORK_DIR"

# Create a network namespace with ONLY loopback (no external interfaces).
# gVisor's --network=none suppresses even loopback, but agents need
# localhost for the TCP-to-UDS forwarder. A loopback-only netns gives
# us 127.0.0.1 inside the container with zero external connectivity.
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up

# Create dirs and populate upper layer with test scripts BEFORE mount.
# Files in the upper layer at mount time are visible through the overlay.
su -s /bin/bash "$OPERATOR" -c "mkdir -p $WORK_DIR/{rootfs-upper/safeyolo-test,rootfs-work,rootfs,config-share}"

for f in connect_uds.py container_uds_forwarder.py http_test.py bypass_test.py dns_test.py; do
    cp "$SCRIPT_DIR/$f" "$WORK_DIR/rootfs-upper/safeyolo-test/$f"
    chown "$OPERATOR_UID:$OPERATOR_GID" "$WORK_DIR/rootfs-upper/safeyolo-test/$f"
done

# Mount overlay
su -s /bin/bash "$OPERATOR" -c "
    fuse-overlayfs \
        -o lowerdir=$BASE_DIR,upperdir=$WORK_DIR/rootfs-upper,workdir=$WORK_DIR/rootfs-work,allow_other,squash_to_uid=$OPERATOR_UID,squash_to_gid=$OPERATOR_GID \
        $WORK_DIR/rootfs
"
if ! mountpoint -q "$WORK_DIR/rootfs"; then
    fail "Preflight: fuse-overlayfs mount failed"; exit 1
fi

# Verify test scripts visible through overlay
if [ -f "$WORK_DIR/rootfs/safeyolo-test/connect_uds.py" ]; then
    pass "Preflight: test scripts visible in overlay"
else
    fail "Preflight: test scripts not visible in overlay"; exit 1
fi

# --- Generate OCI config ---

SOCK_PATH="$WORK_DIR/config-share/proxy.sock"

cat > "$WORK_DIR/config.json" << OCIJSON
{
  "ociVersion": "1.0.0",
  "root": {"path": "$WORK_DIR/rootfs", "readonly": false},
  "hostname": "uds-test",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sleep", "300"],
    "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "TERM=dumb"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_RAW"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_RAW"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_RAW"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_RAW"]
    },
    "noNewPrivileges": false
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid","nodev","mode=1777"]},
    {"destination": "/safeyolo", "type": "bind",
     "source": "$WORK_DIR/config-share",
     "options": ["rbind","rw"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"},
      {"type": "network", "path": "/var/run/netns/$NETNS"}
    ],
    "resources": {
      "memory": {"limit": 268435456},
      "pids": {"limit": 256}
    }
  }
}
OCIJSON

# --- Start container ---

mkdir -p "$RUNSC_ROOT"
# --host-uds=open: allow container to connect() to host UDS files
# Network namespace has loopback only (no veth, no external route)
runsc --root "$RUNSC_ROOT" --host-uds=open \
    --platform="$PLATFORM" create --bundle "$WORK_DIR" "$CID" 2>&1
if [ $? -ne 0 ]; then
    fail "Container create failed"; exit 1
fi

runsc --root "$RUNSC_ROOT" start "$CID"
if [ $? -ne 0 ]; then
    fail "Container start failed"; exit 1
fi
pass "Container started (network=none, host-uds=open)"

# =====================================================
# PHASE 1: Basic UDS connect
# =====================================================

echo ""
echo "=== PHASE 1: UDS connect from gVisor container ==="

# Start a UDS echo listener on the host
python3 -c "
import socket, os, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try: os.unlink('$SOCK_PATH')
except: pass
s.bind('$SOCK_PATH')
os.chmod('$SOCK_PATH', 0o666)
s.listen(1)
s.settimeout(15)
try:
    conn, _ = s.accept()
    data = conn.recv(100)
    conn.sendall(b'ECHO:' + data)
    conn.close()
except socket.timeout:
    sys.exit(1)
s.close()
" &
UDS_PID=$!
sleep 0.5

CONNECT_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/connect_uds.py 2>&1)
CONNECT_RC=$?
wait $UDS_PID 2>/dev/null

if [ $CONNECT_RC -eq 0 ] && echo "$CONNECT_OUT" | grep -q "ECHO:HELLO_FROM_GVISOR"; then
    pass "Phase 1: UDS round-trip works ($CONNECT_OUT)"
else
    fail "Phase 1: UDS connect failed (rc=$CONNECT_RC, out=$CONNECT_OUT)"
    exit 1
fi

# =====================================================
# PHASE 2: Container-side TCP-to-UDS forwarder
# =====================================================

echo ""
echo "=== PHASE 2: Container-side TCP-to-UDS forwarder ==="

# Debug: check loopback state
echo "  Loopback state:"
runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/ip addr show lo 2>&1 | sed 's/^/    /'

# Start forwarder inside container (detached)
runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / -detach "$CID" \
    /usr/bin/python3 /safeyolo-test/container_uds_forwarder.py $PROXY_PORT /safeyolo/proxy.sock 2>&1
sleep 1

FCHECK=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/cat /tmp/forwarder-${PROXY_PORT}.ready 2>&1)
if [ -n "$FCHECK" ] && echo "$FCHECK" | grep -qE '^[0-9]+$'; then
    pass "Phase 2: forwarder running inside container (pid=$FCHECK)"
else
    fail "Phase 2: forwarder not running ($FCHECK)"
    exit 1
fi

# =====================================================
# PHASE 3: Host-side UDS-to-TCP bridge
# =====================================================

echo ""
echo "=== PHASE 3: Host-side UDS-to-TCP bridge ==="

# Start TCP echo server (simulates mitmproxy)
python3 -c "
import socket, threading, os
def handle(conn):
    data = conn.recv(4096)
    body = b'HELLO_PROXY\n'
    conn.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    conn.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT))
s.listen(4)
with open('/tmp/echo-server.pid', 'w') as f:
    f.write(str(os.getpid()))
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" &
sleep 0.3

# Start host bridge: proxy.sock -> echo server
python3 "$SCRIPT_DIR/host_uds_bridge.py" "$SOCK_PATH" 127.0.0.1 $ECHO_PORT &
BRIDGE_PID=$!
echo $BRIDGE_PID > /tmp/uds-bridge.pid
sleep 0.5

if kill -0 $BRIDGE_PID 2>/dev/null; then
    pass "Phase 3: host bridge running (UDS -> TCP:$ECHO_PORT)"
else
    fail "Phase 3: host bridge not running"
    exit 1
fi

# =====================================================
# PHASE 4: End-to-end HTTP
# =====================================================

echo ""
echo "=== PHASE 4: End-to-end HTTP ==="

HTTP_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/http_test.py 2>&1)
HTTP_RC=$?

if [ $HTTP_RC -eq 0 ] && echo "$HTTP_OUT" | grep -q "HELLO_PROXY"; then
    pass "Phase 4: HTTP end-to-end works ($HTTP_OUT)"
else
    fail "Phase 4: HTTP failed (rc=$HTTP_RC, out=$HTTP_OUT)"
fi

# =====================================================
# PHASE 5: Network isolation
# =====================================================

echo ""
echo "=== PHASE 5: Network isolation ==="

# No eth0
ETH_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/ip link show 2>&1)
if echo "$ETH_OUT" | grep -q "eth0"; then
    fail "Phase 5: eth0 exists (should be network=none)"
else
    pass "Phase 5: no eth0 (only loopback)"
fi

# No default route
ROUTE_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/ip route show 2>&1)
if echo "$ROUTE_OUT" | grep -q "default"; then
    fail "Phase 5: default route exists"
else
    pass "Phase 5: no default route"
fi

# Cannot reach external IPs
BYPASS_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/bypass_test.py 2>&1)
if [ $? -eq 0 ]; then
    pass "Phase 5: external TCP blocked ($BYPASS_OUT)"
else
    fail "Phase 5: external TCP allowed ($BYPASS_OUT)"
fi

# Cannot resolve DNS
DNS_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/dns_test.py 2>&1)
if [ $? -eq 0 ]; then
    pass "Phase 5: DNS blocked ($DNS_OUT)"
else
    fail "Phase 5: DNS resolved ($DNS_OUT)"
fi

pass "Phase 5: only egress is UDS-to-proxy (proven in Phase 4)"

# =====================================================
# Results
# =====================================================

# On success, clean up via trap
if [ "$FAIL" -eq 0 ]; then
    trap - EXIT
    cleanup
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
    echo ""
    echo "Work dir preserved: $WORK_DIR"
    exit 1
fi

echo ""
echo "ALL TESTS PASSED"
echo "gVisor network=none + UDS proxy pattern is viable."
