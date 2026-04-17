#!/bin/bash
# test_real_proxy.sh -- test real HTTPS through UDS proxy chain
#
# Builds on test_uds_networking.sh by replacing the echo server
# with a real HTTP CONNECT proxy and testing actual HTTPS traffic.
#
# Usage: sudo bash test_real_proxy.sh

set -u

OPERATOR="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
OPERATOR_UID=$(id -u "$OPERATOR")
OPERATOR_GID=$(id -g "$OPERATOR")
HOME_DIR=$(eval echo "~$OPERATOR")
SHARE_DIR="$HOME_DIR/.safeyolo/share"
BASE_DIR="$SHARE_DIR/rootfs-base"
WORK_DIR="$HOME_DIR/.safeyolo/agents/uds-proxy-test"
RUNSC_ROOT="/run/safeyolo"
CID="safeyolo-uds-proxy-test"
NETNS="safeyolo-lo-proxy"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_PORT=18889

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
    ip netns del "$NETNS" 2>/dev/null
    kill $(cat /tmp/uds-bridge.pid 2>/dev/null) 2>/dev/null
    kill $(cat /tmp/mini-proxy.pid 2>/dev/null) 2>/dev/null
    rm -f /tmp/uds-bridge.pid /tmp/mini-proxy.pid
    echo "  done"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
if [ ! -d "$BASE_DIR" ]; then echo "ERROR: no base rootfs"; exit 2; fi

PLATFORM="systrap"
[ -r /dev/kvm ] && [ -w /dev/kvm ] && PLATFORM="kvm"

echo "=== SETUP ==="

# Clean previous
su -s /bin/bash "$OPERATOR" -c "fusermount3 -u $WORK_DIR/rootfs 2>/dev/null"
runsc --root "$RUNSC_ROOT" kill "$CID" SIGKILL 2>/dev/null
sleep 0.3
runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null
ip netns del "$NETNS" 2>/dev/null
su -s /bin/bash "$OPERATOR" -c "rm -rf $WORK_DIR"

# Netns with loopback only
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up

# Rootfs
su -s /bin/bash "$OPERATOR" -c "mkdir -p $WORK_DIR/{rootfs-upper/safeyolo-test,rootfs-work,rootfs,config-share}"
for f in container_uds_forwarder.py curl_via_proxy_test.py; do
    cp "$SCRIPT_DIR/$f" "$WORK_DIR/rootfs-upper/safeyolo-test/$f"
    chown "$OPERATOR_UID:$OPERATOR_GID" "$WORK_DIR/rootfs-upper/safeyolo-test/$f"
done
su -s /bin/bash "$OPERATOR" -c "
    fuse-overlayfs \
        -o lowerdir=$BASE_DIR,upperdir=$WORK_DIR/rootfs-upper,workdir=$WORK_DIR/rootfs-work,allow_other,squash_to_uid=$OPERATOR_UID,squash_to_gid=$OPERATOR_GID \
        $WORK_DIR/rootfs
"

SOCK_PATH="$WORK_DIR/config-share/proxy.sock"

# OCI config
cat > "$WORK_DIR/config.json" << OCIJSON
{
  "ociVersion": "1.0.0",
  "root": {"path": "$WORK_DIR/rootfs", "readonly": false},
  "hostname": "uds-proxy-test",
  "process": {
    "terminal": false, "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sleep", "300"],
    "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "TERM=dumb"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE"]
    },
    "noNewPrivileges": false
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","mode=1777"]},
    {"destination": "/safeyolo", "type": "bind", "source": "$WORK_DIR/config-share", "options": ["rbind","rw"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
      {"type": "network", "path": "/var/run/netns/$NETNS"}
    ],
    "resources": {"memory": {"limit": 268435456}, "pids": {"limit": 256}}
  }
}
OCIJSON

# Start container
mkdir -p "$RUNSC_ROOT"
runsc --root "$RUNSC_ROOT" --host-uds=open --platform="$PLATFORM" create --bundle "$WORK_DIR" "$CID" 2>&1
runsc --root "$RUNSC_ROOT" start "$CID"
echo "  Container started"

# Start container-side forwarder (localhost:8080 -> UDS)
runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / -detach "$CID" \
    /usr/bin/python3 /safeyolo-test/container_uds_forwarder.py 8080 /safeyolo/proxy.sock 2>&1
sleep 1

# Start real HTTP CONNECT proxy on host
python3 "$SCRIPT_DIR/mini_proxy.py" $PROXY_PORT &
sleep 0.3

# Start host bridge: proxy.sock -> mini_proxy
python3 "$SCRIPT_DIR/host_uds_bridge.py" "$SOCK_PATH" 127.0.0.1 $PROXY_PORT &
BRIDGE_PID=$!
echo $BRIDGE_PID > /tmp/uds-bridge.pid
sleep 0.5

echo "  Full chain ready: container:8080 -> UDS -> bridge -> proxy:$PROXY_PORT -> internet"
echo ""

# === Test 1: HTTP via proxy ===
echo "=== TEST 1: HTTP via proxy ==="
HTTP_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 -c "
import os, urllib.request
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8080'
try:
    r = urllib.request.urlopen('http://httpbin.org/get', timeout=10)
    body = r.read().decode()
    print(f'status={r.status} len={len(body)}')
    if r.status == 200: exit(0)
    exit(1)
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
    exit(1)
" 2>&1)
HTTP_RC=$?
if [ $HTTP_RC -eq 0 ]; then
    pass "HTTP via proxy ($HTTP_OUT)"
else
    fail "HTTP via proxy (rc=$HTTP_RC, $HTTP_OUT)"
fi

# === Test 2: HTTPS via proxy (CONNECT tunnel) ===
echo ""
echo "=== TEST 2: HTTPS via proxy (CONNECT tunnel) ==="
HTTPS_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/curl_via_proxy_test.py 2>&1)
HTTPS_RC=$?
if [ $HTTPS_RC -eq 0 ]; then
    pass "HTTPS CONNECT via proxy ($HTTPS_OUT)"
else
    fail "HTTPS CONNECT via proxy (rc=$HTTPS_RC, $HTTPS_OUT)"
fi

# === Results ===
echo ""
echo "=== RESULTS ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILURES:"
    for r in "${RESULTS[@]}"; do
        [[ "$r" == FAIL* ]] && echo "  $r"
    done
    exit 1
fi

echo ""
echo "REAL PROXY TESTS PASSED"
echo "HTTP and HTTPS CONNECT tunneling works through UDS chain."
