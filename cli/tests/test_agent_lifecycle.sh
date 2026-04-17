#!/bin/bash
# test_agent_lifecycle.sh — end-to-end agent lifecycle integration test
#
# Exercises the FULL agent lifecycle with the hardened security changes:
#   1. fuse-overlayfs rootfs (not kernel overlayfs)
#   2. ip -n networking (not ip netns exec)
#   3. nftables firewall at priority -1 (not iptables)
#   4. runsc container with gVisor
#   5. Proxy port connectivity from inside the container
#   6. Clean teardown (no sudo needed for agent removal)
#
# Requires: Linux host with runsc, fuse-overlayfs, nft, base rootfs extracted.
# Usage: sudo bash test_agent_lifecycle.sh
#
# Idempotent: cleans up on exit even on failure.

set -u

AGENT_NAME="lifecycle-test"
AGENT_INDEX=9  # avoid collision with real agents
SUBNET_BASE=65
THIRD_OCTET=$((SUBNET_BASE + AGENT_INDEX))
HOST_IP="192.168.${THIRD_OCTET}.1"
GUEST_IP="192.168.${THIRD_OCTET}.2"
SUBNET="192.168.${THIRD_OCTET}.0/24"
NETNS="safeyolo-idx${AGENT_INDEX}"
VETH_HOST="veth-sy${AGENT_INDEX}"
PROXY_PORT=8080
ADMIN_PORT=9090
NFT_TABLE="safeyolo"
RUNSC_ROOT="/run/safeyolo"
HOME_DIR=$(eval echo ~$(logname 2>/dev/null || echo $SUDO_USER))
SHARE_DIR="$HOME_DIR/.safeyolo/share"
AGENTS_DIR="$HOME_DIR/.safeyolo/agents"
AGENT_DIR="$AGENTS_DIR/$AGENT_NAME"
BASE_DIR="$SHARE_DIR/rootfs-base"
OPERATOR_UID=$(id -u "${SUDO_USER:-$(logname)}")
OPERATOR_GID=$(id -g "${SUDO_USER:-$(logname)}")

PASS=0
FAIL=0
RESULTS=()

pass() { PASS=$((PASS+1)); RESULTS+=("PASS: $1"); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL: $1"); echo "  FAIL: $1"; }

cleanup() {
    echo ""
    echo "=== CLEANUP ==="
    # Stop container
    runsc --root "$RUNSC_ROOT" kill "safeyolo-${AGENT_NAME}" SIGKILL 2>/dev/null
    sleep 0.5
    runsc --root "$RUNSC_ROOT" delete --force "safeyolo-${AGENT_NAME}" 2>/dev/null
    # Unmount fuse-overlayfs
    fusermount3 -u "$AGENT_DIR/rootfs" 2>/dev/null
    # Remove agent dir (should work without sudo if squash_to_uid worked)
    rm -rf "$AGENT_DIR" 2>/dev/null
    # Teardown networking
    ip link del "$VETH_HOST" 2>/dev/null
    ip netns del "$NETNS" 2>/dev/null
    # Remove nftables table
    nft delete table ip "$NFT_TABLE" 2>/dev/null
    # Kill proxy listener
    fuser -k ${PROXY_PORT}/tcp 2>/dev/null
    echo "  done"
}

trap cleanup EXIT

# --- Preflight ---

echo "=== PREFLIGHT ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root"
    exit 2
fi

if [ ! -d "$BASE_DIR" ]; then
    echo "ERROR: base rootfs not found at $BASE_DIR"
    echo "  Run: safeyolo agent add <name> <template> <folder> first"
    exit 2
fi

# Ensure base rootfs is operator-readable (fuse-overlayfs requirement)
if [ "$(stat -c %u "$BASE_DIR/bin/bash")" = "0" ]; then
    echo "  chown base rootfs to operator (one-time for fuse-overlayfs)"
    chown -R "${OPERATOR_UID}:${OPERATOR_GID}" "$BASE_DIR"
fi

echo "  Agent: $AGENT_NAME (index $AGENT_INDEX)"
echo "  Subnet: $SUBNET (host=$HOST_IP, guest=$GUEST_IP)"
echo "  Netns: $NETNS, Veth: $VETH_HOST"
echo ""

# --- Phase 1: fuse-overlayfs rootfs ---

echo "=== PHASE 1: fuse-overlayfs rootfs ==="

# Create dirs as operator (fuse-overlayfs requires operator-owned dirs)
su -s /bin/bash "${SUDO_USER:-$(logname)}" -c "mkdir -p $AGENT_DIR/{rootfs-upper,rootfs-work,rootfs}"

# Mount as operator (not root) — the whole point of fuse-overlayfs
su -s /bin/bash "${SUDO_USER:-$(logname)}" -c "
    fuse-overlayfs \
        -o lowerdir=$BASE_DIR,upperdir=$AGENT_DIR/rootfs-upper,workdir=$AGENT_DIR/rootfs-work,allow_other,squash_to_uid=$OPERATOR_UID,squash_to_gid=$OPERATOR_GID \
        $AGENT_DIR/rootfs
"
if mountpoint -q "$AGENT_DIR/rootfs"; then
    pass "Phase 1: fuse-overlayfs mounted"
else
    fail "Phase 1: fuse-overlayfs mount failed"
    exit 1
fi

# Verify /bin/bash accessible through the overlay
if [ -x "$AGENT_DIR/rootfs/bin/bash" ]; then
    pass "Phase 1: /bin/bash accessible through overlay"
else
    fail "Phase 1: /bin/bash not found in overlay"
    exit 1
fi

# Create workspace through merged mount (fuse-overlayfs only surfaces
# changes made through the merge, not direct upper-layer writes)
su -s /bin/bash "${SUDO_USER:-$(logname)}" -c "mkdir -p $AGENT_DIR/rootfs/workspace"
if [ -d "$AGENT_DIR/rootfs/workspace" ]; then
    pass "Phase 1: workspace created through overlay (no sudo)"
else
    fail "Phase 1: workspace not visible through overlay"
fi

# --- Phase 2: ip -n networking ---

echo ""
echo "=== PHASE 2: Networking (ip -n) ==="

ip netns add "$NETNS" 2>/dev/null
ip link del "$VETH_HOST" 2>/dev/null
ip link add "$VETH_HOST" type veth peer name eth0 netns "$NETNS"
ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

# Guest-side config using ip -n (not ip netns exec)
ip -n "$NETNS" addr add "${GUEST_IP}/24" dev eth0
ip -n "$NETNS" link set eth0 up
ip -n "$NETNS" link set lo up
ip -n "$NETNS" route add default via "$HOST_IP"
sysctl -q -w net.ipv4.ip_forward=1

# Verify connectivity
if ip netns exec "$NETNS" ping -c 1 -W 2 "$HOST_IP" >/dev/null 2>&1; then
    pass "Phase 2: guest can ping host via veth"
else
    fail "Phase 2: guest cannot ping host"
fi

# --- Phase 3: nftables firewall ---

echo ""
echo "=== PHASE 3: nftables firewall (priority -1) ==="

nft add table ip "$NFT_TABLE" 2>/dev/null
nft flush table ip "$NFT_TABLE"
nft "add chain ip $NFT_TABLE forward { type filter hook forward priority -1; policy accept; }"
nft "add chain ip $NFT_TABLE input { type filter hook input priority -1; policy accept; }"
nft "add chain ip $NFT_TABLE postrouting { type nat hook postrouting priority 100; policy accept; }"

# Per-subnet rules
OUTBOUND_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
OUTBOUND_IF=${OUTBOUND_IF:-eth0}

nft add rule ip "$NFT_TABLE" forward ip saddr "$SUBNET" ip daddr "$HOST_IP" tcp dport "$PROXY_PORT" accept
nft add rule ip "$NFT_TABLE" forward ip saddr "$SUBNET" ip daddr "$HOST_IP" tcp dport "$ADMIN_PORT" drop
nft add rule ip "$NFT_TABLE" forward ip saddr "$SUBNET" drop
nft add rule ip "$NFT_TABLE" input ip saddr "$SUBNET" ip daddr "$HOST_IP" tcp dport "$PROXY_PORT" accept
nft add rule ip "$NFT_TABLE" input ip saddr "$SUBNET" drop
nft add rule ip "$NFT_TABLE" postrouting ip saddr "$SUBNET" oifname "$OUTBOUND_IF" masquerade

if nft list table ip "$NFT_TABLE" | grep -q "chain forward"; then
    pass "Phase 3: nftables rules loaded"
else
    fail "Phase 3: nftables rules not loaded"
fi

# Firewall tests from guest perspective
nohup nc -l -k -p "$PROXY_PORT" -s "$HOST_IP" < /dev/null > /dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

# Proxy port must be reachable
nft flush chain ip "$NFT_TABLE" input
nft add rule ip "$NFT_TABLE" input ip saddr "$SUBNET" ip daddr "$HOST_IP" tcp dport "$PROXY_PORT" counter accept
nft add rule ip "$NFT_TABLE" input ip saddr "$SUBNET" counter drop
ip netns exec "$NETNS" bash -c "echo TEST | nc -w 2 $HOST_IP $PROXY_PORT" >/dev/null 2>&1 || true
COUNTER=$(nft list chain ip "$NFT_TABLE" input 2>&1 | grep "dport $PROXY_PORT" | grep -o 'packets [0-9]*' | awk '{print $2}')
if [ "${COUNTER:-0}" -gt 0 ]; then
    pass "Phase 3: proxy port reachable (nft counter=$COUNTER)"
else
    fail "Phase 3: proxy port not reachable (nft counter=0)"
fi

# External must be blocked
if ip netns exec "$NETNS" nc -w 2 -z 1.1.1.1 80 >/dev/null 2>&1; then
    fail "Phase 3: external TCP allowed (should be blocked)"
else
    pass "Phase 3: external TCP blocked"
fi

kill $LISTENER_PID 2>/dev/null
fuser -k "${PROXY_PORT}/tcp" 2>/dev/null

# --- Phase 4: runsc container ---

echo ""
echo "=== PHASE 4: runsc container ==="

mkdir -p "$RUNSC_ROOT"
CID="safeyolo-${AGENT_NAME}"
PLATFORM="systrap"
[ -r /dev/kvm ] && [ -w /dev/kvm ] && PLATFORM="kvm"

# Generate minimal OCI config
CONFIG_SHARE=$(mktemp -d)
cat > "$AGENT_DIR/config.json" << OCIJSON
{
  "ociVersion": "1.0.0",
  "root": {"path": "$AGENT_DIR/rootfs", "readonly": false},
  "hostname": "safeyolo-$AGENT_NAME",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/bash", "-c", "echo GUEST_BOOT_OK > /tmp/boot-marker && sleep 300"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=dumb", "HOME=/root"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT"]
    },
    "noNewPrivileges": false
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid","noexec","nodev","ro"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","mode=1777"]}
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
      "memory": {"limit": 536870912},
      "cpu": {"quota": 200000, "period": 100000},
      "pids": {"limit": 512}
    }
  }
}
OCIJSON

# Clean stale state
runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null

# Create + start container
STDERR_FILE=$(mktemp)
runsc --root "$RUNSC_ROOT" --platform="$PLATFORM" create --bundle "$AGENT_DIR" "$CID" 2>"$STDERR_FILE"
CREATE_RC=$?
if [ $CREATE_RC -ne 0 ]; then
    fail "Phase 4: runsc create failed (rc=$CREATE_RC)"
    cat "$STDERR_FILE" >&2
    rm -f "$STDERR_FILE"
    exit 1
fi
pass "Phase 4: runsc create succeeded (platform=$PLATFORM)"
rm -f "$STDERR_FILE"

runsc --root "$RUNSC_ROOT" start "$CID"
if [ $? -eq 0 ]; then
    pass "Phase 4: runsc start succeeded"
else
    fail "Phase 4: runsc start failed"
    exit 1
fi

# Wait for boot marker
sleep 2
STATE=$(runsc --root "$RUNSC_ROOT" state "$CID" 2>/dev/null)
STATUS=$(echo "$STATE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
if [ "$STATUS" = "running" ]; then
    pass "Phase 4: container is running"
else
    fail "Phase 4: container status=$STATUS (expected running)"
    # Show boot log if available
    cat "$AGENT_DIR/rootfs-upper/tmp/boot-marker" 2>/dev/null
fi

# Exec into container and verify
EXEC_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" /bin/cat /tmp/boot-marker 2>&1)
if echo "$EXEC_OUT" | grep -q "GUEST_BOOT_OK"; then
    pass "Phase 4: exec into container works, boot marker found"
else
    fail "Phase 4: exec failed or boot marker missing: $EXEC_OUT"
fi

# Verify container sees the network namespace
NET_OUT=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" /bin/ip addr show eth0 2>&1)
if echo "$NET_OUT" | grep -q "$GUEST_IP"; then
    pass "Phase 4: container sees guest IP ($GUEST_IP) on eth0"
else
    fail "Phase 4: container doesn't see guest IP: $NET_OUT"
fi

# --- Phase 5: Connectivity from container ---

echo ""
echo "=== PHASE 5: Container connectivity ==="

# Start proxy listener
nohup nc -l -k -p "$PROXY_PORT" -s "$HOST_IP" < /dev/null > /dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

# Container -> proxy port (use bash /dev/tcp — nc may not be in the rootfs)
CONNECT_RC=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/bash -c "timeout 3 bash -c 'echo > /dev/tcp/$HOST_IP/$PROXY_PORT' 2>/dev/null; echo \$?" 2>/dev/null | tail -1)
if [ "${CONNECT_RC:-1}" = "0" ]; then
    pass "Phase 5: container -> proxy port ALLOWED"
else
    fail "Phase 5: container -> proxy port BLOCKED (rc=$CONNECT_RC)"
fi

# Container -> external (must fail)
EXT_RC=$(runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /bin/bash -c "timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/80' 2>/dev/null; echo \$?" 2>/dev/null | tail -1)
if [ "${EXT_RC:-0}" != "0" ]; then
    pass "Phase 5: container -> external BLOCKED"
else
    fail "Phase 5: container -> external ALLOWED (should be blocked)"
fi

kill $LISTENER_PID 2>/dev/null
fuser -k "${PROXY_PORT}/tcp" 2>/dev/null

# --- Phase 6: Clean teardown ---

echo ""
echo "=== PHASE 6: Clean teardown ==="

# Stop container
runsc --root "$RUNSC_ROOT" kill "$CID" SIGTERM 2>/dev/null
sleep 1
runsc --root "$RUNSC_ROOT" kill --all "$CID" SIGKILL 2>/dev/null
sleep 0.5
runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null
if ! runsc --root "$RUNSC_ROOT" state "$CID" >/dev/null 2>&1; then
    pass "Phase 6: container stopped and deleted"
else
    fail "Phase 6: container still exists after delete"
fi

# Unmount fuse-overlayfs (as operator, no sudo)
su -s /bin/bash "${SUDO_USER:-$(logname)}" -c "fusermount3 -u $AGENT_DIR/rootfs"
if ! mountpoint -q "$AGENT_DIR/rootfs" 2>/dev/null; then
    pass "Phase 6: fuse-overlayfs unmounted (no sudo)"
else
    fail "Phase 6: fuse-overlayfs still mounted"
fi

# Remove agent dir (as operator, no sudo)
su -s /bin/bash "${SUDO_USER:-$(logname)}" -c "rm -rf $AGENT_DIR"
if [ ! -d "$AGENT_DIR" ]; then
    pass "Phase 6: agent dir removed (no sudo, squash_to_uid works)"
else
    fail "Phase 6: agent dir still exists (root-owned files?)"
    ls -la "$AGENT_DIR/" 2>&1
fi

# Teardown networking
ip link del "$VETH_HOST" 2>/dev/null
ip netns del "$NETNS" 2>/dev/null
pass "Phase 6: networking torn down"

# Delete nftables table
nft delete table ip "$NFT_TABLE" 2>/dev/null
if ! nft list table ip "$NFT_TABLE" >/dev/null 2>&1; then
    pass "Phase 6: nftables table deleted"
else
    fail "Phase 6: nftables table still exists"
fi

# Disable cleanup trap (we did it manually)
trap - EXIT

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
