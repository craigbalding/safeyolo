#!/bin/bash
# T1: runsc exec from outside the unshare session
# Start sandbox, write unshare PID, then exec from outside via nsenter
set -e
rm -rf /tmp/t1 && mkdir -p /tmp/t1/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t1/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Start sandbox in background, save the unshare bash PID
aa-exec -p runsc-userns -- unshare -Urn bash -c "
  echo \$\$ > /tmp/t1/unshare.pid
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t1/state create --bundle /tmp/t1 t1 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t1/state start t1 2>&1
  echo sandbox-started
  # Keep unshare alive
  sleep 60
" &
BG=$!
sleep 3

UNSHARE_PID=$(cat /tmp/t1/unshare.pid)
echo "unshare PID=$UNSHARE_PID, bg PID=$BG"

# T1a: nsenter into userns+netns, then runsc exec
echo "--- T1a: nsenter + runsc exec ---"
nsenter --user --net --mount --target $UNSHARE_PID -- \
  runsc --root /tmp/t1/state exec t1 /bin/sh -c 'echo EXEC_VIA_NSENTER && ip addr show lo' 2>&1
echo "t1a_rc=$?"

# T1b: runsc exec WITHOUT nsenter (from host namespace)
echo "--- T1b: runsc exec without nsenter ---"
runsc --root /tmp/t1/state exec t1 /bin/sh -c 'echo EXEC_NO_NSENTER' 2>&1
echo "t1b_rc=$?"

# T1c: runsc exec with only user namespace (not net)
echo "--- T1c: nsenter --user only ---"
nsenter --user --target $UNSHARE_PID -- \
  runsc --root /tmp/t1/state exec t1 /bin/sh -c 'echo EXEC_USER_ONLY' 2>&1
echo "t1c_rc=$?"

# Cleanup
kill $BG 2>/dev/null
wait $BG 2>/dev/null
