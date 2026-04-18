#!/bin/bash
# T1 retry: try various nsenter combos and direct runsc exec
set -e
rm -rf /tmp/t1b && mkdir -p /tmp/t1b/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t1b/config.json << SPECEOF
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

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  echo \$\$ > /tmp/t1b/unshare.pid
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t1b/state create --bundle /tmp/t1b t1b 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t1b/state start t1b 2>&1
  echo sandbox-started
  sleep 60
" &
BG=$!
sleep 3

PID=$(cat /tmp/t1b/unshare.pid)
echo "unshare PID=$PID"

# Find the sandbox/gofer PIDs
echo "--- runsc processes ---"
ps aux | grep 'runsc.*t1b' | grep -v grep

# Option A: no nsenter, direct runsc exec
echo "--- A: direct runsc exec (no nsenter) ---"
runsc --root /tmp/t1b/state exec t1b /bin/sh -c 'echo DIRECT_OK' 2>&1
echo "rc=$?"

# Option B: nsenter --user only
echo "--- B: nsenter --user ---"
nsenter --user --target $PID -- runsc --root /tmp/t1b/state exec t1b /bin/sh -c 'echo USER_NS_OK' 2>&1
echo "rc=$?"

# Option C: nsenter --user --net
echo "--- C: nsenter --user --net ---"
nsenter --user --net --target $PID -- runsc --root /tmp/t1b/state exec t1b /bin/sh -c 'echo USER_NET_OK' 2>&1
echo "rc=$?"

# Option D: just kill the sandbox PID directly
SANDBOX_PID=$(ps aux | grep 'runsc.*boot.*t1b' | grep -v grep | awk '{print $2}')
echo "--- D: kill -0 sandbox PID=$SANDBOX_PID ---"
kill -0 $SANDBOX_PID 2>&1 && echo "can signal" || echo "cannot signal"

kill $BG 2>/dev/null
wait $BG 2>/dev/null
