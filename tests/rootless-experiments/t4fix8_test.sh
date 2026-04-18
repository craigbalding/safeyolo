#!/bin/bash
# T4 fix8: proper userns with newuidmap — nsenter after map is written
set -e
rm -rf /tmp/t4fix8 && mkdir -p /tmp/t4fix8/state

ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix8/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"],
    "cwd": "/"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Create the userns+netns, write PID, then sleep (hold the namespace open)
aa-exec -p runsc-userns -- unshare -Un sleep 120 &
UNSHARE_PID=$!
sleep 1

# Get the actual child PID (unshare forks)
# Actually unshare replaces itself — $! is the sleep process
echo "unshare/sleep PID=$UNSHARE_PID"

# Write uid/gid maps: container 0 → host 100000, container 1000 → host 1000
newuidmap $UNSHARE_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "newuidmap rc=$?"
newgidmap $UNSHARE_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "newgidmap rc=$?"

# Now nsenter into the userns+netns as uid 0 and run commands
echo "=== nsenter as root (container uid 0 = host 100000) ==="
nsenter --user --net --target $UNSHARE_PID -- bash -c '
  echo "id=$(id)"
  echo "uid_map=$(cat /proc/self/uid_map)"
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  echo "lo configured"
  ip addr show lo
'
echo "nsenter_rc=$?"

echo "=== run gVisor inside the namespace ==="
nsenter --user --net --target $UNSHARE_PID -- bash -c '
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix8/state create --bundle /tmp/t4fix8 t4fix8 2>&1
  echo create_rc=$?
  runsc --ignore-cgroups --network=host --root /tmp/t4fix8/state start t4fix8 2>&1
  echo start_rc=$?
'
sleep 3

echo "=== test from outside ==="
echo "--- /home/agent ownership ---"
runsc --root /tmp/t4fix8/state exec t4fix8 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- agent user ---"
runsc --root /tmp/t4fix8/state exec --user 1000:1000 t4fix8 /bin/sh -c '
  id
  touch /home/agent/test && echo write-ok || echo write-failed
' 2>&1

echo "--- chown test ---"
runsc --root /tmp/t4fix8/state exec t4fix8 /bin/sh -c '
  touch /tmp/x && chown 1000:1000 /tmp/x && echo chown-ok || echo chown-failed
' 2>&1

runsc --root /tmp/t4fix8/state kill t4fix8 2>/dev/null
sleep 1
runsc --root /tmp/t4fix8/state delete t4fix8 2>/dev/null
kill $UNSHARE_PID 2>/dev/null
