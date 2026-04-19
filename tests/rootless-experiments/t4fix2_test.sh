#!/bin/bash
# T4 fix2: use newuidmap/newgidmap for proper multi-uid mapping
set -e
rm -rf /tmp/t4fix2 && mkdir -p /tmp/t4fix2/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix2/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Start unshare with -U (user ns) and -n (net ns) but NOT -r
# Then use newuidmap/newgidmap from the parent to set up the mapping
aa-exec -p runsc-userns -- unshare -Un bash -c '
  # Write PID so parent can set up maps
  echo $$ > /tmp/t4fix2/child.pid
  # Wait for parent to set up maps
  while ! cat /proc/self/uid_map 2>/dev/null | grep -q "^"; do sleep 0.1; done
  sleep 0.5

  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  echo "uid_map: $(cat /proc/self/uid_map)"
  echo "gid_map: $(cat /proc/self/gid_map)"

  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix2/state create --bundle /tmp/t4fix2 t4fix2 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix2/state start t4fix2 2>&1
  echo started
  sleep 30
' &
BG=$!
sleep 1

CHILD_PID=$(cat /tmp/t4fix2/child.pid)
echo "child PID=$CHILD_PID"

# Map: container uid 0 -> host uid 1000 (operator)
#       container uid 1-999 -> host uid 100000-100998 (subordinate)
#       container uid 1000 -> host uid 1000 (operator = agent)
# Actually simpler: map container 0 -> host 1000, container 1-65535 -> host 100000-165534
newuidmap $CHILD_PID 0 1000 1 1 100000 65535 2>&1
echo "newuidmap rc=$?"
newgidmap $CHILD_PID 0 1000 1 1 100000 65535 2>&1
echo "newgidmap rc=$?"

sleep 5

echo "--- home/agent ownership ---"
runsc --root /tmp/t4fix2/state exec t4fix2 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- agent user test ---"
runsc --root /tmp/t4fix2/state exec --user 1000:1000 t4fix2 /bin/sh -c '
  id
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
  ls -la /home/agent/test-write
' 2>&1

echo "--- ip addr ---"
runsc --root /tmp/t4fix2/state exec t4fix2 /bin/sh -c 'ip addr show lo' 2>&1

runsc --root /tmp/t4fix2/state kill t4fix2 2>/dev/null
sleep 1
runsc --root /tmp/t4fix2/state delete t4fix2 2>/dev/null
kill $BG 2>/dev/null
wait $BG 2>/dev/null
