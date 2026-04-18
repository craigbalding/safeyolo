#!/bin/bash
# T4 fix3: map container uid 1000 -> host uid 1000 explicitly
set -e
rm -rf /tmp/t4fix3 && mkdir -p /tmp/t4fix3/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix3/config.json << SPECEOF
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

aa-exec -p runsc-userns -- unshare -Un bash -c '
  echo $$ > /tmp/t4fix3/child.pid
  while ! cat /proc/self/uid_map 2>/dev/null | grep -q "^"; do sleep 0.1; done
  sleep 0.5

  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix3/state create --bundle /tmp/t4fix3 t4fix3 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix3/state start t4fix3 2>&1
  echo started
  sleep 30
' &
BG=$!
sleep 1

CHILD_PID=$(cat /tmp/t4fix3/child.pid)
echo "child PID=$CHILD_PID"

# Map:
#   container 0     -> host 100000 (subordinate root — not the operator)
#   container 1-999 -> host 100001-100999 (subordinate)
#   container 1000  -> host 1000   (operator = agent — same as rootfs owner)
#   container 1001-65534 -> host 101001-165534 (subordinate)
newuidmap $CHILD_PID 0 100000 1000 1000 1000 1 1001 101001 64534 2>&1
echo "newuidmap rc=$?"
newgidmap $CHILD_PID 0 100000 1000 1000 1000 1 1001 101001 64534 2>&1
echo "newgidmap rc=$?"

sleep 5

echo "--- uid_map inside ---"
runsc --root /tmp/t4fix3/state exec t4fix3 /bin/sh -c 'cat /proc/1/uid_map' 2>&1

echo "--- home/agent ownership ---"
runsc --root /tmp/t4fix3/state exec t4fix3 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- agent user test ---"
runsc --root /tmp/t4fix3/state exec --user 1000:1000 t4fix3 /bin/sh -c '
  id
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
  ls -lan /home/agent/test-write 2>/dev/null
' 2>&1

runsc --root /tmp/t4fix3/state kill t4fix3 2>/dev/null
sleep 1
runsc --root /tmp/t4fix3/state delete t4fix3 2>/dev/null
kill $BG 2>/dev/null
wait $BG 2>/dev/null
