#!/bin/bash
# T7c: PID limit only
set -e
rm -rf /tmp/t7c && mkdir -p /tmp/t7c/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t7c/config.json << SPECEOF
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
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t7c/state create --bundle /tmp/t7c t7c 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t7c/state start t7c 2>&1
"
sleep 2

echo "=== PID limit test (scope TasksMax=50) ==="
runsc --root /tmp/t7c/state exec t7c /bin/sh -c '
  ok=0
  for i in $(seq 1 100); do
    sleep 999 2>/dev/null &
    if [ $? -eq 0 ]; then ok=$((ok+1)); fi
  done
  echo "attempted=100 spawned=$ok"
  kill $(jobs -p) 2>/dev/null
  wait 2>/dev/null
' 2>&1
echo "rc=$?"

echo "=== still alive ==="
runsc --root /tmp/t7c/state exec t7c /bin/sh -c 'echo ALIVE' 2>&1

runsc --root /tmp/t7c/state kill t7c 2>/dev/null
sleep 1
runsc --root /tmp/t7c/state delete t7c 2>/dev/null
