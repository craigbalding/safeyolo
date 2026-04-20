#!/bin/bash
# T7d: PID limit via OCI spec (gVisor internal enforcement)
set -e
rm -rf /tmp/t7d && mkdir -p /tmp/t7d/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t7d/config.json << SPECEOF
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
    "namespaces": [{"type": "pid"}, {"type": "mount"}],
    "resources": {
      "pids": {"limit": 50}
    }
  }
}
SPECEOF

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t7d/state create --bundle /tmp/t7d t7d 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t7d/state start t7d 2>&1
"
sleep 2

echo "=== PID limit via OCI spec (limit=50) ==="
runsc --root /tmp/t7d/state exec t7d /bin/sh -c '
  ok=0
  fail=0
  for i in $(seq 1 100); do
    if sleep 999 2>/dev/null & then
      ok=$((ok+1))
    else
      fail=$((fail+1))
    fi
  done
  echo "attempted=100 ok=$ok fail=$fail"
  kill $(jobs -p) 2>/dev/null
  wait 2>/dev/null
' 2>&1
echo "rc=$?"

runsc --root /tmp/t7d/state exec t7d /bin/sh -c 'echo ALIVE' 2>&1
runsc --root /tmp/t7d/state kill t7d 2>/dev/null
sleep 1
runsc --root /tmp/t7d/state delete t7d 2>/dev/null
