#!/bin/bash
# Exp 15: Full rootless — delegated cgroups + user netns + runsc create
set -e
rm -rf /tmp/exp15 && mkdir -p /tmp/exp15/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

CG_PATH=$(cat /proc/self/cgroup | sed 's/0:://')

cat > /tmp/exp15/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "ip addr show lo && echo HELLO && exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}],
    "cgroupsPath": "${CG_PATH}/safeyolo-exp15",
    "resources": {
      "memory": {"limit": 268435456},
      "cpu": {"quota": 200000, "period": 100000},
      "pids": {"limit": 1024}
    }
  }
}
SPECEOF

echo "spec written, cgroupsPath=${CG_PATH}/safeyolo-exp15"

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --network=host --root /tmp/exp15/state create --bundle /tmp/exp15 exp15 2>&1
  echo create_rc=\$?

  runsc --network=host --root /tmp/exp15/state start exp15 2>&1
  echo start_rc=\$?

  sleep 2
  runsc --root /tmp/exp15/state state exp15 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); print(f\"status={d[\\\"status\\\"]}\")'

  echo '--- logs ---'
  runsc --root /tmp/exp15/state logs exp15 2>&1

  runsc --root /tmp/exp15/state kill exp15 2>/dev/null
  sleep 1
  runsc --root /tmp/exp15/state delete exp15 2>/dev/null
"
