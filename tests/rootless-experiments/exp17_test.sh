#!/bin/bash
# Exp 17: ignore-cgroups inside runsc, but systemd-run enforces limits from outside
set -e
rm -rf /tmp/exp17 && mkdir -p /tmp/exp17/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/exp17/config.json << SPECEOF
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
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --network=host --ignore-cgroups --root /tmp/exp17/state create --bundle /tmp/exp17 exp17 2>&1
  echo create_rc=\$?

  runsc --network=host --ignore-cgroups --root /tmp/exp17/state start exp17 2>&1
  echo start_rc=\$?

  sleep 2
  runsc --root /tmp/exp17/state exec exp17 /bin/sh -c 'ip addr show lo && cat /proc/self/cgroup && echo EXEC_OK' 2>&1
  echo exec_rc=\$?

  runsc --root /tmp/exp17/state kill exp17 2>/dev/null
  sleep 1
  runsc --root /tmp/exp17/state delete exp17 2>/dev/null
"

echo "--- systemd scope cgroup limits ---"
CG=$(cat /proc/self/cgroup | sed 's/0:://')
echo "memory.max=$(cat /sys/fs/cgroup${CG}/memory.max 2>/dev/null)"
echo "pids.max=$(cat /sys/fs/cgroup${CG}/pids.max 2>/dev/null)"
