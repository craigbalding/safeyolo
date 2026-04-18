#!/bin/bash
# Exp 16: runsc --systemd-cgroup inside delegated scope
set -e
rm -rf /tmp/exp16 && mkdir -p /tmp/exp16/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/exp16/config.json << 'SPECEOF'
{
  "ociVersion": "1.0.0",
  "root": {"path": "ROOTFS_PLACEHOLDER", "readonly": false},
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
    "resources": {
      "memory": {"limit": 268435456},
      "pids": {"limit": 1024}
    }
  }
}
SPECEOF
sed -i "s|ROOTFS_PLACEHOLDER|$ROOTFS|" /tmp/exp16/config.json

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --network=host --systemd-cgroup --root /tmp/exp16/state create --bundle /tmp/exp16 exp16 2>&1
  echo create_rc=\$?

  runsc --network=host --systemd-cgroup --root /tmp/exp16/state start exp16 2>&1
  echo start_rc=\$?

  sleep 2
  runsc --root /tmp/exp16/state exec exp16 /bin/sh -c 'ip addr show lo && cat /proc/self/cgroup' 2>&1
  echo exec_rc=\$?

  runsc --root /tmp/exp16/state kill exp16 2>/dev/null
  sleep 1
  runsc --root /tmp/exp16/state delete exp16 2>/dev/null
"
