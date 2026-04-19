#!/bin/bash
set -e
rm -rf /tmp/exp11 && mkdir -p /tmp/exp11/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/exp11/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": true},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "echo PID1_RUNNING && sleep 30"],
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

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host --root /tmp/exp11/state create --bundle /tmp/exp11 exp11 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/exp11/state start exp11 2>&1
  echo started
  sleep 1

  # Test exec as root
  echo '--- exec as root ---'
  runsc --root /tmp/exp11/state exec exp11 -- ip addr show lo 2>&1
  echo exec_root_rc=\$?

  # Test exec as uid 1000
  echo '--- exec as uid 1000 ---'
  runsc --root /tmp/exp11/state exec --user 1000:1000 exp11 -- whoami 2>&1
  echo exec_user_rc=\$?

  # Cleanup
  runsc --root /tmp/exp11/state kill exp11 2>/dev/null
  runsc --root /tmp/exp11/state delete exp11 2>/dev/null
"
