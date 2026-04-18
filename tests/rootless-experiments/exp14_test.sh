#!/bin/bash
# Exp 14: No CAP_NET_ADMIN inside container — IP from unshare only
set -e
rm -rf /tmp/exp14 && mkdir -p /tmp/exp14/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/exp14/config.json << SPECEOF
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
  # Configure IP in the unshare'd netns BEFORE runsc starts.
  # gVisor's setupNetwork should import these into its netstack.
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  echo '--- host netns lo ---'
  ip addr show lo

  runsc --platform=kvm --ignore-cgroups --network=host --root /tmp/exp14/state create --bundle /tmp/exp14 exp14 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/exp14/state start exp14 2>&1
  sleep 2

  echo '--- container sees ---'
  runsc --root /tmp/exp14/state exec exp14 /bin/sh -c 'ip addr show lo' 2>&1

  runsc --root /tmp/exp14/state kill exp14 2>/dev/null
  sleep 1
  runsc --root /tmp/exp14/state delete exp14 2>/dev/null
"
