#!/bin/bash
# Exp 13: Same as 12 but simpler process — just sleep, then exec
set -e
rm -rf /tmp/exp13 && mkdir -p /tmp/exp13/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/exp13/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "ip link set lo up 2>/dev/null; ip addr add 10.200.0.1/32 dev lo 2>/dev/null; exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_NET_ADMIN"],
      "effective": ["CAP_NET_ADMIN"],
      "permitted": ["CAP_NET_ADMIN"],
      "ambient": ["CAP_NET_ADMIN"]
    }
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

  runsc --platform=kvm --ignore-cgroups --network=host --root /tmp/exp13/state create --bundle /tmp/exp13 exp13 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/exp13/state start exp13 2>&1
  echo started
  sleep 2

  echo '--- state ---'
  runsc --root /tmp/exp13/state state exp13 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[\"status\"])'

  echo '--- exec: ip addr ---'
  runsc --root /tmp/exp13/state exec exp13 /bin/sh -c 'ip addr show lo' 2>&1

  echo '--- exec: curl test ---'
  runsc --root /tmp/exp13/state exec exp13 /bin/sh -c 'curl --version > /dev/null 2>&1 && echo curl-available || echo no-curl' 2>&1

  echo '--- cleanup ---'
  runsc --root /tmp/exp13/state kill exp13 2>/dev/null
  sleep 1
  runsc --root /tmp/exp13/state delete exp13 2>/dev/null
"
