#!/bin/bash
# T21: unshare -Urn + --directfs=false
# Without directfs, the gofer mediates all filesystem access.
# The gofer runs as host uid 1000 (workspace owner).
# Maybe it bypasses the sentry's DAC check?
set -e
rm -rf /tmp/t21 && mkdir -p /tmp/t21/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo

cat > /tmp/t21/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/workspace", "type": "bind", "source": "$WORKSPACE", "options": ["rbind","rw"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p safeyolo-runsc -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --directfs=false \
        --root /tmp/t21/state create --bundle /tmp/t21 t21 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t21/state start t21 2>&1
  echo started
"
sleep 3

echo "=== agent write with --directfs=false ==="
runsc --root /tmp/t21/state exec --user 1000:1000 t21 /bin/sh -c '
  id
  ls -ld /workspace
  touch /workspace/t21-test 2>&1 && echo "WRITE OK" || echo "WRITE FAILED"
  rm -f /workspace/t21-test
'

runsc --root /tmp/t21/state kill t21 2>/dev/null
sleep 1
runsc --root /tmp/t21/state delete t21 2>/dev/null
