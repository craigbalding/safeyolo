#!/bin/bash
# T22: OCI spec uidMappings with unshare -Urn
# Can we tell gVisor to map container uid 1000 → host uid 0 (which is
# the userns root = host operator) via the OCI linux.uidMappings?
set -e
rm -rf /tmp/t22 && mkdir -p /tmp/t22/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo

cat > /tmp/t22/config.json << SPECEOF
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
    "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "user"}],
    "uidMappings": [
      {"containerID": 0, "hostID": 0, "size": 1},
      {"containerID": 1000, "hostID": 0, "size": 1}
    ],
    "gidMappings": [
      {"containerID": 0, "hostID": 0, "size": 1},
      {"containerID": 1000, "hostID": 0, "size": 1}
    ]
  }
}
SPECEOF

aa-exec -p safeyolo-runsc -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t22/state create --bundle /tmp/t22 t22 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --network=host --root /tmp/t22/state start t22 2>&1
  echo start_rc=\$?
"
sleep 3

echo "=== agent write with OCI uidMappings ==="
runsc --root /tmp/t22/state exec --user 1000:1000 t22 /bin/sh -c '
  id
  ls -ld /workspace
  touch /workspace/t22-test 2>&1 && echo "WRITE OK" || echo "WRITE FAILED"
  rm -f /workspace/t22-test
' 2>&1

runsc --root /tmp/t22/state kill t22 2>/dev/null
sleep 1
runsc --root /tmp/t22/state delete t22 2>/dev/null
