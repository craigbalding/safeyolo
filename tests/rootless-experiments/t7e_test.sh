#!/bin/bash
# T7e: try OCI pids.limit WITHOUT --ignore-cgroups, using delegated subtree
set -e
rm -rf /tmp/t7e && mkdir -p /tmp/t7e/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

# Get the delegated cgroup path
CG_REL=$(cat /proc/self/cgroup | sed 's/0:://')

cat > /tmp/t7e/config.json << SPECEOF
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
    "cgroupsPath": "${CG_REL}/safeyolo-t7e",
    "resources": {
      "pids": {"limit": 50}
    }
  }
}
SPECEOF

echo "cgroupsPath=${CG_REL}/safeyolo-t7e"

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --network=host \
        --root /tmp/t7e/state create --bundle /tmp/t7e t7e 2>&1
  echo create_rc=\$?
  runsc --network=host --root /tmp/t7e/state start t7e 2>&1
  echo start_rc=\$?
"
sleep 2

echo "--- state ---"
runsc --root /tmp/t7e/state exec t7e /bin/sh -c 'echo ALIVE' 2>&1 || echo "container not running"

runsc --root /tmp/t7e/state kill t7e 2>/dev/null
sleep 1
runsc --root /tmp/t7e/state delete t7e 2>/dev/null
