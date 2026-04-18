#!/bin/bash
# T4 fix4: unshare -Urn + chown in guest-init (same as current approach)
set -e
rm -rf /tmp/t4fix4 && mkdir -p /tmp/t4fix4/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix4/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "chown -R 1000:1000 /home/agent && exec sleep 300"],
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
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix4/state create --bundle /tmp/t4fix4 t4fix4 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix4/state start t4fix4 2>&1
  echo started
"
sleep 3

echo "--- home/agent ownership after chown ---"
runsc --root /tmp/t4fix4/state exec t4fix4 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- agent user write test ---"
runsc --root /tmp/t4fix4/state exec --user 1000:1000 t4fix4 /bin/sh -c '
  id
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
  ls -lan /home/agent/test-write 2>/dev/null
  mkdir -p /home/agent/.local && echo mkdir-ok || echo mkdir-failed
' 2>&1

runsc --root /tmp/t4fix4/state kill t4fix4 2>/dev/null
sleep 1
runsc --root /tmp/t4fix4/state delete t4fix4 2>/dev/null
