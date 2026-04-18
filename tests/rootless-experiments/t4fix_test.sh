#!/bin/bash
# T4 fix: custom uid mapping — map both root and uid 1000
set -e
rm -rf /tmp/t4fix && mkdir -p /tmp/t4fix/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Use unshare without -r, then manually set up uid/gid maps
# Map container uid 0 -> host uid 1000, container uid 1000 -> host uid 1000
# This way both root and agent inside the container map to the host user
aa-exec -p runsc-userns -- unshare -Un bash -c "
  # Write uid/gid maps
  echo '0 1000 1' > /proc/self/uid_map 2>&1
  echo 'deny' > /proc/self/setgroups 2>&1
  echo '0 1000 1' > /proc/self/gid_map 2>&1

  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix/state create --bundle /tmp/t4fix t4fix 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix/state start t4fix 2>&1
  echo started
"
sleep 2

echo "--- home/agent ownership inside container ---"
runsc --root /tmp/t4fix/state exec t4fix /bin/sh -c 'ls -la /home/agent/' 2>&1

echo "--- agent user write test ---"
runsc --root /tmp/t4fix/state exec --user 1000:1000 t4fix /bin/sh -c '
  whoami 2>/dev/null || echo uid=$(id -u)
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
  touch /tmp/test && echo tmp-write-ok || echo tmp-write-failed
' 2>&1

runsc --root /tmp/t4fix/state kill t4fix 2>/dev/null
sleep 1
runsc --root /tmp/t4fix/state delete t4fix 2>/dev/null
