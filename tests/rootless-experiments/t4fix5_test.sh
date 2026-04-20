#!/bin/bash
# T4 fix5: Can gVisor chown to uid 1000 inside userns where only 0 is mapped?
# gVisor's sentry handles capabilities internally — maybe chown works
# in its emulated kernel even if the host uid is unmapped?
set -e
rm -rf /tmp/t4fix5 && mkdir -p /tmp/t4fix5/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix5/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "mkdir -p /tmp/testdir && chown 1000:1000 /tmp/testdir && ls -lan /tmp/testdir && touch /tmp/testdir/file && chown 1000:1000 /tmp/testdir/file && ls -lan /tmp/testdir/file && exec sleep 300"],
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
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix5/state create --bundle /tmp/t4fix5 t4fix5 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix5/state start t4fix5 2>&1
  echo started
"
sleep 3

echo "--- logs (chown on tmpfs) ---"
runsc --root /tmp/t4fix5/state logs t4fix5 2>&1

echo "--- agent user access ---"
runsc --root /tmp/t4fix5/state exec --user 1000:1000 t4fix5 /bin/sh -c '
  id
  ls -la /tmp/testdir/
  touch /tmp/testdir/agent-file && echo write-ok || echo write-failed
' 2>&1

runsc --root /tmp/t4fix5/state kill t4fix5 2>/dev/null
sleep 1
runsc --root /tmp/t4fix5/state delete t4fix5 2>/dev/null
