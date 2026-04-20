#!/bin/bash
# T20: Can we use fuse-overlayfs to remap workspace uid?
# If fuse-overlayfs with squash_to_uid wraps the workspace, the gofer
# sees all writes as coming from the host operator uid.
#
# Also test: does gVisor's --directfs mode change the DAC behaviour?
set -e
rm -rf /tmp/t20 && mkdir -p /tmp/t20/state /tmp/t20/ws-upper /tmp/t20/ws-work /tmp/t20/ws-merged
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo
UID_VAL=$(id -u)
GID_VAL=$(id -g)

echo "=== mount workspace via fuse-overlayfs with squash_to_uid ==="
fuse-overlayfs \
  -o "lowerdir=$WORKSPACE,upperdir=/tmp/t20/ws-upper,workdir=/tmp/t20/ws-work,allow_other,squash_to_uid=$UID_VAL,squash_to_gid=$GID_VAL" \
  /tmp/t20/ws-merged 2>&1
echo "fuse-overlayfs rc=$?"
ls -ld /tmp/t20/ws-merged

cat > /tmp/t20/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "chown -R 1000:1000 /home/agent 2>/dev/null; exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"]
    }
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/workspace", "type": "bind", "source": "/tmp/t20/ws-merged", "options": ["rbind","rw"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p safeyolo-runsc -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t20/state create --bundle /tmp/t20 t20 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t20/state start t20 2>&1
  echo started
"
sleep 3

echo "=== workspace inside container ==="
runsc --root /tmp/t20/state exec t20 /bin/sh -c 'ls -ld /workspace'

echo "=== agent write ==="
runsc --root /tmp/t20/state exec --user 1000:1000 t20 /bin/sh -c '
  id
  touch /workspace/t20-test && echo "WRITE OK" || echo "WRITE FAILED"
  ls -la /workspace/t20-test 2>/dev/null
  rm -f /workspace/t20-test
'

echo "=== agent read existing files ==="
runsc --root /tmp/t20/state exec --user 1000:1000 t20 /bin/sh -c '
  ls /workspace/README.md && echo "READ OK" || echo "READ FAILED"
  head -1 /workspace/README.md
'

runsc --root /tmp/t20/state kill t20 2>/dev/null
sleep 1
runsc --root /tmp/t20/state delete t20 2>/dev/null
fusermount3 -u /tmp/t20/ws-merged 2>/dev/null
