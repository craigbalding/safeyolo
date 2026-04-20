#!/bin/bash
# T4 fix9: unshare -Urn + CAP_CHOWN + tmpfs chown test
set -e
rm -rf /tmp/t4fix9 && mkdir -p /tmp/t4fix9/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4fix9/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN", "CAP_FSETID", "CAP_SETPCAP", "CAP_MKNOD", "CAP_SETFCAP"],
      "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN", "CAP_FSETID", "CAP_SETPCAP", "CAP_MKNOD", "CAP_SETFCAP"],
      "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN", "CAP_FSETID", "CAP_SETPCAP", "CAP_MKNOD", "CAP_SETFCAP"],
      "ambient": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN", "CAP_FSETID", "CAP_SETPCAP", "CAP_MKNOD", "CAP_SETFCAP"]
    }
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
        --root /tmp/t4fix9/state create --bundle /tmp/t4fix9 t4fix9 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix9/state start t4fix9 2>&1
  echo started
"
sleep 2

echo "--- chown on tmpfs ---"
runsc --root /tmp/t4fix9/state exec t4fix9 /bin/sh -c '
  mkdir /tmp/testdir
  chown 1000:1000 /tmp/testdir && echo tmpfs-chown-ok || echo tmpfs-chown-failed
  ls -lan /tmp/testdir
' 2>&1

echo "--- chown on rootfs ---"
runsc --root /tmp/t4fix9/state exec t4fix9 /bin/sh -c '
  chown -R 1000:1000 /home/agent && echo rootfs-chown-ok || echo rootfs-chown-failed
  ls -lan /home/agent/
' 2>&1

echo "--- agent user access ---"
runsc --root /tmp/t4fix9/state exec --user 1000:1000 t4fix9 /bin/sh -c '
  id
  touch /home/agent/test && echo write-ok || echo write-failed
  touch /tmp/testdir/agentfile && echo tmpdir-write-ok || echo tmpdir-write-failed
' 2>&1

runsc --root /tmp/t4fix9/state kill t4fix9 2>/dev/null
sleep 1
runsc --root /tmp/t4fix9/state delete t4fix9 2>/dev/null
