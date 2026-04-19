#!/bin/bash
# T4: rootfs uid mapping, T5: KVM verification, T6: signal delivery
set -e
rm -rf /tmp/t4 && mkdir -p /tmp/t4/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t4/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4/state create --bundle /tmp/t4 t4 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4/state start t4 2>&1
  echo started
"
sleep 2

# T4: uid mapping
echo "=== T4: rootfs uid mapping ==="
echo "--- T4a: file ownership as root ---"
runsc --root /tmp/t4/state exec t4 /bin/sh -c 'ls -la /etc/passwd /etc/shadow /home/agent' 2>&1

echo "--- T4b: su to agent user, file operations ---"
runsc --root /tmp/t4/state exec --user 1000:1000 t4 /bin/sh -c '
  whoami
  id
  touch /tmp/agent-test && echo touch-ok || echo touch-failed
  ls -la /tmp/agent-test
  cat /etc/hostname 2>/dev/null && echo read-ok || echo read-failed
' 2>&1

echo "--- T4c: agent home dir ---"
runsc --root /tmp/t4/state exec --user 1000:1000 t4 /bin/sh -c '
  ls -la /home/agent/
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
' 2>&1

# T5: KVM verification
echo "=== T5: KVM platform ==="
runsc --root /tmp/t4/state exec t4 /bin/sh -c '
  cat /proc/cpuinfo | head -5
  nproc
  dmesg 2>/dev/null | grep -i kvm | head -3 || echo no-dmesg
' 2>&1

# Check from host: is the sandbox using KVM?
echo "--- host-side: sandbox process flags ---"
ps aux | grep 'runsc-sandbox.*t4' | grep -v grep | grep -o 'platform=[a-z]*'

# T6: signal delivery
echo "=== T6: signal delivery ==="
SANDBOX_PID=$(ps aux | grep 'runsc-sandbox.*boot.*t4' | grep -v grep | awk '{print $2}')
echo "sandbox PID=$SANDBOX_PID"
kill -0 $SANDBOX_PID 2>&1 && echo "kill -0: can signal" || echo "kill -0: EPERM"

# Clean up via runsc kill (not raw signal — save that for verification)
runsc --root /tmp/t4/state kill t4 2>/dev/null
sleep 1
runsc --root /tmp/t4/state delete t4 2>/dev/null
echo "cleanup done"
