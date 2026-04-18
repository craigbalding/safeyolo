#!/bin/bash
# T7: resource limits enforced by systemd scope under load
set -e
rm -rf /tmp/t7 && mkdir -p /tmp/t7/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t7/config.json << SPECEOF
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
      "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL"],
      "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL"],
      "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL"],
      "ambient": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL"]
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
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t7/state create --bundle /tmp/t7 t7 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t7/state start t7 2>&1
  echo started
"
sleep 2

echo "=== T7a: memory limit (64MB scope) ==="
echo "--- allocate 50MB (should work) ---"
runsc --root /tmp/t7/state exec t7 /bin/sh -c '
  python3 -c "x=bytearray(50*1024*1024); print(f\"allocated {len(x)//1024//1024}MB\")" 2>&1
' 2>&1
echo "rc=$?"

echo "--- allocate 100MB (should OOM) ---"
runsc --root /tmp/t7/state exec t7 /bin/sh -c '
  python3 -c "x=bytearray(100*1024*1024); print(f\"allocated {len(x)//1024//1024}MB\")" 2>&1
' 2>&1
echo "rc=$?"

echo "=== T7b: PID limit (100 max) ==="
runsc --root /tmp/t7/state exec t7 /bin/sh -c '
  count=0
  for i in $(seq 1 120); do
    sleep 999 &
    count=$((count+1))
  done 2>/dev/null
  echo "spawned=$count"
  # Count actual background jobs
  actual=$(jobs -p | wc -l)
  echo "actual_running=$actual"
  kill $(jobs -p) 2>/dev/null
' 2>&1
echo "rc=$?"

echo "=== T7c: container still alive? ==="
runsc --root /tmp/t7/state exec t7 /bin/sh -c 'echo STILL_ALIVE' 2>&1

runsc --root /tmp/t7/state kill t7 2>/dev/null
sleep 1
runsc --root /tmp/t7/state delete t7 2>/dev/null
