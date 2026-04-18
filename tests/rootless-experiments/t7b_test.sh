#!/bin/bash
# T7b: resource limits — larger memory scope to account for gVisor overhead
set -e
rm -rf /tmp/t7b && mkdir -p /tmp/t7b/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t7b/config.json << SPECEOF
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
        --root /tmp/t7b/state create --bundle /tmp/t7b t7b 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t7b/state start t7b 2>&1
  echo started
"
sleep 2

echo "=== T7a: memory (256MB scope, gVisor overhead ~40MB) ==="
echo "--- 100MB alloc (should work) ---"
runsc --root /tmp/t7b/state exec t7b /bin/sh -c \
  'python3 -c "x=bytearray(100*1024*1024); print(f\"OK: {len(x)//1024//1024}MB\")"' 2>&1
echo "rc=$?"

echo "--- 300MB alloc (should OOM) ---"
runsc --root /tmp/t7b/state exec t7b /bin/sh -c \
  'python3 -c "x=bytearray(300*1024*1024); print(f\"OK: {len(x)//1024//1024}MB\")"' 2>&1
echo "rc=$?"

echo "=== container alive after OOM? ==="
runsc --root /tmp/t7b/state exec t7b /bin/sh -c 'echo ALIVE' 2>&1

echo "=== T7b: PID limit (512 scope) ==="
runsc --root /tmp/t7b/state exec t7b /bin/sh -c '
  ok=0
  fail=0
  for i in $(seq 1 600); do
    if sleep 999 & then
      ok=$((ok+1))
    else
      fail=$((fail+1))
    fi
  done 2>/dev/null
  echo "spawn_attempted=600 ok=$ok fail=$fail"
  kill $(jobs -p) 2>/dev/null
  wait 2>/dev/null
' 2>&1
echo "rc=$?"

runsc --root /tmp/t7b/state kill t7b 2>/dev/null
sleep 1
runsc --root /tmp/t7b/state delete t7b 2>/dev/null
