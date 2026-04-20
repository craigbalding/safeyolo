#!/bin/bash
# T4 fix7: chown rootfs inside a userns using newuidmap
# Step 1: create userns with subordinate mapping
# Step 2: inside that userns, cp rootfs with preserved ownership → remapped on host
# Step 3: use the remapped rootfs for gVisor
set -e
rm -rf /tmp/t4fix7 && mkdir -p /tmp/t4fix7/state /tmp/t4fix7/rootfs

ROOTFS=$HOME/.safeyolo/share/rootfs-base

echo "=== Step 1: remap rootfs ownership via userns ==="

# Start a userns with the subordinate mapping, cp the rootfs inside it.
# Inside the userns, uid 0 = host 100000, uid 1000 = host 1000.
# cp -a preserves ownership, and the gofer will see host-side uids.
aa-exec -p runsc-userns -- unshare -Un bash -c '
  echo $$ > /tmp/t4fix7/remap.pid
  while [ ! -s /tmp/t4fix7/maps-done ]; do sleep 0.1; done
  echo "userns ready, uid=$(id -u)"
  # Inside the userns, we are root. Copy rootfs — ownership is preserved
  # relative to the userns, which means host-side uids get remapped.
  cp -a '"$ROOTFS"'/. /tmp/t4fix7/rootfs/
  echo "cp done"
  # Verify: /home/agent should be owned by uid 1000 (us-relative)
  ls -lan /tmp/t4fix7/rootfs/home/agent/ | head -3
' &
BGPID=$!
sleep 1

REMAP_PID=$(cat /tmp/t4fix7/remap.pid)
# container 0 → host 100000, container 1000 → host 1000
newuidmap $REMAP_PID 0 100000 1000 1000 1000 1 1001 101001 64534
newgidmap $REMAP_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "done" > /tmp/t4fix7/maps-done
wait $BGPID

echo "=== Step 2: verify host-side ownership ==="
echo "--- rootfs root dir (should be 100000) ---"
ls -lan /tmp/t4fix7/rootfs/ | head -5
echo "--- /home/agent (should be host 1000) ---"
ls -lan /tmp/t4fix7/rootfs/home/agent/ | head -5
echo "--- /etc/passwd (should be 100000) ---"
ls -lan /tmp/t4fix7/rootfs/etc/passwd

echo "=== Step 3: run gVisor with remapped rootfs ==="
cat > /tmp/t4fix7/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "/tmp/t4fix7/rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"],
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

aa-exec -p runsc-userns -- unshare -Un bash -c '
  echo $$ > /tmp/t4fix7/run.pid
  while [ ! -s /tmp/t4fix7/run-maps-done ]; do sleep 0.1; done
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix7/state create --bundle /tmp/t4fix7 t4fix7 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix7/state start t4fix7 2>&1
  echo container-started
  sleep 30
' &
BG2=$!
sleep 1

RUN_PID=$(cat /tmp/t4fix7/run.pid)
newuidmap $RUN_PID 0 100000 1000 1000 1000 1 1001 101001 64534
newgidmap $RUN_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "done" > /tmp/t4fix7/run-maps-done
sleep 5

echo "--- container: /home/agent ownership ---"
runsc --root /tmp/t4fix7/state exec t4fix7 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- container: agent user write ---"
runsc --root /tmp/t4fix7/state exec --user 1000:1000 t4fix7 /bin/sh -c '
  id
  touch /home/agent/test && echo write-ok || echo write-failed
  ls -lan /home/agent/test 2>/dev/null
' 2>&1

echo "--- container: root chown to 1000 ---"
runsc --root /tmp/t4fix7/state exec t4fix7 /bin/sh -c '
  touch /tmp/rootfile
  chown 1000:1000 /tmp/rootfile && echo chown-ok || echo chown-failed
  ls -lan /tmp/rootfile
' 2>&1

runsc --root /tmp/t4fix7/state kill t4fix7 2>/dev/null
sleep 1
runsc --root /tmp/t4fix7/state delete t4fix7 2>/dev/null
kill $BG2 2>/dev/null
wait $BG2 2>/dev/null
