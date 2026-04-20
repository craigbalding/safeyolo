#!/bin/bash
# T4 fix6: remap rootfs ownership to subordinate range
# container 0 → host 100000 (owns rootfs)
# container 1000 → host 1000 (owns /home/agent)
set -e
rm -rf /tmp/t4fix6 && mkdir -p /tmp/t4fix6/state

ROOTFS=$HOME/.safeyolo/share/rootfs-base
REMAPPED=/tmp/t4fix6/rootfs

# Create a remapped copy using fuse-overlayfs with uidmapping
# Actually, simpler: use cp + uidmapshift or just test with a
# minimal rootfs where we control ownership directly

# Create minimal rootfs with correct ownership for the subordinate mapping
mkdir -p $REMAPPED/{bin,usr/bin,lib,lib64,tmp,home/agent,proc,dev,etc}
# Copy essential binaries
cp $ROOTFS/bin/sh $REMAPPED/bin/ 2>/dev/null || cp /bin/sh $REMAPPED/bin/
cp $ROOTFS/bin/ls $REMAPPED/bin/ 2>/dev/null || true
cp $ROOTFS/usr/bin/id $REMAPPED/usr/bin/ 2>/dev/null || true
cp $ROOTFS/usr/bin/whoami $REMAPPED/usr/bin/ 2>/dev/null || true
# Copy libs needed by sh
for lib in $(ldd $REMAPPED/bin/sh 2>/dev/null | grep -o '/lib[^ ]*'); do
  mkdir -p $REMAPPED$(dirname $lib)
  cp $lib $REMAPPED$lib 2>/dev/null || true
done

# Create /etc/passwd
cat > $REMAPPED/etc/passwd << 'EOF'
root:x:0:0:root:/root:/bin/sh
agent:x:1000:1000:agent:/home/agent:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF

# Set ownership for subordinate mapping:
# Everything owned by 100000 (will be container root)
chown -R 100000:100000 $REMAPPED
# /home/agent owned by host 1000 (will be container uid 1000)
chown -R 1000:1000 $REMAPPED/home/agent
# /tmp world-writable
chmod 1777 $REMAPPED/tmp

echo "rootfs ready, ownership:"
ls -lan $REMAPPED/
ls -lan $REMAPPED/home/agent/

cat > /tmp/t4fix6/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$REMAPPED", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "echo BOOTED && exec sleep 300"],
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

# Start with newuidmap: container 0→100000, container 1000→1000
aa-exec -p runsc-userns -- unshare -Un bash -c '
  echo $$ > /tmp/t4fix6/child.pid
  while [ ! -s /tmp/t4fix6/maps-done ]; do sleep 0.1; done

  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t4fix6/state create --bundle /tmp/t4fix6 t4fix6 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t4fix6/state start t4fix6 2>&1
  echo started
  sleep 30
' &
BG=$!
sleep 1

CHILD_PID=$(cat /tmp/t4fix6/child.pid)
echo "child PID=$CHILD_PID"

newuidmap $CHILD_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "newuidmap rc=$?"
newgidmap $CHILD_PID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "newgidmap rc=$?"
echo "done" > /tmp/t4fix6/maps-done

sleep 5

echo "--- exec as root: ls /home/agent ---"
runsc --root /tmp/t4fix6/state exec t4fix6 /bin/sh -c 'ls -lan /home/agent/' 2>&1

echo "--- exec as agent ---"
runsc --root /tmp/t4fix6/state exec --user 1000:1000 t4fix6 /bin/sh -c '
  id
  touch /home/agent/test-write && echo home-write-ok || echo home-write-failed
  touch /tmp/test && echo tmp-write-ok || echo tmp-write-failed
' 2>&1

runsc --root /tmp/t4fix6/state kill t4fix6 2>/dev/null
sleep 1
runsc --root /tmp/t4fix6/state delete t4fix6 2>/dev/null
kill $BG 2>/dev/null
wait $BG 2>/dev/null
