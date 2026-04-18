#!/bin/bash
# T23: pass /dev/kvm fd through nsenter via /proc/self/fd
#
# Strategy: open /dev/kvm BEFORE entering the userns.
# nsenter preserves inherited fds. Inside the userns,
# /proc/self/fd/N still points to the open kvm device.
# Use --platform_device_path=/proc/self/fd/N to tell runsc
# to open THAT path instead of /dev/kvm.
set -e
rm -rf /tmp/t23 && mkdir -p /tmp/t23/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo

cat > /tmp/t23/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/workspace", "type": "bind", "source": "$WORKSPACE", "options": ["rbind","rw"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Create userns with newuidmap (need multi-uid for workspace write)
aa-exec -p safeyolo-runsc -- unshare -Un sleep 120 &
UPID=$!
sleep 1
newuidmap $UPID 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 $(id -g) 1 1001 101001 64534
echo "userns ready, pid=$UPID"

# Open /dev/kvm as the OPERATOR (before nsenter) on fd 9
exec 9</dev/kvm
echo "kvm fd 9 opened as operator (uid $(id -u))"

# nsenter into userns. fd 9 survives. Use /proc/self/fd/9 as device path.
nsenter --user --net --target $UPID -- bash -c "
  echo inside userns: \$(id)
  echo kvm fd 9 readable: \$(test -r /proc/self/fd/9 && echo yes || echo no)
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --platform_device_path=/proc/self/fd/9 \
        --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t23/state create --bundle /tmp/t23 t23 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --network=host --root /tmp/t23/state start t23 2>&1
  echo start_rc=\$?
"
exec 9<&-  # close fd

sleep 3

echo "=== agent write ==="
nsenter --user --target $UPID -- \
  runsc --root /tmp/t23/state exec --user 1000:1000 --cwd /workspace t23 \
    /bin/sh -c '
      id
      touch /workspace/t23-test && echo "WRITE OK" || echo "WRITE FAILED"
      rm -f /workspace/t23-test
      echo "ip:" && ip addr show lo | grep 10.200
    ' 2>&1

nsenter --user --target $UPID -- runsc --root /tmp/t23/state kill t23 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/t23/state delete t23 2>/dev/null
kill $UPID 2>/dev/null
