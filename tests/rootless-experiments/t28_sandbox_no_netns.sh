#!/bin/bash
# T28: sandbox mode WITHOUT network namespace in OCI spec
# gVisor reads from the current netns (unshare'd lo-only) and
# mirrors it into its sandbox netstack
set -e
rm -rf /tmp/t28 && mkdir -p /tmp/t28/state
chmod 777 /tmp/t28/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

sudo setfacl -m u:100000:rw /dev/kvm

# NO network namespace in OCI spec — gVisor reads current netns
cat > /tmp/t28/config.json << EOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 60"],
    "env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_NET_ADMIN"],
      "effective": ["CAP_NET_ADMIN"],
      "permitted": ["CAP_NET_ADMIN"],
      "ambient": ["CAP_NET_ADMIN"]
    }
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
EOF

aa-exec -p safeyolo-runsc -- unshare -Un sleep 30 &
UPID=$!
sleep 1
newuidmap $UPID 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 $(id -g) 1 1001 101001 64534

nsenter --user --net --target $UPID -- bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  echo host-netns-lo:
  ip addr show lo

  runsc --platform=kvm --host-uds=open --ignore-cgroups \
        --network=sandbox \
        --root /tmp/t28/state create --bundle /tmp/t28 t28 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --root /tmp/t28/state start t28 2>&1
  echo start_rc=\$?
"
sleep 2

echo "=== interfaces inside sandbox ==="
nsenter --user --target $UPID -- \
  runsc --root /tmp/t28/state exec t28 /bin/sh -c '
    ip link show
    echo ---
    ip addr show
    echo ---
    python3 -c "
import socket
for addr in [\"127.0.0.1\", \"10.200.0.1\", \"0.0.0.0\"]:
    s = socket.socket()
    try:
        s.bind((addr, 8080))
        print(f\"bind {addr}:8080 OK\")
        s.close()
    except Exception as e:
        print(f\"bind {addr}:8080 FAIL: {e}\")
"
  ' 2>&1

nsenter --user --target $UPID -- runsc --root /tmp/t28/state kill t28 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/t28/state delete t28 2>/dev/null
kill $UPID 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
echo DONE
