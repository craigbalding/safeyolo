#!/bin/bash
# T26: can guest-init bring up loopback inside sandbox networking?
set -e
rm -rf /tmp/t26 && mkdir -p /tmp/t26/state
chmod 777 /tmp/t26/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

sudo setfacl -m u:100000:rw /dev/kvm

# Give the container CAP_NET_ADMIN so it can configure lo
cat > /tmp/t26/config.json << EOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "ip link set lo up 2>&1; ip addr add 10.200.0.1/32 dev lo 2>&1; ip addr add 127.0.0.1/8 dev lo 2>&1; ip addr show; exec sleep 60"],
    "env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_DAC_OVERRIDE"],
      "effective": ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_DAC_OVERRIDE"],
      "permitted": ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_DAC_OVERRIDE"],
      "ambient": ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_DAC_OVERRIDE"]
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
  runsc --platform=kvm --host-uds=open --ignore-cgroups \
        --network=sandbox \
        --root /tmp/t26/state create --bundle /tmp/t26 t26 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --root /tmp/t26/state start t26 2>&1
  echo start_rc=\$?
"
sleep 3

echo "=== logs (ip link/addr output) ==="
nsenter --user --target $UPID -- \
  runsc --root /tmp/t26/state logs t26 2>&1

echo "=== exec: ip addr ==="
nsenter --user --target $UPID -- \
  runsc --root /tmp/t26/state exec t26 /bin/sh -c 'ip addr show' 2>&1

echo "=== exec: bind test ==="
nsenter --user --target $UPID -- \
  runsc --root /tmp/t26/state exec t26 /bin/sh -c '
    python3 -c "
import socket
for addr in [\"127.0.0.1\", \"10.200.0.1\", \"0.0.0.0\"]:
    s = socket.socket()
    try:
        s.bind((addr, 8080))
        print(f\"bind {addr}:8080 OK\")
        s.close()
    except Exception as e:
        print(f\"bind {addr}:8080 failed: {e}\")
"
  ' 2>&1

nsenter --user --target $UPID -- runsc --root /tmp/t26/state kill t26 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/t26/state delete t26 2>/dev/null
kill $UPID 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
echo DONE
