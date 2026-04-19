#!/bin/bash
set -e
rm -rf /tmp/t29 && mkdir -p /tmp/t29/state
chmod 777 /tmp/t29/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
sudo setfacl -m u:100000:rw /dev/kvm

cat > /tmp/t29/config.json << EOF
{"ociVersion":"1.0.0","root":{"path":"$ROOTFS","readonly":false},"process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/bin/sh","-c","exec sleep 60"],"env":["PATH=/usr/bin:/bin"],"cwd":"/"},"mounts":[{"destination":"/proc","type":"proc","source":"proc"}],"linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}
EOF

aa-exec -p safeyolo-runsc -- unshare -Un sleep 30 &
UP=$!
sleep 1
newuidmap $UP 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UP 0 100000 1000 1000 $(id -g) 1 1001 101001 64534

echo "=== network=none ==="
nsenter --user --net --target $UP -- bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=none \
        --root /tmp/t29/state create --bundle /tmp/t29 t29 2>&1
  runsc --ignore-cgroups --root /tmp/t29/state start t29 2>&1
"
sleep 2
nsenter --user --target $UP -- runsc --root /tmp/t29/state exec t29 /bin/sh -c '
  python3 -c "
import socket
for addr in [\"127.0.0.1\", \"0.0.0.0\"]:
    s = socket.socket()
    try:
        s.bind((addr, 8080))
        print(f\"bind {addr}:8080 OK\")
        s.close()
    except Exception as e:
        print(f\"bind {addr}:8080 FAIL: {e}\")
"
' 2>&1

nsenter --user --target $UP -- runsc --root /tmp/t29/state kill t29 2>/dev/null
sleep 1
nsenter --user --target $UP -- runsc --root /tmp/t29/state delete t29 2>/dev/null
kill $UP 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
