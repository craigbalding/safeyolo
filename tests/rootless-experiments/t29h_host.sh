#!/bin/bash
# T29h: confirm --network=host still binds 127.0.0.1 (control test)
set -e
rm -rf /tmp/t29h && mkdir -p /tmp/t29h/state
chmod 777 /tmp/t29h/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
sudo setfacl -m u:100000:rw /dev/kvm

cp /tmp/t29/config.json /tmp/t29h/config.json

aa-exec -p safeyolo-runsc -- unshare -Un sleep 30 &
UP=$!
sleep 1
newuidmap $UP 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UP 0 100000 1000 1000 $(id -g) 1 1001 101001 64534

echo "=== network=host ==="
nsenter --user --net --target $UP -- bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t29h/state create --bundle /tmp/t29h t29h 2>&1
  runsc --ignore-cgroups --root /tmp/t29h/state start t29h 2>&1
"
sleep 2
nsenter --user --target $UP -- runsc --root /tmp/t29h/state exec t29h /bin/sh -c '
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

nsenter --user --target $UP -- runsc --root /tmp/t29h/state kill t29h 2>/dev/null
sleep 1
nsenter --user --target $UP -- runsc --root /tmp/t29h/state delete t29h 2>/dev/null
kill $UP 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
