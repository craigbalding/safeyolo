#!/bin/bash
# T25: --network=sandbox with newuidmap userns
set -e
rm -rf /tmp/t25 && mkdir -p /tmp/t25/state
chmod 777 /tmp/t25/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t25/config.json << EOF
{"ociVersion":"1.0.0","root":{"path":"$ROOTFS","readonly":false},"process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/bin/sh","-c","exec sleep 60"],"env":["PATH=/usr/bin:/bin"],"cwd":"/"},"mounts":[{"destination":"/proc","type":"proc","source":"proc"}],"linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}
EOF

# Need KVM ACL for this test since we're using newuidmap
sudo setfacl -m u:100000:rw /dev/kvm

aa-exec -p safeyolo-runsc -- unshare -Un sleep 30 &
UPID=$!
sleep 1
newuidmap $UPID 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 $(id -g) 1 1001 101001 64534
echo "userns pid=$UPID"

nsenter --user --net --target $UPID -- bash -c "
  echo inside: \$(id)
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  echo trying sandbox networking...
  runsc --platform=kvm --host-uds=open --ignore-cgroups \
        --network=sandbox \
        --root /tmp/t25/state create --bundle /tmp/t25 t25 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --root /tmp/t25/state start t25 2>&1
  echo start_rc=\$?
"
sleep 2

echo "=== state ==="
nsenter --user --target $UPID -- runsc --root /tmp/t25/state state t25 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["status"])' 2>&1 || echo "not running"

echo "=== ip addr inside ==="
nsenter --user --target $UPID -- runsc --root /tmp/t25/state exec t25 /bin/sh -c 'ip addr show' 2>&1

nsenter --user --target $UPID -- runsc --root /tmp/t25/state kill t25 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/t25/state delete t25 2>/dev/null
kill $UPID 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
echo DONE
