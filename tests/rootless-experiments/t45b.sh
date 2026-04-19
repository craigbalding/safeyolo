#!/bin/bash
# T45b: retry EROFS with world-readable image
set -e
cd ~/proj/safeyolo && source .venv/bin/activate

rm -rf /tmp/t45 && mkdir -p /tmp/t45/state /tmp/t45/rootfs
chmod 777 /tmp/t45/state

EROFS=$HOME/.safeyolo/share/rootfs-base.erofs

sudo setfacl -m u:100000:rw /dev/kvm 2>/dev/null

cat > /tmp/t45/config.json << EOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "/tmp/t45/rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 60"],
    "env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_ADMIN","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_FOWNER"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_ADMIN","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_FOWNER"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_ADMIN","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_FOWNER"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_NET_ADMIN","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_FOWNER"]
    }
  },
  "annotations": {
    "dev.gvisor.spec.rootfs.source": "$EROFS",
    "dev.gvisor.spec.rootfs.type": "erofs",
    "dev.gvisor.spec.rootfs.overlay": "memory"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/workspace", "type": "bind", "source": "$HOME/proj/safeyolo", "options": ["rbind","rw"]}
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

NETNS="/proc/$UPID/ns/net"
python3 -c "
import json
with open('/tmp/t45/config.json') as f:
    c = json.load(f)
c['linux']['namespaces'].append({'type': 'network', 'path': '$NETNS'})
with open('/tmp/t45/config.json', 'w') as f:
    json.dump(c, f, indent=2)
"

nsenter --user --net --target $UPID -- bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=sandbox \
        --root /tmp/t45/state create --bundle /tmp/t45 t45 2>&1
  echo create_rc=\$?
  runsc --ignore-cgroups --root /tmp/t45/state start t45 2>&1
  echo start_rc=\$?
"
sleep 3

echo "=== ownership ==="
nsenter --user --target $UPID -- runsc --root /tmp/t45/state exec t45 /bin/sh -c '
  stat -c "%U:%G %a %n" / /etc /home/agent /etc/shadow 2>/dev/null
' 2>&1

echo "=== access ==="
nsenter --user --target $UPID -- runsc --root /tmp/t45/state exec --user 1000:1000 t45 /bin/sh -c '
  id
  touch /home/agent/test && echo home-ok && rm /home/agent/test
  touch /workspace/test && echo ws-ok && rm /workspace/test
  touch /etc/test 2>/dev/null && echo etc-BAD || echo etc-blocked
  cat /etc/shadow > /dev/null 2>&1 && echo shadow-BAD || echo shadow-blocked
' 2>&1

echo "=== network ==="
nsenter --user --target $UPID -- runsc --root /tmp/t45/state exec t45 /bin/sh -c '
  ip addr show lo | grep inet
' 2>&1

nsenter --user --target $UPID -- runsc --root /tmp/t45/state kill t45 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/t45/state delete t45 2>/dev/null
kill $UPID 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
echo DONE
