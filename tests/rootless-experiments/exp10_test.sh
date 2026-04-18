#!/bin/bash
set -e
rm -rf /tmp/exp10 && mkdir -p /tmp/exp10/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

# Start a UDS listener in background
python3 << 'PYEOF' &
import socket, time, os
path = "/tmp/exp10/proxy.sock"
s = socket.socket(socket.AF_UNIX)
s.bind(path)
os.chmod(path, 0o666)
s.listen(1)
print("socket ready", flush=True)
conn, _ = s.accept()
data = conn.recv(64)
print(f"accepted, got: {data}", flush=True)
time.sleep(5)
PYEOF
BGPID=$!
sleep 1

# OCI spec with socket bind-mount
cat > /tmp/exp10/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": true},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "ls -la /safeyolo/proxy.sock && python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/safeyolo/proxy.sock\"); s.send(b\"HELLO\"); print(\"UDS_CONNECTED\")'"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/safeyolo/proxy.sock", "type": "bind", "source": "/tmp/exp10/proxy.sock", "options": ["bind", "rw"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host --root /tmp/exp10/state create --bundle /tmp/exp10 exp10 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/exp10/state start exp10 2>&1
  sleep 3
  runsc --root /tmp/exp10/state logs exp10 2>&1
"
kill $BGPID 2>/dev/null
echo "--- bg listener output ---"
wait $BGPID 2>/dev/null
