#!/bin/bash
# T2: runsc kill from outside + T3: sandbox survives unshare exit
set -e
rm -rf /tmp/t2t3 && mkdir -p /tmp/t2t3/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base

cat > /tmp/t2t3/config.json << SPECEOF
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Start sandbox and EXIT the unshare immediately
aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t2t3/state create --bundle /tmp/t2t3 t2t3 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t2t3/state start t2t3 2>&1
  echo sandbox-started
  # EXIT — don't keep unshare alive
"
echo "unshare exited"

sleep 2

# T3: Is the sandbox still running after unshare exited?
echo "--- T3: sandbox alive after unshare exit? ---"
runsc --root /tmp/t2t3/state state t2t3 2>&1 | python3 -c 'import sys,json; print(json.load(sys.stdin)["status"])' 2>&1
echo "state_rc=$?"

# T3b: Can we still exec?
echo "--- T3b: exec after unshare exit ---"
runsc --root /tmp/t2t3/state exec t2t3 /bin/sh -c 'echo ALIVE_AFTER_UNSHARE_EXIT' 2>&1
echo "exec_rc=$?"

# T2: runsc kill from outside
echo "--- T2: runsc kill from outside ---"
runsc --root /tmp/t2t3/state kill t2t3 2>&1
echo "kill_rc=$?"
sleep 2

runsc --root /tmp/t2t3/state state t2t3 2>&1 | python3 -c 'import sys,json; print(json.load(sys.stdin)["status"])' 2>&1
echo "post_kill_state_rc=$?"

# T2b: delete
runsc --root /tmp/t2t3/state delete t2t3 2>&1
echo "delete_rc=$?"
