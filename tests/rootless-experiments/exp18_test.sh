#!/bin/bash
# Exp 18: newuidmap 0→100000, 1000→1000 with KVM ACL
set -e
rm -rf /tmp/exp18 && mkdir -p /tmp/exp18/state
chmod 777 /tmp/exp18/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo

# Step 1: give uid 100000 access to /dev/kvm
# setfacl not installed — use chmod as workaround for testing
sudo chmod 666 /dev/kvm
echo "kvm permissions: $(ls -la /dev/kvm)"

# Step 2: OCI spec
cat > /tmp/exp18/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "chown -R 1000:1000 /home/agent 2>/dev/null; exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin", "HOME=/home/agent"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETUID","CAP_SETGID","CAP_KILL","CAP_NET_ADMIN"]
    }
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","mode=1777"]},
    {"destination": "/workspace", "type": "bind", "source": "$WORKSPACE", "options": ["rbind","rw","nosuid","nodev"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

# Step 3: create userns, set uid maps, nsenter to run gVisor
aa-exec -p runsc-userns -- unshare -Un sleep 120 &
UPID=$!
sleep 1

# container 0 → host 100000, container 1000 → host 1000
newuidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534
echo "uid maps written"

# nsenter into the userns as root (uid 0 = host 100000)
nsenter --user --net --target $UPID -- bash -c '
  echo "inside userns: $(id)"
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/exp18/state create --bundle /tmp/exp18 exp18 2>&1
  echo "create_rc=$?"
  runsc --ignore-cgroups --network=host --root /tmp/exp18/state start exp18 2>&1
  echo "start_rc=$?"
'
sleep 3

echo "=== exec from outside as uid 1000 ==="
# Need to nsenter into userns for exec too (state dir owned by 100000)
nsenter --user --target $UPID -- \
  runsc --root /tmp/exp18/state exec --user 1000:1000 --cwd /workspace exp18 \
    /bin/sh -c '
      echo "id: $(id)"
      echo "workspace owner: $(ls -ld /workspace | awk "{print \$3,\$4}")"
      touch /workspace/exp18-write-test && echo "workspace-write: OK" || echo "workspace-write: FAILED"
      rm -f /workspace/exp18-write-test
      echo "home owner: $(ls -ld /home/agent | awk "{print \$3,\$4}")"
      touch /home/agent/exp18-write-test && echo "home-write: OK" || echo "home-write: FAILED"
      rm -f /home/agent/exp18-write-test
      echo "ip addr:"
      ip addr show lo | grep inet
    ' 2>&1
echo "exec_rc=$?"

# Cleanup
nsenter --user --target $UPID -- runsc --root /tmp/exp18/state kill exp18 2>/dev/null
sleep 1
nsenter --user --target $UPID -- runsc --root /tmp/exp18/state delete exp18 2>/dev/null
kill $UPID 2>/dev/null

# Restore kvm permissions
sudo chmod 660 /dev/kvm
