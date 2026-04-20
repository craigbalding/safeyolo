#!/bin/bash
# T19: unshare -Urn workspace permissions
# Question: with unshare -Urn (container root = host operator),
# can container uid 1000 write to the workspace?
#
# The workspace dir on the host is typically 775 (rwxrwxr-x).
# Inside the container: owned by root (host operator = container root).
# Container uid 1000 gets "other" permissions (r-x from 775).
# Expected: CANNOT write. Verify.
#
# Then test: what if we chmod the workspace mount inside the OCI spec?
# Or: what if guest-init chowns /workspace to 1000:1000?
set -e
rm -rf /tmp/t19 && mkdir -p /tmp/t19/state
ROOTFS=$HOME/.safeyolo/share/rootfs-base
WORKSPACE=$HOME/proj/safeyolo

echo "=== host workspace permissions ==="
ls -ld $WORKSPACE
stat -c "%a %U:%G" $WORKSPACE

cat > /tmp/t19/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "chown -R 1000:1000 /home/agent 2>/dev/null; exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin"],
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

aa-exec -p safeyolo-runsc -- unshare -Urn bash -c "
  ip link set lo up
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t19/state create --bundle /tmp/t19 t19 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t19/state start t19 2>&1
  echo started
"
sleep 3

echo "=== T19a: workspace permissions inside container ==="
runsc --root /tmp/t19/state exec t19 /bin/sh -c '
  ls -ld /workspace
  stat -c "%a %U:%G" /workspace
'

echo "=== T19b: agent write to workspace (expect FAIL) ==="
runsc --root /tmp/t19/state exec --user 1000:1000 t19 /bin/sh -c '
  id
  touch /workspace/t19-test 2>&1 && echo "WRITE OK" || echo "WRITE FAILED"
'

echo "=== T19c: chown workspace to agent, then write ==="
runsc --root /tmp/t19/state exec t19 /bin/sh -c '
  chown 1000:1000 /workspace 2>&1 && echo "chown OK" || echo "chown FAILED"
'
runsc --root /tmp/t19/state exec --user 1000:1000 t19 /bin/sh -c '
  touch /workspace/t19-test 2>&1 && echo "WRITE AFTER CHOWN OK" || echo "WRITE AFTER CHOWN FAILED"
  rm -f /workspace/t19-test
'

echo "=== T19d: does chown /workspace affect host? ==="
ls -ld $WORKSPACE
stat -c "%a %U:%G" $WORKSPACE

runsc --root /tmp/t19/state kill t19 2>/dev/null
sleep 1
runsc --root /tmp/t19/state delete t19 2>/dev/null
