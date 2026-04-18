#!/bin/bash
# Exp 12: Full integration — rootless gVisor with proxy UDS and egress
set -e
rm -rf /tmp/exp12 && mkdir -p /tmp/exp12/state

cd ~/proj/safeyolo && source .venv/bin/activate

ROOTFS=$HOME/.safeyolo/share/rootfs-base
CONFIG_SHARE=$HOME/.safeyolo/agents/udsecond/config-share
STATUS_DIR=$HOME/.safeyolo/agents/udsecond/status
PROXY_SOCK=$HOME/.safeyolo/data/sockets/udsecond.sock

# Verify prerequisites exist
ls "$ROOTFS" > /dev/null
ls "$CONFIG_SHARE" > /dev/null
ls "$PROXY_SOCK" > /dev/null
mkdir -p "$STATUS_DIR"
echo "prereqs OK"

cat > /tmp/exp12/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/bash", "-c", "mkdir -p /var/log && exec /safeyolo/guest-init >> /var/log/safeyolo-boot.log 2>&1"],
    "env": [
      "PATH=/opt/mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "HOME=/home/agent",
      "SAFEYOLO_DETACH=1",
      "DEBIAN_FRONTEND=noninteractive"
    ],
    "cwd": "/"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]},
    {"destination": "/safeyolo", "type": "bind", "source": "$CONFIG_SHARE", "options": ["rbind", "ro"]},
    {"destination": "/safeyolo-status", "type": "bind", "source": "$STATUS_DIR", "options": ["rbind", "rw"]},
    {"destination": "/safeyolo/proxy.sock", "type": "bind", "source": "$PROXY_SOCK", "options": ["bind", "rw"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}],
    "resources": {"pids": {"limit": 4096}}
  }
}
SPECEOF

echo "spec written"

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo

  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host --root /tmp/exp12/state create --bundle /tmp/exp12 exp12 2>&1
  echo create_rc=\$?

  runsc --ignore-cgroups --network=host --root /tmp/exp12/state start exp12 2>&1
  echo start_rc=\$?

  sleep 8

  echo '--- exec: ip addr ---'
  runsc --root /tmp/exp12/state exec exp12 /bin/sh -c 'ip addr show lo' 2>&1

  echo '--- exec: curl via proxy ---'
  runsc --root /tmp/exp12/state exec --user 1000:1000 exp12 /bin/sh -c 'curl -sf -o /dev/null -w %{http_code} -x http://127.0.0.1:8080 http://ifconfig.co 2>&1' 2>&1
  echo curl_rc=\$?

  echo '--- cleanup ---'
  runsc --root /tmp/exp12/state kill exp12 2>/dev/null
  sleep 1
  runsc --root /tmp/exp12/state delete exp12 2>/dev/null
"

echo "--- status dir ---"
ls "$STATUS_DIR"
echo "--- bridge log ---"
tail -3 ~/.safeyolo/logs/proxy-bridge.log
echo "--- port-identity ---"
grep port-identity ~/.local/state/safeyolo/mitmproxy.log | tail -3
