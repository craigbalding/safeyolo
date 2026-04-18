#!/bin/bash
# T8: full proxy UDS flow — container → proxy.sock → bridge → mitmproxy → internet
set -e
rm -rf /tmp/t8 && mkdir -p /tmp/t8/state

cd ~/proj/safeyolo && source .venv/bin/activate

ROOTFS=$HOME/.safeyolo/share/rootfs-base
CONFIG_SHARE=$HOME/.safeyolo/agents/udsecond/config-share
STATUS_DIR=$HOME/.safeyolo/agents/udsecond/status
PROXY_SOCK=$HOME/.safeyolo/data/sockets/udsecond.sock

# Verify prerequisites
for f in "$ROOTFS" "$CONFIG_SHARE" "$PROXY_SOCK"; do
  ls "$f" > /dev/null || { echo "MISSING: $f"; exit 1; }
done
mkdir -p "$STATUS_DIR"
echo "prereqs OK"

cat > /tmp/t8/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "chown -R 1000:1000 /home/agent 2>/dev/null; exec sleep 300"],
    "env": [
      "PATH=/opt/mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "HOME=/home/agent",
      "HTTP_PROXY=http://127.0.0.1:8080",
      "HTTPS_PROXY=http://127.0.0.1:8080",
      "http_proxy=http://127.0.0.1:8080",
      "https_proxy=http://127.0.0.1:8080",
      "NO_PROXY=localhost,127.0.0.1",
      "SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt",
      "REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/safeyolo.crt",
      "NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/safeyolo.crt"
    ],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN"],
      "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN"],
      "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN"],
      "ambient": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_NET_ADMIN"]
    }
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]},
    {"destination": "/safeyolo", "type": "bind", "source": "$CONFIG_SHARE", "options": ["rbind", "ro"]},
    {"destination": "/safeyolo-status", "type": "bind", "source": "$STATUS_DIR", "options": ["rbind", "rw"]},
    {"destination": "/safeyolo/proxy.sock", "type": "bind", "source": "$PROXY_SOCK", "options": ["bind", "rw"]},
    {"destination": "/usr/local/share/ca-certificates/safeyolo.crt", "type": "bind", "source": "$CONFIG_SHARE/mitmproxy-ca-cert.pem", "options": ["bind", "ro"]}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}]
  }
}
SPECEOF

aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t8/state create --bundle /tmp/t8 t8 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t8/state start t8 2>&1
  echo started
"
sleep 3

echo "=== start guest-proxy-forwarder ==="
runsc --root /tmp/t8/state exec t8 /bin/sh -c '
  /safeyolo/guest-proxy-forwarder &
  sleep 2
  echo "forwarder running: $(ps aux | grep forwarder | grep -v grep | wc -l)"
' 2>&1

echo "=== curl via proxy ==="
runsc --root /tmp/t8/state exec --user 1000:1000 t8 /bin/sh -c '
  curl -sf -o /dev/null -w "http_code=%{http_code}" http://ifconfig.co 2>&1
' 2>&1
echo "curl_rc=$?"

echo "=== bridge log ==="
tail -3 ~/.safeyolo/logs/proxy-bridge.log

echo "=== port-identity ==="
grep port-identity ~/.local/state/safeyolo/mitmproxy.log | tail -3

runsc --root /tmp/t8/state kill t8 2>/dev/null
sleep 1
runsc --root /tmp/t8/state delete t8 2>/dev/null
