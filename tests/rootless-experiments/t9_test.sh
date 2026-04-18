#!/bin/bash
# T9: two rootless agents simultaneously with correct attribution
set -e
cd ~/proj/safeyolo && source .venv/bin/activate

ROOTFS=$HOME/.safeyolo/share/rootfs-base
CONFIG_SHARE=$HOME/.safeyolo/agents/udsecond/config-share
PROXY_SOCK_1=$HOME/.safeyolo/data/sockets/udsecond.sock
CA_CERT=$CONFIG_SHARE/mitmproxy-ca-cert.pem

# We need a second agent socket. Create it manually in agent_map
# so the bridge picks it up.
SOCK_DIR=$HOME/.safeyolo/data/sockets
STATUS_DIR_1=$HOME/.safeyolo/agents/udsecond/status
mkdir -p $STATUS_DIR_1

# Update agent_map with two agents
cat > $HOME/.safeyolo/data/agent_map.json << MAPEOF
{
  "agent-a": {"ip": "10.200.0.1", "port": 30001, "socket": "$SOCK_DIR/agent-a.sock"},
  "agent-b": {"ip": "10.200.0.2", "port": 30002, "socket": "$SOCK_DIR/agent-b.sock"}
}
MAPEOF
sleep 2  # bridge polls every 1s

echo "=== agent_map ==="
cat $HOME/.safeyolo/data/agent_map.json

# Check bridge picked up both
echo "=== bridge sockets ==="
ls -la $SOCK_DIR/*.sock 2>&1

make_config() {
  local name=$1 dir=$2 sock=$3
  rm -rf $dir && mkdir -p $dir/state $dir/status
  cat > $dir/config.json << SPECEOF
{
  "ociVersion": "1.0.0",
  "root": {"path": "$ROOTFS", "readonly": false},
  "process": {
    "terminal": false, "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "exec sleep 300"],
    "env": ["PATH=/usr/bin:/bin", "HTTP_PROXY=http://127.0.0.1:8080", "http_proxy=http://127.0.0.1:8080", "SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt"],
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
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/safeyolo", "type": "bind", "source": "$CONFIG_SHARE", "options": ["rbind", "ro"]},
    {"destination": "/safeyolo/proxy.sock", "type": "bind", "source": "$sock", "options": ["bind", "rw"]},
    {"destination": "/usr/local/share/ca-certificates/safeyolo.crt", "type": "bind", "source": "$CA_CERT", "options": ["bind", "ro"]}
  ],
  "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}]}
}
SPECEOF
}

make_config agent-a /tmp/t9a "$SOCK_DIR/agent-a.sock"
make_config agent-b /tmp/t9b "$SOCK_DIR/agent-b.sock"

# Start agent-a (10.200.0.1)
aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up; ip addr add 10.200.0.1/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t9a/state create --bundle /tmp/t9a agent-a 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t9a/state start agent-a 2>&1
  echo agent-a-started
"

# Start agent-b (10.200.0.2)
aa-exec -p runsc-userns -- unshare -Urn bash -c "
  ip link set lo up; ip addr add 10.200.0.2/32 dev lo
  runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host \
        --root /tmp/t9b/state create --bundle /tmp/t9b agent-b 2>&1
  runsc --ignore-cgroups --network=host --root /tmp/t9b/state start agent-b 2>&1
  echo agent-b-started
"
sleep 3

# Start forwarders
runsc --root /tmp/t9a/state exec agent-a /bin/sh -c '/safeyolo/guest-proxy-forwarder &' 2>&1
runsc --root /tmp/t9b/state exec agent-b /bin/sh -c '/safeyolo/guest-proxy-forwarder &' 2>&1
sleep 2

# Curl from each agent
echo "=== agent-a curl ==="
runsc --root /tmp/t9a/state exec agent-a /bin/sh -c 'curl -sf -o /dev/null -w "%{http_code}" http://ifconfig.co' 2>&1
echo ""

echo "=== agent-b curl ==="
runsc --root /tmp/t9b/state exec agent-b /bin/sh -c 'curl -sf -o /dev/null -w "%{http_code}" http://ifconfig.co' 2>&1
echo ""

echo "=== port-identity (last 5) ==="
grep port-identity ~/.local/state/safeyolo/mitmproxy.log | tail -5

echo "=== bridge (last 5) ==="
tail -5 ~/.safeyolo/logs/proxy-bridge.log

# Cleanup
runsc --root /tmp/t9a/state kill agent-a 2>/dev/null
runsc --root /tmp/t9b/state kill agent-b 2>/dev/null
sleep 1
runsc --root /tmp/t9a/state delete agent-a 2>/dev/null
runsc --root /tmp/t9b/state delete agent-b 2>/dev/null

# Restore original agent_map
cat > $HOME/.safeyolo/data/agent_map.json << MAPEOF
{
  "udsecond": {"ip": "10.200.0.1", "port": 30001, "socket": "$SOCK_DIR/udsecond.sock"}
}
MAPEOF
