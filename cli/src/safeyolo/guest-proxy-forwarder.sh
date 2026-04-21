#!/bin/sh
# Guest-side proxy forwarder.
#
# Bridges the agent's HTTP_PROXY target (127.0.0.1:8080 TCP inside the
# sandbox) to the host-side SafeYolo proxy via one of:
#
#   UDS (Linux / gVisor): /safeyolo/proxy.sock — bind-mounted from the
#     host, reached through gVisor's --host-uds=open.
#   vsock (macOS / VZ):   port 1080 on the host CID — safeyolo-vm's
#     VSockProxyRelay accepts and forwards to mitmproxy.
#
# Transport auto-selection: UDS is preferred when /safeyolo/proxy.sock
# exists; otherwise fall back to vsock. Same contract as the previous
# guest-proxy-forwarder.py that this replaces (socat 1.8+ gained
# VSOCK-CONNECT, making the python stdlib pump unnecessary).
#
# Runs as a daemon started by guest-init-per-run; exits on SIGTERM / VM
# shutdown.
set -eu

LISTEN_PORT="${1:-8080}"
UDS_PATH="${2:-/safeyolo/proxy.sock}"
VSOCK_HOST_CID=2
VSOCK_HOST_PORT=1080

if [ -S "$UDS_PATH" ]; then
    upstream="UNIX-CONNECT:$UDS_PATH"
else
    upstream="VSOCK-CONNECT:$VSOCK_HOST_CID:$VSOCK_HOST_PORT"
fi

echo "[guest-proxy-forwarder] 127.0.0.1:${LISTEN_PORT} -> ${upstream} (running as agent)" >&2
# su=agent: socat opens the TCP listener as root (launched via sudo from
# guest-init-per-run), then setuid()'s to the agent user before any
# client connection is accepted. Per-connection AF_VSOCK creation and
# UNIX-CONNECT work fine as agent (UDS perms are granted via gVisor
# userns mapping on Linux; AF_VSOCK socket() itself is unprivileged).
# Narrowing the attack surface: a socat bug can't give root in the VM.
exec socat \
    "TCP-LISTEN:${LISTEN_PORT},bind=127.0.0.1,reuseaddr,fork,su=agent" \
    "${upstream}"
