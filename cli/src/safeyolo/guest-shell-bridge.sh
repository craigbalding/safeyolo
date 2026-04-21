#!/bin/sh
# Guest-side shell bridge.
#
# Listens on vsock:2220 and forwards each connection to the in-VM sshd
# on 127.0.0.1:22. This is how `safeyolo agent shell` reaches an agent
# VM that has no external network interface (macOS vsock mode) -- the
# host-side VSockShellBridge in safeyolo-vm connects to vsock:2220 and
# this script pumps it to sshd.
#
# Replaces the earlier guest-shell-bridge.py. socat 1.8+ has
# VSOCK-LISTEN, making the Python stdlib version unnecessary.
#
# Runs as a daemon started by guest-init-per-run; exits on SIGTERM /
# VM shutdown. Harmless on Linux / gVisor (vsock is available but the
# host side doesn't connect).
set -eu

VSOCK_LISTEN_PORT=2220
TARGET_HOST=127.0.0.1
TARGET_PORT=22

echo "[guest-shell-bridge] vsock:${VSOCK_LISTEN_PORT} -> ${TARGET_HOST}:${TARGET_PORT}" >&2
exec socat \
    "VSOCK-LISTEN:${VSOCK_LISTEN_PORT},reuseaddr,fork" \
    "TCP:${TARGET_HOST}:${TARGET_PORT}"
