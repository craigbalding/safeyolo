#!/bin/bash
#
# SafeYolo guest init — the real init, served from VirtioFS config share.
#
# This file is written to the config share by the CLI on every agent run.
# The rootfs stub (/usr/local/bin/safeyolo-guest-init) execs this.
# Changes here take effect immediately — no rootfs rebuild needed.
#
set -e
export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# 1. Networking (static IP from config share)
# --------------------------------------------------------------------------
ip link set lo up 2>/dev/null || true

if [ -f /safeyolo/network.env ] && ip link show eth0 >/dev/null 2>&1; then
    . /safeyolo/network.env
    ip link set eth0 up
    ip addr add ${GUEST_IP}/24 dev eth0 2>/dev/null || true
    ip route add default via ${GATEWAY_IP} 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 2. Mount VirtioFS shares (workspace, host config dirs/files)
# --------------------------------------------------------------------------
mkdir -p /workspace
mount -t virtiofs workspace /workspace 2>/dev/null || true

# Host config directory mounts (e.g., ~/.claude → /home/agent/.claude)
if [ -f /safeyolo/host-mounts ]; then
    while IFS=: read -r tag guest_path; do
        [ -z "$tag" ] && continue
        mkdir -p "$guest_path"
        mount -t virtiofs "$tag" "$guest_path" 2>/dev/null || true
        chown -R agent:agent "$guest_path" 2>/dev/null || true
    done < /safeyolo/host-mounts
fi

# Host config files (copied into config share)
if [ -f /safeyolo/host-files-manifest ]; then
    while IFS=: read -r src_name guest_path; do
        [ -z "$src_name" ] && continue
        if [ -f "/safeyolo/host-files/$src_name" ]; then
            mkdir -p "$(dirname "$guest_path")"
            cp "/safeyolo/host-files/$src_name" "$guest_path"
            chown agent:agent "$guest_path" 2>/dev/null || true
        fi
    done < /safeyolo/host-files-manifest
fi

# --------------------------------------------------------------------------
# 3. Configure environment
# --------------------------------------------------------------------------
if [ -f /safeyolo/proxy.env ]; then
    set -a; . /safeyolo/proxy.env; set +a
    cp /safeyolo/proxy.env /etc/environment
fi

if [ -f /safeyolo/agent.env ]; then
    set -a; . /safeyolo/agent.env; set +a
    cat /safeyolo/agent.env >> /etc/environment
fi

echo 'export HOME=/home/agent' >> /etc/environment

# --------------------------------------------------------------------------
# 4. Trust SafeYolo CA certificate
# --------------------------------------------------------------------------
if [ -f /safeyolo/mitmproxy-ca-cert.pem ]; then
    install -m 644 /safeyolo/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/safeyolo.crt
    update-ca-certificates --fresh >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------------------
# 5. Inject agent instructions (e.g., /etc/claude-code/CLAUDE.md)
# --------------------------------------------------------------------------
if [ -f /safeyolo/instructions.md ] && [ -n "${SAFEYOLO_INSTRUCTIONS_PATH:-}" ]; then
    mkdir -p "$(dirname "$SAFEYOLO_INSTRUCTIONS_PATH")"
    cp /safeyolo/instructions.md "$SAFEYOLO_INSTRUCTIONS_PATH"
fi

# --------------------------------------------------------------------------
# 6. Set up agent token, SSH, disable IPv6
# --------------------------------------------------------------------------
if [ -f /safeyolo/agent_token ]; then
    mkdir -p /app
    cp /safeyolo/agent_token /app/agent_token
    chmod 644 /app/agent_token
fi

if [ -f /safeyolo/authorized_keys ]; then
    mkdir -p /home/agent/.ssh
    cp /safeyolo/authorized_keys /home/agent/.ssh/authorized_keys
    chown -R agent:agent /home/agent/.ssh
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys
fi

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A >/dev/null 2>&1 || true
fi

mkdir -p /run/sshd
/usr/sbin/sshd -D &

sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
# Write VM IP so the CLI can discover it
# --------------------------------------------------------------------------
VM_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo "")
if [ -n "$VM_IP" ]; then
    echo "$VM_IP" > /safeyolo/vm-ip 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 7. Install agent binary via mise if missing
# --------------------------------------------------------------------------
if [ -n "${SAFEYOLO_MISE_PACKAGE:-}" ] && [ -n "${SAFEYOLO_AGENT_BINARY:-}" ]; then
    if ! su agent -c "command -v $SAFEYOLO_AGENT_BINARY" >/dev/null 2>&1; then
        echo "installing" > /safeyolo/vm-status 2>/dev/null || true
        timeout 120 su agent -lc "mise use -g ${SAFEYOLO_MISE_PACKAGE}@latest" >/dev/null 2>&1 || {
            echo "install-failed" > /safeyolo/vm-status 2>/dev/null || true
        }
        echo "" > /safeyolo/vm-status 2>/dev/null || true
    fi
fi

# --------------------------------------------------------------------------
# 8. Run user init hook
# --------------------------------------------------------------------------
if [ -f /home/agent/.safeyolo-hooks/agent-init.sh ]; then
    su agent -c "bash /home/agent/.safeyolo-hooks/agent-init.sh" || true
fi

# --------------------------------------------------------------------------
# 9. Remount config share read-only (all writes complete)
# --------------------------------------------------------------------------
mount -o remount,ro /safeyolo 2>/dev/null || true

# --------------------------------------------------------------------------
# 10. Run agent or stay alive for SSH access
# --------------------------------------------------------------------------

YOLO_ARGS=""
if [ -n "${SAFEYOLO_YOLO_MODE:-}" ] && [ -n "${SAFEYOLO_AUTO_ARGS:-}" ]; then
    YOLO_ARGS="${SAFEYOLO_AUTO_ARGS}"
fi

# vsock-term is on the config share (cross-compiled, no rootfs rebuild needed)
VSOCK_TERM="/safeyolo/vsock-term"
if [ ! -x "$VSOCK_TERM" ]; then
    # Fallback to rootfs copy if config share version not present
    VSOCK_TERM="/usr/local/bin/vsock-term"
fi

# Detach mode: skip vsock terminal, keep VM alive for SSH access.
# The host-side safeyolo-vm runs with --no-terminal so it doesn't
# try to connect vsock. sshd is already running in background.
if [ "${SAFEYOLO_DETACH:-}" = "1" ]; then
    echo "Detach mode: VM running, SSH ready" >&2
    exec sleep infinity
fi

if [ -x "$VSOCK_TERM" ]; then
    # Exec the agent binary directly — no shell wrapper.
    # vsock-term sets up the PTY, drops privileges, sets PATH with mise shims,
    # and execs the command. A shell wrapper (bash -lc) would break the TTY
    # connection, causing process.stdout.isTTY to be undefined in Node.js.
    if [ -n "${SAFEYOLO_AGENT_CMD:-}" ]; then
        "$VSOCK_TERM" --uid 1000 --gid 1000 --home /home/agent --cwd /workspace \
            ${SAFEYOLO_AGENT_CMD} ${YOLO_ARGS} ${SAFEYOLO_AGENT_ARGS:-} || true
    else
        "$VSOCK_TERM" --uid 1000 --gid 1000 --home /home/agent --cwd /workspace \
            bash -l || true
    fi
else
    echo "Warning: vsock-term not found, falling back to basic shell" >&2
    su agent -lc "cd /workspace && bash -l" || true
fi

# Agent exited — shut down the VM cleanly.
# We are PID 1, so /sbin/{reboot,poweroff,halt} don't work: they signal init,
# which is us. Call the reboot() syscall directly via busybox, which relies
# on PSCI (CONFIG_ARM_PSCI_FW=y) to hand off to VZ.
sync
/usr/bin/busybox poweroff -f 2>/dev/null || true
# Unreachable if poweroff succeeded; fallback keeps PID 1 alive so the kernel
# doesn't panic, and the host's 5s force-stop will catch us.
exec sleep infinity
