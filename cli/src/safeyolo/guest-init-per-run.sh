#!/bin/bash
#
# SafeYolo guest-init — PER-RUN phase.
#
# Runs after the /safeyolo/per-run-go gate, which the host opens either
# immediately (passthrough / restore) or after taking a snapshot (capture).
# Contains the state that must be re-applied every run, even when resuming
# a snapshot captured on a previous run:
#   - hwclock resync (after restore the system clock has jumped)
#   - VirtioFS readdir (host-side per-run files may be invisible to a
#     resumed guest until the directory is re-read)
#   - agent.env / proxy.env sourcing (agent_token, mise package, argv
#     overrides — all per-run)
#   - instructions injection
#   - mise install of the agent binary if missing
#   - remount /safeyolo read-only and launch the agent
#
set -e
export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# 0. Post-restore fixups (no-ops on cold boot)
# --------------------------------------------------------------------------
# System clock jumps across restore — sync from the VZ-provided hwclock.
hwclock -s 2>/dev/null || true

# Invalidate VirtioFS readdir cache so per-run files the host wrote while
# the guest was paused/snapshotted become visible. Read of the directory
# is enough; content isn't used.
ls /safeyolo >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
# 1. Configure environment
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
# 2. Inject agent instructions (e.g., /etc/claude-code/CLAUDE.md)
# --------------------------------------------------------------------------
if [ -f /safeyolo/instructions.md ] && [ -n "${SAFEYOLO_INSTRUCTIONS_PATH:-}" ]; then
    mkdir -p "$(dirname "$SAFEYOLO_INSTRUCTIONS_PATH")"
    cp /safeyolo/instructions.md "$SAFEYOLO_INSTRUCTIONS_PATH"
fi

# --------------------------------------------------------------------------
# 3. Agent API token (may rotate between runs — always refresh)
# --------------------------------------------------------------------------
if [ -f /safeyolo/agent_token ]; then
    mkdir -p /app
    cp /safeyolo/agent_token /app/agent_token
    chmod 644 /app/agent_token
fi

# --------------------------------------------------------------------------
# 4. Install agent binary via mise if missing
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
# 5. Run user init hook
# --------------------------------------------------------------------------
if [ -f /home/agent/.safeyolo-hooks/agent-init.sh ]; then
    su agent -c "bash /home/agent/.safeyolo-hooks/agent-init.sh" || true
fi

# --------------------------------------------------------------------------
# 6. Remount config share read-only (all writes complete)
# --------------------------------------------------------------------------
mount -o remount,ro /safeyolo 2>/dev/null || true

# --------------------------------------------------------------------------
# 7. Run agent or stay alive for SSH access
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
