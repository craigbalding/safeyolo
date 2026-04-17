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

echo "[per-run start] pid=$$" > /dev/console 2>/dev/null || true

# --------------------------------------------------------------------------
# 0. Post-restore fixups (no-ops on cold boot)
# --------------------------------------------------------------------------
# System clock jumps across restore — sync from the VZ-provided hwclock.
hwclock -s 2>/dev/null || true

# Invalidate VirtioFS readdir cache so per-run files the host wrote while
# the guest was paused/snapshotted become visible. Read of the directory
# is enough; content isn't used.
ls /safeyolo >/dev/null 2>&1 || true

# Definitive "the guest reached per-run" signal. The host-side CLI polls
# for this marker to decide whether a restore attempt succeeded, rather
# than racing on the stale vm-ip file that persists across runs. Written
# after the VirtioFS readdir above so the host sees the write promptly.
echo "$(date +%s)" > /safeyolo/per-run-started 2>/dev/null || true
echo "[per-run-started written] pid=$$" > /dev/console 2>/dev/null || true

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
# 1b. Guest-side proxy forwarder (localhost:8080 -> UDS or vsock)
#
# Bridges the agent's HTTP_PROXY target (a plain TCP listener the agent
# can reach via loopback) to the host-side SafeYolo proxy. Transport is
# UDS on Linux/gVisor (bind-mounted /safeyolo/proxy.sock, reached via
# gVisor --host-uds=open) or vsock on macOS (port 1080 on the VM helper).
#
# Runs unconditionally: if neither transport is available, the forwarder
# logs the reason and exits — harmless on agents still using the legacy
# veth/feth path. Runs as daemon; stderr lands on console for diagnostics.
# Not blocking: guest-init continues even if the forwarder fails to start.
# --------------------------------------------------------------------------
if [ -x /safeyolo/guest-proxy-forwarder ]; then
    setsid nohup /safeyolo/guest-proxy-forwarder >/dev/console 2>&1 </dev/null &
    echo "[per-run] started guest-proxy-forwarder (pid=$!)" > /dev/console 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 1c. Shell bridge: vsock:2220 -> 127.0.0.1:22 (sshd)
#
# Lets `safeyolo agent shell` reach sshd from the host when the VM has
# no network interface (macOS vsock mode). The host side of the bridge
# lives in safeyolo-vm's VSockShellBridge. socat is already in the
# image (installed at rootfs build time).
#
# Harmless on Linux-gVisor agents — vsock is available but the host
# side doesn't listen, so no connections are ever accepted.
# --------------------------------------------------------------------------
if [ -x /safeyolo/guest-shell-bridge ]; then
    setsid nohup /safeyolo/guest-shell-bridge >/dev/console 2>&1 </dev/null &
    echo "[per-run] started guest-shell-bridge (pid=$!)" > /dev/console 2>/dev/null || true
fi

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
# 4. Install agent binary via mise — safety net only
#
# The real install happens in guest-init-static (pre-snapshot) so the
# binary is captured in the rootfs clone and restore doesn't re-install.
# This block is a no-op on the happy path (command -v succeeds). It
# only fires when static's install failed at capture time, or when
# something external removed the binary — either way we retry here and
# the agent still gets to launch.
# --------------------------------------------------------------------------
if [ -n "${SAFEYOLO_MISE_PACKAGE:-}" ] && [ -n "${SAFEYOLO_AGENT_BINARY:-}" ]; then
    # `-lc` so mise's shell activation sources the profile and adds its
    # shims to PATH — otherwise `command -v` reports a correctly-installed
    # binary as missing and we redundantly re-run `mise use -g` on every
    # boot. This safety-net is meant to be a no-op after a healthy
    # static-phase install.
    if ! su agent -lc "command -v $SAFEYOLO_AGENT_BINARY" >/dev/null 2>&1; then
        echo "installing" > /safeyolo/vm-status 2>/dev/null || true
        timeout 120 su agent -lc "mise use -g ${SAFEYOLO_MISE_PACKAGE}@latest" >/dev/null 2>&1 || true
    fi
    # Ground vm-status in reality — the install command's exit code can
    # lie (timeout fires after the binary is already in place), and
    # skipping the install block entirely because a stale install-failed
    # from static is still on disk is exactly how the status went out of
    # sync in practice. `command -v` is the source of truth.
    if su agent -lc "command -v $SAFEYOLO_AGENT_BINARY" >/dev/null 2>&1; then
        echo "" > /safeyolo/vm-status 2>/dev/null || true
    else
        echo "install-failed" > /safeyolo/vm-status 2>/dev/null || true
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
