#!/bin/bash
#
# SafeYolo guest-init -- PER-RUN phase.
#
# Runs after the /safeyolo/per-run-go gate, which the host opens either
# immediately (passthrough / restore) or after taking a snapshot (capture).
# Contains the state that must be re-applied every run, even when resuming
# a snapshot captured on a previous run:
#   - hwclock resync (after restore the system clock has jumped)
#   - VirtioFS readdir (host-side per-run files may be invisible to a
#     resumed guest until the directory is re-read)
#   - agent.env / proxy.env sourcing (agent_token, mise package, argv
#     overrides -- all per-run)
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
# System clock jumps across restore -- sync from the VZ-provided hwclock.
hwclock -s 2>/dev/null || true

# Invalidate VirtioFS readdir cache so per-run files the host wrote while
# the guest was paused/snapshotted become visible. Read of the directory
# is enough; content isn't used.
ls /safeyolo >/dev/null 2>&1 || true

# Definitive "the guest reached per-run" signal. The host-side CLI polls
# for this marker to decide whether a restore attempt succeeded, rather
# than racing on the stale vm-ip file that persists across runs. Written
# after the VirtioFS readdir above so the host sees the write promptly.
echo "$(date +%s)" > /safeyolo-status/per-run-started
echo "[per-run-started written] pid=$$" > /dev/console 2>/dev/null || true

# --------------------------------------------------------------------------
# 1. Configure environment
#
# We publish the env two ways so interactive shells find it regardless
# of whether the distro uses PAM:
#
#   /etc/environment        -- picked up by Debian/Ubuntu via pam_env.so
#                              when sshd's PAM stack runs. Alpine's sshd
#                              isn't PAM-linked so this file is inert
#                              there; we keep it for PAM distros and
#                              for tooling that reads it directly.
#   /etc/profile.d/safeyolo-proxy.sh -- sourced by /etc/profile on every
#                              bash-login shell (Debian, Alpine, Fedora,
#                              Arch all iterate /etc/profile.d/*.sh from
#                              /etc/profile). This is what makes
#                              `safeyolo agent shell <name>` interactive
#                              sessions pick up HTTP_PROXY etc. on
#                              non-PAM distros.
# --------------------------------------------------------------------------
if [ -f /safeyolo/proxy.env ]; then
    set -a; . /safeyolo/proxy.env; set +a
    cp /safeyolo/proxy.env /etc/environment
    install -D -m 0644 /safeyolo/proxy.env /etc/profile.d/safeyolo-proxy.sh
fi

if [ -f /safeyolo/agent.env ]; then
    set -a; . /safeyolo/agent.env; set +a
    cat /safeyolo/agent.env >> /etc/environment
    cat /safeyolo/agent.env >> /etc/profile.d/safeyolo-proxy.sh
fi

echo 'export HOME=/home/agent' >> /etc/environment
echo 'export HOME=/home/agent' >> /etc/profile.d/safeyolo-proxy.sh

# --------------------------------------------------------------------------
# 1b. Guest-side proxy forwarder (localhost:8080 -> UDS or vsock)
#
# Bridges the agent's HTTP_PROXY target (a plain TCP listener the agent
# can reach via loopback) to the host-side SafeYolo proxy. Transport is
# UDS on Linux/gVisor (bind-mounted /safeyolo/proxy.sock, reached via
# gVisor --host-uds=open) or vsock on macOS (port 1080 on the VM helper).
#
# Runs unconditionally: if neither transport is available, the forwarder
# logs the reason and exits -- harmless on agents still using the legacy
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
# lives in safeyolo-vm's VSockShellBridge. Uses socat (1.8+ required
# for VSOCK-LISTEN); socat is a runtime dep of both the default base
# and any custom rootfs -- see contrib/ROOTFS_SCRIPT_GUIDE.md.
#
# Harmless on Linux-gVisor agents -- vsock is available but the host
# side doesn't listen, so no connections are ever accepted.
# --------------------------------------------------------------------------
if [ -x /safeyolo/guest-shell-bridge ]; then
    # Probe sshd reachability so failures are diagnosable from the host.
    (
      (echo > /dev/tcp/127.0.0.1/22) 2>/dev/null \
        && echo "[per-run] sshd reachable at 127.0.0.1:22" > /dev/console \
        || { echo "[per-run] WARNING sshd NOT reachable at 127.0.0.1:22" > /dev/console
             echo "[per-run] listening ports:" > /dev/console
             ss -tlnp 2>/dev/null | head -20 > /dev/console || netstat -tln 2>/dev/null | head -20 > /dev/console || true
             echo "[per-run] sshd.log tail:" > /dev/console
             tail -10 /var/log/sshd.log 2>/dev/null > /dev/console || true
             echo "[per-run] /etc/hosts.deny:" > /dev/console
             cat /etc/hosts.deny 2>/dev/null > /dev/console || true
             echo "[per-run] ip addr:" > /dev/console
             ip -o addr 2>/dev/null > /dev/console || ifconfig -a 2>/dev/null > /dev/console || true; }
    ) 2>/dev/null || true
    setsid nohup /safeyolo/guest-shell-bridge >/var/log/shell-bridge.log 2>&1 </dev/null &
    SB_PID=$!
    echo "[per-run] started guest-shell-bridge (pid=$SB_PID)" > /dev/console 2>/dev/null || true
    sleep 0.5
    if kill -0 "$SB_PID" 2>/dev/null; then
        echo "[per-run] guest-shell-bridge alive" > /dev/console
    else
        echo "[per-run] guest-shell-bridge EXITED; log:" > /dev/console
        cat /var/log/shell-bridge.log > /dev/console 2>/dev/null || true
    fi
fi

# --------------------------------------------------------------------------
# 2. Agent API token (may rotate between runs -- always refresh)
# --------------------------------------------------------------------------
if [ -f /safeyolo/agent_token ]; then
    mkdir -p /app
    cp /safeyolo/agent_token /app/agent_token
    chmod 644 /app/agent_token
fi

echo "ready" > /safeyolo-status/vm-status

# --------------------------------------------------------------------------
# 3. Run user init hook (legacy; host script can write here too)
# --------------------------------------------------------------------------
if [ -f /home/agent/.safeyolo-hooks/agent-init.sh ]; then
    su agent -c "bash /home/agent/.safeyolo-hooks/agent-init.sh" || true
fi

# --------------------------------------------------------------------------
# 4. Run the host-script-provided foreground command, or bash
#
# The host script (`safeyolo agent add --host-script ...`) may write an
# executable at /home/agent/.safeyolo-command. If present, we exec
# that. Otherwise the sandbox boots to an interactive bash login. In
# both cases SAFEYOLO_AGENT_ARGS (from `agent run -- …`) is appended
# as extra arguments to the command, for users who want to pass
# flags at run time rather than baking them into the command file.
# --------------------------------------------------------------------------

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

if [ "${SAFEYOLO_HOST_TERMINAL:-}" = "1" ]; then
    # Linux/gVisor: the host CLI launches the agent via `runsc exec`,
    # which bridges the user's terminal into the sandbox directly.
    # Keep the container alive so runsc exec has a target.
    exec sleep infinity
elif [ -x "$VSOCK_TERM" ]; then
    # macOS: vsock-term sets up the PTY, drops privileges, sets PATH,
    # and execs the command. A shell wrapper (bash -lc) would break
    # the TTY connection, causing process.stdout.isTTY to be undefined
    # in Node.js.
    if [ -x /home/agent/.safeyolo-command ]; then
        "$VSOCK_TERM" --uid 1000 --gid 1000 --home /home/agent --cwd /workspace \
            /home/agent/.safeyolo-command ${SAFEYOLO_AGENT_ARGS:-} || true
    else
        "$VSOCK_TERM" --uid 1000 --gid 1000 --home /home/agent --cwd /workspace \
            bash -l || true
    fi
else
    echo "Error: no terminal bridge available" >&2
    echo "terminal-failed" > /safeyolo-status/vm-status
fi

# Agent exited -- shut down the VM cleanly.
# We are PID 1, so /sbin/{reboot,poweroff,halt} don't work: they signal init,
# which is us. Call the reboot() syscall directly via busybox, which relies
# on PSCI (CONFIG_ARM_PSCI_FW=y) to hand off to VZ.
sync
/usr/bin/busybox poweroff -f 2>/dev/null || true
# Unreachable if poweroff succeeded; fallback keeps PID 1 alive so the kernel
# doesn't panic, and the host's 5s force-stop will catch us.
exec sleep infinity
