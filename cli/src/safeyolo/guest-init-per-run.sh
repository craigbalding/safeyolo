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
#   - agent.env / proxy.env sourcing (agent_token, argv overrides,
#     auth env -- all per-run; the agent binary and mise itself are
#     baked into the rootfs at build time)
#   - instructions injection
#   - remount /safeyolo read-only and launch the agent
#
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[per-run start] pid=$$" > /dev/console 2>/dev/null || true

# The orchestrator execs this script as PID 1. Use a separate process to set
# the limit on numeric PID 1, then read the same /proc/1 file that an agent
# shell reads later. Reapply after restore and before the host receives its
# ready marker. This does not depend on Bash's saved view of its own PID.
ensure_pid1_nofile() {
    _nofile_limit=65536
    if ! command -v prlimit >/dev/null 2>&1; then
        echo "FATAL: prlimit is required to establish PID 1 RLIMIT_NOFILE=${_nofile_limit}/${_nofile_limit}" >&2
        echo "[per-run fatal] prlimit is required for PID 1 RLIMIT_NOFILE" > /dev/console 2>/dev/null || true
        return 1
    fi
    if ! prlimit --pid 1 --nofile="${_nofile_limit}:${_nofile_limit}"; then
        echo "FATAL: unable to establish PID 1 RLIMIT_NOFILE=${_nofile_limit}/${_nofile_limit}" >&2
        echo "[per-run fatal] unable to establish PID 1 RLIMIT_NOFILE=${_nofile_limit}/${_nofile_limit}" > /dev/console 2>/dev/null || true
        return 1
    fi

    _nofile_soft=
    _nofile_hard=
    while read -r _limit_word1 _limit_word2 _limit_word3 _limit_soft _limit_hard _limit_unit; do
        if [ "$_limit_word1 $_limit_word2 $_limit_word3" = "Max open files" ]; then
            _nofile_soft=$_limit_soft
            _nofile_hard=$_limit_hard
            break
        fi
    done < "/proc/1/limits"
    if [ "$_nofile_soft" != "$_nofile_limit" ] || [ "$_nofile_hard" != "$_nofile_limit" ]; then
        echo "FATAL: PID 1 RLIMIT_NOFILE is ${_nofile_soft:-unknown}/${_nofile_hard:-unknown}; expected ${_nofile_limit}/${_nofile_limit}" >&2
        echo "[per-run fatal] PID 1 RLIMIT_NOFILE is ${_nofile_soft:-unknown}/${_nofile_hard:-unknown}; expected ${_nofile_limit}/${_nofile_limit}" > /dev/console 2>/dev/null || true
        return 1
    fi
    echo "[per-run rlimit] PID 1 RLIMIT_NOFILE=${_nofile_soft}/${_nofile_hard}" > /dev/console 2>/dev/null || true
    unset _nofile_limit _nofile_soft _nofile_hard
    unset _limit_word1 _limit_word2 _limit_word3 _limit_soft _limit_hard _limit_unit
}

# --------------------------------------------------------------------------
# 0. Post-restore fixups (no-ops on cold boot)
# --------------------------------------------------------------------------
# System clock jumps across restore -- sync from the VZ-provided hwclock.
hwclock -s 2>/dev/null || true

# Invalidate VirtioFS readdir cache so per-run files the host wrote while
# the guest was paused/snapshotted become visible. Read of the directory
# is enough; content isn't used.
ls /safeyolo >/dev/null 2>&1 || true

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

if [ -f /etc/safeyolo-mise-environment ]; then
    cat /etc/safeyolo-mise-environment >> /etc/environment
fi

echo 'export HOME=/home/agent' >> /etc/environment
echo 'export HOME=/home/agent' >> /etc/profile.d/safeyolo-proxy.sh

# --------------------------------------------------------------------------
# 1b. Guest-side proxy forwarder (localhost:8080 -> UDS or vsock)
#
# Bridges the agent's HTTP_PROXY target (a plain TCP listener the agent
# can reach via loopback) to the host-side SafeYolo proxy. Transport is
# UDS on Linux/gVisor (directory-mounted /safeyolo/proxy/proxy.sock, via
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

# Keep Bash as PID 1 after the kernel check. A physical VZ test reported a low
# limit after the final idle exec. A child can wait without replacing PID 1.
# The wait command also reaps the child when it exits.
COMMAND_SUPERVISOR_PID=
COMMAND_SUPERVISOR_STATE=/home/agent/.safeyolo-command-supervisor.json
COMMAND_SUPERVISOR_STOP=/home/agent/.safeyolo-command-supervisor.stop
COMMAND_SUPERVISOR_SCRIPT=/run/safeyolo/guest-command-supervisor.py
if [ ! -x "$COMMAND_SUPERVISOR_SCRIPT" ]; then
    COMMAND_SUPERVISOR_SCRIPT=/safeyolo/guest-command-supervisor.py
fi

command_supervisor_terminal() {
    [ -f "$COMMAND_SUPERVISOR_STATE" ] &&
        grep -Eq '"state":"(failed|stopped)"' "$COMMAND_SUPERVISOR_STATE"
}

command_supervisor_live() {
    [ -n "$COMMAND_SUPERVISOR_PID" ] || return 1
    kill -0 "$COMMAND_SUPERVISOR_PID" 2>/dev/null || return 1
    ! ps -p "$COMMAND_SUPERVISOR_PID" -o stat= 2>/dev/null | grep -q '^Z'
}

stop_command_supervisor_if_requested() {
    [ -f "$COMMAND_SUPERVISOR_STOP" ] || return 0
    if command_supervisor_live; then
        # The durable stop fence is written by the host before it stops the
        # sandbox. Signal the live guest owner too so a direct recovery-shell
        # stop reaches the command without waiting for the command to exit.
        kill -TERM "$COMMAND_SUPERVISOR_PID" 2>/dev/null || true
    fi
}

start_command_supervisor_if_needed() {
    [ "${SAFEYOLO_COMMAND_SUPERVISED:-}" = "1" ] || return 0
    [ -x "$COMMAND_SUPERVISOR_SCRIPT" ] || return 0
    stop_command_supervisor_if_requested
    [ -f "$COMMAND_SUPERVISOR_STOP" ] && return 0
    command_supervisor_terminal && return 0
    if command_supervisor_live; then
        return 0
    fi
    if [ -n "$COMMAND_SUPERVISOR_PID" ]; then
        wait "$COMMAND_SUPERVISOR_PID" 2>/dev/null || true
        COMMAND_SUPERVISOR_PID=
    fi
    # PID 1 is the durable owner: if this child is killed, the next loop
    # iteration starts a fresh runtime supervisor. The supervisor records its
    # command PID and start token so a replacement fences an orphan before
    # resuming the preserved checkpoint.
    setsid su agent -s /bin/bash -c \
        "exec python3 '$COMMAND_SUPERVISOR_SCRIPT'" >/dev/null 2>&1 < /dev/null &
    COMMAND_SUPERVISOR_PID=$!
    echo "[per-run] started guest command supervisor (pid=$COMMAND_SUPERVISOR_PID)" > /dev/console 2>/dev/null || true
}

keep_pid1_alive() {
    while :; do
        start_command_supervisor_if_needed
        sleep 0.25
    done
}

# All per-run setup is complete. Establish the externally visible PID 1
# contract at the common boundary before the host publishes readiness and
# before detach, host-terminal, or vsock-term can launch. The host waits for
# per-run-started, so an immediate agent-shell probe cannot race this check.
ensure_pid1_nofile
echo "$(date +%s)" > /safeyolo-status/per-run-started
echo "ready" > /safeyolo-status/vm-status
echo "[per-run-started written] pid=$$" > /dev/console 2>/dev/null || true

# Detach mode: skip vsock terminal, keep VM alive for SSH access.
# The host-side safeyolo-vm runs with --no-terminal so it doesn't
# try to connect vsock. sshd is already running in background.
if [ "${SAFEYOLO_DETACH:-}" = "1" ]; then
    echo "Detach mode: VM running, SSH ready" >&2
    keep_pid1_alive
fi

if [ "${SAFEYOLO_HOST_TERMINAL:-}" = "1" ]; then
    # Linux/gVisor: the host CLI launches the agent via `runsc exec`,
    # which bridges the user's terminal into the sandbox directly.
    # Keep the container alive so runsc exec has a target.
    keep_pid1_alive
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
# Unreachable if poweroff succeeded. The fallback keeps PID 1 alive. The host
# force-stops the VM after five seconds.
keep_pid1_alive
