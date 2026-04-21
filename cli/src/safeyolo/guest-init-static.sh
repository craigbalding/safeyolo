#!/bin/bash
#
# SafeYolo guest-init -- STATIC phase.
#
# Runs the setup that is identical across every run of this agent and
# therefore snapshottable: network bring-up, VirtioFS mounts, CA trust,
# sshd, ipv6 disable, VM-IP discovery. Does NOT touch per-run state
# (agent.env, instructions, agent_token, mise install, remount ro,
# agent launch) -- those live in guest-init-per-run.
#
# Invoked by /safeyolo/guest-init (orchestrator) before the per-run-go
# gate. On restore, this script has already executed into snapshotted
# memory and is never re-entered; the orchestrator wakes up in the
# gate-wait and proceeds to per-run.
#
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[static start] pid=$$" > /dev/console 2>/dev/null || true

# --------------------------------------------------------------------------
# Hostname -- set to agent name so `hostname`, the shell prompt, syslog,
# and sshd all identify the guest correctly. The Docker stack did this
# via container-name=hostname inheritance; the VM stack has to do it
# explicitly. Runs pre-snapshot so the hostname lands in the captured
# memory state and restores along with everything else.
# --------------------------------------------------------------------------
_agent_name=""
if [ -f /safeyolo/agent-name ]; then
    _agent_name=$(cat /safeyolo/agent-name 2>/dev/null || echo "")
    if [ -n "$_agent_name" ]; then
        hostname "$_agent_name" 2>/dev/null || true
        echo "$_agent_name" > /etc/hostname 2>/dev/null || true
    fi
fi

# --------------------------------------------------------------------------
# 0. Remove attack-surface device nodes
#
# gVisor's default /dev includes /dev/net/tun and /dev/fuse, both of
# which a captured agent would reach for: /dev/net/tun lets it create
# a userspace TUN interface and forge L3 packets (bypassing our
# firewall rules at the veth layer); /dev/fuse lets it mount an
# attacker-controlled filesystem inside the container. Neither is
# needed for any legitimate agent workflow, so delete the nodes
# before dropping to agent-user context. We run as root at this
# point (pre-per-run) with CAP_MKNOD + CAP_DAC_OVERRIDE, which is
# sufficient to unlink.
rm -f /dev/net/tun 2>/dev/null || true
rmdir /dev/net 2>/dev/null || true
rm -f /dev/fuse 2>/dev/null || true

# Standard /dev symlinks -- normally created by udev or systemd-tmpfiles
# at boot, but this VM uses a minimal init with neither. Without these,
# programs that write to /dev/stderr (curl, bash redirections, etc.) fail.
# Standard /dev symlinks -- normally created by udev or systemd-tmpfiles
# at boot, but this VM uses a minimal init with neither. gVisor already
# provides these; only create if missing.
[ -e /dev/fd ]     || ln -s /proc/self/fd /dev/fd
[ -e /dev/stdin ]  || ln -s /proc/self/fd/0 /dev/stdin
[ -e /dev/stdout ] || ln -s /proc/self/fd/1 /dev/stdout
[ -e /dev/stderr ] || ln -s /proc/self/fd/2 /dev/stderr

# --------------------------------------------------------------------------
# 1. Networking (static IP from config share)
# --------------------------------------------------------------------------
ip link set lo up

# Source network.env unconditionally -- GUEST_IP is needed later for the
# /safeyolo/vm-ip readiness signal even on runtimes where `ip link show
# eth0` is unhappy (notably gVisor: its netstack doesn't surface the
# netns's eth0 as a kernel interface, so standard `ip` queries find
# only lo -- yet traffic flows fine because netstack forwards transparently).
if [ -f /safeyolo/network.env ]; then
    . /safeyolo/network.env
fi

# Add the agent's unique IP to loopback. This is the same IP that
# appears in mitmproxy flows, logs, and the agent map -- giving the
# operator a consistent per-agent identity inside and outside the
# sandbox.
if [ -n "${AGENT_IP:-}" ]; then
    ip addr add "${AGENT_IP}/32" dev lo
fi

# /etc/hosts -- make the agent hostname resolve so sudo, hostname -f, and
# any getaddrinfo() caller don't fail with "Temporary failure in name
# resolution". Append only if no existing entry maps the name; leaves
# any distro-default or user-added lines intact.
if [ -n "$_agent_name" ] \
   && ! grep -qE "^[[:space:]]*[^#]*[[:space:]]${_agent_name}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    printf '%s %s\n' "${AGENT_IP:-127.0.1.1}" "$_agent_name" >> /etc/hosts
fi
if ip link show eth0 >/dev/null 2>&1; then
    # On gVisor the sandbox inherits eth0 fully configured from the netns
    # (UP, IP assigned, default route) -- bringing it up here would just
    # EPERM, and set -e would kill the script. Detect that and skip.
    # On the macOS microVM path the guest kernel sees a bare interface
    # and we have to configure it ourselves; failure here IS a bug and
    # should propagate (no `|| true` masking).
    if ! ip -4 addr show eth0 | grep -qE "inet ${GUEST_IP}/"; then
        ip link set eth0 up
        ip addr add ${GUEST_IP}/24 dev eth0
        ip route add default via ${GATEWAY_IP}
    fi
fi

# --------------------------------------------------------------------------
# 2. Mount VirtioFS shares (workspace, host config dirs/files)
#
# On macOS (VZ microVM), VirtioFS is the mount mechanism -- failure is
# fatal. On Linux (gVisor), the OCI spec handles mounts via bind -- the
# virtiofs mount calls legitimately fail and are skipped. Detect by
# checking if /workspace is already mounted (OCI bind-mounts appear
# before init runs).
# --------------------------------------------------------------------------
_needs_virtiofs_mount() { ! mountpoint -q /workspace 2>/dev/null; }

mkdir -p /workspace
if _needs_virtiofs_mount; then
    mount -t virtiofs workspace /workspace
else
    mount -t virtiofs workspace /workspace 2>/dev/null || true
fi

# Status share -- writable channel for guest→host signals (vm-status,
# per-run-started, etc.). Separate from /safeyolo so the config share
# can be read-only.
mkdir -p /safeyolo-status
if _needs_virtiofs_mount; then
    mount -t virtiofs status /safeyolo-status
else
    mount -t virtiofs status /safeyolo-status 2>/dev/null || true
fi

# Persistent /home/agent -- must mount before the host-config-mount
# loop, SSH key drop, install block, and host-files copy so writes
# from each land in the host-side mount (~/.safeyolo/agents/<name>/
# home/) rather than the ephemeral rootfs. MISE_DATA_DIR is
# $HOME/.mise (see /etc/profile.d/mise.sh + vsock-term), so mise
# installs persist here too. First boot: /etc/skel seeds sensible
# dotfiles for the agent's login shell.
mkdir -p /home/agent
if _needs_virtiofs_mount; then
    mount -t virtiofs home /home/agent
else
    mount -t virtiofs home /home/agent 2>/dev/null || true
fi
if [ -z "$(ls -A /home/agent 2>/dev/null)" ] && [ -d /etc/skel ]; then
    # `cp -r` (not `-a`) -- VirtioFS on VZ rejects utimes, which makes
    # `cp -a`'s timestamp-preserve step fail, and `set -e` takes PID 1
    # down with it (kernel panic "Attempted to kill init"). Timestamps
    # on skel dotfiles aren't load-bearing; default modes under umask
    # are fine for .bashrc / .profile / .bash_logout.
    cp -r /etc/skel/. /home/agent/
fi

# Host config directory mounts (e.g., ~/.claude → /home/agent/.claude)
if [ -f /safeyolo/host-mounts ]; then
    while IFS=: read -r tag guest_path; do
        [ -z "$tag" ] && continue
        mkdir -p "$guest_path"
        if _needs_virtiofs_mount; then
            mount -t virtiofs "$tag" "$guest_path"
        else
            mount -t virtiofs "$tag" "$guest_path" 2>/dev/null || true
        fi
        # No chown: on gVisor the userns map (container uid 1000 →
        # host operator uid) already presents host-owned files as
        # agent-owned; on macOS VZ VirtioFS maps ownership at the FS
        # layer (verified: /home/agent/.safeyolo-hooks reads+writes
        # as agent without any chown). chown on VirtioFS fails anyway.
    done < /safeyolo/host-mounts
fi

# --------------------------------------------------------------------------
# 3. Trust SafeYolo CA certificate (idempotent)
#
# Skip the rebuild on every boot -- the CA cert is the same across runs.
# Trigger update-ca-certificates only if either:
#   - the source cert differs from what's installed
#   - the bundle file is missing (recovery from a corrupt/missing state)
# Drop --fresh: incremental update is enough since we're adding, not pruning.
# --------------------------------------------------------------------------
SY_CERT_SRC=/safeyolo/mitmproxy-ca-cert.pem
SY_CERT_DST=/usr/local/share/ca-certificates/safeyolo.crt
SY_BUNDLE=/etc/ssl/certs/ca-certificates.crt
if [ -f "$SY_CERT_SRC" ]; then
    if [ ! -f "$SY_CERT_DST" ] || ! cmp -s "$SY_CERT_SRC" "$SY_CERT_DST" || [ ! -f "$SY_BUNDLE" ]; then
        install -m 644 "$SY_CERT_SRC" "$SY_CERT_DST"
        if ! update-ca-certificates >/dev/null 2>&1; then
            echo "[static] WARNING: update-ca-certificates failed" > /dev/console 2>/dev/null || true
        fi
    fi
fi

# --------------------------------------------------------------------------
# 4. SSH server and agent authorized keys
# --------------------------------------------------------------------------
if [ -f /safeyolo/authorized_keys ]; then
    mkdir -p /home/agent/.ssh
    cp /safeyolo/authorized_keys /home/agent/.ssh/authorized_keys
    chown -R agent:agent /home/agent/.ssh
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys
fi

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A >/dev/null 2>&1
fi
# SSH host keys must be root-owned and 600. Keys from the rootfs
# tarball already have correct ownership, but ssh-keygen -A above
# creates new ones as the current user -- fix unconditionally.
# The glob may not match on runtimes where keygen failed (gVisor
# without /dev/random early in boot) -- check before chown/chmod.
for keyfile in /etc/ssh/ssh_host_*_key; do
    [ -f "$keyfile" ] || continue
    chown root:root "$keyfile"
    chmod 600 "$keyfile"
done

mkdir -p /run/sshd
# -e routes syslog messages to stderr, which we capture in sshd.log.
# Without it, auth failures go to syslog -- and custom rootfs images
# (Alpine, etc.) often have no syslog daemon, so diagnosing
# "Permission denied (publickey)" required rebuilding to add -e.
# Silent is worse than verbose here; the log file is per-agent and small.
/usr/sbin/sshd -D -e >/var/log/sshd.log 2>&1 &
echo "[static] sshd launched pid=$!" > /dev/console 2>/dev/null || true

sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
# 5. Write VM IP so the CLI can discover it
# --------------------------------------------------------------------------
# Prefer GUEST_IP from network.env (host-written, accurate on every runtime);
# fall back to `ip addr` for legacy paths or for cases where the env wasn't
# staged. On gVisor the `ip addr` path returns nothing because eth0 isn't
# visible from inside the sandbox -- the env-var path is what makes vm-ip
# reliably appear there.
VM_IP="${GUEST_IP:-$(ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo '')}"
if [ -n "$VM_IP" ]; then
    echo "$VM_IP" > /safeyolo-status/vm-ip
fi

# Stage guest-init-per-run into tmpfs so the orchestrator has something
# to exec after a restore. VirtioFS file reads are unreliable post-
# resume in this framework (stat works via cached dentry, but open+read
# may fail -- observed as exit 127 when exec'ing a /safeyolo/ path,
# which triggers a kernel panic in init). /run is tmpfs, part of the
# captured memory image, so the staged copy survives the save/restore
# round trip.
mkdir -p /run/safeyolo
if [ -f /safeyolo/guest-init-per-run ]; then
    cp /safeyolo/guest-init-per-run /run/safeyolo/guest-init-per-run
    chmod +x /run/safeyolo/guest-init-per-run
fi

# --------------------------------------------------------------------------
# 6. Seed /etc/environment from proxy.env + agent.env.
#
# Subsequent shells (login or otherwise) pick up HTTP_PROXY / SSL_CERT_FILE
# / etc. via pam_env. Under the host-script model there's no pre-snapshot
# agent install step here -- the host script populates /home/agent/
# .safeyolo-command, which takes care of first-run install work.
# --------------------------------------------------------------------------
if [ -f /safeyolo/proxy.env ]; then
    cp /safeyolo/proxy.env /etc/environment
fi
if [ -f /safeyolo/agent.env ]; then
    cat /safeyolo/agent.env >> /etc/environment
fi
echo 'export HOME=/home/agent' >> /etc/environment

# Start the proxy forwarder. Per-run also starts it; duplicate launch
# is harmless (the second bind fails and the process exits).
if [ -x /safeyolo/guest-proxy-forwarder ]; then
    setsid nohup /safeyolo/guest-proxy-forwarder >/dev/console 2>&1 </dev/null &
    echo "[static] started guest-proxy-forwarder (pid=$!)" > /dev/console 2>/dev/null || true
fi

echo "[static end] pid=$$" > /dev/console 2>/dev/null || true
