#!/bin/bash
#
# SafeYolo guest-init — STATIC phase.
#
# Runs the setup that is identical across every run of this agent and
# therefore snapshottable: network bring-up, VirtioFS mounts, CA trust,
# sshd, ipv6 disable, VM-IP discovery. Does NOT touch per-run state
# (agent.env, instructions, agent_token, mise install, remount ro,
# agent launch) — those live in guest-init-per-run.
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
# Hostname — set to agent name so `hostname`, the shell prompt, syslog,
# and sshd all identify the guest correctly. The Docker stack did this
# via container-name=hostname inheritance; the VM stack has to do it
# explicitly. Runs pre-snapshot so the hostname lands in the captured
# memory state and restores along with everything else.
# --------------------------------------------------------------------------
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

# --------------------------------------------------------------------------
# 1. Networking (static IP from config share)
# --------------------------------------------------------------------------
ip link set lo up 2>/dev/null || true

# Source network.env unconditionally — GUEST_IP is needed later for the
# /safeyolo/vm-ip readiness signal even on runtimes where `ip link show
# eth0` is unhappy (notably gVisor: its netstack doesn't surface the
# netns's eth0 as a kernel interface, so standard `ip` queries find
# only lo — yet traffic flows fine because netstack forwards transparently).
if [ -f /safeyolo/network.env ]; then
    . /safeyolo/network.env
fi
if ip link show eth0 >/dev/null 2>&1; then
    # On gVisor the sandbox inherits eth0 fully configured from the netns
    # (UP, IP assigned, default route) — bringing it up here would just
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
# 3. Trust SafeYolo CA certificate (idempotent)
#
# Skip the rebuild on every boot — the CA cert is the same across runs.
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
        update-ca-certificates >/dev/null 2>&1 || true
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
    ssh-keygen -A >/dev/null 2>&1 || true
fi

mkdir -p /run/sshd
/usr/sbin/sshd -D >/var/log/sshd.log 2>&1 &
echo "[static] sshd launched pid=$!" > /dev/console 2>/dev/null || true

sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
# 5. Write VM IP so the CLI can discover it
# --------------------------------------------------------------------------
# Prefer GUEST_IP from network.env (host-written, accurate on every runtime);
# fall back to `ip addr` for legacy paths or for cases where the env wasn't
# staged. On gVisor the `ip addr` path returns nothing because eth0 isn't
# visible from inside the sandbox — the env-var path is what makes vm-ip
# reliably appear there.
VM_IP="${GUEST_IP:-$(ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo '')}"
if [ -n "$VM_IP" ]; then
    echo "$VM_IP" > /safeyolo/vm-ip 2>/dev/null || true
fi

# Stage guest-init-per-run into tmpfs so the orchestrator has something
# to exec after a restore. VirtioFS file reads are unreliable post-
# resume in this framework (stat works via cached dentry, but open+read
# may fail — observed as exit 127 when exec'ing a /safeyolo/ path,
# which triggers a kernel panic in init). /run is tmpfs, part of the
# captured memory image, so the staged copy survives the save/restore
# round trip.
mkdir -p /run/safeyolo 2>/dev/null || true
if [ -f /safeyolo/guest-init-per-run ]; then
    cp /safeyolo/guest-init-per-run /run/safeyolo/guest-init-per-run 2>/dev/null || true
    chmod +x /run/safeyolo/guest-init-per-run 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 6. Install the agent binary (pre-snapshot)
#
# Runs here rather than in per-run so the installed binary is captured
# in the rootfs clone and survives restore. Before this moved, every
# restore re-ran mise install (~10s for claude-code), defeating most
# of the snapshot speedup for coding-agent templates.
#
# /etc/environment is written now so that `su agent -l`'s login shell
# picks up HTTP_PROXY / SSL_CERT_FILE via pam_env — mise install hits
# HTTPS endpoints through the host proxy. Per-run will rewrite this
# file with the same content on every boot (idempotent).
# --------------------------------------------------------------------------
if [ -f /safeyolo/proxy.env ]; then
    cp /safeyolo/proxy.env /etc/environment
fi
if [ -f /safeyolo/agent.env ]; then
    cat /safeyolo/agent.env >> /etc/environment
fi
echo 'export HOME=/home/agent' >> /etc/environment

(
    # Subshell keeps the sourced env scope-limited; the static script's
    # parent env stays minimal.
    set -a
    [ -f /safeyolo/proxy.env ] && . /safeyolo/proxy.env
    [ -f /safeyolo/agent.env ] && . /safeyolo/agent.env
    set +a

    # Start the proxy forwarder early so the install can reach the host
    # proxy. The forwarder is also started in per-run; duplicate launch
    # is harmless (the second bind fails and the process exits).
    if [ -x /safeyolo/guest-proxy-forwarder ]; then
        setsid nohup /safeyolo/guest-proxy-forwarder >/dev/console 2>&1 </dev/null &
        echo "[static] started guest-proxy-forwarder (pid=$!)" > /dev/console 2>/dev/null || true
    fi

    # Wait for egress connectivity before attempting install. The proxy
    # chain (forwarder → vsock/UDS → bridge → mitmproxy) needs a moment
    # to come up. Probe with a lightweight HTTP request through the
    # proxy; fail fast with a clear message instead of letting mise/npm
    # hang for 120s on a dead connection.
    if [ -n "${HTTP_PROXY:-}" ] && [ -n "${SAFEYOLO_MISE_PACKAGE:-}" ]; then
        _proxy_ok=0
        for _try in $(seq 1 20); do
            if curl -sf -o /dev/null --max-time 2 -x "$HTTP_PROXY" http://registry.npmjs.org/ 2>/dev/null; then
                _proxy_ok=1
                break
            fi
            sleep 0.5
        done
        if [ "$_proxy_ok" -eq 0 ]; then
            echo "[static] WARNING: no egress connectivity after 10s — skipping install" > /dev/console 2>/dev/null || true
            echo "install-failed" > /safeyolo/vm-status 2>/dev/null || true
            exit 0
        fi
        echo "[static] egress connectivity confirmed (attempt $_try)" > /dev/console 2>/dev/null || true
    fi

    if [ -n "${SAFEYOLO_MISE_PACKAGE:-}" ] && [ -n "${SAFEYOLO_AGENT_BINARY:-}" ]; then
        # `-lc` so mise's shell activation runs and puts its shims on
        # PATH; without `-l`, `command -v` can't find a mise-managed
        # binary even when it's correctly installed.
        if ! su agent -lc "command -v $SAFEYOLO_AGENT_BINARY" >/dev/null 2>&1; then
            echo "installing" > /safeyolo/vm-status 2>/dev/null || true
            timeout 120 su agent -lc "mise use -g ${SAFEYOLO_MISE_PACKAGE}@latest" >/dev/null 2>&1 || true
        fi
        # Ground vm-status in reality. `mise use -g` can exit nonzero
        # (notably: the outer `timeout` fires *after* the package is
        # already installed on disk) yet leave a working binary behind —
        # so trusting the install command's exit code leaves a stale
        # "install-failed" even on healthy boots. Decide on command -v.
        # Per-run has a safety-net retry, so "install-failed" here is
        # only terminal if per-run's retry also fails.
        if su agent -lc "command -v $SAFEYOLO_AGENT_BINARY" >/dev/null 2>&1; then
            echo "" > /safeyolo/vm-status 2>/dev/null || true
        else
            echo "install-failed" > /safeyolo/vm-status 2>/dev/null || true
        fi
    fi
)

echo "[static end] pid=$$" > /dev/console 2>/dev/null || true
