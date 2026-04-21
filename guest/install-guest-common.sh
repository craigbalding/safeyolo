#!/bin/bash
#
# Sourceable shell library for custom rootfs builders (--rootfs-script).
#
# Takes an unpacked rootfs tree and installs the bits SafeYolo's boot
# orchestrator assumes are present. This is what makes a bare distro tree
# into a SafeYolo-compatible rootfs.
#
# Usage (inside a rootfs-script, after you've unpacked your distro tree):
#
#     : "${SAFEYOLO_GUEST_SRC_DIR:?must be set by safeyolo}"
#     source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
#     install_safeyolo_guest_common /path/to/unpacked/rootfs
#
# What it installs:
#   * agent user (uid 1000, shell /bin/bash, home /home/agent)
#   * /usr/local/bin/safeyolo-guest-init stub (exec'd as PID 1)
#   * sshd: pubkey auth only, password off, host keys generated
#   * mise profile glue at /etc/profile.d/mise.sh (only if mise present)
#   * package-manager intercepts at /usr/local/bin/{apt,apt-get,yum,dnf,apk}
#     pointing users at mise (agents must not apt-install at runtime)
#   * hostname = safeyolo
#
# Idempotent -- safe to re-run on the same rootfs.

install_safeyolo_guest_common() {
    local rootfs="$1"

    : "${SAFEYOLO_GUEST_SRC_DIR:?SAFEYOLO_GUEST_SRC_DIR not set}"
    [ -n "$rootfs" ] || { echo "install_safeyolo_guest_common: rootfs arg required" >&2; return 1; }
    [ -d "$rootfs" ] || { echo "install_safeyolo_guest_common: rootfs not a dir: $rootfs" >&2; return 1; }
    [ -r "$SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-guest-init" ] || {
        echo "install_safeyolo_guest_common: missing $SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-guest-init" >&2
        return 1
    }

    echo "=== Installing SafeYolo guest bits into $rootfs ==="

    # Guest-init stub, exec'd as PID 1 by our initramfs on macOS and as
    # the container entrypoint on Linux.
    install -m 0755 \
        "$SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-guest-init" \
        "$rootfs/usr/local/bin/safeyolo-guest-init"

    # agent user. Not fatal if useradd missing (e.g., minimal Alpine --
    # scripts should install `shadow` first).
    if [ ! -x "$rootfs/usr/sbin/useradd" ] && [ ! -x "$rootfs/usr/bin/useradd" ]; then
        echo "install_safeyolo_guest_common: no useradd in rootfs -- install the shadow/shadow-utils package first" >&2
        return 1
    fi
    chroot "$rootfs" useradd -m -s /bin/bash -u 1000 agent 2>/dev/null || true
    # Unlock the agent account's password field so OpenSSH accepts pubkey
    # auth. useradd creates accounts with pw="!" (locked). OpenSSH on
    # Alpine (9.7+) refuses any auth for locked accounts, including
    # pubkey. Setting pw="*" means "no password set" without the locked
    # flag; pubkey auth then works. PasswordAuthentication is off in our
    # sshd_config so this cannot be abused for passwordless login.
    chroot "$rootfs" usermod -p '*' agent 2>/dev/null || true

    # sshd config: pubkey only, no passwords. Skip silently if no sshd
    # package is installed -- some minimal rootfs don't ship one and the
    # VM only needs sshd when `safeyolo agent shell` is used.
    if [ -f "$rootfs/etc/ssh/sshd_config" ]; then
        sed -i "s/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/" \
            "$rootfs/etc/ssh/sshd_config"
        sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" \
            "$rootfs/etc/ssh/sshd_config"
        chroot "$rootfs" ssh-keygen -A >/dev/null 2>&1 || true
    fi

    # mise profile glue -- sources only if mise is present in the rootfs.
    # Custom rootfs authors who don't want mise can skip -- guest-init
    # tolerates its absence. See guest/rootfs-customize-hook.sh for the
    # canonical version baked into the default base.
    if [ -x "$rootfs/usr/local/bin/mise" ] || [ -x "$rootfs/usr/bin/mise" ]; then
        install -d -m 0755 "$rootfs/etc/profile.d"
        cat > "$rootfs/etc/profile.d/mise.sh" <<'MISE_PROFILE'
export MISE_DATA_DIR="${HOME:-/home/agent}/.mise"
export MISE_CONFIG_DIR="${HOME:-/home/agent}/.mise"
export MISE_CACHE_DIR="${HOME:-/home/agent}/.mise/cache"
export PATH="${HOME:-/home/agent}/.mise/shims:$PATH"
eval "$(mise activate bash)" 2>/dev/null || true
MISE_PROFILE
        chmod 0755 "$rootfs/etc/profile.d/mise.sh"
        cp "$rootfs/etc/profile.d/mise.sh" "$rootfs/etc/mise-activate.sh"
        grep -q '^BASH_ENV=' "$rootfs/etc/environment" 2>/dev/null \
            || echo "BASH_ENV=/etc/mise-activate.sh" >> "$rootfs/etc/environment"
    fi

    # Package-manager intercepts. Agents inside the VM must install tools
    # via mise, not the distro package manager -- apt/yum/apk egress doesn't
    # go through the SafeYolo proxy. Intercepts placed in /usr/local/bin so
    # they shadow the real binaries on $PATH.
    install -d -m 0755 "$rootfs/usr/local/bin"
    for cmd in apt apt-get yum dnf apk; do
        cat > "$rootfs/usr/local/bin/$cmd" <<'INTERCEPT'
#!/bin/sh
echo "Error: Package manager not available in SafeYolo sandbox."
echo ""
echo "Use mise to install languages and tools:"
echo "  mise install go@latest"
echo "  mise install python@3.12"
echo "  mise install rust@latest"
exit 1
INTERCEPT
        chmod 0755 "$rootfs/usr/local/bin/$cmd"
    done

    # Hostname. DNS is overridden by DHCP / guest-init at boot.
    echo "safeyolo" > "$rootfs/etc/hostname"

    echo "=== SafeYolo guest bits installed ==="
}
