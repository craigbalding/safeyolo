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
#   * install_safeyolo_mise helper for custom rootfs scripts that want the
#     same pinned mise binary as the default rootfs
#   * agent user (uid 1000, shell /bin/bash, home /home/agent)
#   * /usr/local/bin/safeyolo-guest-init stub (exec'd as PID 1)
#   * sshd: pubkey auth only, password off, host keys generated
#   * baseline PATH glue at /etc/profile.d/00-path.sh + /etc/environment
#   * mise profile glue at /etc/profile.d/mise.sh (only if mise present)
#   * BusyBox applet shims (`hexdump`, `nc`) when busybox is present
#   * hostname = safeyolo
#
# What it deliberately does NOT install:
#   * Package-manager policy (apt sources, proxy config).
#     Custom rootfs authors own that; the default Debian base's
#     customize-hook writes /etc/apt/apt.conf.d/99safeyolo-proxy so
#     `apt-get install` (run via `safeyolo agent shell --root`)
#     routes through SafeYolo's proxy, but this library doesn't force
#     the policy.
#
# Idempotent -- safe to re-run on the same rootfs.

install_safeyolo_mise() {
    local rootfs="$1"
    local target_arch="${2:-${SAFEYOLO_TARGET_ARCH:-}}"
    local mise_version="${MISE_VERSION:-2026.4.19}"
    local mise_sha_arm64="${MISE_SHA256_ARM64:-882d10aa67fcb4fd8008c1e31ac3c6d0dc80dac2c4cb3c0d794ca9e0e5aece3d}"
    local mise_sha_amd64="${MISE_SHA256_AMD64:-17bf037c94dd5e790a9b56ab0a00f64a9ed910df1e0b67ad041d6336bafc44cb}"
    local mise_arch mise_sha

    [ -n "$rootfs" ] || { echo "install_safeyolo_mise: rootfs arg required" >&2; return 1; }
    [ -d "$rootfs" ] || { echo "install_safeyolo_mise: rootfs not a dir: $rootfs" >&2; return 1; }

    case "$target_arch" in
        amd64) mise_arch=x64; mise_sha="$mise_sha_amd64" ;;
        arm64) mise_arch=arm64; mise_sha="$mise_sha_arm64" ;;
        *) echo "install_safeyolo_mise: unsupported arch: $target_arch" >&2; return 1 ;;
    esac

    if [ -x "$rootfs/usr/local/bin/mise" ] || [ -x "$rootfs/usr/bin/mise" ]; then
        echo "=== mise already installed in $rootfs ==="
        return 0
    fi

    command -v curl >/dev/null || { echo "install_safeyolo_mise: missing curl" >&2; return 1; }
    command -v sha256sum >/dev/null || { echo "install_safeyolo_mise: missing sha256sum" >&2; return 1; }
    command -v tar >/dev/null || { echo "install_safeyolo_mise: missing tar" >&2; return 1; }

    local url
    url="https://github.com/jdx/mise/releases/download"
    url="${url}/v${mise_version}/mise-v${mise_version}-linux-${mise_arch}.tar.gz"
    local tmp_dir="$rootfs/tmp/safeyolo-mise"
    local tarball="$tmp_dir/mise.tar.gz"

    echo "=== Installing mise ${mise_version} ==="
    rm -rf "$tmp_dir"
    mkdir -p "$tmp_dir" "$rootfs/usr/local/bin"
    curl -fsSL "$url" -o "$tarball"
    echo "${mise_sha}  $tarball" | sha256sum -c -
    tar -xzf "$tarball" -C "$tmp_dir"
    cp "$tmp_dir/mise/bin/mise" "$rootfs/usr/local/bin/mise"
    chmod 0755 "$rootfs/usr/local/bin/mise"
    rm -rf "$tmp_dir"
}

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
        rm -f "$rootfs"/etc/ssh/ssh_host_*_key "$rootfs"/etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
    fi

    # Keep sbin directories visible in both login and non-login shells so
    # service binaries like sshd don't disappear from PATH.
    install -d -m 0755 "$rootfs/etc/profile.d"
    cat > "$rootfs/etc/profile.d/00-path.sh" <<'PATH_PROFILE'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH_PROFILE
    chmod 0755 "$rootfs/etc/profile.d/00-path.sh"
    if [ -f "$rootfs/etc/environment" ]; then
        if grep -q '^PATH=' "$rootfs/etc/environment"; then
            sed -i 's|^PATH=.*|PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|' \
                "$rootfs/etc/environment"
        else
            echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> \
                "$rootfs/etc/environment"
        fi
    else
        echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" > \
            "$rootfs/etc/environment"
    fi

    # mise profile glue -- sources only if mise is present in the rootfs.
    # Custom rootfs authors who don't want mise can skip -- guest-init
    # tolerates its absence. See guest/rootfs-customize-hook.sh for the
    # canonical version baked into the default base.
    if [ -x "$rootfs/usr/local/bin/mise" ] || [ -x "$rootfs/usr/bin/mise" ]; then
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

    # BusyBox applet shims (`hexdump`, `nc`) -- convenience only, installed
    # when the rootfs ships busybox. apt/yum/apk remain usable at runtime
    # (per-agent cache binds + in-VM socat relay routes downloads through
    # SafeYolo's proxy); custom rootfs authors wanting different policy
    # can still override.
    install -d -m 0755 "$rootfs/usr/local/bin"
    for busybox_path in /bin/busybox /usr/bin/busybox; do
        if [ -x "$rootfs$busybox_path" ]; then
            ln -sf "$busybox_path" "$rootfs/usr/local/bin/hexdump"
            ln -sf "$busybox_path" "$rootfs/usr/local/bin/nc"
            break
        fi
    done

    # Hostname. DNS is overridden by DHCP / guest-init at boot.
    echo "safeyolo" > "$rootfs/etc/hostname"

    echo "=== SafeYolo guest bits installed ==="
}
