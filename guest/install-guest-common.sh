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
#   * host bind-mount targets required by the Linux gVisor runtime
#   * sshd: pubkey auth only, password off, host keys generated
#   * baseline PATH glue at /etc/profile.d/00-path.sh + /etc/environment
#   * mise profile glue at /etc/profile.d/mise.sh (only if mise present)
#   * BusyBox applet shims (`hexdump`, `nc`) when busybox is present
#   * `/usr/local/bin/fd` compatibility link for Debian's `fdfind`, when needed
#   * `/usr/local/bin/sudo` compatibility shim + passwordless guest-root policy
#     (including a validated `sudo` group and user-scoped rule)
#   * hostname = safeyolo
#
# What it deliberately does NOT install:
#   * Package-manager policy (apt sources, proxy config).
#     Custom rootfs authors own that; the default Debian base's
#     customize-hook writes /etc/apt/apt.conf.d/99safeyolo-proxy so
#     `sudo apt-get install` routes through SafeYolo's proxy, but this library
#     doesn't force distro-specific proxy policy.
#
# Idempotent -- safe to re-run on the same rootfs.

install_safeyolo_mise() {
    local rootfs="$1"
    local target_arch="${2:-${SAFEYOLO_TARGET_ARCH:-}}"
    local mise_version="${MISE_VERSION:-2026.8.8}"
    local mise_sha_arm64="${MISE_SHA256_ARM64:-6e6e96d319fe274996db5aed691f5398552865e641dc4b6fb6b01d73f4853a17}"
    local mise_sha_amd64="${MISE_SHA256_AMD64:-58edfbdba6d4255b6536a61daeaf3b21f7a059430c789e948c8494ba32d59e1f}"
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

install_safeyolo_mise_integration() {
    local rootfs="$1"

    [ -n "$rootfs" ] || {
        echo "install_safeyolo_mise_integration: rootfs arg required" >&2
        return 1
    }
    [ -d "$rootfs" ] || {
        echo "install_safeyolo_mise_integration: rootfs not a dir: $rootfs" >&2
        return 1
    }

    # Custom rootfs authors may intentionally omit mise. Keep the rest of the
    # shared guest setup usable in that case.
    if [ ! -x "$rootfs/usr/local/bin/mise" ] && [ ! -x "$rootfs/usr/bin/mise" ]; then
        return 0
    fi

    install -d -m 0755 "$rootfs/etc/profile.d" "$rootfs/usr/local/bin"
    cat > "$rootfs/etc/profile.d/mise.sh" <<'MISE_PROFILE'
export MISE_DATA_DIR="${HOME:-/home/agent}/.mise"
export MISE_CONFIG_DIR="${HOME:-/home/agent}/.mise"
export MISE_CACHE_DIR="${HOME:-/home/agent}/.mise/cache"
# SafeYolo's pinned mise uses these early-init settings to keep ordinary
# commands on the persistent global toolset. Repository mise.toml and
# .tool-versions files are available only through the mise-project opt-in.
export MISE_OVERRIDE_CONFIG_FILENAMES="/etc/safeyolo/mise-project-config-disabled.toml"
export MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES="none"
export PATH="${HOME:-/home/agent}/.mise/shims:$PATH"
MISE_PROFILE
    chmod 0755 "$rootfs/etc/profile.d/mise.sh"
    cp "$rootfs/etc/profile.d/mise.sh" "$rootfs/etc/mise-activate.sh"

    # guest-init rebuilds /etc/environment from per-run proxy and agent data.
    # Keep the rootfs-owned mise baseline separate so both cold boot and
    # snapshot restore can append it again after that replacement.
    cat > "$rootfs/etc/safeyolo-mise-environment" <<'MISE_ENVIRONMENT'
export MISE_DATA_DIR=/home/agent/.mise
export MISE_CONFIG_DIR=/home/agent/.mise
export MISE_CACHE_DIR=/home/agent/.mise/cache
export MISE_OVERRIDE_CONFIG_FILENAMES=/etc/safeyolo/mise-project-config-disabled.toml
export MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none
export PATH=/home/agent/.mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export BASH_ENV=/etc/mise-activate.sh
MISE_ENVIRONMENT
    chmod 0644 "$rootfs/etc/safeyolo-mise-environment"

    # Deliberate project mise use is command-scoped. Unsetting the discovery
    # guards in a child process cannot make later ordinary commands ambiently
    # trust repository configuration.
    cat > "$rootfs/usr/local/bin/mise-project" <<'MISE_PROJECT'
#!/bin/sh
unset MISE_OVERRIDE_CONFIG_FILENAMES
unset MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES
exec mise "$@"
MISE_PROJECT
    chmod 0755 "$rootfs/usr/local/bin/mise-project"

    [ -f "$rootfs/etc/environment" ] || : > "$rootfs/etc/environment"
    local key
    for key in MISE_DATA_DIR MISE_CONFIG_DIR MISE_CACHE_DIR \
        MISE_OVERRIDE_CONFIG_FILENAMES MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES \
        PATH BASH_ENV
    do
        sed -i "/^\(export \)\?${key}=/d" "$rootfs/etc/environment"
    done
    cat "$rootfs/etc/safeyolo-mise-environment" >> "$rootfs/etc/environment"
}

install_safeyolo_runtime_mount_targets() {
    local rootfs="$1"

    [ -n "$rootfs" ] || {
        echo "install_safeyolo_runtime_mount_targets: rootfs arg required" >&2
        return 1
    }
    [ -d "$rootfs" ] || {
        echo "install_safeyolo_runtime_mount_targets: rootfs not a dir: $rootfs" >&2
        return 1
    }

    # Linux uid-remaps the completed tree (container root becomes host uid
    # 100000), so its unprivileged launcher cannot add a missing bind target.
    # macOS also benefits: every mount lands on a known object in the ext4
    # image.  Keep this function shared by the default and custom build paths.
    install -d -m 0755 \
        "$rootfs/workspace" \
        "$rootfs/safeyolo" \
        "$rootfs/safeyolo-status" \
        "$rootfs/home/agent" \
        "$rootfs/usr/local/share/ca-certificates"
    install -m 0644 /dev/null \
        "$rootfs/usr/local/share/ca-certificates/safeyolo.crt"
}


install_safeyolo_fd_compat() {
    local rootfs="$1"
    local path dir fdfind_path fdfind_target

    [ -n "$rootfs" ] || {
        echo "install_safeyolo_fd_compat: rootfs arg required" >&2
        return 1
    }
    [ -d "$rootfs" ] || {
        echo "install_safeyolo_fd_compat: rootfs not a dir: $rootfs" >&2
        return 1
    }

    # Check every standard PATH directory before creating the compatibility
    # link. This preserves a distro or package-provided binary or symlink,
    # including a link whose target is supplied later in the build.
    for dir in usr/local/sbin usr/local/bin usr/sbin usr/bin sbin bin; do
        path="$rootfs/$dir/fd"
        if [ -e "$path" ] || [ -L "$path" ]; then
            return 0
        fi
    done

    # Debian's fd-find package installs fdfind rather than fd. Other distro
    # trees may already provide fd, or may not ship either command.
    for dir in usr/local/sbin usr/local/bin usr/sbin usr/bin sbin bin; do
        fdfind_path="$rootfs/$dir/fdfind"
        if [ -x "$fdfind_path" ]; then
            fdfind_target="/$dir/fdfind"
            install -d -m 0755 "$rootfs/usr/local/bin"
            ln -s "$fdfind_target" "$rootfs/usr/local/bin/fd"
            return 0
        fi
    done
    return 0
}


install_safeyolo_privilege_helper() {
    local rootfs="$1"
    local helper="$SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-sudo"
    local policy="$rootfs/etc/sudoers.d/safeyolo-agent"
    local policy_tmp="${policy}.tmp.$$"
    local visudo

    [ -n "$rootfs" ] || {
        echo "install_safeyolo_privilege_helper: rootfs arg required" >&2
        return 1
    }
    [ -d "$rootfs" ] || {
        echo "install_safeyolo_privilege_helper: rootfs not a dir: $rootfs" >&2
        return 1
    }
    [ -r "$helper" ] || {
        echo "install_safeyolo_privilege_helper: missing $helper" >&2
        return 1
    }

    # Do not shadow a missing real sudo with a helper that can never delegate.
    # Bundled rootfs builders install sudo; third-party minimal builders may
    # intentionally omit package management and should remain usable.
    if [ ! -x "$rootfs/usr/bin/sudo" ]; then
        echo "=== sudo absent; skipping SafeYolo guest-root helper ==="
        return 0
    fi

    # Keep the distro-neutral group contract explicit. Debian/Ubuntu call
    # this group `sudo`; Alpine commonly uses `wheel`, but a direct
    # user-scoped rule is still required because adding a group does not
    # update the supplementary groups of an already-running shell. Creating
    # the same named group on Alpine keeps fresh shells and diagnostics
    # consistent across the supported rootfs builders.
    if ! grep -q '^sudo:' "$rootfs/etc/group" 2>/dev/null; then
        if ! chroot "$rootfs" groupadd -f sudo 2>/dev/null; then
            if ! chroot "$rootfs" addgroup sudo 2>/dev/null; then
                echo "install_safeyolo_privilege_helper: rootfs cannot create the sudo group" >&2
                return 1
            fi
        fi
    fi
    if ! chroot "$rootfs" usermod -a -G sudo agent; then
        echo "install_safeyolo_privilege_helper: could not add agent to the sudo group" >&2
        return 1
    fi
    if ! chroot "$rootfs" id -nG agent 2>/dev/null | grep -qw sudo; then
        echo "install_safeyolo_privilege_helper: agent is not a member of the sudo group" >&2
        return 1
    fi

    # sudo is a bundled-rootfs prerequisite, so visudo is available with it.
    # Refuse a partially provisioned image instead of shipping a policy that
    # only fails later from an agent's pre-existing shell.
    if [ -x "$rootfs/usr/sbin/visudo" ]; then
        visudo=/usr/sbin/visudo
    elif [ -x "$rootfs/usr/bin/visudo" ]; then
        visudo=/usr/bin/visudo
    else
        echo "install_safeyolo_privilege_helper: sudo is present but visudo is missing" >&2
        return 1
    fi

    install -d -m 0755 "$rootfs/usr/local/bin" "$rootfs/etc/sudoers.d"
    install -m 0755 "$helper" "$rootfs/usr/local/bin/sudo"

    # Leave any existing valid policy in place until the replacement has
    # passed syntax validation. This matters when a custom builder retries.
    rm -f "$policy_tmp"
    cat > "$policy_tmp" <<'SUDOERS'
agent ALL=(ALL) NOPASSWD:ALL
Defaults env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS"
SUDOERS
    chmod 0440 "$policy_tmp"
    chown 0:0 "$policy_tmp"
    if ! chroot "$rootfs" "$visudo" -cf "/etc/sudoers.d/$(basename "$policy_tmp")"; then
        rm -f "$policy_tmp"
        echo "install_safeyolo_privilege_helper: generated sudoers policy failed visudo validation" >&2
        return 1
    fi
    mv -f "$policy_tmp" "$policy"
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
    if ! chroot "$rootfs" /bin/bash -c 'command -v prlimit >/dev/null 2>&1'; then
        echo "install_safeyolo_guest_common: missing prlimit in rootfs -- install util-linux first" >&2
        return 1
    fi

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
    # Idempotency must not hide a genuine useradd failure. Check the passwd
    # database first, then require creation to succeed when the account is
    # absent.
    if ! grep -q '^agent:[^:]*:1000:' "$rootfs/etc/passwd" 2>/dev/null; then
        chroot "$rootfs" useradd -m -s /bin/bash -u 1000 agent
    fi
    # Unlock the agent account's password field so OpenSSH accepts pubkey
    # auth. useradd creates accounts with pw="!" (locked). OpenSSH on
    # Alpine (9.7+) refuses any auth for locked accounts, including
    # pubkey. Setting pw="*" means "no password set" without the locked
    # flag; pubkey auth then works. PasswordAuthentication is off in our
    # sshd_config so this cannot be abused for passwordless login.
    chroot "$rootfs" usermod -p '*' agent

    # Same treatment for root so `safeyolo agent shell --root` works.
    # Debian bases ship root with pw="!"; sshd's default
    # `PermitRootLogin prohibit-password` allows pubkey but Alpine's
    # OpenSSH refuses locked accounts for any auth path. The authorized_keys
    # for root are dropped by guest-init-static.sh at boot from the
    # per-agent share; this only unlocks the account so sshd will
    # honour that key.
    chroot "$rootfs" usermod -p '*' root 2>/dev/null || true

    install_safeyolo_runtime_mount_targets "$rootfs"
    install_safeyolo_privilege_helper "$rootfs"

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

    # Keep persistent global tools on PATH without consulting repository mise
    # configuration. The default rootfs builder calls the same helper.
    install_safeyolo_mise_integration "$rootfs"

    # Debian names the fd-find binary fdfind. Add the conventional command
    # without replacing a command already supplied by the rootfs.
    install_safeyolo_fd_compat "$rootfs"

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

    # Treat these as the function's output contract, not best-effort setup.
    # This also protects callers that source this library without `set -e`.
    [ -x "$rootfs/usr/local/bin/safeyolo-guest-init" ] || return 1
    grep -q '^agent:[^:]*:1000:' "$rootfs/etc/passwd" || return 1
    local required_dir
    for required_dir in workspace safeyolo safeyolo-status home/agent; do
        [ -d "$rootfs/$required_dir" ] || return 1
    done
    [ -f "$rootfs/usr/local/share/ca-certificates/safeyolo.crt" ] || return 1

    echo "=== SafeYolo guest bits installed ==="
}
