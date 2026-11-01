#!/bin/bash
#
# SafeYolo custom rootfs builder -- Alpine Linux.
#
# Minimal example using an OCI image. Swap the ALPINE_* pins and apk package
# list to produce your own variant.
#
# Runs on Linux, including a Lima builder with the required inputs mounted.
# Prepare the image explicitly, then supply it to the native installation or
# a stopped agent. See contrib/ROOTFS_SCRIPT_GUIDE.md for inputs and paths.
#
# Host deps (Linux): skopeo, umoci, curl, tar, sha256sum.
# e2fsprogs needed only when preparing the ext4 output for macOS VZ.
set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?set the agent name (see contrib/ROOTFS_SCRIPT_GUIDE.md)}"
: "${SAFEYOLO_ROOTFS_WORK_DIR:?}"
: "${SAFEYOLO_GUEST_SRC_DIR:?}"
: "${SAFEYOLO_TARGET_ARCH:?}"

# --- Pins. Bump the tag; re-pull for a fresh digest. ---
ALPINE_TAG="3.22"
ALPINE_IMAGE="${ALPINE_IMAGE:-docker://alpine:${ALPINE_TAG}}" # DOC: contrib/ROOTFS_SCRIPT_GUIDE.md

case "$SAFEYOLO_TARGET_ARCH" in
    arm64|amd64) ;;
    *) echo "Unsupported SAFEYOLO_TARGET_ARCH: $SAFEYOLO_TARGET_ARCH" >&2; exit 1 ;;
esac

# Match the default and Kali builders: downloads stay unprivileged; ownership,
# chroot and filesystem operations use command-scoped root access.
BUILDER_UID="$(id -u)"
BUILDER_GID="$(id -g)"
SUDO=()
if [ "$BUILDER_UID" -ne 0 ]; then
    sudo -v
    SUDO=(sudo)
fi
_as_root() { "${SUDO[@]}" "$@"; }

# --- Tools check (fail fast with clear messages). ---
for tool in skopeo umoci curl tar sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing $tool. Install skopeo, umoci, curl, and coreutils." >&2; exit 1; }
done
if [ -n "${SAFEYOLO_ROOTFS_OUT_EXT4:-}" ]; then
    command -v mkfs.ext4 >/dev/null || { echo "Missing mkfs.ext4. Install e2fsprogs." >&2; exit 1; }
fi
# SAFEYOLO_ROOTFS_OUT_TREE (Linux gVisor) needs no extra tools — we just
# leave the unpacked tree in place for gVisor to mount as OCI root.path.

TREE="$SAFEYOLO_ROOTFS_WORK_DIR/tree"
OCI_DIR="$SAFEYOLO_ROOTFS_WORK_DIR/oci"
mkdir -p "$TREE" "$OCI_DIR"

echo "=== Pulling Alpine ${ALPINE_TAG} (${SAFEYOLO_TARGET_ARCH}) ==="
skopeo --override-arch="$SAFEYOLO_TARGET_ARCH" --override-os=linux \
    copy "$ALPINE_IMAGE" "oci:$OCI_DIR:alpine-${ALPINE_TAG}"

echo "=== Unpacking ==="
# No --rootless: preserve image ownership and modes for chroot and ext4.
_as_root umoci unpack --image "$OCI_DIR:alpine-${ALPINE_TAG}" "$SAFEYOLO_ROOTFS_WORK_DIR/unpack"
# umoci lays out `rootfs/` + `config.json` + `umoci.json`; we only want rootfs.
_as_root rm -rf "$TREE"
_as_root mv "$SAFEYOLO_ROOTFS_WORK_DIR/unpack/rootfs" "$TREE"

# --- Add packages. Chroot so apk uses the tree's own resolver/config.
# This assumes the host kernel can run ${SAFEYOLO_TARGET_ARCH} binaries
# (true on matching-arch hosts; cross-arch needs qemu-user-static). ---
echo "=== Installing Alpine packages ==="
# Baseline SafeYolo runtime needs:
#   bash     -- shebang on safeyolo-guest-init and entrypoints
#   socat    -- guest-proxy-forwarder + guest-shell-bridge (1.8+ for
#               VSOCK-LISTEN / VSOCK-CONNECT; Alpine 3.22 ships 1.8)
#   shadow   -- useradd + usermod used by install_safeyolo_guest_common
#   openssh-server -- `safeyolo agent shell` SSH target
#   ca-certificates -- HTTPS trust store (SafeYolo CA appended at boot)
#   setpriv -- util-linux helper used by the guest sudo shim (not BusyBox)
# Plus the small, universal developer toolkit we expect coding agents to use:
# curl, git, jq, ripgrep, fd, file, unzip/zip, tmux, lsof, strace, Python venv,
# and pkgconf for native build discovery. Alpine's native mise package is
# musl-linked; do not use the upstream glibc tarball on Alpine.
_as_root cp /etc/resolv.conf "$TREE/etc/resolv.conf" 2>/dev/null || true
# The builder's trusted CA path is outside the fresh chroot. Give only this
# apk invocation a temporary copy, outside ca-certificates' import directory,
# so the build proxy CA does not enter the guest's system trust bundle.
# Ordinary build-host sudo can reset these variables. Pass only configured
# proxy values to apk, including an explicitly empty bypass list.
APK_ENV=(env)
for proxy_name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy; do
    if [ "${!proxy_name+x}" = x ]; then
        APK_ENV+=("$proxy_name=${!proxy_name}")
    fi
done
APK_BUILD_CA=""
if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
    APK_BUILD_CA="$(_as_root mktemp "$TREE/tmp/safeyolo-apk-ca.XXXXXX")"
    trap '_as_root rm -f "$APK_BUILD_CA"' EXIT
    _as_root install -m 0644 "$SSL_CERT_FILE" "$APK_BUILD_CA"
    APK_ENV+=("SSL_CERT_FILE=${APK_BUILD_CA#"$TREE"}") # DOC: contrib/ROOTFS_SCRIPT_GUIDE.md
fi
_as_root chroot "$TREE" "${APK_ENV[@]}" /sbin/apk add --no-cache \
    bash socat ca-certificates shadow openssh-server curl git jq sudo setpriv util-linux-misc mise \
    python3 py3-pip py3-virtualenv \
    ripgrep fd file unzip zip tmux lsof strace pkgconf
if [ -n "$APK_BUILD_CA" ]; then
    _as_root rm -f "$APK_BUILD_CA"
    trap - EXIT
fi

# --- SafeYolo guest bits. ---
_as_root env SAFEYOLO_GUEST_SRC_DIR="$SAFEYOLO_GUEST_SRC_DIR" \
    bash -c 'set -euo pipefail; source "$1"; install_safeyolo_guest_common "$2"' \
    bash "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh" "$TREE"

# apk honours http_proxy / https_proxy natively. The shared guest installer
# supplies the sudo compatibility shim and preserves proxy + CA variables.

# --- Pack into the format SafeYolo asked for. ---
# Exactly one of OUT_EXT4 / OUT_TREE is set per invocation.
if [ -n "${SAFEYOLO_ROOTFS_OUT_EXT4:-}" ]; then
    echo "=== Packing ext4 → $SAFEYOLO_ROOTFS_OUT_EXT4 ==="
    # 2 GiB sparse; the base is small, rest left as headroom for mise +
    # first-run installs.
    truncate -s 2G "$SAFEYOLO_ROOTFS_OUT_EXT4"
    _as_root mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$TREE" "$SAFEYOLO_ROOTFS_OUT_EXT4"
    _as_root chown "$BUILDER_UID:$BUILDER_GID" "$SAFEYOLO_ROOTFS_OUT_EXT4"
fi
if [ -n "${SAFEYOLO_ROOTFS_OUT_TREE:-}" ]; then
    echo "=== Staging tree → $SAFEYOLO_ROOTFS_OUT_TREE ==="
    # gVisor mounts the directory directly; no packing needed. cp -a
    # preserves ownership/perms/xattrs which matter for suid binaries,
    # sshd host keys, and /etc/shadow perms.
    _as_root mkdir -p "$(dirname "$SAFEYOLO_ROOTFS_OUT_TREE")"
    _as_root cp -a "$TREE/." "$SAFEYOLO_ROOTFS_OUT_TREE/"
    # Native Linux startup requires the tree to belong to mapped sandbox root.
    _as_root chmod 0755 "$SAFEYOLO_ROOTFS_OUT_TREE"
    _as_root chown -R 100000:100000 "$SAFEYOLO_ROOTFS_OUT_TREE"
fi

# Per-distro package caches worth persisting across agent restarts.
# Alpine uses /var/cache/apk — SafeYolo bind-mounts a per-agent host
# dir onto that path at boot so runtime `apk add` hits a warm cache.
if [ -n "${SAFEYOLO_ROOTFS_OUT_CACHE_PATHS:-}" ]; then
    cat > "$SAFEYOLO_ROOTFS_OUT_CACHE_PATHS" <<'CACHE_PATHS'
/var/cache/apk
CACHE_PATHS
fi

echo "=== Alpine rootfs built successfully ==="
