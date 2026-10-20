#!/bin/bash
#
# SafeYolo custom rootfs builder -- Alpine Linux + headful browser via noVNC.
#
# A copy of contrib/alpine-minimal with one addition: a virtual X display
# (Xvfb) exported over noVNC, so an agent can spawn a real browser inside the
# container and the operator can watch it from their host in a web browser.
#
# Chromium is baked in alongside the noVNC stack so the core SafeYolo desktop
# launcher can open a browser immediately after first boot.
#
# Prepare the image explicitly, then supply it to the native installation or
# a stopped agent. See contrib/ROOTFS_SCRIPT_GUIDE.md for inputs and paths.
# After starting the agent, `safeyolo agent present NAME` opens its desktop.
#
# Runs on Linux, including a Lima builder with the required inputs mounted.
# Host deps (Linux): skopeo, umoci, curl, tar, sha256sum.
# e2fsprogs only for the ext4 output (macOS).
set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?set the agent name (see contrib/ROOTFS_SCRIPT_GUIDE.md)}"
: "${SAFEYOLO_ROOTFS_WORK_DIR:?}"
: "${SAFEYOLO_GUEST_SRC_DIR:?}"
: "${SAFEYOLO_TARGET_ARCH:?}"

# --- Pins. Bump the tag; re-pull for a fresh digest. ---
ALPINE_TAG="3.22"
ALPINE_IMAGE="docker://alpine:${ALPINE_TAG}"

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
_as_root rm -rf "$TREE"
_as_root mv "$SAFEYOLO_ROOTFS_WORK_DIR/unpack/rootfs" "$TREE"

# --- Add packages. Chroot so apk uses the tree's own resolver/config. ---
echo "=== Installing Alpine packages ==="
# Baseline SafeYolo runtime + the small universal developer toolkit (same set
# as contrib/alpine-minimal), plus the headful-browser display stack:
#   xvfb        -- virtual X server (the :99 framebuffer the browser draws on)
#   x11vnc      -- exposes that display over VNC (localhost:5900)
#   noVNC assets are installed below; the packaged native guest helper serves
#   them and bridges WebSocket to VNC on loopback :6080.
#   fluxbox/xterm -- tiny window manager plus a discoverable app menu/terminal
#   font-noto      -- without fonts the browser renders blank/tofu text
#   procps-ng      -- the core desktop launcher uses pkill (not in busybox)
#   util-linux-misc -- provides setsid and the PID 1 prlimit operation
#   mise          -- Alpine's native musl-linked package
#   nodejs/npm    -- native musl-linked Node toolchain for Codex/web tooling
#   chromium      -- headful browser shown through noVNC
#   nss-tools     -- certutil, used by the staged browser launcher for CA trust
_as_root cp /etc/resolv.conf "$TREE/etc/resolv.conf" 2>/dev/null || true
# The builder's trusted CA path is outside the fresh chroot. Give only this
# apk invocation a temporary copy, outside ca-certificates' import directory,
# so the build proxy CA does not enter the guest's system trust bundle.
APK_ENV=()
APK_BUILD_CA=""
if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
    APK_BUILD_CA="$(_as_root mktemp "$TREE/tmp/safeyolo-apk-ca.XXXXXX")"
    _as_root install -m 0644 "$SSL_CERT_FILE" "$APK_BUILD_CA"
    APK_ENV=(env "SSL_CERT_FILE=${APK_BUILD_CA#"$TREE"}") # DOC: contrib/ROOTFS_SCRIPT_GUIDE.md
fi
_as_root chroot "$TREE" "${APK_ENV[@]}" /sbin/apk add --no-cache \
    bash socat ca-certificates shadow openssh-server curl git jq sudo mise nodejs npm \
    python3 py3-pip py3-virtualenv \
    ripgrep fd file unzip zip tmux lsof strace pkgconf \
    xvfb x11vnc font-noto procps-ng util-linux-misc \
    nss-tools dbus fluxbox xterm chromium
if [ -n "$APK_BUILD_CA" ]; then
    _as_root rm -f "$APK_BUILD_CA"
fi

NOVNC_STAGE="$SAFEYOLO_ROOTFS_WORK_DIR/novnc-stage"
bash "$SAFEYOLO_GUEST_SRC_DIR/install-novnc-assets.sh" \
    "$NOVNC_STAGE" "$SAFEYOLO_ROOTFS_WORK_DIR/.download-cache"
_as_root cp -a "$NOVNC_STAGE/usr/share/novnc" "$TREE/usr/share/"
_as_root chown -R 0:0 "$TREE/usr/share/novnc"
_as_root chmod -R a+rX "$TREE/usr/share/novnc"

# SafeYolo stages its current desktop lifecycle/browser helper at
# /safeyolo/guest-desktop on every run. This rootfs supplies only the optional
# graphical capability packages, so it cannot drift from the CLI contract.

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
    # 2 GiB sparse. This base is mounted read-only at runtime; all runtime
    # writes (mise runtimes, browser cache) land in the separate
    # per-agent 256 GiB overlay (/dev/vdb), so the base only needs to hold
    # the build-time tree (Alpine base + X stack, a few hundred MB).
    truncate -s 2G "$SAFEYOLO_ROOTFS_OUT_EXT4"
    _as_root mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$TREE" "$SAFEYOLO_ROOTFS_OUT_EXT4"
    _as_root chown "$BUILDER_UID:$BUILDER_GID" "$SAFEYOLO_ROOTFS_OUT_EXT4"
fi
if [ -n "${SAFEYOLO_ROOTFS_OUT_TREE:-}" ]; then
    echo "=== Staging tree → $SAFEYOLO_ROOTFS_OUT_TREE ==="
    # gVisor mounts the directory directly; no packing needed. cp -a preserves
    # ownership/perms/xattrs (sshd host keys, /etc/shadow, suid bits).
    _as_root mkdir -p "$(dirname "$SAFEYOLO_ROOTFS_OUT_TREE")"
    _as_root cp -a "$TREE/." "$SAFEYOLO_ROOTFS_OUT_TREE/"
    # Native Linux startup requires the tree to belong to mapped sandbox root.
    _as_root chmod 0755 "$SAFEYOLO_ROOTFS_OUT_TREE"
    _as_root chown -R 100000:100000 "$SAFEYOLO_ROOTFS_OUT_TREE"
fi

# Per-agent apk cache persisted across restarts so runtime `apk add` is warm.
if [ -n "${SAFEYOLO_ROOTFS_OUT_CACHE_PATHS:-}" ]; then
    cat > "$SAFEYOLO_ROOTFS_OUT_CACHE_PATHS" <<'CACHE_PATHS'
/var/cache/apk
CACHE_PATHS
fi

echo "=== Alpine browser rootfs built successfully ==="
