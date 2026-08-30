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
# Operator workflow (the agent must already be running):
#     safeyolo agent add web . \
#         --rootfs-script contrib/alpine-browser/build-alpine-browser-rootfs.sh
#     safeyolo agent desktop web --browser https://example.com --open
#
# Runs on Linux (native) or inside the safeyolo-builder Lima VM on macOS.
# Host deps (Linux): skopeo, umoci, curl, tar, sha256sum.
# e2fsprogs only for the ext4 output (macOS).
set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be invoked via safeyolo agent add --rootfs-script}"
: "${SAFEYOLO_ROOTFS_WORK_DIR:?}"
: "${SAFEYOLO_GUEST_SRC_DIR:?}"
: "${SAFEYOLO_TARGET_ARCH:?}"

# --- Pins. Bump the tag; re-pull for a fresh digest. ---
ALPINE_TAG="3.20"
ALPINE_IMAGE="docker://alpine:${ALPINE_TAG}"

case "$SAFEYOLO_TARGET_ARCH" in
    arm64|amd64) ;;
    *) echo "Unsupported SAFEYOLO_TARGET_ARCH: $SAFEYOLO_TARGET_ARCH" >&2; exit 1 ;;
esac

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
# No --rootless: SafeYolo runs this script as VM-root (sudo -E wrapper in
# vm.py::_run_rootfs_script_lima). --rootless leaves xattrs/modes that
# mkfs.ext4 -d can't read back when packing the final image.
umoci unpack --image "$OCI_DIR:alpine-${ALPINE_TAG}" "$SAFEYOLO_ROOTFS_WORK_DIR/unpack"
rm -rf "$TREE"
mv "$SAFEYOLO_ROOTFS_WORK_DIR/unpack/rootfs" "$TREE"

# --- Add packages. Chroot so apk uses the tree's own resolver/config. ---
echo "=== Installing Alpine packages ==="
# Baseline SafeYolo runtime + the small universal developer toolkit (same set
# as contrib/alpine-minimal), plus the headful-browser display stack:
#   xvfb        -- virtual X server (the :99 framebuffer the browser draws on)
#   x11vnc      -- exposes that display over VNC (localhost:5900)
#   novnc       -- the web client assets served at /usr/share/novnc
#   websockify  -- WebSocket<->VNC bridge that serves noVNC on :6080
#   fluxbox/xterm -- tiny window manager plus a discoverable app menu/terminal
#   font-noto      -- without fonts the browser renders blank/tofu text
#   procps-ng      -- the core desktop launcher uses pkill (not in busybox)
#   util-linux-misc -- provides setsid and the PID 1 prlimit operation
#   mise          -- Alpine's native musl-linked package
#   nodejs/npm    -- native musl-linked Node toolchain for Codex/web tooling
#   chromium      -- headful browser shown through noVNC
#   nss-tools     -- certutil, used by the chrome wrapper to trust SafeYolo CA
cp /etc/resolv.conf "$TREE/etc/resolv.conf" 2>/dev/null || true
chroot "$TREE" /sbin/apk add --no-cache \
    bash socat ca-certificates shadow openssh-server curl git jq sudo mise nodejs npm \
    python3 py3-pip py3-virtualenv \
    ripgrep fd file unzip zip tmux lsof strace pkgconf \
    xvfb x11vnc novnc websockify font-noto procps-ng util-linux-misc \
    nss-tools dbus fluxbox xterm chromium

# SafeYolo stages its current desktop lifecycle/browser helper at
# /safeyolo/guest-desktop on every run. This rootfs supplies only the optional
# graphical capability packages, so it cannot drift from the CLI contract.

# --- SafeYolo guest bits. ---
source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
install_safeyolo_guest_common "$TREE"

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
    mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$TREE" "$SAFEYOLO_ROOTFS_OUT_EXT4"
fi
if [ -n "${SAFEYOLO_ROOTFS_OUT_TREE:-}" ]; then
    echo "=== Staging tree → $SAFEYOLO_ROOTFS_OUT_TREE ==="
    # gVisor mounts the directory directly; no packing needed. cp -a preserves
    # ownership/perms/xattrs (sshd host keys, /etc/shadow, suid bits).
    mkdir -p "$(dirname "$SAFEYOLO_ROOTFS_OUT_TREE")"
    cp -a "$TREE/." "$SAFEYOLO_ROOTFS_OUT_TREE/"
fi

# Per-agent apk cache persisted across restarts so runtime `apk add` is warm.
if [ -n "${SAFEYOLO_ROOTFS_OUT_CACHE_PATHS:-}" ]; then
    cat > "$SAFEYOLO_ROOTFS_OUT_CACHE_PATHS" <<'CACHE_PATHS'
/var/cache/apk
CACHE_PATHS
fi

echo "=== Alpine browser rootfs built successfully ==="
