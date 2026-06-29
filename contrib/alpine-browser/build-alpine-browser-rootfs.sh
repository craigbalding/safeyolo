#!/bin/bash
#
# SafeYolo custom rootfs builder -- Alpine Linux + headful browser via noVNC.
#
# A copy of contrib/alpine-minimal with one addition: a virtual X display
# (Xvfb) exported over noVNC, so an agent can spawn a real browser inside the
# container and the operator can watch it from their host in a web browser.
#
# The browser itself is NOT baked in. The agent installs it at runtime with
#     sudo apk add chromium
# which keeps it current for long-lived agents and hits the warm per-agent
# apk cache (/var/cache/apk is bind-mounted at boot).
#
# Operator workflow:
#     safeyolo agent add web . \
#         --rootfs-script contrib/alpine-browser/build-alpine-browser-rootfs.sh
#     safeyolo agent shell web -c 'sudo apk add chromium'   # once
#     safeyolo agent shell web -c 'startvnc && chrome https://example.com'
#     safeyolo agent preview web 6080                       # on the host
#     # open http://127.0.0.1:6080/vnc.html
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
#   font-noto      -- without fonts the browser renders blank/tofu text
#   procps-ng      -- startvnc uses pkill/pgrep (Alpine busybox lacks them)
#   util-linux-misc -- provides setsid, used by startvnc to detach x11vnc
#   gcompat/libgcc -- let the glibc-linked mise release binary run on Alpine
# The browser is NOT installed here -- `sudo apk add chromium` at runtime.
cp /etc/resolv.conf "$TREE/etc/resolv.conf" 2>/dev/null || true
chroot "$TREE" /sbin/apk add --no-cache \
    bash socat ca-certificates shadow openssh-server curl git jq sudo gcompat libgcc \
    python3 py3-pip py3-virtualenv \
    ripgrep fd file unzip zip tmux lsof strace pkgconf \
    xvfb x11vnc novnc websockify font-noto procps-ng util-linux-misc

# --- Browser helpers on PATH (embedded; only this script file is staged into
# the macOS build VM, so siblings must be written inline). ---
echo "=== Installing startvnc + chrome helpers ==="

# startvnc: bring up Xvfb -> x11vnc -> websockify on loopback. Idempotent.
# Binds 127.0.0.1 only -- the operator reaches it via `safeyolo agent preview`.
# No need to expose 0.0.0.0 inside the VM.
cat > "$TREE/usr/local/bin/startvnc" <<'STARTVNC'
#!/bin/bash
# Start the noVNC display stack: Xvfb -> x11vnc -> websockify.
# Idempotent — kills any previous run first. Does NOT launch a browser;
# use `chrome` for that. View from the host:
#   safeyolo agent preview <name> 6080
#   open http://127.0.0.1:6080/vnc.html
set -euo pipefail

DISPLAY_NUM=99
VNC_PORT=5900
NOVNC_PORT=6080
export DISPLAY=":${DISPLAY_NUM}"

rm -f "/tmp/.X${DISPLAY_NUM}-lock" "/tmp/.X11-unix/X${DISPLAY_NUM}" 2>/dev/null || true
pkill -f "Xvfb :${DISPLAY_NUM}" 2>/dev/null || true
pkill -f "x11vnc -display :${DISPLAY_NUM}" 2>/dev/null || true
pkill -f "websockify.*${NOVNC_PORT}" 2>/dev/null || true
sleep 1

# 1. Xvfb (virtual framebuffer)
Xvfb ":${DISPLAY_NUM}" -screen 0 1280x800x24 &>/tmp/xvfb.log &
sleep 1

# 2. x11vnc on loopback. The -noxdamage/-noxfixes/-noscr/-nowf flags avoid a
#    50%+ CPU busy-loop in x11vnc 0.9.x; -threads is needed for connections.
setsid x11vnc -display ":${DISPLAY_NUM}" -nopw -listen 127.0.0.1 -rfbport "${VNC_PORT}" \
  -forever -shared -noxdamage -noxfixes -noscr -nowf -threads \
  &>/tmp/x11vnc.log &
sleep 2

# 3. websockify (noVNC web frontend) on loopback
websockify --web /usr/share/novnc "127.0.0.1:${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" \
  &>/tmp/websockify.log &

echo "noVNC ready inside the VM on 127.0.0.1:${NOVNC_PORT}"
echo "From the host:  safeyolo agent preview <name> ${NOVNC_PORT}"
echo "Then open:      http://127.0.0.1:${NOVNC_PORT}/vnc.html"
STARTVNC
chmod 0755 "$TREE/usr/local/bin/startvnc"

# chrome: thin launcher. Auto-detects chromium, points it at the Xvfb display,
# enables CDP on 127.0.0.1:9222, and inherits HTTP_PROXY so traffic flows
# through SafeYolo. NO_PROXY (set in the guest env) keeps CDP/loopback direct.
cat > "$TREE/usr/local/bin/chrome" <<'CHROME'
#!/bin/bash
# Launch chromium on the noVNC display. Usage: chrome [URL]
set -euo pipefail

export DISPLAY="${DISPLAY:-:99}"
CDP_PORT="${CHROME_CDP_PORT:-9222}"
PROFILE="${HOME}/.cache/chrome/profile"

BIN=""
for c in chromium chromium-browser; do
  command -v "$c" >/dev/null 2>&1 && { BIN="$c"; break; }
done
if [ -z "$BIN" ]; then
  echo "error: no chromium found. Install it first:  sudo apk add chromium" >&2
  exit 1
fi

mkdir -p "$PROFILE"
# --no-sandbox: the VM is the sandbox; chromium's own sandbox needs kernel
# features gVisor doesn't expose. Chromium inherits HTTP_PROXY from the env.
exec "$BIN" \
  --no-sandbox --no-first-run --no-default-browser-check \
  --disable-gpu --disable-dev-shm-usage --start-maximized \
  --remote-debugging-port="${CDP_PORT}" \
  --user-data-dir="${PROFILE}" \
  "$@"
CHROME
chmod 0755 "$TREE/usr/local/bin/chrome"

# --- SafeYolo guest bits. ---
source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
install_safeyolo_mise "$TREE" "$SAFEYOLO_TARGET_ARCH"
install_safeyolo_guest_common "$TREE"

# --- Runtime apk support: passwordless sudo, env-propagated proxy. ---
# apk honours http_proxy / https_proxy natively, so we only need sudo to keep
# those vars (and the SafeYolo CA paths) across the privilege boundary.
mkdir -p "$TREE/etc/sudoers.d"
cat > "$TREE/etc/sudoers.d/safeyolo-agent" <<'SUDOERS'
agent ALL=(ALL) NOPASSWD:ALL
Defaults env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy"
Defaults env_keep += "NO_PROXY no_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS"
SUDOERS
chmod 0440 "$TREE/etc/sudoers.d/safeyolo-agent"

# --- Pack into the format SafeYolo asked for. ---
# Exactly one of OUT_EXT4 / OUT_TREE is set per invocation.
if [ -n "${SAFEYOLO_ROOTFS_OUT_EXT4:-}" ]; then
    echo "=== Packing ext4 → $SAFEYOLO_ROOTFS_OUT_EXT4 ==="
    # 2 GiB sparse. This base is mounted read-only at runtime; all runtime
    # writes (apk add chromium, mise runtimes, browser cache) land in the separate
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
