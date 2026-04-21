#!/bin/bash
#
# SafeYolo custom rootfs builder -- Alpine Linux.
#
# Minimal example proving that --rootfs-script works with any distro that
# publishes an OCI image. Swap the ALPINE_* pins + apk add list to produce
# your own variant.
#
# Runs on Linux (native) or inside the safeyolo-builder Lima VM on macOS.
# Invoked automatically by:
#
#     safeyolo agent add <name> <folder> \
#         --rootfs-script contrib/alpine-minimal/build-alpine-rootfs.sh
#
# Host deps (Linux): skopeo, umoci, apk-tools (apk-tools-static is fine),
# e2fsprogs, erofs-utils. macOS: brew install lima (the Lima VM
# preinstalls everything).
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
for tool in skopeo umoci; do
    command -v "$tool" >/dev/null || { echo "Missing $tool. Install skopeo + umoci." >&2; exit 1; }
done
if [ -n "${SAFEYOLO_ROOTFS_OUT_EXT4:-}" ]; then
    command -v mkfs.ext4 >/dev/null || { echo "Missing mkfs.ext4. Install e2fsprogs." >&2; exit 1; }
fi
if [ -n "${SAFEYOLO_ROOTFS_OUT_EROFS:-}" ]; then
    command -v mkfs.erofs >/dev/null || { echo "Missing mkfs.erofs. Install erofs-utils." >&2; exit 1; }
fi

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
# umoci lays out `rootfs/` + `config.json` + `umoci.json`; we only want rootfs.
rm -rf "$TREE"
mv "$SAFEYOLO_ROOTFS_WORK_DIR/unpack/rootfs" "$TREE"

# --- Add packages. Chroot so apk uses the tree's own resolver/config.
# This assumes the host kernel can run ${SAFEYOLO_TARGET_ARCH} binaries
# (true on matching-arch hosts; cross-arch needs qemu-user-static). ---
echo "=== Installing Alpine packages ==="
# Baseline SafeYolo runtime needs:
#   bash     -- shebang on safeyolo-guest-init and entrypoints
#   python3  -- guest-shell-bridge (vsock→sshd) is a Python script
#   shadow   -- useradd used by install_safeyolo_guest_common
#   openssh-server -- `safeyolo agent shell` SSH target
#   ca-certificates -- HTTPS trust store (SafeYolo CA appended at boot)
# Plus a baseline developer toolkit (curl, git, jq). Users extend this.
cp /etc/resolv.conf "$TREE/etc/resolv.conf" 2>/dev/null || true
chroot "$TREE" /sbin/apk add --no-cache \
    bash python3 ca-certificates shadow openssh-server curl git jq

# --- SafeYolo guest bits. ---
source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"
install_safeyolo_guest_common "$TREE"

# --- Pack into the format SafeYolo asked for. ---
if [ -n "${SAFEYOLO_ROOTFS_OUT_EXT4:-}" ]; then
    echo "=== Packing ext4 → $SAFEYOLO_ROOTFS_OUT_EXT4 ==="
    # 2 GiB sparse; the base is ~100 MB, rest left as headroom for mise +
    # first-run installs.
    truncate -s 2G "$SAFEYOLO_ROOTFS_OUT_EXT4"
    mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$TREE" "$SAFEYOLO_ROOTFS_OUT_EXT4"
fi
if [ -n "${SAFEYOLO_ROOTFS_OUT_EROFS:-}" ]; then
    echo "=== Packing erofs → $SAFEYOLO_ROOTFS_OUT_EROFS ==="
    mkfs.erofs -E noinline_data "$SAFEYOLO_ROOTFS_OUT_EROFS" "$TREE"
fi

echo "=== Alpine rootfs built successfully ==="
