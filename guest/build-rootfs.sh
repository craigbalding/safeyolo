#!/bin/bash
#
# Build Debian trixie rootfs for SafeYolo agents.
#
# Runs on Linux only (natively or inside the Lima VM on macOS — see
# guest/build-all.sh). Uses mmdebstrap instead of Docker+debootstrap.
#
# Supports: arm64 (default on Apple Silicon), amd64 (for x86_64 VPS).
#
# Usage:
#   ./build-rootfs.sh              # Build for host architecture
#   ARCH=amd64 ./build-rootfs.sh   # Build for x86_64
#   ARCH=arm64 ./build-rootfs.sh   # Build for ARM64
#
# Output: out/rootfs-base.ext4 (~400MB actual)
#
# Dependencies (install via apt on the host):
#   mmdebstrap e2fsprogs
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

# Linux-only guard — mmdebstrap uses Linux-specific syscalls.
if [ "$(uname)" != "Linux" ]; then
    echo "Error: build-rootfs.sh runs on Linux only." >&2
    echo "On macOS, run ./build-all.sh from the repo which will shell" >&2
    echo "into a Lima VM automatically. See guest/README.md." >&2
    exit 1
fi

# Architecture detection
HOST_ARCH="$(uname -m)"
case "${ARCH:-$HOST_ARCH}" in
    aarch64|arm64) DEB_ARCH="arm64" ;;
    x86_64|amd64)  DEB_ARCH="amd64" ;;
    *) echo "Unsupported architecture: ${ARCH:-$HOST_ARCH}"; exit 1 ;;
esac

# Matches the original Docker-based build (2GB sparse) — leaves room for
# agent-time installs (npm packages, mise tools, pip installs).
ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"

# Pinned mise version (same as previous Docker-based build).
# mise names its amd64 asset "linux-x64" (not "linux-amd64") — the hook
# script maps DEB_ARCH→MISE_ARCH when building the download URL.
MISE_VERSION="${MISE_VERSION:-2026.1.1}"
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-dcd7006e84d3557284a7c87b99abdce4a465900f67609e99b39c757006a361dd}"
MISE_SHA256_AMD64="${MISE_SHA256_AMD64:-e35fd46d51f27829f4aefe60c9a8e92a68534de5ad07568b5f034144d1d3cf0c}"

# Pinned gh CLI version
GH_VERSION="${GH_VERSION:-2.89.0}"
GH_SHA256_ARM64="${GH_SHA256_ARM64:-9e64a623dfc242990aa5d9b3f507111149c4282f66b68eaad1dc79eeb13b9ce5}"
GH_SHA256_AMD64="${GH_SHA256_AMD64:-d0422caade520530e76c1c558da47daebaa8e1203d6b7ff10ad7d6faba3490d8}"

# Pinned debian-archive-keyring (arch: all, so one pin for every ARCH).
#
# We fetch+verify this ourselves instead of relying on the host's
# /usr/share/keyrings/debian-archive-keyring.gpg. Reasons:
#   1) Ubuntu LTS ships a pre-trixie keyring (2023.3), which fails
#      Release.gpg verification with NO_PUBKEY on trixie's InRelease.
#   2) Host keyring state drifts silently. A pinned + SHA256-verified
#      fetch makes the build reproducible across host distros.
#   3) Same trust model as the pinned mise/gh binaries above — no
#      system-wide package mutation just to run a build.
DAK_VERSION="${DAK_VERSION:-2025.1}"
DAK_SHA256="${DAK_SHA256:-9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac}"

mkdir -p "$OUTPUT_DIR"

OUTPUT_EXT4="$OUTPUT_DIR/rootfs-base.ext4"
if [ -f "$OUTPUT_EXT4" ]; then
    echo "Rootfs already exists at $OUTPUT_EXT4"
    echo "Delete it to rebuild."
    exit 0
fi

command -v mmdebstrap >/dev/null || {
    echo "Error: mmdebstrap not installed." >&2
    echo "  Debian/Ubuntu: sudo apt-get install mmdebstrap e2fsprogs" >&2
    exit 1
}
command -v mkfs.ext4 >/dev/null || {
    echo "Error: mkfs.ext4 not installed (apt-get install e2fsprogs)." >&2
    exit 1
}

# Fetch + SHA256-verify debian-archive-keyring, cache under out/, and pass it
# to mmdebstrap via --keyring= below. See DAK_VERSION comment above for why.
# dpkg-deb is always present alongside mmdebstrap on Debian/Ubuntu hosts.
command -v dpkg-deb >/dev/null || {
    echo "Error: dpkg-deb not found (needed to unpack the pinned keyring)." >&2
    exit 1
}

DAK_CACHE_DIR="$OUTPUT_DIR/.keyring-cache"
DAK_DEB="$DAK_CACHE_DIR/debian-archive-keyring_${DAK_VERSION}_all.deb"
DAK_GPG="$DAK_CACHE_DIR/debian-archive-keyring.gpg"
mkdir -p "$DAK_CACHE_DIR"

# Re-fetch if missing or if a previous interrupted download left a bad file.
if [ ! -f "$DAK_DEB" ] \
   || ! echo "${DAK_SHA256}  ${DAK_DEB}" | sha256sum -c - >/dev/null 2>&1; then
    echo "--- Fetching debian-archive-keyring ${DAK_VERSION} (pinned) ---"
    curl -fsSL \
        "http://ftp.debian.org/debian/pool/main/d/debian-archive-keyring/debian-archive-keyring_${DAK_VERSION}_all.deb" \
        -o "$DAK_DEB"
    echo "${DAK_SHA256}  ${DAK_DEB}" | sha256sum -c -
    rm -f "$DAK_GPG"  # force re-extract from the fresh .deb
fi

# Extract just the combined keyring file — that's all mmdebstrap needs.
if [ ! -f "$DAK_GPG" ]; then
    DAK_TMP="$(mktemp -d -t safeyolo-dak.XXXXXX)"
    dpkg-deb -x "$DAK_DEB" "$DAK_TMP"
    cp "$DAK_TMP/usr/share/keyrings/debian-archive-keyring.gpg" "$DAK_GPG"
    rm -rf "$DAK_TMP"
fi

echo "=== Building Debian trixie ${DEB_ARCH} rootfs with mmdebstrap ==="

# Work directory for the unpacked tree before we size + pack the ext4 image.
# mmdebstrap runs under sudo and populates WORK_DIR with root-owned files,
# so cleanup must also run under sudo or we'll hit thousands of "Permission
# denied" errors and leave the tree behind.
WORK_DIR="$(mktemp -d -t safeyolo-rootfs.XXXXXX)"
cleanup_workdir() {
    if [ -d "$WORK_DIR" ]; then
        # Try sudo first (the common case — sudo creds are cached after the
        # mmdebstrap call). Fall back to a best-effort plain rm that may
        # leave some files behind rather than spamming errors.
        sudo -n rm -rf "$WORK_DIR" 2>/dev/null \
            || rm -rf "$WORK_DIR" 2>/dev/null \
            || true
    fi
}
trap cleanup_workdir EXIT

# Resolve the pinned mise/gh tarball SHA256s by architecture.
MISE_SHA256_VAR="MISE_SHA256_$(echo "$DEB_ARCH" | tr a-z A-Z)"
GH_SHA256_VAR="GH_SHA256_$(echo "$DEB_ARCH" | tr a-z A-Z)"
MISE_SHA256="${!MISE_SHA256_VAR:-}"
GH_SHA256="${!GH_SHA256_VAR:-}"

CUSTOMIZE_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
ESSENTIAL_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-essential-hook.sh"
[ -r "$CUSTOMIZE_HOOK_SCRIPT" ] || { echo "Missing $CUSTOMIZE_HOOK_SCRIPT" >&2; exit 1; }
[ -x "$ESSENTIAL_HOOK_SCRIPT" ] || { echo "Missing or non-executable $ESSENTIAL_HOOK_SCRIPT" >&2; exit 1; }

# Export for the customize-hook process. mmdebstrap's hooks inherit the
# invoking process's env, so we just export and the hook sees them.
export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export GUEST_SRC_DIR="$SCRIPT_DIR"

# Essential-hook: runs after essential packages are installed but BEFORE
# the --include packages. Lives in rootfs-essential-hook.sh.
#
# We pass a file path (not an inline string) so mmdebstrap's hook dispatch
# hits its `-x $script` branch and executes the script directly — shebang
# honored, no `sh -c` wrap, no Perl "Unsuccessful stat on filename
# containing newline" noise from mmdebstrap probing an inline script body.

echo "--- Running mmdebstrap (trixie, ${DEB_ARCH}, minbase) ---"
# Explain the sudo prompt before it appears. mmdebstrap --mode=root needs
# real root to mknod device files, chroot + run package maintainer scripts,
# and chown files to root inside the rootfs tree. The alternative
# (--mode=unshare, user namespaces) is blocked by Ubuntu 24.04's default
# AppArmor restriction on unprivileged userns, so --mode=root is the
# portable choice. Everything root touches is under $WORK_DIR in /tmp.
if ! sudo -n true 2>/dev/null; then
    echo ""
    echo "    sudo prompt ahead: mmdebstrap needs root to populate and chroot"
    echo "    into the new rootfs under $WORK_DIR (a scratch /tmp directory)."
    echo "    Nothing outside that directory is modified. See guest/README.md"
    echo "    'Why sudo?' for the full explanation and unshare-mode alternative."
    echo ""
fi
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,GUEST_SRC_DIR \
    mmdebstrap \
        --mode=root \
        --variant=minbase \
        --arch="$DEB_ARCH" \
        --keyring="$DAK_GPG" \
        --include=ca-certificates,curl,git,jq,build-essential,gnupg,openssh-server,iproute2,iputils-ping,procps,less,xz-utils,libgomp1,libatomic1,python3,python3-pip,busybox-static,socat \
        --essential-hook="$ESSENTIAL_HOOK_SCRIPT" \
        --customize-hook="bash $CUSTOMIZE_HOOK_SCRIPT \"\$1\"" \
        trixie \
        "$WORK_DIR" \
        http://deb.debian.org/debian

# Fixed ${ROOTFS_SIZE_MB}M sparse image, matching the original Docker-based
# EROFS image — for Linux gVisor rootless path. gVisor mounts the EROFS
# image directly in its sentry and handles writable overlay internally
# (memory-backed). All agents share one read-only image. No fuse-overlayfs,
# no uid remapping, no per-agent copies.
#
# -E noinline_data: gVisor's EROFS implementation on some releases can't
# read inline file data layouts. This flag disables them at the cost of
# ~5% larger images. Drop it when the target gVisor version supports
# inline data reliably.
OUTPUT_EROFS="$OUTPUT_DIR/rootfs-base.erofs"
if command -v mkfs.erofs >/dev/null 2>&1; then
    echo "--- Creating EROFS image ---"
    sudo mkfs.erofs -E noinline_data "$OUTPUT_EROFS" "$WORK_DIR"
    sudo chown "$(id -u):$(id -g)" "$OUTPUT_EROFS"
    chmod 644 "$OUTPUT_EROFS"  # must be world-readable for rootless userns
    echo "EROFS: $OUTPUT_EROFS ($(du -sh "$OUTPUT_EROFS" | cut -f1))"
else
    echo "--- mkfs.erofs not found, skipping EROFS image ---"
    echo "    Install: sudo apt install erofs-utils"
fi

# ext4 image — for macOS microVMs (Virtualization.framework mounts ext4
# directly). Leaves enough free space for agent-time installs.
echo "--- Building ${ROOTFS_SIZE_MB} MiB sparse ext4 image ---"
truncate -s "${ROOTFS_SIZE_MB}M" "$OUTPUT_EXT4"
sudo mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$WORK_DIR" "$OUTPUT_EXT4"
sudo chown "$(id -u):$(id -g)" "$OUTPUT_EXT4"

echo "=== Rootfs ready ==="
echo "  ext4:  $OUTPUT_EXT4 ($(du -sh "$OUTPUT_EXT4" | cut -f1))"
if [ -f "$OUTPUT_EROFS" ]; then
    echo "  erofs: $OUTPUT_EROFS ($(du -sh "$OUTPUT_EROFS" | cut -f1))"
fi
