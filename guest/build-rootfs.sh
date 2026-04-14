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

# Pinned mise version (same as previous Docker-based build)
MISE_VERSION="${MISE_VERSION:-2026.1.1}"
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-dcd7006e84d3557284a7c87b99abdce4a465900f67609e99b39c757006a361dd}"
MISE_SHA256_AMD64="${MISE_SHA256_AMD64:-}"

# Pinned gh CLI version
GH_VERSION="${GH_VERSION:-2.89.0}"
GH_SHA256_ARM64="${GH_SHA256_ARM64:-9e64a623dfc242990aa5d9b3f507111149c4282f66b68eaad1dc79eeb13b9ce5}"
GH_SHA256_AMD64="${GH_SHA256_AMD64:-}"

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

HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
[ -r "$HOOK_SCRIPT" ] || { echo "Missing $HOOK_SCRIPT" >&2; exit 1; }

# Export for the customize-hook process. mmdebstrap's hooks inherit the
# invoking process's env, so we just export and the hook sees them.
export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export GUEST_SRC_DIR="$SCRIPT_DIR"

# Essential-hook: runs after the essential packages are installed but BEFORE
# the --include packages. Drops in a dpkg.cfg.d file that tells dpkg to skip
# docs, man pages, info files, and non-English locales during ALL subsequent
# installs — including build-essential and its 100+MB of compiler docs that
# otherwise dominate the rootfs size.
#
# We keep copyright files specifically (Debian redistribution compliance)
# via the path-include rule.
ESSENTIAL_HOOK='
set -euo pipefail
ROOTFS="$1"
mkdir -p "$ROOTFS/etc/dpkg/dpkg.cfg.d"
cat > "$ROOTFS/etc/dpkg/dpkg.cfg.d/01-nodoc" <<NODOC
path-exclude /usr/share/doc/*
path-include /usr/share/doc/*/copyright
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
path-include /usr/share/locale/locale.alias
NODOC
'

echo "--- Running mmdebstrap (trixie, ${DEB_ARCH}, minbase) ---"
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,GUEST_SRC_DIR \
    mmdebstrap \
        --mode=root \
        --variant=minbase \
        --arch="$DEB_ARCH" \
        --include=ca-certificates,curl,git,jq,build-essential,gnupg,openssh-server,iproute2,iputils-ping,procps,less,xz-utils,libgomp1,libatomic1,python3,python3-pip,busybox-static \
        --essential-hook="$ESSENTIAL_HOOK" \
        --customize-hook="bash $HOOK_SCRIPT \"\$1\"" \
        trixie \
        "$WORK_DIR" \
        http://deb.debian.org/debian

# Fixed ${ROOTFS_SIZE_MB}M sparse image, matching the original Docker-based
# build. Leaves enough free space for agent-time installs (npm, pip, mise
# tools). Sparse on-disk, so the actual bytes used are close to content size.
echo "--- Building ${ROOTFS_SIZE_MB} MiB sparse ext4 image ---"
truncate -s "${ROOTFS_SIZE_MB}M" "$OUTPUT_EXT4"
# mkfs.ext4 -d populates directly from the unpacked tree. Requires the target
# directory to be owned by root (it is, coming from --mode=root mmdebstrap).
sudo mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$WORK_DIR" "$OUTPUT_EXT4"

# Make the resulting image readable by the invoking user.
sudo chown "$(id -u):$(id -g)" "$OUTPUT_EXT4"

echo "=== Rootfs ready at $OUTPUT_EXT4 ==="
echo "Actual size: $(du -sh "$OUTPUT_EXT4" | cut -f1)"
