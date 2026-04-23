#!/bin/bash
#
# Build the SafeYolo base rootfs from the official Debian trixie OCI image.
#
# Pulls docker://debian:trixie via skopeo, unpacks with umoci, apt-installs
# our baseline toolkit inside a chroot, runs rootfs-customize-hook.sh to
# stamp SafeYolo-specific bits (mise, gh, init stub, sshd config, agent
# user, package-manager intercepts), then writes two artifacts:
#
#   out/rootfs-base.ext4    — for macOS VZ (mounts this as /dev/vda read-only)
#   out/rootfs-tree/        — for Linux gVisor (used as OCI root.path;
#                             gVisor mounts the directory tree directly,
#                             overlayfs upper handles writes)
#
# Runs on Linux only (natively or inside Lima on macOS — see build-all.sh).
# No mmdebstrap / debootstrap dependency; skopeo + umoci do the heavy
# lifting and work on any Linux distro (Fedora, Arch, Alpine, Debian,
# Ubuntu). Part of the exp/erofs-vz-phase-a unification.
#
# EROFS output was dropped in the unification — gVisor's EROFS-sourced
# rootfs silently ignores dir= overlay (PR #12337: "EROFS mounts skip
# gofer-specific processing"), which blocked disk-backed write
# persistence on Linux. A directory-tree root.path doesn't have that
# constraint, so Linux now gets the same persistence model as macOS.
#
# Dependencies (install via the host's package manager):
#   skopeo umoci e2fsprogs curl
#
set -euo pipefail

# Refuse to be sourced. Sourcing from an interactive login shell makes $0
# expand to "-bash" (or similar), which then feeds `-b` into `dirname`.
if [ -n "${BASH_SOURCE:-}" ]; then
    if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
        echo "Error: build-rootfs.sh must be executed, not sourced." >&2
        return 1 2>/dev/null || exit 1
    fi
elif [ -n "${ZSH_EVAL_CONTEXT:-}" ] && [[ "$ZSH_EVAL_CONTEXT" == *:file* ]]; then
    echo "Error: build-rootfs.sh must be executed, not sourced." >&2
    return 1 2>/dev/null || exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

# Linux-only guard. chroot + mkfs.ext4/erofs are Linux-specific.
if [ "$(uname)" != "Linux" ]; then
    echo "Error: build-rootfs.sh runs on Linux only." >&2
    echo "On macOS, run ./build-all.sh which will shell into a Lima VM." >&2
    exit 1
fi

# --- Architecture selection -------------------------------------------------
HOST_ARCH=$(uname -m)
case "${ARCH:-$HOST_ARCH}" in
    aarch64|arm64) DEB_ARCH="arm64" ;;
    x86_64|amd64)  DEB_ARCH="amd64" ;;
    *) echo "Unsupported architecture: ${ARCH:-$HOST_ARCH}"; exit 1 ;;
esac

# --- Fixed-size ext4 image (matches the historical 2 GiB sparse) ------------
ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"

# --- Pinned tarballs installed by the customize-hook -----------------------
MISE_VERSION="${MISE_VERSION:-2026.4.19}"
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-882d10aa67fcb4fd8008c1e31ac3c6d0dc80dac2c4cb3c0d794ca9e0e5aece3d}"
MISE_SHA256_AMD64="${MISE_SHA256_AMD64:-17bf037c94dd5e790a9b56ab0a00f64a9ed910df1e0b67ad041d6336bafc44cb}"

GH_VERSION="${GH_VERSION:-2.89.0}"
GH_SHA256_ARM64="${GH_SHA256_ARM64:-9e64a623dfc242990aa5d9b3f507111149c4282f66b68eaad1dc79eeb13b9ce5}"
GH_SHA256_AMD64="${GH_SHA256_AMD64:-d0422caade520530e76c1c558da47daebaa8e1203d6b7ff10ad7d6faba3490d8}"

# --- Debian source image ----------------------------------------------------
# TODO: replace with `docker://debian:trixie@sha256:<digest>` once we pick a
# canonical digest to pin. Floating tag is no worse than mmdebstrap's
# "whatever deb.debian.org has today" — reproducibility has always been
# a future-work item — but pinning by digest is a strict improvement.
DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker://debian:trixie}"

# --- Helper: `command -v` that also probes /usr/sbin / /sbin --------------
# Debian packages these binaries into system sbin dirs that aren't on
# an interactive user's PATH by default; command_v alone false-negatives.
command_x() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 && return 0
    for dir in /usr/local/sbin /usr/sbin /sbin; do
        [ -x "$dir/$cmd" ] && return 0
    done
    return 1
}

# --- Dependency check -------------------------------------------------------
command_x skopeo || {
    echo "Error: skopeo not installed." >&2
    echo "  Debian/Ubuntu: sudo apt-get install skopeo" >&2
    echo "  Fedora:        sudo dnf install skopeo" >&2
    echo "  Arch:          sudo pacman -S skopeo" >&2
    echo "  Alpine:        apk add skopeo" >&2
    exit 1
}
command_x umoci || {
    echo "Error: umoci not installed." >&2
    echo "  Debian/Ubuntu: sudo apt-get install umoci" >&2
    echo "  Fedora:        sudo dnf install umoci" >&2
    echo "  Arch:          yay -S umoci (or pacman -S umoci if in repos)" >&2
    echo "  Alpine:        apk add umoci" >&2
    exit 1
}
command_x mkfs.ext4 || {
    echo "Error: mkfs.ext4 not installed (apt-get install e2fsprogs)." >&2
    exit 1
}
# mkfs.erofs no longer required — Linux runtime uses the directory
# tree output; macOS runtime uses ext4. Users who still have
# erofs-utils installed from earlier builds will find it unused.

# --- Outputs ----------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_EXT4="$OUTPUT_DIR/rootfs-base.ext4"
OUTPUT_TREE="$OUTPUT_DIR/rootfs-tree"

# Short-circuit only if BOTH artifacts are already present. A partial
# build can never self-heal otherwise.
if [ -f "$OUTPUT_EXT4" ] && [ -d "$OUTPUT_TREE" ]; then
    echo "Rootfs already present:"
    echo "  $OUTPUT_EXT4"
    echo "  $OUTPUT_TREE/"
    echo "Delete them to rebuild."
    exit 0
fi
if [ -f "$OUTPUT_EXT4" ] || [ -d "$OUTPUT_TREE" ]; then
    echo "Partial build detected. Rebuilding both."
    sudo rm -rf "$OUTPUT_EXT4" "$OUTPUT_TREE" 2>/dev/null \
        || rm -rf "$OUTPUT_EXT4" "$OUTPUT_TREE" 2>/dev/null \
        || true
fi

# --- Download cache ---------------------------------------------------------
DOWNLOAD_CACHE="$OUTPUT_DIR/.download-cache"
OCI_CACHE="$DOWNLOAD_CACHE/oci"
mkdir -p "$DOWNLOAD_CACHE" "$OCI_CACHE"

# Pre-fetch mise + gh tarballs, SHA256-verified. The customize-hook reads
# MISE_TARBALL / GH_TARBALL and installs the pre-fetched binaries without
# re-downloading, so rebuilds are fast.
fetch_pinned() {
    local label="$1" url="$2" sha="$3" dest="$4"
    if [ -f "$dest" ]; then
        if echo "${sha}  $dest" | sha256sum -c - >/dev/null 2>&1; then
            return 0
        fi
        echo "Cached $label has wrong SHA256, re-downloading: $dest" >&2
        rm -f "$dest"
    fi
    echo "--- Fetching $label ($url) ---"
    curl -fsSL "$url" -o "$dest"
    echo "${sha}  $dest" | sha256sum -c -
}

# mise uses "x64" for its amd64 asset, not Debian's "amd64". arm64 matches.
case "$DEB_ARCH" in
    amd64) MISE_ARCH=x64 ;;
    arm64) MISE_ARCH=arm64 ;;
esac
MISE_URL="https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz"
MISE_TARBALL="$DOWNLOAD_CACHE/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz"
case "$DEB_ARCH" in
    arm64) _MISE_SHA="$MISE_SHA256_ARM64" ;;
    amd64) _MISE_SHA="$MISE_SHA256_AMD64" ;;
esac
fetch_pinned "mise ${MISE_VERSION} ($DEB_ARCH)" "$MISE_URL" "$_MISE_SHA" "$MISE_TARBALL"
export MISE_TARBALL

GH_URL="https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz"
GH_TARBALL="$DOWNLOAD_CACHE/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz"
case "$DEB_ARCH" in
    arm64) _GH_SHA="$GH_SHA256_ARM64" ;;
    amd64) _GH_SHA="$GH_SHA256_AMD64" ;;
esac
fetch_pinned "gh ${GH_VERSION} ($DEB_ARCH)" "$GH_URL" "$_GH_SHA" "$GH_TARBALL"
export GH_TARBALL

MISE_SHA256="$_MISE_SHA"
GH_SHA256="$_GH_SHA"

# --- Pull the Debian OCI image ---------------------------------------------
OCI_REF="debian-trixie-${DEB_ARCH}"
echo "=== Pulling $DEBIAN_IMAGE ($DEB_ARCH) via skopeo ==="
skopeo --override-arch="$DEB_ARCH" --override-os=linux \
    copy "$DEBIAN_IMAGE" "oci:$OCI_CACHE:$OCI_REF"

# --- Unpack ----------------------------------------------------------------
# umoci layout: bundle/{rootfs,config.json,umoci.json}. We only want rootfs.
#
# --rootless=false (equivalent to omitting --rootless) leaves real ownership
# + xattrs — necessary so mkfs.ext4 -d later reads the tree back correctly.
# alpine-minimal has the same rationale.
WORK_DIR="$(mktemp -d -t safeyolo-rootfs.XXXXXX)"
cleanup_workdir() {
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        sudo -n rm -rf "$WORK_DIR" 2>/dev/null \
            || rm -rf "$WORK_DIR" 2>/dev/null \
            || true
    fi
}
trap cleanup_workdir EXIT

echo "=== Unpacking OCI image ==="
sudo umoci unpack --image "$OCI_CACHE:$OCI_REF" "$WORK_DIR/bundle"
ROOTFS="$WORK_DIR/rootfs"
sudo mv "$WORK_DIR/bundle/rootfs" "$ROOTFS"

# --- dpkg nodoc config, early --------------------------------------------
# Drop docs, man pages, info files, non-English locales for everything
# installed from now on (the apt-get install block below). Copyright
# files kept for Debian redistribution compliance. Previously lived in
# rootfs-essential-hook.sh under the old mmdebstrap pipeline.
sudo mkdir -p "$ROOTFS/etc/dpkg/dpkg.cfg.d"
sudo tee "$ROOTFS/etc/dpkg/dpkg.cfg.d/01-nodoc" >/dev/null <<'NODOC'
path-exclude /usr/share/doc/*
path-include /usr/share/doc/*/copyright
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
path-include /usr/share/locale/locale.alias
NODOC

# --- Chroot apt-get install ------------------------------------------------
# debian:trixie OCI is minimal. We need a baseline toolkit that the
# customize-hook (mise/gh/sshd/useradd/pip3) and the agent runtime
# (socat for proxy forwarding, openssh-server for `safeyolo agent shell`)
# depend on, plus the small developer toolkit agents benefit from.
#
# /etc/resolv.conf is copied in so apt-get update can resolve
# deb.debian.org. Cleaned up before packaging so the image doesn't
# ship the build host's DNS config.
sudo cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

echo "=== apt-get update (inside chroot) ==="
sudo chroot "$ROOTFS" /usr/bin/apt-get update

echo "=== Installing base packages ==="
sudo chroot "$ROOTFS" env DEBIAN_FRONTEND=noninteractive \
    /usr/bin/apt-get install -y --no-install-recommends \
    ca-certificates curl git jq build-essential gnupg \
    openssh-server iproute2 iputils-ping procps less xz-utils \
    libgomp1 libatomic1 \
    python3 python3-pip python3-venv \
    busybox-static socat file pkg-config \
    ripgrep fd-find unzip zip lsof strace tmux

# --- SafeYolo customize-hook (unchanged from mmdebstrap era) --------------
CUSTOMIZE_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
[ -r "$CUSTOMIZE_HOOK_SCRIPT" ] || {
    echo "Missing $CUSTOMIZE_HOOK_SCRIPT" >&2; exit 1
}

export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export GUEST_SRC_DIR="$SCRIPT_DIR"

echo "=== Running customize-hook ==="
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,MISE_TARBALL,GH_TARBALL,GUEST_SRC_DIR \
    bash "$CUSTOMIZE_HOOK_SCRIPT" "$ROOTFS"

# --- Strip DNS config before packing --------------------------------------
# Shipping /etc/resolv.conf with the build host's nameservers in the
# rootfs would leak DNS configuration into every agent. guest-init
# writes a default at boot; the rootfs should ship it empty/absent.
sudo rm -f "$ROOTFS/etc/resolv.conf"

# --- Emit: directory tree for Linux gVisor ------------------------------
# gVisor's OCI root.path wants a real filesystem directory, and
# dir= overlay needs a tree-based root (not rootfs.source=erofs).
# We tar-stream the populated rootfs over to $OUTPUT_TREE so file
# metadata (uid/gid/mode/xattrs) is preserved end-to-end; `cp -a`
# under sudo gets flustered by overlayfs-style special files in
# certain rootfs contents, the tar pipe is more reliable.
echo "=== Emitting directory tree ==="
sudo rm -rf "$OUTPUT_TREE"
sudo mkdir -p "$OUTPUT_TREE"
sudo tar --xattrs --xattrs-include='*' --acls -C "$ROOTFS" -cf - . \
    | sudo tar --xattrs --xattrs-include='*' --acls -C "$OUTPUT_TREE" -xf -
echo "tree:  $OUTPUT_TREE/ ($(sudo du -sh "$OUTPUT_TREE" | cut -f1))"

# --- Emit: ext4 for macOS VZ ---------------------------------------------
echo "=== Creating ${ROOTFS_SIZE_MB} MiB sparse ext4 image ==="
truncate -s "${ROOTFS_SIZE_MB}M" "$OUTPUT_EXT4"
sudo mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$ROOTFS" "$OUTPUT_EXT4"
sudo chown "$(id -u):$(id -g)" "$OUTPUT_EXT4"
echo "ext4:  $OUTPUT_EXT4 ($(du -sh "$OUTPUT_EXT4" | cut -f1))"

# --- Emit: package cache paths (Linux bridge) ----------------------------
# On Linux gVisor the root overlay is memory-backed (dir= is silently
# ignored, see cli/src/safeyolo/platform/linux.py), so runtime writes to
# /var/cache/apt etc. vanish on agent stop. SafeYolo bind-mounts a
# per-agent host dir onto each listed path so `apt install` hits a warm
# cache after restart. Macro contract: one absolute in-rootfs path per
# line; see contrib/ROOTFS_SCRIPT_GUIDE.md.
cat > "$OUTPUT_DIR/cache-paths.txt" <<'CACHE_PATHS'
/var/cache/apt
/var/lib/apt/lists
CACHE_PATHS
echo "cache-paths: $OUTPUT_DIR/cache-paths.txt"

echo "=== Rootfs build complete ==="
