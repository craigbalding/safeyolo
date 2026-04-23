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

# Pinned mise version. mise names its amd64 asset "linux-x64" (not
# "linux-amd64") — the hook script maps DEB_ARCH→MISE_ARCH when building
# the download URL. Bump policy: set to the latest published `mise` release
# at build-script-edit time and refresh both SHA256 pins.
MISE_VERSION="${MISE_VERSION:-2026.4.19}"
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-882d10aa67fcb4fd8008c1e31ac3c6d0dc80dac2c4cb3c0d794ca9e0e5aece3d}"
MISE_SHA256_AMD64="${MISE_SHA256_AMD64:-17bf037c94dd5e790a9b56ab0a00f64a9ed910df1e0b67ad041d6336bafc44cb}"

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
OUTPUT_EROFS="$OUTPUT_DIR/rootfs-base.erofs"

# Short-circuit only if BOTH artifacts are already present. The historical
# version exited 0 when just rootfs-base.ext4 existed, which meant a partial
# build (ext4 succeeded, EROFS skipped because erofs-utils was missing) could
# never self-heal without the user manually deleting the stale ext4 first.
if [ -f "$OUTPUT_EXT4" ] && [ -f "$OUTPUT_EROFS" ]; then
    echo "Rootfs already present:"
    echo "  $OUTPUT_EXT4"
    echo "  $OUTPUT_EROFS"
    echo "Delete them to rebuild."
    exit 0
fi
# If one is present but the other isn't, wipe the stale one so the rebuild
# below produces a consistent pair. Users who deliberately want only one
# target can pass -e / -E to this script (not currently supported).
if [ -f "$OUTPUT_EXT4" ] && [ ! -f "$OUTPUT_EROFS" ]; then
    echo "Partial build detected ($OUTPUT_EXT4 present, EROFS missing). Rebuilding."
    sudo rm -f "$OUTPUT_EXT4" || rm -f "$OUTPUT_EXT4"
fi
if [ -f "$OUTPUT_EROFS" ] && [ ! -f "$OUTPUT_EXT4" ]; then
    echo "Partial build detected ($OUTPUT_EROFS present, ext4 missing). Rebuilding."
    sudo rm -f "$OUTPUT_EROFS" || rm -f "$OUTPUT_EROFS"
fi

command -v mmdebstrap >/dev/null || {
    echo "Error: mmdebstrap not installed." >&2
    echo "  Debian/Ubuntu: sudo apt-get install mmdebstrap e2fsprogs erofs-utils" >&2
    exit 1
}
command -v mkfs.ext4 >/dev/null || {
    echo "Error: mkfs.ext4 not installed (apt-get install e2fsprogs)." >&2
    exit 1
}
# EROFS is the rootfs format gVisor mounts on Linux (see
# cli/src/safeyolo/platform/linux.py: "dev.gvisor.spec.rootfs.type=erofs").
# Skipping it would leave the agent-run path broken on Linux while the build
# silently claims success, so treat missing erofs-utils as a hard error.
command -v mkfs.erofs >/dev/null || {
    echo "Error: mkfs.erofs not installed." >&2
    echo "  Debian/Ubuntu: sudo apt-get install erofs-utils" >&2
    echo "  (Required — gVisor mounts the rootfs via EROFS; without it" >&2
    echo "   'safeyolo agent add' will fail later with 'EROFS rootfs image" >&2
    echo "   not found'.)" >&2
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

# ---------------------------------------------------------------------------
# Persistent download cache — avoids re-fetching pinned binaries + Debian
# .debs on rebuild. Lives under out/ so `rm -rf out/*` wipes it (explicit
# opt-out); lives outside the ext4/EROFS output files so it's never bundled
# into the rootfs.
#
# Layout:
#   out/.download-cache/mise-<ver>-linux-<arch>.tar.gz
#   out/.download-cache/gh-<ver>-linux-<arch>.tar.gz
#   out/.download-cache/apt-archives/            (mmdebstrap --aptopt target)
# ---------------------------------------------------------------------------
DOWNLOAD_CACHE="$OUTPUT_DIR/.download-cache"
mkdir -p "$DOWNLOAD_CACHE"

# mise asset: amd64 is named "linux-x64" upstream, arm64 is "linux-arm64".
case "$DEB_ARCH" in
    amd64) MISE_ARCH=x64 ;;
    arm64) MISE_ARCH=arm64 ;;
    *) echo "Unsupported DEB_ARCH for mise cache: $DEB_ARCH" >&2; exit 1 ;;
esac
MISE_TARBALL="$DOWNLOAD_CACHE/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz"
GH_TARBALL="$DOWNLOAD_CACHE/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz"

# Resolve the pinned SHA256s once so we can verify the cached artifacts
# before handing them to the customize-hook.
_MISE_VAR="MISE_SHA256_$(echo "$DEB_ARCH" | tr a-z A-Z)"
_GH_VAR="GH_SHA256_$(echo "$DEB_ARCH" | tr a-z A-Z)"
_MISE_SHA="${!_MISE_VAR:-}"
_GH_SHA="${!_GH_VAR:-}"

fetch_pinned() {
    # $1=url  $2=cache-path  $3=expected-sha256 ("" allowed, with a warning)
    local url="$1" dest="$2" want="$3"
    if [ -n "$want" ] && [ -f "$dest" ] \
       && echo "${want}  ${dest}" | sha256sum -c - >/dev/null 2>&1; then
        return 0
    fi
    echo "--- Fetching $(basename "$dest") ---"
    curl -fsSL "$url" -o "$dest.tmp"
    if [ -n "$want" ]; then
        echo "${want}  ${dest}.tmp" | sha256sum -c -
    else
        echo "WARNING: no pinned SHA256 for $(basename "$dest") — proceeding unverified" >&2
    fi
    mv "$dest.tmp" "$dest"
}

fetch_pinned \
    "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz" \
    "$MISE_TARBALL" "$_MISE_SHA"
fetch_pinned \
    "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz" \
    "$GH_TARBALL" "$_GH_SHA"

# Apt archive cache — tell mmdebstrap to keep downloaded .deb files in a
# shared directory we persist between rebuilds. Without this, every
# rebuild re-pulls the full Debian package set (~200 MB) from deb.debian.org.
APT_ARCHIVE_CACHE="$DOWNLOAD_CACHE/apt-archives"
mkdir -p "$APT_ARCHIVE_CACHE"

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

# SHA256s were resolved above (used by fetch_pinned) — re-export under the
# legacy names the customize-hook still reads, for defence in depth if the
# pre-staged tarball is somehow replaced between fetch and consumption.
MISE_SHA256="$_MISE_SHA"
GH_SHA256="$_GH_SHA"

CUSTOMIZE_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
ESSENTIAL_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-essential-hook.sh"
[ -r "$CUSTOMIZE_HOOK_SCRIPT" ] || { echo "Missing $CUSTOMIZE_HOOK_SCRIPT" >&2; exit 1; }
[ -x "$ESSENTIAL_HOOK_SCRIPT" ] || { echo "Missing or non-executable $ESSENTIAL_HOOK_SCRIPT" >&2; exit 1; }

# Export for the customize-hook process. mmdebstrap's hooks inherit the
# invoking process's env, so we just export and the hook sees them.
# MISE_TARBALL / GH_TARBALL: hand the pre-fetched + SHA256-verified tarballs
# to the hook so it doesn't re-download on every rebuild.
export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export MISE_TARBALL GH_TARBALL
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
# Apt archive cache integration:
#   --setup-hook: seed rootfs /var/cache/apt/archives/ with previously
#     downloaded .debs so apt reuses them instead of re-fetching from
#     deb.debian.org. First run does a full download (cache empty); every
#     subsequent run reuses what's there.
#   Extra customize-hook (runs before rootfs-customize-hook.sh's `apt-get
#     clean`): copies freshly fetched .debs back to $APT_ARCHIVE_CACHE so
#     the next build benefits from them.
#
# These run from mmdebstrap's process, which is under sudo on the host, so
# no extra privilege is needed to read/write $APT_ARCHIVE_CACHE.
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,MISE_TARBALL,GH_TARBALL,GUEST_SRC_DIR,APT_ARCHIVE_CACHE \
    mmdebstrap \
        --mode=root \
        --variant=minbase \
        --arch="$DEB_ARCH" \
        --keyring="$DAK_GPG" \
        --include=ca-certificates,curl,git,jq,build-essential,gnupg,openssh-server,iproute2,iputils-ping,procps,less,xz-utils,libgomp1,libatomic1,python3,python3-pip,python3-venv,busybox-static,socat,file,pkg-config,ripgrep,fd-find,unzip,zip,lsof,strace,tmux \
        --setup-hook='mkdir -p "$1/var/cache/apt/archives"; if compgen -G "'"$APT_ARCHIVE_CACHE"'/*.deb" > /dev/null; then cp -n "'"$APT_ARCHIVE_CACHE"'"/*.deb "$1/var/cache/apt/archives/" 2>/dev/null || true; fi' \
        --customize-hook='if compgen -G "$1/var/cache/apt/archives/*.deb" > /dev/null; then cp -n "$1/var/cache/apt/archives/"*.deb "'"$APT_ARCHIVE_CACHE"'/" 2>/dev/null || true; fi' \
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
# EROFS image — the rootfs format gVisor mounts on Linux. erofs-utils
# availability is verified above; this step must succeed. Fail-hard rather
# than leaving behind a bare ext4 the platform layer cannot consume.
echo "--- Creating EROFS image ---"
sudo mkfs.erofs -E noinline_data "$OUTPUT_EROFS" "$WORK_DIR"
sudo chown "$(id -u):$(id -g)" "$OUTPUT_EROFS"
# mkfs.erofs writes 644 by default -- this explicit chmod is defensive
# for rootless userns. On macOS Lima virtiofs it fails with EPERM
# (the mount layer rejects chmod even when ownership matches), and
# set -e kills the build before the ext4 step. The file already has
# the right mode from mkfs, so swallow the error.
chmod 644 "$OUTPUT_EROFS" 2>/dev/null || true
echo "EROFS: $OUTPUT_EROFS ($(du -sh "$OUTPUT_EROFS" | cut -f1))"

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
