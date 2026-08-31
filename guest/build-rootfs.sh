#!/bin/bash
#
# Build the SafeYolo base rootfs from the official Debian trixie OCI image.
#
# Pulls docker://debian:trixie via skopeo, unpacks with umoci, apt-installs
# our baseline toolkit inside a chroot, runs rootfs-customize-hook.sh to
# stamp SafeYolo-specific bits (mise, gh, init stub, sshd config, agent
# user, package-manager proxy/cache support), then writes two artifacts:
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
ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"  # DOC: guest/README.md

# --- Pinned tarballs installed by the customize-hook -----------------------
MISE_VERSION="${MISE_VERSION:-2026.8.8}"  # DOC: guest/README.md
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-6e6e96d319fe274996db5aed691f5398552865e641dc4b6fb6b01d73f4853a17}"
MISE_SHA256_AMD64="${MISE_SHA256_AMD64:-58edfbdba6d4255b6536a61daeaf3b21f7a059430c789e948c8494ba32d59e1f}"

GH_VERSION="${GH_VERSION:-2.98.0}"  # DOC: guest/README.md
GH_SHA256_ARM64="${GH_SHA256_ARM64:-cf689084f3a3618f7eae4a2420d335d74626d65f5e594b9828d125d69f800d86}"
GH_SHA256_AMD64="${GH_SHA256_AMD64:-3b8ac6b30336802fc1a858d7c084e11cdf24ac1a761ca90b68022d7d729208de}"

# --- Debian source image ----------------------------------------------------
# TODO: replace with `docker://debian:trixie@sha256:<digest>` once we pick a
# canonical digest to pin. Floating tag is no worse than mmdebstrap's
# "whatever deb.debian.org has today" — reproducibility has always been
# a future-work item — but pinning by digest is a strict improvement.
DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker://debian:trixie}"  # DOC: guest/README.md, README.md

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
    echo "  Debian/Ubuntu:                sudo apt-get install umoci" >&2
    echo "  Fedora / Alpine / Arch:       run 'safeyolo bootstrap' — it installs" >&2
    echo "                                a pinned upstream umoci to ~/.safeyolo/bin/" >&2
    echo "                                (umoci is not in default dnf/apk/pacman repos)" >&2
    exit 1
}
# Resolve umoci to an absolute path once. sudo resets PATH to secure_path
# (typically /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin), so
# `sudo umoci` fails when umoci lives in ~/.safeyolo/bin/ or any other
# non-secure_path location. Passing the absolute path to sudo bypasses
# secure_path resolution.
UMOCI=$(command -v umoci)
if [ -z "$UMOCI" ]; then
    # command_x found umoci under /usr/sbin or /sbin — probe those.
    for dir in /usr/local/sbin /usr/sbin /sbin; do
        [ -x "$dir/umoci" ] && { UMOCI="$dir/umoci"; break; }
    done
fi
[ -n "$UMOCI" ] || { echo "Error: umoci passed command_x but not resolvable to an absolute path" >&2; exit 1; }
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
if [ -f "$OUTPUT_EXT4" ] && [ -d "$OUTPUT_TREE" ]; then  # DOC: guest/README.md
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
sudo "$UMOCI" unpack --image "$OCI_CACHE:$OCI_REF" "$WORK_DIR/bundle"
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
# A conventional host resolver is useful when the chroot connects directly.
# A SafeYolo guest deliberately has no /etc/resolv.conf: its build traffic
# already uses the proxy on loopback, which resolves upstream names. Support
# both hosts and never synthesize or retain host DNS state in the artifact.
sudo rm -f "$ROOTFS/etc/resolv.conf"
if [ -r /etc/resolv.conf ]; then
    sudo install -D -m 0644 /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
    echo "Using the build host resolver inside the temporary chroot."
else
    echo "No build host resolver found; relying on the configured HTTP proxy."
fi

# SafeYolo exports an absolute SSL_CERT_FILE that points at the outer proxy's
# CA. sudo preserves that variable, but the freshly unpacked rootfs does not
# yet contain the file. Stage it at the same absolute path before the first
# chroot command so apt/curl keep TLS verification enabled. Restore a file
# supplied by the base image, or remove the staged file, before packaging.
BUILD_SSL_CERT_DEST=""
BUILD_SSL_CERT_BACKUP=""
if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
    case "$SSL_CERT_FILE" in
        /*) ;;
        *)
            echo "Error: SSL_CERT_FILE must be absolute: $SSL_CERT_FILE" >&2
            exit 1
            ;;
    esac
    BUILD_SSL_CERT_DEST=$(realpath -m -- "$ROOTFS$SSL_CERT_FILE")
    case "$BUILD_SSL_CERT_DEST" in
        "$ROOTFS"/*) ;;
        *)
            echo "Error: SSL_CERT_FILE escapes the temporary rootfs: $SSL_CERT_FILE" >&2
            exit 1
            ;;
    esac
    if [ -e "$BUILD_SSL_CERT_DEST" ] || [ -L "$BUILD_SSL_CERT_DEST" ]; then
        BUILD_SSL_CERT_BACKUP="$WORK_DIR/original-ssl-cert"
        sudo cp -a -- "$BUILD_SSL_CERT_DEST" "$BUILD_SSL_CERT_BACKUP"
    fi
    sudo install -D -m 0644 -- "$SSL_CERT_FILE" "$BUILD_SSL_CERT_DEST"
    echo "Staged the build host TLS CA at $SSL_CERT_FILE inside the temporary chroot."
fi

echo "=== apt-get update (inside chroot) ==="
sudo chroot "$ROOTFS" /usr/bin/apt-get update

echo "=== Installing base packages ==="
# build-essential is back in the default base. Rationale: under rootless
# gVisor, the rootfs overlay is memory-backed (dir= is silently ignored),
# so runtime `apt-get install` lands in the memory upper and vanishes on
# agent stop. An on-demand install of build-essential would cost ~20–30s
# of dpkg unpacking on every agent start that needed a compiler. Since
# the rootfs tree is shared across ALL agents (/share/rootfs-tree,
# mounted read-only via the overlay lower), the ~250 MB cost is paid
# once globally, not per-agent. Keeping the compiler in the shared base
# is the better tradeoff.
#
# Agents that need OTHER packages at runtime can still install them as
# namespace-root without host sudo. The SafeYolo sudo shim uses the sandbox's
# CAP_SETUID/CAP_SETGID path; /etc/apt/apt.conf.d/99safeyolo-proxy plus the
# /var/cache/apt + /var/lib/apt/lists cache binds keep traffic mediated and
# downloads warm. The unpacked install does not survive restart.
sudo chroot "$ROOTFS" env DEBIAN_FRONTEND=noninteractive \
    /usr/bin/apt-get install -y --no-install-recommends \
    ca-certificates curl git jq build-essential gnupg \
    openssh-server iproute2 iputils-ping procps util-linux less xz-utils \
    libgomp1 libatomic1 \
    python3 python3-pip python3-venv \
    busybox-static socat file pkg-config \
    ripgrep fd-find unzip zip lsof strace tmux \
    sudo

# --- SafeYolo customize-hook (unchanged from mmdebstrap era) --------------
CUSTOMIZE_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
[ -r "$CUSTOMIZE_HOOK_SCRIPT" ] || {
    echo "Missing $CUSTOMIZE_HOOK_SCRIPT" >&2; exit 1
}

export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export SAFEYOLO_GUEST_SRC_DIR="$SCRIPT_DIR"

echo "=== Running customize-hook ==="
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,MISE_TARBALL,GH_TARBALL,SAFEYOLO_GUEST_SRC_DIR \
    bash "$CUSTOMIZE_HOOK_SCRIPT" "$ROOTFS"

# --- Strip temporary host network state before packing ---------------------
# Shipping /etc/resolv.conf or the outer SafeYolo CA would leak host-specific
# network configuration into every agent. guest-init writes a resolver at
# boot, and the runtime bind-mounts the correct per-instance proxy CA.
sudo rm -f "$ROOTFS/etc/resolv.conf"
if [ -n "$BUILD_SSL_CERT_DEST" ]; then
    sudo rm -f -- "$BUILD_SSL_CERT_DEST"
    if [ -n "$BUILD_SSL_CERT_BACKUP" ]; then
        sudo cp -a -- "$BUILD_SSL_CERT_BACKUP" "$BUILD_SSL_CERT_DEST"
    elif [ "$SSL_CERT_FILE" = "/usr/local/share/ca-certificates/safeyolo.crt" ]; then
        # The runtime bind destination is part of the rootfs contract. Keep
        # the target, but not the outer instance's certificate bytes.
        sudo install -D -m 0644 /dev/null "$BUILD_SSL_CERT_DEST"
    fi
fi

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
sudo rsync -aHAX --numeric-ids "$ROOTFS/" "$OUTPUT_TREE/"

# Rootless gVisor userns semantics: container uid 0 is mapped to host
# uid 100000 (see linux.py::_start_userns), and CAP_DAC_OVERRIDE inside
# the sandbox only covers files owned by uids in the subordinate range
# (100000–101000). If we ship the tree owned by host uid 0, those files
# show as `nobody` inside the sandbox and sandbox-root can't modify
# them — apt-get install dies on dpkg lock EACCES. Shipping the tree
# pre-owned by 100000 makes it writable by sandbox-root out of the box.
# No-op / harmless for macOS VZ (ext4 image is rebuilt from the tree
# below; file ownership in the image is preserved by mkfs.ext4 -d, but
# VZ runs a full Linux VM with its own real root, so ownership doesn't
# matter there).
echo "=== Chowning tree to 100000:100000 (rootless subuid-root) ==="
sudo chown -R 100000:100000 "$OUTPUT_TREE"  # DOC: guest/README.md, SECURITY.md
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
