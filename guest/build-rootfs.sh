#!/bin/bash
#
# Build the SafeYolo base rootfs from the official Debian trixie OCI image.
#
# Pulls a digest-pinned Debian trixie image via skopeo, unpacks with umoci, apt-installs
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
#   skopeo umoci e2fsprogs curl jq rsync
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

# Resolve once for this build. Explicit frozen inputs remain usable offline.
export SAFEYOLO_GUEST_SRC_DIR="$SCRIPT_DIR"
source "$SCRIPT_DIR/input-functions.sh"
if [[ -z ${GUEST_INPUTS:-} ]]; then
    mkdir -p "$OUTPUT_DIR"
    GUEST_INPUTS=$(mktemp "$OUTPUT_DIR/inputs.XXXXXX.json")
    "${SAFEYOLO_BUILD_PYTHON:-python3}" "$SCRIPT_DIR/resolve_inputs.py" resolve \
        --tools mise gh --base --output "$GUEST_INPUTS"
    export GUEST_INPUTS
fi
guest_inputs "$DEB_ARCH"

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
command_x jq || { echo "Error: jq not installed (required for OCI build provenance)." >&2; exit 1; }
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

# Existing output is never freshness evidence. Replace only these build outputs.
sudo -n rm -rf -- "$OUTPUT_EXT4" "$OUTPUT_TREE"
rm -f -- "$OUTPUT_DIR/build-base.txt"

# --- Download cache ---------------------------------------------------------
DOWNLOAD_CACHE="$OUTPUT_DIR/.download-cache"
OCI_CACHE="$DOWNLOAD_CACHE/oci"
mkdir -p "$DOWNLOAD_CACHE" "$OCI_CACHE"

# Reuse downloads only after matching the frozen official identities.
MISE_TARBALL="$DOWNLOAD_CACHE/mise-$MISE_VERSION-$DEB_ARCH.tar.gz"
GH_TARBALL="$DOWNLOAD_CACHE/gh-$GH_VERSION-$DEB_ARCH.tar.gz"
guest_download "$DEB_ARCH" mise "$MISE_TARBALL"
guest_download "$DEB_ARCH" gh "$GH_TARBALL"
export MISE_TARBALL GH_TARBALL

# --- Pull the Debian OCI image ---------------------------------------------
rm -f "$OUTPUT_DIR/build-base.txt"
OCI_REF="debian-trixie-${DEB_ARCH}"
echo "=== Pulling $DEBIAN_IMAGE ($DEB_ARCH) via skopeo ==="
copy_options=()
if [[ "$DEBIAN_IMAGE" == docker://*@sha256:* ]]; then
    copy_options+=(--preserve-digests)
    skopeo --override-arch="$DEB_ARCH" --override-os=linux inspect --config "$DEBIAN_IMAGE" | jq -e --arg arch "$DEB_ARCH" \
        '.os == "linux" and .architecture == $arch' >/dev/null
fi
skopeo --override-arch="$DEB_ARCH" --override-os=linux \
    copy "${copy_options[@]}" "$DEBIAN_IMAGE" "oci:$OCI_CACHE:$OCI_REF"
# Record the manifest actually unpacked. Keep contributor transport overrides;
# only registry inputs can supply the qualified build-base for OCI publication.
BUILD_BASE=""
if [[ "$DEBIAN_IMAGE" == docker://*@sha256:* ]]; then
    base_name=$(skopeo inspect --no-tags --format '{{.Name}}' "$DEBIAN_IMAGE")
    base_digest=$(jq -er --arg ref "$OCI_REF" \
        '.manifests[] | select(.annotations["org.opencontainers.image.ref.name"] == $ref) | .digest' \
        "$OCI_CACHE/index.json")
    BUILD_BASE="$base_name@$base_digest"
fi

# --- Unpack ----------------------------------------------------------------
# umoci layout: bundle/{rootfs,config.json,umoci.json}. We only want rootfs.
#
# --rootless=false (equivalent to omitting --rootless) leaves real ownership
# + xattrs — necessary so mkfs.ext4 -d later reads the tree back correctly.
# alpine-minimal has the same rationale.
WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/safeyolo-rootfs.XXXXXX")"
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

# Package installation must not start cron/at in the builder's namespace.
# Restore the base image's policy after installation; runtime service control
# remains available to guest administrators.
if sudo test -e "$ROOTFS/usr/sbin/policy-rc.d"; then
    sudo cp -a "$ROOTFS/usr/sbin/policy-rc.d" "$WORK_DIR/policy-rc.d"
fi
sudo mkdir -p "$ROOTFS/usr/sbin"
sudo rm -f "$ROOTFS/usr/sbin/policy-rc.d"
sudo tee "$ROOTFS/usr/sbin/policy-rc.d" >/dev/null <<'SERVICE_POLICY'
#!/bin/sh
exit 101
SERVICE_POLICY
sudo chmod 0755 "$ROOTFS/usr/sbin/policy-rc.d"

# --- Chroot apt-get install ------------------------------------------------
# debian:trixie OCI is minimal. Keep the packages that the
# customize-hook (mise/gh/sshd/useradd) and the agent runtime
# (socat for proxy forwarding, openssh-server for `safeyolo agent shell`)
# depend on. Language runtimes and development tools are installed on demand.
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

# Debian OCI images can lack ca-certificates until the first package install.
# Stage a verified builder CA for HTTPS APT without replacing the guest bundle
# that ca-certificates will generate. It never enters the packaged artifact.
BUILD_APT_CA=$("${SAFEYOLO_BUILD_PYTHON:-python3}" -c 'import ssl; print(ssl.get_default_verify_paths().cafile or "")')
[[ -r "$BUILD_APT_CA" ]] || { echo 'No readable builder TLS CA bundle for APT.' >&2; exit 1; }
sudo install -D -m 0644 "$BUILD_APT_CA" "$ROOTFS/tmp/safeyolo-build-ca.pem"
APT_TLS_OPTIONS=(-o Acquire::https::CaInfo=/tmp/safeyolo-build-ca.pem)

echo "=== apt-get update (inside chroot) ==="
# Restrict the default build to the intended signed Trixie suites.
sudo rm -f "$ROOTFS/etc/apt/sources.list"
sudo rm -rf "$ROOTFS/etc/apt/sources.list.d"
sudo mkdir -p "$ROOTFS/etc/apt/sources.list.d"
sudo tee "$ROOTFS/etc/apt/sources.list.d/debian.sources" >/dev/null <<'APT_SOURCES'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://deb.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
APT_SOURCES
sudo chroot "$ROOTFS" /usr/bin/apt-get -o APT::Update::Error-Mode=any update "${APT_TLS_OPTIONS[@]}"
sudo chroot "$ROOTFS" env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y dist-upgrade "${APT_TLS_OPTIONS[@]}"
remaining=$(sudo chroot "$ROOTFS" /usr/bin/apt list --upgradable 2>/dev/null)
if [[ "$remaining" == *$'\n'* ]]; then
    echo "Inherited Trixie packages remain upgradable: $remaining" >&2
    exit 1
fi

echo "=== Installing base packages ==="
# Git stays available for gh repository commands and agent edits/checks.
# SSH client and server remain available on both gVisor and VZ.
# curl and xz support tool downloads; BusyBox supplies nc/hexdump and poweroff.
# Agents that need development packages at runtime can install them as
# namespace-root without host sudo. The SafeYolo sudo shim uses the sandbox's
# CAP_SETUID/CAP_SETGID path; /etc/apt/apt.conf.d/99safeyolo-proxy plus the
# /var/cache/apt + /var/lib/apt/lists cache binds keep traffic mediated and
# downloads warm. Default Linux directory overlays retain installed files;
# --ephemeral guests must unpack packages again after a stop.
sudo chroot "$ROOTFS" env DEBIAN_FRONTEND=noninteractive \
    /usr/bin/apt-get install -y --no-install-recommends "${APT_TLS_OPTIONS[@]}" \
    ca-certificates curl git openssh-client openssh-server \
    iproute2 procps util-linux xz-utils busybox-static socat fd-find sudo cron at sensible-utils

# Capture the verified build repositories before the hook clears APT lists
# and installs the separate runtime proxy settings.
mkdir -p "$OUTPUT_DIR/provenance"
sudo cat "$ROOTFS/etc/apt/sources.list.d/debian.sources" > "$OUTPUT_DIR/provenance/apt-sources-$DEB_ARCH.txt"
# apt has verified the InRelease signatures through Signed-By. Retain the exact
# verified metadata, package-index hashes and archive-keyring identity.
sudo bash -c 'cd "$1"; tar -cf - etc/apt usr/share/keyrings/debian-archive-keyring.gpg var/lib/apt/lists/*_InRelease' \
    -- "$ROOTFS" > "$OUTPUT_DIR/provenance/apt-$DEB_ARCH.tar"
sudo bash -c 'cd "$1"; sha256sum var/lib/apt/lists/*_InRelease var/lib/apt/lists/*Packages*' \
    -- "$ROOTFS" > "$OUTPUT_DIR/provenance/apt-indexes-$DEB_ARCH.sha256"

# --- SafeYolo customize hook ---------------------------------------------
CUSTOMIZE_HOOK_SCRIPT="$SCRIPT_DIR/rootfs-customize-hook.sh"
[ -r "$CUSTOMIZE_HOOK_SCRIPT" ] || {
    echo "Missing $CUSTOMIZE_HOOK_SCRIPT" >&2; exit 1
}

export DEB_ARCH MISE_VERSION MISE_SHA256 GH_VERSION GH_SHA256
export SAFEYOLO_GUEST_SRC_DIR="$SCRIPT_DIR"

echo "=== Running customize-hook ==="
sudo --preserve-env=DEB_ARCH,MISE_VERSION,MISE_SHA256,GH_VERSION,GH_SHA256,MISE_TARBALL,GH_TARBALL,SAFEYOLO_GUEST_SRC_DIR \
    bash "$CUSTOMIZE_HOOK_SCRIPT" "$ROOTFS"

sudo rm -f "$ROOTFS/usr/sbin/policy-rc.d"
if sudo test -e "$WORK_DIR/policy-rc.d"; then
    sudo cp -a "$WORK_DIR/policy-rc.d" "$ROOTFS/usr/sbin/policy-rc.d"
fi

# Keep signed repository metadata and final inventory before the chroot is removed.
mkdir -p "$OUTPUT_DIR/provenance"
cp -- "$GUEST_INPUTS" "$OUTPUT_DIR/provenance/inputs.json"
actual_mise=$(sudo chroot "$ROOTFS" /usr/local/bin/mise --version)
actual_gh=$(sudo chroot "$ROOTFS" /usr/local/bin/gh --version)
[[ "$actual_mise" == "$MISE_VERSION "* || "$actual_mise" == "mise $MISE_VERSION "* ]] || {
    echo 'Installed mise version/interface differs from the frozen release.' >&2; exit 1;
}
[[ "$actual_gh" == "gh version $GH_VERSION "* ]] || {
    echo 'Installed gh version/interface differs from the frozen release.' >&2; exit 1;
}
printf '%s\n' "$actual_mise" > "$OUTPUT_DIR/provenance/mise-version-$DEB_ARCH.txt"
printf '%s\n' "$actual_gh" > "$OUTPUT_DIR/provenance/gh-version-$DEB_ARCH.txt"
sudo chroot "$ROOTFS" /usr/bin/dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$OUTPUT_DIR/provenance/dpkg-$DEB_ARCH.tsv"
{ date -u +%Y-%m-%dT%H:%M:%SZ; skopeo --version; "$UMOCI" --version; \
  rsync --version; mkfs.ext4 -V 2>&1; } > "$OUTPUT_DIR/provenance/builder-$DEB_ARCH.txt"

# --- Strip temporary host network state before packing ---------------------
# Shipping /etc/resolv.conf or the outer SafeYolo CA would leak host-specific
# network configuration into every agent. guest-init writes a resolver at
# boot, and the runtime bind-mounts the correct per-instance proxy CA.
sudo rm -f "$ROOTFS/etc/resolv.conf" "$ROOTFS/tmp/safeyolo-build-ca.pem"
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
# SafeYolo bind-mounts a per-agent host directory onto each listed path so
# package downloads remain available even when an ephemeral root overlay
# is discarded. Contract: one absolute in-rootfs path per
# line; see contrib/ROOTFS_SCRIPT_GUIDE.md.
cat > "$OUTPUT_DIR/cache-paths.txt" <<'CACHE_PATHS'
/var/cache/apt
/var/lib/apt/lists
CACHE_PATHS
echo "cache-paths: $OUTPUT_DIR/cache-paths.txt"
if [[ -n "$BUILD_BASE" ]]; then
    printf '%s\n' "$BUILD_BASE" > "$OUTPUT_DIR/build-base.txt"
    echo "build-base: $BUILD_BASE"
fi

echo "=== Rootfs build complete ==="
