#!/bin/bash
#
# mmdebstrap customize-hook -- runs inside the fresh Debian rootfs after
# package installation, adds SafeYolo-specific tooling and configuration.
#
# Invoked by guest/build-rootfs.sh via --customize-hook=<this-script>.
# $1 is the path to the unpacked rootfs.
#
# Environment variables consumed (set by build-rootfs.sh):
#   DEB_ARCH         (arm64 | amd64)
#   MISE_VERSION
#   MISE_SHA256
#   MISE_TARBALL     (optional) path to pre-fetched mise tarball
#   GH_VERSION
#   GH_SHA256
#   GH_TARBALL       (optional) path to pre-fetched gh tarball
#   GUEST_SRC_DIR    absolute path to the repo's guest/ directory
#                    (where rootfs/safeyolo-guest-init lives)
#
# Running this script directly (for debugging) is supported -- just set the
# vars above and pass the rootfs path as $1. MISE_TARBALL/GH_TARBALL are
# optional; if unset, the hook falls back to a direct download.
#
set -euo pipefail

# Uncomment for verbose tracing when debugging hook failures:
# set -x

ROOTFS="$1"

# Required vars -- fail early with a clear message rather than getting a
# weird error later.
: "${DEB_ARCH:?DEB_ARCH not set}"
: "${MISE_VERSION:?MISE_VERSION not set}"
: "${GH_VERSION:?GH_VERSION not set}"
: "${GUEST_SRC_DIR:?GUEST_SRC_DIR not set}"

[ -d "$ROOTFS" ] || { echo "Rootfs not found: $ROOTFS" >&2; exit 1; }
[ -r "$GUEST_SRC_DIR/rootfs/safeyolo-guest-init" ] || {
    echo "Missing $GUEST_SRC_DIR/rootfs/safeyolo-guest-init" >&2
    exit 1
}

echo "=== Customizing rootfs at $ROOTFS ==="

# ---------------------------------------------------------------------------
# mise
# ---------------------------------------------------------------------------
echo "--- Installing mise ${MISE_VERSION} ---"
# mise uses "x64" for its amd64 asset, not Debian's "amd64". arm64 matches.
case "$DEB_ARCH" in
    amd64) MISE_ARCH=x64 ;;
    arm64) MISE_ARCH=arm64 ;;
    *) echo "Unsupported DEB_ARCH for mise URL: $DEB_ARCH" >&2; exit 1 ;;
esac
# Prefer the tarball that build-rootfs.sh pre-fetched + SHA256-verified
# into $OUTPUT_DIR/.download-cache/ (MISE_TARBALL). Fall back to a direct
# download so the hook still works when invoked standalone for debugging.
if [ -n "${MISE_TARBALL:-}" ] && [ -f "$MISE_TARBALL" ]; then
    cp "$MISE_TARBALL" "$ROOTFS/tmp/mise.tar.gz"
else
    MISE_URL="https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz"
    curl -fsSL "$MISE_URL" -o "$ROOTFS/tmp/mise.tar.gz"
fi
if [ -n "${MISE_SHA256:-}" ]; then
    echo "${MISE_SHA256}  $ROOTFS/tmp/mise.tar.gz" | sha256sum -c -
else
    echo "WARNING: no pinned SHA256 for mise ${DEB_ARCH} -- proceeding unverified" >&2
fi
tar -xzf "$ROOTFS/tmp/mise.tar.gz" -C "$ROOTFS/tmp"
cp "$ROOTFS/tmp/mise/bin/mise" "$ROOTFS/usr/local/bin/mise"
chmod +x "$ROOTFS/usr/local/bin/mise"
rm -rf "$ROOTFS/tmp/mise.tar.gz" "$ROOTFS/tmp/mise"

# Per-agent mise data dir lives under the agent's persistent $HOME
# (which vm.py bind-mounts from ~/.safeyolo/agents/<name>/home via
# VirtioFS). Installs made through `mise use -g` land on the host and
# survive rootfs snapshot/restore. Agents install their own runtimes
# on first boot -- no shared /opt/mise preinstall any more.
cat > "$ROOTFS/etc/profile.d/mise.sh" <<'MISE_PROFILE'
export MISE_DATA_DIR="${HOME:-/home/agent}/.mise"
export MISE_CONFIG_DIR="${HOME:-/home/agent}/.mise"
export MISE_CACHE_DIR="${HOME:-/home/agent}/.mise/cache"
export PATH="${HOME:-/home/agent}/.mise/shims:$PATH"
eval "$(mise activate bash)" 2>/dev/null || true
MISE_PROFILE
chmod +x "$ROOTFS/etc/profile.d/mise.sh"
cp "$ROOTFS/etc/profile.d/mise.sh" "$ROOTFS/etc/mise-activate.sh"
cat > "$ROOTFS/etc/profile.d/00-path.sh" <<'PATH_PROFILE'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH_PROFILE
chmod +x "$ROOTFS/etc/profile.d/00-path.sh"
if [ -f "$ROOTFS/etc/environment" ]; then
    if grep -q '^PATH=' "$ROOTFS/etc/environment"; then
        sed -i 's|^PATH=.*|PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|' \
            "$ROOTFS/etc/environment"
    else
        echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> \
            "$ROOTFS/etc/environment"
    fi
else
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" > \
        "$ROOTFS/etc/environment"
fi
grep -q '^BASH_ENV=' "$ROOTFS/etc/environment" 2>/dev/null || \
    echo "BASH_ENV=/etc/mise-activate.sh" >> "$ROOTFS/etc/environment"

# ---------------------------------------------------------------------------
# gh CLI
# ---------------------------------------------------------------------------
echo "--- Installing gh CLI ${GH_VERSION} ---"
if [ -n "${GH_TARBALL:-}" ] && [ -f "$GH_TARBALL" ]; then
    cp "$GH_TARBALL" "$ROOTFS/tmp/gh.tar.gz"
else
    GH_URL="https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz"
    curl -fsSL "$GH_URL" -o "$ROOTFS/tmp/gh.tar.gz"
fi
if [ -n "${GH_SHA256:-}" ]; then
    echo "${GH_SHA256}  $ROOTFS/tmp/gh.tar.gz" | sha256sum -c -
else
    echo "WARNING: no pinned SHA256 for gh ${DEB_ARCH} -- proceeding unverified" >&2
fi
tar -xzf "$ROOTFS/tmp/gh.tar.gz" -C "$ROOTFS/tmp"
cp "$ROOTFS/tmp/gh_${GH_VERSION}_linux_${DEB_ARCH}/bin/gh" "$ROOTFS/usr/local/bin/gh"
chmod +x "$ROOTFS/usr/local/bin/gh"
rm -rf "$ROOTFS/tmp/gh.tar.gz" "$ROOTFS/tmp/gh_${GH_VERSION}_linux_${DEB_ARCH}"

# ---------------------------------------------------------------------------
# Users, sshd, init stub, hostname, DNS
# ---------------------------------------------------------------------------
chroot "$ROOTFS" useradd -m -s /bin/bash agent 2>/dev/null || true

echo "--- Installing Python test deps ---"
chroot "$ROOTFS" pip3 install --break-system-packages --quiet \
    pytest httpx pytest-timeout

# sshd config: pubkey only, no passwords
sed -i "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/" "$ROOTFS/etc/ssh/sshd_config"
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" "$ROOTFS/etc/ssh/sshd_config"
chroot "$ROOTFS" ssh-keygen -A >/dev/null 2>&1

# Install guest init stub from the repo's guest/rootfs/ into the new rootfs
cp "$GUEST_SRC_DIR/rootfs/safeyolo-guest-init" "$ROOTFS/usr/local/bin/safeyolo-guest-init"
chmod +x "$ROOTFS/usr/local/bin/safeyolo-guest-init"

# Pre-create OCI bind-mount targets. gVisor's gofer tries to create any
# missing bind-mount destinations; with overlay-dir= mode the overlay
# upper takes the creates, but some places (rootfs paths blocked by
# readonly + host-uid ownership) can still trip the gofer. Pre-creating
# the exact target paths in the image sidesteps it entirely — the bind
# mount lands on an existing directory/file regardless of overlay state.
#
# /home/agent already exists from useradd -m above; listed here for doc.
# safeyolo.crt is a zero-byte file because it's a FILE bind-mount
# target (vs the directory bind-mounts above); bind-mounting onto
# a file requires the target to be a regular file.
mkdir -p \
    "$ROOTFS/workspace" \
    "$ROOTFS/safeyolo" \
    "$ROOTFS/safeyolo-status" \
    "$ROOTFS/home/agent"
: > "$ROOTFS/usr/local/share/ca-certificates/safeyolo.crt"
# /safeyolo/proxy.sock — the per-agent proxy UDS is file-bind-mounted
# here by the platform layer. Pre-create as an empty regular file so
# gVisor can bind over it without needing to create-on-readonly-root.
: > "$ROOTFS/safeyolo/proxy.sock"

# Hostname + DNS defaults (DNS overridden by DHCP at boot)
echo "safeyolo" > "$ROOTFS/etc/hostname"
echo "nameserver 8.8.8.8" > "$ROOTFS/etc/resolv.conf"

# Expose a few useful BusyBox applets without adding extra packages.
for busybox_path in /bin/busybox /usr/bin/busybox; do
    if [ -x "$ROOTFS$busybox_path" ]; then
        ln -sf "$busybox_path" "$ROOTFS/usr/local/bin/hexdump"
        ln -sf "$busybox_path" "$ROOTFS/usr/local/bin/nc"
        break
    fi
done

# ---------------------------------------------------------------------------
# Apt cleanup + sweep any residual docs that escaped the essential-hook's
# dpkg nodoc rules. Sources of residual docs: tarballs (mise, gh), pip
# installs, package maintainer scripts that force-create doc dirs.
# ---------------------------------------------------------------------------
chroot "$ROOTFS" /usr/bin/apt-get clean
rm -rf "$ROOTFS/var/lib/apt/lists/"*
rm -rf "$ROOTFS/var/cache/apt/archives/"*.deb 2>/dev/null || true

# Strip everything in /usr/share/doc EXCEPT copyright files (kept for
# Debian redistribution compliance). The essential-hook's dpkg rules
# should have prevented most of this at install time, but pip and tarball
# installs (mise, gh) don't honor dpkg config.
find "$ROOTFS/usr/share/doc" -mindepth 2 -type f ! -name 'copyright' -delete 2>/dev/null || true
find "$ROOTFS/usr/share/doc" -mindepth 1 -type d -empty -delete 2>/dev/null || true

rm -rf "$ROOTFS/usr/share/man/"*
rm -rf "$ROOTFS/usr/share/info/"*
find "$ROOTFS/usr/share/locale" -maxdepth 1 ! -name "en*" -type d -exec rm -rf {} + 2>/dev/null || true

# Python pyc caches -- pip leaves __pycache__ dirs everywhere.
find "$ROOTFS" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Runtime apt support.
#
# Earlier revisions shadowed apt/apt-get/yum/dnf/apk with mise-pointing
# error stubs on the premise that "agents install tools via mise, not
# apt." That was over-restrictive: guest-proxy-forwarder + the
# per-agent proxy UDS give apt a clear path, and the /var/cache/apt
# + /var/lib/apt/lists bind mounts (cli/src/safeyolo/platform/linux.py)
# let downloads persist across agent restarts. So apt stays usable —
# compilers and system libs can be pulled on demand instead of living
# in the shipped base.
#
# Operator model under rootless gVisor: on-demand package installs
# are a HOST-OPERATOR action, not an in-sandbox agent action.
#
#   Works:
#     safeyolo agent shell NAME --root -c "apt-get install -y PKG"
#
#   Doesn't work:
#     (agent user inside the sandbox) sudo apt-get install -y PKG
#
# Why: rootless user namespaces ignore the setuid bit, so `sudo`
# running as the agent user (uid 1000) can't escalate to root. No
# sudoers config fixes that — it's a kernel/userns property. Package
# installs therefore happen via `safeyolo agent shell --root`, which
# invokes `runsc exec --user 0:0` directly and lands the caller as
# sandbox-root with no setuid dance.
#
# Important caveat: the install itself persists only for the life of
# the sandbox. The Linux overlay is memory-backed (gVisor silently
# ignores dir=), so unpacked package files in /usr vanish on agent
# stop. The per-agent /var/cache/apt bind means the re-download is
# free on restart, but the dpkg unpack cost recurs. Heavy toolkits
# (build-essential, pentest tools, etc.) belong in the base image;
# lightweight one-offs are fine to install ad-hoc.
#
# apt itself ignores HTTP_PROXY / HTTPS_PROXY — it reads its own
# Acquire::*::Proxy from /etc/apt/apt.conf.d/. Point it at the in-VM
# socat relay (guest-proxy-forwarder listens on :8080) so apt-get
# routes through SafeYolo's policy layer. TLS works because
# guest-init-static.sh adds SafeYolo's CA to the trust bundle before
# the agent's shell opens.
# ---------------------------------------------------------------------------
mkdir -p "$ROOTFS/etc/apt/apt.conf.d"
cat > "$ROOTFS/etc/apt/apt.conf.d/99safeyolo-proxy" <<'APTCONF'
Acquire::http::Proxy "http://127.0.0.1:8080";
Acquire::https::Proxy "http://127.0.0.1:8080";

// Keep the .deb files in /var/cache/apt/archives after install.
// /var/cache/apt is bind-mounted to a per-agent persistent host dir
// (see cli/src/safeyolo/platform/linux.py), so keeping the downloaded
// packages there means a subsequent `apt-get install X` on the same
// agent reuses the cached .debs instead of re-fetching. Without this,
// apt's default post-install cleanup strips the archives and the cache
// bind holds only the lock dirs.
APT::Keep-Downloaded-Packages "true";
APTCONF

echo "=== Customize hook completed successfully ==="
