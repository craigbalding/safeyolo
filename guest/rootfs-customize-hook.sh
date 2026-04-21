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
#   GH_VERSION
#   GH_SHA256
#   GUEST_SRC_DIR    absolute path to the repo's guest/ directory
#                    (where rootfs/safeyolo-guest-init lives)
#
# Running this script directly (for debugging) is supported -- just set the
# vars above and pass the rootfs path as $1.
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
MISE_URL="https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${MISE_ARCH}.tar.gz"
curl -fsSL "$MISE_URL" -o "$ROOTFS/tmp/mise.tar.gz"
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
GH_URL="https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${DEB_ARCH}.tar.gz"
curl -fsSL "$GH_URL" -o "$ROOTFS/tmp/gh.tar.gz"
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
#
# Uses /usr/bin/apt-get explicitly because the intercepts below will shadow
# /usr/bin/apt-get on $PATH.
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
# Package-manager intercepts -- agents inside the guest VM must install
# tools via mise, not apt. Run LAST so earlier apt-get calls aren't shadowed.
# ---------------------------------------------------------------------------
for cmd in apt apt-get yum dnf apk; do
    cat > "$ROOTFS/usr/local/bin/$cmd" <<'INTERCEPT'
#!/bin/bash
echo "Error: Package manager not available in SafeYolo VM"
echo ""
echo "Use mise to install languages and tools:"
echo "  mise install go@latest"
echo "  mise install python@3.12"
echo "  mise install rust@latest"
echo ""
echo "List available versions: mise ls-remote go"
exit 1
INTERCEPT
    chmod +x "$ROOTFS/usr/local/bin/$cmd"
done

echo "=== Customize hook completed successfully ==="
