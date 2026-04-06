#!/bin/bash
#
# Build Debian trixie ARM64 rootfs for SafeYolo microVMs.
# Runs in Docker on macOS (requires --privileged for mount/debootstrap).
#
# Output: out/rootfs-base.ext4 (~2GB sparse, ~400MB actual)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"
ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"

# Pinned mise version (same as current SafeYolo Dockerfile)
MISE_VERSION="${MISE_VERSION:-2026.1.1}"
MISE_SHA256_ARM64="${MISE_SHA256_ARM64:-dcd7006e84d3557284a7c87b99abdce4a465900f67609e99b39c757006a361dd}"

mkdir -p "$OUTPUT_DIR"

if [ -f "$OUTPUT_DIR/rootfs-base.ext4" ]; then
    echo "Rootfs already exists at $OUTPUT_DIR/rootfs-base.ext4"
    echo "Delete it to rebuild."
    exit 0
fi

echo "=== Building Debian trixie ARM64 rootfs ==="
echo "Size: ${ROOTFS_SIZE_MB}MB"
echo "This runs in Docker (privileged) and takes several minutes on first build."

docker run --rm --privileged --platform linux/arm64/v8 \
    -v "$SCRIPT_DIR/rootfs:/build/rootfs:ro" \
    -v "$OUTPUT_DIR:/output" \
    -e MISE_VERSION="$MISE_VERSION" \
    -e MISE_SHA256_ARM64="$MISE_SHA256_ARM64" \
    debian:trixie-slim /bin/bash -c '
set -euo pipefail

ROOTFS_SIZE_MB='"$ROOTFS_SIZE_MB"'

echo "--- Installing build tools ---"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    debootstrap e2fsprogs curl ca-certificates >/dev/null

# Create sparse ext4 image
echo "--- Creating ${ROOTFS_SIZE_MB}MB ext4 image ---"
dd if=/dev/zero of=/output/rootfs-base.ext4 bs=1M count=0 seek=$ROOTFS_SIZE_MB 2>/dev/null
mkfs.ext4 -F -E lazy_itable_init=0 -q /output/rootfs-base.ext4

# Mount
mkdir -p /mnt/rootfs
mount /output/rootfs-base.ext4 /mnt/rootfs

# Debootstrap
echo "--- Running debootstrap (trixie, arm64, minbase) ---"
debootstrap --arch=arm64 --variant=minbase trixie /mnt/rootfs http://deb.debian.org/debian

# Suppress doc/man/locale installation
cat > /mnt/rootfs/etc/dpkg/dpkg.cfg.d/01-nodoc << EOF
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
EOF

# Install packages
echo "--- Installing packages ---"
chroot /mnt/rootfs apt-get update -qq
chroot /mnt/rootfs apt-get install -y -qq --no-install-recommends \
    git curl jq ca-certificates build-essential \
    openssh-server iproute2 iputils-ping procps \
    less xz-utils libgomp1 libatomic1 \
    busybox-static >/dev/null

# Create agent user
echo "--- Creating agent user ---"
chroot /mnt/rootfs useradd -m -s /bin/bash agent

# Install mise (pinned, checksum-verified)
echo "--- Installing mise ${MISE_VERSION} ---"
ARCH=arm64
curl -fsSL "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${ARCH}.tar.gz" -o /tmp/mise.tar.gz
echo "${MISE_SHA256_ARM64}  /tmp/mise.tar.gz" | sha256sum -c -
tar -xzf /tmp/mise.tar.gz -C /tmp
cp /tmp/mise/bin/mise /mnt/rootfs/usr/local/bin/mise
chmod +x /mnt/rootfs/usr/local/bin/mise
rm -rf /tmp/mise.tar.gz /tmp/mise

# Configure mise with shared dirs (accessible to all users)
# MISE_CONFIG_DIR must also be shared so `mise use -g` config is visible to all users
mkdir -p /mnt/rootfs/opt/mise
cat > /mnt/rootfs/etc/profile.d/mise.sh << '"'"'MISE_PROFILE'"'"'
export MISE_DATA_DIR="/opt/mise"
export MISE_CONFIG_DIR="/opt/mise"
export MISE_CACHE_DIR="/opt/mise/cache"
export PATH="/opt/mise/shims:$PATH"
eval "$(mise activate bash)" 2>/dev/null || true
MISE_PROFILE
chmod +x /mnt/rootfs/etc/profile.d/mise.sh

# Also source for non-interactive shells
cp /mnt/rootfs/etc/profile.d/mise.sh /mnt/rootfs/etc/mise-activate.sh
echo "BASH_ENV=/etc/mise-activate.sh" >> /mnt/rootfs/etc/environment

# Pre-install node@22 into shared mise dir
echo "--- Installing node@22 via mise ---"
MISE_ENV="MISE_DATA_DIR=/opt/mise MISE_CONFIG_DIR=/opt/mise MISE_CACHE_DIR=/opt/mise/cache"
chroot /mnt/rootfs env $MISE_ENV mise install node@22 || true
chroot /mnt/rootfs env $MISE_ENV mise use -g node@22 || true
echo "--- Installing gh CLI via mise ---"
chroot /mnt/rootfs env $MISE_ENV MISE_AQUA_VERIFY_ATTESTATIONS=false \
    mise install github-cli || true
chroot /mnt/rootfs env $MISE_ENV MISE_AQUA_VERIFY_ATTESTATIONS=false \
    mise use -g github-cli || true
# Regenerate shims with correct config
chroot /mnt/rootfs env $MISE_ENV mise reshim || true
# Make shared dir writable by agent user (for installing additional tools)
chroot /mnt/rootfs chmod -R 777 /opt/mise

# Clean up apt BEFORE installing package-manager intercepts
echo "--- Cleaning up ---"
chroot /mnt/rootfs /usr/bin/apt-get clean
rm -rf /mnt/rootfs/var/lib/apt/lists/*

# Package-manager intercepts (same as current SafeYolo Dockerfile)
# MUST come after apt-get clean since they shadow /usr/bin/apt-get
for cmd in apt apt-get yum dnf apk; do
    cat > "/mnt/rootfs/usr/local/bin/$cmd" << '"'"'INTERCEPT'"'"'
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
    chmod +x "/mnt/rootfs/usr/local/bin/$cmd"
done

# Configure sshd
echo "--- Configuring sshd ---"
sed -i "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/" /mnt/rootfs/etc/ssh/sshd_config
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /mnt/rootfs/etc/ssh/sshd_config
# Generate host keys
chroot /mnt/rootfs ssh-keygen -A >/dev/null 2>&1

# Install guest init script
echo "--- Installing guest init ---"
cp /build/rootfs/safeyolo-guest-init /mnt/rootfs/usr/local/bin/safeyolo-guest-init
chmod +x /mnt/rootfs/usr/local/bin/safeyolo-guest-init

# Set hostname
echo "safeyolo" > /mnt/rootfs/etc/hostname

# Default DNS (overridden by DHCP at boot)
echo "nameserver 8.8.8.8" > /mnt/rootfs/etc/resolv.conf
rm -rf /mnt/rootfs/usr/share/doc/*
rm -rf /mnt/rootfs/usr/share/man/*
find /mnt/rootfs/usr/share/locale -maxdepth 1 ! -name "en*" -type d -exec rm -rf {} + 2>/dev/null || true

umount /mnt/rootfs
echo "--- Rootfs built ---"
'

echo "=== Rootfs ready at $OUTPUT_DIR/rootfs-base.ext4 ==="
echo "Actual size: $(du -sh "$OUTPUT_DIR/rootfs-base.ext4" | cut -f1)"
