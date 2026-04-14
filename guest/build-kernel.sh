#!/bin/bash
#
# Build minimal ARM64 Linux kernel for SafeYolo microVMs.
# Runs in Docker on macOS (cross-compilation via linux/arm64/v8).
#
# Output: out/Image (~10-15MB)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="${KERNEL_VERSION:-6.12.17}"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

mkdir -p "$OUTPUT_DIR"

if [ -f "$OUTPUT_DIR/Image" ]; then
    echo "Kernel already exists at $OUTPUT_DIR/Image"
    echo "Delete it to rebuild, or set KERNEL_VERSION to change version."
    exit 0
fi

echo "=== Building Linux $KERNEL_VERSION (ARM64) ==="
echo "This runs in Docker and takes a few minutes on first build."

docker run --rm --platform linux/arm64/v8 \
    -v "$SCRIPT_DIR/defconfig:/build/defconfig:ro" \
    -v "$OUTPUT_DIR:/output" \
    debian:trixie-slim /bin/bash -c "
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo '--- Installing build dependencies ---'
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential bc flex bison libelf-dev libssl-dev \
    curl xz-utils ca-certificates >/dev/null

echo '--- Downloading kernel source ---'
cd /tmp
curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz | tar xJ
cd linux-${KERNEL_VERSION}

echo '--- Configuring kernel ---'
cp /build/defconfig .config
make ARCH=arm64 olddefconfig

echo '--- Building kernel ---'
make ARCH=arm64 -j\$(nproc) Image 2>&1 | tail -5

echo '--- Copying output ---'
cp arch/arm64/boot/Image /output/Image
echo \"Kernel built: \$(ls -lh /output/Image | awk '{print \$5}')\"
"

echo "=== Kernel ready at $OUTPUT_DIR/Image ==="
