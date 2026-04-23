#!/bin/bash
#
# Build minimal ARM64 Linux kernel for SafeYolo microVMs.
#
# Runs on Linux only (natively or inside the Lima VM on macOS — see
# guest/build-all.sh). Cross-compiles to arm64 via native toolchain.
#
# Output: out/Image (~10-15MB)
#
# Dependencies (install via apt on the host):
#   build-essential bc flex bison libelf-dev libssl-dev gcc-aarch64-linux-gnu
#   curl xz-utils
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="${KERNEL_VERSION:-6.12.17}"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

# Linux-only guard.
if [ "$(uname)" != "Linux" ]; then
    echo "Error: build-kernel.sh runs on Linux only." >&2
    echo "On macOS, run ./build-all.sh which will shell into a Lima VM." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [ -f "$OUTPUT_DIR/Image" ]; then
    echo "Kernel already exists at $OUTPUT_DIR/Image"
    echo "Delete it to rebuild, or set KERNEL_VERSION to change version."
    exit 0
fi

# Dependency check
MISSING=()
for cmd in make bc flex bison curl xz aarch64-linux-gnu-gcc; do
    command -v "$cmd" >/dev/null || MISSING+=("$cmd")
done
# libelf / libssl check via pkg-config so we don't rely on specific header locations
if command -v pkg-config >/dev/null; then
    pkg-config --exists libelf || MISSING+=("libelf-dev")
    pkg-config --exists openssl || MISSING+=("libssl-dev")
fi
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "Error: missing build dependencies: ${MISSING[*]}" >&2
    echo "  Debian/Ubuntu: sudo apt-get install build-essential bc flex bison \\" >&2
    echo "    libelf-dev libssl-dev gcc-aarch64-linux-gnu curl xz-utils pkg-config" >&2
    exit 1
fi

echo "=== Building Linux $KERNEL_VERSION (ARM64, native cross-compile) ==="

WORK_DIR="$(mktemp -d -t safeyolo-kernel.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Persistent download cache shared with build-rootfs.sh. Re-running after
# `rm -f guest/out/Image` on an otherwise-warm tree doesn't re-download the
# kernel tarball; only `rm -rf guest/out/` flushes the cache.
DOWNLOAD_CACHE="$OUTPUT_DIR/.download-cache"
mkdir -p "$DOWNLOAD_CACHE"
KERNEL_TARBALL="$DOWNLOAD_CACHE/linux-${KERNEL_VERSION}.tar.xz"

if [ ! -f "$KERNEL_TARBALL" ]; then
    echo "--- Downloading kernel source ---"
    curl -fsSL \
        "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz" \
        -o "$KERNEL_TARBALL.tmp"
    mv "$KERNEL_TARBALL.tmp" "$KERNEL_TARBALL"
else
    echo "--- Using cached kernel source ($KERNEL_TARBALL) ---"
fi

echo "--- Extracting kernel source ---"
tar xJ -C "$WORK_DIR" -f "$KERNEL_TARBALL"
KERNEL_SRC="$WORK_DIR/linux-${KERNEL_VERSION}"

echo "--- Configuring kernel ---"
cp "$SCRIPT_DIR/defconfig" "$KERNEL_SRC/.config"
make -C "$KERNEL_SRC" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig

echo "--- Building kernel ---"
make -C "$KERNEL_SRC" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
    -j"$(nproc)" Image 2>&1 | tail -5

echo "--- Copying output ---"
cp "$KERNEL_SRC/arch/arm64/boot/Image" "$OUTPUT_DIR/Image"
echo "Kernel built: $(ls -lh "$OUTPUT_DIR/Image" | awk '{print $5}')"

echo "=== Kernel ready at $OUTPUT_DIR/Image ==="
