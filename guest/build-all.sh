#!/bin/bash
#
# Build all SafeYolo guest image artifacts.
#
# Output (in ./out/):
#   Image              - Linux kernel (macOS microVMs only, not needed for gVisor)
#   initramfs.cpio.gz  - Minimal initramfs (macOS microVMs only)
#   rootfs-base.ext4   - Debian trixie rootfs with mise + node@22
#
# Architecture:
#   Default: host architecture (arm64 on Apple Silicon, amd64 on x86_64)
#   Override: ARCH=amd64 ./build-all.sh
#
# Prerequisites: Docker with cross-platform support
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

echo "=== SafeYolo Guest Image Build ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

# Check Docker
if ! docker version >/dev/null 2>&1; then
    echo "Error: Docker is required to build guest images."
    echo "Install Docker Desktop or equivalent."
    exit 1
fi

# Kernel and initramfs are only needed for macOS microVMs (Virtualization.framework).
# On Linux, gVisor provides its own kernel — only the rootfs is needed.
if [ "$(uname)" = "Darwin" ] || [ "${BUILD_KERNEL:-}" = "1" ]; then
    "$SCRIPT_DIR/build-kernel.sh"
    echo ""
    "$SCRIPT_DIR/build-initramfs.sh"
    echo ""
else
    echo "Skipping kernel + initramfs (not needed for gVisor on Linux)"
    echo "Set BUILD_KERNEL=1 to build anyway"
    echo ""
fi

# Rootfs is always needed (both macOS VMs and Linux gVisor containers)
"$SCRIPT_DIR/build-rootfs.sh"

echo ""
echo "=== All artifacts built ==="
echo ""
ls -lh "$OUTPUT_DIR/"
echo ""
echo "Install to ~/.safeyolo/share/ with:"
echo "  mkdir -p ~/.safeyolo/share && cp $OUTPUT_DIR/* ~/.safeyolo/share/"
