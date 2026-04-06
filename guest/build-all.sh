#!/bin/bash
#
# Build all SafeYolo guest image artifacts.
#
# Output (in ./out/):
#   Image              - ARM64 Linux kernel
#   initramfs.cpio.gz  - Minimal initramfs
#   rootfs-base.ext4   - Debian trixie rootfs with mise + node@22
#
# Prerequisites: Docker with linux/arm64/v8 platform support
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

# Build in order: kernel, initramfs, rootfs
"$SCRIPT_DIR/build-kernel.sh"
echo ""
"$SCRIPT_DIR/build-initramfs.sh"
echo ""
"$SCRIPT_DIR/build-rootfs.sh"

echo ""
echo "=== All artifacts built ==="
echo ""
ls -lh "$OUTPUT_DIR/"
echo ""
echo "Install to ~/.safeyolo/share/ with:"
echo "  mkdir -p ~/.safeyolo/share && cp $OUTPUT_DIR/* ~/.safeyolo/share/"
