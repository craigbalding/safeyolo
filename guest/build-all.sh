#!/bin/bash
#
# Build all SafeYolo guest image artifacts.
#
# Output (in ./out/):
#   Image              - Linux kernel (macOS microVMs only, not needed for gVisor)
#   initramfs.cpio.gz  - Minimal initramfs (macOS microVMs only)
#   rootfs-base.ext4   - Debian trixie rootfs with mise + compact agent tooling
#
# Platform handling:
#   Linux  - runs the three build-*.sh scripts natively
#   macOS  - auto-creates a Lima VM (from guest/lima.yaml) and shells in
#
# No Docker required. On macOS, `brew install lima` is a one-time setup.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

LIMA_VM_NAME="safeyolo-builder"
LIMA_MOUNT_POINT="/build/guest"

die() { echo "Error: $*" >&2; exit 1; }

run_builds_native() {
    echo "=== SafeYolo Guest Image Build (native Linux) ==="
    echo "Output directory: $OUTPUT_DIR"
    echo ""

    # Kernel and initramfs are only needed for macOS microVMs
    # (Virtualization.framework). On Linux, gVisor provides its own kernel —
    # only the rootfs is needed. Set BUILD_KERNEL=1 to force kernel+initramfs
    # on Linux (e.g., when producing artifacts for macOS consumers in CI).
    if [ "${BUILD_KERNEL:-}" = "1" ]; then
        "$SCRIPT_DIR/build-kernel.sh"
        echo ""
        "$SCRIPT_DIR/build-initramfs.sh"
        echo ""
    else
        echo "Skipping kernel + initramfs (not needed for gVisor on Linux)."
        echo "Set BUILD_KERNEL=1 to build anyway (required if producing artifacts for macOS)."
        echo ""
    fi

    # Rootfs is always needed
    "$SCRIPT_DIR/build-rootfs.sh"

    echo ""
    echo "=== All artifacts built ==="
    echo ""
    ls -lh "$OUTPUT_DIR/"
    echo ""
    echo "Install to ~/.safeyolo/share/ with:"
    echo "  mkdir -p ~/.safeyolo/share && cp $OUTPUT_DIR/* ~/.safeyolo/share/"
}

ensure_lima_vm() {
    command -v limactl >/dev/null || die "Lima not installed.
  macOS: brew install lima
  See guest/README.md for details."

    # Repo root, resolved to an absolute path (Lima mount locations require it).
    local repo_dir
    repo_dir="$(cd "$SCRIPT_DIR/.." && pwd)"

    if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$LIMA_VM_NAME"; then
        echo "=== Creating Lima VM '$LIMA_VM_NAME' (first run; ~2-3 min) ==="
        # --set injects the REPO_DIR param at start time so the mount
        # locations in lima.yaml resolve to absolute paths on this host.
        limactl start --name="$LIMA_VM_NAME" --tty=false \
            --set=".param.REPO_DIR = \"$repo_dir\"" \
            "$SCRIPT_DIR/lima.yaml"
    fi

    # Start the VM if it's stopped
    local status
    status="$(limactl list --format '{{.Status}}' --filter "name=$LIMA_VM_NAME" 2>/dev/null || true)"
    if [ "$status" != "Running" ]; then
        echo "=== Starting Lima VM '$LIMA_VM_NAME' ==="
        limactl start "$LIMA_VM_NAME"
    fi
}

# Helper: shell into Lima with the workdir set to a mount point (avoids
# Lima's auto-cd-to-host-CWD, which spams "No such file or directory"
# warnings when the host CWD isn't mapped into the VM — which it never
# is, by design).
lima_shell() {
    limactl shell --workdir "$LIMA_MOUNT_POINT" "$LIMA_VM_NAME" -- "$@"
}

# Guard against Lima's default home-directory mount leaking back in through
# a future lima.yaml edit. If /Users/$USER is visible inside the VM, abort —
# a build that can read SSH keys and browser data is a security regression.
verify_no_home_mount() {
    # On macOS the home path is /Users/<name>. The Lima default template
    # also exposes it at the same path inside the VM for "unix-like" paths.
    # If neither exists inside the VM, mounts are narrow as intended.
    if lima_shell sh -c "[ -d /Users/$USER ]" 2>/dev/null; then
        die "Security: /Users/$USER is visible inside the Lima VM.
guest/lima.yaml has lost its narrow-mount override. Refusing to run
the build. Fix lima.yaml (ensure explicit 'mounts:' block with no
home passthrough), then: limactl delete $LIMA_VM_NAME && ./build-all.sh"
    fi
    # Also sanity-check the expected mount point exists.
    if ! lima_shell sh -c "[ -d $LIMA_MOUNT_POINT ]" 2>/dev/null; then
        die "Expected mount $LIMA_MOUNT_POINT not present inside Lima VM.
Check guest/lima.yaml 'mounts:' block."
    fi
}

run_builds_via_lima() {
    ensure_lima_vm
    # Stop the VM on exit so it doesn't keep CPU/RAM pinned between builds.
    # Boot cost on re-use is trivial.
    trap 'echo "=== Stopping Lima VM ${LIMA_VM_NAME} ==="; limactl stop "$LIMA_VM_NAME" >/dev/null 2>&1 || true' EXIT
    verify_no_home_mount

    echo "=== SafeYolo Guest Image Build (via Lima VM '$LIMA_VM_NAME') ==="
    echo "Output directory (host): $OUTPUT_DIR"
    echo ""

    # On macOS we always need kernel+initramfs (Virtualization.framework).
    # Pass BUILD_KERNEL=1 through to the VM.
    # Output goes to $LIMA_MOUNT_POINT/out inside the VM, which is bind-mounted
    # to guest/out on the host.
    lima_shell env \
        BUILD_KERNEL=1 \
        OUTPUT_DIR="$LIMA_MOUNT_POINT/out" \
        bash "$LIMA_MOUNT_POINT/build-all.sh" --inside-lima

    echo ""
    echo "=== Host-side artifacts ==="
    ls -lh "$OUTPUT_DIR/"
    echo ""
    echo "Install to ~/.safeyolo/share/ with:"
    echo "  mkdir -p ~/.safeyolo/share && cp $OUTPUT_DIR/* ~/.safeyolo/share/"
}

# --- Dispatch ---

# The --inside-lima flag indicates we're executing inside the Lima VM
# (which is Linux) — just run the native path.
if [ "${1:-}" = "--inside-lima" ]; then
    BUILD_KERNEL=1 run_builds_native
    exit 0
fi

case "$(uname)" in
    Linux)  run_builds_native ;;
    Darwin) run_builds_via_lima ;;
    *)      die "Unsupported platform: $(uname). Linux and macOS only." ;;
esac
