#!/bin/bash
#
# Build minimal initramfs for SafeYolo microVMs.
#
# Runs on Linux only (natively or inside the Lima VM on macOS — see
# guest/build-all.sh). Contains busybox, e2fsck, resize2fs, and the init
# script at guest/initramfs/init.
#
# Output: out/initramfs.cpio.gz (~5-10MB)
#
# Dependencies (install via apt on the host):
#   busybox-static e2fsprogs pax-utils cpio
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

# Linux-only guard.
if [ "$(uname)" != "Linux" ]; then
    echo "Error: build-initramfs.sh runs on Linux only." >&2
    echo "On macOS, run ./build-all.sh which will shell into a Lima VM." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [ -f "$OUTPUT_DIR/initramfs.cpio.gz" ]; then
    echo "Initramfs already exists at $OUTPUT_DIR/initramfs.cpio.gz"
    echo "Delete it to rebuild."
    exit 0
fi

# Dependency check. Debian's busybox-static ships /bin/busybox (static binary).
MISSING=()
[ -x /bin/busybox ] || MISSING+=("busybox-static (/bin/busybox)")
command -v lddtree >/dev/null || MISSING+=("pax-utils (lddtree)")
command -v cpio >/dev/null || MISSING+=("cpio")
[ -x /sbin/e2fsck ] || [ -x /usr/sbin/e2fsck ] || MISSING+=("e2fsprogs (e2fsck)")
[ -x /sbin/resize2fs ] || [ -x /usr/sbin/resize2fs ] || MISSING+=("e2fsprogs (resize2fs)")
[ -x /sbin/mkfs.ext4 ] || [ -x /usr/sbin/mkfs.ext4 ] || MISSING+=("e2fsprogs (mkfs.ext4)")
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "Error: missing build dependencies: ${MISSING[*]}" >&2
    echo "  Debian/Ubuntu: sudo apt-get install busybox-static e2fsprogs pax-utils cpio" >&2
    exit 1
fi

# Resolve e2fsprogs binary locations (Debian moves some between /sbin and /usr/sbin).
E2FSCK_BIN="$(command -v e2fsck || echo /sbin/e2fsck)"
[ -x "$E2FSCK_BIN" ] || E2FSCK_BIN=/usr/sbin/e2fsck
RESIZE2FS_BIN="$(command -v resize2fs || echo /sbin/resize2fs)"
[ -x "$RESIZE2FS_BIN" ] || RESIZE2FS_BIN=/usr/sbin/resize2fs
MKFS_EXT4_BIN="$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)"
[ -x "$MKFS_EXT4_BIN" ] || MKFS_EXT4_BIN=/usr/sbin/mkfs.ext4

[ -r "$SCRIPT_DIR/initramfs/init" ] || {
    echo "Error: missing initramfs init script at $SCRIPT_DIR/initramfs/init" >&2
    exit 1
}

echo "=== Building initramfs ==="

WORK="$(mktemp -d -t safeyolo-initramfs.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p \
    "$WORK/bin" \
    "$WORK/sbin" \
    "$WORK/usr/sbin" \
    "$WORK/proc" \
    "$WORK/sys" \
    "$WORK/dev" \
    "$WORK/mnt/root" \
    "$WORK/usr/share/udhcpc" \
    "$WORK/etc"

# Busybox (static, all-in-one)
cp /bin/busybox "$WORK/bin/busybox"
for cmd in sh mount umount cp chmod echo cat mkdir rm \
           ip ifconfig route udhcpc switch_root sleep; do
    ln -sf busybox "$WORK/bin/$cmd"
done

# e2fsck, resize2fs and mkfs.ext4 (with lib deps via lddtree).
# mkfs.ext4 is needed by initramfs/init to lazy-format /dev/vdb on an
# agent's first boot (the host ships a zeroed sparse file; the guest
# formats it the first time it sees one). Subsequent boots mount the
# already-formatted image directly.
cp "$E2FSCK_BIN" "$WORK/sbin/e2fsck"
cp "$RESIZE2FS_BIN" "$WORK/usr/sbin/resize2fs"
cp "$MKFS_EXT4_BIN" "$WORK/sbin/mkfs.ext4"

lddtree -l "$E2FSCK_BIN" "$RESIZE2FS_BIN" "$MKFS_EXT4_BIN" 2>/dev/null | sort -u | while read -r lib; do
    [ -f "$lib" ] || continue
    dst_dir="$WORK$(dirname "$lib")"
    mkdir -p "$dst_dir"
    # Skip if already placed (e2fsck itself shows up in lddtree output)
    [ -f "$WORK$lib" ] || cp "$lib" "$WORK$lib"
done

# udhcpc default script (busybox DHCP client)
cat > "$WORK/usr/share/udhcpc/default.script" <<'DHCP'
#!/bin/sh
case "$1" in
    bound|renew)
        [ -n "$ip" ] && ip addr add $ip/$mask dev $interface 2>/dev/null
        [ -n "$router" ] && ip route add default via $router dev $interface 2>/dev/null
        [ -n "$dns" ] && echo "nameserver $dns" > /etc/resolv.conf
        ;;
esac
DHCP
chmod +x "$WORK/usr/share/udhcpc/default.script"

# Init script
cp "$SCRIPT_DIR/initramfs/init" "$WORK/init"
chmod +x "$WORK/init"

# Create the cpio archive
( cd "$WORK" && find . | cpio -o -H newc --quiet 2>/dev/null | gzip > "$OUTPUT_DIR/initramfs.cpio.gz" )
echo "Initramfs built: $(ls -lh "$OUTPUT_DIR/initramfs.cpio.gz" | awk '{print $5}')"

echo "=== Initramfs ready at $OUTPUT_DIR/initramfs.cpio.gz ==="
