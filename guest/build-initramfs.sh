#!/bin/bash
#
# Build minimal initramfs for SafeYolo microVMs.
# Contains busybox, e2fsck, resize2fs, and init script.
# Runs in Docker on macOS.
#
# Output: out/initramfs.cpio.gz (~5-10MB)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/out}"

mkdir -p "$OUTPUT_DIR"

echo "=== Building initramfs ==="

docker run --rm --platform linux/arm64/v8 \
    -v "$SCRIPT_DIR/initramfs/init:/build/init:ro" \
    -v "$OUTPUT_DIR:/output" \
    debian:trixie-slim /bin/bash -c '
set -euo pipefail

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    busybox-static e2fsprogs pax-utils cpio >/dev/null

# Create initramfs structure
WORK=/tmp/initramfs
mkdir -p $WORK/{bin,sbin,usr/sbin,proc,sys,dev,mnt/root,usr/share/udhcpc}

# Busybox (static, all-in-one)
cp /bin/busybox $WORK/bin/busybox
for cmd in sh mount umount cp chmod echo cat mkdir rm \
           ip ifconfig route udhcpc switch_root sleep; do
    ln -sf busybox $WORK/bin/$cmd
done

# e2fsck and resize2fs with all library dependencies
lddtree -l /sbin/e2fsck /usr/sbin/resize2fs 2>/dev/null | sort -u | while read lib; do
    if [ -f "$lib" ]; then
        dir="$WORK$(dirname "$lib")"
        mkdir -p "$dir"
        cp "$lib" "$WORK$lib"
    fi
done

# udhcpc default script (busybox DHCP client)
cat > $WORK/usr/share/udhcpc/default.script << '"'"'DHCP'"'"'
#!/bin/sh
case "$1" in
    bound|renew)
        [ -n "$ip" ] && ip addr add $ip/$mask dev $interface 2>/dev/null
        [ -n "$router" ] && ip route add default via $router dev $interface 2>/dev/null
        [ -n "$dns" ] && echo "nameserver $dns" > /etc/resolv.conf
        ;;
esac
DHCP
chmod +x $WORK/usr/share/udhcpc/default.script

# Init script
cp /build/init $WORK/init
chmod +x $WORK/init

# Create the cpio archive
cd $WORK
find . | cpio -o -H newc --quiet 2>/dev/null | gzip > /output/initramfs.cpio.gz
echo "Initramfs built: $(ls -lh /output/initramfs.cpio.gz | awk '"'"'{print $5}'"'"')"
'

echo "=== Initramfs ready at $OUTPUT_DIR/initramfs.cpio.gz ==="
