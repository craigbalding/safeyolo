#!/usr/bin/env bash
# Archive finished default-guest files without changing backend metadata.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo 'Usage: archive-default.sh CONSUMER_PLATFORM BUILT_DIRECTORY ARCHIVE_DIRECTORY' >&2
    exit 64
fi
platform=$1
assets=$(cd -- "$2" && pwd)
mkdir -p -- "$3"
destination=$(cd -- "$3" && pwd)
case "$platform" in
    linux/amd64|linux/arm64) files=(rootfs-tree cache-paths.txt) ;;
    darwin/arm64) files=(Image initramfs.cpio.gz rootfs-base.ext4) ;;
    *) echo "Unsupported consumer platform: $platform" >&2; exit 64 ;;
esac
for file in "${files[@]}" build-base.txt; do
    [[ -e "$assets/$file" ]] || { echo "Missing finished build output: $assets/$file" >&2; exit 1; }
done
if [[ "$platform" == linux/* ]]; then
    [[ -d "$assets/rootfs-tree" && -f "$assets/cache-paths.txt" ]] || exit 1
else
    for file in "${files[@]}"; do [[ -f "$assets/$file" ]] || exit 1; done
fi
temporary=$(mktemp "$destination/.guest.tar.zst.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
# GNU tar reads Linux subuid-owned files as guest root. pax retains numeric
# owners, modes, hard/symbolic links, ACLs and xattrs; sparse ext4 holes remain
# holes after a matching GNU tar extraction. Remove access/change-time fields
# so reading the same stopped inputs produces the same archive on a retry.
sudo -n tar --format=pax --numeric-owner --acls --xattrs --xattrs-include='*' \
    --sparse --sort=name --pax-option=delete=atime,delete=ctime \
    -C "$assets" -cf - -- "${files[@]}" | zstd -T1 -3 -q -c > "$temporary"
mv -- "$temporary" "$destination/guest.tar.zst"
cp -- "$assets/build-base.txt" "$destination/build-base.txt"
printf '%s archive_bytes=%s\n' "$platform" "$(stat -c %s "$destination/guest.tar.zst")"
