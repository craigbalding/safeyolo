#!/usr/bin/env bash
# Derive consumer files from one completed, stopped tree without rebuilding it.
set -euo pipefail
build= platform= output= native_cli= kernel_assets= host_settings=
while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || exit 64
    case "$1" in
        --build) build=$2 ;; --platform) platform=$2 ;; --output) output=$2 ;;
        --native-cli) native_cli=$2 ;; --kernel-assets) kernel_assets=$2 ;;
        --host-settings) host_settings=$2 ;;
        *) echo "Unknown export argument: $1" >&2; exit 64 ;;
    esac
    shift 2
done
[[ -d $build/rootfs-tree && -s $build/build-inputs.json && -s $build/build-base.txt && -n $output ]] || {
    echo 'Supply --build COMPLETED_PROFILE --platform OS/ARCH --output NEW_DIRECTORY.' >&2; exit 64;
}
[[ ! -e $output && ! -L $output ]] || { echo "Output already exists: $output" >&2; exit 1; }
"${SAFEYOLO_BUILD_PYTHON:-python3}" -c '
import json, sys
with open(sys.argv[1]) as source:
    inputs = json.load(source)
if inputs["architecture"] != sys.argv[2].split("/")[-1] or inputs["output_kind"] != "tree":
    raise ValueError("consumer architecture or tree output differs from the completed build")
' "$build/build-inputs.json" "$platform"
parent=$(dirname -- "$output")
mkdir -p -- "$parent"
stage=$(mktemp -d "$parent/extract-profile.XXXXXX")
chmod 0700 "$stage"
trap 'if [[ -d $stage ]]; then sudo -n rm -rf -- "$stage"; fi' EXIT
case "$platform" in
    linux/amd64|linux/arm64)
        [[ -x $native_cli ]] || { echo '--native-cli must name the built native CLI.' >&2; exit 64; }
        sudo -n cp -a --reflink=auto -- "$build/rootfs-tree" "$stage/rootfs-tree"
        sudo -n "$native_cli" host archive-profile-tree "$stage/rootfs-tree" "$(id -u)"
        if [[ -n $host_settings ]]; then
            read -r uid_base gid_base < <("${SAFEYOLO_BUILD_PYTHON:-python3}" -c '
import os, sys, tomllib
with open(sys.argv[1], "rb") as source:
    settings = tomllib.load(source)["linux"]
if (settings["host_uid"], settings["host_gid"]) != (os.getuid(), os.getgid()):
    raise ValueError("host settings belong to another host account")
print(settings["uid_base"], settings["gid_base"])
' "$host_settings")
            sudo -n "$native_cli" host remap-rootfs "$stage/rootfs-tree" \
                "$uid_base" "$gid_base" "$(id -u)" "$(id -g)"
        fi
        cp -- "$build/cache-paths.txt" "$stage/cache-paths.txt"
        ;;
    darwin/arm64)
        [[ -s $kernel_assets/Image && -s $kernel_assets/initramfs.cpio.gz ]] || {
            echo '--kernel-assets must supply qualified matching Image and initramfs.cpio.gz.' >&2; exit 64;
        }
        cp -- "$kernel_assets/Image" "$kernel_assets/initramfs.cpio.gz" "$stage/"
        # Size from the successful tree plus ordinary filesystem overhead and
        # free space. The artifact stays sparse; runtime uses a separate overlay.
        bytes=$(sudo -n du -sx --apparent-size -B1 -- "$build/rootfs-tree" | cut -f1)
        truncate -s "$((bytes + bytes / 4 + 512 * 1024 * 1024))" "$stage/rootfs-base.ext4"
        sudo -n mkfs.ext4 -q -F -E lazy_itable_init=0 -d "$build/rootfs-tree" "$stage/rootfs-base.ext4"
        sudo -n chown "$(id -u):$(id -g)" "$stage/rootfs-base.ext4"
        ;;
    *) echo "Unsupported consumer platform: $platform" >&2; exit 64 ;;
esac
cp -- "$build/build-inputs.json" "$build/build-base.txt" "$stage/"
mv -- "$stage" "$output"
echo "$output"
