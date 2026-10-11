#!/usr/bin/env bash
# Install the noVNC web client without a distro bridge/interpreter dependency.
# Usage: install-novnc-assets.sh ROOTFS CACHE_DIRECTORY
set -euo pipefail
rootfs=${1:?rootfs directory required}
cache=${2:?download cache directory required}
version=1.6.0
digest=5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa
mkdir -p "$cache"
archive=$cache/novnc-$version.tar.gz
if [[ ! -f $archive ]]; then
    download=$(mktemp "$cache/novnc-download.XXXXXX")
    trap 'rm -f -- "$download"' EXIT
    curl -fSL "https://github.com/novnc/noVNC/archive/refs/tags/v$version.tar.gz" -o "$download"
    printf '%s  %s\n' "$digest" "$download" | sha256sum -c -
    mv -- "$download" "$archive"
fi
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
stage=$(mktemp -d "$cache/novnc-assets.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
tar -xzf "$archive" -C "$stage"
source_dir=$stage/noVNC-$version
destination=$rootfs/usr/share/novnc
mkdir -p "$destination"
# The upstream launchers and build/test tools are not product assets. Preserve
# all client modules, fonts/images and their licensing notices.
cp -R "$source_dir/"{app,core,vendor} "$destination/"
cp "$source_dir/"{vnc.html,vnc_lite.html,LICENSE.txt,AUTHORS} "$destination/"
printf '%s\n' "$version" > "$destination/VERSION"
