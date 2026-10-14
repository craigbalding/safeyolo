#!/usr/bin/env bash
# Unpack the complete pinned upstream runtime for the host package producer.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/native_package.sh"
(($# == 1)) || { package_error 'Usage: acquire_runsc.sh DESTINATION'; exit 2; }
destination=$1
platform=$(host_platform)
case "$platform" in
  linux-amd64) architecture=x86_64; expected=0a8a9058b9f11791a2097f03190c2ddc5b963c3dbee5bb9fd8497f4801c42f92;;
  linux-arm64) architecture=aarch64; expected=f8bd7cb4e989db445255c20e6c2962498e5b5bd1ec1407bfcf187fbd5f184a2a;;
  *) package_error 'gVisor runtime acquisition is for Linux'; exit 1;;
esac
[[ ! -e $destination && ! -L $destination ]] || { package_error "runtime destination already exists: $destination"; exit 1; }
cache=${XDG_CACHE_HOME:-$HOME/.cache}/safeyolo/gvisor/release-20261005.0
mkdir -p "$cache" "$(dirname -- "$destination")"
archive=$cache/gvisor-$architecture.tar.zstd
temporary= stage=
cleanup_runsc() { [[ -z $temporary ]] || rm -f -- "$temporary"; [[ -z $stage ]] || rm -rf -- "$stage"; }
trap cleanup_runsc EXIT
if [[ ! -f $archive ]]; then
  temporary=$(mktemp "$cache/download.XXXXXX")
  curl -fLsS --proto '=https' --proto-redir '=https' \
    "https://github.com/google/gvisor/releases/download/release-20261005.0/gvisor-$architecture.tar.zstd" -o "$temporary"
  [[ $(file_sha256 "$temporary") == "$expected" ]] || { package_error 'upstream gVisor archive checksum differs; no runtime was installed'; exit 1; }
  # A concurrent producer may have published the same pinned input.
  ln "$temporary" "$archive" 2>/dev/null || [[ -f $archive ]]
fi
[[ $(file_sha256 "$archive") == "$expected" ]] || { package_error "cached gVisor archive is corrupt: $archive; remove that file and retry"; exit 1; }
stage=$(mktemp -d "$(dirname -- "$destination")/gvisor.XXXXXX")
tar --zstd -xpf "$archive" -C "$stage"
verify_runsc_payload "$stage" "$platform"
mv -T "$stage" "$destination"
stage=
echo "Prepared gVisor release-20261005.0 $platform" >&2
