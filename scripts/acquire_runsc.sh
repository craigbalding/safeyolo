#!/usr/bin/env bash
# Prepare the complete patched runtime for the host package producer.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/native_package.sh"
(($# == 1)) || { package_error 'Usage: acquire_runsc.sh DESTINATION'; exit 2; }
destination=$1
platform=$(host_platform)
case "$platform" in
  linux-amd64) architecture=x86_64; bazel_sha=17247e8a84245f59d3bc633d0cfe0a840992a7760a11af1a30012d03da31604c;;
  linux-arm64) architecture=arm64; bazel_sha=52bb74f0880ee87b17e3a1aa41257d0dba9e9cb92df4e83f8f6c656a46df152d;;
  *) package_error 'gVisor runtime acquisition is for Linux'; exit 1;;
esac
[[ ! -e $destination && ! -L $destination ]] || { package_error "runtime destination already exists: $destination"; exit 1; }
build_input=$(file_sha256 "$script_dir/build_runsc.sh")
patch_input=$(file_sha256 "$script_dir/gvisor/nofollow.patch")
cache=${XDG_CACHE_HOME:-$HOME/.cache}/safeyolo/gvisor/release-20261005.0-safeyolo.1/$patch_input-$build_input/$platform
selected=${SAFEYOLO_RUNSC_ARTIFACTS:-}
stage=
cleanup_runsc() { [[ -z $stage ]] || rm -rf -- "$stage"; }
trap cleanup_runsc EXIT

if [[ -z $selected ]]; then
  mkdir -p "$cache"
  selected=$cache/runtime
  if [[ ! -d $selected ]]; then
    # Bazel fetches the Go toolchain pinned by this upstream source.
    # Reuse an installed pinned Bazel when available.
    if [[ $(bazel --version 2>/dev/null || true) != 'bazel 8.3.1' ]]; then
      mkdir -p "$cache/tools"
      if [[ ! -f $cache/tools/bazel ]]; then
        download=$(mktemp "$cache/tools/download.XXXXXX")
        curl -fLsS --proto '=https' --proto-redir '=https' \
          "https://github.com/bazelbuild/bazel/releases/download/8.3.1/bazel-8.3.1-linux-$architecture" -o "$download"
        [[ $(file_sha256 "$download") == "$bazel_sha" ]] || { package_error 'Bazel checksum differs'; exit 1; }
        chmod +x "$download"
        mv -- "$download" "$cache/tools/bazel"
      fi
      [[ $(file_sha256 "$cache/tools/bazel") == "$bazel_sha" ]] || { package_error 'cached Bazel checksum differs'; exit 1; }
      export PATH="$cache/tools:$PATH"
    fi
    build=$(mktemp -d "$cache/build.XXXXXX")
    echo "Building the patched runtime in $build; failed source and compiler outputs are retained there" >&2
    git init "$build/source"
    git -C "$build/source" remote add origin https://github.com/google/gvisor.git
    git -C "$build/source" fetch --depth=1 origin 97e8e896904cb364319cd9758241d3f0bd27a6f4
    git -C "$build/source" checkout --detach FETCH_HEAD
    "$script_dir/build_runsc.sh" "$build/source" "$build/runtime"
    (cd "$build/runtime"; sha256sum runsc gvisor-bin/* > SHA256SUMS)
    # Concurrent producers may finish the same pinned input. Keep the winner
    # and leave this build available rather than replacing its directory.
    if ! mv -T -- "$build/runtime" "$selected"; then
      [[ -d $selected ]] || exit 1
    fi
  fi
  (cd "$selected"; sha256sum -c SHA256SUMS)
fi
verify_runsc_payload "$selected" "$platform"
mkdir -p "$(dirname -- "$destination")"
stage=$(mktemp -d "$(dirname -- "$destination")/gvisor.XXXXXX")
mkdir "$stage/gvisor-bin"
while IFS= read -r name; do cp -- "$selected/$name" "$stage/$name"; done < <(runsc_files)
verify_runsc_payload "$stage" "$platform"
mv -T -- "$stage" "$destination"
stage=
echo "Prepared gVisor release-20261005.0-safeyolo.1 $platform" >&2
