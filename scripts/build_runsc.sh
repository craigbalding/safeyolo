#!/usr/bin/env bash
# Build the patched runtime from a clean checkout of the pinned upstream source.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/native_package.sh"
(($# == 2)) || { package_error 'Usage: build_runsc.sh UPSTREAM_SOURCE OUTPUT_DIRECTORY'; exit 2; }
upstream=$(cd -- "$1" && pwd)
mkdir -p "$(dirname -- "$2")"
output=$(cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")
revision=97e8e896904cb364319cd9758241d3f0bd27a6f4
version=release-20261005.0-safeyolo.1
platform=$(host_platform)
case "$platform" in
  linux-amd64) configuration=x86_64;;
  linux-arm64) configuration=aarch64;;
  *) package_error 'gVisor builds require a Linux host'; exit 1;;
esac
[[ $(git -C "$upstream" rev-parse HEAD) == "$revision" ]] || { package_error "gVisor source must be $revision"; exit 1; }
[[ -z $(git -C "$upstream" status --porcelain) ]] || { package_error 'use a clean upstream checkout; retain an interrupted build and resume its Bazel commands there'; exit 1; }
[[ ! -e $output && ! -L $output ]] || { package_error "runtime destination already exists: $output"; exit 1; }
git -C "$upstream" apply --check "$script_dir/gvisor/nofollow.patch"
git -C "$upstream" apply "$script_dir/gvisor/nofollow.patch"

# The caller selects the build filesystem and preserves its required reserve.
# Bazelisk honors the upstream .bazelversion; the source pins the Go toolchain.
cd -- "$upstream"
bazel test --jobs=1 --config="$configuration" //pkg/sentry/vfs:vfs_test \
  --test_filter='TestShouldFollowSymlinkDirectoryRequirement|TestSymlinkTargetTrailingSlash'
targets=(//runsc:runsc //runsc/cmd/sentry:gvisor_sentry \
  //runsc/prewarmer:prewarmer_binary //runsc/fdparking:fdparking_binary)
names=(runsc gvisor-bin/gvisor_sentry gvisor-bin/gvisor-sentry-prewarmer gvisor-bin/runsc-fd-parking)
bazel build --jobs=1 --config="$configuration" "${targets[@]}"

mkdir -p "$(dirname -- "$output")"
stage=$(mktemp -d "$(dirname -- "$output")/runsc-build.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/gvisor-bin"
for index in "${!targets[@]}"; do
  binary=$(bazel cquery --config="$configuration" --output=files "${targets[$index]}")
  [[ -n $binary && $binary != *$'\n'* ]] || { package_error "expected one output for ${targets[$index]}"; exit 1; }
  native_executable "$binary" "$platform"
  cp -- "$binary" "$stage/${names[$index]}"
done
observed=$("$stage/runsc" --version)
[[ ${observed%%$'\n'*} == "runsc version $version" ]] || { package_error "built gVisor version differs: $observed"; exit 1; }
mv -T -- "$stage" "$output"
trap - EXIT
echo "Prepared gVisor $version $platform from $revision and gvisor/nofollow.patch" >&2
