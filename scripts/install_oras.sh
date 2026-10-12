#!/usr/bin/env bash
# Install the publisher's exact ORAS release after checking its pinned archive.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: install_oras.sh BIN_DIRECTORY' >&2; exit 64; }
case "$(uname -m)" in
    x86_64|amd64) architecture=amd64; checksum=f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454 ;;
    aarch64|arm64) architecture=arm64; checksum=15702c6e3a4a56a8bd8ac5c17efdbcab56d9bada661ccbcf017f5b10c1d89399 ;;
    *) echo 'ORAS publisher tooling requires Linux amd64 or arm64.' >&2; exit 64 ;;
esac
[[ "$(uname -s)" == Linux ]] || exit 64
mkdir -p -- "$1"
destination=$(cd -- "$1" && pwd)
scratch=$(mktemp -d "$destination/.oras.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
archive="oras_1.3.4_linux_$architecture.tar.gz"
curl -fsSL "https://github.com/oras-project/oras/releases/download/v1.3.4/$archive" -o "$scratch/$archive"
printf '%s  %s\n' "$checksum" "$scratch/$archive" | sha256sum -c -
tar -xzf "$scratch/$archive" -C "$scratch" oras
install -m 0755 "$scratch/oras" "$destination/oras"
"$destination/oras" version
