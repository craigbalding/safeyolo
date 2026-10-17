#!/usr/bin/env bash
# Install the resolved official stable publisher with its verified checksum.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: install_oras.sh BIN_DIRECTORY' >&2; exit 64; }
case "$(uname -m)" in
    x86_64|amd64) architecture=amd64 ;;
    aarch64|arm64) architecture=arm64 ;;
    *) echo 'ORAS publisher tooling requires Linux amd64 or arm64.' >&2; exit 64 ;;
esac
[[ "$(uname -s)" == Linux ]] || exit 64
export SAFEYOLO_GUEST_SRC_DIR="$(cd -- "$(dirname -- "$0")/../guest" && pwd)"
source "$SAFEYOLO_GUEST_SRC_DIR/input-functions.sh"
guest_inputs "$architecture" --tools oras
mkdir -p -- "$1"
destination=$(cd -- "$1" && pwd)
scratch=$(mktemp -d "$destination/.oras.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
guest_download "$architecture" oras "$scratch/oras.tar.gz"
tar -xzf "$scratch/oras.tar.gz" -C "$scratch" oras
install -m 0755 "$scratch/oras" "$destination/oras"
"$destination/oras" version
# Required interfaces fail visibly if the selected upstream becomes incompatible.
"$destination/oras" attach --help >/dev/null
"$destination/oras" discover --help >/dev/null
"$destination/oras" manifest index create --help >/dev/null
cp "$GUEST_INPUTS" "$destination/oras-inputs.json"
