#!/usr/bin/env bash
set -euo pipefail

version=0.16.1

usage() {
  printf '%s\n' \
    'Usage: install-presenterm.sh [--print-asset]' \
    '' \
    'Install the pinned Presenterm release in the persistent user command directory.'
}

[ "$(uname -s)" = Linux ] || {
  printf 'This installer supports SafeYolo Linux guests only.\n' >&2
  exit 2
}

case "$(uname -m)" in
  aarch64|arm64)
    architecture=aarch64
    ;;
  x86_64|amd64)
    architecture=x86_64
    ;;
  *)
    printf 'No pinned Presenterm asset is configured for architecture: %s\n' \
      "$(uname -m)" >&2
    exit 2
    ;;
esac

if ldd --version 2>&1 | grep -qi musl; then
  libc=musl
else
  libc=gnu
fi
target="${architecture}-unknown-linux-${libc}"

case "$target" in
  aarch64-unknown-linux-gnu)
    expected_sha256=d08cac84c26f2c683ae34458e8be497575ef92af9bca5bfbe8e01a97742eadd9
    ;;
  aarch64-unknown-linux-musl)
    expected_sha256=c03c3744609d61587aac9dda4f431912748bd70d88d4fa6c0440b079001c64c3
    ;;
  x86_64-unknown-linux-gnu)
    expected_sha256=01fbe92c16d76e84ad9baa10c32ae6ed020a514bf72bd3980a1218250a292b14
    ;;
  x86_64-unknown-linux-musl)
    expected_sha256=87512d7c88c3d961c7687aca3519f83c2b7611a550cf769c67c6f7948e8b8f54
    ;;
esac

archive="presenterm-${version}-${target}.tar.gz"
download_url="https://github.com/mfontanini/presenterm/releases/download/v${version}/${archive}"

case "${1:-}" in
  '')
    [ "$#" -eq 0 ] || {
      usage >&2
      exit 2
    }
    ;;
  --print-asset)
    [ "$#" -eq 1 ] || {
      usage >&2
      exit 2
    }
    printf 'archive=%s\nsha256=%s\nurl=%s\n' \
      "$archive" "$expected_sha256" "$download_url"
    exit 0
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

install_dir="${HOME:?HOME is not set}/.local/bin"
install_path="$install_dir/presenterm"
if [ -e "$install_path" ] || [ -L "$install_path" ]; then
  if [ -x "$install_path" ] && \
      [ "$("$install_path" --version 2>/dev/null || true)" = "presenterm $version" ]; then
    printf 'Presenterm %s is already installed at %s\n' "$version" "$install_path"
    exit 0
  fi
  printf 'Refusing to replace the existing path: %s\n' "$install_path" >&2
  exit 2
fi

if existing=$(command -v presenterm 2>/dev/null); then
  if [ "$("$existing" --version 2>/dev/null || true)" = "presenterm $version" ]; then
    printf 'Presenterm %s is already available at %s\n' "$version" "$existing"
    exit 0
  fi
  printf 'A different Presenterm is already on PATH: %s\n' "$existing" >&2
  exit 2
fi

for command in curl sha256sum tar find install; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required command is not installed: %s\n' "$command" >&2
    exit 127
  }
done

temporary_dir=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

printf 'Downloading Presenterm %s for %s.\n' "$version" "$target"
curl --fail --location --silent --show-error \
  --output "$temporary_dir/$archive" \
  "$download_url"

printf '%s  %s\n' "$expected_sha256" "$temporary_dir/$archive" |
  sha256sum --check --status
printf 'Published SHA-256 checksum matched.\n'

tar -xzf "$temporary_dir/$archive" -C "$temporary_dir"
mapfile -t binaries < <(
  find "$temporary_dir" -type f -name presenterm -perm /111 -print
)
[ "${#binaries[@]}" -eq 1 ] || {
  printf 'Expected one Presenterm binary; found %s.\n' "${#binaries[@]}" >&2
  exit 1
}

install -D -m 0755 "${binaries[0]}" "$install_path"
printf 'Installed: %s\n' "$install_path"
"$install_path" --version
