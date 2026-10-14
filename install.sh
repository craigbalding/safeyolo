#!/usr/bin/env bash
# Downloaded bootstrap and contributor entry point share the packaged installer.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=${SAFEYOLO_CONFIG_DIR:-${SAFEYOLO_HOME:-$HOME/.safeyolo}}
release=
bundle=
install_arguments=()
while (($#)); do
  case "$1" in
    --root|--release)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$option requires a nonempty value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --release) release=$2;;
      esac
      shift 2;;
    --bundle|--platform-assets|--command-dir|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile)
      (($# >= 2)) || { echo "$1 requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$1 requires a nonempty value" >&2; exit 2; }
      [[ $1 != --bundle ]] || bundle=$2
      install_arguments+=("$1" "$2"); shift 2;;
    --no-guest-download) install_arguments+=("$1"); shift;;
    --help)
      echo 'Usage: bash install-safeyolo.sh [--root DIRECTORY] [--release host-COMMIT] [--command-dir DIRECTORY] [--platform-assets DIRECTORY | --no-guest-download]'
      echo 'Downloads the production host package from the official GitHub release and runs its installer. The default instance is HOME/.safeyolo (or SAFEYOLO_CONFIG_DIR). Repeat uses the installed package without checking Latest or upgrading.'
      echo 'Trust source: HTTPS from the official github.com/craigbalding/safeyolo release, including its install-safeyolo.sh bootstrap. Same-release SHA256SUMS checks integrity; it is not independent publisher authentication.'
      echo 'Ubuntu AMD64/ARM64 and Apple Silicon macOS use the same download-and-run route. No package manager or build toolchain is needed for host acquisition. Host preparation, runtime and first-agent launch must also be available in the selected release.'
      echo 'Contributor builds and --bundle, --platform-assets, --no-guest-download and --command-dir remain available from the source or unpacked bundle.'
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-amd64;;
  Linux-aarch64|Linux-arm64) platform=linux-arm64;;
  Darwin-arm64) platform=darwin-arm64;;
  *) echo 'Unsupported host. Use Ubuntu AMD64/ARM64 or Apple Silicon macOS.' >&2; exit 1;;
esac
if [[ -n $release && ! $release =~ ^host-[0-9a-f]{40}$ ]]; then
  echo '--release must name an official host release: host- followed by its full commit.' >&2; exit 2
fi
if [[ -f $repository/scripts/install_native.sh && -z $release ]]; then
  "$repository/scripts/install_native.sh" --root "$root" ${install_arguments[@]+"${install_arguments[@]}"}
  exit
fi
if [[ -n $bundle ]]; then
  "$bundle/install_native.sh" --root "$root" ${install_arguments[@]+"${install_arguments[@]}"}
  exit
fi
# Use the retained installer before any network request. Older or unrelated
# roots are preserved rather than converted or replaced with Latest.
if [[ -e $root/config.toml || -L $root/config.toml || -e $root/policy.toml || -L $root/policy.toml || -e $root/data/admin_token ]]; then
  if [[ ! -f $root/install_native.sh || ! -f $root/native_package.sh ]]; then
    echo "Existing installation at $root was preserved. Use its installed command, or choose a separate --root and --command-dir; this installer does not convert older state." >&2
    exit 1
  fi
  if [[ -n $release ]] && ! grep -qx "source_commit=${release#host-}" "$root/package-info"; then
    echo "Release differs from the installed host at $root. Repeat is not an upgrade; use the installed command or a separate --root and --command-dir." >&2; exit 1
  fi
  "$root/install_native.sh" --root "$root" --bundle "$root" ${install_arguments[@]+"${install_arguments[@]}"}
  exit
fi
for tool in curl tar; do
  command -v "$tool" >/dev/null || { echo "Host acquisition requires the standard $tool command; restore it and retry." >&2; exit 1; }
done
if command -v sha256sum >/dev/null; then
  archive_sha256() { local value; value=$(sha256sum "$1"); printf '%s\n' "${value%% *}"; }
else
  command -v shasum >/dev/null || { echo 'Host acquisition requires sha256sum or shasum; restore it and retry.' >&2; exit 1; }
  archive_sha256() { local value; value=$(shasum -a 256 "$1"); printf '%s\n' "${value%% *}"; }
fi
download() {
  curl --fail --location --show-error --silent --proto '=https' --proto-redir '=https' --output "$2" "$1" || {
    echo "Host download failed: $1. Retry this command; partial files are not installed." >&2; return 1
  }
}
if [[ -z $release ]]; then
  echo 'SafeYolo: resolving the official host release.' >&2
  resolved=$(curl --fail --location --show-error --silent --proto '=https' --proto-redir '=https' \
    --output /dev/null --write-out '%{url_effective}' https://github.com/craigbalding/safeyolo/releases/latest) || {
    echo 'Cannot resolve the official host release. Check the connection and retry.' >&2; exit 1
  }
  release=${resolved#https://github.com/craigbalding/safeyolo/releases/tag/}
  [[ $release =~ ^host-[0-9a-f]{40}$ ]] || { echo 'Latest is not a supported host release. Select an official --release host-COMMIT.' >&2; exit 1; }
fi
name=safeyolo-$platform-production
cache=${XDG_CACHE_HOME:-$HOME/.cache}/safeyolo/host-packages/$release
mkdir -p "$cache"
stage=$(mktemp -d "$cache/acquire.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
base=https://github.com/craigbalding/safeyolo/releases/download/$release
echo "SafeYolo: acquiring $name from $release." >&2
download "$base/SHA256SUMS" "$stage/SHA256SUMS"
expected= count=0
while IFS= read -r line || [[ -n $line ]]; do
  if [[ ${line:64} == "  $name.tar.gz" ]]; then
    expected=${line:0:64}; ((count += 1))
  fi
done < "$stage/SHA256SUMS"
[[ $count == 1 && $expected =~ ^[0-9a-f]{64}$ ]] || {
  echo "The release has no unique SHA-256 entry for $name.tar.gz. No package was installed." >&2; exit 1
}
archive=$cache/$name.tar.gz
if [[ ! -f $archive ]] || [[ $(archive_sha256 "$archive") != "$expected" ]]; then
  download "$base/$name.tar.gz" "$stage/$name.tar.gz"
  [[ $(archive_sha256 "$stage/$name.tar.gz") == "$expected" ]] || {
    echo 'Host archive checksum failed. No package was installed. Retry to download verified bytes.' >&2; exit 1
  }
  mv "$stage/$name.tar.gz" "$archive"
else
  echo 'SafeYolo: reusing the verified host archive.' >&2
fi
echo 'SafeYolo: verifying and unpacking the host package.' >&2
tar -xzf "$archive" -C "$stage"
package=$stage/$name
[[ -f $package/package-info && -f $package/install.sh ]] || { echo 'The host archive is incomplete; no package was installed.' >&2; exit 1; }
for field in "source_commit=${release#host-}" "profile=production" "platform=$platform"; do
  grep -qx "$field" "$package/package-info" || { echo "Host package differs from its release: $field. No package was installed." >&2; exit 1; }
done
for field in guest_compatibility guest_repository guest_discovery_tag; do
  grep -q "^$field=" "$package/package-info" || {
    echo "This host release lacks compatible guest acquisition metadata ($field). No instance was initialized. Use a host release that includes guest acquisition." >&2; exit 1
  }
done
source "$package/native_package.sh"
verify_native_package "$package"
"$package/install.sh" --root "$root" ${install_arguments[@]+"${install_arguments[@]}"}
