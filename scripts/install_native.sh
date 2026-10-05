#!/usr/bin/env bash
# Install the native product into a fresh root. Extend this layout as the
# remaining native commands and guest artifacts become available.
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=
artifacts=
profile=production
while (($#)); do
  case "$1" in
    --root|--artifacts|--profile)
      option=$1
      if (($# < 2)); then echo "$option requires a value" >&2; exit 2; fi
      case "$option" in
        --root) root=$2 ;;
        --artifacts) artifacts=$2 ;;
        --profile) profile=$2 ;;
      esac
      shift 2 ;;
    --help)
      echo 'Usage: scripts/install_native.sh --root ROOT [--artifacts BIN_DIRECTORY] [--profile production|debug]'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z $root ]]; then echo '--root is required; choose a fresh instance directory' >&2; exit 2; fi
case "$profile" in production|debug) ;; *) echo 'profile must be production or debug' >&2; exit 2;; esac
if [[ -e $root/config.toml || -e $root/policy.toml || -e $root/data/admin_token ]]; then
  echo 'Instance already has configuration; choose a fresh root' >&2
  exit 1
fi
if [[ -z $artifacts ]]; then
  build_options=()
  target_profile=debug
  if [[ $profile == production ]]; then build_options+=(--release); target_profile=release; fi
  revision=$(git -C "$repository" rev-parse HEAD)
  (cd "$repository"; SAFEYOLO_BUILD_REVISION=$revision CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} \
    scripts/cargo_with_space.sh build --manifest-path proxy/Cargo.toml --locked \
      --bin safeyolo --bin safeyolo-proxy "${build_options[@]}")
  artifacts=${CARGO_TARGET_DIR:-$repository/proxy/target}/$target_profile
fi
for binary in safeyolo safeyolo-proxy; do
  if [[ ! -x $artifacts/$binary ]]; then echo "Required native artifact is missing: $artifacts/$binary" >&2; exit 1; fi
done
cli_identity=$("$artifacts/safeyolo" --version)
proxy_identity=$("$artifacts/safeyolo-proxy" --version)
if [[ ${cli_identity#* commit=} != "${proxy_identity#* commit=}" ]]; then
  echo 'CLI and proxy source/profile identities differ' >&2
  exit 1
fi
mkdir -p -- "$root/bin"
for binary in safeyolo safeyolo-proxy; do
  cp -- "$artifacts/$binary" "$root/bin/$binary"
  chmod 0755 "$root/bin/$binary"
done
"$root/bin/safeyolo" --root "$root" init
echo "$cli_identity"
echo "Installed: $root/bin/safeyolo"
