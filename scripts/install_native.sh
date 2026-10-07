#!/usr/bin/env bash
# Install the native product into a fresh root. Extend this layout as the
# remaining native commands and guest artifacts become available.
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=
artifacts=
guest_artifacts=
profile=production
while (($#)); do
  case "$1" in
    --root|--artifacts|--guest-artifacts|--profile)
      option=$1
      if (($# < 2)); then echo "$option requires a value" >&2; exit 2; fi
      case "$option" in
        --root) root=$2 ;;
        --artifacts) artifacts=$2 ;;
        --guest-artifacts) guest_artifacts=$2 ;;
        --profile) profile=$2 ;;
      esac
      shift 2 ;;
    --help)
      echo 'Usage: scripts/install_native.sh --root ROOT [--artifacts BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] [--profile production|debug]'
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
  revision=${SAFEYOLO_BUILD_REVISION:-}
  if [[ -z $revision && -z $(git -C "$repository" status --porcelain) ]]; then revision=$(git -C "$repository" rev-parse HEAD); fi
  revision_env=()
  if [[ -n $revision ]]; then revision_env=(SAFEYOLO_BUILD_REVISION="$revision"); fi
  (cd "$repository"; env "${revision_env[@]}" CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} \
    scripts/cargo_with_space.sh build --manifest-path proxy/Cargo.toml --locked \
      --bin safeyolo --bin safeyolo-proxy --bin safeyolo-coord "${build_options[@]}")
  artifacts=${CARGO_TARGET_DIR:-$repository/proxy/target}/$target_profile
  if [[ -z $guest_artifacts ]]; then
    env "${revision_env[@]}" SAFEYOLO_BUILD_PROFILE=$profile "$repository/scripts/build_guest_command.sh"
    guest_artifacts=${SAFEYOLO_GUEST_TARGET_DIR:-$repository/guest/command/target}/${SAFEYOLO_GUEST_TARGET:+$SAFEYOLO_GUEST_TARGET/}$target_profile
  fi
fi
guest_artifacts=${guest_artifacts:-$artifacts}
for binary in safeyolo safeyolo-proxy safeyolo-coord; do
  if [[ ! -x $artifacts/$binary ]]; then echo "Required native artifact is missing: $artifacts/$binary" >&2; exit 1; fi
done
cli_identity=$("$artifacts/safeyolo" --version)
proxy_identity=$("$artifacts/safeyolo-proxy" --version)
coord_identity=$("$artifacts/safeyolo-coord" --version)
if [[ ${cli_identity#* commit=} != "${proxy_identity#* commit=}" || ${cli_identity#* commit=} != "${coord_identity#* commit=}" ]]; then
  echo 'CLI and proxy source/profile identities differ' >&2
  exit 1
fi
for guest_binary in safeyolo-guest safeyolo-coord; do
  helper=$guest_artifacts/$guest_binary
  for required in "$helper" "$helper.version" "$helper.sha256"; do
    if [[ ! -f $required ]]; then echo "Required Linux guest artifact is missing: $required; use scripts/build_guest_command.sh and --guest-artifacts" >&2; exit 1; fi
  done
  guest_identity=$(cat "$helper.version")
  if [[ ${guest_identity#* commit=} != "${cli_identity#* commit=}" ]]; then echo 'Guest and host source/profile identities differ' >&2; exit 1; fi
  if command -v sha256sum >/dev/null 2>&1; then digest=$(sha256sum "$helper"); else digest=$(shasum -a 256 "$helper"); fi
  if [[ ${digest%% *} != "$(cat "$helper.sha256")" ]]; then echo 'Guest helper bytes differ from the built artifact checksum' >&2; exit 1; fi
  if [[ $(uname -s) == Linux && $("$helper" --version) != "$guest_identity" ]]; then echo 'Guest helper executable identity differs' >&2; exit 1; fi
done
mkdir -p -- "$root/bin" "$root/assets/guest"
for binary in safeyolo safeyolo-proxy safeyolo-coord; do
  cp -- "$artifacts/$binary" "$root/bin/$binary"
  chmod 0755 "$root/bin/$binary"
done
for guest_binary in safeyolo-guest safeyolo-coord; do
  helper=$guest_artifacts/$guest_binary
  cp -- "$helper" "$helper.version" "$helper.sha256" "$root/assets/guest/"
  chmod 0755 "$root/assets/guest/$guest_binary"
done
for asset in guest-init guest-init-static guest-init-per-run guest-proxy-forwarder guest-shell-bridge guest-desktop; do
  cp -- "$repository/cli/src/safeyolo/$asset.sh" "$root/assets/guest/$asset"
  chmod 0755 "$root/assets/guest/$asset"
done
cp -- "$repository/guest/rootfs/safeyolo-sudo" "$root/assets/guest/guest-sudo"
chmod 0755 "$root/assets/guest/guest-sudo"
mkdir -p -- "$root/assets/launchers"
for launcher in tmux-window tmux-pane tmux-common; do
  cp -- "$repository/cli/src/safeyolo/launchers/$launcher.sh" "$root/assets/launchers/$launcher.sh"
  chmod 0755 "$root/assets/launchers/$launcher.sh"
done
# Lab stages only the skills its native entry actually reaches.
mkdir -p -- "$root/assets/skills"
for skill in safeyolo safeyolo-lab-controller; do
  mkdir -p -- "$root/assets/skills/$skill"
  tar -C "$repository/cli/src/safeyolo/agent_context/skills/$skill" \
    --exclude='__pycache__' --exclude='*.pyc' -cf - . | \
    tar -C "$root/assets/skills/$skill" -xf -
done
"$root/bin/safeyolo" --root "$root" init
echo "$cli_identity"
echo "Installed: $root/bin/safeyolo"
