#!/usr/bin/env bash
# Build the Linux guest helper separately from host-platform executables.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=${SAFEYOLO_BUILD_PROFILE:-production}
options=()
case "$profile" in
  production) options+=(--release); directory=release ;;
  debug) directory=debug ;;
  *) echo 'SAFEYOLO_BUILD_PROFILE must be production or debug' >&2; exit 2 ;;
esac
target=${SAFEYOLO_GUEST_TARGET:-}
if [[ $(uname -s) != Linux && -z $target ]]; then
  echo 'A Linux guest artifact is required; build it on Linux or set SAFEYOLO_GUEST_TARGET to a configured Linux cross-build target' >&2
  exit 1
fi
if [[ -n $target ]]; then options+=(--target "$target"); fi
revision=${SAFEYOLO_BUILD_REVISION:-}
if [[ -z $revision && -z $(git -C "$repository" status --porcelain) ]]; then
  revision=$(git -C "$repository" rev-parse HEAD)
fi
revision_env=()
if [[ -n $revision ]]; then revision_env=(SAFEYOLO_BUILD_REVISION="$revision"); fi
revision=${revision:-unknown}
target_dir=${SAFEYOLO_GUEST_TARGET_DIR:-$repository/guest/command/target}
(cd "$repository"; env "${revision_env[@]}" CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} \
  CARGO_TARGET_DIR=$target_dir scripts/cargo_with_space.sh build \
  --manifest-path guest/command/Cargo.toml --locked "${options[@]}")
artifact=$target_dir/${target:+$target/}$directory/safeyolo-guest
printf 'safeyolo-guest 0.1.0 commit=%s profile=%s\n' "$revision" "$profile" > "$artifact.version"
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$artifact"); digest=${digest%% *}
else
  digest=$(shasum -a 256 "$artifact"); digest=${digest%% *}
fi
printf '%s\n' "$digest" > "$artifact.sha256"
echo "$artifact"

# The supervisor and MCP adapter run in the Linux guest, also on macOS hosts.
# Reuse the proxy tree's target rather than rebuild its dependencies in the
# small guest-command tree. Both guest executables are returned together.
coord_target_dir=${CARGO_TARGET_DIR:-$repository/proxy/target}
(cd "$repository"; env "${revision_env[@]}" CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} \
  CARGO_TARGET_DIR=$coord_target_dir scripts/cargo_with_space.sh build \
  --manifest-path proxy/Cargo.toml --locked --bin safeyolo-coord "${options[@]}")
coord_source=$coord_target_dir/${target:+$target/}$directory/safeyolo-coord
coord_artifact=$(dirname -- "$artifact")/safeyolo-coord
if [[ $coord_source != "$coord_artifact" ]]; then cp -- "$coord_source" "$coord_artifact"; fi
printf 'safeyolo-coord 0.1.0 commit=%s profile=%s\n' "$revision" "$profile" > "$coord_artifact.version"
if command -v sha256sum >/dev/null 2>&1; then digest=$(sha256sum "$coord_artifact"); else digest=$(shasum -a 256 "$coord_artifact"); fi
printf '%s\n' "${digest%% *}" > "$coord_artifact.sha256"
echo "$coord_artifact"
