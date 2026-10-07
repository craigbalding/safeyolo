#!/usr/bin/env bash
# Assemble the installed native layout from checked platform artifacts.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/native_package.sh"
output= directory= artifacts= guest_artifacts= runtime_artifacts= vm_artifacts=
profile=production
while (($#)); do
  case "$1" in
    --output|--directory|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile)
      option=$1
      (($# >= 2)) || { package_error "$option requires a value"; exit 2; }
      case "$option" in
        --output) output=$2;; --directory) directory=$2;; --artifacts) artifacts=$2;; --guest-artifacts) guest_artifacts=$2;;
        --runtime-artifacts) runtime_artifacts=$2;; --vm-artifacts) vm_artifacts=$2;; --profile) profile=$2;;
      esac
      shift 2;;
    --help)
      echo 'Usage: scripts/build_host_packages.sh --output DIRECTORY [--profile production|debug] [--artifacts HOST_BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] --runtime-artifacts DIRECTORY [--vm-artifacts DIRECTORY]'
      echo 'Runtime inputs: tmux and its required private libraries. macOS VM inputs: safeyolo-vm, build metadata/dSYM and vsock-term with .version/.sha256 receipts.'
      echo '--directory assembles an unpacked bundle instead of a tar.gz. Prepared guest images remain separate inputs to installation.'
      exit 0;;
    *) package_error "unknown argument: $1"; exit 2;;
  esac
done
[[ -n $output || -n $directory ]] || { package_error '--output or --directory is required'; exit 2; }
[[ -z $output || -z $directory ]] || { package_error 'choose --output or --directory'; exit 2; }
[[ $profile =~ ^(production|debug)$ ]] || { package_error 'profile must be production or debug'; exit 2; }
platform=$(host_platform)
revision=$(git -C "$repository" rev-parse HEAD)
[[ -z $(git -C "$repository" status --porcelain --untracked-files=all) ]] || { package_error 'use a clean committed source checkout'; exit 1; }
[[ ${SAFEYOLO_BUILD_REVISION:-$revision} == "$revision" ]] || { package_error 'build revision differs from this source'; exit 1; }
if [[ -z $artifacts ]]; then
  options=() target_profile=debug
  if [[ $profile == production ]]; then options+=(--release); target_profile=release; fi
  (cd "$repository"; SAFEYOLO_BUILD_REVISION=$revision CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} scripts/cargo_with_space.sh build \
    --manifest-path proxy/Cargo.toml --locked --bin safeyolo --bin safeyolo-proxy --bin safeyolo-coord ${options[@]+"${options[@]}"})
  artifacts=${CARGO_TARGET_DIR:-$repository/proxy/target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}$target_profile
fi
if [[ -z $guest_artifacts ]]; then
  SAFEYOLO_BUILD_REVISION=$revision SAFEYOLO_BUILD_PROFILE=$profile "$repository/scripts/build_guest_command.sh"
  target_profile=debug
  [[ $profile != production ]] || target_profile=release
  guest_artifacts=${SAFEYOLO_GUEST_TARGET_DIR:-$repository/guest/command/target}/${SAFEYOLO_GUEST_TARGET:+$SAFEYOLO_GUEST_TARGET/}$target_profile
fi
verify_native_artifacts "$artifacts" "$guest_artifacts" "$profile" "$platform"
[[ -n $runtime_artifacts ]] || { package_error '--runtime-artifacts is required; supply prepared tmux bytes'; exit 1; }
native_executable "$runtime_artifacts/tmux" "$platform"
if [[ $platform == darwin-arm64 ]]; then
  [[ -n $vm_artifacts ]] || { package_error '--vm-artifacts is required on macOS'; exit 1; }
  for binary in safeyolo-vm safeyolo-vm.build-info.json vsock-term vsock-term.version vsock-term.sha256; do require_file "$vm_artifacts/$binary"; done
  [[ -d $vm_artifacts/safeyolo-vm.dSYM ]] || { package_error 'VM helper debug symbols are missing'; exit 1; }
fi
name=safeyolo-$platform-$profile
temporary=
if [[ -n $output ]]; then
  mkdir -p "$output"
  temporary=$(mktemp -d "$output/native-package.XXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  directory=$temporary/$name
fi
[[ ! -e $directory ]] || { package_error "bundle directory already exists: $directory"; exit 1; }
mkdir -p "$directory/bin" "$directory/libexec" "$directory/lib" "$directory/assets/guest" "$directory/assets/launchers" "$directory/assets/contrib/lib" "$directory/assets/docs"
for binary in safeyolo safeyolo-proxy safeyolo-coord; do cp "$artifacts/$binary" "$directory/bin/"; done
cp "$runtime_artifacts/tmux" "$directory/libexec/"
cp "$repository/scripts/tmux_runtime.sh" "$directory/bin/tmux"
# ldd resolves the entire Linux dependency closure. On macOS walk non-system
# dylibs, whose install names are resolved by the private launcher's directory.
libraries=()
if [[ $platform == darwin-arm64 ]]; then
  pending=("$runtime_artifacts/tmux") index=0
  while ((index < ${#pending[@]})); do
    dependencies=$(otool -L "${pending[index]}")
    while IFS= read -r library; do
      case "$library" in /usr/lib/*|/System/*) continue;; esac
      [[ $library == /* ]] || { package_error "unresolved tmux dependency: $library"; exit 1; }
      found=0
      for known in ${libraries[@]+"${libraries[@]}"}; do [[ $known != "$library" ]] || found=1; done
      if (( ! found )); then libraries+=("$library"); pending+=("$library"); fi
    done < <(printf '%s\n' "$dependencies" | sed -n '2,$s/^[[:space:]]*\([^[:space:]]*\).*/\1/p')
    ((index += 1))
  done
else
  dependencies=$(ldd "$runtime_artifacts/tmux")
  [[ $dependencies != *'not found'* ]] || { package_error "tmux library is missing: $dependencies"; exit 1; }
  while IFS= read -r library; do
    case "${library##*/}" in libc.so.*|libm.so.*|libpthread.so.*|librt.so.*|libdl.so.*|ld-linux*) continue;; esac
    libraries+=("$library")
  done < <(printf '%s\n' "$dependencies" | awk '$2=="=>" && $3 ~ /^\// {print $3}')
fi
for library in ${libraries[@]+"${libraries[@]}"}; do cp -L "$library" "$directory/lib/"; done
for binary in safeyolo-guest safeyolo-coord; do
  cp "$guest_artifacts/$binary" "$guest_artifacts/$binary.version" "$guest_artifacts/$binary.sha256" "$directory/assets/guest/"
done
for asset in guest-init guest-init-static guest-init-per-run guest-proxy-forwarder guest-shell-bridge guest-desktop; do
  cp "$repository/cli/src/safeyolo/$asset.sh" "$directory/assets/guest/$asset"
done
cp "$repository/guest/rootfs/safeyolo-sudo" "$directory/assets/guest/guest-sudo"
cp "$repository/cli/src/safeyolo/launchers/"*.sh "$directory/assets/launchers/"
cp -R "$repository/cli/src/safeyolo/agent_context/skills" "$directory/assets/"
cp -R "$repository/cli/src/safeyolo/services" "$directory/assets/"
cp "$repository/LICENSE" "$directory/"
if [[ -d $runtime_artifacts/licenses ]]; then
  cp -R "$runtime_artifacts/licenses" "$directory/assets/"
fi
# Retain installed Ubuntu package notices for the runtime bytes we copy.
# Prepared or other-platform artifacts carry their notices alongside tmux.
if [[ $platform == linux-* ]] && command -v dpkg-query >/dev/null 2>&1; then
  mkdir -p "$directory/assets/licenses"
  for runtime_file in "$runtime_artifacts/tmux" ${libraries[@]+"${libraries[@]}"}; do
    if provider=$(dpkg-query -S "$(readlink -f "$runtime_file")" 2>/dev/null); then
      provider=${provider%%: /*}
      provider=${provider%%:*}
      if [[ -f /usr/share/doc/$provider/copyright ]]; then
        cp "/usr/share/doc/$provider/copyright" "$directory/assets/licenses/$provider-copyright"
      fi
    fi
  done
  cp -R /usr/share/common-licenses "$directory/assets/licenses/"
fi
cp "$repository/docs/AGENTS.md" "$directory/assets/docs/"
cp "$repository/cli/src/safeyolo/repo_map.py" "$directory/assets/"
cp "$repository/repo-map.toml" "$directory/assets/"
for asset in claude-host-setup codex-host-setup codex-coord-host-setup pi-host-setup pi-coord-host-setup mise-shell-host-setup coord-mcp-bootstrap safeyolo-coord-mcp-launcher; do
  cp "$repository/contrib/$asset.sh" "$directory/assets/contrib/"
done
cp "$repository/contrib/pi-coord-extension.ts" "$directory/assets/contrib/"
cp "$repository/contrib/lib/"*.sh "$directory/assets/contrib/lib/"
if [[ $platform == darwin-arm64 ]]; then
  cp "$vm_artifacts/safeyolo-vm" "$vm_artifacts/safeyolo-vm.build-info.json" "$vm_artifacts/vsock-term" "$vm_artifacts/vsock-term.version" "$vm_artifacts/vsock-term.sha256" "$directory/bin/"
  cp -R "$vm_artifacts/safeyolo-vm.dSYM" "$directory/bin/"
fi
cp "$repository/scripts/install_native.sh" "$directory/install_native.sh"
cp "$repository/scripts/install_host_package.sh" "$directory/install.sh"
cp "$repository/scripts/native_package.sh" "$directory/native_package.sh"
chmod 0755 "$directory/bin/"{safeyolo,safeyolo-proxy,safeyolo-coord,tmux} "$directory/libexec/tmux" "$directory/assets/guest/"{guest-*,safeyolo-guest,safeyolo-coord} "$directory/"*.sh
minimum=
runtime_binaries=("$directory/libexec/tmux")
for library in ${libraries[@]+"${libraries[@]}"}; do runtime_binaries+=("$directory/lib/${library##*/}"); done
if [[ $platform == darwin-arm64 ]]; then
  minimum=$(otool -l "$directory/bin/"{safeyolo,safeyolo-proxy,safeyolo-coord,safeyolo-vm} "${runtime_binaries[@]}" | awk '
    $1=="cmd" {command=$2} (command=="LC_BUILD_VERSION" && $1=="minos") || (command=="LC_VERSION_MIN_MACOSX" && $1=="version") {print $2}' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
else
  minimum=$(readelf --version-info "$directory/bin/"{safeyolo,safeyolo-proxy,safeyolo-coord} "${runtime_binaries[@]}" | sed -n 's/.*Name: GLIBC_\([0-9.]*\).*/\1/p' | sort -V | tail -1)
fi
printf 'source_commit=%s\nprofile=%s\nplatform=%s\nminimum_runtime=%s\n' "$revision" "$profile" "$platform" "$minimum" > "$directory/package-info"
(cd "$directory"; find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(file_sha256 "$file")" "$file"; done > SHA256SUMS)
verify_native_package "$directory"
if [[ -n $output ]]; then
  tar -czf "$output/$name.tar.gz" -C "$temporary" "$name"
  echo "Built native bundle: $output/$name.tar.gz"
else echo "Built native bundle: $directory"; fi
