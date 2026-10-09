#!/usr/bin/env bash
# Install the native bundle into a fresh instance root and initialize it once.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root= bundle= platform_assets= command_dir=
build_arguments=()
while (($#)); do
  case "$1" in
    --root|--bundle|--platform-assets|--command-dir|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --bundle) bundle=$2;; --platform-assets) platform_assets=$2;;
        --command-dir) command_dir=$2;;
        *) build_arguments+=("$option" "$2");;
      esac
      shift 2;;
    --help)
      echo 'Usage: install_native.sh --root ROOT [--bundle UNPACKED_BUNDLE] [--platform-assets DIRECTORY] [--command-dir DIRECTORY]'
      echo 'From source: scripts/install_native.sh --root ROOT --runtime-artifacts DIRECTORY [--artifacts HOST_BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] [--vm-artifacts DIRECTORY] [--profile production|debug]'
      echo 'Installation checks the native bundle and creates configuration, trust and tokens internally. ROOT must have no existing instance configuration. Prepared guest images are optional for proxy startup and required before agent start.'
      echo 'Installs the safeyolo command in HOME/.local/bin when that directory is already on PATH, otherwise /usr/local/bin (using sudo if needed). --command-dir selects another command location. Existing unrelated commands are preserved.'
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n $root ]] || { echo '--root is required; choose a fresh instance directory' >&2; exit 2; }
if [[ ( -e $root && ! -d $root ) || -e $root/config.toml || -e $root/policy.toml || -e $root/data/admin_token ]]; then
  echo 'Instance already has configuration or is not a directory; choose a fresh root' >&2; exit 1
fi
temporary=
if [[ -z $bundle ]]; then
  mkdir -p "$(dirname -- "$root")"
  temporary=$(mktemp -d "$(dirname -- "$root")/native-install.XXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  "$script_dir/build_host_packages.sh" --directory "$temporary/bundle" ${build_arguments[@]+"${build_arguments[@]}"}
  bundle=$temporary/bundle
else
  [[ ${#build_arguments[@]} == 0 ]] || { echo 'Build inputs cannot be combined with --bundle' >&2; exit 2; }
fi
source "$bundle/native_package.sh"
verify_native_package "$bundle"
if [[ -n $platform_assets ]]; then
  if [[ $(uname -s) == Darwin ]]; then
    for asset in Image initramfs.cpio.gz rootfs-base.ext4; do require_file "$platform_assets/$asset"; done
  else
    [[ -d $platform_assets/rootfs-tree ]] || { package_error "prepared rootfs-tree is missing: $platform_assets"; exit 1; }
  fi
fi
mkdir -p "$root"
root=$(cd -- "$root" && pwd -P)
if [[ -z $command_dir ]]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) command_dir=$HOME/.local/bin ;;
    *) command_dir=/usr/local/bin ;;
  esac
fi
command_on_path=false
case ":$PATH:" in *":$command_dir:"*) command_on_path=true ;; esac
[[ $command_dir == /* ]] || command_dir=$PWD/$command_dir
# The command entry is host installation state. Use the same conventional
# location on Linux and Mac; elevate only the directory/link operations.
command_parent=$command_dir
while [[ ! -d $command_parent ]]; do command_parent=$(dirname "$command_parent"); done
command_install=()
if [[ ! -w $command_parent ]]; then
  command -v sudo >/dev/null || {
    echo "Cannot write command directory $command_dir and sudo is unavailable; select a writable command directory with --command-dir." >&2
    exit 1
  }
  command_install=(sudo)
fi
${command_install[@]+"${command_install[@]}"} mkdir -p "$command_dir"
command_dir=$(cd -- "$command_dir" && pwd -P)
command_entry=$command_dir/safeyolo
command_target=$root/bin/safeyolo
if [[ -e $command_entry || -L $command_entry ]]; then
  if [[ ! -L $command_entry || $(readlink "$command_entry") != "$command_target" ]]; then
    echo "Existing command $command_entry was preserved. Move or rename it if you intend to replace it, or select another command directory with --command-dir; no instance configuration was created." >&2
    exit 1
  fi
fi
cp -R "$bundle/bin" "$bundle/libexec" "$bundle/assets" "$root/"
if [[ -d $bundle/lib ]]; then cp -R "$bundle/lib" "$root/"; fi
cp "$bundle/package-info" "$bundle/SHA256SUMS" "$bundle/LICENSE" "$root/"
if [[ -n $platform_assets ]]; then
  mkdir -p "$root/share"
  if [[ $(uname -s) == Darwin ]]; then
    # APFS clones retain separate writable file identities without full copies.
    for asset in Image initramfs.cpio.gz rootfs-base.ext4; do cp -c "$platform_assets/$asset" "$root/share/$asset"; done
  else
    # The prepared tree retains its sandbox UID/GID ownership. The operator
    # supplies a reusable immutable tree; per-agent writable state is separate.
    ln -s "$(cd "$platform_assets/rootfs-tree" && pwd)" "$root/share/rootfs-tree"
    if [[ -f $platform_assets/cache-paths.txt ]]; then
      cp "$platform_assets/cache-paths.txt" "$root/share/cache-paths.txt"
    fi
  fi
fi
"$root/bin/safeyolo" --root "$root" init
cat >> "$root/config.toml" <<'EOF'
gateway_builtin_services_dir = "assets/services"
gateway_services_dir = "data/services"
EOF
mkdir -p "$root/data/services"
if [[ ! -L $command_entry ]]; then
  ${command_install[@]+"${command_install[@]}"} ln -s "$command_target" "$command_entry"
fi
if $command_on_path; then
    hash -r
    discovered=$(command -v safeyolo || true)
    if [[ -z $discovered || ! $discovered -ef $command_target ]]; then
      echo "Installed files are in $root, but this shell finds ${discovered:-no safeyolo command}. That existing command was preserved. Move or rename the earlier command if you intend to use this installation, then retry safeyolo in a new terminal." >&2
      exit 1
    fi
fi
echo "Installed SafeYolo: $root"
echo "Command: $command_entry"
"$root/bin/safeyolo" --version
echo 'With prepared guest inputs and normal Codex authentication, try a tiny app task: safeyolo demo'
