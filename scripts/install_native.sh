#!/usr/bin/env bash
# Install verified files and initialize once; preserve matching installed state.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=${SAFEYOLO_CONFIG_DIR:-${SAFEYOLO_HOME:-$HOME/.safeyolo}}
bundle= platform_assets= command_dir=
download_guest=true
build_arguments=()
while (($#)); do
  case "$1" in
    --root|--bundle|--platform-assets|--command-dir|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$option requires a nonempty value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --bundle) bundle=$2;; --platform-assets) platform_assets=$2;;
        --command-dir) command_dir=$2;;
        *) build_arguments+=("$option" "$2");;
      esac
      shift 2;;
    --help)
      echo 'Usage: install_native.sh [--root ROOT] [--bundle UNPACKED_BUNDLE] [--platform-assets DIRECTORY | --no-guest-download] [--command-dir DIRECTORY]'
      echo 'From source: scripts/install_native.sh --root ROOT --runtime-artifacts DIRECTORY [--artifacts HOST_BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] [--vm-artifacts DIRECTORY] [--profile production|debug]'
      echo 'Installation checks the bundle, acquires its compatible default guest and creates configuration, trust and tokens internally. Default ROOT is HOME/.safeyolo (or SAFEYOLO_CONFIG_DIR). Repeat preserves a matching installation without upgrading. Conflicting or older state requires a separate root. --platform-assets uses prepared/offline guest inputs; --no-guest-download supports contributor or proxy-only installation.'
      echo 'Installs the safeyolo command in HOME/.local/bin when that directory is already on PATH, otherwise /usr/local/bin (using sudo if needed). --command-dir selects another command location. Existing unrelated commands are preserved.'
      exit 0;;
    --no-guest-download) download_guest=false; shift;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n $root ]] || { echo '--root requires a nonempty directory' >&2; exit 2; }
source "$script_dir/native_package.sh"
host_platform >/dev/null
[[ $root == /* ]] || root=$PWD/$root
check_fresh_root() {
  local name
  for name in config.toml policy.toml bin libexec lib assets package-info SHA256SUMS LICENSE install.sh install_native.sh native_package.sh data certs logs builtin-services services; do
    [[ ! -e $root/$name && ! -L $root/$name ]] || {
      echo "Existing path $root/$name was preserved. Choose a fresh --root and separate --command-dir." >&2; return 1
    }
  done
}
move_install_input() {
  local input=$1 directory=$2
  mv -n "$input" "$directory/"
  [[ ! -e $input && ! -L $input ]] || {
    echo "Existing path $directory/${input##*/} was preserved. Installation is incomplete. Choose a fresh --root and separate --command-dir." >&2; return 1
  }
}
if [[ -e $root && ! -d $root ]]; then
  echo "Instance path $root is not a directory; choose a fresh root." >&2; exit 1
fi
existing=false
if [[ -e $root/config.toml || -L $root/config.toml || -e $root/policy.toml || -L $root/policy.toml || -e $root/data/admin_token ]]; then
  existing=true
  if [[ ! -f $root/install_native.sh || ! -f $root/native_package.sh || ! -f $root/config.toml || ! -f $root/policy.toml ]]; then
    echo "Existing or incomplete instance at $root was preserved; use its installed command or choose a fresh root with --root and a separate --command-dir." >&2; exit 1
  fi
  [[ -n $bundle ]] || bundle=$root
fi
temporary= staged_root= install_lock=
cleanup_install() {
  if [[ -n $temporary ]]; then rm -rf -- "$temporary"; fi
  if [[ -n $staged_root ]]; then rm -rf -- "$staged_root"; fi
  if [[ -n $install_lock ]]; then rmdir "$install_lock"; fi
}
trap cleanup_install EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z $bundle ]]; then
  mkdir -p "$(dirname -- "$root")"
  temporary=$(mktemp -d "$(dirname -- "$root")/native-install.XXXXXX")
  "$script_dir/build_host_packages.sh" --directory "$temporary/bundle" ${build_arguments[@]+"${build_arguments[@]}"}
  bundle=$temporary/bundle
else
  [[ ${#build_arguments[@]} == 0 ]] || { echo 'Build inputs cannot be combined with --bundle' >&2; exit 2; }
fi
echo 'SafeYolo: checking the host package.' >&2
verify_native_package "$bundle"
if $existing; then
  cmp -s "$root/package-info" "$bundle/package-info" || {
    echo "Host package differs from the installed host at $root. State was preserved. Repeat is not an upgrade; use the installed command or a separate --root and --command-dir." >&2; exit 1
  }
  cmp -s "$root/SHA256SUMS" "$bundle/SHA256SUMS" || {
    echo "Host package bytes differ from the installed host at $root. State was preserved. Repeat is not an upgrade; use the installed command or a separate --root and --command-dir." >&2; exit 1
  }
  verify_native_package "$root"
  for file in data/admin_token data/agent_token data/instance_id certs/mitmproxy-ca.pem certs/mitmproxy-ca-cert.pem; do
    require_file "$root/$file"
  done
  if [[ -f $root/share/guest-selection.json ]]; then
    temporary=$(mktemp -d "$(dirname -- "$root")/native-repeat.XXXXXX")
    "$root/bin/safeyolo" --root "$root" guest acquire --package-info "$root/package-info" --write-selection "$temporary/guest-selection.json" >/dev/null
  fi
fi
if ! $existing && [[ -n $platform_assets ]]; then
  if [[ $(uname -s) == Darwin ]]; then
    for asset in Image initramfs.cpio.gz rootfs-base.ext4; do require_file "$platform_assets/$asset"; done
  else
    [[ -d $platform_assets/rootfs-tree ]] || { package_error "prepared rootfs-tree is missing: $platform_assets"; exit 1; }
  fi
fi
if [[ -d $root ]]; then root=$(cd -- "$root" && pwd -P); fi
if [[ -z $command_dir ]]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) command_dir=$HOME/.local/bin ;;
    *":/usr/local/bin:"*) command_dir=/usr/local/bin ;;
    *) echo 'No conventional command directory is on PATH. Select an existing PATH directory with --command-dir; your shell settings were preserved.' >&2; exit 1;;
  esac
fi
command_on_path=false
case ":$PATH:" in *":$command_dir:"*) command_on_path=true ;; esac
[[ $command_dir == /* ]] || command_dir=$PWD/$command_dir
command_target=$root/bin/safeyolo
# Elevate only command-directory and link operations, after explaining them.
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
command_entry=$command_dir/safeyolo
check_command_entry() {
  local discovered
  if $command_on_path; then
    discovered=$(command -v safeyolo || true)
    if [[ -n $discovered && ! $discovered -ef $command_target ]]; then
      echo "Existing command $discovered was preserved. Select a separate --command-dir or move that command yourself before retrying." >&2; return 1
    fi
  fi
  if [[ -e $command_entry || -L $command_entry ]]; then
    if [[ ! -L $command_entry ]] || { [[ ! $command_entry -ef $command_target ]] && [[ $(readlink "$command_entry") != "$command_target" ]]; }; then
      echo "Existing command $command_entry was preserved. Move or rename it yourself, or select another command directory with --command-dir." >&2
      return 1
    fi
  fi
}
check_command_entry
if ! $existing; then
  # Existing prepared inputs and unrelated files can remain in a fresh root.
  # Never overwrite a partially initialized instance or another host package.
  check_fresh_root
  mkdir -p "$(dirname -- "$root")"
  lock_path=$root.install-lock
  mkdir "$lock_path" 2>/dev/null || {
    echo "Another installation may be using $root. If no installer is running, remove the empty $lock_path directory and retry." >&2; exit 1
  }
  install_lock=$lock_path
  staged_root=$(mktemp -d "$(dirname -- "$root")/safeyolo-install.XXXXXX")
  if [[ -z $platform_assets ]] && $download_guest; then
    [[ ! -e $root/share && ! -L $root/share ]] || {
      echo "Guest inputs at $root/share were preserved. Supply them with --platform-assets or retain them with --no-guest-download." >&2; exit 1
    }
    echo 'SafeYolo: acquiring and verifying the compatible guest.' >&2
    platform_assets=$("$bundle/bin/safeyolo" --root "$staged_root" guest acquire --package-info "$bundle/package-info" --write-selection "$staged_root/guest-selection.json") || {
      acquisition_status=$?
      echo 'Guest acquisition failed. No instance was initialized. Retry after repairing the reported prerequisite; verified guest inputs remain reusable.' >&2; exit "$acquisition_status"
    }
    install_platform_assets "$platform_assets" "$staged_root/share"
    mv "$staged_root/guest-selection.json" "$staged_root/share/guest-selection.json"
  elif [[ -n $platform_assets ]]; then
    install_platform_assets "$platform_assets" "$staged_root/share"
  fi
  cp -R "$bundle/bin" "$bundle/libexec" "$bundle/assets" "$staged_root/"
  if [[ -d $bundle/lib ]]; then cp -R "$bundle/lib" "$staged_root/"; fi
  cp "$bundle/package-info" "$bundle/SHA256SUMS" "$bundle/LICENSE" "$bundle/install.sh" "$bundle/install_native.sh" "$bundle/native_package.sh" "$staged_root/"
  echo 'SafeYolo: initializing configuration, identity and trust.' >&2
  "$staged_root/bin/safeyolo" --root "$staged_root" init
  cat >> "$staged_root/config.toml" <<'EOF'
gateway_builtin_services_dir = "assets/services"
gateway_services_dir = "data/services"
EOF
  mkdir -p "$staged_root/data/services"
  if [[ -d $staged_root/share && -d $root/share ]]; then
    for input in "$staged_root/share/"*; do
      [[ ! -e $root/share/${input##*/} && ! -L $root/share/${input##*/} ]] || {
        echo "Prepared input $root/share/${input##*/} was preserved. Choose a fresh --root or retain your prepared inputs with --no-guest-download." >&2; exit 1
      }
    done
  fi
fi
if ! $existing; then
  # Downloads can take time. Preserve an instance initialized meanwhile.
  check_fresh_root
fi
check_command_entry
if ((${#command_install[@]})); then
  echo "SafeYolo will create $command_dir if needed and link $command_entry to $command_target. Only these command-entry operations require sudo." >&2
fi
${command_install[@]+"${command_install[@]}"} mkdir -p "$command_dir"
if ! $existing; then
  echo "SafeYolo: activating the verified installation at $root." >&2
  mkdir -p "$root"
  # Publish config last. Never replace a path created during activation.
  # A partial activation is preserved and refused on the next invocation.
  for input in "$staged_root/"*; do
    [[ ${input##*/} != config.toml ]] || continue
    if [[ ${input##*/} == share && -d $root/share ]]; then
      for asset in "$input/"*; do move_install_input "$asset" "$root/share"; done
    else
      move_install_input "$input" "$root"
    fi
  done
  move_install_input "$staged_root/config.toml" "$root"
else
  echo "SafeYolo: retaining the installed host, guest and state at $root." >&2
fi
if [[ ! -L $command_entry ]]; then
  link_options=(-s)
  if [[ $(uname -s) == Darwin ]]; then link_options+=(-h); else link_options+=(-T); fi
  ${command_install[@]+"${command_install[@]}"} ln "${link_options[@]}" "$command_target" "$command_entry"
fi
check_command_entry
[[ $command_entry -ef $command_target ]] || {
  echo "Command entry $command_entry does not select $command_target. Installation at $root was preserved. Check the command directory and retry, or select a separate --command-dir." >&2; exit 1
}
echo "Installed SafeYolo: $root"
echo "Command: $command_entry"
"$command_entry" --version
