#!/usr/bin/env bash
# Install verified files and initialize once; preserve matching installed state.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=${SAFEYOLO_CONFIG_DIR:-${SAFEYOLO_HOME:-$HOME/.safeyolo}}
bundle= platform_assets= command_dir= guest_index=
download_guest=true
move_bundle=false
runtime_override=false
host_arguments=()
build_arguments=()
while (($#)); do
  case "$1" in
    --root|--bundle|--platform-assets|--guest-index|--command-dir|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile|--system-runsc)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$option requires a nonempty value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --bundle) bundle=$2;; --platform-assets) platform_assets=$2;;
        --command-dir) command_dir=$2;;
        --guest-index) guest_index=$2;;
        --system-runsc) host_arguments+=("$option" "$2"); runtime_override=true;;
        *) build_arguments+=("$option" "$2");;
      esac
      shift 2;;
    --help)
      echo 'Usage: install_native.sh [--root ROOT] [--bundle UNPACKED_BUNDLE] [--guest-index sha256:DIGEST | --platform-assets DIRECTORY | --no-guest-download] [--command-dir DIRECTORY] [--system-runsc PATH] [--yes]'
      echo 'From source: scripts/install_native.sh --root ROOT --runtime-artifacts DIRECTORY [--artifacts HOST_BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] [--vm-artifacts DIRECTORY] [--profile production|debug]'
      echo 'The public bootstrap uses --move-bundle to consume its temporary extraction. Ordinary --bundle input is copied and remains reusable.'
      echo 'Installation checks the bundle, acquires its compatible default guest and creates configuration, trust and tokens internally. Default ROOT is HOME/.safeyolo (or SAFEYOLO_CONFIG_DIR). Repeat preserves a matching installation without upgrading. Conflicting or older state requires a separate root. --platform-assets uses prepared/offline guest inputs; --no-guest-download supports contributor or proxy-only installation.'
      echo 'New Linux bundles include the complete pinned gVisor runtime. Host preparation explains required packages, unused UID/GID allocations, private-runtime access and AppArmor changes before consent. --yes accepts those changes; --system-runsc selects a complete compatible system payload. Proxy-only --no-guest-download skips preparation unless --system-runsc explicitly selects a runtime.'
      echo 'Installs the safeyolo command in HOME/.local/bin when that directory is already on PATH, otherwise /usr/local/bin (using sudo if needed). --command-dir selects another command location. Existing unrelated commands are preserved.'
      echo '--guest-index pins first acquisition to an exact compatible OCI index. Repeated installation retains its installed guest; use guest upgrade for a later change.'
      exit 0;;
    --no-guest-download) download_guest=false; shift;;
    --move-bundle) move_bundle=true; shift;;
    --yes) host_arguments+=(--yes); shift;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
if [[ -n $guest_index ]]; then
  [[ $guest_index =~ ^sha256:[0-9a-f]{64}$ && -z $platform_assets && $download_guest == true ]] || {
    echo '--guest-index requires a SHA-256 index and guest download without --platform-assets' >&2; exit 2
  }
fi
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
if [[ -n $platform_assets && $(uname -s) == Linux ]]; then
  host_arguments+=(--platform-assets "$platform_assets")
fi
existing=false
if [[ -e $root/config.toml || -L $root/config.toml || -e $root/policy.toml || -L $root/policy.toml || -e $root/data/admin_token ]]; then
  existing=true
  if [[ ! -f $root/install_native.sh || ! -f $root/native_package.sh || ! -f $root/config.toml || ! -f $root/policy.toml ]]; then
    echo "Existing or incomplete instance at $root was preserved; use its installed command or choose a fresh root with --root and a separate --command-dir." >&2; exit 1
  fi
  [[ -n $bundle ]] || bundle=$root
fi
if $move_bundle && { $existing || [[ -z $bundle ]]; }; then
  echo '--move-bundle requires a temporary unpacked bundle and a fresh instance.' >&2; exit 2
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
  # The normal repeat supplies the installed directory itself. A distinct
  # supplied bundle still requires an independent check of the installed files.
  if [[ ! $bundle -ef $root ]]; then verify_native_package "$root"; fi
  for file in data/admin_token data/agent_token data/instance_id certs/mitmproxy-ca.pem certs/mitmproxy-ca-cert.pem; do
    require_file "$root/$file"
  done
  if [[ $(uname -s) == Linux ]] && { $download_guest || [[ -n $platform_assets ]] || $runtime_override; }; then
    "$root/bin/safeyolo" --root "$root" host prepare ${host_arguments[@]+"${host_arguments[@]}"}
  fi
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
  guest_host_arguments=()
  [[ -z $guest_index ]] || guest_host_arguments+=(--index "$guest_index")
  if [[ $(uname -s) == Linux ]] && { $download_guest || [[ -n $platform_assets ]] || $runtime_override; }; then
    echo 'SafeYolo: checking and preparing the Linux host.' >&2
    "$bundle/bin/safeyolo" --root "$root" host prepare --package-root "$bundle" --installed-root "$root" \
      --write-settings "$staged_root/host-settings.toml" ${host_arguments[@]+"${host_arguments[@]}"}
    require_file "$staged_root/host-settings.toml"
    guest_host_arguments+=(--host-settings "$staged_root/host-settings.toml")
  fi
  # Only the public bootstrap transfers ownership of its disposable extraction.
  # Contributor and offline bundles remain reusable, as before.
  package_inputs=("$bundle/bin" "$bundle/libexec" "$bundle/assets")
  [[ ! -d $bundle/lib ]] || package_inputs+=("$bundle/lib")
  package_inputs+=("$bundle/package-info" "$bundle/SHA256SUMS" "$bundle/LICENSE" "$bundle/install.sh" "$bundle/install_native.sh" "$bundle/native_package.sh")
  if $move_bundle; then
    mv "${package_inputs[@]}" "$staged_root/"
  else
    cp -R "${package_inputs[@]}" "$staged_root/"
  fi
  if [[ -z $platform_assets ]] && $download_guest; then
    [[ ! -e $root/share && ! -L $root/share ]] || {
      echo "Guest inputs at $root/share were preserved. Supply them with --platform-assets or retain them with --no-guest-download." >&2; exit 1
    }
    echo 'SafeYolo: acquiring and verifying the compatible guest.' >&2
    platform_assets=$("$staged_root/bin/safeyolo" --root "$staged_root" guest acquire --package-info "$staged_root/package-info" --write-selection "$staged_root/guest-selection.json" ${guest_host_arguments[@]+"${guest_host_arguments[@]}"}) || {
      acquisition_status=$?
      echo 'Guest acquisition failed. No instance was activated. Completed host preparation remains as reported above. Retry after repairing the prerequisite; verified guest inputs remain reusable.' >&2; exit "$acquisition_status"
    }
    install_platform_assets "$platform_assets" "$staged_root/share"
    mv "$staged_root/guest-selection.json" "$staged_root/share/guest-selection.json"
  elif [[ -n $platform_assets ]]; then
    install_platform_assets "$platform_assets" "$staged_root/share"
  fi
  echo 'SafeYolo: initializing configuration, identity and trust.' >&2
  "$staged_root/bin/safeyolo" --root "$staged_root" init
  cat >> "$staged_root/config.toml" <<'EOF'
gateway_builtin_services_dir = "assets/services"
gateway_services_dir = "data/services"
EOF
  if [[ -f $staged_root/host-settings.toml ]]; then
    cat "$staged_root/host-settings.toml" >> "$staged_root/config.toml"
    rm "$staged_root/host-settings.toml"
  fi
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
  echo "SafeYolo will use sudo to create $command_dir if needed and link $command_entry to $command_target because your account cannot write $command_parent. Linux host preparation and guest extraction use sudo separately." >&2
fi
${command_install[@]+"${command_install[@]}"} mkdir -p "$command_dir"
if ! $existing; then
  echo "SafeYolo: activating the verified installation at $root." >&2
  mkdir -p "$root"
  if [[ $(uname -s) == Linux ]] && { $download_guest || [[ -n $platform_assets ]] || $runtime_override; }; then
    "$staged_root/bin/safeyolo" --root "$staged_root" host grant-runtime-access
  fi
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
