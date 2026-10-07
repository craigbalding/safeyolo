#!/usr/bin/env bash
# Install the native bundle into a fresh instance root and initialize it once.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root= bundle= platform_assets=
build_arguments=()
while (($#)); do
  case "$1" in
    --root|--bundle|--platform-assets|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --bundle) bundle=$2;; --platform-assets) platform_assets=$2;;
        *) build_arguments+=("$option" "$2");;
      esac
      shift 2;;
    --help)
      echo 'Usage: install_native.sh --root ROOT [--bundle UNPACKED_BUNDLE] [--platform-assets DIRECTORY]'
      echo 'From source: scripts/install_native.sh --root ROOT --runtime-artifacts DIRECTORY [--artifacts HOST_BIN_DIRECTORY] [--guest-artifacts LINUX_BIN_DIRECTORY] [--vm-artifacts DIRECTORY] [--profile production|debug]'
      echo 'Installation checks the native bundle and creates configuration, trust and tokens internally. ROOT must be absent or empty. Prepared guest images are optional for proxy startup and required before agent start.'
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n $root ]] || { echo '--root is required; choose a fresh instance directory' >&2; exit 2; }
if [[ -e $root && ( ! -d $root || -n $(find "$root" -mindepth 1 -maxdepth 1 -print -quit) ) ]]; then
  echo 'Instance root is not empty; choose a fresh root' >&2; exit 1
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
cp -R "$bundle/bin" "$bundle/libexec" "$bundle/assets" "$root/"
if [[ -d $bundle/lib ]]; then cp -R "$bundle/lib" "$root/"; fi
cp "$bundle/package-info" "$bundle/SHA256SUMS" "$root/"
if [[ -n $platform_assets ]]; then
  mkdir -p "$root/share"
  if [[ $(uname -s) == Darwin ]]; then
    # APFS clones retain separate writable file identities without full copies.
    for asset in Image initramfs.cpio.gz rootfs-base.ext4; do cp -c "$platform_assets/$asset" "$root/share/$asset"; done
  else
    # The prepared tree retains its sandbox UID/GID ownership. The operator
    # supplies a reusable immutable tree; per-agent writable state is separate.
    ln -s "$(cd "$platform_assets/rootfs-tree" && pwd)" "$root/share/rootfs-tree"
  fi
fi
"$root/bin/safeyolo" --root "$root" init
cat >> "$root/config.toml" <<'EOF'
gateway_builtin_services_dir = "assets/services"
gateway_services_dir = "data/services"
EOF
mkdir -p "$root/data/services"
echo "Installed: $root/bin/safeyolo"
"$root/bin/safeyolo" --version
