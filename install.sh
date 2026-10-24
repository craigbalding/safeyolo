#!/usr/bin/env bash
# Downloaded bootstrap and contributor entry point share the packaged installer.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=${SAFEYOLO_CONFIG_DIR:-${SAFEYOLO_HOME:-$HOME/.safeyolo}}
release=
bundle=
stage=
host_pid= copy_pid= decode_pid= unpack_pid= guest_pid= download_pid= codex_pid=
download_guest=true
download_only=
install_arguments=()
launch=false
launch_arguments=()
while (($#)); do
  case "$1" in
    --launch)
      launch=true; shift
      launch_arguments=("$@")
      break;;
    --root|--release|--download-only)
      option=$1
      (($# >= 2)) || { echo "$option requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$option requires a nonempty value" >&2; exit 2; }
      case "$option" in
        --root) root=$2;; --release) release=$2;;
        --download-only) download_only=$2;;
      esac
      shift 2;;
    --bundle|--platform-assets|--command-dir|--artifacts|--guest-artifacts|--runtime-artifacts|--vm-artifacts|--profile|--system-runsc)
      (($# >= 2)) || { echo "$1 requires a value" >&2; exit 2; }
      [[ -n $2 ]] || { echo "$1 requires a nonempty value" >&2; exit 2; }
      [[ $1 != --bundle ]] || bundle=$2
      [[ $1 != --platform-assets ]] || download_guest=false
      install_arguments+=("$1" "$2"); shift 2;;
    --no-guest-download|--yes)
      [[ $1 != --no-guest-download ]] || download_guest=false
      install_arguments+=("$1"); shift;;
    --help)
      echo 'Usage: bash install-safeyolo.sh [--root DIRECTORY] [--release host-COMMIT] [--command-dir DIRECTORY] [--platform-assets DIRECTORY | --no-guest-download] [--system-runsc PATH] [--yes] [--launch [WORKSPACE] [AGENT_LAUNCH_OPTIONS...]]'
      echo 'Downloads the production host package from the official GitHub release and runs its installer. The default instance is HOME/.safeyolo (or SAFEYOLO_CONFIG_DIR). Repeat uses the installed package without checking Latest or upgrading.'
      echo 'Trust source: HTTPS from the official github.com/craigbalding/safeyolo release, including its install-safeyolo.sh bootstrap. Same-release SHA256SUMS checks integrity; it is not independent publisher authentication.'
      echo 'Ubuntu AMD64/ARM64 and Apple Silicon macOS use the same download-and-run route. No package manager or build toolchain is needed for host acquisition. Host preparation, runtime and first-agent launch must also be available in the selected release.'
      echo 'Contributor builds and --bundle, --platform-assets, --no-guest-download and --command-dir remain available from the source or unpacked bundle.'
      echo '--launch runs the installed agent launch operation after installation succeeds. Put installer options first; all arguments after --launch go to agent launch. Workspace defaults to the current directory, harness to Claude. Setup, workspace access, copied authentication and approvals retain their interactive host choices; --yes only accepts host preparation.'
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
libc_suffix=
if [[ $platform == linux-* ]]; then
  if ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
    runtime=$(ldd --version 2>&1) || true
    [[ $runtime == *'musl libc'* ]] || {
      echo 'Cannot identify the Linux host libc. Use a glibc or musl host.' >&2; exit 1
    }
    libc_suffix=-musl
  fi
fi
if [[ -n $release && ! $release =~ ^host-[0-9a-f]{40}$ ]]; then
  echo '--release must name an official host release: host- followed by its full commit.' >&2; exit 2
fi
[[ $root == /* ]] || root=$PWD/$root
install_and_launch() {
  "$@" --root "$root" ${install_arguments[@]+"${install_arguments[@]}"}
  if $launch; then
    if [[ -n $codex_pid ]]; then
      wait "$codex_pid" || echo 'SafeYolo: early Codex acquisition did not complete; the guest will use its ordinary installer.' >&2
      codex_pid=
    fi
    if [[ -n $stage && -f $stage/codex/version ]]; then
      # Keep this private handoff until setup consent lets launch move the
      # payload into the new agent home. Cleanup also covers refusal/failure.
      echo 'SafeYolo: launching the first agent from the installed instance.' >&2
      SAFEYOLO_CODEX_PACKAGE="$stage/codex" "$root/bin/safeyolo" --root "$root" agent launch ${launch_arguments[@]+"${launch_arguments[@]}"}
      return
    fi
    if [[ -n $stage ]]; then
      rm -rf -- "$stage"
      trap - EXIT
    fi
    echo 'SafeYolo: launching the first agent from the installed instance.' >&2
    exec "$root/bin/safeyolo" --root "$root" agent launch ${launch_arguments[@]+"${launch_arguments[@]}"}
  fi
}
start_codex_prefetch() {
  $launch && [[ -z $codex_pid ]] || return 0
  local index
  for ((index=0; index<${#launch_arguments[@]}; index++)); do
    if [[ ${launch_arguments[index]} == --harness && ${launch_arguments[index+1]:-} == codex ]]; then
      "$1" codex prefetch "$stage/codex" &
      codex_pid=$!
      return
    fi
  done
}
if [[ -n $download_only ]]; then
  [[ -n $release && -z $bundle && ${#install_arguments[@]} == 0 && $launch == false ]] || {
    echo '--download-only requires an explicit --release and no installation or launch options.' >&2; exit 2
  }
  [[ ! -e $download_only && ! -L $download_only ]] || { echo 'The download destination already exists.' >&2; exit 1; }
fi
if [[ -z $download_only && -f $repository/scripts/install_native.sh && -z $release ]]; then
  install_and_launch "$repository/scripts/install_native.sh"
  exit
fi
if [[ -n $bundle ]]; then
  install_and_launch "$bundle/install_native.sh"
  exit
fi
# Use the retained installer before any network request. Older or unrelated
# roots are preserved rather than converted or replaced with Latest.
if [[ -z $download_only ]] && [[ -e $root/config.toml || -L $root/config.toml || -e $root/policy.toml || -L $root/policy.toml || -e $root/data/admin_token ]]; then
  if [[ ! -f $root/install_native.sh || ! -f $root/native_package.sh ]]; then
    echo "Existing installation at $root was preserved. Use its installed command, or choose a separate --root and --command-dir; this installer does not convert older state." >&2
    exit 1
  fi
  if [[ -n $release ]] && ! grep -qx "source_commit=${release#host-}" "$root/package-info"; then
    echo "Release differs from the installed host at $root. Repeat is not an upgrade; use the installed command or a separate --root and --command-dir." >&2; exit 1
  fi
  install_and_launch "$root/install_native.sh" --bundle "$root"
  exit
fi
for tool in curl tar tee mkfifo; do
  command -v "$tool" >/dev/null || { echo "Host acquisition requires the standard $tool command; restore it and retry." >&2; exit 1; }
done
if command -v sha256sum >/dev/null; then
  archive_sha256() { local value; value=$(sha256sum "$1"); printf '%s\n' "${value%% *}"; }
else
  command -v shasum >/dev/null || { echo 'Host acquisition requires sha256sum or shasum; restore it and retry.' >&2; exit 1; }
  archive_sha256() { local value; value=$(shasum -a 256 "$1"); printf '%s\n' "${value%% *}"; }
fi
download() {
  local status=0
  curl --fail --location --show-error --silent --proto '=https' --proto-redir '=https' --output "$2" "$1" &
  download_pid=$!
  wait "$download_pid" || status=$?
  download_pid=
  if ((status != 0)); then
    echo "Host download failed: $1. Retry this command; partial files are not installed." >&2; return 1
  fi
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
name=safeyolo-$platform$libc_suffix-production
cache=${XDG_CACHE_HOME:-$HOME/.cache}/safeyolo/host-packages/$release
mkdir -p "$cache"
stage=$(mktemp -d "$cache/acquire.XXXXXX")
cleanup_acquisition() {
  local child
  for child in "$host_pid" "$copy_pid" "$decode_pid" "$unpack_pid" "$guest_pid" "$download_pid" "$codex_pid"; do
    if [[ -n $child ]]; then
      kill -TERM "$child" 2>/dev/null || true
      wait "$child" 2>/dev/null || true
    fi
  done
  # Restore directory access before descending into unchecked archive modes.
  # Do not follow links or change regular-file (including hard-link) modes.
  find -P "$stage" -type d -exec chmod u+rwx {} \;
  rm -rf -- "$stage"
}
trap cleanup_acquisition EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
base=https://github.com/craigbalding/safeyolo/releases/download/$release
echo "SafeYolo: acquiring $name from $release." >&2
download "$base/SHA256SUMS" "$stage/SHA256SUMS"
expected= count=0 guest_expected= guest_count=0
while IFS= read -r line || [[ -n $line ]]; do
  if [[ ${line:64} == "  $name.tar.gz" ]]; then
    expected=${line:0:64}; ((count += 1))
  fi
  if [[ ${line:64} == "  $name-guest-download.tar.gz" ]]; then
    guest_expected=${line:0:64}; ((guest_count += 1))
  fi
done < "$stage/SHA256SUMS"
[[ $count == 1 && $expected =~ ^[0-9a-f]{64}$ ]] || {
  echo "The release has no unique SHA-256 entry for $name.tar.gz. No package was installed." >&2; exit 1
}
archive=$cache/$name.tar.gz
if [[ ! -f $archive ]] || [[ $(archive_sha256 "$archive") != "$expected" ]]; then
  # Unpack into a separate private directory while receiving the archive.
  # Do not execute or source anything there until the release checksum passes.
  # The early CLI has its own verified archive and extraction directory.
  mkdir "$stage/host"
  mkfifo "$stage/host-input" "$stage/host-output"
  echo 'SafeYolo: downloading and unpacking the host package.' >&2
  # Own every PID: failure or interruption also reaps blocked FIFO readers.
  curl --fail --location --show-error --silent --proto '=https' --proto-redir '=https' \
    --output "$stage/host-input" "$base/$name.tar.gz" &
  host_pid=$!
  tee "$stage/$name.tar.gz" < "$stage/host-input" > "$stage/host-output" &
  copy_pid=$!
  if $download_guest && [[ -z $download_only && $guest_count != 0 ]]; then
    [[ $guest_count == 1 && $guest_expected =~ ^[0-9a-f]{64}$ ]] || {
      echo 'The release has no unique guest download package checksum. No package was installed.' >&2; exit 1
    }
    download "$base/$name-guest-download.tar.gz" "$stage/guest-download.tar.gz"
    [[ $(archive_sha256 "$stage/guest-download.tar.gz") == "$guest_expected" ]] || {
      echo 'Guest download package checksum failed. No package was installed.' >&2; exit 1
    }
    mkdir "$stage/early"
    tar -xzf "$stage/guest-download.tar.gz" -C "$stage/early"
    early=$stage/early/$name
    for field in "source_commit=${release#host-}" "profile=production" "platform=$platform"; do
      grep -qx "$field" "$early/package-info" || {
        echo "Guest download package differs from its release: $field. No package was installed." >&2; exit 1
      }
    done
    identity=$("$early/bin/safeyolo" --version)
    [[ ${identity#* commit=} == "${release#host-} profile=production" ]] || {
      echo 'Guest download executable differs from its release. No package was installed.' >&2; exit 1
    }
    start_codex_prefetch "$early/bin/safeyolo"
    echo 'SafeYolo: downloading the compatible guest while acquiring the host package.' >&2
    guest_arguments=()
    if "$early/bin/safeyolo" guest download --help | grep -q -- '--prepare'; then
      guest_arguments+=(--prepare)
    fi
    "$early/bin/safeyolo" guest download --package-info "$early/package-info" ${guest_arguments[@]+"${guest_arguments[@]}"} > "$stage/guest-index" &
    guest_pid=$!
  fi
  if [[ -n $guest_pid ]] && "$early/bin/safeyolo" host-package --help >/dev/null 2>&1; then
    mkfifo "$stage/host-tar"
    "$early/bin/safeyolo" host-package gunzip "$stage/host-output" > "$stage/host-tar" &
    decode_pid=$!
    tar -xf - -C "$stage/host" < "$stage/host-tar" &
  else
    # Older releases and paths without an early CLI retain standard tar/gzip.
    tar -xzf - -C "$stage/host" < "$stage/host-output" &
  fi
  unpack_pid=$!
  wait "$host_pid" || { echo 'Host download failed. No package was installed; retry this command.' >&2; exit 1; }
  host_pid=
  echo 'SafeYolo: verifying and unpacking the host package.' >&2
  wait "$copy_pid" || { echo 'Host archive could not be saved. No package was installed; retry this command.' >&2; exit 1; }
  copy_pid=
  if [[ -n $decode_pid ]]; then
    wait "$decode_pid" || { echo 'Host archive could not be decoded. No package was installed; retry this command.' >&2; exit 1; }
    decode_pid=
  fi
  wait "$unpack_pid" || { echo 'Host archive could not be unpacked. No package was installed; retry this command.' >&2; exit 1; }
  unpack_pid=
  [[ $(archive_sha256 "$stage/$name.tar.gz") == "$expected" ]] || {
    echo 'Host archive checksum failed. No package was installed. Retry to download verified bytes.' >&2; exit 1
  }
  mv "$stage/$name.tar.gz" "$archive"
  package=$stage/host/$name
else
  echo 'SafeYolo: reusing the verified host archive.' >&2
  echo 'SafeYolo: verifying and unpacking the host package.' >&2
  tar -xzf "$archive" -C "$stage"
  package=$stage/$name
fi
[[ -f $package/package-info && -f $package/install.sh ]] || { echo 'The host archive is incomplete; no package was installed.' >&2; exit 1; }
for field in "source_commit=${release#host-}" "profile=production" "platform=$platform"; do
  grep -qx "$field" "$package/package-info" || { echo "Host package differs from its release: $field. No package was installed." >&2; exit 1; }
done
for field in guest_compatibility guest_repository guest_discovery_tag; do
  grep -q "^$field=" "$package/package-info" || {
    echo "This host release lacks compatible guest acquisition metadata ($field). No instance was initialized. Use a host release that includes guest acquisition." >&2; exit 1
  }
done
if [[ -n $guest_pid ]]; then
  cmp -s "$early/package-info" "$package/package-info" && cmp -s "$early/bin/safeyolo" "$package/bin/safeyolo" || {
    echo 'Guest download inputs differ from the verified host package. No instance was activated.' >&2; exit 1
  }
  wait "$guest_pid" || { echo 'Guest acquisition failed. No instance was activated. Retry this command; verified inputs remain reusable.' >&2; exit 1; }
  guest_pid=
  guest_index=$(cat "$stage/guest-index")
  [[ $guest_index =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'Guest download did not return a verified index.' >&2; exit 1; }
  install_arguments+=(--guest-index "$guest_index")
fi
if [[ -n $download_only ]]; then
  source "$package/native_package.sh"
  verify_native_package "$package"
  mv "$package" "$download_only"
  echo "Downloaded SafeYolo package: $download_only"
  exit
fi
start_codex_prefetch "$package/bin/safeyolo"
# The ordinary installer performs the complete file/layout/executable check.
# Its private extraction can then become the installed files without a copy.
install_and_launch "$package/install.sh" --move-bundle
