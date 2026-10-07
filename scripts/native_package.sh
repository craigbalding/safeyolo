#!/usr/bin/env bash
# Shared checks for the native bundle producer and the ordinary installer.

package_error() { echo "Native package: $*" >&2; return 1; }

host_platform() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) echo linux-amd64 ;;
    Linux-aarch64|Linux-arm64) echo linux-arm64 ;;
    Darwin-arm64) echo darwin-arm64 ;;
    *) package_error "unsupported host: $(uname -s)-$(uname -m)" ;;
  esac
}

file_sha256() {
  local digest
  if command -v sha256sum >/dev/null 2>&1; then digest=$(sha256sum "$1");
  else digest=$(shasum -a 256 "$1"); fi
  printf '%s\n' "${digest%% *}"
}

require_file() { [[ -f $1 ]] || package_error "required artifact is missing: $1"; }

native_executable() {
  local header platform=$2
  require_file "$1" || return
  [[ -x $1 ]] || { package_error "artifact is not executable: $1"; return 1; }
  header=$(od -An -tx1 -N20 "$1" | tr -d ' \n')
  case "$platform:$header" in
    linux-amd64:7f454c460201????????????????????????3e00|\
    linux-arm64:7f454c460201????????????????????????b700|\
    darwin-arm64:cffaedfe0c000001*) ;;
    *) package_error "artifact is not a $platform executable: $1" ;;
  esac
}

version_at_least() {
  local observed required index
  IFS=. read -r -a observed <<< "$1"
  IFS=. read -r -a required <<< "$2"
  for index in 0 1 2; do
    (( ${observed[index]:-0} >= ${required[index]:-0} )) || return 1
    (( ${observed[index]:-0} == ${required[index]:-0} )) || return 0
  done
}

verify_native_artifacts() {
  local host=$1 guest=$2 profile=$3 platform=$4 identity reference binary helper guest_platform digest
  native_executable "$host/safeyolo" "$platform" || return
  reference=$("$host/safeyolo" --version)
  case "$reference" in "safeyolo "*" commit="*" profile=$profile") ;; *) package_error 'CLI build profile is incorrect'; return 1;; esac
  for binary in safeyolo safeyolo-proxy safeyolo-coord; do
    native_executable "$host/$binary" "$platform" || return
    identity=$("$host/$binary" --version) || return
    [[ $identity == "$binary "* && ${identity#* commit=} == "${reference#* commit=}" ]] || {
      package_error "host source/profile identities differ: $binary"; return 1;
    }
  done
  case "$platform" in linux-amd64) guest_platform=linux-amd64;; *) guest_platform=linux-arm64;; esac
  for binary in safeyolo-guest safeyolo-coord; do
    helper=$guest/$binary
    native_executable "$helper" "$guest_platform" || return
    require_file "$helper.version" && require_file "$helper.sha256" || return
    identity=$(cat "$helper.version")
    [[ $identity == "$binary "* && ${identity#* commit=} == "${reference#* commit=}" ]] || {
      package_error "guest and host source/profile identities differ: $binary"; return 1;
    }
    digest=$(file_sha256 "$helper")
    [[ $digest == "$(cat "$helper.sha256")" ]] || { package_error "guest checksum differs: $binary"; return 1; }
    if [[ $(uname -s) == Linux && $("$helper" --version) != "$identity" ]]; then
      package_error "guest executable identity differs: $binary"; return 1
    fi
  done
}

verify_native_package() {
  local package=$1 key value source= profile= platform= minimum= identity binary
  require_file "$package/package-info" && require_file "$package/SHA256SUMS" || return
  while IFS='=' read -r key value; do
    case "$key" in
      source_commit) source=$value;; profile) profile=$value;; platform) platform=$value;; minimum_runtime) minimum=$value;;
      *) package_error "unknown package field: $key"; return 1;;
    esac
  done < "$package/package-info"
  [[ $source =~ ^[0-9a-f]{40}$ && $profile =~ ^(production|debug)$ ]] || { package_error 'invalid source/profile metadata'; return 1; }
  [[ $platform == "$(host_platform)" ]] || { package_error "package platform $platform differs from this host"; return 1; }
  [[ $minimum =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { package_error 'invalid minimum runtime'; return 1; }
  if [[ $platform == darwin-arm64 ]]; then
    version_at_least "$(sw_vers -productVersion)" "$minimum" || { package_error "requires macOS $minimum"; return 1; }
  else
    value=$(getconf GNU_LIBC_VERSION)
    version_at_least "${value#glibc }" "$minimum" || { package_error "requires glibc $minimum"; return 1; }
  fi
  for binary in safeyolo safeyolo-proxy safeyolo-coord; do
    native_executable "$package/bin/$binary" "$platform" || return
  done
  require_file "$package/bin/tmux" || return
  require_file "$package/bin/watch-backlog-factory" || return
  native_executable "$package/libexec/tmux" "$platform" || return
  for binary in guest-init guest-init-static guest-init-per-run guest-proxy-forwarder guest-shell-bridge guest-desktop guest-sudo; do
    require_file "$package/assets/guest/$binary" || return
  done
  for binary in tmux-common tmux-window tmux-pane; do
    require_file "$package/assets/launchers/$binary.sh" || return
  done
  (cd "$package"; if command -v sha256sum >/dev/null 2>&1; then sha256sum --check --status SHA256SUMS; else shasum -a 256 --check --status SHA256SUMS; fi) || {
    package_error 'bundle checksum verification failed'; return 1;
  }
  verify_native_artifacts "$package/bin" "$package/assets/guest" "$profile" "$platform" || return
  identity=$("$package/bin/safeyolo" --version)
  [[ ${identity#* commit=} == "$source profile=$profile" ]] || { package_error 'package source differs from executable'; return 1; }
  "$package/bin/tmux" -V >/dev/null || return
  if [[ $platform == darwin-arm64 ]]; then
    native_executable "$package/bin/safeyolo-vm" "$platform" || return
    native_executable "$package/bin/vsock-term" linux-arm64 || return
    require_file "$package/bin/vsock-term.version" && require_file "$package/bin/vsock-term.sha256" || return
    [[ $(cat "$package/bin/vsock-term.version") == "vsock-term commit=$source" ]] || { package_error 'guest terminal source differs'; return 1; }
    [[ $(file_sha256 "$package/bin/vsock-term") == "$(cat "$package/bin/vsock-term.sha256")" ]] || { package_error 'guest terminal checksum differs'; return 1; }
    local helper_profile=production
    [[ $profile != debug ]] || helper_profile=development
    "$package/bin/safeyolo-vm" verify --profile "$helper_profile" --source "$source" || return
  fi
  echo "Verified native package: $source $platform $profile"
}
