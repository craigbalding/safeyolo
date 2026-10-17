#!/usr/bin/env bash
# Prepare the installed native product, then run one maintained black-box selection.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(cd -- "$script_dir/../.." && pwd)
lane=${1:-}
[[ -n $lane ]] || { echo "Usage: $0 {systrap|kvm|vz|proxy} [--install-checkout DIRECTORY] [--prepare-only|--prepare-kvm-only] [run-tests.sh options]" >&2; exit 2; }
shift
checkout=$repository
if [[ ${1:-} == --install-checkout ]]; then
  [[ $# -ge 2 && -f $2/install.sh ]] || { echo '--install-checkout requires a source checkout' >&2; exit 2; }
  checkout=$(cd -- "$2" && pwd -P)
  shift 2
fi
prepare_only=false
prepare_kvm_only=false
case ${1:-} in
  --prepare-only) prepare_only=true; shift;;
  --prepare-kvm-only) prepare_kvm_only=true; shift;;
esac
case "$lane:$(uname -s)" in
  systrap:Linux|kvm:Linux|vz:Darwin|proxy:*) ;;
  *) echo "Unsupported black-box lane/host: $lane/$(uname -s)" >&2; exit 2;;
esac
if [[ $prepare_kvm_only == true && $lane != kvm ]]; then
  echo '--prepare-kvm-only requires the KVM lane' >&2; exit 2
fi
command -v uv >/dev/null || { echo 'uv is required for the Python test drivers' >&2; exit 2; }
# The installer prepares Linux host prerequisites. VZ and guest inputs are
# supplied by the owned test host.
root=${SAFEYOLO_CONFIG_DIR:?Set SAFEYOLO_CONFIG_DIR to a fresh disposable native installation}
if [[ $lane == systrap || $lane == kvm ]]; then export SAFEYOLO_RUNSC_PLATFORM=$lane; else unset SAFEYOLO_RUNSC_PLATFORM; fi
if [[ $prepare_kvm_only == true ]]; then
  "${SAFEYOLO_NATIVE_CLI:-$root/bin/safeyolo}" --root "$root" host prepare --yes
  echo 'KVM access prepared; no product installation or guest started'
  exit 0
fi
inputs=()
if [[ $lane != proxy ]]; then
  platform_assets=${SAFEYOLO_PLATFORM_ASSETS:-$checkout/guest/out}
  if [[ $lane == vz ]]; then
    for name in Image initramfs.cpio.gz rootfs-base.ext4; do
      [[ -f $platform_assets/$name ]] || { echo "Missing prepared VZ input: $platform_assets/$name" >&2; exit 2; }
    done
  else
    [[ -d $platform_assets/rootfs-tree ]] || { echo "Missing prepared Linux rootfs: $platform_assets/rootfs-tree" >&2; exit 2; }
    if [[ $lane == kvm ]]; then
      [[ -e /dev/kvm ]] || { echo 'KVM lane requires /dev/kvm' >&2; exit 2; }
    fi
  fi
  inputs+=(--platform-assets "$platform_assets")
else
  inputs+=(--no-guest-download)
fi
if [[ -n ${SAFEYOLO_NATIVE_BUNDLE:-} ]]; then
  inputs+=(--bundle "$SAFEYOLO_NATIVE_BUNDLE")
else
  runtime=${SAFEYOLO_NATIVE_RUNTIME_ARTIFACTS:-}
  if [[ -z $runtime ]]; then
    tmux=$(command -v tmux) || { echo 'Prepared native tmux runtime is required' >&2; exit 2; }
    runtime=$(dirname -- "$tmux")
  fi
  inputs+=(--runtime-artifacts "$runtime" --profile "${SAFEYOLO_BUILD_PROFILE:-production}")
  [[ -z ${SAFEYOLO_NATIVE_ARTIFACTS:-} ]] || inputs+=(--artifacts "$SAFEYOLO_NATIVE_ARTIFACTS")
  [[ -z ${SAFEYOLO_NATIVE_GUEST_ARTIFACTS:-} ]] || inputs+=(--guest-artifacts "$SAFEYOLO_NATIVE_GUEST_ARTIFACTS")
  [[ -z ${SAFEYOLO_NATIVE_VM_ARTIFACTS:-} ]] || inputs+=(--vm-artifacts "$SAFEYOLO_NATIVE_VM_ARTIFACTS")
fi
# This is the ordinary source entry, delegating to the accepted installer.
"$checkout/install.sh" --root "$root" --command-dir "$root/commands" --yes "${inputs[@]}"
# The separate test environment never publishes a product CLI.
(cd -- "$repository"; uv sync --frozen --group dev)
export SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT="$checkout"
export PATH="$root/bin:$root/libexec:$repository/.venv/bin:$PATH"
export PYTHONPATH="$repository/tests/reference:$repository${PYTHONPATH:+:$PYTHONPATH}"
if [[ $prepare_only == true ]]; then
  nats=()
  [[ -z ${SAFEYOLO_COORD_NATS_BINARY:-} ]] || nats+=(--binary "$SAFEYOLO_COORD_NATS_BINARY")
  if [[ $lane == vz ]]; then nats+=(--client-port 46370 --monitor-port 46372); fi
  safeyolo --root "$root" coord start ${nats[@]+"${nats[@]}"}
  safeyolo --root "$root" coord stop
  echo "Native product and $lane inputs prepared; no test guest started"
  exit 0
fi
if [[ $lane == proxy ]]; then
  exec "$script_dir/run-tests.sh" --proxy --rust-bin "$root/bin/safeyolo-proxy" "$@"
fi
exec "$script_dir/run-tests.sh" --expect-platform "$lane" "$@"
