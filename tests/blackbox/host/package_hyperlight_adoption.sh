#!/usr/bin/env bash
# Run as UID 1000 in sy-239-clean-6728, the selected native Ubuntu x86_64 guest.
# Inputs are the retained packet, checker update and complete pinned gVisor root.
# This constructs a package; installation and factory adoption are separate steps.
set -euo pipefail
if (($# != 4)); then
  echo 'Usage: package_hyperlight_adoption.sh PACKET CHECKER_UPDATE GVISOR_ROOT NEW_OUTPUT_DIRECTORY' >&2
  exit 2
fi
packet=$(realpath "$1")
update=$(realpath "$2")
gvisor=$(realpath "$3")
output=$4
[[ $(uname -s)-$(uname -m) == Linux-x86_64 && $(id -u) == 1000 ]] || {
  echo 'Use the selected native Linux x86_64 UID1000 packaging venue.' >&2; exit 1;
}
[[ $(getconf GNU_LIBC_VERSION) == 'glibc 2.39' ]] || {
  echo 'The prepared GNU inputs require the selected glibc2.39 venue.' >&2; exit 1;
}
[[ ! -e $output && ! -L $output ]] || { echo 'Use a new output directory.' >&2; exit 1; }
printf '%s  %s\n' a744fe13c8f58d576def3786bb97a322606f88cdb19223cc5d47dfad3fe2000a "$packet" | sha256sum -c -
printf '%s  %s\n' b233a410eb20efd16d8013134d088c8e30f245bff1e0b5e3bc43f0a1eee95b81 "$update" | sha256sum -c -
umask 022
mkdir -p "$output"
output=$(realpath "$output")
mkdir "$output/inputs" "$output/diagnostics"
chmod 0700 "$output/diagnostics"
tar -xzf "$packet" -C "$output/inputs"
tar -xzf "$update" -C "$output/inputs"
inputs=$output/inputs/safeyolo-1552-b8272ea8
correction=$output/inputs/1552-f4275ba6-checker-update
source "$inputs/source/scripts/native_package.sh"
[[ $(git -C "$inputs/source" rev-parse HEAD) == b8272ea837a62240fec92a8f4e9263c2a650bbcd ]]
[[ -z $(git -C "$inputs/source" status --porcelain --untracked-files=all) ]]
# These four executables, including gvisor-bin, are the producer's complete set.
# An explicit binding prevents acquire_runsc.sh from starting a new Bazel build.
verify_runsc_payload "$gvisor" linux-amd64
cp -a "$inputs/runtime" "$output/runtime"
cp "$correction/"{service_checker.py,artifact_checker.py} "$output/runtime/"
cp "$correction/linux-x86_64/"*.json "$output/runtime/"
export SAFEYOLO_RUNSC_ARTIFACTS=$gvisor
"$inputs/source/scripts/build_host_packages.sh" --profile debug \
  --directory "$output/package" --artifacts "$inputs/bin" \
  --guest-artifacts "$inputs/guest" --runtime-artifacts /usr/bin \
  --hyperlight-artifacts "$output/runtime"
verify_native_package "$output/package"
printf 'native_source=%s\nchecker_source=%s\n' \
  b8272ea837a62240fec92a8f4e9263c2a650bbcd \
  f4275ba656f38a22b5215caab25217355dad04eb > "$output/diagnostics/selected-sources.txt"
echo "Package verified: $output/package"
