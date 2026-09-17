#!/usr/bin/env bash
# Run Cargo only while the target filesystem retains an operational reserve.
# CARGO_TARGET_DIR may point at an isolated candidate; otherwise ./target is used.
set -euo pipefail

reserve_gib=${SAFEYOLO_CARGO_RESERVE_GIB:-48}
poll_seconds=${SAFEYOLO_CARGO_SPACE_POLL_SECONDS:-15}

case $reserve_gib in ''|*[!0-9]*) echo 'SAFEYOLO_CARGO_RESERVE_GIB must be a whole number of GiB' >&2; exit 64;; esac
case $poll_seconds in ''|*[!0-9]*|0) echo 'SAFEYOLO_CARGO_SPACE_POLL_SECONDS must be a positive whole number' >&2; exit 64;; esac

# df needs an existing path. Walking parents makes a new isolated target work
# before Cargo has created it.
target_dir=${CARGO_TARGET_DIR:-"$PWD/target"}
probe=$target_dir
while [[ ! -e $probe ]]; do
  parent=$(dirname -- "$probe")
  [[ $parent != "$probe" ]] || break
  probe=$parent
done
reserve_kib=$((reserve_gib * 1024 * 1024))

check_space() {
  local available_kib
  available_kib=$(df -Pk -- "$probe" | awk 'NR == 2 { print $4 }')
  if [[ -z $available_kib || ! $available_kib =~ ^[0-9]+$ ]]; then
    echo "cannot determine free space for Cargo target filesystem: $probe" >&2
    return 1
  fi
  if (( available_kib < reserve_kib )); then
    echo "Cargo not started: ${available_kib} KiB free at $probe is below ${reserve_gib} GiB reserve" >&2
    return 1
  fi
}

check_space || exit 75

# A dedicated session lets the guard interrupt Cargo and every compiler child
# it owns without touching proxy, VM, container, or unrelated build jobs.
if ! command -v setsid >/dev/null 2>&1; then
  echo 'setsid is required to supervise Cargo disk-space reserve' >&2
  exit 69
fi
setsid cargo "$@" &
cargo_pid=$!
interrupted=0
cleanup() {
  if kill -0 "$cargo_pid" 2>/dev/null; then
    kill -INT -- "-$cargo_pid" 2>/dev/null || kill -INT "$cargo_pid" 2>/dev/null || true
  fi
}
trap 'cleanup; exit 130' INT TERM

while kill -0 "$cargo_pid" 2>/dev/null; do
  if ! check_space; then
    echo 'Cargo interrupted before the filesystem reserve was exhausted' >&2
    interrupted=1
    cleanup
    break
  fi
  sleep "$poll_seconds"
done

set +e
wait "$cargo_pid"
status=$?
set -e
if (( interrupted )); then
  exit 75
fi
exit "$status"
