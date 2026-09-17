#!/usr/bin/env bash
# Run Cargo only while the target filesystem retains an operational reserve.
# CARGO_TARGET_DIR may point at an isolated candidate; otherwise ./target is used.
set -euo pipefail

reserve_gib=${SAFEYOLO_CARGO_RESERVE_GIB:-20}
poll_seconds=${SAFEYOLO_CARGO_SPACE_POLL_SECONDS:-15}
hard_stop=${SAFEYOLO_CARGO_HARD_STOP:-0}

case $reserve_gib in ''|*[!0-9]*) echo 'SAFEYOLO_CARGO_RESERVE_GIB must be a whole number of GiB' >&2; exit 64;; esac
case $poll_seconds in ''|*[!0-9]*|0) echo 'SAFEYOLO_CARGO_SPACE_POLL_SECONDS must be a positive whole number' >&2; exit 64;; esac
case $hard_stop in 0|1) ;; *) echo 'SAFEYOLO_CARGO_HARD_STOP must be 0 or 1' >&2; exit 64;; esac

# df needs an existing path. Walking parents makes a new isolated target work
# before Cargo has created it.
target_dir=${CARGO_TARGET_DIR:-"$PWD/target"}
probe=$target_dir
case "$(uname -s)" in
  Darwin)
    df_command=(df -Pk)
    dirname_command=(dirname)
    ;;
  *)
    df_command=(df -Pk --)
    dirname_command=(dirname --)
    ;;
esac
while [[ ! -e $probe ]]; do
  parent=$("${dirname_command[@]}" "$probe")
  [[ $parent != "$probe" ]] || break
  probe=$parent
done
reserve_kib=$((reserve_gib * 1024 * 1024))

check_space() {
  local available_kib
  available_kib=$("${df_command[@]}" "$probe" | awk 'NR == 2 { print $4 }')
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

# A dedicated session permits an explicit emergency stop without touching proxy,
# VM, container, or unrelated build jobs. Normal reserve crossings finish the
# current Cargo command and make the wrapper stop a subsequent batch instead.
# Hosts without setsid run Cargo in the current session and report the narrower
# emergency-stop behavior below.
process_group=0
if command -v setsid >/dev/null 2>&1; then
  process_group=1
  setsid cargo "$@" &
else
  echo 'setsid unavailable: Cargo runs without a dedicated process group; SAFEYOLO_CARGO_HARD_STOP=1 signals Cargo only and may leave child processes running' >&2
  ( trap - INT; exec cargo "$@" ) &
fi
cargo_pid=$!
interrupted=0
reserve_crossed=0
cleanup() {
  if kill -0 "$cargo_pid" 2>/dev/null; then
    if (( process_group )); then
      kill -INT -- "-$cargo_pid" 2>/dev/null || kill -INT "$cargo_pid" 2>/dev/null || true
    else
      kill -INT "$cargo_pid" 2>/dev/null || true
    fi
  fi
}
trap 'cleanup; exit 130' INT TERM

while kill -0 "$cargo_pid" 2>/dev/null; do
  if ! check_space; then
    reserve_crossed=1
    if (( hard_stop )); then
      echo 'Cargo interrupted by explicit emergency disk-space stop' >&2
      interrupted=1
      cleanup
      break
    fi
    echo 'Cargo reserve crossed: finish this command, retire eligible reviewed targets, and do not dispatch another build batch' >&2
    while kill -0 "$cargo_pid" 2>/dev/null; do
      sleep "$poll_seconds"
    done
    break
  fi
  sleep "$poll_seconds"
done

set +e
wait "$cargo_pid"
status=$?
set -e
if (( interrupted || reserve_crossed )); then
  exit 75
fi
exit "$status"
