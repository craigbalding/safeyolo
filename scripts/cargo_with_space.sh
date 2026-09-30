#!/usr/bin/env bash
# Run Cargo only while the target filesystem retains an operational reserve.
# CARGO_TARGET_DIR may point at an isolated candidate; otherwise ./target is used.
set -euo pipefail

reserve_gib=${SAFEYOLO_CARGO_RESERVE_GIB:-20}
poll_seconds=${SAFEYOLO_CARGO_SPACE_POLL_SECONDS:-15}
hard_stop=${SAFEYOLO_CARGO_HARD_STOP:-0}
source_batch=${SAFEYOLO_CARGO_SOURCE_BATCH:-}

case $reserve_gib in ''|*[!0-9]*) echo 'SAFEYOLO_CARGO_RESERVE_GIB must be a whole number of GiB' >&2; exit 64;; esac
case $poll_seconds in ''|*[!0-9]*|0) echo 'SAFEYOLO_CARGO_SPACE_POLL_SECONDS must be a positive whole number' >&2; exit 64;; esac
case $hard_stop in 0|1) ;; *) echo 'SAFEYOLO_CARGO_HARD_STOP must be 0 or 1' >&2; exit 64;; esac
case $source_batch in
  ''|*[!A-Za-z0-9._-]*)
    if [[ -n $source_batch ]]; then
      echo 'SAFEYOLO_CARGO_SOURCE_BATCH may contain only letters, digits, dot, underscore, and hyphen' >&2
      exit 64
    fi
    ;;
esac

# df needs an existing path. Walking parents makes a new isolated target work
# before Cargo has created it.
target_dir=${CARGO_TARGET_DIR:-"$PWD/target"}

# Sensitivity tests can build an exact candidate and several source mutants in
# one Cargo target. When the caller names that batch, bind the target to one
# stable source tree by its canonical path and directory identity. This catches
# stale artifacts when a scratch tree is replaced at the same path. The wrapper
# does not create source trees or extra targets.
if [[ -n $source_batch ]]; then
  source_root_input=${SAFEYOLO_CARGO_SOURCE_ROOT:-$PWD}
  if [[ ! -d $source_root_input ]]; then
    echo 'Cargo source batch root is not a directory' >&2
    exit 64
  fi
  if ! source_root=$(cd -- "$source_root_input" 2>/dev/null && pwd -P); then
    echo 'Cargo source batch cannot resolve its source root' >&2
    exit 64
  fi
  source_cwd=$(pwd -P)
  case "$source_cwd/" in
    "$source_root/"*) ;;
    *)
      echo 'Cargo source batch must run beneath its selected source root' >&2
      exit 64
      ;;
  esac

  case "$(uname -s)" in
    Darwin) source_root_identity=$(stat -f '%d:%i' "$source_root" 2>/dev/null) || source_root_identity= ;;
    *) source_root_identity=$(stat -c '%d:%i' -- "$source_root" 2>/dev/null) || source_root_identity= ;;
  esac
  if [[ -z $source_root_identity ]]; then
    echo 'Cargo source batch cannot identify its source root' >&2
    exit 64
  fi

  if ! mkdir -p "$target_dir" 2>/dev/null; then
    echo 'Cargo source batch cannot initialize its target directory' >&2
    exit 64
  fi
  if ! target_dir=$(cd -- "$target_dir" 2>/dev/null && pwd -P); then
    echo 'Cargo source batch cannot resolve its target directory' >&2
    exit 64
  fi
  source_batch_file="$target_dir/.safeyolo-cargo-source-batch"
  if [[ -e $source_batch_file || -L $source_batch_file ]]; then
    if [[ ! -f $source_batch_file || -L $source_batch_file ]]; then
      echo 'Cargo target has malformed source-batch metadata' >&2
      exit 64
    fi
    if [[ ! -r $source_batch_file ]]; then
      echo 'Cargo target has unreadable source-batch metadata' >&2
      exit 64
    fi
    recorded_source_batch=()
    while IFS= read -r recorded_source_batch_line; do
      recorded_source_batch+=("$recorded_source_batch_line")
    done < "$source_batch_file"
    if [[ ${#recorded_source_batch[@]} -ne 3 \
      || ${recorded_source_batch[0]} != "$source_batch" \
      || ${recorded_source_batch[1]} != "$source_root" \
      || ${recorded_source_batch[2]} != "$source_root_identity" ]]; then
      echo 'Cargo target belongs to another source batch or source tree' >&2
      exit 64
    fi
  else
    if ! { printf '%s\n%s\n%s\n' "$source_batch" "$source_root" "$source_root_identity" > "$source_batch_file"; } 2>/dev/null; then
      echo 'Cargo source batch cannot record its target binding' >&2
      exit 64
    fi
  fi
fi

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
cargo_stop_grace_seconds=5

cargo_target_alive() {
  if (( process_group )); then
    # In setsid mode the process group is the owned Cargo target.  The leader
    # may exit while a child still owns Cargo's output pipes, so probe the
    # group instead of the leader PID.
    kill -0 -- "-$cargo_pid" 2>/dev/null
  else
    # Without setsid this is necessarily the narrower leader-only check.
    kill -0 "$cargo_pid" 2>/dev/null
  fi
}

signal_cargo() {
  local signal_number=$1
  if cargo_target_alive; then
    if (( process_group )); then
      kill -"$signal_number" -- "-$cargo_pid" 2>/dev/null || true
    else
      kill -"$signal_number" "$cargo_pid" 2>/dev/null || true
    fi
  fi
}

stop_cargo() {
  # Preserve Cargo's normal interrupt handling first, then make a timeout or
  # explicit emergency stop deterministic if Cargo (or one of its children)
  # does not exit.  The bounded wait is deliberately local to this wrapper;
  # it does not alter the reserve check or stop unrelated process groups.
  signal_cargo INT
  local attempts=0
  while cargo_target_alive && (( attempts < cargo_stop_grace_seconds * 10 )); do
    sleep 0.1
    ((attempts += 1))
  done
  if cargo_target_alive; then
    echo 'Cargo did not exit after interrupt; forcing its process group to stop' >&2
    signal_cargo KILL
  fi
  set +e
  wait "$cargo_pid"
  set -e
}

cleanup() {
  stop_cargo
}
trap 'cleanup; exit 130' INT TERM

while cargo_target_alive; do
  if ! check_space; then
    reserve_crossed=1
    if (( hard_stop )); then
      echo 'Cargo interrupted by explicit emergency disk-space stop' >&2
      interrupted=1
      cleanup
      break
    fi
    echo 'Cargo reserve crossed: finish this command, retire eligible reviewed targets, and do not dispatch another build batch' >&2
    while cargo_target_alive; do
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
