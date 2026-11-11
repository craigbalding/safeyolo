#!/usr/bin/env bash
# Physical macOS snapshot probe using a shared read-only base and owned overlay.
#
# Run on an allocated Apple Silicon host, from this checkout, with a signed
# source-compatible helper, an extracted standard guest (Image,
# initramfs.cpio.gz, rootfs-base.ext4), and public staged guest assets.
# RUN_DIR must not exist and must be on disk. Capture needs room for 1 GiB
# of saved memory and two 256 MiB overlays; full needs two memory images and
# five overlays. Inputs are read only; all writes stay in RUN_DIR.
#
# Usage: snapshot-smoke.sh capture-only|full HELPER GUEST_DIR ASSETS_DIR RUN_DIR
# Set SAFEYOLO_VZ_TEST_RUNNER to the maintained run-vz-test wrapper on Bristol.
# capture-only saves at the static gate, then observes real cron/at startup
# and queued jobs after opening that gate. It never attempts memory restore.
# full additionally restores a COPY of the paired overlay, saves again to prove
# the restored VM runs, and checks a memory fingerprint refusal (exit 75).
# A full run needs separate restore authority and a working VZ recipient.
# Logs, snapshots and failure state remain in RUN_DIR after owned cleanup.
set -euo pipefail
umask 077

if [[ $# != 5 || ( "$1" != capture-only && "$1" != full ) ]]; then
    echo "Usage: $0 capture-only|full HELPER GUEST_DIR ASSETS_DIR RUN_DIR" >&2
    exit 64
fi
MODE=$1
HELPER=$2
GUEST=$3
ASSETS=$4
RUN=$5
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
HELPER=$(cd "$(dirname "$HELPER")" && printf '%s/%s' "$PWD" "$(basename "$HELPER")")
GUEST=$(cd "$GUEST" && pwd -P)
ASSETS=$(cd "$ASSETS" && pwd -P)
RUNNER=${SAFEYOLO_VZ_TEST_RUNNER:-}
TIMEOUT=${SAFEYOLO_SNAPSHOT_TIMEOUT_SECONDS:-120}
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || exit 64
[[ -x "$HELPER" ]] || { echo "Missing executable: $HELPER" >&2; exit 1; }
for path in "$GUEST/Image" "$GUEST/initramfs.cpio.gz" "$GUEST/rootfs-base.ext4" \
    "$ASSETS/guest-init" "$ASSETS/guest-init-static" "$ASSETS/guest-init-per-run" "$ASSETS/safeyolo-guest"; do
    [[ -r "$path" ]] || { echo "Missing input: $path" >&2; exit 1; }
done
[[ -z "$RUNNER" || -x "$RUNNER" ]] || { echo "Missing runner: $RUNNER" >&2; exit 1; }
mkdir -m 700 "$RUN"  # Refuse to overwrite a previous or uncertain attempt.
RUN=$(cd "$RUN" && pwd -P)
echo "Retained results: $RUN"
PROCESS_PID=
HELPER_PID=
LOG=

running() { jobs -pr | grep -qx "$PROCESS_PID"; }

stop_owned() {
    [[ -n "$PROCESS_PID" ]] || return 0
    if running; then
        kill -TERM "$PROCESS_PID"
        local deadline=$((SECONDS + 12))
        while running && (( SECONDS < deadline )); do sleep 0.1; done
        if running; then
            # The maintained runner normally reaps its child within nine seconds.
            # Keep the saved inputs if that cleanup contract fails.
            echo "Owned runner did not finish cleanup: $PROCESS_PID (helper $HELPER_PID)" >&2
            return 1
        fi
    fi
    local rc=0
    wait "$PROCESS_PID" || rc=$?
    printf 'runner=%s helper=%s exit=%s reaped=yes\n' "$PROCESS_PID" "$HELPER_PID" "$rc" >> "$RUN/cleanup.log"
    PROCESS_PID=
    HELPER_PID=
}

cleanup() {
    local rc=$?
    trap - EXIT
    stop_owned || rc=1
    printf 'exit=%s\n' "$rc" > "$RUN/exit"
    echo "Probe exit $rc; inputs and logs retained at $RUN"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "FAIL: $*; inspect $RUN" >&2
    [[ -z "$LOG" ]] || tail -20 "$LOG" >&2
    exit 1
}

wait_for() {
    local label=$1
    shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@"; do
        [[ ! -f "$RUN/status/probe.failed" ]] || fail "guest scheduling probe failed"
        running || fail "helper exited while waiting for $label"
        (( SECONDS < deadline )) || fail "deadline waiting for $label"
        sleep 0.1
    done
}

mkdir "$RUN/config" "$RUN/status" "$RUN/home" "$RUN/workspace"
# These disposable shares must be writable by guest uid 1000 through VirtioFS.
chmod 0777 "$RUN/status" "$RUN/home" "$RUN/workspace"
for name in guest-init guest-init-static guest-init-per-run safeyolo-guest \
    guest-proxy-forwarder guest-shell-bridge guest-sudo guest-desktop; do
    if [[ -f "$ASSETS/$name" ]]; then
        cp "$ASSETS/$name" "$RUN/config/$name"
        chmod 0755 "$RUN/config/$name"
    fi
done
mv "$RUN/config/guest-init-static" "$RUN/config/guest-init-static-original"
cat > "$RUN/config/guest-init-static" <<'STATIC'
#!/bin/bash
set -e
/safeyolo/guest-init-static-original
# Test instrumentation only; the normal orchestrator still owns its gate.
/bin/bash /safeyolo/snapshot-scheduling.sh > /safeyolo-status/probe.log 2>&1 &
STATIC
chmod 0755 "$RUN/config/guest-init-static"
cp "$SCRIPT_DIR/snapshot-scheduling.sh" "$RUN/config/snapshot-scheduling.sh"
printf 'SAFEYOLO_DETACH=1\nTZ=UTC\n' > "$RUN/config/agent.env"
printf 'snapshot-smoke\n' > "$RUN/config/agent-name"
# The initramfs formats this new, sparse upper disk. Never copy a used spool.
dd if=/dev/zero of="$RUN/overlay.ext4" bs=1 count=0 seek=268435456 2> "$RUN/overlay-create.log"
shasum -a 256 "$HELPER" "$GUEST/Image" "$GUEST/initramfs.cpio.gz" \
    "$GUEST/rootfs-base.ext4" "$RUN/config/"* > "$RUN/inputs.sha256"
"$HELPER" version > "$RUN/helper-version.txt"
uname -a > "$RUN/host.txt"
id >> "$RUN/host.txt"

BASE_ARGS=(run --kernel "$GUEST/Image" --initrd "$GUEST/initramfs.cpio.gz"
    --rootfs "$GUEST/rootfs-base.ext4" --cpus 2
    --cmdline 'console=hvc0 root=/dev/vda rw quiet')
for name in config status home workspace; do
    mode=rw
    [[ "$name" != config ]] || mode=ro
    BASE_ARGS+=(--share "$RUN/$name:$name:$mode")
done

start_helper() {
    local phase=$1 overlay=$2
    shift 2
    LOG="$RUN/$phase-helper.log"
    local command=("$HELPER" "${BASE_ARGS[@]}" --memory 1024 --overlay "$overlay"
        --serial-log "$RUN/$phase-serial.log" "$@")
    printf '%q ' "${command[@]}" > "$RUN/$phase-command.txt"
    printf '\n' >> "$RUN/$phase-command.txt"
    if [[ -n "$RUNNER" ]]; then
        "$RUNNER" --timeout-seconds "$((TIMEOUT * 4))" -- "${command[@]}" </dev/null > "$LOG" 2>&1 &
    else
        "${command[@]}" </dev/null > "$LOG" 2>&1 &
    fi
    PROCESS_PID=$!
    HELPER_PID=$PROCESS_PID
    if [[ -n "$RUNNER" ]]; then
        wait_for 'owned helper child' find_helper
    fi
    printf 'runner=%s helper=%s\n' "$PROCESS_PID" "$HELPER_PID" >> "$RUN/pids.txt"
}

find_helper() {
    local child
    child=$(pgrep -P "$PROCESS_PID" -x safeyolo-vm) || return 1
    [[ "$child" =~ ^[0-9]+$ ]] || return 1
    HELPER_PID=$child
}

saved() {
    [[ -s "$1" && -s "$1.meta.json" && -s "$1.overlay" ]] &&
        grep -Fq "Snapshot written to $1 (overlay cloned to $1.overlay)" "$LOG"
}

snapshot() {
    # Recheck wrapper ownership immediately before signaling its helper.
    [[ -z "$RUNNER" ]] || find_helper || fail 'owned helper child missing'
    kill -USR1 "$HELPER_PID"
    wait_for 'completed save, sidecar and paired overlay' saved "$1"
}

quiet_after() {
    local tick
    [[ -s "$RUN/status/quiet-ticks" ]] || return 1
    read -r tick < "$RUN/status/quiet-ticks"
    [[ "$tick" =~ ^[0-9]+$ ]] && (( tick > $1 ))
}

release_gate() {
    [[ ! -e "$RUN/config/per-run-go" && ! -e "$RUN/status/per-run-started" ]] || fail 'per-run began before release'
    cp "$RUN/status/queued.txt" "$RUN/$1-queued.txt"
    cp "$RUN/status/quiet-ticks" "$RUN/$1-quiet-ticks"
    touch "$RUN/config/per-run-go"
    wait_for 'per-run initialization' test -s "$RUN/status/per-run-started"
    wait_for 'daemon-fired canaries and guest queue cleanup' test -s "$RUN/status/probe.done"
    cp "$RUN/status/jobs" "$RUN/$1-jobs.txt"
    cp "$RUN/status/daemons" "$RUN/$1-daemons.txt"
    stop_owned || fail 'owned cleanup failed'
}

SNAP="$RUN/capture.snap"
start_helper capture "$RUN/overlay.ext4" --snapshot-on-signal "$SNAP"
wait_for 'static initialization' test -s "$RUN/status/static-init-done"
wait_for 'queued canaries with schedulers absent' test -s "$RUN/status/probe.ready"
snapshot "$SNAP"
# A new guest sample after save completion proves the resumed producer stays quiet.
read -r before < "$RUN/status/quiet-ticks"
wait_for 'post-save scheduler observation with gate absent' quiet_after "$before"
shasum -a 256 "$SNAP.overlay" > "$RUN/paired-overlay.sha256"
release_gate capture
echo 'Capture completed; schedulers stayed quiet until gate release, then both jobs ran.'

if [[ "$MODE" = full ]]; then
    # Every restore receives a fresh copy. The paired overlay is reusable input.
    cp "$SNAP.overlay" "$RUN/restore.overlay.ext4"
    rm "$RUN/config/per-run-go" "$RUN/status/per-run-started" "$RUN/status/probe.done" "$RUN/status/jobs"
    start_helper restore "$RUN/restore.overlay.ext4" --restore-from "$SNAP" --snapshot-on-signal "$RUN/liveness.snap"
    read -r before < "$RUN/status/quiet-ticks"
    wait_for 'restored guest sample' quiet_after "$before"
    snapshot "$RUN/liveness.snap"
    release_gate restore
    cp "$SNAP.overlay" "$RUN/boundary.overlay.ext4"
    command=("$HELPER" "${BASE_ARGS[@]}" --overlay "$RUN/boundary.overlay.ext4"
        --memory 2048 --restore-from "$SNAP")
    printf '%q ' "${command[@]}" > "$RUN/fingerprint-command.txt"
    printf '\n' >> "$RUN/fingerprint-command.txt"
    if [[ -n "$RUNNER" ]]; then
        "$RUNNER" --timeout-seconds "$TIMEOUT" -- "${command[@]}" > "$RUN/fingerprint.log" 2>&1 &
    else
        "${command[@]}" > "$RUN/fingerprint.log" 2>&1 &
    fi
    PROCESS_PID=$!
    HELPER_PID=
    deadline=$((SECONDS + TIMEOUT))
    while running; do
        (( SECONDS < deadline )) || fail 'deadline waiting for fingerprint refusal'
        sleep 0.1
    done
    rc=0
    wait "$PROCESS_PID" || rc=$?
    printf 'runner=%s exit=%s reaped=yes\n' "$PROCESS_PID" "$rc" >> "$RUN/cleanup.log"
    PROCESS_PID=
    [[ "$rc" = 75 ]] && grep -Fq 'snapshot/host hardware fingerprint mismatch (memoryMB=' "$RUN/fingerprint.log" || fail 'expected memory fingerprint refusal and exit 75'
    echo 'Memory restore, second completed save and memory fingerprint refusal passed.'
fi
shasum -a 256 -c "$RUN/paired-overlay.sha256" > "$RUN/paired-overlay-check.txt"
shasum -a 256 -c "$RUN/inputs.sha256" > "$RUN/inputs-check.txt"
