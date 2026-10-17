#!/bin/bash
# Independent Bristol entry. Reuse #889's local lock and observation recovery.
set -euo pipefail
umask 077
trusted=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
script=$trusted/tests/blackbox/hardware/run-vz.sh

if [[ ${1:-} = __execute ]]; then
    shift
    interpreter=$1; lock=$2; shift 2
    exec "$interpreter" -I -B -c '
import fcntl, os, sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    with open(sys.argv[3]+"/exit", "x") as stream: stream.write("2\n")
    raise SystemExit(2)
os.set_inheritable(descriptor, True)
os.execv("/bin/bash", ["/bin/bash", sys.argv[2], "__run", *sys.argv[3:]])
' "$lock" "$script" "$@"
fi
if [[ ${1:-} = __run ]]; then
    shift
    work=$1; controller=$2; digest=$3
    status=2
    save_exit() { trap - EXIT; printf '%s\n' "$status" > "$work/exit.tmp"; mv "$work/exit.tmp" "$work/exit"; }
    trap save_exit EXIT
    forward_signal() { kill -s "$1" %1 2>/dev/null || true; }
    trap 'forward_signal HUP' HUP
    trap 'forward_signal INT' INT
    trap 'forward_signal TERM' TERM
    set +e
    /bin/bash "$trusted/tests/blackbox/hardware/run-hardware-lane.sh" \
        "$work/source" "$controller" vz "$work/inputs" "$digest" "$work/reports" &
    child=$!
    while :; do
        wait "$child"; status=$?
        if jobs -pr | grep -Fxq "$child"; then continue; fi
        break
    done
    set -e
    exit "$status"
fi

source "${VZ_DEPLOYMENT_ENV:-/etc/safeyolo-hardware/vz.env}"
python=${HARDWARE_PYTHON:-python3}
root=${VZ_ATTEMPTS:?Set the trusted private attempt directory outside sy-agent authority}
publisher=$trusted/tests/blackbox/hardware/publish_results.py
ssh_command=(ssh -F "${VZ_SSH_CONFIG:?Set the existing sy-agent SSH configuration}" -o BatchMode=yes seatbelt-mac)
trigger=${1:-}; shift || true
selection=()
if [[ $trigger = on-demand ]]; then
    [[ $# = 2 && $1 =~ ^[0-9]+$ && $2 =~ ^sha256:[0-9a-f]{64}$ ]]
    selection=(--host-run "$1" --guest-index "$2")
elif [[ $trigger = overnight ]]; then
    [[ $# = 0 ]]
elif [[ $trigger = collect ]]; then
    [[ $# = 1 ]]
    attempt=$(cd -- "$1" && pwd -P)
else
    echo 'Usage: run-vz.sh overnight | on-demand HOST_RUN GUEST_INDEX | collect ATTEMPT' >&2
    exit 64
fi
if [[ $trigger != collect ]]; then
    attempt=$("$python" "$publisher" begin --root "$root" --lane vz --trigger "$trigger")
fi
printf 'Attempt: %s\n' "$attempt"
test "$(dirname "$attempt")" = "$(cd -- "$root" && pwd -P)"
run_id=$(jq -er .run_id "$attempt/attempt.json")
[[ $run_id =~ ^[0-9a-f]{32}$ && $(basename "$attempt") = "$run_id" ]]
test "$(jq -er .lane "$attempt/attempt.json")" = vz
controller=$(jq -er .controller_revision "$attempt/attempt.json")
work=${VZ_RUNS:-/Users/sy-agent/hw}/${run_id:0:8}
states=${VZ_STATES:-/Users/sy-agent/s}/${run_id:0:8}
status=2; stage=selection; cleanup=verified; launched=0
finish() {
    trap - EXIT
    if [[ $launched = 1 && ! -f $attempt/observed-exit ]]; then
        printf 'Local VZ outcome is unknown; inspect Bristol, then collect %s. Do not relaunch.\n' "$attempt" >&2
        exit 2
    fi
    options=(--attempt "$attempt" --exit "$status" --cleanup "$cleanup" --stage "$stage")
    if [[ -d $attempt/reports ]]; then options+=(--reports "$attempt/reports"); fi
    if "$python" "$publisher" finish "${options[@]}"; then :; else status=2; fi
    printf '%s\n' "$status" > "$attempt/exit"
    exit "$status"
}
trap finish EXIT
check_ports() {
    local command
    printf -v command '%q ' "$VZ_PYTHON" -I -B "$publisher" ports
    "${ssh_command[@]}" "$command"
}
if [[ $trigger != collect ]]; then
    "$python" "$trusted/scripts/select_blackbox_artifacts.py" --platform darwin-arm64 \
        --output "$attempt/inputs" --download-guest-archive "${selection[@]}" > "$attempt/selection-private.log" 2>&1
    input_digest=$("$python" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$attempt/inputs/selection.json")
    printf '%s\n' "$input_digest" > "$attempt/input-selection.sha256"
    stage=preflight
    test "$(uname -s)" = Darwin
    test "$(uname -m)" = arm64
    [[ $(sysctl -n hw.model) = Mac* ]]
    test "$(sysctl -n hw.optional.hypervisor)" = 1
    test "$("${ssh_command[@]}" 'hostname -s')" = "$(hostname -s)"
    check_ports > "$attempt/port-preflight-private.log" 2>&1
    # Only finished host/guest bytes and the pinned controller source move.
    # Test dependencies are preinstalled separately; Tart is not a nightly builder.
    git -C "$trusted" bundle create "$attempt/controller.bundle" HEAD
    tar -C "$attempt/inputs" -cf "$attempt/inputs.tar" selection.json safeyolo-darwin-arm64-production.tar.gz guest.tar.zst
    printf -v command 'set -euo pipefail; mkdir -p %q %q; mkdir -m 700 %q %q %q %q; printf %%s %q > %q; cat > %q' \
        "$(dirname "$work")" "$(dirname "$states")" "$work" "$states" "$work/source" "$work/inputs" "$run_id" "$work/owner" "$work/controller.bundle"
    stage=transfer
    "${ssh_command[@]}" "$command" < "$attempt/controller.bundle" > "$attempt/transfer-private.log" 2>&1
    printf -v command 'set -euo pipefail; tar -xf - -C %q; git -C %q init; git -C %q fetch %q HEAD; git -C %q checkout --detach FETCH_HEAD; ln -s %q %q; ln -s %q %q; printf "/.venv\\n/offline\\n" >> %q' \
        "$work/inputs" "$work/source" "$work/source" "$work/controller.bundle" "$work/source" \
        "${VZ_TEST_ENV:?Set the verified offline development Python environment}" "$work/source/.venv" \
        "${VZ_OFFLINE_TEST_INPUTS:?Set the verified architecture-matched guest test dependencies}" "$work/source/offline" "$work/source/.git/info/exclude"
    "${ssh_command[@]}" "$command" < "$attempt/inputs.tar" >> "$attempt/transfer-private.log" 2>&1
    env_options=(HOME=/Users/sy-agent USER=sy-agent PATH="${VZ_RUNTIME_PATH:?Set the verified offline runtime PATH}" LANG=C LC_ALL=C BASH_ENV=/dev/null
        SAFEYOLO_BLACKBOX_STATE_PARENT="$states" SAFEYOLO_GUEST_TEST_INPUTS=/workspace/offline
        SAFEYOLO_COORD_NATS_BINARY="${VZ_NATS_BINARY:?Set the verified offline NATS executable}"
        SAFEYOLO_VZ_TEST_RUNNER=/Users/sy-agent/bin/run-vz-test SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS="${VZ_HELPER_TIMEOUT:-120}")
    for name in SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS; do
        if declare -p "$name" >/dev/null 2>&1; then env_options+=("$name=${!name}"); fi
    done
    env_options+=(SSL_CERT_FILE="${SSL_CERT_FILE:-${VZ_CA_BUNDLE:?Set readable public CA trust}}" REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-$VZ_CA_BUNDLE}")
    printf -v command '%q ' env -i "${env_options[@]}" "$VZ_PYTHON" -I -B -c \
        'import json,subprocess,sys; sys.path.insert(0,sys.argv[1]); from process_identity import process_start_token; log=open(sys.argv[2]+"/runner-private.log","xb"); child=subprocess.Popen(sys.argv[3:],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True); open(sys.argv[2]+"/local.json","x").write(json.dumps({"pid":child.pid,"start_token":process_start_token(child.pid)}))' \
        "$trusted/tests/blackbox/harness" "$work" /bin/bash "$script" __execute "$VZ_PYTHON" \
        "${VZ_LOCK:?Set a protected host-local lock readable by sy-agent}" "$work" "$controller" "$input_digest"
    stage=execution; cleanup=unverified; launched=1
    "${ssh_command[@]}" "$command" > "$attempt/launch-private.log" 2>&1
else
    launched=1; cleanup=unverified
fi
limit=$((SECONDS + ${VZ_OBSERVER_TIMEOUT:-10800}))
printf -v command 'test -f %q && cat %q' "$work/exit" "$work/exit"
while (( SECONDS < limit )); do
    if "${ssh_command[@]}" "$command" > "$attempt/observed-exit.tmp" 2> "$attempt/observer-private.log"; then
        status=$(cat "$attempt/observed-exit.tmp")
        [[ $status =~ ^[0-9]+$ && $status -le 255 ]]
        mv "$attempt/observed-exit.tmp" "$attempt/observed-exit"
        break
    fi
    sleep 2
done
test -f "$attempt/observed-exit"
stage=cleanup; cleanup=failed
printf -v command '%q ' "$VZ_PYTHON" -I -B "$trusted/tests/blackbox/harness/macos_process_argv.py" --owned-roots 502 "$work" "$states"
"${ssh_command[@]}" "$command" > "$attempt/process-check-private.json" 2> "$attempt/process-check-private.log"
check_ports > "$attempt/port-check-private.log" 2>&1
cleanup=verified; stage=report
for name in retained-run.json selection.json installed-inputs.json guest/installed-sections.json; do
    mkdir -p "$attempt/reports/$(dirname "$name")"
    printf -v command '%q ' "$VZ_PYTHON" -I -B -c \
        'import os,stat,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); info=os.fstat(fd); assert stat.S_ISREG(info.st_mode) and info.st_size<=8388608; data=os.read(fd,8388609); assert len(data)<=8388608; sys.stdout.buffer.write(data)' \
        "$work/reports/$name"
    "${ssh_command[@]}" "$command" > "$attempt/reports/$name" 2> "$attempt/fetch-private.log"
done
stage=complete
exit "$status"
