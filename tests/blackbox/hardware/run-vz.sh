#!/bin/bash
# Trusted Bristol cron entry. Tart inputs are prepared for the selected commit.
set -euo pipefail
umask 077
trusted=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
script=$trusted/tests/blackbox/hardware/run-vz.sh

# These internal entries run confined, without selection/publication authority.
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
    work=$1; states=$2; selected=$3; digest=$4; interpreter=$5; deadline=$6; lane_id=$7
    status=2
    save_exit() { trap - EXIT; printf '%s\n' "$status" > "$work/exit.tmp"; mv "$work/exit.tmp" "$work/exit"; }
    trap save_exit EXIT
    # This local session is detached from SSH observers. Explicit cancellation
    # reaches only the retained shell job, whose runner owns child cleanup.
    forward_signal() {
        # A naturally exited job can disappear before this trap. Bash's job
        # identity cannot redirect a signal to an unrelated reused PID.
        kill -s "$1" %1 2>/dev/null || true
    }
    trap 'forward_signal HUP' HUP
    trap 'forward_signal INT' INT
    trap 'forward_signal TERM' TERM
    set +e
    /bin/bash "$trusted/tests/blackbox/hardware/run-hardware-lane.sh" \
        "$work/source" "$selected" vz "$work/results" --staged-inputs "$work/payload" \
        --staged-sha256 "$digest" --python "$interpreter" --state-parent "$states" \
        --run-id "$lane_id" --vz-test-runner /Users/sy-agent/bin/run-vz-test \
        --vz-test-timeout-seconds "$deadline" &
    child=$!
    while :; do
        wait "$child"; status=$?
        if jobs -pr | grep -Fxq "$child"; then continue; fi
        break
    done
    set -e
    exit "$status"
fi

config=${VZ_DEPLOYMENT_ENV:-/etc/safeyolo-hardware/vz.env}
source "$config"
python=${HARDWARE_PYTHON:-python3}
root=${VZ_ATTEMPTS:?Set a trusted Bristol attempt directory outside sy-agent authority}
publisher=$trusted/tests/blackbox/hardware/publish_results.py
ssh_command=(ssh -F "${VZ_SSH_CONFIG:?Set the existing sy-agent SSH configuration}" -o BatchMode=yes seatbelt-mac)
mkdir -p "$root"
trigger=${1:-}; shift || true
selection=()
if [[ $trigger = on-demand ]]; then
    [[ $# = 1 && $1 =~ ^[0-9a-f]{40}$ ]] || { echo 'on-demand requires an operator-authorized full SHA' >&2; exit 64; }
    selection=(--authorized-commit "$1")
elif [[ $trigger = overnight ]]; then
    [[ $# = 0 ]] || exit 64
elif [[ $trigger = collect ]]; then
    [[ $# = 1 ]] || exit 64
    attempt=$(cd -- "$1" && pwd -P)
    test "$(dirname "$attempt")" = "$(cd -- "$root" && pwd -P)"
else
    echo "Usage: $0 overnight | on-demand FULL_SHA | collect ATTEMPT_DIRECTORY" >&2; exit 64
fi
if [[ $trigger != collect ]]; then
    if ! attempt=$("$python" -I -B "$publisher" --begin vz --root "$root" --trigger "$trigger" "${selection[@]}"); then
        printf 'Attempt: %s\n' "$attempt" >&2; exit 2
    fi
fi
printf 'Attempt: %s\n' "$attempt"
run_id=$(jq -er '.run_id' "$attempt/attempt.json")
[[ $run_id =~ ^[0-9a-f]{32}$ && $(basename "$attempt") = "$run_id" ]]
test "$(jq -c '.required_lanes' "$attempt/attempt.json")" = '["vz"]'
selected=$(jq -er '.source_revision' "$attempt/attempt.json")
lane_id=$(jq -er '.lanes.vz.run_id' "$attempt/attempt.json")
[[ $selected =~ ^[0-9a-f]{40}$ && $lane_id =~ ^[0-9a-f]{32}$ ]]
work=${VZ_RUNS:-/Users/sy-agent/hw}/${run_id:0:8}
states=${VZ_STATES:-/Users/sy-agent/s}/${run_id:0:8}
status=2; stage=preflight; cleanup=verified; launched=0
finish() {
    trap - EXIT
    # A lost connection/deadline leaves local execution unknown. Preserve the
    # attempt and index for collect; never cancel or clean an unobserved child.
    if [[ $launched = 1 && ! -f $attempt/observed-exit ]]; then
        printf 'Local VZ attempt remains unknown; collect %s after inspecting Bristol.\n' "$attempt" >&2
        exit 2
    fi
    options=(--attempt "$attempt" --finish --command-exit "$status" --cleanup "$cleanup")
    if [[ -n $stage ]]; then options+=(--failure-stage "$stage"); fi
    if [[ -f $attempt/installed-summary.json ]]; then options+=(--summary "$attempt/installed-summary.json"); fi
    if [[ -f $attempt/input-index.sha256 ]]; then options+=(--input-index-sha256 "$(cat "$attempt/input-index.sha256")"); fi
    if ! "$python" -I -B "$publisher" "${options[@]}"; then status=2; fi
    printf '%s\n' "$status" > "$attempt/exit"
    exit "$status"
}
trap finish EXIT
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
[[ $(sysctl -n hw.model) = Mac* ]]
test "$(sysctl -n hw.optional.hypervisor)" = 1
check_ports() {
    local command
    printf -v command '%q ' "$VZ_PYTHON" -I -B -c \
        'import sys; sys.path.insert(0,sys.argv[1]); from installed_sections import check_vz_ports; assert not check_vz_ports(include_owner=True)' \
        "$trusted/tests/blackbox"
    "${ssh_command[@]}" "$command"
}
if [[ $trigger != collect ]]; then
    # A credential-free, commit-addressed Tart output is a deployment input.
    # Missing/currently pending inputs fail before any candidate code runs.
    input=${VZ_TART_INPUTS:?Set the directory containing verified Tart outputs}/$selected
    test "$(git -C "$input/source" rev-parse HEAD)" = "$selected"
    test -z "$(git -C "$input/source" status --porcelain)"
    digest=$(cat "$input/staged-sha256")
    [[ $digest =~ ^[0-9a-f]{64}$ ]]
    "$python" -I -B -c 'import hashlib,sys; assert hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()==sys.argv[2]' \
        "$input/payload/staged-inputs.json" "$digest"
    printf '%s\n' "$digest" > "$attempt/input-index.sha256"
    test "$("${ssh_command[@]}" 'hostname -s')" = "$(hostname -s)"
    check_ports > "$attempt/port-preflight-private.log" 2>&1
    # Bundle only source Git objects; do not transfer hooks or Git credentials.
    git -C "$input/source" bundle create "$attempt/source.bundle" HEAD
    printf -v command 'set -euo pipefail; mkdir -p %q %q; mkdir -m 700 %q %q %q; printf %%s %q > %q; tar -xf - -C %q; git -C %q init; git -C %q fetch %q HEAD; git -C %q checkout --detach FETCH_HEAD' \
        "$(dirname "$work")" "$(dirname "$states")" "$work" "$states" "$work/source" "$run_id" "$work/owner" "$work" "$work/source" "$work/source" "$work/source.bundle" "$work/source"
    stage=transfer
    # Both source and payload stay in the confined account. No control or
    # publication credential is present in this transfer or its environment.
    "$python" -I -B - "$input/payload" "$attempt/source.bundle" "$attempt/inputs.tar" <<'PY'
import json, tarfile, sys
from pathlib import Path
payload = Path(sys.argv[1]).resolve()
index = json.loads((payload / "staged-inputs.json").read_text())
with tarfile.open(sys.argv[3], "w") as archive:
    archive.add(sys.argv[2], arcname="source.bundle", recursive=False)
    for name in ("staged-inputs.json", *index["files"]):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("input archive path must stay within its payload")
        source = (payload / relative).resolve(strict=True)
        if not source.is_relative_to(payload) or not source.is_file():
            raise ValueError("input archive requires regular payload files")
        archive.add(source, arcname="payload/" + relative.as_posix(), recursive=False)
PY
    "${ssh_command[@]}" "$command" < "$attempt/inputs.tar" > "$attempt/transfer-private.log" 2>&1
    env_options=(HOME=/Users/sy-agent USER=sy-agent PATH="${VZ_RUNTIME_PATH:?Set the verified offline Python/uv PATH}" LANG=C LC_ALL=C BASH_ENV=/dev/null)
    for name in SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS; do
        if declare -p "$name" >/dev/null 2>&1; then env_options+=("$name=${!name}"); fi
    done
    env_options+=(SSL_CERT_FILE="${SSL_CERT_FILE:-${VZ_CA_BUNDLE:?Set usable public CA trust}}" REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-$VZ_CA_BUNDLE}")
    # This short local launcher detaches the execution session before its SSH
    # observer ends. The pinned script retains local exit/reports and a lock.
    printf -v command '%q ' env -i "${env_options[@]}" "${VZ_PYTHON:?Set the existing offline interpreter}" -I -B -c \
        'import json,subprocess,sys; sys.path.insert(0,sys.argv[1]+"/cli/src"); from safeyolo.runtime_identity import process_start_token; log=open(sys.argv[2]+"/runner-private.log","xb"); child=subprocess.Popen(sys.argv[3:],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True); open(sys.argv[2]+"/local.json","x").write(json.dumps({"pid":child.pid,"start_token":process_start_token(child.pid)}))' \
        "$trusted" "$work" /bin/bash "$script" __execute "$VZ_PYTHON" "${VZ_LOCK:?Set a protected host-local flock file readable by sy-agent}" \
        "$work" "$states" "$selected" "$digest" "$VZ_PYTHON" "${VZ_HELPER_TIMEOUT:-120}" "$lane_id"
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
# Read-only account inspection catches processes whose runtime markers vanished.
# The inspected paths belong to this retained run, and foreign processes survive.
printf -v command '%q ' "$VZ_PYTHON" -I -B "$trusted/tests/blackbox/harness/macos_process_argv.py" --owned-roots 502 "$work" "$states"
"${ssh_command[@]}" "$command" > "$attempt/process-check-private.json" 2> "$attempt/process-check-private.log"
check_ports > "$attempt/port-check-private.log" 2>&1
cleanup=verified; stage=report
for name in installed-summary.json installed-sections.json; do
    printf -v command '%q ' "$VZ_PYTHON" -I -B -c \
        'import os,stat,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); info=os.fstat(fd); assert stat.S_ISREG(info.st_mode) and info.st_size<=8388608; data=os.read(fd,8388609); assert len(data)<=8388608; sys.stdout.buffer.write(data)' \
        "$work/results/$name"
    "${ssh_command[@]}" "$command" > "$attempt/$name" 2> "$attempt/fetch-private.log"
done
stage=''
exit "$status"
