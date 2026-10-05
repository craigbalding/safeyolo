#!/bin/bash
# Trusted devstack/rundeck cron entry. Candidate code runs only in its guest.
set -euo pipefail
umask 077
trusted=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
script=$trusted/tests/blackbox/hardware/run-kvm.sh
config=${KVM_DEPLOYMENT_ENV:-/etc/safeyolo-hardware/kvm.env}
source "$config"
python=${HARDWARE_PYTHON:-python3}
root=${KVM_ATTEMPTS:-/var/lib/rundeck/harness/evidence/issue889}
jobs=${HARNESS_JOBS:-/var/lib/rundeck/harness/jobs}
publisher=$trusted/tests/blackbox/hardware/publish_results.py

if [[ ${1:-} = overnight || ${1:-} = on-demand ]]; then
    trigger=$1; shift
    selection=()
    if [[ $trigger = on-demand ]]; then
        [[ $# = 1 && $1 =~ ^[0-9a-f]{40}$ ]] || { echo 'on-demand requires an operator-authorized full SHA' >&2; exit 64; }
        selection=(--authorized-commit "$1")
    else
        [[ $# = 0 ]] || exit 64
    fi
    mkdir -p "$root"
    # Selection and the discoverable index precede Rundeck dispatch.
    if ! attempt=$("$python" -I -B "$publisher" --begin kvm --root "$root" --trigger "$trigger" "${selection[@]}"); then
        printf 'Attempt: %s\n' "$attempt" >&2; exit 2
    fi
    printf 'Attempt: %s\n' "$attempt"
    printf 'exec env KVM_DEPLOYMENT_ENV=%q %q %q host %q\n' "$config" /bin/bash "$script" "$attempt" > "$attempt/rundeck-script.sh"
    credential=()
    if [[ -n ${RUNDECK_TOKEN_FILE:-} ]]; then credential=(--token-file "$RUNDECK_TOKEN_FILE"); fi
    "$python" -I -B "$trusted/tests/blackbox/hardware/service_calls.py" \
        --rundeck-url "${RUNDECK_URL:?Set the approved Rundeck service URL}" "${credential[@]}" \
        --script "$attempt/rundeck-script.sh" --receipt "$attempt/rundeck.json" \
        --output "$attempt/rundeck-private.log" --timeout-seconds "${KVM_OBSERVER_TIMEOUT:-10800}"
    # A Rundeck SUCCEEDED state alone is not a hardware pass. The host job
    # must have completed its own cleanup and read-back-verified publication.
    test -f "$attempt/exit"
    exit "$(cat "$attempt/exit")"
fi

[[ ${1:-} = host || ${1:-} = reconcile ]] && [[ $# = 2 ]] || {
    echo "Usage: $0 overnight | on-demand FULL_SHA | reconcile ATTEMPT_DIRECTORY" >&2; exit 64;
}
action=$1; attempt=$(cd -- "$2" && pwd -P)
test "$(dirname "$attempt")" = "$(cd -- "$root" && pwd -P)"
run_id=$(jq -er '.run_id' "$attempt/attempt.json")
[[ $run_id =~ ^[0-9a-f]{32}$ && $(basename "$attempt") = "$run_id" ]]
owner=issue889-$run_id
test "$(jq -er '.owner' "$attempt/attempt.json")" = "$owner"
test "$(jq -c '.required_lanes' "$attempt/attempt.json")" = '["kvm"]'
selected=$(jq -er '.source_revision' "$attempt/attempt.json")
lane_id=$(jq -er '.lanes.kvm.run_id' "$attempt/attempt.json")
[[ $selected =~ ^[0-9a-f]{40}$ && $lane_id =~ ^[0-9a-f]{32}$ ]]
source "$jobs/_common.sh"

cleanup_guest() {
    acquire_provision_lock || return
    local names leased='' guest='' paths
    names=$(virsh -c qemu:///system list --all --name) || return
    if [[ -f $(guest_lease_path) ]]; then IFS= read -r leased < "$(guest_lease_path)" || return; fi
    if [[ -f $attempt/guest-name ]]; then guest=$(cat "$attempt/guest-name"); fi
    if [[ $leased = sy-"$owner"-* ]]; then
        [[ -z $guest || $guest = "$leased" ]] || return 2
        guest=$leased
    fi
    if [[ -z $guest ]]; then
        # Provision can fail before its final receipt. Its early lease is
        # authoritative; without one, require exact-attempt absence.
        if printf '%s\n' "$names" | grep -F "sy-$owner-" >/dev/null; then return 2; fi
        local files=("$POOL_DIR/sy-$owner-"*.qcow2 "$POOL_DIR/sy-$owner-"*-seed.iso)
        for path in "${files[@]}"; do [[ ! -e $path && ! -L $path ]] || return 2; done
        return 0
    fi
    [[ $guest = sy-"$owner"-* ]] || return 2
    printf '%s\n' "$guest" > "$attempt/guest-name"
    if printf '%s\n' "$names" | grep -Fxq "$guest"; then
        paths=$(virsh -c qemu:///system domblklist "$guest" --details) || return
        while read -r type device target path; do
            [[ $type = file ]] || continue
            [[ $path = "$POOL_DIR/$guest.qcow2" || $path = "$POOL_DIR/$guest-seed.iso" ]] || return 2
        done <<< "$paths"
        if [[ $action = reconcile ]]; then
            # Stale reclamation is permitted only for an inactive exact owner.
            test "$(virsh -c qemu:///system domstate "$guest")" = 'shut off' || return 2
        fi
    fi
    bash "$jobs/teardown.sh" "$guest" > "$attempt/teardown-private.log" 2>&1 || return
    names=$(virsh -c qemu:///system list --all --name) || return
    if printf '%s\n' "$names" | grep -Fxq "$guest"; then return 2; fi
    [[ ! -e $POOL_DIR/$guest.qcow2 && ! -L $POOL_DIR/$guest.qcow2
       && ! -e $POOL_DIR/$guest-seed.iso && ! -L $POOL_DIR/$guest-seed.iso ]] || return 2
    if [[ -f $(guest_lease_path) ]]; then
        IFS= read -r leased < "$(guest_lease_path)" || return
        [[ $leased != "$guest" ]] || return 2
    fi
}

if [[ $action = reconcile ]]; then
    exec 9<>"$root/.kvm.lock"
    flock -n 9
    cleanup_guest
    printf 'Exact owned inactive guest, disk, seed and lease are absent. Original result is retained.\n'
    exit 0
fi
status=2; stage=preflight; allocated=0; cleanup=verified
finish() {
    trap - EXIT HUP INT TERM
    if [[ $allocated = 1 ]]; then
        cleanup=failed
        if cleanup_guest; then cleanup=verified; else status=2; stage=cleanup; fi
    fi
    options=(--attempt "$attempt" --finish --command-exit "$status" --cleanup "$cleanup")
    if [[ -n $stage ]]; then options+=(--failure-stage "$stage"); fi
    if [[ -f $attempt/installed-summary.json ]]; then options+=(--summary "$attempt/installed-summary.json"); fi
    if ! "$python" -I -B "$publisher" "${options[@]}"; then status=2; fi
    printf '%s\n' "$status" > "$attempt/exit"
    exit "$status"
}
test "$(jq -r '.finished_at' "$attempt/attempt.json")" = null
trap finish EXIT
# The local attempt holds this lock independently of its external observer.
# Provisioning has its own lifetime lock; its detached console must not inherit
# this attempt lock. Started SSH commands retain it until they finish.
touch "$root/.kvm.lock"
exec 9<>"$root/.kvm.lock"
if ! flock -n 9; then
    if [[ $(cat "$root/.kvm.lock") = "$run_id" ]]; then trap - EXIT; fi
    echo 'another local KVM invocation is active; do not redispatch this attempt' >&2
    exit 75
fi
printf '%s\n' "$run_id" > "$root/.kvm.lock"
# Wait for a started provisioner/SSH command naturally, including after a
# cancellation request. Never tear down while its descendants still hold locks.
cancelled=0
trap 'cancelled=129' HUP
trap 'cancelled=130' INT
trap 'cancelled=143' TERM
wait_child() {
    local child=$1 code
    while :; do
        set +e; wait "$child"; code=$?; set -e
        if jobs -pr | grep -Fxq "$child"; then continue; fi
        return "$code"
    done
}
test "$(uname -s)" = Linux
test "$(nproc)" -ge 4
test "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -ge 10485760
test "$(df -Pk "$POOL_DIR" | awk 'NR==2 {print $4}')" -ge 94371840
virsh -c qemu:///system domcapabilities --virttype kvm | grep -q '<domain>kvm</domain>'
bash "$jobs/list_guests.sh" > "$attempt/inventory-private.log"
stage=allocation; allocated=1
bash "$jobs/provision.sh" --scenario "$owner" --safeyolo-ref "$selected" \
    --flavor full --distro ubuntu --reuse --vcpus 4 --mem 10240 --disk 90 \
    9>&- > "$attempt/provision-private.log" 2>&1 &
if wait_child $!; then :; else status=$?; exit "$status"; fi
if [[ $cancelled != 0 ]]; then status=$cancelled; stage=cancelled; exit "$status"; fi
receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/provision-private.log" | tail -1)
guest=$(jq -er '.guest_name' <<< "$receipt"); ip=$(jq -er '.guest_ip' <<< "$receipt")
[[ $guest = sy-"$owner"-* && $ip = 192.168.122.100 ]]
printf '%s\n' "$guest" > "$attempt/guest-name"
virsh -c qemu:///system dumpxml "$guest" | grep -q "<domain type='kvm'"
wrapper=$(base64 -w0 < "$trusted/tests/blackbox/hardware/run-hardware-lane.sh")
printf -v command 'set -euo pipefail\ntest -r /dev/kvm && test -w /dev/kvm\npython3 -c %q\nwrapper=$(mktemp)\nprintf %%s %q | base64 -d > "$wrapper"\nbash "$wrapper" /home/agent/safeyolo %q kvm /home/agent/issue889-results --run-id %q\n' \
    'import os,fcntl; fd=os.open("/dev/kvm", os.O_RDWR); assert fcntl.ioctl(fd,0xAE00,0)==12; os.close(fd)' \
    "$wrapper" "$selected" "$lane_id"
stage=execution
bash "$jobs/ssh_exec.sh" "$ip" "$(printf '%s' "$command" | base64 -w0)" "${KVM_LANE_TIMEOUT:-7200}" \
    > "$attempt/execution-private.log" 2>&1 &
if wait_child $!; then :; else status=$?; exit "$status"; fi
receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/execution-private.log" | tail -1)
status=$(jq -er '.exit_code | select(type == "number" and . >= 0 and . <= 255)' <<< "$receipt")
test "$(jq -er '.timed_out | tostring' <<< "$receipt")" = false
stage=report
for name in installed-summary.json installed-sections.json; do
    bash "$jobs/ssh_fetch.sh" "$ip" "/home/agent/issue889-results/$name" 8388608 > "$attempt/fetch-private.log"
    receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/fetch-private.log" | tail -1)
    test "$(jq -er '.truncated | tostring' <<< "$receipt")" = false
    jq -er '.content_b64' <<< "$receipt" | base64 -d > "$attempt/$name"
    test "$(sha256sum "$attempt/$name" | cut -d' ' -f1)" = "$(jq -er '.sha256' <<< "$receipt")"
done
stage=''
if [[ $cancelled != 0 ]]; then status=$cancelled; stage=cancelled; fi
exit "$status"
