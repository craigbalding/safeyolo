#!/bin/bash
# Independent devstack/rundeck entry; only retained artifacts enter the guest.
# Ownership/lease teardown is reused from #889 source 4fc6e11c.
set -euo pipefail
umask 077
trusted=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
source "${KVM_DEPLOYMENT_ENV:-/etc/safeyolo-hardware/kvm.env}"
python=${HARDWARE_PYTHON:-python3}
root=${KVM_ATTEMPTS:-/var/lib/rundeck/harness/evidence/issue889}
jobs=${HARNESS_JOBS:-/var/lib/rundeck/harness/jobs}
publisher=$trusted/tests/blackbox/hardware/publish_results.py
source "$jobs/_common.sh"
action=${1:-}; shift || true
selection=()
if [[ $action = overnight || $action = on-demand ]]; then
    if [[ $action = overnight ]]; then [[ $# = 0 ]];
    else
        [[ $# = 2 && $1 =~ ^[0-9]+$ && $2 =~ ^sha256:[0-9a-f]{64}$ ]]
        selection=(--host-run "$1" --guest-index "$2")
    fi
    attempt=$("$python" "$publisher" begin --root "$root" --lane kvm --trigger "$action")
else
    [[ $action = reconcile && $# = 1 ]] || { echo 'Usage: run-kvm.sh overnight | on-demand HOST_RUN GUEST_INDEX | reconcile ATTEMPT' >&2; exit 64; }
    attempt=$(cd -- "$1" && pwd -P)
fi
printf 'Attempt: %s\n' "$attempt"
test "$(dirname "$attempt")" = "$(cd -- "$root" && pwd -P)"
run_id=$(jq -er .run_id "$attempt/attempt.json")
[[ $run_id =~ ^[0-9a-f]{32}$ && $(basename "$attempt") = "$run_id" ]]
owner=issue889-$run_id
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
    echo 'Exact owned inactive guest, disk, seed and lease are absent. Original result is retained.'
    exit 0
fi
status=2; stage=selection; allocated=0; cleanup=verified
finish() {
    trap - EXIT HUP INT TERM
    if [[ $allocated = 1 ]]; then
        cleanup=failed
        if cleanup_guest; then cleanup=verified; else status=2; stage=cleanup; fi
    fi
    options=(--attempt "$attempt" --exit "$status" --cleanup "$cleanup" --stage "$stage")
    if [[ -d $attempt/reports ]]; then options+=(--reports "$attempt/reports"); fi
    if "$python" "$publisher" finish "${options[@]}"; then :; else status=2; fi
    printf '%s\n' "$status" > "$attempt/exit"
    exit "$status"
}
trap finish EXIT
touch "$root/.kvm.lock"
exec 9<>"$root/.kvm.lock"
flock -n 9
printf '%s\n' "$run_id" > "$root/.kvm.lock"
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
"$python" "$trusted/scripts/select_blackbox_artifacts.py" --platform linux-amd64 \
    --output "$attempt/inputs" --download-guest-archive "${selection[@]}" > "$attempt/selection-private.log" 2>&1
if [[ $cancelled != 0 ]]; then status=$cancelled; stage=execution; exit "$status"; fi
controller=$(jq -er .controller_revision "$attempt/attempt.json")
input_digest=$(sha256sum "$attempt/inputs/selection.json" | cut -d' ' -f1)
stage=preflight
test "$(uname -s)" = Linux
test "$(nproc)" -ge 4
test "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -ge 10485760
test "$(df -Pk "$POOL_DIR" | awk 'NR==2 {print $4}')" -ge 94371840
virsh -c qemu:///system domcapabilities --virttype kvm | grep -q '<domain>kvm</domain>'
bash "$jobs/list_guests.sh" > "$attempt/inventory-private.log"
stage=allocation; allocated=1
# The harness full flavor builds SafeYolo. Bare has no product installation.
bash "$jobs/provision.sh" --scenario "$owner" --flavor bare --distro ubuntu \
    --reuse --vcpus 4 --mem 10240 --disk 90 9>&- > "$attempt/provision-private.log" 2>&1 &
if wait_child $!; then :; else status=$?; exit "$status"; fi
if [[ $cancelled != 0 ]]; then status=$cancelled; stage=execution; exit "$status"; fi
receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/provision-private.log" | tail -1)
guest=$(jq -er .guest_name <<< "$receipt"); ip=$(jq -er .guest_ip <<< "$receipt")
[[ $guest = sy-"$owner"-* && $ip = 192.168.122.100 ]]
printf '%s\n' "$guest" > "$attempt/guest-name"
virsh -c qemu:///system dumpxml "$guest" | grep -q "<domain type='kvm'"
stage=transfer
git -C "$trusted" bundle create "$attempt/controller.bundle" HEAD
host_archive=$(jq -er .host.archive.name "$attempt/inputs/selection.json")
[[ $host_archive = safeyolo-linux-amd64-production.tar.gz ]]
tar -C "$attempt/inputs" -cf "$attempt/inputs.tar" selection.json "$host_archive" guest.tar.zst
harness_scp_to "$ip" "$attempt/controller.bundle" /home/agent/controller.bundle
harness_scp_to "$ip" "$attempt/inputs.tar" /home/agent/inputs.tar
printf -v command 'set -euo pipefail
umask 077
mkdir /home/agent/source /home/agent/inputs
tar -xf /home/agent/inputs.tar -C /home/agent/inputs
git -C /home/agent/source init
git -C /home/agent/source fetch /home/agent/controller.bundle HEAD
git -C /home/agent/source checkout --detach FETCH_HEAD
cd /home/agent/source
uv sync --frozen --group dev --python 3.13
sudo -n apt-get update -qq
sudo -n apt-get install -y -qq --no-install-recommends uidmap acl util-linux iproute2 openssh-server socat
test -c /dev/kvm
if ! id -nG agent | tr " " "\n" | grep -Fxq kvm; then
    sudo -n usermod -aG kvm agent
fi
sudo -n -E -u agent -- /bin/bash -c %q kvm-runner %q %q %q
' \
    'set -euo pipefail
umask 022
.venv/bin/python -c "$1"
exec ./tests/blackbox/hardware/run-hardware-lane.sh /home/agent/source "$2" kvm /home/agent/inputs "$3" /home/agent/reports
' \
    'import os,fcntl; assert os.geteuid()!=0; fd=os.open("/dev/kvm", os.O_RDWR); assert fcntl.ioctl(fd,0xAE00,0)==12; os.close(fd)' "$controller" "$input_digest"
stage=execution
if [[ $cancelled != 0 ]]; then status=$cancelled; exit "$status"; fi
bash "$jobs/ssh_exec.sh" "$ip" "$(printf '%s' "$command" | base64 -w0)" "${KVM_LANE_TIMEOUT:-7200}" \
    > "$attempt/execution-private.log" 2>&1 &
if wait_child $!; then :; else status=$?; exit "$status"; fi
receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/execution-private.log" | tail -1)
status=$(jq -er '.exit_code | select(type == "number" and . >= 0 and . <= 255)' <<< "$receipt")
test "$(jq -er '.timed_out | tostring' <<< "$receipt")" = false
stage=report
for name in retained-run.json selection.json installed-inputs.json guest/installed-sections.json; do
    mkdir -p "$attempt/reports/$(dirname "$name")"
    bash "$jobs/ssh_fetch.sh" "$ip" "/home/agent/reports/$name" 8388608 > "$attempt/fetch-private.log"
    receipt=$(sed -n 's/^HARNESS_JSON://p' "$attempt/fetch-private.log" | tail -1)
    test "$(jq -er '.truncated | tostring' <<< "$receipt")" = false
    jq -er .content_b64 <<< "$receipt" | base64 -d > "$attempt/reports/$name"
    test "$(sha256sum "$attempt/reports/$name" | cut -d' ' -f1)" = "$(jq -er .sha256 <<< "$receipt")"
done
stage=complete
if [[ $cancelled != 0 ]]; then status=$cancelled; stage=execution; fi
exit "$status"
