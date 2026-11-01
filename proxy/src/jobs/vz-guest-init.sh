#!/bin/bash
# The SSH observer remains in the VM's initial credential and mount domain.
set -euo pipefail

stage='raise observer loopback'
trap 'status=$?; printf "safeyolo job startup: %s failed (status %d)\n" "$stage" "$status" >&2; exit "$status"' ERR
ip link set lo up

stage='create job directories'
mkdir -p /input /run/sshd /run/job-base /run/job-lower /run/job-private
stage='mount read-only input'
mount -t virtiofs -o ro workspace /input

# Reuse the same read-only Trixie disk. Only ownership presentation changes;
# the job's separate RAM upper is created in its descendant user namespace.
stage='mount read-only base'
mount -t ext4 -o ro,noload /dev/vda /run/job-base
stage='mount mapped base'
mount --bind -o X-mount.idmap=b:0:65536:65536 /run/job-base /run/job-lower
stage='read mapped root ownership'
mapped_owner=$(stat -c '%u:%g' /run/job-lower)
stage="check mapped root ownership (expected 65536:65536, observed $mapped_owner)"
test "$mapped_owner" = 65536:65536
stage='set private directory owner'
chown 65536:65536 /run/job-private
stage='set private directory permissions'
chmod 700 /run/job-private

stage='copy SSH host key'
cp /safeyolo/job-host-key /run/job-host-key
stage='copy SSH authorized keys'
cp /safeyolo/authorized_keys /run/job-authorized-keys
stage='set SSH key owners'
chown 0:0 /run/job-host-key /run/job-authorized-keys
stage='set SSH key permissions'
chmod 600 /run/job-host-key /run/job-authorized-keys
stage='lock root password'
usermod -p '*' root
stage='start SSH observer'
/usr/sbin/sshd -D -e -f /safeyolo/sshd_config >/run/job-sshd.log 2>&1 &
sshd_pid=$!
stage='start SSH bridge'
socat VSOCK-LISTEN:2220,reuseaddr,fork TCP:127.0.0.1:22 >/run/job-bridge.log 2>&1 &
bridge_pid=$!

status=0
wait -n -p exited_pid "$sshd_pid" "$bridge_pid" || status=$?
case ${exited_pid-} in
    "$sshd_pid")
        printf 'safeyolo job startup: sshd exited (status %d)\n' "$status" >&2
        # Retain private DEBUG1/session/wait records in the existing log. Only
        # sshd's setup and error diagnostics belong on the guest console.
        grep -E '^(error: |fatal: |sshd: |/usr/sbin/sshd: |/safeyolo/sshd_config( |:)|Unable to load host key:|Missing privilege separation directory:|Bind to port |Cannot bind any address|safeyolo job startup:)|^.*/guest-init: line [0-9]+:' /run/job-sshd.log >&2 || true
        ;;
    "$bridge_pid")
        printf 'safeyolo job startup: socat exited (status %d)\n' "$status" >&2
        grep -E ' socat\[[0-9]+\] [EW] |^safeyolo job startup:|^.*/guest-init: line [0-9]+:' /run/job-bridge.log >&2 || true
        ;;
    *)
        printf 'safeyolo job startup: wait for SSH observer or bridge failed (status %d)\n' "$status" >&2
        ;;
esac
exit "$status"
