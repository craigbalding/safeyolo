#!/bin/bash
# The SSH observer remains in the VM's initial credential and mount domain.
set -euo pipefail

mkdir -p /input /run/sshd /run/job-base /run/job-lower /run/job-private
mount -t virtiofs -o ro workspace /input

# Reuse the same read-only Trixie disk. Only ownership presentation changes;
# the job's separate RAM upper is created in its descendant user namespace.
mount -t ext4 -o ro,noload /dev/vda /run/job-base
mount --bind -o X-mount.idmap=b:65536:0:65536 /run/job-base /run/job-lower
test "$(stat -c '%u:%g' /run/job-lower)" = 65536:65536
chown 65536:65536 /run/job-private
chmod 700 /run/job-private

cp /safeyolo/job-host-key /run/job-host-key
cp /safeyolo/authorized_keys /run/job-authorized-keys
chown 0:0 /run/job-host-key /run/job-authorized-keys
chmod 600 /run/job-host-key /run/job-authorized-keys
usermod -p '*' root
/usr/sbin/sshd -D -e -f /safeyolo/sshd_config >/run/job-sshd.log 2>&1 &
socat VSOCK-LISTEN:2220,reuseaddr,fork TCP:127.0.0.1:22 >/run/job-bridge.log 2>&1 &
wait -n
