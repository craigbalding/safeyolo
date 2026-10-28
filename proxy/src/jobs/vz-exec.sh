#!/bin/bash
# Enter the private job root with the shared guest's existing util-linux tools.
set -euo pipefail

if [[ ${1-} != --job-root ]]; then
    # unshare's root mapper exits and is reaped before exec. Without --fork or
    # a PID namespace, this PID remains sshd's observed fixed command process.
    exec /usr/bin/setpriv --clear-groups /usr/bin/unshare \
        --user --mount --net --map-users=0:65536:65536 --map-groups=0:65536:65536 \
        --setuid=0 --setgid=0 -- /bin/bash /safeyolo/job-exec --job-root
fi

mount --make-rprivate /
private=/run/job-private
mount -t tmpfs -o mode=700 tmpfs "$private"
mkdir "$private/upper" "$private/work" "$private/root"
root=$private/root
mount -t overlay -o "lowerdir=/run/job-lower,upperdir=$private/upper,workdir=$private/work,userxattr" overlay "$root"
mkdir -p "$root"/{input,work,proc,sys,dev,tmp,run,home/agent}
mount --bind /input "$root/input"
# PIDs remain visible, but observer credentials and descriptors are outside
# the job's user namespace. A chroot or hidden PIDs alone is insufficient.
mount --bind /proc "$root/proc"
mount --bind /sys "$root/sys"
mount -o remount,bind,ro "$root/sys"
mount -t tmpfs -o nosuid,mode=755 tmpfs "$root/dev"
for device in null zero random urandom tty; do
    touch "$root/dev/$device"
    mount --bind "/dev/$device" "$root/dev/$device"
done
mkdir "$root/dev/pts"
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620,gid=5 devpts "$root/dev/pts"
ln -s pts/ptmx "$root/dev/ptmx"
ln -s /proc/self/fd "$root/dev/fd"
mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs "$root/tmp"
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs "$root/run"
mount -t tmpfs -o nosuid,nodev,mode=700,uid=1000,gid=1000 tmpfs "$root/home/agent"
chown 1000:1000 "$root/work"
/usr/sbin/ip link set lo up
mkdir "$root/.observer-root"
cd "$root"
/usr/sbin/pivot_root . .observer-root
umount -l /.observer-root
rmdir /.observer-root
cd /work

# Close inherited descriptors before the fixed argv. Bash keeps its script
# at fd 255 with CLOEXEC; that final descriptor closes with the exec below.
for descriptor in /proc/self/fd/*; do
    descriptor=${descriptor##*/}
    if (( descriptor > 2 && descriptor != 255 )); then
        exec {descriptor}>&-
    fi
done
# The host appends an environment reset, privilege selection and literal argv.
