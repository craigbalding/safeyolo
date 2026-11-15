#!/bin/bash
# Observe Linux metadata inside the retained published Mac guest. The host
# probe starts the unchanged installed init; this script is test instrumentation.
# Per-command exits describe supported/unsupported observations, not acceptance.
set -u

observe() {
    local label=$1
    shift
    printf '\nOBSERVATION %s\n' "$label"
    "$@"
    printf 'EXIT %s\n' "$?"
}

for ((attempt=0; attempt<600; attempt++)); do
    [[ ! -f /safeyolo-status/per-run-started ]] || break
    sleep 0.1
done
if [[ ! -f /safeyolo-status/per-run-started ]]; then
    echo 'per-run setup did not complete'
    echo 1 > /safeyolo-status/probe.done
    exit 1
fi

observe root-identity id
observe kernel uname -a
observe os-release cat /etc/os-release
observe mounts findmnt -n -o TARGET,SOURCE,FSTYPE,OPTIONS
observe published-stat stat -c '%n type=%F uid=%u gid=%g mode=%a size=%s blocks=%b inode=%i links=%h' \
    / /usr/bin/bash /usr/bin/cat /usr/bin/passwd /usr/bin/sudo /bin /lib /dev/null /dev/vda
observe published-links readlink /bin /lib /sbin
for tool in getfacl getfattr getcap setfacl setcap setpriv; do
    command -v "$tool" || printf 'UNAVAILABLE %s\n' "$tool"
done
observe published-capabilities getcap -n -r /usr/bin /usr/sbin
observe published-acls getfacl -n /usr/bin/bash /usr/bin/passwd /etc /home/agent
observe published-xattrs getfattr -d -m - /usr/bin/passwd /usr/bin/sudo

fixture=/var/tmp/rootless-1553
mkdir -p "$fixture"
cd "$fixture" || exit 1
printf 'rootless-1553\n' > regular
ln regular hardlink
ln -s regular symlink
mkdir private acl-dir
printf 'private-1000\n' > private/agent
chown -R 1000:1000 private
chmod 0700 private
printf '#!/bin/sh\nprintf "guest-exec-1553\\n"\n' > executable
chmod 0755 executable
truncate -s 67108864 sparse
printf sparse-end | dd of=sparse bs=1 seek=67108854 conv=notrunc status=none
observe fifo mkfifo fifo
observe character-node mknod character c 1 3
observe block-node mknod block b 7 0
observe character-access head -c 0 character
observe fixture-stat find . -maxdepth 2 -exec stat -c '%n type=%F uid=%u gid=%g mode=%a size=%s blocks=%b inode=%i links=%h' '{}' +
observe hardlink-identity test regular -ef hardlink
observe symlink-target readlink symlink
observe sparse-tail tail -c 10 sparse
observe user-xattr setfattr -n user.safeyolo -v rootless-1553 regular
observe access-acl setfacl -m u:1000:rwx,u:33:r-x,m:rwx acl-dir
observe default-acl setfacl -m d:u::rwx,d:u:1000:rwx,d:u:33:r-x,d:g::r-x,d:m::rwx,d:o::--- acl-dir
touch acl-dir/inherited
observe fixture-acls getfacl -n -R private acl-dir
observe fixture-xattrs getfattr -d -m - regular
cp /usr/bin/cat cap-v3
cp /usr/bin/cat setid
chmod 0755 cap-v3
chmod 4755 setid
observe file-capability setcap cap_net_bind_service=ep cap-v3
observe raw-capability getcap -n -v cap-v3
observe capability-xattr getfattr -d -m security.capability -e hex cap-v3
for identity in 1000 33 65535; do
    observe "identity-effects/$identity" setpriv --reuid="$identity" --regid="$identity" \
        --clear-groups --inh-caps=-all --ambient-caps=-all /bin/bash -c '
        id
        for operation in "cat private/agent" "ls acl-dir" "stat acl-dir/inherited" "./executable"; do
            printf "OPERATION %s\n" "$operation"
            /bin/bash -c "$operation"
            printf "EXIT %s\n" "$?"
        done
        for executable in cap-v3 setid; do
            printf "EXEC %s\n" "$executable"
            "./$executable" /proc/self/status
            printf "EXIT %s\n" "$?"
        done'
done

# Root and ordinary-user operations must actually work; collection success
# alone cannot establish the required usable guest. These writes stay in the
# disposable overlay and the new private instance's shares.
rc=0
[[ $(id -u):$(id -g) == 0:0 ]] || rc=1
printf 'root-rwx\n' > /var/tmp/1553-root-marker || rc=1
[[ $(cat /var/tmp/1553-root-marker) == root-rwx ]] || rc=1
./executable || rc=1
setpriv --reuid=1000 --regid=1000 --clear-groups /bin/bash -euc '
    test "$(id -u):$(id -g)" = 1000:1000
    for directory in /home/agent /workspace; do
        printf "ordinary-1553\n" > "$directory/1553-data"
        test "$(cat "$directory/1553-data")" = ordinary-1553
        cp /var/tmp/rootless-1553/executable "$directory/1553-executable"
        chmod 0755 "$directory/1553-executable"
        test "$("$directory/1553-executable")" = guest-exec-1553
    done
' || rc=1
printf '\nREQUIRED_IDENTITY_RWX_EXIT %s\n' "$rc"
echo "$rc" > /safeyolo-status/probe.done
