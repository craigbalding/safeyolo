#!/bin/bash
# Observe retained candidate/baseline mounts inside the disposable Ubuntu guest.
# Run as guest root. No package install or host privilege is used. Individual
# exits are observations; exit 0 means collection completed, not matrix parity.
set -u
[[ $(id -u) == 0 ]] || exit 64

observe() {
    local label=$1
    shift
    printf '\nOBSERVATION %s\n' "$label"
    "$@"
    printf 'EXIT %s\n' "$?"
}

for tree in candidate baseline; do
    (
        cd "/$tree" || exit
        observe "$tree/stat" find . -exec stat -c '%n type=%F uid=%u gid=%g mode=%a size=%s blocks=%b inode=%i links=%h' '{}' +
        observe "$tree/content" find . -type f -exec sha256sum -- '{}' +
        observe "$tree/links" find . -type l -exec readlink -- '{}' ';'
        observe "$tree/capability" getcap -n -v ./cap-v3
        for tool in getfacl getfattr; do
            if command -v "$tool"; then
                if [[ $tool == getfacl ]]; then
                    observe "$tree/$tool" getfacl -n -R .
                else
                    observe "$tree/$tool" getfattr -d -m - -R .
                fi
            else
                printf 'UNAVAILABLE %s %s\n' "$tree" "$tool"
            fi
        done
        for identity in 1000 33 65535; do
            # Retain the bounding set so file capabilities can take effect.
            # Execution below records all masks after the real identity drop.
            observe "$tree/access/$identity" setpriv --reuid="$identity" --regid="$identity" \
                --clear-groups --inh-caps=-all --ambient-caps=-all /bin/bash -c '
                id
                grep -E "^(Uid|Gid|Groups|Cap|NoNewPrivs)" /proc/self/status
                for operation in "cat private/agent" "ls acl-dir" "stat acl-dir/inherited"; do
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
    ) || exit
done
