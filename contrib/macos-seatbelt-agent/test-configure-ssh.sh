#!/bin/sh
# Native macOS acceptance in a disposable VM. Creates/removes a test account
# and the fixed entry directory; refuses to reuse either.
set -eu
[ "$(uname -s)" = Darwin ] && [ "$(id -u)" -eq 0 ] || {
    echo 'Run on macOS with sudo.' >&2
    exit 1
}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
account=sy-seatbelt-test
entry=/Library/PrivilegedHelperTools/seatbelt-agent
[ ! -e "$entry" ] || { echo "Entry already exists: $entry" >&2; exit 1; }
! dscl . -read "/Users/$account" >/dev/null 2>&1 || { echo 'Test account already exists' >&2; exit 1; }
[ ! -e "/Users/$account" ] || { echo 'Test home already exists' >&2; exit 1; }
! dscl . -list /Users UniqueID | awk '$2 == 59900 { found=1 } END { exit !found }' || exit 1
if /usr/bin/pgrep -U 59900 >/dev/null; then
    echo 'Processes already use the test UID; refusing to reuse it' >&2
    exit 1
fi
lab=$(mktemp -d /Library/PrivilegedHelperTools/seatbelt-test.XXXXXX)
chmod 755 "$lab"
created=no
cleanup() {
    result=$?
    trap - EXIT
    if [ "$created" = yes ]; then
        dseditgroup -o edit -d "$account" -t user admin >/dev/null 2>&1 || true
        rm -f /etc/sudoers.d/seatbelt-acceptance-test
        if /bin/launchctl print user/59900 >/dev/null 2>&1; then
            /bin/launchctl bootout user/59900 || result=1
        fi
        # All processes of this freshly allocated UID belong to the fixture.
        # Signals may race an exit; success depends on observing absence below.
        /usr/bin/pkill -TERM -U 59900 >/dev/null 2>&1 || true
        attempt=0
        while [ "$attempt" -lt 50 ]; do
            process_status=0
            /usr/bin/pgrep -U 59900 >/dev/null || process_status=$?
            [ "$process_status" = 1 ] && break
            [ "$process_status" = 0 ] || { result=1; break; }
            if [ "$attempt" = 20 ]; then
                /usr/bin/pkill -KILL -U 59900 >/dev/null 2>&1 || true
            fi
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if [ "$process_status" != 1 ]; then
            echo 'Cleanup failed: could not establish absence of test-UID processes' >&2
            result=1
        fi
        dscl . -delete "/Users/$account"
        rm -rf "$entry" "/Users/$account"
    fi
    rm -rf "$lab"
    if [ "$result" = 0 ]; then
        echo 'All acceptance checks passed; test account, entry, files and processes removed.'
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[ ! -e /etc/sudoers.d/seatbelt-acceptance-test ] || exit 1
dscl . -create "/Users/$account"
created=yes
dscl . -create "/Users/$account" UniqueID 59900
dscl . -create "/Users/$account" PrimaryGroupID 20
dscl . -create "/Users/$account" NFSHomeDirectory "/Users/$account"
dscl . -create "/Users/$account" UserShell /bin/zsh
install -d -o "$account" -g staff -m 700 "/Users/$account"
install -d -o root -g wheel -m 755 "$entry"
xcrun clang -Wall -Wextra -Werror -O2 -DAGENT_USER='"sy-seatbelt-test"' \
    -DAGENT_HOME='"/Users/sy-seatbelt-test"' "$source_dir/agent-entry.c" -o "$entry/agent-entry"
codesign --force --sign - --options runtime --timestamp=none "$entry/agent-entry"
install -o root -g wheel -m 755 "$source_dir/agent-session" "$entry/"
install -o root -g wheel -m 644 "$source_dir/agent-dev.sb" "$entry/"
ssh-keygen -q -t ed25519 -N '' -f "$lab/client-key"
install -o root -g wheel -m 644 "$lab/client-key.pub" "$entry/authorized_keys"
mkdir "$lab/tool"
cp "$source_dir/check-account.c" "$lab/tool/"
# Redirect only the fixed system-rc path to a disposable fixture.
sed "s@/etc/ssh/sshrc@$lab/sshrc@g" "$source_dir/configure-ssh" > "$lab/tool/configure-ssh"
cp "$source_dir/sshd_config.example" "$lab/tool/sshd_config.example"
tool="$lab/tool/configure-ssh"

# A standalone daemon configuration uses the Mac's host keys, without changing
# the running daemon or depending on the operator's admission configuration.
cat > "$lab/base" <<'CONFIG'
PermitUserEnvironment no
AcceptEnv LANG LC_*
Subsystem sftp /usr/libexec/sftp-server
CONFIG
/usr/sbin/sshd -t -f "$lab/base"

fixture() {
    mkdir "$lab/$1"
    config="$lab/$1/sshd_config"
    cp "$lab/base" "$config"
    fragment="$config.seatbelt-$account.conf"
}
run() { /bin/sh "$tool" --user "$account" --config "$config" "$@"; }
shell_value() { dscl . -read "/Users/$account" UserShell; }
rejected() {
    expected=$1
    shift
    cp -p "$config" "$lab/before"
    shell_value > "$lab/shell.before"
    if run "$@" > "$lab/output" 2>&1; then
        echo "Expected rejection: $expected" >&2
        exit 1
    fi
    awk -v expected="$expected" 'index($0, expected) { found=1 } END { exit !found }' "$lab/output" || { cat "$lab/output" >&2; exit 1; }
    cmp "$lab/before" "$config"
    shell_value > "$lab/shell.after"
    cmp "$lab/shell.before" "$lab/shell.after"
    [ ! -e "$fragment" ]
}
effective() {
    /usr/sbin/sshd -T -f "$config" -C "user=$1,host=localhost,addr=127.0.0.1"
}

fixture normal
chmod 600 "$config"
effective operator > "$lab/operator.before"
run --check
[ ! -e "$fragment" ]
[ "$(shell_value)" = 'UserShell: /bin/zsh' ]
run
[ "$(shell_value)" = "UserShell: $entry/agent-entry" ]
[ "$(stat -f %Lp "$config")" = 600 ]
effective "$account" | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
effective operator > "$lab/operator.after"
cmp "$lab/operator.before" "$lab/operator.after"
cp "$config" "$lab/installed"
run
cmp "$lab/installed" "$config"
echo 'PASS: normal install, preserved mode, other account unchanged, repeat run'

fixture precedence
printf '\nMatch User sy-seatbelt-test\n    ForceCommand internal-sftp\n' >> "$config"
run
effective "$account" | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
echo 'PASS: earlier managed include supplies the account settings'

fixture 'path with spaces'
run
effective "$account" | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
echo 'PASS: custom account and configuration path with spaces'

fixture environment
sed 's/PermitUserEnvironment no/PermitUserEnvironment yes/' "$lab/base" > "$config"
rejected 'PermitUserEnvironment is enabled'
cp "$lab/base" "$config"
printf '\nAcceptEnv *\n' >> "$config"
rejected 'AcceptEnv pattern'
cp "$lab/base" "$config"
printf '\nAcceptEnv CUSTOM_*\n' >> "$config"
run
echo 'PASS: unsafe environment settings rejected; unrelated variables accepted'

fixture invalid
printf '\nInvalidDirective yes\n' >> "$config"
rejected 'Existing SSH configuration is invalid'
echo 'PASS: invalid existing config leaves SSH files unchanged'

fixture startup
printf '# A comment-only system rc\n\n' > "$lab/sshrc"
run
fixture startup_commands
printf ': # A harmless command still requires review\n' > "$lab/sshrc"
rejected 'contains startup commands'
run --reviewed-sshrc
rm "$lab/sshrc"
echo 'PASS: startup-code review is required only when commands exist'

fixture account_preflight
dseditgroup -o edit -a "$account" -t user admin
rejected 'must not belong to admin'
dseditgroup -o edit -d "$account" -t user admin
printf '%s ALL=(root) NOPASSWD: /usr/bin/true\n' "$account" > /etc/sudoers.d/seatbelt-acceptance-test
chmod 440 /etc/sudoers.d/seatbelt-acceptance-test
rejected 'has sudo grants'
rm /etc/sudoers.d/seatbelt-acceptance-test
chmod +a "$account allow write" "$entry/agent-dev.sb"
rejected 'account can modify or replace'
chmod -N "$entry/agent-dev.sb"
chmod +a "$account allow delete_child" "$entry"
rejected 'account can modify or replace'
chmod -N "$entry"
chmod +a "$account allow read" "$entry/agent-dev.sb"
run --check
chmod -N "$entry/agent-dev.sb"
echo 'PASS: admin, sudo and modifying ACLs rejected; read-only ACL accepted'

fixture unsafe_config_directory
chmod g+w "$(dirname "$config")"
rejected 'expected root ownership'
chmod g-w "$(dirname "$config")"
echo 'PASS: unsafe configuration directory rejected before activation'

# Fail the final sshd syntax check, after the two active files were installed.
# The wrapper delegates every other invocation to the real macOS sshd.
cat > "$lab/sshd-wrapper" <<'WRAPPER'
#!/bin/sh
count_file="$(dirname "$0")/calls"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
if [ "$count" -eq 5 ]; then
    echo 'Deliberate final-validation failure' >&2
    exit 1
fi
exec /usr/sbin/sshd "$@"
WRAPPER
chmod 755 "$lab/sshd-wrapper"
sed "s@/usr/sbin/sshd@$lab/sshd-wrapper@g" "$tool" > "$lab/tool/failing-configure-ssh"
fixture rollback
dscl . -create "/Users/$account" UserShell /bin/zsh
tool="$lab/tool/failing-configure-ssh"
rejected 'Previous SSH configuration and login shell restored'

tool="$lab/tool/configure-ssh"
fixture rollback_existing
run
cp -p "$config" "$lab/rollback.config"
cp -p "$fragment" "$lab/rollback.fragment"
printf '\n# Changed candidate fragment\n' >> "$lab/tool/sshd_config.example"
rm "$lab/calls"
tool="$lab/tool/failing-configure-ssh"
if run > "$lab/output" 2>&1; then
    echo 'Expected final-validation failure on an existing install' >&2
    exit 1
fi
cmp "$lab/rollback.config" "$config"
cmp "$lab/rollback.fragment" "$fragment"
echo 'PASS: final-validation failure restores both new and existing installations'

# If even restored SSH configuration cannot be validated, retain the compiled
# shell rather than returning a normal shell behind possibly active admission.
fixture failed_restore
dscl . -create "/Users/$account" UserShell /bin/zsh
sed 's/"$count" -eq 5/"$count" -ge 5/' "$lab/sshd-wrapper" > "$lab/changed-wrapper"
cat "$lab/changed-wrapper" > "$lab/sshd-wrapper"
rm "$lab/calls"
if run > "$lab/output" 2>&1; then
    echo 'Expected recovery validation to fail' >&2
    exit 1
fi
awk '/Automatic restore failed/ { found=1 } END { exit !found }' "$lab/output"
[ "$(shell_value)" = "UserShell: $entry/agent-entry" ]
echo 'PASS: failed SSH recovery retains the compiled login shell'
/usr/bin/python3 "$source_dir/test-client-live.py" "$lab" "$account"
