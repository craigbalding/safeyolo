#!/bin/sh
# Native macOS acceptance. Only temporary configuration files are modified.
set -eu
[ "$(uname -s)" = Darwin ] && [ "$(id -u)" -eq 0 ] || {
    echo 'Run on macOS with sudo.' >&2
    exit 1
}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
lab=$(mktemp -d)
trap 'rm -rf "$lab"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$lab/tool"
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
    fragment="$config.seatbelt-sy-agent.conf"
}
run() { /bin/sh "$tool" --config "$config" "$@"; }
rejected() {
    expected=$1
    shift
    cp -p "$config" "$lab/before"
    if run "$@" > "$lab/output" 2>&1; then
        echo "Expected rejection: $expected" >&2
        exit 1
    fi
    awk -v expected="$expected" 'index($0, expected) { found=1 } END { exit !found }' "$lab/output"
    cmp "$lab/before" "$config"
    [ ! -e "$fragment" ]
}
effective() {
    /usr/sbin/sshd -T -f "$config" -C "user=$1,host=localhost,addr=127.0.0.1"
}

fixture normal
chmod 600 "$config"
effective operator > "$lab/operator.before"
run
[ "$(stat -f %Lp "$config")" = 600 ]
effective sy-agent | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
effective operator > "$lab/operator.after"
cmp "$lab/operator.before" "$lab/operator.after"
cp "$config" "$lab/installed"
run
cmp "$lab/installed" "$config"
echo 'PASS: normal install, preserved mode, other account unchanged, repeat run'

fixture precedence
printf '\nMatch User sy-agent\n    ForceCommand internal-sftp\n' >> "$config"
run
effective sy-agent | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
echo 'PASS: earlier managed include supplies the account settings'

fixture 'path with spaces'
run --user another-agent
effective another-agent | awk '$1 == "forcecommand" && $2 == "seatbelt-session" { found=1 } END { exit !found }'
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
tool="$lab/tool/failing-configure-ssh"
rejected 'Previous SSH configuration restored'

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
echo 'All configure-ssh acceptance checks passed; temporary files removed on exit.'
