# Pending #622 physical VZ witness

This procedure is prepared work. It has not established a VM boot under the
changed policy. Sylab owns execution and Bristol resource exclusion. The forced
`sy-agent` SSH entry can observe the VM, but cannot attach this separate policy.
Tart cannot run nested Virtualization.framework (VZ). If Sylab cannot bind an
existing trusted host launch facility, Craig must launch from a normal Bristol
terminal as `sy-agent`, UID 502. Do not retry either unavailable route.

Use two terminals: the outside terminal launches the existing foreground runner;
the factory terminal observes through the approved SSH entry. Prepare the
observer command before launch, because the runner has a 60-second deadline.
Closing a terminal or reaching that deadline does not establish cleanup.

## Inputs and protected policy

The existing fixture is `/Users/sy-agent/s622-20261020`, called `LAB` below.
The helper is `/Users/sy-agent/full-guest-lab/development-install/safeyolo-vm`.
Its signed identity reports source `1ed8780308763cb96a2f4eebeed55b550e0175e6`,
development profile and release optimization. It is an existing workload input,
not a product binary built from PR #1159. Keep the existing images read-only.
The reserved overlay is a 1 GiB sparse file. This fixture initramfs uses a tmpfs
upper layer; the overlay is supplied to the helper but is not mounted by this
initramfs. This witness makes no disk-persistence claim.

Immediately before execution, Sylab must refresh the physical reservation,
current #622 direction, PR head, profile identity, overlay ownership and absence
of a helper using this fixture. Preserve other issues' VMs and inputs. The
existing policy was root-owned with SHA-256
`ec39eca32a8ac8ba2ceea9dcb4f587523bfbe2fdb8f2948b0386527ab9c32d80`.
If it changed, review the new policy and preserve all current local grants.

A host administrator prepares a protected test copy at
`/Library/PrivilegedHelperTools/s622-20261020.sb`. First check that this name is
absent, including symlinks. The source below is the current installed profile.
Append exactly the six committed denial forms; do not copy the agent-writable
staging profile as trusted configuration. In the administrator's Bristol shell:

```sh
sudo -n /bin/sh <<'SH'
set -eu
profile=/Library/PrivilegedHelperTools/s622-20261020.sb
[ ! -e "$profile" ] && [ ! -L "$profile" ]
umask 022
cat /Library/PrivilegedHelperTools/seatbelt-agent/agent-dev.sb > "$profile"
cat >> "$profile" <<'SB'
(deny job-creation)
(deny lsopen appleevent-send)
(deny mach-lookup (global-name "com.apple.xpc.smd"))
(deny file-write* (subpath (string-append agent-home "/Library/LaunchAgents")))
(deny file-write-unlink (literal (string-append agent-home "/Library")))
(deny file-write* (subpath "/private/var/at"))
SB
chown root:wheel "$profile"
chmod 644 "$profile"
shasum -a 256 "$profile"
SH
```

With the recorded base and exact staged suffix, the expected hash is
`05516d438610c5126595e15f5078f4a7f63a162bd910192c9dd5f19cfd5b3b7c`.
Review any difference before launch. The protected copy is a scoped test input;
the active SSH profile and daemon configuration are not changed.

The owner stages the unchanged repository observers
`tests/blackbox/harness/macos_process_argv.py` and `process_identity.py` under
`LAB/observers/`. They inspect exact arguments and process birth identity without
invoking host `ps`. The existing `full-guest-lab/venv` has Paramiko. Its existing
`config/data/vm_ssh_key` matches `fixture/authorized_keys` in the prepared
`sshd-initramfs.cpio.gz`; keep that private key in place.

## Launch and host canary

In the outside Bristol terminal as UID 502, use `/bin/bash`. Preserve the normal
home, temporary-directory, PATH and configured certificate variables. Define:

```sh
set -eu
LAB=/Users/sy-agent/s622-20261020
SCOPED_PROFILE=/Library/PrivilegedHelperTools/s622-20261020.sb
PYTHON=/Users/sy-agent/full-guest-lab/venv/bin/python3
test "$(id -u)" = 502
test ! -e "$LAB/shell.sock" && test ! -L "$LAB/shell.sock"
test ! -e "$LAB/control.sock" && test ! -L "$LAB/control.sock"
test ! -L "$LAB/overlay.img"
test "$(stat -f '%u:%z:%b' "$LAB/overlay.img")" = 502:1073741824:0
"$PYTHON" -I -B "$LAB/observers/macos_process_argv.py" --owned-roots 502 "$LAB"
# Only this disposable marker directory is shared with guest UID 1000.
chmod 777 "$LAB/share"
chmod 644 "$LAB/share/host-marker"
CANARY_DIR=$(mktemp -d /Users/Shared/s622-canary.XXXXXX)
printf 'CANARY_DIR=%s\n' "$CANARY_DIR"
printf 'outside-seatbelt-622\n' > "$CANARY_DIR/canary"
cat "$CANARY_DIR/canary"
/usr/bin/sandbox-exec -f "$SCOPED_PROFILE" \
  -D AGENT_HOME=/Users/sy-agent -D TOOLCHAIN_ROOT=/opt/homebrew \
  "$PYTHON" -I -B - "$CANARY_DIR/canary" <<'PY'
import errno, sys
from pathlib import Path
try:
    Path(sys.argv[1]).read_bytes()
except OSError as error:
    assert error.errno == errno.EPERM, error
    print('PASS: existing outside file denied under the scoped profile')
else:
    raise AssertionError('outside canary was readable')
PY
```

Require the outside read to print the marker and the confined read to report
EPERM. The process observer must report `owned_processes: []`. Stop on a failed
prerequisite. Do not replace an occupied socket or overlay. Then run the helper
directly through the existing runner, with no intervening shell:

```sh
runner_status=0
/usr/bin/sandbox-exec -f "$SCOPED_PROFILE" \
  -D AGENT_HOME=/Users/sy-agent -D TOOLCHAIN_ROOT=/opt/homebrew \
  /Users/sy-agent/bin/run-vz-test --timeout-seconds 60 -- \
  /Users/sy-agent/full-guest-lab/development-install/safeyolo-vm run \
  --kernel /Users/sy-agent/full-guest-lab/images/Image \
  --initrd /Users/sy-agent/full-guest-lab/sshd-initramfs.cpio.gz \
  --rootfs /Users/sy-agent/full-guest-lab/images/rootfs-base.ext4 \
  --overlay "$LAB/overlay.img" --cpus 2 --memory 1024 \
  --cmdline 'console=hvc0 root=/dev/vda rw' \
  --serial-log "$LAB/serial.log" --no-terminal \
  --shell-socket "$LAB/shell.sock" --control-socket "$LAB/control.sock" \
  --share "$LAB/share:workspace:rw" > "$LAB/helper.log" 2>&1 || runner_status=$?
printf 'runner_status=%s\n' "$runner_status"
```

## Observe the actual guest and stop it

From the factory terminal with the existing SSH configuration, send this program
on stdin. Do not put a here-document inside the remote forced shell. The probe
connects to this fixture's private shell socket, then authenticates to the actual
guest through that same socket. No host TCP listener or forwarding is added.

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import dataclasses, json, os, socket, sys, time
from pathlib import Path
import paramiko
lab = Path('/Users/sy-agent/s622-20261020')
old = Path('/Users/sy-agent/full-guest-lab')
sys.path.insert(0, str(old / 'source/cli/src'))
sys.path.insert(0, str(lab / 'observers'))
from safeyolo.vm_diagnostics import probe_shell_socket
from macos_process_argv import process_argv
from process_identity import _darwin_process_info
deadline = time.monotonic() + 40
while True:
    banner = probe_shell_socket(lab / 'shell.sock', timeout=0.5)
    if banner.banner:
        break
    assert time.monotonic() < deadline, banner
    time.sleep(0.1)
print('SSH banner:', dataclasses.asdict(banner), flush=True)
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(3)
    control.connect(str(lab / 'control.sock'))
    control.sendall(b'{"operation":"status"}\n')
    status = json.loads(control.makefile('rb').readline(2 * 1024 * 1024))
assert status['ok'] is True and status['vm']['state'] == 'running', status
assert status['helper']['git_sha'] == '1ed8780308763cb96a2f4eebeed55b550e0175e6', status
pid = status['pid']
info = _darwin_process_info(pid)
assert info is not None and info.pbi_uid == 502
argv = [os.fsdecode(arg) for arg in process_argv(pid)]
assert argv[0] == str(old / 'development-install/safeyolo-vm')
assert argv[argv.index('--control-socket') + 1] == str(lab / 'control.sock')
identity = dict(pid=pid, birth=[info.pbi_start_tvsec, info.pbi_start_tvusec], argv=argv)
(lab / 'helper-status.json').write_text(json.dumps(status, indent=2) + '\n')
(lab / 'helper-process.json').write_text(json.dumps(identity, indent=2) + '\n')
print('VM status:', status, flush=True)
assert 'SSHD_FIXTURE_READY' in (lab / 'serial.log').read_text()
stream = socket.socket(socket.AF_UNIX)
stream.settimeout(3)
stream.connect(str(lab / 'shell.sock'))
client = paramiko.SSHClient()
# The disposable guest generates its host key at boot. Its private UDS is the
# fixture endpoint, as in the existing run-sshd.py observer.
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect('seatbelt-622', username='agent', sock=stream,
                   pkey=paramiko.Ed25519Key.from_private_key_file(str(old / 'config/data/vm_ssh_key')),
                   look_for_keys=False, allow_agent=False, timeout=3, banner_timeout=3, auth_timeout=3)
    command = ("set -eu; id; uname -r; sudo -n mkdir -p /workspace; "
               "sudo -n mount -t virtiofs workspace /workspace; "
               "test \"$(cat /workspace/host-marker)\" = seatbelt-622-owned-share; "
               "printf 'guest-to-host-622\\n' > /workspace/guest-marker; "
               "findmnt -n -t virtiofs -o SOURCE,TARGET /workspace")
    stdin, stdout, stderr = client.exec_command(command, timeout=10)
    stdin.close()
    output, error = stdout.read().decode(), stderr.read().decode()
    assert stdout.channel.recv_exit_status() == 0, (output, error)
    assert (lab / 'share/guest-marker').read_text() == 'guest-to-host-622\n'
    print('Guest identity and mounted share:', output, flush=True)
    print('PASS: host-to-guest and guest-to-host share markers', flush=True)
finally:
    # Request poweroff even when a share assertion fails. This request alone
    # does not establish termination; the foreground runner and checks below do.
    try:
        if client.get_transport() and client.get_transport().is_active():
            client.exec_command('sudo -n /usr/bin/busybox poweroff -f', timeout=3)
            print('Guest poweroff requested', flush=True)
    finally:
        client.close()
        stream.close()
PY
```

Require a real SSH identification, VM state `running`, the expected helper
identity, `SSHD_FIXTURE_READY` in the serial log, guest `id`/kernel output and
`workspace /workspace` as the mounted VirtioFS share. Require the host to see the
guest marker. Retain actual stdout/stderr and logs. A failed command remains a
failed witness even if cleanup succeeds.

## Verify teardown and remove only owned inputs

If guest poweroff fails, the existing runner still owns stopping and reaping its
exact helper. For an explicit earlier stop, use another outside Bristol terminal
as UID 502. Check the saved birth identity and complete arguments before sending
TERM to that exact helper; an inspection error must stop this command:

```sh
/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B - <<'PY'
import json, os, signal, sys
from pathlib import Path
lab = Path('/Users/sy-agent/s622-20261020')
sys.path.insert(0, str(lab / 'observers'))
from macos_process_argv import process_argv
from process_identity import _darwin_process_info
owned = json.loads((lab / 'helper-process.json').read_text())
info = _darwin_process_info(owned['pid'])
if info is not None:
    assert [info.pbi_start_tvsec, info.pbi_start_tvusec] == owned['birth']
    assert [os.fsdecode(arg) for arg in process_argv(owned['pid'])] == owned['argv']
    os.kill(owned['pid'], signal.SIGTERM)
    print('TERM sent to verified helper', owned['pid'])
PY
```

After the foreground runner has returned, in the outside terminal where `LAB`
and `CANARY_DIR` remain defined:

```sh
"$PYTHON" -I -B "$LAB/observers/macos_process_argv.py" --owned-roots 502 "$LAB"
"$PYTHON" -I -B - "$LAB" <<'PY'
import errno, socket, sys
from pathlib import Path
lab = Path(sys.argv[1])
for name in ('shell.sock', 'control.sock'):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(2)
        try:
            stream.connect(str(lab / name))
        except OSError as error:
            assert error.errno in (errno.ENOENT, errno.ECONNREFUSED), error
        else:
            raise AssertionError(f'owned socket is still listening: {name}')
print('PASS: neither owned socket has a listener')
PY
```

Require `owned_processes: []` and no listener. The observer raises on failed or
truncated process inspection. If either check fails, retain the overlay, account
context and diagnostics; report the exact surviving process or socket. Do not
signal by name. Runner status 124 records a deadline, not a passing workload.

When both checks pass, remove only these fixture files in that outside terminal.
Keep the policy/source snapshots, observers and result logs for Lens:

```sh
rm -f "$LAB/shell.sock" "$LAB/control.sock" "$LAB/control.sock.lock" \
  "$LAB/overlay.img" "$LAB/share/host-marker" "$LAB/share/guest-marker"
rmdir "$LAB/share"
rm "$CANARY_DIR/canary"
rmdir "$CANARY_DIR"
test ! -e "$LAB/overlay.img" && test ! -L "$LAB/overlay.img"
test ! -e "$LAB/shell.sock" && test ! -L "$LAB/shell.sock"
test ! -e "$LAB/control.sock" && test ! -L "$LAB/control.sock"
```

The host administrator removes only the protected test copy after its identity
is checked against the reviewed copy:

```sh
sudo -n rm /Library/PrivilegedHelperTools/s622-20261020.sb
test ! -e /Library/PrivilegedHelperTools/s622-20261020.sb && \
  test ! -L /Library/PrivilegedHelperTools/s622-20261020.sb
```

Do not remove the active profile, helper, images or other lab directories.
Return the actor/profile/helper identity, commands, runner result,
boot/banner/share/canary observations and final process/socket/file absence.
