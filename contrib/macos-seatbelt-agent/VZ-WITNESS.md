# Pending #622 physical VZ witness

This procedure prepares one Virtualization.framework (VZ) boot, guest command
and bidirectional VirtioFS share operation under the six added denials. Physical
execution under that policy is unverified. Criterion 12 of #622 remains open;
#622 stays 11/12 and #500 stays 13/14. The accepted shell, toolchain, SafeYolo
test and negative-control results do not need another run.

Sylab owns the physical reservation and evaluates this preparation before any
request to Craig. The forced `sy-agent` Secure Shell (SSH) entry can prepare and
observe this fixture, but cannot attach a second policy. Tart cannot run nested
VZ. Do not retry either route or change the installed account, profile or
Keychain. The remaining host operation is a protected profile copy and one
UID-502 launch from an approved trusted Bristol terminal.

Use two terminals: the trusted Bristol terminal launches the foreground runner;
the factory terminal observes through the existing SSH entry. Prepare the
observer before launch because the runner has a 60-second deadline. A deadline
or a closed terminal does not establish cleanup. No proxy, coding client,
desktop, host TCP listener or production agent is started by this procedure.

## Retained inputs

The package is `/Users/sy-agent/forge587-13260/instance`, called `PACKAGE` below.
Its helper reports clean production source
`7d4b812b69e46708b2132b749641af2bac2668ea`, release optimization and no debugging
entitlement. Its SHA-256 is
`a851f70365bf17aba2f83e11ca1fb4bd7d3fd7a7327ec9efc99c05c7449f6328`.
This is a qualified workload input, not a binary built from PR #1159.

The package's `share/` links resolve into the retained guest tree
`/Users/sy-agent/.local/share/safeyolo/guests/trees/sha256/01d3a982fc07370d73e31a0f5314416ce5af6511e5338e96bc63be2315e1fe8a`:

| File | SHA-256 |
|---|---|
| `Image` | `cfb99c160084f605b4acf9e7d7a50e4805e07de0c6fa7a88918067100a9066c0` |
| `initramfs.cpio.gz` | `1ca27b00cef28f6e7065f84524fc65bf48ed71c91b1bf498a4dc8532c5a6ec15` |
| `rootfs-base.ext4` | `5d2286d5deb330073b9af96b54a62ee1982707308a52223e2e714fc642f0063f` |

Read-only inspection on 4 November 2026 found the package, resolved images,
scripts and retained account inputs owned by UID 502. The #587 runtime is
stopped; its runtime and launch context both name generation
`f5cda6aab12944c6b6c43d156c82a994`. Its retained local CLI is `e23f0559`; its
proxy/helper package is `7d4b812b`. Do not restart or modify that agent. The
[Lens assessment](https://github.com/craigbalding/safeyolo/issues/622#issuecomment-6619214285)
explains reuse of #587/#1393 and the missing combined policy proof. #616 remains
a separate assessment of the VZ grants.

The explicit Python runtime
`/Users/sy-agent/full-guest-lab/venv/bin/python3` is Python 3.12.14 with Paramiko.
Only that runtime is reused from `full-guest-lab`. No old fixture image, source
tree or SSH key is used. The runner `/Users/sy-agent/bin/run-vz-test` has SHA-256
`534297944736aa9cb1fef615c88628577d5236a32d183c92f952d4d32ebd7593`.
Its supported command is `safeyolo-vm run`; invoke the runner with this explicit
Python to avoid its environment-dependent `python3` shebang.

## Worker preparation

From `/workspace` in the factory terminal, use the existing SSH configuration.
Stage this disposable fixture once as UID 502. If the directory already exists,
inspect its inputs and logs before deciding whether to reuse it; do not overwrite
a previous result. The shared home, status and marker directories are disposable.
The new guest uses an explicit tmpfs upper layer and no overlay disk. It makes
no persistence claim and does not use the retained #587 home or overlay.

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import os, shutil
from pathlib import Path
import paramiko
assert os.getuid() == 502
package = Path('/Users/sy-agent/forge587-13260/instance')
lab = Path('/Users/sy-agent/s622-20261104')
key = paramiko.Ed25519Key.from_private_key_file(str(package / 'data/vm_ssh_key'))
authorized = (package / 'agents/local587/config-share/authorized_keys').read_text()
assert authorized.split()[:2] == [key.get_name(), key.get_base64()]
lab.mkdir(mode=0o700)
for name in ('config', 'observers', 'home', 'status', 'share'):
    (lab / name).mkdir(mode=0o700)
for name in ('guest-init', 'guest-init-static', 'guest-init-per-run',
             'guest-shell-bridge', 'guest-sudo', 'safeyolo-guest'):
    shutil.copyfile(package / 'assets/guest' / name, lab / 'config' / name)
    (lab / 'config' / name).chmod(0o755)
for name, value in {'authorized_keys': authorized, 'agent-name': 'seatbelt622\n',
                    'agent.env': 'export SAFEYOLO_DETACH=1\n',
                    'proxy.env': '', 'per-run-go': ''}.items():
    (lab / 'config' / name).write_text(value)
    (lab / 'config' / name).chmod(0o644)
(lab / 'config').chmod(0o755)
for name in ('home', 'status', 'share'):
    (lab / name).chmod(0o777)
(lab / 'share/host-marker').write_text('seatbelt-622-owned-share\n')
(lab / 'share/host-marker').chmod(0o644)
print('Prepared', lab, 'without starting a VM')
PY
tar -C /workspace -cf - tests/blackbox/harness/macos_process_argv.py \
  tests/blackbox/harness/process_identity.py | \
  ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/usr/bin/tar -xf - -C /Users/sy-agent/s622-20261104/observers --strip-components 3'
```

The copied scripts are the retained package's guest boot path. The
config share contains a public SSH key and detach setting, without instance
credentials or a coding command. The private key stays at
`PACKAGE/data/vm_ssh_key`. The unchanged repository observers read exact process
arguments and birth identities without host `ps`. The retained per-run script
requires `safeyolo-guest` even in detach mode, so its existing binary is copied
with the scripts; no command supervisor is enabled and no native input is built.

Immediately before execution, Sylab refreshes the Bristol reservation, current
#622 direction, PR head and retained input identities. In the factory terminal,
require no fixture process, occupied socket or previous boot marker:

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import os, sys
from pathlib import Path
lab = Path('/Users/sy-agent/s622-20261104')
sys.path.insert(0, str(lab / 'observers'))
from macos_process_argv import owned_account_processes
assert os.getuid() == 502
assert owned_account_processes(502, [str(lab)]) == []
for name in ('shell.sock', 'control.sock', 'helper-process.json', 'share/guest-marker'):
    assert not os.path.lexists(lab / name), name
assert not list((lab / 'status').iterdir())
print('PASS: prepared fixture is idle')
PY
```

Preserve other VMs and inputs. The overall issue remains Project Size L /
Uncertainty High: the trusted outside-profile host launch remains unproved.
The bounded preparation uses known tools and does not change that estimate.

## Protected policy and one host launch

In an approved trusted Bristol administrator terminal, use `/bin/bash`. Preserve
the configured proxy and certificate environment. A host administrator creates
`/Library/PrivilegedHelperTools/s622-20261020.sb` from the root-owned installed
profile plus exactly the six committed denial forms. Do not promote the
agent-writable staging profile to trusted configuration.

```sh
sudo -n /bin/sh <<'SH'
set -eu
profile=/Library/PrivilegedHelperTools/s622-20261020.sb
base=/Library/PrivilegedHelperTools/seatbelt-agent/agent-dev.sb
[ ! -e "$profile" ] && [ ! -L "$profile" ]
[ "$(shasum -a 256 "$base" | awk '{print $1}')" = ec39eca32a8ac8ba2ceea9dcb4f587523bfbe2fdb8f2948b0386527ab9c32d80 ]
umask 022
cat "$base" > "$profile"
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
[ "$(shasum -a 256 "$profile" | awk '{print $1}')" = 05516d438610c5126595e15f5078f4a7f63a162bd910192c9dd5f19cfd5b3b7c ]
stat -f '%Su:%Sg %Lp %N' "$profile"
shasum -a 256 "$base" "$profile"
SH
```

Require `root:wheel 644` and the expected hashes. If an input differs, stop and
review the difference. This construction preserves all current local VZ, Fuse,
home-extension, Metal, toolchain, directory and loopback grants. The installed
SSH profile remains unchanged. Its account shell is the fixed-profile
`agent-shell-launcher`, SHA-256
`36b37b40a1efe93aa5bd55f8e37789b9c0ad0ee9cc3ddcf800229605fb7b63e1`;
the separate `agent-entry` binary does not change that binding.

After the worker reports the fixture idle and has the observer ready, run this
in the same trusted administrator terminal. `sudo` selects UID 502 and its home;
it invokes `sandbox-exec` directly, without an unsandboxed account login shell.
The explicit Python runner directly spawns the selected helper. Retain the
terminal output and the printed status; `HOST_LOG` is in the acting host user's
home because that user cannot write the private fixture directory.

```sh
set -euo pipefail
LAB=/Users/sy-agent/s622-20261104
PACKAGE=/Users/sy-agent/forge587-13260/instance
PYTHON=/Users/sy-agent/full-guest-lab/venv/bin/python3
SCOPED_PROFILE=/Library/PrivilegedHelperTools/s622-20261020.sb
HOST_LOG=$(mktemp "$HOME/s622-20261104-launch.XXXXXX")
test ! -L "$SCOPED_PROFILE"
test "$(stat -f '%u:%g:%Lp' "$SCOPED_PROFILE")" = 0:0:644
test "$(shasum -a 256 "$SCOPED_PROFILE" | awk '{print $1}')" = 05516d438610c5126595e15f5078f4a7f63a162bd910192c9dd5f19cfd5b3b7c
set +e
sudo -n -H --preserve-env=HTTP_PROXY,HTTPS_PROXY,http_proxy,https_proxy,NO_PROXY,no_proxy,SSL_CERT_FILE,REQUESTS_CA_BUNDLE,NODE_EXTRA_CA_CERTS \
  -u sy-agent /usr/bin/sandbox-exec -f "$SCOPED_PROFILE" \
  -D AGENT_HOME=/Users/sy-agent -D TOOLCHAIN_ROOT=/opt/homebrew \
  "$PYTHON" -I -B /Users/sy-agent/bin/run-vz-test --timeout-seconds 60 -- \
  "$PACKAGE/bin/safeyolo-vm" run \
  --kernel "$PACKAGE/share/Image" --initrd "$PACKAGE/share/initramfs.cpio.gz" \
  --rootfs "$PACKAGE/share/rootfs-base.ext4" --cpus 2 --memory 1024 \
  --cmdline 'console=hvc0 root=/dev/vda rw quiet safeyolo.ephemeral_upper=1' \
  --serial-log "$LAB/serial.log" --no-terminal \
  --shell-socket "$LAB/shell.sock" --control-socket "$LAB/control.sock" \
  --share "$LAB/share:workspace:rw" --share "$LAB/config:config:ro" \
  --share "$LAB/status:status:rw" --share "$LAB/home:home:rw" \
  2>&1 | tee "$HOST_LOG"
launch_status=("${PIPESTATUS[@]}")
set -e
printf 'runner_status=%s log_status=%s host_log=%s\n' \
  "${launch_status[0]}" "${launch_status[1]}" "$HOST_LOG"
```

This is a prepared command, not evidence that the host launch succeeded. Keep
the profile-copy receipt with the launch output to bind the trusted policy,
actor and inherited helper confinement. Worker observations below bind the
actual helper, its runner parent and guest operation. Require both printed
statuses to be 0 and the worker's guest/share checks to pass. Retain diagnostics
on any failure.

## Worker observation and guest stop

From the factory terminal, send this program through the existing SSH entry.
Do not place a here-document inside the remote forced-shell command. The probe
uses only this fixture's private Unix-domain sockets (UDS). Readiness means an
actual SSH identification and a guest command, not elapsed time or socket-file
presence. Save status and process evidence before testing their assertions.

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import errno, json, os, socket, sys, time
from pathlib import Path
import paramiko
lab = Path('/Users/sy-agent/s622-20261104')
package = Path('/Users/sy-agent/forge587-13260/instance')
sys.path.insert(0, str(lab / 'observers'))
from macos_process_argv import process_argv
from process_identity import _darwin_process_info
deadline = time.monotonic() + 40
while True:
    try:
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(0.5)
            probe.connect(str(lab / 'shell.sock'))
            banner = probe.recv(256)
    except OSError as error:
        if error.errno not in (errno.ENOENT, errno.ECONNREFUSED) and not isinstance(error, TimeoutError):
            raise
        banner = b''  # Expected while this fixture's helper/guest is starting.
    ready = lab / 'status/vm-status'
    if banner.startswith(b'SSH-2.0-') and ready.is_file() and ready.read_text().strip() == 'ready':
        break
    assert time.monotonic() < deadline, ('SSH readiness deadline', banner)
    time.sleep(0.1)
print('SSH banner:', banner, flush=True)
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(3)
    control.connect(str(lab / 'control.sock'))
    control.sendall(b'{"operation":"status"}\n')
    status = json.loads(control.makefile('rb').readline(2 * 1024 * 1024))
(lab / 'helper-status.json').write_text(json.dumps(status, indent=2) + '\n')
pid = status['pid']
info = _darwin_process_info(pid)
assert info is not None
argv = [os.fsdecode(arg) for arg in process_argv(pid)]
parent = _darwin_process_info(info.pbi_ppid)
assert parent is not None
parent_argv = [os.fsdecode(arg) for arg in process_argv(info.pbi_ppid)]
identity = dict(pid=pid, uid=info.pbi_uid,
                birth=[info.pbi_start_tvsec, info.pbi_start_tvusec], argv=argv,
                parent=dict(pid=info.pbi_ppid, uid=parent.pbi_uid,
                            birth=[parent.pbi_start_tvsec, parent.pbi_start_tvusec],
                            argv=parent_argv))
(lab / 'helper-process.json').write_text(json.dumps(identity, indent=2) + '\n')
print('VM status and process:', status, identity, flush=True)
assert status['ok'] is True and status['vm']['state'] == 'running', status
assert status['helper']['git_sha'] == '7d4b812b69e46708b2132b749641af2bac2668ea', status
assert info.pbi_uid == parent.pbi_uid == 502, identity
assert argv[0] == str(package / 'bin/safeyolo-vm') and argv[1] == 'run', argv
for flag, expected in {
    '--kernel': package / 'share/Image', '--initrd': package / 'share/initramfs.cpio.gz',
    '--rootfs': package / 'share/rootfs-base.ext4',
    '--shell-socket': lab / 'shell.sock', '--control-socket': lab / 'control.sock',
}.items():
    assert argv[argv.index(flag) + 1] == str(expected), argv
assert parent_argv[1:] == ['-I', '-B', '/Users/sy-agent/bin/run-vz-test',
                            '--timeout-seconds', '60', '--', *argv], parent_argv
assert (lab / 'status/vm-status').read_text().strip() == 'ready'
stream = socket.socket(socket.AF_UNIX)
stream.settimeout(3)
stream.connect(str(lab / 'shell.sock'))
client = paramiko.SSHClient()
# This disposable guest generates its host key at boot. The private UDS and
# verified helper identify the fixture; no unrelated SSH endpoint is used.
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect('seatbelt-622', username='agent', sock=stream,
                   pkey=paramiko.Ed25519Key.from_private_key_file(str(package / 'data/vm_ssh_key')),
                   look_for_keys=False, allow_agent=False, timeout=3, banner_timeout=3, auth_timeout=3)
    command = ("set -eu; test \"$(id -u)\" = 1000; id; uname -r; "
               "test \"$(cat /workspace/host-marker)\" = seatbelt-622-owned-share; "
               "printf 'guest-to-host-622\\n' > /workspace/guest-marker; "
               "findmnt -n -t virtiofs -o SOURCE,TARGET /workspace")
    stdin, stdout, stderr = client.exec_command(command, timeout=10)
    stdin.close()
    output, error = stdout.read().decode(), stderr.read().decode()
    result = stdout.channel.recv_exit_status()
    (lab / 'guest-result.json').write_text(json.dumps(
        dict(status=result, stdout=output, stderr=error), indent=2) + '\n')
    assert result == 0, (output, error)
    assert output.splitlines()[-1].split() == ['workspace', '/workspace'], output
    assert (lab / 'share/guest-marker').read_text() == 'guest-to-host-622\n'
    print('Guest identity and mounted share:', output, flush=True)
    print('PASS: host-to-guest and guest-to-host share markers', flush=True)
finally:
    # A poweroff request is best effort. The foreground runner still owns
    # stopping and reaping the exact helper, including on any assertion failure.
    try:
        if client.get_transport() and client.get_transport().is_active():
            client.exec_command('sudo -n /usr/bin/busybox poweroff -f', timeout=3)
            print('Guest poweroff requested', flush=True)
    finally:
        client.close()
        stream.close()
PY
```

Retain stdout/stderr, `serial.log`, `helper-status.json`, `helper-process.json`
and `guest-result.json`. A failed command remains a failed witness even if
cleanup succeeds. A runner status of 124 records a deadline, not productivity.

## Owned teardown

If guest poweroff fails, the runner still stops and reaps its exact helper.
For an earlier stop, the worker can send TERM only after comparing the saved
UID, process birth and complete arguments. Inspection failure stops this command:

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import json, os, signal, sys
from pathlib import Path
lab = Path('/Users/sy-agent/s622-20261104')
sys.path.insert(0, str(lab / 'observers'))
from macos_process_argv import process_argv
from process_identity import _darwin_process_info
owned = json.loads((lab / 'helper-process.json').read_text())
info = _darwin_process_info(owned['pid'])
if info is not None:
    assert info.pbi_uid == owned['uid'] == 502
    assert [info.pbi_start_tvsec, info.pbi_start_tvusec] == owned['birth']
    assert [os.fsdecode(arg) for arg in process_argv(owned['pid'])] == owned['argv']
    os.kill(owned['pid'], signal.SIGTERM)
    print('TERM sent to verified helper', owned['pid'])
PY
```

After the trusted host terminal's foreground runner has returned, the worker
checks process and listener absence through SSH. File presence alone is not a
cleanup failure. If inspection fails or finds a survivor, retain all fixture
inputs and diagnostics and report the exact process or socket. Do not signal by
name or remove a running fixture.

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac \
  '/Users/sy-agent/full-guest-lab/venv/bin/python3 -I -B -' <<'PY'
import errno, os, socket, sys
from pathlib import Path
lab = Path('/Users/sy-agent/s622-20261104')
sys.path.insert(0, str(lab / 'observers'))
from macos_process_argv import owned_account_processes
assert os.getuid() == 502
assert owned_account_processes(502, [str(lab)]) == []
for name in ('shell.sock', 'control.sock'):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(2)
        try:
            stream.connect(str(lab / name))
        except OSError as error:
            assert error.errno in (errno.ENOENT, errno.ECONNREFUSED), error
        else:
            raise AssertionError(f'owned socket is still listening: {name}')
print('PASS: no owned process or socket listener')
# These names are exclusive to this disposable fixture. Keep guest/host logs,
# boot markers, config and observers for Lens, including after workload failure.
for name in ('shell.sock', 'control.sock', 'control.sock.lock'):
    (lab / name).unlink(missing_ok=True)
print('PASS: owned socket files removed; diagnostics retained')
PY
```

After successful teardown, the host administrator verifies and removes only
the protected test profile. Run this in the trusted Bristol terminal:

```sh
sudo -n /bin/sh <<'SH'
set -eu
profile=/Library/PrivilegedHelperTools/s622-20261020.sb
[ ! -L "$profile" ]
[ "$(stat -f '%u:%g:%Lp' "$profile")" = 0:0:644 ]
[ "$(shasum -a 256 "$profile" | awk '{print $1}')" = 05516d438610c5126595e15f5078f4a7f63a162bd910192c9dd5f19cfd5b3b7c ]
rm "$profile"
[ ! -e "$profile" ] && [ ! -L "$profile" ]
SH
```

Do not remove the active profile, package, images, private key or retained
#587/#1393 state. Return the trusted copy/launch receipt, actor/profile/helper
identities, guest command/share result, runner status and final process/socket
absence. Lens independently decides criterion 12 after physical execution.
