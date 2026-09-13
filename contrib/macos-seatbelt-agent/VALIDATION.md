# macOS Seatbelt acceptance records

The entry, profile and probe in this contribution were exercised through a real
SSH daemon in the operator's disposable Tart guest on 2026-09-13. Nothing was
installed on the physical host during those runs. The test used a dedicated non-admin `sy-seatbelt-test` account
(UID 59900), with its own home and the compiled native entry as its login shell.

The original Tart runs predate the setup simplifications and rename from
`agent-entry` to `agent-shell-launcher`; filenames and hashes below retain the
tested names.

| Component | Tested value |
| --- | --- |
| macOS | 26.6.2, build 25G83, arm64 |
| Swift | 6.3.3, swiftlang-6.3.3.1.3 |
| Python | 3.14.7, Homebrew |
| tmux | 3.7c, official tmux-builds macos-arm64 release |
| SafeYolo VM helper source | `d5ee2c369a9d2bf25f513f8a412aa77f55f650f5` |

The entry was compiled with `clang -Wall -Wextra -Werror -O2`, overriding only
the account and home macros. It was ad-hoc signed with `--options runtime` and
passed `codesign --verify --strict`. Installed entry components were root-owned,
with mode 755 for the directory, binary and session script, and 644 for the
profile and authorized public key. The SSH fragment passed both `sshd -t` and
`sshd -T -C` in the temporary daemon configuration.

## Boundary and workload results

The outside canary was readable and writable by the account without Seatbelt.
The outside UDS had mode 777. The TCP listeners were live, owned test fixtures.
These checks distinguish policy denials from missing services or Unix-mode
denials. Each SSH command entered through the configured login shell.

| Check | Result |
| --- | --- |
| Home read/write and child execution | Pass |
| Other-home canary read/write and symlink read | Denied |
| PTY read/write | Pass |
| Home UDS bind, connect and byte exchange | Pass |
| Outside UDS, symlink to it, and a client bound inside the home connecting outside | Denied; zero outside accepts |
| Baseline TCP connection to a live loopback fixture | Denied; zero accepts |
| Child signalling and task information | Pass |
| Signalling a known unsandboxed same-UID process | Denied |
| Outside same-UID basic task information | **Visible: 96 bytes; limitation below** |
| C and Swift compilation and execution | Pass |
| tmux server, pane capture and home socket | Pass |
| Interactive SSH attachment to tmux | Pass |
| Hostile `.zshenv` reading the outside canary before the requested command | Denied; empty leak file and confined marker |
| SSH remote TCP forwarding | Rejected with exit 255 |
| One explicit loopback TCP destination added to the operator-owned profile | Byte exchange succeeds; a different live port remains denied with zero accepts |
| Malformed profile | Nonzero exit; requested marker command never executes |
| Restore profile and stop the temporary SSH daemon | Pass |

The shipped probe produced:

```json
{"status":"pass","observations":{"outside_taskinfo_bytes":96}}
```

Its full `checks` array lists the exercised workload and enforced boundaries.
The surrounding SSH acceptance also checked the listeners' accept queues,
interactive entry, forwarding, the fixed-port adaptation, and malformed-policy
failure. Follow the [fixture procedure](REFERENCE.md#validation-and-adaptation)
to repeat these checks using your recorded fixture paths, ports, and PIDs.

## Measured limitations

`proc_pidinfo(PROC_PIDTASKINFO)` and `proc_pidpath` exposed basic information about
the unsandboxed same-UID process. Removing the `process-info` allowance did not
prevent the task-info read. Restricting `sysctl-read` to hardware/OS selectors,
or excluding `kern.proc` selectors, also left it readable. The same process's
signal check was denied. This profile does not promise full process metadata
isolation; the result is deliberately an observation, not a passed denial test.

The SafeYolo VM helper built and signed through the entry with:

```sh
cd ~/vm
swift build --disable-sandbox -c release
codesign --entitlements safeyolo-vm.entitlements --force -s - \
  .build/release/safeyolo-vm
.build/release/safeyolo-vm check
```

The build and signing succeeded. The check exited 1 with
`Error: Virtualization is not supported on this machine`. A normal SwiftPM build
first failed while trying to apply its additional sandbox; the documented flag
lets it build beneath the already-attached profile. **No VM boot was proved.**
Physical Apple Silicon acceptance is still required before claiming that the
helper's Virtualization.framework workload works under an adapted profile.

## Original boundary-run source hashes

SHA-256 hashes for the original broader boundary/workload run above. The
workflow run below also tests the current entry with its added `--check` mode:

```text
131afa24ad5f4194388191091349e9dc8e9d02c8a1873232dd06c7a4877d0e72  agent-entry.c
3a339427229b941845822ba993dcbb4e36ed28772a88a4064cad496018c3b57e  agent-dev.sb
8b0dcface9e336ee57a29095b2ba52d26effa0be81a71b914a61c1936e92a467  agent-session
af2249fc7890bca313e61088e1025d00d0b61006cdf40d84c29a01c8d63a86e4  probe.py
954af3152a9aa6a29d1b45cd919376be6afe873586b4782aa941e4cb5c80f903  sshd_config.example
```

The SSH fixture replaced only `Match User sy-agent` with the disposable account
name. The tmux release archive had SHA-256
`0a763dd0380aa980d239509654da1bc7455843706a3c050f6709c8cd2e13d12d`.

## Teardown

After acceptance, the dedicated account record, home, root-owned entry directory,
outside canary/socket directory, and temporary client/server private keys were
removed. The temporary SSH daemon was stopped and no processes with UID 59900
remained. Directory Services confirmed the account record was absent; a cached
`getpwnam` result immediately after deletion was not used as the authority.
Only the test source and nonsecret evidence were retained in the VM's admin lab
directory.

## Setup and client workflow acceptance (2026-09-13)

The current helpers were tested on macOS 26.6.2 (25G83), arm64, in the disposable
Tart VM. The native suite creates `sy-seatbelt-test` (UID 59900), its home and the
fixed entry directory. It refuses to reuse an existing account, UID, home or
entry. It installs a compiled/signed entry, changes the test account's login shell,
and starts an isolated SSH daemon on an ephemeral loopback port. The normal SSH
service is not changed. Teardown removes the test user launch domain, stops
remaining fixture processes, and checks that the UID has no processes before
removing the account and files. A failed cleanup makes the suite fail.

**Use a disposable Mac VM with Command Line Tools and SSH host keys provisioned.
In an administrator terminal, change to this checkout's
`contrib/macos-seatbelt-agent` directory before running:**

```sh
sudo /bin/sh ./test-configure-ssh.sh
```

The suite redirects the system startup-file check to a fixture. Failure cases
wrap the real `sshd` to reject final validation after activation.

| Check | Result |
| --- | --- |
| `--check` | Account, entry and candidate validation pass; shell and SSH files unchanged |
| Normal activation | Compiled shell installed before SSH fragment; resulting settings verified |
| File mode, other account settings, repeat installation | Preserved; no duplicate include |
| Custom account and configuration path containing spaces | Pass |
| Unsafe environment settings, invalid existing configuration | Rejected before activation |
| Harmless environment variables, comment-only system startup file | Accepted |
| System startup commands | Require explicit operator review |
| Admin membership and sudo grants | Rejected |
| File write ACL and directory delete-child ACL | Rejected |
| Read-only ACL | Accepted |
| Unsafe configuration directory | Rejected before activation |
| Final-validation failure, first installation | SSH configuration and original `/bin/zsh` restored; new fragment removed |
| Final-validation failure, existing installation | Previous configuration, fragment and compiled login shell restored |
| Failed SSH recovery validation | Compiled login shell retained; explicit recovery error |
| Generated client configuration and operator host-key handoff | Fresh SSH login succeeds with expected UID |
| Binary SSH stdin/stdout | 256 KiB round trip is unchanged |
| Read of an outside canary accessible without Seatbelt | Denied after SSH entry |
| Incorrect pinned server key | SSH rejects before account login |

The native client test uses an isolated CONNECT relay to exercise real OpenSSH,
the generated configuration and the Mac entry. It does not substitute that relay
for evidence about SafeYolo policy. Separately, `tests/test_seatbelt_client.py`
runs the actual SafeYolo network policy addon in mitmproxy inside Linux. It
verifies SSH banner/binary traffic without `tcp_hosts` or `ignore_hosts`
exceptions, port-scoped admission, zero upstream accepts on 403/428, approval
diagnostics, and refusal to fall back when a proxy is missing or unsupported.
HTTPS-proxy tests verify a trusted TLS connection and rejection of an untrusted
certificate or a TLS 1.1-only peer before sending CONNECT.
It also verifies the pinned client configuration and preservation of existing
client keys and global SSH configuration. These tests use only disposable local
listeners; they do not probe services on the physical host.

The [scripted install block](REFERENCE.md#scripted-setup), previously in the
README, was also tested in this Mac VM with its destination redirected to a
disposable fixture. Compilation, signing,
ownership/modes and public-key contents passed. An invalid public key or a
fingerprint mismatch stopped before installation. The native suite installs the same entry files
before testing the full SSH workflow above. Broader confinement evidence and
platform limits remain in the preceding sections.

Workflow source hashes for the native run and Linux client tests:

```text
d789b0ae177916b64179aa9de355e6f9735211929fa1ea875e326aa17e7c0fe1  agent-entry.c
71e408c6fdfa74e7b47256adcab02d0b4f3fcf0198e6b5b18bff30502a5e95d5  check-account.c
b55265a8c4c58952c49c8f93226307aaaa3c9c7de5ded7a3685c3a6249d68424  configure-ssh
4621765dffa74ecaaa27b58e9e5b155e923e3ff288bfe0fd929bd9b72c7016a9  configure-client
5e198a93f3703fdf73615118ca2b6d88f7808f1ae0a3cae317ea363508ca3379  ssh-via-proxy.py
4bd9f43e0c0e90fbdb81e5b452c236e6ffd3b9e09de013be69f051285d2d0d6c  test-configure-ssh.sh
ecd2dbc98dd59e6be9610d668c29ced8bc5c70cb5a606c93aba1d5a65a80d5a7  test-client-live.py
```

## Client handoff with socat (2026-09-13)

On Linux, the installed `socat` carried SSH banners and binary data through
mitmproxy with SafeYolo's real network-policy addon. The check used disposable
loopback endpoints and port-scoped admission, with no TCP inspection exceptions.
Denied and approval-required CONNECT requests produced `Forbidden` and
`Precondition Required` respectively, with zero upstream accepts.

The Mac helper's client-output and public-key selection code was exercised on
Linux with disposable RSA and Ed25519 host keys. OpenSSH parsed the printed
configuration with a custom account, port, and IPv6 destination; the dedicated
known-hosts entry contained the selected Ed25519 key. Missing public keys and
malformed destination inputs were rejected. Running the printed `mkdir` and
`printf` commands twice produced valid SSH files without duplicate entries.
The simplified key handoff returned the public key directly from its private
key, including when its `.pub` companion was missing or stale, without changing
the private key. The generated client instructions included the configured UID
for the agent to check.
Appending a second client key preserved the first, including when the existing
file lacked a final newline. New-file creation and mode 644 were checked under
a restrictive umask; OpenSSH parsed both authorized keys.
Shell syntax and documentation checks passed. These checks did not rerun macOS
account activation or establish a fresh login to the Mac.

## Process visibility acceptance (2026-09-13)

A follow-up run through the configured Mac SSH account exercised the remaining
process-management criterion in [issue #600](https://github.com/craigbalding/safeyolo/issues/600).
It used macOS 26.6.2 (25G83), arm64, Python 3.14.7 and tmux 3.7c, as UID 502.
The installed profile and session script matched repository revision
`fb042e6fc098ddb9c5cb7fb4ab3a81b9cee9b02b`. No installed policy or account settings
were changed for this run.

The operator started a disposable unsandboxed `/bin/sleep` under the same UID.
A native `proc_pidinfo(PROC_PIDTBSDINFO)` check verified the fixture's PID and UID;
`proc_pidpath` verified its executable. The completed process probe recorded:

| Check | Result |
| --- | --- |
| Child spawn, task information, custom signal, stop/continue, termination and reaping | Pass |
| Process-group signalling and grandchild reaping | Pass |
| Isolated tmux server, pane and worker-window management | Pass |
| Signal 0 and SIGCONT to the unsandboxed same-UID fixture | Denied with EPERM |
| Outside fixture task information | Visible: 96 bytes |
| Outside fixture BSD process information | Visible: 136 bytes |
| Outside fixture executable path | Visible: `/bin/sleep` |
| `proc_listallpids` | Returned 676 PIDs, including the outside fixture and PID 1 |
| `/bin/ps` targeting a child or the outside fixture | Execution denied with EPERM; the binary was root-owned and setuid |
| Probe children, process group, tmux server/panes and temporary home directory | Cleaned up |

The visibility-denial assertions failed, reproducing the earlier limitation.
The operator explicitly accepted this residual risk and approved closing the
issue with that exception. Process-management functionality passed; complete
process metadata isolation was not established. The installed policy remains
unchanged.

A dedicated non-admin account is recommended. Operators should run host
commands as that user only if they accept visibility of those commands' process
metadata from sandboxed processes. Personal and sensitive host work belongs
under a separate account; keep secrets out of process names and command-line
arguments. See [the risk guidance](REFERENCE.md#process-visibility-and-accepted-risk).
