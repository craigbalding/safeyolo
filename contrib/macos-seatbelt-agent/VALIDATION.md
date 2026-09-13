# Tart acceptance record — 2026-09-13

The entry, profile and probe in this contribution were exercised through a real
SSH daemon in the operator's disposable Tart guest. Nothing was installed on the
physical host. The test used a dedicated non-admin `sy-seatbelt-test` account
(UID 59900), with its own home and the compiled native entry as its login shell.

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

## Tested source hashes

SHA-256 hashes of the runtime sources copied into the guest:

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

## SSH setup acceptance — 2026-09-13

The [configure-ssh](configure-ssh) helper was tested with the native macOS
26.6.2 `sshd` in the same Tart guest. To repeat the checks, use an administrator
terminal on a Mac with SSH host keys already provisioned. Change to the checkout's
`contrib/macos-seatbelt-agent` directory before running this command:

```sh
sudo /bin/sh ./test-configure-ssh.sh
```

The tests use temporary configuration files. They do not change the running
SSH service. The system startup-file check is redirected to a temporary file;
the rollback cases substitute a wrapper that deliberately fails the final
validation and delegates all other calls to the real `sshd`.

| Check | Result |
| --- | --- |
| Install and verify account settings | Pass |
| Preserve the original configuration's mode | Pass |
| Other account's effective settings unchanged | Pass |
| Repeat installation without duplicate includes | Pass |
| Existing account-specific rules and include precedence | Pass |
| Another account name and a configuration path containing spaces | Pass |
| Enabled user environment files and unsafe `AcceptEnv` patterns | Rejected before activation |
| Locale settings and unrelated custom environment variables | Accepted |
| Invalid existing configuration | Rejected without changing SSH files |
| Empty/comment-only system startup file | Accepted |
| System startup commands | Require explicit operator review |
| Final-validation failure on a new installation | Original configuration restored; new fragment removed |
| Final-validation failure on an existing installation | Original configuration and fragment restored |

All checks passed, and the temporary configuration files and backups were
removed. This run checks configuration installation and recovery; the SSH
login and confinement evidence remains the earlier boundary test record.

The shortened README's install block was also run on this Mac, redirecting only
its installation directory to a disposable fixture. Compilation, signing,
installed ownership/modes, and public-key contents passed. An invalid public
key stopped the block before installation. The fixture and keys were removed;
the account's login shell and active SSH configuration were not changed.

Tested SHA-256 hashes:

```text
3fe9f83a6982ae2b090cd156348d0d480e2fe63f01bf92a023e04ec5da9bd002  configure-ssh
17b344eb894dafcd80555b3803f6c3ab6b8f040900c851e831386331f56e7bb1  test-configure-ssh.sh
```
