# macOS Seatbelt acceptance records

## Execution-boundary acceptance (2026-11-08)

Lens independently accepted all 12 criteria in
[issue #622](https://github.com/craigbalding/safeyolo/issues/622#issuecomment-6726896131).
The reviewed source was [PR #1159 at fb669cdca5ef2fe9d6e0715dad18e4df46ea37e8](https://github.com/craigbalding/safeyolo/pull/1159/commits/fb669cdca5ef2fe9d6e0715dad18e4df46ea37e8).
Its reference profile was unchanged from `4472ce34bd53d0546c772f15f65b6fab377b8e12`.
The [native/account disposition](https://github.com/craigbalding/safeyolo/issues/622#issuecomment-6304513652)
establishes the execution denials and account checks. The
[developer/test disposition](https://github.com/craigbalding/safeyolo/issues/622#issuecomment-6304665613)
adds seven maintained SafeYolo test cases under that policy, with no skips or
failures. These results retain their recorded source, runtime and platform limits.

The final physical Virtualization.framework (VZ) observation used Bristol's
dedicated account through fresh Secure Shell (SSH) sessions as user ID (UID)
502. The fixed shell launcher selected the root-owned, mode 0644 profile at
`/Library/PrivilegedHelperTools/seatbelt-agent/agent-dev.sb`. That installed
profile contains the six denial forms from this PR: job creation,
LaunchServices/AppleEvents, the ServiceManagement broker, LaunchAgents writes,
Library replacement, and cron/at spool writes.

The installed profile also contains local VZ, VirtioFS, toolchain/cache and
loopback allowances, plus a separate same-sandbox signal restriction. It is
not byte-identical to the reference template. The VZ grants remain optional
and disabled in the reference profile.

| Physical witness input | SHA-256 |
| --- | --- |
| Installed profile | `2fd3165f583c6a9e734c09c5ed066e015c183b2eda47e9a1d7c1868b805d1780` |
| Retained VM helper | `a851f70365bf17aba2f83e11ca1fb4bd7d3fd7a7327ec9efc99c05c7449f6328` |
| `/evidence/operator/622/bristol-profile-proof-20261108.json` | `27d2aae4830f44ea5e3b8fe224ab2fa05564aafae4c1e307fdce7d25eabe7bc0` |

Both the original and replacement profiles reached VM ready and produced a
fresh, nonempty guest startup marker through the status share. Both used the
same helper and prepared boot inputs, with a separate cloned root filesystem,
home, status and workspace for each run. Each VM had 2 CPUs and 1024 MiB memory.
Exit 124 followed the declared 90-second runner deadline and exact-child reap;
it did not indicate a failure to reach readiness. The recorded elapsed times
were 95.44 and 95.45 seconds. Profile hashes remained unchanged during each run.

This establishes compatibility of the six denials with that explicitly permitted
VM workload. It does not qualify a whole PR build, current default-branch or
installed source, model execution, every platform, or the wider VZ security
assessment in [#616](https://github.com/craigbalding/safeyolo/issues/616).
The separate signal and supplementary Tart controls do not expand that scope.

Craig selected the tested installed profile as Bristol's ongoing daily baseline
on 8 November. The original backup remains available for regression recovery.
No restoration or physical witness replay is pending. Factory work has no
authority to obtain root on Bristol or change that installed policy. The
accepted evidence does not require a personal-account fixture.

## Account fixture inputs and noncreating observer, 2026-10-20

The first account attempt stopped before allocation because
`/Library/PrivilegedHelperTools` was absent. Sylab created only that missing
parent as root:wheel with mode 0755. The second attempt used staged source
`b48c1712f607259badda97b704dad53e9df50cd8` on Tart macOS 26.6.2/25G83, with
administrator user ID (UID) 501 and disposable account UID 59900. Its setup,
repeat, precedence, path, environment, startup, admin/sudo, access control list
(ACL), hardlink, consumer, crontab and rollback controls passed. The full script
exited 1 before fresh Secure Shell (SSH) login because no usable native SSH
transport was selected. The retired Python
`safeyolo` 0.1.1 on the ordinary PATH does not provide `ssh-proxy`.

The cleanup then retained the account and diagnostic lab. On this OS, its
`launchctl print user/59900` check created the domain it was meant to observe.
Sylab independently observed domain and process absence after a successful
scoped bootout. The direct print recreated the domain with the print command's
process ID (PID) as its creator and started `distnoted`. A second scoped bootout restored
absence. `launchctl print system` observed both states without creating the
user domain.

The permanent cleanup now reads the system inventory's `subdomains` section.
It matches the complete `user/59900` entry. Failed, incomplete or unknown
inventory retains the fixture and diagnostics. An existing domain still gets
only the scoped bootout, followed by another system inventory. UID signals,
exact-owned-crontab checks, temporary privilege revocation and tracked root
daemon/session guards retain their existing scope.

The account fixture now calls `configure-client --check` before allocation.
That check reuses the actual client's executable selection, version check and
`ssh-proxy --help` command. It does not read keys, prompt for a destination or
write client files. `SAFEYOLO_SSH_PROXY_EXECUTABLE` takes precedence over
`SAFEYOLO_CLI` and discovery. A missing or unsupported selection fails before
fixture allocation; it does not silently select another transport.

For this correction, Linux passed four focused tests with 40 controlled cases.
On Tart macOS 26.6.2 with system Python 3.9.6, the same cases and the native
system-inventory presence/absence/error test passed. The native check read
existing domains and an absent control UID; it did not open a user domain or
touch UID 59900. The actual retained executable also passed the root fixture's
preallocation prefix with the recipe's filtered environment and `sudo` options.
No account or root SSH daemon was started. The separate test inputs were removed.
From the checkout root, the focused command is:

```sh
python3 -I -B tests/test_seatbelt_fixture_safety.py -v FixtureSafetyTests SystemDomainInventoryTests
```

Sylab selected the existing native executable
`/Users/admin/forge769-correction-9925aada/proxy/target/debug/safeyolo` through
`SAFEYOLO_SSH_PROXY_EXECUTABLE`. Its version reported commit
`9925aadac447c51d52a3a24e2b56f554b921aaef`, profile `debug`. Its SHA-256 was
`bf6408363438c1976da580c0ea08213fa112603949fce500d8e20c7cd5408636`.
Both version and `ssh-proxy --help` exited 0. The `ssh_proxy.rs` source matched
the b48c module, with SHA-256
`3e969f1f6bc9de8584a87c23d36675501ebe31206a61ad6d0231a47ef91228f8`.
This identifies the retained transport; it is not a b48c production binary.

The unchanged b48c client script then passed at 23:40:44–23:40:45 UTC using the
retained account and client key in a separate owned subdirectory. Generated
configuration, fresh confined SSH identity, binary standard input/output, outside-canary
denial and host-key mismatch rejection passed. The tracked root daemon was
reaped with no session children, and its pending marker was absent.

Sylab separately verified owned cleanup at 23:43:00.661760 UTC. Root daemons
94358 and 94562 were absent; pending markers and the account crontab were absent.
Temporary admin membership and the sudoers file were revoked. Successful
account/UID inspection found no reserved account or UID. The noncreating system
inventory found no user domain, and `pgrep` returned 1. The account, home, entry,
sudoers file and lab were removed. The created parent was empty and removed.
The original full script remains a failed run. Its passed sections, the client
continuation and the independent cleanup are distinct observations. No new
account run or client continuation is needed for this fixture correction.
Lens's [native/account disposition](https://github.com/craigbalding/safeyolo/issues/622#issuecomment-6304513652)
accepted these observations. The
[physical VZ result](#execution-boundary-acceptance-2026-11-08) supplies the
separate VM workload evidence.

## Existing LaunchAgents aliases, 2026-10-20

Lens found that `a883eca23e1501c3c5aeee4dd2a7fca484724136` allowed a write through
a hardlink created outside `LaunchAgents` before confinement. The protected
file's contents changed. A focused owner probe also changed a protected input
through a pre-existing symlink to a writable file elsewhere in the test home.
Neither probe registered a job or demonstrated outside execution.

The filesystem preflight now inspects existing files throughout `LaunchAgents`.
It refuses writable multiply-linked files, including files whose owner can
restore write access. It also checks external symlink targets and their parents
with the existing account permission checks. Internal symlinks and inputs that
the account cannot modify remain usable. The checker names unsafe or unknown
inputs and does not remove or replace them. Privileged installation paths still
require root ownership.

On the existing Tart guest, macOS 26.6.2/25G83 and system Python 3.9.6 as UID501,
the focused module passed nine tests: the earlier 27 fixture cases and seven
native filesystem cases. The new cases cover writable and read-only-owner
hardlinks, a nested hardlink, an unaliased file with an internal symlink, an
external writable target, a protected system-file target and an unresolved link.
Unsafe files and aliases remained present with unchanged contents. After the
unsafe extra link was removed, preflight passed. The unaliased control passed
preflight and denied a direct confined write while an ordinary cache write worked.

The native test driver compiles and invokes the actual post-identity filesystem
function in `check-account.c`, using `clang -Wall -Wextra -Werror -O2`. It does
not invoke the root account/scheduler/SSH entrypoint. Linux passed the existing
three tests with 27 cases and skipped the six Mac-only tests. Sylab later
observed the reserved root fixture's writable-hardlink refusal,
protected-hardlink acceptance and unaliased controls at b48c, as recorded above.
The [physical VZ result](#execution-boundary-acceptance-2026-11-08) has its own
installed-profile and helper identities.

## Disposable fixture safety correction, 2026-10-20

The account fixture previously treated failed account/UID/process inspection as
absence. Its cleanup could remove the account, entry, home and diagnostic lab
while UID processes remained or could not be inspected. Lens reproduced these
branches at both PR #1159's first head and its base; the new crontab guard did
not introduce them.

The correction requires successful local account/UID inspection and process
status 1 before allocation. Existing targets and symlinks at the reserved home,
entry and sudoers paths refuse allocation. Cleanup retains the account, entry,
home and lab when UID-process absence or launchd removal cannot be established.
The live client retains a marker until it observes no root SSH session children
and reaps its tracked root daemon. The outer cleanup honors that marker.
Cleanup first attempts to revoke temporary admin membership and removes the
temporary sudoers file. The exact-owned-crontab comparison and retention of
unknown crontabs are preserved.

At `a883eca23e1501c3c5aeee4dd2a7fca484724136`, `uv run --frozen --no-sync python -m
unittest -v tests/test_seatbelt_fixture_safety.py` ran three tests with 27 cases on Linux.
The same source ran with system Python 3.9.6 and `/bin/sh` on the existing Tart
macOS 26.6.2 guest. All cases passed. The controlled cases redirect deletion to
temporary files and stub account, scheduler and process commands. They cover
legitimate absence/removal, inspection errors, live processes, failed launchd
removal, unknown cron state and uncertain root daemon/session teardown. Shell
syntax and Python compilation also passed on that guest. No account was
allocated and no real root SSH daemon was started by these controls.

The later operator observations above complete the reserved account execution
and cleanup. They do not turn the failed original script into a passing run.
The running SSH daemon was never reloaded. On cleanup uncertainty, the fixture
must still return nonzero and retain the printed lab path with its root SSH log
and pending marker intact.

The [completed physical VZ observation](#execution-boundary-acceptance-2026-11-08)
is separate from these account-fixture controls. Its actual boot and guest
startup/share results define the accepted scope.

## Execution-boundary hardening, 2026-10-20

Forge ran `python3 test-boundary.py` outside Seatbelt in the approved Tart guest
on macOS 26.6.2 (25G83), arm64. The operator process used the existing `admin`
account, UID 501. Each confined process used the supplied policy with
`AGENT_HOME` set to a fresh owned subdirectory. This was a scoped-process test,
not a converted dedicated account or a Bristol installation. System Python
was 3.9.6. Command Line Tools compiled the Objective-C helper; ad-hoc signatures
passed `codesign --verify --strict`.

| Actual operation | Observation |
| --- | --- |
| `launchctl bootstrap` and `submit` | Refused; the outside observer found no owned service. The kernel logged `deny job-creation`. |
| LaunchAgents directory/file creation, modification, directory rename and hardlink | EPERM. Replacing `Library` was also denied. Ordinary rc and cache writes worked. |
| Modern SMAppService LoginItem, LaunchAgent and LaunchDaemon registration | All three refused; the outside observer found no registration. Direct lookup of `com.apple.xpc.smd` returned `BOOTSTRAP_NOT_PRIVILEGED` (1100) inside confinement and succeeded outside. |
| Identical signed SMAppService bundles outside confinement | LoginItem and LaunchAgent reached enabled status (1). LaunchDaemon reached requiresApproval (2), despite the API returning false/EPERM. Each was explicitly unregistered and checked as status 0 before cleanup. No daemon approval was given. |
| `open -n -a` and direct LaunchServices API | Refused with no marker; the same application launched outside confinement and read the outside canary. |
| AppleEvent to a live owned receiver | The outside sender received a reply. The confined sender failed; lookup of `com.apple.coreservices.appleevents` returned 1100. No unrelated application was targeted. |
| `crontab`, `at -t 209901010000` and `batch` | `sandbox-exec` refused the setuid executables with EPERM. The outside observer found no crontab and an unchanged at queue. No scheduler setting was changed. |
| Existing unsafe launchd job, then confined `kickstart` | The helper ran with PPID 1 and read the outside canary. The job was removed through its exact owned label. `deny job-creation` alone does not confine a pre-existing consumer. |
| Corrected existing job, then confined `kickstart` | launchd ran the system `sandbox-exec` with a profile outside the writable test home, before reaching the same helper. The helper's outside-file read failed with EPERM. |
| Developer workload through the supplied policy | Home read/write, PTY, UDS exchange, child supervision, C/Swift compile and execute, and tmux passed. The outside-file/symlink and live TCP checks were denied. |

The modern LaunchAgent/LaunchDaemon calls reported code-signing inspection
errors inside the sandbox. The positive controls establish that these were
usable signed fixtures. The observed broker denial is preserved as an explicit
narrow policy rule. LoginItem's confined error was a disconnected socket.
Neither those error strings nor a false registration return alone establishes
absence; the outside status observations supply that check.

Trusted log inspection for the owned processes recorded denied Mach lookups
for `com.apple.xpc.smd`, `com.apple.CoreServices.coreservicesd`,
`com.apple.coreservices.launchservicesd`, `com.apple.coreservices.quarantine-resolver`,
`com.apple.lsd.mapdb`, `com.apple.lsd.modifydb`, and
`com.apple.coreservices.appleevents`. These names describe this OS observation;
they are not a new allowance list. Other incidental denial messages were not
turned into permissions.

The final grouped run returned `status: pass` and removed its fixture. Registered
services and launchd jobs were unregistered through their owner before removing
bundles. The owned AppleEvent receiver was terminated and reaped. The live TCP
listener received no connections. No factory policy, SSH or account setting was
installed or changed.
A focused follow-up also denied creation of an absent `LaunchAgents` directory
and modification of the corrected job's profile outside the writable test home.
The profile bytes remained unchanged; that fixture was removed.

The changed native account checker compiles with `-Wall -Wextra -Werror -O2` on
this guest. At that scoped-process test, the new account/consumer cases and real
SSH were unverified. The later operator observations above cover those account
operations at b48c. The later
[physical VZ observation](#execution-boundary-acceptance-2026-11-08) used the
installed profile with all six denials. Existing dated results below retain
their original source and scope.

## Earlier accepted workloads

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
The Tart result alone does not establish a working VZ VM. The later physical-host
record below demonstrates specific workloads with optional grants.

## Optional VZ workload acceptance (2026-09-14)

The work merged in [PR #615](https://github.com/craigbalding/safeyolo/pull/615)
ran on physical Apple Silicon with macOS 26.6.2 (25G83), using the non-admin
`sy-agent` account through its confined SSH entry. The operator enabled the
named VM-service lookup, generic Fuse extension and four path-specific share
delegation grants now recorded as commented examples in
[agent-dev.sb](agent-dev.sb). The baseline profile does not enable them.

The full guest booted with VirtioFS config, workspace, status and home shares.
Workspace/home access and shared-home recovery passed. The final bounded-load
run also passed with four shares on production helper source `a2f45b8d`, whose
native source matches the published admission candidate `1ed87803`.

Snapshot save and restore passed in a separate disk-only fixture on the earlier
production helper `62d8be6b`, after the operator created, unlocked and registered
the account's own login keychain. No graphical login was required for that
setup. This does not establish snapshot support for a VM with VirtioFS shares
or for every VM configuration.

These are successful workload observations, not a security assessment of the
new grants. Their effects on host resources, unrelated workloads and potential
sandbox escape remain under [issue #616](https://github.com/craigbalding/safeyolo/issues/616).
The [optional VZ setup](REFERENCE.md#optional-vz-workloads) preserves that
distinction and keeps the grants disabled by default.

## Public VZ export comparison (2026-11-06)

On physical Apple Silicon with macOS 26.6.2 (25G83), the confined `sy-agent`
account (UID 502) exercised nine direct-startup Virtualization.framework (VZ)
exports using disposable, nonsecret canaries. The installed profile permitted
both read and read-write file-extension issuance throughout `/Users/sy-agent`.
It also permitted the generic Fuse extension and the named VM-service lookup.
Ordinary host file access covered the home and the account's per-user temporary
directory. This profile differed from the selected-root examples shipped in
[agent-dev.sb](agent-dev.sb); those examples remain commented out.

The following identities bind the observation:

| Input | Tested value |
| --- | --- |
| Helper | `safeyolo-vm` 0.3.1, production arm64, clean source `e23f055957ec55d80b2b6c03f544b901773f8c8e` |
| Helper SHA-256 | `2dee6808cd4c9042a8478e51ad1e5d734113b5da351af2aa939d0d159c49e0fa` |
| Signature | Ad-hoc, hardened runtime, strict verification passed; only `com.apple.security.virtualization`; `get_task_allow=false` |
| Installed profile SHA-256 | `ec39eca32a8ac8ba2ceea9dcb4f587523bfbe2fdb8f2948b0386527ab9c32d80` |
| Profile parameters | `AGENT_HOME=/Users/sy-agent`, `TOOLCHAIN_ROOT=/opt/homebrew` |
| Guest | Linux 6.12.17; SSH user `agent` (UID 1000), data operations as guest root |

The helper's startup and share-construction sources matched assigned SafeYolo
source `e85bea5eec2182bc6ad1b1b414baa896087a22c2`. The only intervening Swift
changes were snapshot-restore diagnostics and their tests; snapshots were not
exercised. The existing read-only base disk and SSH initramfs supplied a fresh
tmpfs overlay for each VM. The retained `overlay.img` was not used.

Before export, the confined host driver directly read the canary and wrote and
reread a separate control file in each root and its descendant. These successful
operations established same-UID host access independently of guest I/O. The
directories were owned by UID 502 with mode 0777; canary files had mode 0666.
The outside-home fixture was a newly created directory under the account's
`/private/var/folders/.../T` directory. No other account's data was used.

Each VM requested one explicit `--share PATH:probe:ro` or `:rw` at startup,
then mounted `probe` as VirtioFS at `/probe`. The helper also constructed its
empty extra-share device. No live share update was used. All nine VMs booted
and mounted the requested export successfully. Each row covers reads of
`canary` and `descendant/canary`, and creation of `guest-write` at both levels:

| Requested export | Guest reads | Guest writes and independent host observation |
| --- | --- | --- |
| Selected root, read-only | Exact canary bytes | Exit 1; both host outputs absent |
| Selected root, writable | Exact canary bytes | Exit 0; both host outputs matched the written bytes |
| Unlisted home sibling, read-only | Exact canary bytes | Exit 1; both host outputs absent |
| Unlisted home sibling, writable | Exact canary bytes | Exit 0; both host outputs matched the written bytes |
| Symlink alias to selected writable root | Exact canary bytes | Exit 0; both host outputs matched the written bytes |
| Outside-home root, read-only | Exit 1 | Exit 1; both host outputs absent |
| Outside-home root, writable | Exit 1 | Exit 1; both host outputs absent |
| Selected descendant symlink to outside-home root, exported read-only | Exit 1 | Exit 1; both host outputs absent |
| Same descendant symlink, exported writable | Exit 1 | Exit 1; both host outputs absent |

The refused I/O returned `Operation not permitted` after a successful mount.
This is an observed public export/guest I/O result; the responsible private
issuance or service check was not identified. Access to the unlisted home
sibling is consistent with home-wide issuance and does not prove selected-root
confinement. Traversing the absolute outside-home symlink *within* the mounted
selected share returned `No such file or directory`; that guest path-resolution
failure does not establish service-side canonicalization. No tested outside-home
canary access succeeded. Cross-workload effects were not assessed.

A separate attempt to apply a nested sandbox before `/usr/bin/true` returned
71 with `sandbox-exec: sandbox_apply: Operation not permitted`. Both the
permissive nested profile and the profile denying the two file-issuance classes
failed before the command ran. Consequently, the selected-root-only profile
and file-grants-omitted export comparison remain unverified. This refusal is
not a guest denial, and the current-profile run does not replace those controls.

The driver and all nine recorded helper PIDs were independently absent after
the run. Runner exit 143 followed requested shutdown. After result transfer,
only the two new trial/canary directories were removed. The retained images,
original overlay, installed profile and login keychain were preserved.

The retained result `result.json` has SHA-256
`d4763242f593da42c258d23cb9128611e520351c3339f9517723676b4e4d39d0`.
It records the complete installed profile, commands, host controls, helper
status and guest output. The result, driver, helper/serial logs and independent
cleanup observations are retained under `/evidence/operator/616` for review.
[Issue #616](https://github.com/craigbalding/safeyolo/issues/616) remains open.
The private VZ recipient PID, UID and effective policy, raw-token transfer/reuse,
private requests, lifetime/revocation, broader cross-VM effects and other OS
versions remain unverified. These results do not establish complete containment
or change the optional policy or account-local snapshot-keychain instructions.

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
`contrib/macos-seatbelt-agent` directory. Set `native` below to the absolute path
of an existing macOS native SafeYolo command-line interface (CLI) or Coord
executable with `ssh-proxy`. Preserve the configured proxy and certificate
authority (CA) environment. This is the ordinary fresh
fixture recipe; it is not a command to repeat the completed 2026-10-20 run.**

If `/Library/PrivilegedHelperTools` is absent, create only that parent. Leave
an existing directory's ownership and mode intact:

```sh
if [ ! -e /Library/PrivilegedHelperTools ] && [ ! -L /Library/PrivilegedHelperTools ]; then
    sudo -n install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools
fi
```

Pass the selected executable explicitly through `sudo`. The fixture checks it
before allocating the account. The live client inherits the selection and CA
variables; its isolated CONNECT relay supplies only the test's proxy URL.

```sh
native=/absolute/path/to/native/safeyolo
sudo -n --preserve-env=HTTP_PROXY,HTTPS_PROXY,SSL_CERT_FILE,REQUESTS_CA_BUNDLE,NODE_EXTRA_CA_CERTS \
    env SAFEYOLO_SSH_PROXY_EXECUTABLE="$native" /bin/sh ./test-configure-ssh.sh
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
