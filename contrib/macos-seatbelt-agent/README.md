# A macOS account for contained SSH development

This example gives a coding agent a useful macOS shell beneath Apple's Seatbelt
policy. Use a dedicated, non-admin account with no personal credentials. The
account can build, test, run subprocesses, use PTYs and tmux, and create Unix-domain
sockets beneath its home. The baseline denies IP networking and access to other
users' homes. It does not grant general Mach IPC, AppleEvents, LaunchServices,
or control of other VM/container runtimes.

Seatbelt is defense in depth, not VM-quality isolation. `sandbox-exec` is deprecated,
and the profile language is not a stable public Apple API. Revalidate on the macOS
versions you use. Kernel defects, Seatbelt weaknesses, and vulnerabilities in any
services you explicitly permit remain outside this protection.

## Files and entry order

- [agent-entry.c](agent-entry.c) builds a native login-shell shim. It checks its
  configured account and root-owned components, supplies a fixed environment,
  closes inherited descriptors other than standard I/O, and executes
  `/usr/bin/sandbox-exec` with a fixed profile.
- [agent-dev.sb](agent-dev.sb) contains the baseline policy.
- [agent-session](agent-session) runs **after** attachment. It creates home-scoped
  state directories and starts the command, interactive shell, or tmux session.
- [sshd_config.example](sshd_config.example) configures the SSH admission path.
- [probe.py](probe.py) exercises representative workloads and denied operations
  against operator-created disposable fixtures.
- [VALIDATION.md](VALIDATION.md) records the tested versions, results, source
  hashes, and remaining limitations.

```text
sshd → native account login shell → sandbox-exec → agent-session
                                                 ├─ zsh command
                                                 └─ tmux → zsh → build/test children
```

`ForceCommand` alone is insufficient: sshd invokes the account's login shell with
`-c`. A normal login shell can read user startup files before it executes the
forced command. The account's **UserShell must be the compiled entry binary**.
No shell startup file, command string, or user executable runs before Seatbelt
attachment in this entry path. The remote command is passed as an argument and
is interpreted only by the inner shell. See OpenSSH's
[session implementation](https://github.com/openssh/openssh-portable/blob/master/session.c)
and [sshd configuration reference](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5).

The signed entry uses the hardened runtime without library-injection entitlements.
Keep its parent directories, profile, session script, and authorized keys outside
the writable home. Do not add user-writable dynamic libraries to the entry binary.

## Operator installation

Run these steps from a trusted administrator session on the target Mac. First
exercise them in a disposable VM. This contribution does not install anything as
part of SafeYolo setup.

1. Create a **Standard**, non-admin account named `sy-agent`, with home
   `/Users/sy-agent`. Keep its password and recovery access with the operator.
   Do not give the agent a second login path, GUI automation session, sudo rule,
   or administrative group membership. Verify `id sy-agent` and
   `dseditgroup -o checkmember -m sy-agent admin`.
2. Inspect the profile and choose toolchain roots. The example permits read access
   to macOS system paths, Command Line Tools, and `/opt/homebrew`. It permits
   writes beneath the dedicated home and to terminal devices. Root-directory
   listing and metadata for standard path aliases support the macOS loader;
   they do not grant reads beneath other users' homes.
3. Build and install the entry components. From this directory:

```sh
xcrun clang -Wall -Wextra -Werror -O2 agent-entry.c -o agent-entry
codesign --force --sign - --options runtime --timestamp=none agent-entry
codesign --verify --strict agent-entry
sudo install -d -o root -g wheel -m 755 \
  /Library/PrivilegedHelperTools/seatbelt-agent
sudo install -o root -g wheel -m 755 agent-entry agent-session \
  /Library/PrivilegedHelperTools/seatbelt-agent/
sudo install -o root -g wheel -m 644 agent-dev.sb \
  /Library/PrivilegedHelperTools/seatbelt-agent/
sudo install -o root -g wheel -m 644 /path/to/agent-public-key.pub \
  /Library/PrivilegedHelperTools/seatbelt-agent/authorized_keys
sudo dscl . -create /Users/sy-agent UserShell \
  /Library/PrivilegedHelperTools/seatbelt-agent/agent-entry
```

For another account, change `AGENT_USER` and `AGENT_HOME` at build time, and change
`Match User` in the SSH fragment. `TOOLCHAIN_ROOT` is also a compile-time setting.
Never derive these settings or the profile path from SSH client environment
variables. The home must match the account record. The binary refuses root,
a different account, unexpected shell arguments, symlinked entry components,
and components writable by group or others.

Verify ownership, permissions **and ACLs** with `ls -ldeO` on the entry directory,
its parents, and each installed file. The binary checks Unix ownership/modes;
it does not audit ACLs. An ACL must not let the dedicated account replace or
modify entry components. Apply the same rule to the authorized-keys file and
sshd configuration. The account may manage tools beneath its own home; those
tools run only after confinement has been attached.

4. Review the SSH fragment before including it. `PermitUserEnvironment` is a
   global directive on the tested macOS sshd; it cannot go inside `Match User`.
   Its default is `no`. If your existing daemon needs a different setting for
   other accounts, use a separate SSH daemon configuration for this account.
   Do not assume an included value overrides an earlier global value. Avoid
   broad `AcceptEnv` rules. Review any administrator-owned `/etc/ssh/sshrc` too;
   it must not source or execute files controlled by this account.
5. Validate the real configuration with `sudo /usr/sbin/sshd -t`, then inspect
   the effective account settings before reloading your SSH service:

```sh
sudo /usr/sbin/sshd -T \
  -C user=sy-agent,host=localhost,addr=127.0.0.1
```

Confirm the forced command, root-owned authorized-keys path, key-only
`AuthenticationMethods`, disabled forwarding/X11/tunnel/user-rc settings, and
`PermitUserEnvironment no`. Keep the trusted administrator session open while
proving a separate login. The literal forced command `seatbelt-session` is a
marker accepted by the native entry; it is not resolved through `PATH`.

## Daily work and tmux

A remote command runs through the confined zsh. An interactive login creates or
attaches to tmux session `agent` when `tmux` is installed, with its socket at
`~/.local/state/tmux/default`. Otherwise it opens zsh directly. Install tmux in
the selected toolchain root or `~/.local/bin`; the fixed inner `PATH` includes
both. PTYs and their device ioctls are permitted for terminal operation.

`HOME`, `TMPDIR`, XDG config/cache/state paths, Python bytecode cache, and Clang's
module cache stay under the dedicated home. User startup files run inside the
policy and can configure additional home-scoped tools and caches. A tool that
ignores these settings may need its own cache flag. Avoid sharing operator
credentials or pointing its caches into another home.

All tmux servers must start through this entry. Stop the dedicated tmux server
before changing the profile: an existing server and its children retain the
policy attached when that server started. A later client connection does not
replace the server's policy. Avoid unsandboxed processes under this account.
Home-scoped sockets are intentionally general; any service you place there
becomes reachable by the account's processes.

Transfer archives through SSH command stdin and extract them beneath the home.
For example, run `ssh sy-agent@mac 'cat > workspace.tar' < workspace.tar`, then
extract it through another confined command. Do not enable SSH forwarding to
transfer files. This entry does not special-case an in-process SFTP subsystem;
verify your chosen file-transfer client through the same forced entry.

## Optional network access

The baseline contains no IP allowance. To obtain dependencies, either:

1. Fetch them through the coding agent's existing SafeYolo proxy route, then
   transfer the files into the macOS account; or
2. Have the operator create one fixed loopback listener outside this account's
   sandbox, bridged into an existing SafeYolo **per-agent** proxy socket.

For the second option, an illustrative operator command is:

```sh
socat TCP4-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork \
  UNIX-CONNECT:/absolute/path/to/the/agent/proxy.sock
```

Choose the port and the actual socket explicitly. The example does not create,
manage, or authenticate this listener. Account for other local users who can
reach a TCP loopback listener; a dedicated sandbox account is not a local
multi-user authentication system. Keep the listener's lifecycle under operator
control.

Add only that destination to the **operator-owned** profile:

```scheme
(allow network-outbound (remote tcp "localhost:18080"))
```

Seatbelt uses the literal `localhost` selector for loopback addresses; this rule
permits TCP only on the selected port. It is not a hostname resolved by DNS.

Inside the confined shell, set `HTTP_PROXY` and `HTTPS_PROXY` to
`http://127.0.0.1:18080`. Transfer and configure the appropriate SafeYolo CA file
for each tool, including `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and
`NODE_EXTRA_CA_CERTS` where applicable. The entry deliberately discards incoming
client environment; configure these values in the confined account's startup
files. Other IP destinations remain denied. Do not replace the allowance with
`localhost:*`, arbitrary network access, or broad host UDS access.

## SafeYolo as a worked workload

Clone or transfer SafeYolo beneath this account's home. Its mutable state,
including `~/.safeyolo`, `~/.safeyolo-test`, `~/.local/state/safeyolo`, agent
homes, overlays and logs, fits the home write rule. Per-agent proxy and shell
sockets, and the private traffic tmux socket, fit the general home UDS rules.
No per-socket profile generator is needed.

For tests that use local HTTP servers, choose a bounded set of test ports and
add explicit local bind/inbound and outbound rules for those fixtures in your
local profile. The baseline intentionally does not permit arbitrary localhost
services. Keep the default profile and the workload's extra allowances separate
in your operator records. Same-sandbox child signalling and process-information
rules support subprocess supervision without granting general process control.

**Process visibility is incomplete.** On the tested macOS 26.6.2 guest,
`proc_pidinfo(PROC_PIDTASKINFO)` returned basic task metrics for an unsandboxed
process with the same UID, and its executable path remained readable through
`proc_pidpath`. This persisted after removing the profile's `process-info`
allowance and after narrowing `sysctl-read`. Outside-process signalling was
denied. The profile does not provide a private PID namespace or complete process
metadata isolation; keep the account dedicated and put secrets in neither
process names nor command lines. The probe records outside task-info visibility
separately from the boundaries it requires to pass.

SwiftPM tries to attach a second sandbox while evaluating its manifest, which
macOS rejects after this profile is attached. Within this already-confined shell,
use `swift build --disable-sandbox` to suppress SwiftPM's additional sandbox.
The inherited Seatbelt profile still confines the compiler, manifest and build
children. This flag is not an instruction to run unconfined builds elsewhere.

For Apple Silicon VM work, build the repository's `vm` Swift package and sign
`safeyolo-vm` with its supplied entitlements. Start with `safeyolo-vm check`, then
prove a minimal boot on a physical Apple Silicon host. Inspect denials from a
trusted administrator session and add only the framework/Mach services actually
needed by that helper. The example contains **no speculative Virtualization
Mach allowances** and gives no control of unrelated container or VM daemons.
A successful build or capability check does not prove a VM can boot.

Tart guests do not provide the nested virtualization needed for that boot test.
The baseline shell/build/IPC checks can run in Tart; Virtualization.framework
boot acceptance must run on physical hardware before claiming that workload
works under the adapted profile.

## Validation and adaptation

Use a disposable account and fixtures. First prove that the account can read an
outside canary without Seatbelt, so a denied read cannot be mistaken for an
ordinary Unix permission failure. Make that disposable canary writable by the
account too and verify an append-mode open without changing its contents; the
confined probe requires reads and writes to fail. Create an outside listening TCP socket and,
optionally, a world-accessible UDS and an unsandboxed process with the same UID.
Copy `probe.py` under the dedicated home, then run it through SSH:

```sh
ssh sy-agent@mac 'python3 ~/probe.py \
  --outside-file /Users/disposable-other-home/canary \
  --loopback-port 18081 \
  --outside-socket /Users/disposable-other-home/test.sock \
  --outside-pid 12345'
```

Replace the example port and PID with your live disposable fixtures. Never use
an unrelated process as a signal-test target. The probe requires all selected
checks to pass, including C/Swift compilation and tmux. It removes its temporary
home files and stops its tmux server and child process. Check the outside
listeners too: denied connections must produce zero accepts.

Also test an interactive SSH/tmux attach, rejected SSH forwarding, and a hostile
`.zshenv` that tries to read the outside canary. It must fail before any requested
command runs. Temporarily add one fixed loopback allowance, verify that it reaches
only the intended listener, then restore the baseline. Keep the exact profile,
source revision, OS/tool versions, commands, results and cleanup evidence.

Inspect denials from the trusted administrator account, for example with
`sudo log show --last 5m --style compact --predicate 'process == "kernel" AND eventMessage CONTAINS "Sandbox:"'`.
Grant access only for a failed, required workload. Successful tools can emit
harmless denials for optional discovery or instrumentation; those denials alone
do not justify opening Mach services, DTrace, global process access, or paths
outside the account. Stop test daemons and tmux servers and remove disposable
accounts/keys when testing is complete.
