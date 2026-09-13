# Seatbelt account reference

Use the [setup guide](README.md) for installation. This reference covers the
entry design, customization, daily work, and disposable validation fixtures.

Seatbelt is defense in depth, not VM-quality isolation. `sandbox-exec` is
deprecated, and its profile language is not a stable public Apple API.
Revalidate on each macOS version you use. Kernel defects, Seatbelt weaknesses,
and vulnerabilities in explicitly permitted services remain outside this
protection. The baseline grants no general Mach IPC, AppleEvents,
LaunchServices, or control of other VM/container runtimes.

## Files and entry order

- [agent-entry.c](agent-entry.c) builds a native login-shell shim. It checks its
  configured account and root-owned components, supplies a fixed environment,
  closes inherited descriptors other than standard I/O, and executes
  `/usr/bin/sandbox-exec` with a fixed profile.
- [agent-dev.sb](agent-dev.sb) contains the baseline policy.
- [agent-session](agent-session) runs **after** attachment. It creates home-scoped
  state directories and starts the command, interactive shell, or tmux session.
- [sshd_config.example](sshd_config.example) configures the SSH admission path.
- [configure-ssh](configure-ssh) installs and checks the SSH configuration.
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

## SSH identities

SafeYolo's existing `vm_ssh_key` serves the operator-to-guest connection. Its
default host location is `~/.safeyolo/data/vm_ssh_key`, with a `.pub` companion;
`SAFEYOLO_CONFIG_DIR` can change the configuration root. The guest receives its
public half in `~/.ssh/authorized_keys`. Keep that operator private key on the
host. The setup guide creates a separate client key for agent-to-Mac access.

To use an existing client identity, supply its public key during installation
and select its private key when connecting. The installed public key is kept
in the root-owned entry directory; the SSH fragment does not use the account's
home `authorized_keys` file.

## Account and toolchain customization

On the Mac, in the operator terminal, from any directory, verify an existing
account with `id sy-agent` and `dseditgroup -o checkmember -m sy-agent admin`.
The account must be Standard and have no sudo grants.

Before building on the Mac, set `AGENT_USER`, `AGENT_HOME`, and `TOOLCHAIN_ROOT`
as compiler definitions for any non-default values. Also replace `sy-agent` in
the setup guide's account and login commands. Pass the same account name to
`configure-ssh --user`; the helper generates its matching SSH fragment.
Never derive these settings or the profile path from SSH client environment
variables. The home must match the account record. The binary refuses root,
a different account, unexpected shell arguments, symlinked entry components,
and components writable by group or others. The default profile permits reads
of macOS system paths, Command Line Tools, and `/opt/homebrew`. Root-directory
listing and metadata for standard path aliases support the loader; they do not
grant reads beneath other users' homes.

## Entry ownership

**On the target Mac, use the trusted administrator/root terminal, from any
directory, after installing the entry and before enabling login.** Inspect Unix
permissions and access control lists (ACLs). The listed paths must be root-owned,
without group/other write bits or ACL entries allowing the dedicated account to
modify or replace them. The entry checks Unix ownership/modes, but not ACLs.

```sh
(
  entry=/Library/PrivilegedHelperTools/seatbelt-agent
  ls -ldeO /Library /Library/PrivilegedHelperTools "$entry" "$entry"/* \
    /etc/ssh /etc/ssh/sshd_config
)
```

Keep SSH configuration and authorized keys under the same ownership rule.
Home-installed tools are permitted; they execute after confinement attaches.

## Custom SSH configurations

On the Mac, in an administrator terminal at `contrib/macos-seatbelt-agent` in
the checkout, run `./configure-ssh --help` for the supported options. The account
name must match the compiled entry. For a separately managed SSH
daemon, reload that daemon after installation using its normal service command.

The helper requires the existing `PermitUserEnvironment` setting to be `no`.
That directive applies globally in the tested macOS sshd. The helper checks the
effective value before installing the fragment, so it cannot silently disable
environment files for other accounts. It also rejects `AcceptEnv` patterns that
match known variables affecting execution before Seatbelt, while permitting
locale settings and unrelated custom variables.

An existing `/etc/ssh/sshrc` with startup commands needs operator review because
the commands execute before Seatbelt attachment. The helper reports the file
and the `--reviewed-sshrc` option. Use that option only after checking that the
file does not source or execute files controlled by the dedicated account.
Empty or comment-only files need no review. These checks preserve the entry
requirements; they do not audit arbitrary startup code.

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

**Inside the client agent, as its normal user, change to the directory containing
the archive `workspace.tar`.** Have the client key from setup and an SSH
destination configured through the approved proxy transport. This example
replaces `workspace.tar` in the Mac account's home. It uses SSH command stdin;
forwarding is not needed.

```sh
(
  set -e
  printf 'Configured SSH destination or alias: '
  IFS= read -r destination
  ssh -i "$HOME/.ssh/id_ed25519_sy_agent" -l sy-agent -- "$destination" \
    'cat > workspace.tar' < workspace.tar
)
```

Extract the archive through another confined command. This entry does not
special-case an in-process SFTP subsystem; verify your chosen transfer client
through the same forced entry.

## Optional network access

The baseline contains no IP allowance. To obtain dependencies, either:

1. Fetch them through the coding agent's existing SafeYolo proxy route, then
   transfer the files into the macOS account; or
2. Have the operator create one fixed loopback listener outside this account's
   sandbox, bridged into an existing SafeYolo **per-agent** proxy socket.

For the second option, **run on the target Mac in a trusted operator terminal,
from any directory, outside the confined account**. Install `socat` first.
Choose the existing SafeYolo per-agent proxy socket you intend to expose and
ensure loopback TCP port 18080 is available. The command prompts for the socket
path and starts a foreground listener; leave that terminal open while using it.
This listener has no client authentication, so account for other local users
who can connect. Keep its lifecycle under operator control.

```sh
(
  set -e
  printf 'Absolute path to the existing per-agent proxy socket: '
  IFS= read -r proxy_socket
  test -S "$proxy_socket"
  exec socat TCP4-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork \
    "UNIX-CONNECT:$proxy_socket"
)
```

**On the Mac, as the operator, stop the account's existing coding sessions and
tmux server before editing the installed
`/Library/PrivilegedHelperTools/seatbelt-agent/agent-dev.sb`.** Add the following
profile rule for that same port. This is profile syntax, not a shell command.
Seatbelt's literal `localhost` selector permits only loopback on the named TCP
port; it does not resolve a DNS hostname. Choose fresh SSH sessions after editing.

```scheme
(allow network-outbound (remote tcp "localhost:18080"))
```

Inside a fresh confined Mac shell, set `HTTP_PROXY` and `HTTPS_PROXY` to
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
macOS rejects after this profile is attached. Inside the confined Mac account,
from the Swift package directory, use `swift build --disable-sandbox` to suppress
SwiftPM's additional sandbox.
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

**Prepare fixtures from the trusted operator session on a disposable Mac.**
Use a disposable account, a canary file outside its home, and a live loopback
TCP listener. Verify that the account can read the canary and open it for append
without Seatbelt; ordinary Unix permissions must not cause the expected denials.
An append-mode open need not change the canary's contents.

Copy `probe.py` into the dedicated home. Install Python 3, C/Swift
compilers, and tmux before running the probe. For optional outside-socket and
process checks, create a world-accessible Unix socket and an unsandboxed process
with the same UID. Use only that disposable process with `--outside-pid`;
never substitute an unrelated PID.

**Now enter the confined Mac account through SSH, as its normal user, from any
directory.** The following block prompts for your actual canary path and live
TCP port. It runs the baseline file, TCP, PTY, home-socket, compiler, and tmux
checks. To select the optional checks as well, add `--outside-socket` and
`--outside-pid` with the fixture path and PID you recorded before running it.

```sh
(
  set -e
  printf 'Absolute path to the disposable outside canary: '
  IFS= read -r outside_file
  printf 'TCP port of the live loopback fixture: '
  IFS= read -r loopback_port
  python3 "$HOME/probe.py" --outside-file "$outside_file" \
    --loopback-port "$loopback_port"
)
```

The probe requires all selected checks to pass. It removes temporary home files
and stops its tmux server and child process. From the operator session, check the
outside listeners too: denied connections must produce zero accepts.

Also test an interactive SSH/tmux attach, rejected SSH forwarding, and a hostile
`.zshenv` that tries to read the outside canary. It must fail before any requested
command runs. Temporarily add one fixed loopback allowance, verify that it reaches
only the intended listener, then restore the baseline. Keep the exact profile,
source revision, OS/tool versions, commands, results and cleanup evidence.

**On the Mac, in the trusted administrator terminal, from any directory**, inspect
recent denials with the following command:

```sh
sudo log show --last 5m --style compact \
  --predicate 'process == "kernel" AND eventMessage CONTAINS "Sandbox:"'
```

Grant access only for a failed, required workload. Successful tools can emit
harmless denials for optional discovery or instrumentation; those denials alone
do not justify opening Mach services, DTrace, global process access, or paths
outside the account. Stop test daemons and tmux servers and remove disposable
accounts/keys when testing is complete.
