# Seatbelt account reference

Use the [setup guide](README.md) for installation. This reference covers the
entry design, customization, daily work, and disposable validation fixtures.

## Why Seatbelt

Seatbelt lets this entry attach filesystem, network, and process restrictions
before starting a native Mac shell. Build tools and their children inherit the
profile while using the Mac's installed toolchain. This is useful for development
that needs macOS tools without a separate guest operating system.

The mechanism remains in use:

- **Apple:** WebKit includes sandbox policies for its
  [web content](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/WebProcess/com.apple.WebProcess.sb.in)
  and [network](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/mac/com.apple.WebKit.NetworkProcess.sb.in)
  processes.
- **OpenAI:** [Codex's macOS sandbox uses Seatbelt](https://learn.chatgpt.com/docs/sandboxing#prerequisites).
- **Anthropic:** [Claude Code's sandboxed Bash tool uses Seatbelt on macOS](https://code.claude.com/docs/en/sandboxing#os-level-enforcement).

`sandbox-exec` is the deprecated command-line interface used by this contribution.
Apple's [explanation of the deprecation](https://developer.apple.com/forums/thread/661939)
distinguishes custom sandbox profiles, whose language is not supported for
third-party development, from the supported, entitlement-based App Sandbox.
Continued use of Seatbelt does not give this custom profile a stable public API
or establish that it enforces the same policy as another product.

Treat this entry as defense in depth, not VM-quality isolation. Revalidate on
each macOS version you use; [VALIDATION.md](VALIDATION.md) records the tested
versions and boundaries, including incomplete process visibility. Kernel defects,
Seatbelt weaknesses, and vulnerabilities in explicitly permitted services remain
outside this protection. The baseline grants no general Mach IPC, AppleEvents,
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
- [configure-ssh](configure-ssh) checks the account and entry, then activates
  or recovers the login shell and SSH configuration together.
- [check-account.c](check-account.c) supplies the native account/ACL preflight.
- [configure-client](configure-client) writes the client route and pinned host key;
  [ssh-via-proxy.py](ssh-via-proxy.py) carries SSH through the configured proxy.
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
`configure-ssh --user` and `configure-client --user`; the helpers generate
matching server and client configurations.
Never derive these settings or the profile path from SSH client environment
variables. The home must match the account record. The binary refuses root,
a different account, unexpected shell arguments, symlinked entry components,
and components writable by group or others. The default profile permits reads
of macOS system paths, Command Line Tools, and `/opt/homebrew`. Root-directory
listing and metadata for standard path aliases support the loader; they do not
grant reads beneath other users' homes.

## Entry ownership and account preflight

`configure-ssh` checks an existing local account before changing admission. It
requires a non-root account outside the `admin` group (including nested
membership), no sudo grants, and a real home directory owned by the account.
It does not create an account, remove privileges, terminate processes, or audit
personal credentials and other login paths.

The helper stages preflight files and compiles [check-account.c](check-account.c)
using Command Line Tools under root's private home, before trusting the selected
configuration directory. It moves the backup beside that configuration only
after preflight and candidate validation pass.
The checker adopts the account's UID and supplementary groups without invoking
its shell. It checks the entry directory, binary, session script, profile,
authorized keys, selected SSH configuration, existing managed fragment and
system `sshrc`, plus their parent directories. Each must be root-owned, without
symlinks or group/other write bits. The selected SSH directory is canonicalized
first, so macOS's `/etc` alias resolves to `/private/etc`.

macOS extended `access()` checks evaluate effective permission, including ACL
ordering and group membership, to write, append, delete, remove children, or
change attributes, extended attributes, permissions or ownership. A modifying
grant fails preflight and names its path. Read-only ACLs are permitted. The
binary also retains its Unix ownership/mode checks on every entry; the ACL audit
runs during setup. Keep administrator-owned paths protected after installation.
Other files included by a custom daemon configuration remain the operator's
responsibility.

The helper verifies the code signature and hardened-runtime flag, then runs the
entry's `--check` under the account. This validates its compiled account/home and
runs `/usr/bin/true` under the installed profile, without shell startup files or
home-cache creation. It proves that the profile loads, not the full confinement
boundary. Home-installed tools execute only after normal confinement attaches.

## SSH setup mechanics

After installing entry files, the guide runs [configure-ssh](configure-ssh).
The helper owns the login-shell and SSH-configuration transition together.
`--check` performs preflight and candidate validation without activating either.
Entry files and authorized keys are installed separately in README step 2.

| Stage | Behaviour |
| --- | --- |
| Existing configuration | Checks syntax with `sshd -t` and evaluates settings with `sshd -T -C user=sy-agent,host=localhost,addr=127.0.0.1`, substituting a custom account when selected. |
| Startup environment | Checks `PermitUserEnvironment`, relevant `AcceptEnv` patterns, and whether system `sshrc` commands need review; see [custom SSH configurations](#custom-ssh-configurations). |
| Account and entry | Runs the [preflight](#entry-ownership-and-account-preflight) and records the previous local `UserShell`. |
| Candidate | Generates an account fragment from `sshd_config.example`, prepends its `Include`, and validates syntax and effective settings before activation. |
| Activation | Sets the compiled login shell **first**, installs the fragment, replaces the daemon configuration while preserving its mode, and verifies the resulting shell and SSH settings. |
| Repeat installation | Removes only its own exact `Include` line before adding it at the top again. |
| Failure during activation | Restores the previous SSH files and checks their syntax **before** restoring the previous login shell. If SSH recovery fails, it retains the compiled entry. |

For the defaults, the managed files are `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.seatbelt-sy-agent.conf`. The first `Include` gives the
fragment's account settings precedence over later matching settings. It selects
the root-owned authorized-key file, requires public-key authentication, disables
password and keyboard-interactive authentication and forwarding, and applies
`ForceCommand seatbelt-session`. PTYs remain enabled. The compiled login shell
must precede that forced command; see [entry order](#files-and-entry-order).
No daemon is restarted and existing sessions are left running.

After activation starts, the helper retains a backup directory beside the
selected daemon configuration and prints its path. `config.before` holds the
previous configuration, `shell.before` holds the previous login shell, and
`fragment.before` exists only for a previously installed fragment. Candidate
files and effective-setting output remain for diagnosis. A rejection before
activation leaves both states unchanged and removes temporary files.

The success message verifies the configured account's **loopback** SSH settings.
Test a fresh connection through the actual client transport. Configuration
validation does not prove login success or confinement; use the
[boundary probes](#validation-and-adaptation) for the latter.

## Setup recovery

Keep the trusted Mac administrator terminal open. For preflight rejection or a
successful automatic restore, correct the named problem and rerun
`sudo ./configure-ssh` from this contribution directory. Use the same `--user`
and `--config` options for a customized setup. Test a fresh login after success.

If the helper reports **Automatic restore failed**, keep the compiled login shell
while repairing SSH from the printed backup. From the trusted Mac administrator
terminal, restore `config.before` to the selected daemon configuration and
`fragment.before` to its managed fragment when present; otherwise remove only
the newly created fragment. Preserve ownership and modes. Check syntax with
`sudo /usr/sbin/sshd -t -f` and the selected configuration path. Only after SSH
restoration succeeds may you restore the value in `shell.before` with `dscl`.
This order also applies when deliberately undoing a successful installation.
A normal shell behind `ForceCommand` can run user startup code before confinement.

Recovery covers the selected daemon configuration, managed fragment and login
shell. It does not undo README step 2's entry files or authorized keys, account
creation, policy grants, or client configuration. Do not delete the installed
entry while the account still uses it as its login shell. Interrupted power or
`SIGKILL` cannot run the recovery trap; use the retained backup in the same order.

## Approved SSH route

**On the SafeYolo proxy host, use the operator's normal account with its
configured SafeYolo CLI, from any directory.** Choose the Mac's reachable host
and SSH port as seen **by the proxy**. `127.0.0.1` means the proxy host; use it only
when SSH runs there. Obtain the client agent's SafeYolo name from its operator
configuration. This grant permits that agent's CONNECT requests to that endpoint
and uses the global rate budget. It updates an existing matching endpoint entry.

```sh
(
  set -e
  printf 'SafeYolo client agent name: '
  IFS= read -r client_agent
  printf 'Mac host/IP as seen by the proxy: '
  IFS= read -r mac_host
  printf 'Mac SSH port: '
  IFS= read -r mac_port
  safeyolo policy host add "$mac_host" --port "$mac_port" --agent "$client_agent"
)
```

The CLI reports its policy update/reload result. Give these same host and port
values to the client. For custom SSH daemons, obtain the host public key from
that daemon's configured `HostKey`, rather than the default file in the README.
The client must receive the key through the trusted operator handoff; do not
replace this with an unverified `ssh-keyscan` result.

[configure-client](configure-client) reuses and verifies the client key pair at
`~/.ssh/id_ed25519_sy_agent{,.pub}`. It writes `config`, `known_hosts`, and a copy
of [ssh-via-proxy.py](ssh-via-proxy.py) under `~/.ssh/seatbelt-agent/`. It validates
the supplied host key and SSH configuration locally; it does not open a network
connection. Existing managed files are saved as `.before`; the global SSH
configuration and identity key remain unchanged. Invoke this dedicated
configuration with `ssh -F`, as shown in the README. For a different Mac account,
use `configure-client --user` with the same name used by `configure-ssh`.

The configuration pins the operator-supplied Ed25519 key with strict host-key
checking and uses `seatbelt-mac` as its host-key alias. The proxy command selects
`HTTPS_PROXY`, falling back to `HTTP_PROXY`, and supports HTTP or HTTPS proxy
URLs without embedded credentials. HTTPS proxies require TLS 1.2 or newer and
use the default certificate/hostname verification and trusted CA environment.
It opens only that proxy connection, sends
CONNECT for the configured destination, and relays SSH bytes unchanged after a
200 response. It has no direct destination fallback. HTTP status, blocker and
request ID remain visible on rejection; 428 directs the operator to the existing
approval flow. Retry after approval. A 403 is a denial; inspect the applicable
policy instead of changing the transport. SSH traffic needs no `ignore_hosts`
or TCP inspection exemption. CONNECT admission is policy checked; SSH encrypts
its subsequent session contents, which are not regular HTTP inspection traffic.

The Mac's Seatbelt IP restriction applies to processes started by the entry.
It does not prevent replies over the SSH session already admitted by `sshd`.
This route therefore requires no IP allowance in `agent-dev.sb`. Optional outbound
networking from within the Mac account is a separate facility described below.

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

For Apple Silicon VM work, use the confined Mac account and change to the
SafeYolo checkout's `vm` directory. Build the Swift package and sign
`.build/release/safeyolo-vm` using the supplied `safeyolo-vm.entitlements`.
From that same directory, run `.build/release/safeyolo-vm check`, then prove a
minimal boot on a physical Apple Silicon host. Inspect denials from a
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
