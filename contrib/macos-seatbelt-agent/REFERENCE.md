# Seatbelt account reference

Use the [setup guide](README.md) for installation. This reference covers the
shell-launcher design, customization, daily work, and disposable validation fixtures.

## Why Seatbelt

Seatbelt lets this shell launcher attach filesystem, network, and process restrictions
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

Treat this shell launcher as defense in depth, not VM-quality isolation.
[VALIDATION.md](VALIDATION.md) records the tested
versions and boundaries, including incomplete process visibility. Kernel defects,
Seatbelt weaknesses, and vulnerabilities in explicitly permitted services remain
outside this protection. The baseline grants no general Mach IPC, AppleEvents,
LaunchServices, or control of other VM/container runtimes.

## Files and login sequence

- [agent-shell-launcher.c](agent-shell-launcher.c) builds the shell launcher used as the account's login shell. It checks its
  configured account and root-owned components, supplies a fixed environment,
  closes inherited descriptors other than standard I/O, and executes
  `/usr/bin/sandbox-exec` with a fixed profile.
- [agent-dev.sb](agent-dev.sb) contains the baseline policy.
- [agent-session](agent-session) runs **after** attachment. It creates home-scoped
  state directories and starts the command, interactive shell, or tmux session.
- [sshd_config.example](sshd_config.example) configures the SSH admission path.
- [configure-ssh](configure-ssh) checks the account and login shell, then activates
  or recovers the login shell and SSH configuration together.
- [check-account.c](check-account.c) supplies the native account/ACL preflight.
- The normal client route uses OpenSSH and `socat`. The optional
  [configure-client](configure-client) and [ssh-via-proxy.py](ssh-via-proxy.py)
  provide the alternative Python client setup described below.
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
forced command. The account's **UserShell must be `agent-shell-launcher`**.
No shell startup file, command string, or user executable runs before Seatbelt
attachment in this login path. The remote command is passed as an argument and
is interpreted only by the inner shell. See OpenSSH's
[session implementation](https://github.com/openssh/openssh-portable/blob/master/session.c)
and [sshd configuration reference](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5).

The signed shell launcher uses the hardened runtime without library-injection entitlements.
Keep its parent directories, profile, session script, and authorized keys outside
the writable home. Do not add user-writable dynamic libraries to the shell-launcher binary.

## SSH identities

SafeYolo's existing `vm_ssh_key` serves the operator-to-guest connection. Its
default host location is `~/.safeyolo/data/vm_ssh_key`, with a `.pub` companion;
`SAFEYOLO_CONFIG_DIR` can change the configuration root. The guest receives its
public half in `~/.ssh/authorized_keys`. Keep that operator private key on the
host. The setup guide creates a separate client key for agent-to-Mac access.

For another SSH client key, supply its public key during installation
and select its private key with `IdentityFile` in the client configuration.
The installed public key is kept
in the root-owned installation directory; the SSH fragment does not use the account's
home `authorized_keys` file.

To add another client agent, create its key using README step 1, then run the
key-append command from step 2 with its public key. Authorize that agent's SSH
route and give it the connection instructions from step 3. The launcher does
not need rebuilding; existing authorized keys and confined sessions stay valid.

## Account and toolchain customization

Before building on the Mac, set `AGENT_USER`, `AGENT_HOME`, and `TOOLCHAIN_ROOT`
as compiler definitions for any non-default values. Also replace `sy-agent` in
the setup guide's account and login commands. Pass the same account name to
`configure-ssh --user`; it generates matching server and client configurations
when called with `--host`.
The installation directory `/Library/PrivilegedHelperTools/seatbelt-agent` is
fixed in the source.
Never derive these settings or the profile path from SSH client environment
variables. The home must match the account record. The binary refuses root,
a different account, unexpected shell arguments, symlinked launcher files,
and components writable by group or others. The default profile permits reads
of macOS system paths, Command Line Tools, and `/opt/homebrew`. Root-directory
listing and metadata for standard path aliases support the loader; they do not
grant reads beneath other users' homes.

## Reuse an existing account

**On the Mac, use your existing administrator account, from any directory.**
Skip the README's account-creation command if `sy-agent` already exists. For a
different short name or home, apply the
[account customization](#account-and-toolchain-customization) before building.

The account must be a Standard account with no sudo grants and a real home
directory owned by that account. Inspect its identity, home and sudo policy:

```sh
id sy-agent
dscl . -read /Users/sy-agent NFSHomeDirectory
sudo -l -U sy-agent
```

The home must be `/Users/sy-agent` for the default build. The account must not
belong to `admin`, including through nested groups. The sudo query must report
that the user is not allowed to run sudo; its exit status alone is insufficient
on macOS. Resolve privileges or a home mismatch before installation.
`configure-ssh` performs the [account preflight](#file-ownership-and-account-preflight)
before changing admission.

Before converting an existing account, stop its unconfined shells and tmux
servers. Changing the login shell does not confine already-running processes.
Keep the account password outside the agent and review any personal credentials
or other login paths associated with the account. The helper does not perform
that review or terminate sessions.

## Remote Login troubleshooting

**Run these checks on the Mac, in your existing administrator terminal, from
any directory.** Remote Login enables the SSH service; membership in its access
group determines which accounts can use it. `configure-ssh` changes neither
setting. It configures the selected account's authentication and confined shell
after these prerequisites are ready.

If `systemsetup -setremotelogin on` reports that Full Disk Access is required,
grant that permission to the terminal application through macOS privacy settings
or your organization's management policy, then retry from a new terminal
session. `sudo` alone does not grant this privacy permission. This is permission
for the administrator's terminal to change the setting, not a requirement to
enable full disk access for remote users. See Apple's
[Full Disk Access settings](https://support.apple.com/guide/mac-help/mchlccb25729/mac).

To verify that the service is enabled:

```sh
sudo systemsetup -getremotelogin
```

Expect `Remote Login: On` before continuing. With the standard macOS Remote
Login settings, an absent `com.apple.access_ssh` group means access is allowed
for all users. In that case, skip the README's group-edit command and continue
with installation. Do not create or replace the group merely to clear a
missing-group error: creating it changes access to selected users, and replacing
it can remove existing members. For a managed Mac or custom access policy,
check that policy before treating a missing group as unrestricted access.

If the group exists, the README's `dseditgroup -o edit -a` command adds the
account while retaining its existing members. Verify the result with:

```sh
dseditgroup -o checkmember -m sy-agent com.apple.access_ssh
```

Expect a positive membership result. A negative result or directory-service
error must be resolved before continuing. Apple's
[Remote Login guide](https://support.apple.com/guide/mac-help/mchlp1066/mac)
describes the all-users and selected-users settings; `man dseditgroup` documents
the CLI operations.

## File ownership and account preflight

`configure-ssh` checks an existing local account before changing admission. It
requires a non-root account outside the `admin` group (including nested
membership), no sudo grants, and a real home directory owned by the account.
It does not create an account, remove privileges, enable Remote Login, change
its allowed-user group, terminate processes, or audit personal credentials and
other login paths.

The helper stages preflight files and compiles [check-account.c](check-account.c)
using Command Line Tools under root's private home, before trusting the selected
configuration directory. It moves the backup beside that configuration only
after preflight and candidate validation pass.
The checker adopts the account's UID and supplementary groups without invoking
its shell. It checks the installation directory, binary, session script, profile,
authorized keys, selected SSH configuration, existing managed fragment and
system `sshrc`, plus their parent directories. Each must be root-owned, without
symlinks or group/other write bits. The selected SSH directory is canonicalized
first, so macOS's `/etc` alias resolves to `/private/etc`.

macOS extended `access()` checks evaluate effective permission, including ACL
ordering and group membership, to write, append, delete, remove children, or
change attributes, extended attributes, permissions or ownership. A modifying
grant fails preflight and names its path. Read-only ACLs are permitted. The
binary also retains its Unix ownership/mode checks on every login; the ACL audit
runs during setup. Keep administrator-owned paths protected after installation.
Other files included by a custom daemon configuration remain the operator's
responsibility.

The helper verifies the code signature and hardened-runtime flag, then runs the
shell launcher's `--check` under the account. This validates its compiled account/home and
runs `/usr/bin/true` under the installed profile, without shell startup files or
home-cache creation. It proves that the profile loads, not the full confinement
boundary. Home-installed tools execute only after normal confinement attaches.

## SSH setup mechanics

After installing the launcher files, the guide runs [configure-ssh](configure-ssh).
The helper owns the login-shell and SSH-configuration transition together.
`--check` performs preflight and candidate validation without activating either.
Launcher files and authorized keys are installed separately in README step 2.

| Stage | Behaviour |
| --- | --- |
| Existing configuration | Checks syntax with `sshd -t` and evaluates settings with `sshd -T -C user=sy-agent,host=localhost,addr=127.0.0.1`, substituting a custom account when selected. |
| Startup environment | Checks `PermitUserEnvironment`, relevant `AcceptEnv` patterns, and whether system `sshrc` commands need review; see [custom SSH configurations](#custom-ssh-configurations). |
| Account and login shell | Runs the [preflight](#file-ownership-and-account-preflight) and records the previous local `UserShell`. |
| Candidate | Generates an account fragment from `sshd_config.example`, prepends its `Include`, and validates syntax and effective settings before activation. |
| Activation | Sets the compiled shell launcher **first**, installs the fragment, replaces the daemon configuration while preserving its mode, and verifies the resulting shell and SSH settings. |
| Repeat installation | Removes only its own exact `Include` line before adding it at the top again. |
| Failure during activation | Restores the previous SSH files and checks their syntax **before** restoring the previous login shell. If SSH recovery fails, it retains the compiled shell launcher. |

For the defaults, the managed files are `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.seatbelt-sy-agent.conf`. The first `Include` gives the
fragment's account settings precedence over later matching settings. It selects
the root-owned authorized-key file, requires public-key authentication, disables
password and keyboard-interactive authentication and forwarding, and applies
`ForceCommand seatbelt-session`. PTYs remain enabled. The compiled login shell
must precede that forced command; see [login sequence](#files-and-login-sequence).
No daemon is restarted and existing sessions are left running.

After activation starts, the helper retains a backup directory beside the
selected daemon configuration and prints its path. `config.before` holds the
previous configuration, `shell.before` holds the previous login shell, and
`fragment.before` exists only for a previously installed fragment. Candidate
files and effective-setting output remain for diagnosis. A rejection before
activation leaves both states unchanged and removes temporary files.

The success message verifies the configured account's **loopback** SSH settings.
The generated client instructions test a fresh connection and compare its UID
with the configured account. The profile can prevent macOS from displaying the
account name, so the check uses its numeric UID. This checks the SSH setup;
optional [boundary probes](#validation-and-adaptation) test confinement.

## Setup recovery

For preflight rejection or a successful automatic restore, correct the named problem and rerun
`sudo ./configure-ssh` from this contribution directory. Use the same `--user`
and `--config` options for a customized setup. Test a fresh login after success.

If the helper reports **Automatic restore failed**, keep the compiled shell launcher
while repairing SSH from the printed backup. From the trusted Mac administrator
terminal, restore `config.before` to the selected daemon configuration and
`fragment.before` to its managed fragment when present; otherwise remove only
the newly created fragment. Preserve ownership and modes. Check syntax with
`sudo /usr/sbin/sshd -t -f` and the selected configuration path. Only after SSH
restoration succeeds may you restore the value in `shell.before` with `dscl`.
This order also applies when deliberately undoing a successful installation.
A normal shell behind `ForceCommand` can run user startup code before confinement.

Recovery covers the selected daemon configuration, managed fragment and login
shell. It does not undo README step 2's launcher files or authorized keys, account
creation, policy grants, or client configuration. Do not delete the installed
launcher while the account still uses it as its login shell. Interrupted power or
`SIGKILL` cannot run the recovery trap; use the retained backup in the same order.

## Approved SSH route

**On the SafeYolo proxy host, use the operator's normal account with its
configured SafeYolo CLI, from any directory.** Choose the Mac's reachable host
and SSH port as seen **by the proxy**. `127.0.0.1` means the proxy host; use it only
when SSH runs there. Obtain the client agent's SafeYolo name from its operator
configuration. This grant permits that agent's CONNECT requests to that endpoint
and uses the global rate budget. It updates an existing matching endpoint entry.

Replace `mac.example.net`, `22`, and `client-agent` below with the destination
host, SSH port, and SafeYolo agent name you selected:

```sh
safeyolo policy host add mac.example.net --port 22 --agent client-agent
```

The CLI reports its policy update/reload result. Use these same host and port
values with `configure-ssh --host` and `--port` on your Mac. That command reads
the host public key from the selected daemon's `HostKey` files and includes it
in the client instructions. Copy that output from your Mac; do not substitute
an unverified `ssh-keyscan` result.

## Client proxy options

The README uses OpenSSH with a `socat` HTTP CONNECT transport. The standard
SafeYolo guest image includes `socat`. The generated client configuration uses
`http://127.0.0.1:8080`; for another HTTP proxy, substitute the host and
`proxyport` from the client's configured `HTTPS_PROXY` or `HTTP_PROXY` URL.
This transport connects only through that proxy. OpenSSH checks the Mac's
public host key against the dedicated `known_hosts` file.

The Mac setup prints the destination supplied with `--host` and `--port`, the
configured account, and an Ed25519 public host key from the selected daemon's
`HostKey` files. It reads the `.pub` companion file. With `--host`, a missing
public host key stops setup before activation. The destination is supplied by
the operator because the Mac cannot infer how the proxy reaches it.

`socat` reports a denied CONNECT as `Forbidden` (HTTP 403), and an approval
request as `Precondition Required` (HTTP 428). For approval, the operator runs
`safeyolo watch` or uses Commander, then the client retries. For a denial,
inspect the applicable policy. SSH traffic needs no `ignore_hosts` or TCP
inspection exemption. CONNECT admission is policy checked; SSH encrypts the
subsequent session contents.

### Optional Python client

For a proxy URL using `https://`, or to retain automatic proxy URL selection
and SafeYolo request-ID diagnostics, the previous Python client remains
available. It requires Python 3.9 or newer and both
[configure-client](configure-client) and [ssh-via-proxy.py](ssh-via-proxy.py)
together in a directory inside the client agent. It is optional; the `socat`
setup above requires neither file.

From that directory, run `python3 configure-client`, adding `--user` for a
custom Mac account. It asks for the approved destination host, port, and the
Mac's public host-key line beginning with `ssh-ed25519`. If copying from the
new Mac setup output, omit the leading `seatbelt-mac` host alias.

The helper reuses and verifies `~/.ssh/id_ed25519_sy_agent{,.pub}`. It writes
`config`, `known_hosts`, and the Python transport under `~/.ssh/seatbelt-agent/`.
It validates the key and SSH configuration locally without opening a network
connection. It saves existing managed files as `.before`; the global SSH
configuration and identity key remain unchanged. Connect using the same
`ssh -F` command as in the README.

The Python transport selects `HTTPS_PROXY`, falling back to `HTTP_PROXY`, and
supports HTTP or HTTPS proxy URLs without embedded credentials. HTTPS proxies
require TLS 1.2 or newer with certificate and hostname verification using the
trusted CA environment. It has no direct destination fallback. On rejection,
it reports the HTTP status, blocker and request ID; a 428 directs the operator
to the existing approval flow.

The Mac's Seatbelt IP restriction applies to processes started by the shell launcher.
It does not prevent replies over the SSH session already admitted by `sshd`.
This route therefore requires no IP allowance in `agent-dev.sb`. Optional outbound
networking from within the Mac account is a separate facility described below.

## Custom SSH configurations

On the Mac, in an administrator terminal at `contrib/macos-seatbelt-agent` in
the checkout, run `./configure-ssh --help` for the supported options. The account
name must match the compiled shell launcher. For a separately managed SSH
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
Empty or comment-only files need no review. These checks preserve the shell-launcher
requirements; they do not audit arbitrary startup code.

## Daily work and tmux

For an interactive login, run inside the client agent from any directory:

```sh
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac
```

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

All tmux servers must start through this shell launcher. Stop the dedicated tmux server
before changing the profile: an existing server and its children retain the
policy attached when that server started. A later client connection does not
replace the server's policy. Avoid unsandboxed processes under this account.
Home-scoped sockets are intentionally general; any service you place there
becomes reachable by the account's processes.

**Inside the client agent, as its normal user, change to the directory containing
the archive `workspace.tar`.** Use the dedicated client configuration created
by setup. This example replaces `workspace.tar` in the Mac account's home. It
uses SSH command stdin; forwarding is not needed.

```sh
ssh -F "$HOME/.ssh/seatbelt-agent/config" seatbelt-mac \
  'cat > workspace.tar' < workspace.tar
```

Extract the archive through another confined command. This shell launcher does not
special-case an in-process SFTP subsystem; verify your chosen transfer client
through the same shell launcher.

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
`NODE_EXTRA_CA_CERTS` where applicable. The shell launcher deliberately discards incoming
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

## Scripted setup

These optional blocks automate key creation/reuse and shell-launcher installation.
Read the [Mac setup requirements](README.md#2-set-up-the-mac) first. Use these
blocks in place of the key request and build/install commands in the README;
then run `configure-ssh` as shown there.

### Create the client key

**Run inside the client agent, as its normal user, from any directory. Do not
use sudo.** This creates an unattended SSH key in its persistent home and reuses
an existing private key. Use the printed public-key line in the Mac installation
block below. The private key stays with the client.

```sh
(
  set -eu
  umask 077
  mkdir -p "$HOME/.ssh"
  key="$HOME/.ssh/id_ed25519_sy_agent"
  if [ ! -e "$key" ] && [ ! -e "$key.pub" ]; then
    ssh-keygen -q -t ed25519 -N '' -C 'safeyolo-seatbelt-client' -f "$key"
  fi
  ssh-keygen -y -P '' -f "$key"
)
```

### Install the shell launcher

**Run on the target Mac, in an administrator or root terminal, from the checkout's
`contrib/macos-seatbelt-agent` directory.** Paste the public-key line from the
client-key block above when prompted. An unreadable key stops installation.
The block replaces installed launcher files and appends the new authorized key,
preserving existing keys. It stops on failure and leaves the account's login
shell unchanged at this stage.
After signing, `sudo` may prompt for your password.

```sh
(
  set -eu
  entry=/Library/PrivilegedHelperTools/seatbelt-agent
  staging=$(mktemp -d)
  trap 'rm -rf "$staging"' EXIT
  printf 'Paste the client public-key line, then press Return: '
  IFS= read -r public_key
  printf '%s\n' "$public_key" > "$staging/authorized_keys"
  ssh-keygen -lf "$staging/authorized_keys" > /dev/null
  xcrun clang -Wall -Wextra -Werror -O2 agent-shell-launcher.c -o "$staging/agent-shell-launcher"
  codesign --force --sign - --options runtime --timestamp=none "$staging/agent-shell-launcher"
  sudo install -d -o root -g wheel -m 755 "$entry"
  sudo install -o root -g wheel -m 755 "$staging/agent-shell-launcher" agent-session "$entry/"
  sudo install -o root -g wheel -m 644 agent-dev.sb "$entry/"
  printf '\n%s\n' "$public_key" | sudo tee -a "$entry/authorized_keys" > /dev/null
  sudo chmod 644 "$entry/authorized_keys"
)
```

After installation, run `sudo ./configure-ssh` with the host and port as shown
in [Mac setup](README.md#2-set-up-the-mac), then follow the client instructions.
