# Coding clients through WSL2

Run SafeYolo's Linux host commands inside Windows Subsystem for Linux 2
(WSL2). Windows and the WSL distribution are trusted host infrastructure;
gVisor confines the agent. A shared writable workspace remains real host data.

This reference starts with an existing, operator-prepared WSL2 distribution
and qualified Linux host and guest inputs. It covers packaged installation,
client setup and terminal use. Windows provisioning and cold public acquisition
are separate. See the
[qualification limits](#qualification-limits) before choosing this path.

## Enter the selected distribution

Use your existing authenticated Windows OpenSSH connection with a
pseudo-terminal (PTY). The example runs from a macOS or Linux terminal. It
assumes an existing Secure Shell (SSH) alias `windows-host` for your Windows
account, a distribution named `Ubuntu-24.04`, and an ordinary Linux account
`linux-user`.
Replace these names with your configured choices before running the command.
The Windows SSH command shell in the tested path was PowerShell.

```sh
ssh -tt windows-host 'wsl.exe -d Ubuntu-24.04 -u linux-user --exec /bin/bash'
```

The command selects the distribution and Linux user, then opens WSL Bash.
Run the remaining commands in that Bash session. Keep Linux arguments there
instead of embedding shell expressions or credentials in a Windows command.
Select gVisor's systrap platform explicitly for this session before starting
SafeYolo or preparing another installation:

```sh
export SAFEYOLO_RUNSC_PLATFORM=systrap
```

This selects the qualified Linux backend. It does not enable a Windows backend
or require `/dev/kvm`.

The qualification used Windows OpenSSH and PowerShell to invoke fixed Linux
Bash scripts and a Python observer in WSL. The observer launched the coding
client through `agent start` and its staged Bash command.
Arbitrary Windows quoting and local Windows Terminal entry remain unqualified.
No Windows launcher is required by the observed path, so this workflow adds none.

## Install from prepared inputs

In the selected WSL Bash session, use the ordinary Linux account that will own
the instance. The example assumes a matching repository checkout at
`$HOME/wsl-inputs/product-source`, an unpacked qualified host package at
`$HOME/wsl-inputs/bundle`, and prepared matching guest assets at
`$HOME/wsl-inputs/prepared/share`. Replace these input paths before running it.
The [recorded input identities](#packaged-first-boot) identify the qualified
continuous integration (CI) artifacts; they are not a published host release.
This procedure does not acquire or provision Windows, WSL or those artifacts.

The command creates a new instance at `$HOME/.safeyolo` and a command entry
under `$HOME/wsl-commands`. It verifies the full package and reuses the supplied
guest assets. If the destination already exists, inspect its original results
and use its installed command or select a separate root and command directory.
Review any proposed Linux host changes before granting the installer's existing
host-preparation consent. The qualification used an already prepared host and
declined any proposed change. It did not use `--yes`.

```sh
bash "$HOME/wsl-inputs/product-source/install.sh" --bundle "$HOME/wsl-inputs/bundle" --platform-assets "$HOME/wsl-inputs/prepared/share" --root "$HOME/.safeyolo" --command-dir "$HOME/wsl-commands"
```

Expected result: the installer prints the selected source commit, build profile,
installation root and command path. Host preparation reports `prepared` with
no applied changes on the qualified setup. Installation alone does not start
a guest or a coding client.

Before startup, provide the [runtime prerequisites](installation.md#guest-prerequisites),
including the pinned NATS executable or its permitted acquisition route.
The recorded isolated test copied only the accepted NATS executable, selected
an ephemeral administrative port and used no parent proxy. It reused no other
instance's state or keys.

## Prepare the client in WSL

Use the Linux account that owns the installed instance. The examples use an
existing installation at `$HOME/.safeyolo`, its matching Linux guest assets,
an existing Linux-filesystem project at `$HOME/code/my-project`, and a new
agent named `work`. Replace the project directory before running the command.
The selected instance must have its runtime and network prerequisites ready.
The [installation reference](installation.md#guest-prerequisites) describes them.

Read the selected host script first. It runs with your Linux host account's
permissions and stages the client command and SafeYolo context in the agent's
persistent home. The workspace becomes writable by the agent at startup.
Keep host scripts outside every agent-writable share. Existing script trust
checks still refuse an unsafe location.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent create work --workspace "$HOME/code/my-project" --host-script "$HOME/.safeyolo/assets/contrib/codex-host-setup.sh"
```

Creation runs host setup without starting a guest or Codex. SafeYolo supplies
`SAFEYOLO_AGENT_NAME`, `SAFEYOLO_AGENT_HOME` and `SAFEYOLO_AGENT_FOLDER` as Linux
names and paths. Inside the guest, the shared project is `/workspace`.
Do not invoke the setup script directly with Windows paths or substitute
Windows profile paths for the staged agent home.

Before authenticating a client, establish shell readiness in the same instance:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent start work --sandbox-only
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent shell work -c 'id; pwd'
```

Expected result: the command runs inside the guest as user ID (UID) 1000 and
prints `/workspace` as its working directory. This establishes shell execution,
not client authentication or a completed model task. The sandbox remains running.

Codex setup does not import the Windows or WSL user's login. Before submitting
a model task, deliberately provision or create the agent-local login through
the existing [first Codex login workflow](../contrib/HOST_SCRIPT_GUIDE.md#first-codex-login).
For a separately authorized subscription login, use the existing
[Codex credential import](credentials.md#use-codex-with-a-chatgpt-subscription)
for this instance and agent. Login adoption alone grants no proxy authority.
Keep credential contents private. Existing workspace consent, credential
approval and network rules remain applicable.

For reproduction with the recorded prepared client, supply a disposable copy
of the complete verified Codex package at `$HOME/wsl-inputs/codex-import`.
Its source metadata must match the installed SafeYolo build and its target must
match the Linux guest. The following import moves that copy's payload into the
new agent home. Keep the donor unchanged and separate from login material.
The destination must not already contain a `codex-package` directory.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" codex import "$HOME/wsl-inputs/codex-import" "$HOME/.safeyolo/agents/work/home"
```

Expected result: exit 0 and a complete package under the agent home's
`.safeyolo/codex-package`. Import does not authenticate the client. If the
source/platform guard refuses the copy, inspect the selected inputs; do not
edit a provenance marker to make it pass.

For an existing stopped agent, reuse its home and follow the
[host-script reapply procedure](../contrib/HOST_SCRIPT_GUIDE.md).
Claude setup is also staged through Bash, but Claude's real client terminal and
authentication were not qualified on this Windows path. Its
[host-state copying choice](../contrib/HOST_SCRIPT_GUIDE.md#bundled-setups)
remains separate from Codex authentication.

## Use the terminal and inspect the result

With the selected instance ready, start Codex in the current terminal.
Complete the selected login workflow before submitting model work.
This uses the complete Linux client
package; it does not require a Windows Codex installation or Node.js.
Arguments after `--` belong to this client launch. Bash quoting preserves
space-containing and empty arguments. To supply an initial task, pass the task
as one quoted argument after `--no-alt-screen`.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent start work --foreground -- --no-alt-screen
```

The foreground client uses the Windows SSH terminal through WSL. Exit through
the client's normal controls when finished. Codex handled Ctrl-D and Ctrl-C
with command exit 0 in the qualified runs. An interrupt does not necessarily
produce exit 130. After an interrupt, inspect the actual client and runtime
state before restarting or resubmitting a task.

From the same WSL account, use the selected instance to read the result:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent status work
```

Read the recorded command exit separately from the Windows SSH connection's
status. A successful SSH wrapper does not establish a successful client task.
If the terminal or runtime fails, use `agent diagnostics work` with the same
instance. Stop this agent explicitly when the sandbox is no longer needed:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent stop work
```

Stopping retains the agent home and workspace. See
[agent launchers](agent-launchers.md) for persistent terminals and recovery.

## Qualification limits

### Packaged first boot

The 12 November 2026 [#1417 qualification](https://github.com/craigbalding/safeyolo/issues/1417)
used the repository's official `install.sh` entry with an explicit verified
bundle, prepared guest assets and `SAFEYOLO_RUNSC_PLATFORM=systrap`.
It created a separate instance at `/home/syop/safeyolo-test/q1417/instance`,
with command entries in `q1417/commands` and an ext4 workspace in
`q1417/workspace`. Host preparation reported `prepared`, subordinate UID and
group ID (GID) bases 100000, host UID/GID 1000 and `applied=[]`.
No host preparation change was made.

The observed composition reached installation, a real guest shell and one
authenticated native Codex task. These are prepared-input results. They do
not establish cold public-release acquisition, installation or first use.

| Input | Exact identity |
| --- | --- |
| Controller checkout | `dcbedbf70748aba57ad72f55322721db8624dc92` |
| Official bootstrap SHA-256 | `dfb8215a4898a01dc79acba65d0cf99bf0da57201ff86e470cf88153843e9d2e` |
| Linux AMD64 production host package | `bf3a7b2fc880f0141f50e42be968e7a13b1623e8`, [CI producer 42865165121](https://github.com/craigbalding/safeyolo/actions/runs/42865165121) |
| Bundle checksum manifest SHA-256 | `be73a0041ae1f5d9337c8465ede26c307a404574d811b23dfaa302d49ccdf10a` |
| Prepared Linux settings SHA-256 | `c6b8c34b4c455225c853b0fe84bfab00bc24ddacb15b1fdaf2bef44c999fba39` |
| Guest source and producer | `27ea8aa6a700b473e35b040f35f89a08b076475b`, [CI producer 42981692240](https://github.com/craigbalding/safeyolo/actions/runs/42981692240) |
| Guest archive SHA-256 | `c232174140058313a679e4b780566744b89e769df36d67dac151d219b24b2f5c` |
| Guest Open Container Initiative (OCI) index SHA-256 | `5494a6ee6204492c330ba6e1ce073b57ab6c898537ece12825b2285d2336ecb8` |
| gVisor | Bundled `release-20261005.0-safeyolo.1` |
| Coding client | Complete native Codex `0.167.0`, `x86_64-unknown-linux-musl`, including code-mode host, ripgrep and resources |

The selected installer, package helpers, Linux launch/boot sources and Codex
setup/package sources were unchanged between the installed package and the
controller source. The dependency lockfile differed. This source comparison
does not qualify a later built package or establish Rustix equivalence.

Times below use Coordinated Universal Time (UTC) on 12 November.

| Stage | Original result |
| --- | --- |
| Bootstrap invocation, 00:02:17–00:02:22 | Exit 0. Full package verification passed before and after installation. The enclosing verification/configuration driver ran 00:02:12–00:02:26. |
| First shell, 00:03:07–00:03:11 | Exit 0. `agent start bbtest --sandbox-only` followed by `agent shell bbtest -c ...` checked guest UID 1000, read the host marker and printed `wsl1417-shell-ready`. The maintained platform assertion observed the owned systrap backend. Agent creation/setup preceded this interval. |
| Authenticated client, 00:31:01.246076–00:31:28.869392 | One real SSH-PTY launch, all three standard streams were terminals, native exit 0 and normal Ctrl-D completion. The host observed the requested file at 00:31:19.924851. Input and output each contained exactly 24 bytes, `wsl1417-bootstrap-shell` plus a newline, with SHA-256 `cf150fb5524cdca94a1ee44f4982873975348adae37751f9ad53149a3f001abd`. No model retry or timeout occurred. |
| Owned cleanup, 00:33:23.450616–00:33:23.628412 | Helper exit 1 solely for retained `bbtest/container.pid`. Native stop commands reported no other failure. Before/after reads showed agent, sandbox, control and runtime stopped, command exit 0, no owned processes and no UNIX listeners. Independent readback found process ID (PID) 724 recorded in the file and no `/proc/724`; its process birth was unavailable. The boot identity had changed. The original helper failure remains retained; file presence did not establish a live cleanup failure. |

Input acquisition, prior host preparation/reboots, required reading, consent and
approval, login provision, package import and protected-app recovery are outside
these stage intervals. Reading and approval durations were not measured. The
agent-local login was deliberately provisioned for the separately authorized
service before the task; creation/setup did not import it.

Original failures also remain part of the result. Read-only collection first
encountered a Windows command-length refusal and a timed-out stdin collector.
A shorter explicit Linux invocation recovered the results without replaying
bootstrap or shell. Protected credential lookups timed out before SSH on three
occasions; recovery used the existing operator-owned route. Package import
succeeded, then its complete-tree observer failed because the destination
directory and version file had modes `0755`/`0644` instead of the donor's
`0700`/`0600`. A read-only comparison established identical payload contents,
names, links, owners and payload modes. Correcting those two destination modes
preserved the original failure, donor and provenance guard; companion probes
then passed. None of these failures triggered an automatic model retry.

Reuse the [accepted #1413 reboot and recovery result](https://github.com/craigbalding/safeyolo/issues/1413#issuecomment-6801103593),
[#1414 private ingress](https://github.com/craigbalding/safeyolo/issues/1414#issuecomment-6804692641),
[#1415 guest acquisition and storage](https://github.com/craigbalding/safeyolo/issues/1415#issuecomment-6809789958)
and [#1416 terminal interruption](https://github.com/craigbalding/safeyolo/issues/1416#issuecomment-6808643164)
at their original input bindings. The dedicated distribution recovered its
saved marker and systrap boundary after WSL termination and a Windows reboot.
The #1417 driver requested no new Windows reboot or WSL termination and reused
the earlier interruption proof. Later changed WSL boot identities were observed;
their cause remains unknown. The earlier
normal-session WSL stop/restart also remains unexplained. These observations
give no always-on service guarantee.

Keep these boundaries separate when reproducing that qualification:

| Boundary | Required observation |
| --- | --- |
| Starting state | Record the Windows edition/build, WSL version/kernel, distribution, ordinary Linux account, effective networking mode, filesystem, existing installation and cached inputs. |
| Preparation | Record acquisition, host preparation, input verification and any reading or consent before the installation interval. Preserve the host-preparation prompt; `--yes` does not authorize workspace sharing or client authentication. |
| Installation and first shell | Record the exact bootstrap, host package and guest identities, explicit systrap selection, invocation, start/end points, exit and a successful command in the new guest. Mark prepared or cached inputs explicitly. |
| Coding client | Record the complete client package, separately authorized authentication, actual terminal interaction and a host-verified workspace result. Keep authentication and approval waits separate from installation and shell readiness. |
| Recovery and teardown | Inspect the original result before retrying an uncertain command. Stop only the owned agent, proxy and Coord instance. Retain original failures, stopped state and useful inputs. |

There is no new performance target. A fresh instance with prepared host or
guest bytes is a prepared-input result. It must not be described as a cold
first boot or a cold public download. Reuse the accepted reboot/recovery,
ingress, storage and terminal results at their actual source and input bindings;
do not repeat those journeys solely to collect a new report.

### Installed systrap checks

The maintained [installed-section runner](../tests/blackbox/README.md#run-installed-sections-with-one-preparation)
can reuse the selected installed package inside WSL. Run it from a clean
matching test checkout with its prepared Python environment and the selected
installation's runtime prerequisites. The example assumes that installation
is `$HOME/.safeyolo`. It creates separate writable test instances and starts
real guests. Reports and owned cleanup results go to the selected output
directory; use a new directory for a new attempt.

```sh
SAFEYOLO_RUNSC_PLATFORM=systrap .venv/bin/python tests/blackbox/installed_sections.py systrap --prepared-config "$HOME/.safeyolo" --section isolation --section lifecycle --artifacts "$HOME/wsl-isolation-lifecycle"
```

Success requires both sections to report `passed` with no cleanup failures.
The accepted #1413 run already exercised these sections with the inputs below.
The KVM-only `installed_ingress.py` selector does not establish systrap ingress;
use the separately accepted #1414 result for that boundary.

### Tested platform and inputs

The retained 11–12 November 2026 observations used physical Windows 11 Pro 25H2,
build 26200.9711, Windows OpenSSH, PowerShell, WSL 3.0.5.0 with kernel package
6.18.58.1-1 (`6.18.58.1-microsoft-standard-WSL2`), Ubuntu 24.04.5 x86_64,
a Linux account with user ID
(UID) and group ID (GID) 1000, network address translation (NAT), and an ext4
workspace.
The selected distribution was `SafeYoloTest` and the Linux user was `syop`.
Control used an authenticated Windows OpenSSH connection as `FANBOY\sy-test`
over the existing Tailscale route, then explicitly selected that distribution,
Linux account and interpreter. Credentials stayed private in the existing
in-memory consumer. The Windows account's provisioning and authority were
separate from the ordinary Linux account's UID/GID 1000 runtime.
These observations do not qualify other distributions, networking modes or
Windows terminal programs.
The selected Pro edition is an evidence binding, not a WSL2 requirement for
Pro or Enterprise. No nested Windows Server or Windows guest image was
qualified by this physical run. Mirrored networking and a native Windows
backend remain unqualified. The table below retains the separate #1416
setup and terminal results; its 38-byte task was not the #1417 24-byte task.

| Boundary | Observed result |
| --- | --- |
| Bash setup and consent | 27 focused setup controls and four consent-refusal cases passed inside WSL. Native Codex and Claude setup, reapplication, staged Linux paths and refusal of an agent-writable host script passed. Setup copied no login. |
| Real terminal delivery | A deterministic guest command received typed input and replied through Windows OpenSSH with a PTY. Space-containing, empty, quoted, literal shell-syntax and Unicode arguments arrived intact. The child exited 7. A separate Ctrl-C reached its interrupt marker and child exit 130. The command and runtime stopped. |
| Real coding client | Codex 0.167.0 ran through Windows OpenSSH with a PTY, PowerShell, a WSL Python observer and the staged Bash command. All three standard streams were terminals. One initial task copied an ext4 workspace file; the host independently verified all 38 bytes. Ctrl-D ended that launch with native exit 0. A separate launch with no model task received Ctrl-C and also exited 0. Neither launch reached its timeout. |
| Runtime stop | The coding commands exited before their sandboxes stopped. The final read found all three fixture agents stopped, no owned live processes and no UNIX listeners. The cleanup helper returned 1 for retained `bbpeer` process ID (PID) and socket paths; those paths did not establish a live process or listener. The helper's nonzero result remains part of the qualification evidence. |
| Windows-mounted workspace | The Windows profile mount used the Windows drive filesystem (DrvFS) through 9p with UID/GID 0 and no metadata option. Creating a host marker succeeded; changing its mode to `0600` failed with `EPERM` (operation not permitted). The attempt stopped before configuring or starting a guest with that workspace. Guest read/write, case behavior and symlink behavior remain unqualified. |

Use the Linux filesystem for the exercised workflow. The Windows mount result
does not establish that all Windows mounts fail, or that a changed mount would
work. No metadata, ownership or mount control was relaxed for qualification.
An empty observer file after the Windows failure is not a guest workspace
result.

The controller source was
`6db6bd4b3e36c67ea732e7986833c383152605bb`; the installed production package was
`bf3a7b2fc880f0141f50e42be968e7a13b1623e8`, with prepared guest inputs from
`27ea8aa6a700b473e35b040f35f89a08b076475b`.
Later production packages remain unqualified by this run.
The ordinary full package verifier passed preparation. After an intermittent
`sha256sum` failure, the terminal run selected the unchanged verifier's
maintained `shasum` support only for its child process. An incorrect digest was
rejected; complete package and runtime verification passed. The `sha256sum` failure's
cause remains unknown. No checksum requirement or package bytes were changed.

See [#1416](https://github.com/craigbalding/safeyolo/issues/1416) for independent
assessment and retained qualification evidence.
