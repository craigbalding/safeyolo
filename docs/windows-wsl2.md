# Coding clients through WSL2

Run SafeYolo's Linux host commands inside Windows Subsystem for Linux 2
(WSL2). Windows and the WSL distribution are trusted host infrastructure;
gVisor confines the agent. A shared writable workspace remains real host data.

This reference starts with an existing, operator-prepared WSL2 distribution
and SafeYolo Linux installation. It covers host setup and terminal use, not
Windows provisioning or a cold installation. See the
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

Codex setup does not import the Windows or WSL user's login. Before submitting
a model task, deliberately provision or create the agent-local login through
the existing [first Codex login workflow](../contrib/HOST_SCRIPT_GUIDE.md#first-codex-login).
For a separately authorized subscription login, use the existing
[Codex credential import](credentials.md#use-codex-with-a-chatgpt-subscription)
for this instance and agent. Login adoption alone grants no proxy authority.
Keep credential contents private. Existing workspace consent, credential
approval and network rules remain applicable.

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

The accepted observations below start with prepared host and guest inputs.
They do not establish a cold public-bootstrap installation on Windows.
The remaining [packaged first-boot qualification](https://github.com/craigbalding/safeyolo/issues/1417)
must join the official bootstrap, package installation, shell readiness and
authenticated coding-client interaction on the selected WSL setup.
Installation completion alone is not shell or client readiness.

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

The retained 11 November 2026 observations used physical Windows 11 Pro 25H2,
Windows OpenSSH, PowerShell, WSL2 Ubuntu 24.04.5, a Linux account with user ID
(UID) and group ID (GID) 1000, network address translation (NAT), and an ext4
workspace.
The selected distribution was `SafeYoloTest` and the Linux user was `syop`.
These observations do not qualify other distributions, networking modes or
Windows terminal programs.
The selected Pro edition is an evidence binding, not a WSL2 requirement for
Pro or Enterprise. No nested Windows Server or Windows guest image was
qualified by this physical run.

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
