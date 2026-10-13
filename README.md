# SafeYolo

SafeYolo runs coding agents in isolated Linux sandboxes with controlled network
and service access. Give an agent a workspace and guest-local root to install
tools, run browsers, start services and debug code within the permissions you
choose. Works with Claude Code, OpenAI Codex, Pi and other coding agents.

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

## What you get

- A separate sandbox and persistent home for each agent: hardware-backed Linux
  microVMs on Apple Silicon macOS, rootless gVisor on Linux.
- Mediated network access with per-agent host policies, approvals, rate budgets
  and service capabilities. Sandboxes have no external network interface.
- Host-owned service credentials and scoped credential enforcement. A network
  permission does not grant permission to send a credential.
- Operator commands for traffic, approvals, logs and diagnosis, with
  scoped exports and capture/retention limits. Commander provides the Mac GUI.
- Controlled labs, canonical Coord messaging and supervised factories.

SafeYolo is pre-v1. The native product uses Rust, with a signed Swift VM helper
on macOS. Native production downloads are available in the release linked below;
published Python CLI packages describe the earlier product. Python is used by
repository tests and black-box instruments. Automatic and later release
publication remain stopped.

## Quick start

### 1. Install on your host

Use your ordinary account on Ubuntu or an Apple Silicon Mac. Download the
production archive for your host and `SHA256SUMS` from the published
[native release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796).
This release contains host source `7a38dff14e7e4eacb4095da732ffe06d7c7c5796`;
the documentation also covers newer source. Use this explicit release, rather
than GitHub's Latest selector.

| Host | Production download |
| --- | --- |
| Ubuntu x86_64 | [safeyolo-linux-amd64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-linux-amd64-production.tar.gz) |
| Ubuntu arm64 | [safeyolo-linux-arm64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-linux-arm64-production.tar.gz) |
| Apple Silicon macOS | [safeyolo-darwin-arm64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-darwin-arm64-production.tar.gz) |

Save the archive and [SHA256SUMS](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/SHA256SUMS)
in the same directory. In a host terminal, change to that directory. On Ubuntu,
verify the archive with:

```sh
sha256sum --ignore-missing --check SHA256SUMS
```

On macOS, use:

```sh
shasum -a 256 --ignore-missing --check SHA256SUMS
```

Continue only when the downloaded archive's filename is reported as `OK`.
Before installation, complete the [platform prerequisites](docs/native-policy.md#guest-prerequisites).
Ubuntu needs the host administrator's runsc and user-namespace setup. Both
platforms need Bash, curl, tar and a trusted network route for guest and runtime
downloads. The published default guest is acquired anonymously from GitHub
Container Registry (GHCR); no registry account or local guest build is needed.

Use a fresh `$HOME/.safeyolo`, the default installation directory. If it already
contains an installation, preserve it and follow the
[custom-instance reference](docs/native-policy.md#other-installation-paths).
SafeYolo does not convert earlier state. Installation creates configuration,
trust and private tokens. It may ask for your normal sudo password to create
the command entry or preserve Linux guest ownership. Instance files stay owned
by your account.

The commands below use the Ubuntu x86_64 download. For Ubuntu arm64, replace
`linux-amd64` with `linux-arm64`; for Apple Silicon, replace it with
`darwin-arm64`. The extracted `package-info` records the minimum glibc or macOS
version, which the installer checks before installation. No compiler or Python
installation is needed. Downloaded guest assets remain in
`$HOME/.local/share/safeyolo/guests`. Keep that directory: Linux instances
reference its prepared trees.

```sh
tar -xzf safeyolo-linux-amd64-production.tar.gz
cat safeyolo-linux-amd64-production/package-info
./safeyolo-linux-amd64-production/install.sh --root "$HOME/.safeyolo"
```

The installer prints the installed source and `profile=production`. In a new
host terminal, check the installed version and start the proxy:

```sh
safeyolo --version
safeyolo start
safeyolo status
```

Version must identify the release's host source and production profile. Status
identifies your installation and reports `proxy_state: running`. If a command
fails, resolve its named error before continuing. See
[installation details](docs/native-policy.md#install-and-start) for recovery,
[source builds](docs/native-policy.md#build-a-native-bundle) for contributor
inputs, and [other guest inputs](docs/native-policy.md#guest-prerequisites)
for offline or custom setups.

### 2. Run your first agent task

This example uses Claude Code and a new workspace at
`$HOME/code/safeyolo-first-run`. Choose an unused directory and agent name if
that path or `work` is already in use, and replace them in the commands below.
The agent can read and change the workspace through `/workspace`. Tools and
state in its `/home/agent` persist.

Have an account with Claude Code access ready. The bundled setup runs with your
host permissions and copies selected Claude settings, extensions and
`~/.claude/.credentials.json` when present. The agent can read copied credentials.
If your login is not copied, enter `/login` when Claude opens. Open its login
URL in your host browser and paste any prompted code back into the agent
terminal. See [Claude authentication](https://code.claude.com/docs/en/authentication#log-in-to-claude-code).
Claude runs with its own permission prompts disabled inside SafeYolo; SafeYolo
still enforces sandbox and access policy.
[Other agent setups](contrib/HOST_SCRIPT_GUIDE.md#bundled-setups), including
Codex's required [first guest login](contrib/HOST_SCRIPT_GUIDE.md#first-codex-login),
are available separately.

The fresh policy allows network access and prompts for unfamiliar credentials.
If installation of Claude or sign-in pauses for an access request, open a second
host terminal on the same account and run `safeyolo inspect`. Select `work`,
read the request's scope and decide it using the
[approval guide](docs/native-operator.md#inspect-and-decide-one-request).
Network approval and credential approval are separate.

From your host terminal, create the workspace and launch Claude in that terminal.
The setup installs Claude on its first guest run:

```sh
mkdir -p "$HOME/code/safeyolo-first-run"
safeyolo agent create work --workspace "$HOME/code/safeyolo-first-run" --host-script "$HOME/.safeyolo/assets/contrib/claude-host-setup.sh"
safeyolo agent start work --foreground
```

After sign-in, send Claude this task:

> Create `/workspace/index.html` as a complete HTML page with the heading
> "Hello from SafeYolo". Use no external dependencies.

### 3. Read the result on your host

After Claude reports completion, open a second host terminal on the same account:

```sh
cat "$HOME/code/safeyolo-first-run/index.html"
```

The file should contain the requested heading. Open it in your host browser to
see the page. The file remains in your workspace after stopping the agent.
When you finish, stop this agent's command and sandbox:

```sh
safeyolo agent stop work
```

Use the [everyday commands](#everyday-commands) to run and reconnect to an agent
for your own project. For an optional guided app task and access decision on
Ubuntu, see the [Demo](docs/demo.md).

## Everyday commands

These commands use your default installation. For another instance, use the
[custom-instance reference](docs/native-policy.md#other-installation-paths).

| Task | Command |
| --- | --- |
| Run the agent | `safeyolo agent start work` |
| Read proxy and agent state | `safeyolo status` |
| Reconnect to the agent terminal | `safeyolo agent attach work` |
| Open a separate shell | `safeyolo agent shell work` |
| Open the running desktop | `safeyolo agent present work` |
| Stop the agent | `safeyolo agent stop work` |
| Diagnose runtime state | `safeyolo doctor` |
| Stop the proxy and its Coord runtime | `safeyolo stop` |

Stopping the proxy leaves agents running. Stop each disposable agent separately.
[Agent launchers](docs/agent-launchers.md) describe persistent terminals,
foreground runs, sandbox-only starts and explicit supervision.
[Configuration](docs/CONFIGURATION.md) describes workspace, memory, mounts,
policy, trust and operator listeners. The [CLI guide](cli/README.md) links each
command family to its current operating instructions.

## Optional workflows

| Need | Documentation |
| --- | --- |
| Try a useful task and decide its access | [Demo](docs/demo.md) |
| Controlled experiments | [The Lab](cli/README.md#lab) and [agent debugging](docs/agent-debugging.md) |
| Coordinating agents | [Factories](docs/factories.md), [Coord](docs/coord-operations.md), [Mattermost](docs/coord-mattermost.md) |
| A different agent or setup | [Host scripts](contrib/HOST_SCRIPT_GUIDE.md) |
| Kali, Alpine or another rootfs | [Custom rootfs preparation](contrib/ROOTFS_SCRIPT_GUIDE.md) |
| Contained physical Mac access | [Seatbelt SSH account](contrib/macos-seatbelt-agent/README.md) |
| SafeYolo inside a Linux agent | [Nested integration lab](docs/nested-linux-lab.md) |
| Publish approved public output | [Dispatch](docs/dispatch-generation.md) |

## Trust model and reference

The host and operator are trusted; agent code may be compromised. SafeYolo
constrains agent actions, but cannot eliminate prompt injection, protect an
already compromised host or replace service authentication. Host scripts that
intentionally copy authentication into an agent have a different boundary from
host-vault service credentials. See [the security model](SECURITY.md).

- [Configuration](docs/CONFIGURATION.md) and [native settings](docs/native-settings.md)
- [Proxy architecture](docs/DEVELOPERS.md#architecture-overview) and [platform runtimes](docs/ARCHITECTURE.md#sandbox-runtime-and-networking)
- [Network routing and identity](docs/networking-vsock-uds.md)
- [Historical Python addons](docs/ADDONS.md)
- [Coord completion notes](docs/coord-completion-notes.md) and [factory proposals](docs/factory-proposals.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License.
