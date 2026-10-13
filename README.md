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

Use your ordinary account on supported Ubuntu or Apple Silicon macOS. Download the
production archive for your host and `SHA256SUMS` from the published
[native release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796).

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
Ubuntu needs administrator-supplied runsc and user-namespace setup. Both platforms
need Bash, curl, tar and network access for guest and runtime downloads.

Use a fresh `$HOME/.safeyolo`, the default installation directory. If it already
contains an installation, preserve it and follow the
[custom-instance reference](docs/native-policy.md#other-installation-paths).
SafeYolo does not convert earlier state. Installation creates configuration,
trust and private tokens. It may ask for your normal sudo password to create
the command entry or preserve Linux guest ownership. Instance files stay owned
by your account. The installer downloads the compatible public guest automatically.

The commands below use the Ubuntu x86_64 download. For Ubuntu arm64, replace
`linux-amd64` with `linux-arm64`; for Apple Silicon, replace it with
`darwin-arm64`. Stop if installation or startup reports an error; use the
[installation reference](docs/native-policy.md#install-and-start) to resolve it.

```sh
tar -xzf safeyolo-linux-amd64-production.tar.gz
./safeyolo-linux-amd64-production/install.sh --root "$HOME/.safeyolo"
```

In a new host terminal, start the proxy:

```sh
safeyolo start
safeyolo status
```

Status should report `proxy_state: running`.

### 2. Run your first agent task

This example uses Claude Code, a new owned workspace at
`$HOME/code/safeyolo-first-run`, and an unused agent name `work`. If either is
already in use, replace it in the commands. The agent can read and change this
directory through `/workspace`.

Have an account with Claude Code access ready. The bundled setup runs with your
host permissions and copies selected Claude settings, extensions and
`~/.claude/.credentials.json` when present. The agent can read copied credentials.
If your login is not copied, enter `/login` when Claude opens. Open its login
URL in your host browser and paste any prompted code back into the agent
terminal. See [Claude authentication](https://code.claude.com/docs/en/authentication).
Claude runs with its own permission prompts disabled inside SafeYolo; SafeYolo
still enforces sandbox and access policy.

The fresh policy allows network access and prompts for unfamiliar credentials.
For an access request, run `safeyolo inspect` in a second host terminal. Select
`work` and decide the request using the
[approval guide](docs/native-operator.md#inspect-and-decide-one-request).
Network approval and credential approval are separate.

Create the workspace and launch Claude in your current terminal. The setup
installs Claude on its first guest run:

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

Open the file in your host browser to see "Hello from SafeYolo". When you finish,
stop this agent's command and sandbox; its workspace and home remain available:

```sh
safeyolo agent stop work
```

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
