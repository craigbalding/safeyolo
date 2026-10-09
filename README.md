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

SafeYolo is pre-v1. The current source product is native Rust, with a signed
Swift VM helper on macOS. Python is used by repository tests and black-box
instruments. Public release publication is stopped; published Python CLI
packages describe the earlier product.

## Quick start

### 1. Install on your host

Use your ordinary account on a supported Ubuntu or Apple Silicon Mac host.
[Build a SafeYolo bundle](docs/native-policy.md#build-a-native-bundle), or obtain
an already prepared bundle for your host and selected source. The bundle's
`package-info` states its platform, build profile and minimum glibc or macOS
version. Verify a transferred archive against its supplied SHA-256 before
extracting it. The installer checks its internal checksums and identities.

Before installation, follow the [platform prerequisites and prepared guest
inputs](docs/native-policy.md#guest-prerequisites). The package supplies native
helpers and setup scripts; platform images/rootfs are separate. This arm64
Linux example uses an unpacked production bundle in your current directory and
prepared guest inputs at `$HOME/safeyolo-platform`. Replace that assets path
with the directory you obtained during preparation.

Install into a fresh `$HOME/.safeyolo`, the default location. If that directory
already contains an installation, preserve it and use the
[custom-instance reference](docs/native-policy.md#other-installation-paths).
SafeYolo does not convert an earlier installation's state. Follow
[installation details](docs/native-policy.md#install-and-start) if you need
another platform or build input.

The installer may ask for your normal sudo password to create the command
entry in a conventional bin directory. Instance files stay owned by your
account. New terminals use the default installation automatically.

```sh
./safeyolo-linux-arm64-production/install.sh --root "$HOME/.safeyolo" --platform-assets "$HOME/safeyolo-platform"
safeyolo --help
safeyolo --version
safeyolo start
safeyolo status
```

Use `linux-amd64` for x86_64 Ubuntu or `darwin-arm64` for Apple Silicon.
Installation creates configuration, trust and private tokens. It requires no
Python, wheel, virtual environment or uv tool installation. Status identifies
the selected root and reports `proxy_state: running` after successful startup.
If installation or startup fails, resolve its named error before retrying.
For source installation, the repository's `./install.sh` delegates to the same
installer and accepts the same inputs.

To try a small task on a prepared Ubuntu host, use the disposable
[Demo](docs/demo.md). It uses your configured Codex login, with your agreement,
or a stopped guest's existing login. It shows the agent build a tiny app, asks
you to decide its real fixture request, and reads the resulting app response.

```sh
safeyolo demo
```

### 2. Choose your agent and workspace

Choose an existing project that you own. The agent can read and change that
project through `/workspace`. Host setup scripts run with your host permissions
and can copy selected files into its home.

The example uses the existing owned directory `$HOME/code` and Claude setup,
which copies selected host authentication and extensions. For another tool,
choose `codex-host-setup.sh`, `pi-host-setup.sh` or `mise-shell-host-setup.sh`
in the same installed directory before creating the agent. Ordinary Codex setup
requires its [first login inside the agent](contrib/HOST_SCRIPT_GUIDE.md#first-codex-login);
it does not copy host login credentials. The mise shell needs no model login.

```sh
safeyolo agent create work --workspace "$HOME/code" --host-script "$HOME/.safeyolo/assets/contrib/claude-host-setup.sh"
safeyolo agent start work
```

Ask the agent to list `/workspace` to check the selected project. Tools and
agent state under `/home/agent` persist.

### 3. Review access requests

Open a second terminal on the same host and account:

```sh
safeyolo inspect
```

Inspect lists agent names; select `work` to see its state and pending requests.
The banner identifies the instance and selected agent. Follow the
[inspect and approval example](docs/native-operator.md#inspect-and-decide-one-request)
to create a network prompt, read its scope and decide it. The fresh policy
allows network access by default, so a successful request does not create a
pending network item. A network approval allows reusable access to its host and
port; credential approval is separate. See [operator commands](docs/native-operator.md) and
[policy configuration](docs/CONFIGURATION.md#policy).

## Everyday commands

These commands use your default installation. For another instance, use the
[custom-instance reference](docs/native-policy.md#other-installation-paths).

| Task | Command |
| --- | --- |
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
