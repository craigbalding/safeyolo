# SafeYolo

SafeYolo runs coding agents in isolated Linux sandboxes with controlled network
and service access. Give agents guest-local root to install tools, run browsers,
start services, and debug code within the workspace and permissions you choose.
They use ordinary command-line tools, libraries, and web services.

Works with Claude Code, OpenAI Codex, and other coding agents.

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

## What you get

- **An isolated workspace:** hardware-backed Linux microVMs on macOS, rootless
  gVisor on Linux. Each agent has its own sandbox and persistent home.
- **Controlled network access:** sandboxes have no external network interface.
  Traffic goes through SafeYolo's host proxy, with per-agent policies for hosts,
  approvals, rate budgets, and service capabilities.
- **Protected service credentials:** the service gateway keeps vaulted credentials
  on the host and injects them into authorized requests. Credential guards
  control where detected secrets can be sent.
- **Visible work:** inspect live HTTP(S) traffic, open sandboxed browser and desktop
  previews, and optionally share these operator views over Tailscale.
- **Limits and evidence:** rate budgets, circuit breakers, and loop detection
  contain runaway requests. Audit logs and queryable traffic records preserve
  request history and test context. Agents can inspect their policy and block
  reasons to resolve problems.

SafeYolo is **pre-v1** and currently installed from source. It builds on
[mitmproxy](https://mitmproxy.org/), with microVM patterns informed by
[Shuru](https://github.com/superhq-ai/shuru/).

## Quick Start

### 1. Install on your host

Use your normal account on the Mac or Linux machine that will run SafeYolo.
Install [uv](https://docs.astral.sh/uv/) first. Its tool directory, normally
`~/.local/bin`, must be on your `PATH`; the installer selects a supported Python
interpreter automatically.

| Host | Requirements |
| --- | --- |
| macOS | Apple Silicon (M1+), Command Line Tools, Lima, and tmux. For Homebrew, use `brew install lima tmux`. |
| Linux | x86_64 or arm64. Bootstrap checks build dependencies and configures the gVisor runtime. |

The commands below install the CLI, initialize `~/.safeyolo/`, and build the
platform's guest artifacts. On Linux, missing build packages cause bootstrap
to print an installation command and stop. Run the printed command, then rerun
`safeyolo bootstrap`. Runtime setup explains any privileged changes before
using `sudo`, which may prompt for your password.

```sh
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo
./install.sh
safeyolo bootstrap
```

**On macOS**, also build and install the Swift VM helper from this checkout:

```sh
make -C vm install
```

For other package managers, individual installation phases, and recovery, see
[installation details](cli/README.md#installation).

### 2. Choose your agent and workspace

Choose an existing project directory that you own. Replace `~/code` below with
that directory: the agent can read and change its files through `/workspace`.
The example names the agent `work`.

Choose the host setup before running the command. Host scripts execute with
your host permissions and can copy files into the agent's readable home.

| Setup | Authentication and result |
| --- | --- |
| `@claude` | Copies your Claude Code authentication and selected extensions into the agent, then launches Claude Code. |
| `@codex` | Launches Codex without copying host credentials. Complete the [first login inside the agent](contrib/HOST_SCRIPT_GUIDE.md#first-codex-login) after its first run installs the CLI. |
| `@mise-shell` | Opens a shell with mise for installing your tools. |

The example uses Claude Code; substitute another alias if needed:

```sh
safeyolo agent add work ~/code --host-script @claude
safeyolo agent run work
```

After first-run tool installation and any required login, you should reach the
agent's terminal. Ask it to list `/workspace`; it should see the project you
selected. Toolchains and agent state in `/home/agent` persist across restarts.

### 3. Handle access requests

When a request needs your approval, open a second terminal **on the host**:

```sh
safeyolo watch
```

Review the agent, destination or service capability, and requested credential use.
You can authorize, deny, or defer the request. See [access configuration](docs/CONFIGURATION.md#policy-cli-commands)
for host policies and [service access](cli/README.md#service-gateway)
for binding credentials to specific capabilities.

## Everyday commands

Run these on the host; `work` is the agent created above.

| Task | Command |
| --- | --- |
| List agents and their state | `safeyolo agent list` |
| Run an agent | `safeyolo agent run work` |
| Open a separate shell in a running sandbox | `safeyolo agent shell work` |
| Stop an agent | `safeyolo agent stop work` |
| Diagnose a setup or runtime problem | `safeyolo doctor` |

To add another agent, choose a different name and an existing workspace:

```sh
safeyolo agent add side-project ~/side-project --host-script @claude
safeyolo agent run side-project
```

For persistent background runs and reconnecting, see [agent launchers](docs/agent-launchers.md).
For changing a saved folder or memory allocation, see [agent configuration](docs/CONFIGURATION.md#workspace-and-memory).
The [CLI reference](cli/README.md) covers traffic inspection, previews, logs, and
other commands. `safeyolo doctor` checks reported prerequisites and runtime state;
[security verification](docs/security-verification.md) covers isolation testing.

## Optional workflows

| Need | Documentation |
| --- | --- |
| Guided tour | Run `safeyolo demo` on the host, with `safeyolo watch` in a second host terminal. |
| Controlled experiments | [The Lab](cli/README.md#lab) and [agent debugging tools](docs/agent-debugging.md) |
| Coordinating several agents | [Supervised factories](docs/factories.md), [coord operations](docs/coord-operations.md), and the [Mattermost adapter](docs/coord-mattermost.md) |
| A different agent or setup | [Host scripts](contrib/HOST_SCRIPT_GUIDE.md), including `@codex-coord` |
| Kali, Alpine, or another guest image | [Custom rootfs guide](contrib/ROOTFS_SCRIPT_GUIDE.md), [Kali example](contrib/kali-pentest/build-kali-rootfs.sh), and [Alpine example](contrib/alpine-minimal/build-alpine-rootfs.sh) |
| macOS work that needs a physical Mac | [Contained SSH access with Seatbelt](contrib/macos-seatbelt-agent/README.md) |
| SafeYolo inside an existing Linux agent | [Nested integration lab](docs/nested-linux-lab.md) |

## Trust model and reference

The host and operator are trusted. SafeYolo constrains agent actions but does
not eliminate prompt injection, protect an already compromised host, or replace
an external service's authentication. The service-vault guarantee is separate
from authentication that a host script intentionally copies into the agent.
See the [security model](SECURITY.md) for the boundaries and limitations.

- [Configuration](docs/CONFIGURATION.md)
- [Architecture and platform runtimes](docs/ARCHITECTURE.md)
- [Network routing and agent identity](docs/networking-vsock-uds.md)
- [Architecture and addons](docs/ADDONS.md)
- [Coord completion notes](docs/coord-completion-notes.md) and [factory proposals](docs/factory-proposals.md)
- [Dispatch generation](docs/dispatch-generation.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License.
