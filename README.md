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
  contain runaway requests. Audit logs and queryable traffic records retain
  scoped observations and test context, subject to capture and retention limits.
  Agents can inspect their policy and block reasons to resolve problems.

SafeYolo is **pre-v1**. Published host packages include the command-line
interface (CLI) and Rust proxy.
The first Rust release provides read-only traffic
inspection and selected exports; [traffic scope and capture limits](docs/DEVELOPERS.md#live-traffic-inspection)
describe what the view can show. Its microVM patterns are informed by
[Shuru](https://github.com/superhq-ai/shuru/).

## Quick Start

### 1. Install on your host

Use your normal account on the Mac or Linux machine that will run SafeYolo.
Open the [latest successful release](https://github.com/craigbalding/safeyolo/releases/latest).
Choose the **production** archive for your host. Current packages have these
compatibility requirements; each archive's `manifest.json` records its minimum,
which the installer checks before installation:

| Host | Archive | Compatibility |
| --- | --- | --- |
| Apple Silicon macOS | `safeyolo-darwin-arm64-production.tar.gz` | macOS 14.0 or newer |
| x86_64 Linux | `safeyolo-linux-amd64-production.tar.gz` | GNU libc (glibc) 2.39 or newer |
| arm64 Linux | `safeyolo-linux-arm64-production.tar.gz` | glibc 2.39 or newer |

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) first.
The package installer requires uv and uses it to select or download Python
3.12 or 3.13 and install dependencies. Cargo, Swift and a local C compiler are
not needed to install the host package.

Put uv's tool directory, normally `~/.local/bin`, on your `PATH` before
installation. This command updates your shell configuration; open a new
terminal after running it:

```sh
uv tool update-shell
```

Download the archive and `SHA256SUMS` from **the same release** into a new
directory. In a host terminal, change to that directory. Run only the commands
for your platform below. Run the checksum command first: it must print your
archive's filename followed by `: OK`. If the command fails or does not print
that result, stop. Do not extract or install the archive.

Installation replaces any existing uv `safeyolo` tool environment. On macOS,
it also installs the helper and guest terminal utility in `~/.safeyolo/bin/`.

**Apple Silicon macOS** — verify:

```sh
grep ' safeyolo-darwin-arm64-production.tar.gz$' SHA256SUMS | shasum -a 256 --check -
```

After the checksum reports `OK`, extract and install:

```sh
tar -xzf safeyolo-darwin-arm64-production.tar.gz
./safeyolo-darwin-arm64-production/install.sh
```

**x86_64 Linux** — verify:

```sh
grep ' safeyolo-linux-amd64-production.tar.gz$' SHA256SUMS | sha256sum --check -
```

After the checksum reports `OK`, extract and install:

```sh
tar -xzf safeyolo-linux-amd64-production.tar.gz
./safeyolo-linux-amd64-production/install.sh
```

**arm64 Linux** — verify:

```sh
grep ' safeyolo-linux-arm64-production.tar.gz$' SHA256SUMS | sha256sum --check -
```

After the checksum reports `OK`, extract and install:

```sh
tar -xzf safeyolo-linux-arm64-production.tar.gz
./safeyolo-linux-arm64-production/install.sh
```

If the installer fails, stop and resolve its reported error. After a successful
installation, confirm that the CLI loads:

```sh
safeyolo --help
```

Expected result: SafeYolo's command help appears. For debug profiles, upgrades
and package identity, see the [host package reference](docs/host-packages.md).

**Before adding an agent**, complete [guest and host runtime setup](cli/README.md#bootstrap-and-individual-phases).
Host packages do not include guest images or configure the sandbox runtime.
Guest builds currently need a source checkout and these platform prerequisites:

| Host | Guest/runtime setup prerequisites |
| --- | --- |
| macOS | Command Line Tools, Lima, and tmux. For Homebrew, use `brew install lima tmux`. The host package already installs the VM helper. |
| Linux | Bootstrap checks guest build dependencies and configures gVisor. If packages are missing, it prints an installation command and stops. |

**Source installation is an alternative.** For contributor builds and their
compiler requirements, see [source installation](cli/README.md#installation).
For an explicit return to the selected prior Python package, see
[package rollback](cli/README.md#return-to-the-prior-python-package).

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
- [Current proxy architecture](docs/DEVELOPERS.md#architecture-overview) and [platform runtimes](docs/ARCHITECTURE.md#sandbox-runtime-and-networking)
- [Network routing and agent identity](docs/networking-vsock-uds.md)
- [Historical Python addon reference](docs/ADDONS.md)
- [Historical Python proxy architecture](docs/ARCHITECTURE.md#historical-python-policy-model)
- [Coord completion notes](docs/coord-completion-notes.md) and [factory proposals](docs/factory-proposals.md)
- [Dispatch generation](docs/dispatch-generation.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License.
