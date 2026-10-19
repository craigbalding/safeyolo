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

SafeYolo is pre-v1. It uses Rust and a signed Swift VM helper on macOS.
The quick start uses a tested production release. Published Python CLI packages
describe the earlier product. Python is used by repository tests and black-box
instruments.

## Quick start

Tested: Ubuntu 24.04.4 AMD64, user ID 1000, existing Claude login.
Bash, curl, tar, Git, system Python, tmux and subordinate ranges were present.
Use a writable workspace without `index.html` or `install-safeyolo.sh`, unused
`first` and fresh `~/.safeyolo`. Run individually; stop on errors.
HTTPS trusts the project publisher.

Setup downloads packages, explains host changes before sudo, and asks before
sharing this workspace or copying authentication/settings. Copied credentials
are guest-readable. Claude runs tools without per-tool prompts. Decline copying
to use `/login`; declining setup stops launch.

```sh
curl --fail --location --proto '=https' --proto-redir '=https' --output install-safeyolo.sh https://raw.githubusercontent.com/craigbalding/safeyolo/45d8853a202c04c9f5f8ca772df410ae8ced1844/install.sh
bash install-safeyolo.sh --release host-c5ce76019b6c997e282ab05cea0212b492e945d2 --launch . --name first --harness claude --launcher tmux-window
```

Answer vendor prompts. For access requests, press Ctrl-b then d, enter `a`,
select the request number and approve/reject its displayed effect. Credential
approval persists for all current/future agents in this instance; network
approval grants reusable access to this agent's displayed host/port. After
review, Enter returns to Claude; `q` exits, retaining state.

Send Claude:

> Create /workspace/index.html as a complete HTML page with the heading
> "Hello from SafeYolo". Use no external dependencies.

### Check the result

Detach, then `q`. On the host:

```sh
cat index.html
```

> Expected: a complete HTML page containing the heading "Hello from SafeYolo".

Open it in your browser.

## Everyday commands

These optional commands use the quick start's agent `first` and default
installation. For another instance, use the
[custom-instance reference](docs/installation.md#other-installation-paths).

| Task | Command |
| --- | --- |
| Run the agent | `safeyolo agent start first` |
| Read proxy and agent state | `safeyolo status` |
| Reconnect to the agent terminal | `safeyolo agent attach first` |
| Open a separate shell | `safeyolo agent shell first` |
| Open the running desktop | `safeyolo agent present first` |
| Stop the agent | `safeyolo agent stop first` |
| Diagnose runtime state | `safeyolo doctor` |
| Stop the proxy and its Coord runtime | `safeyolo stop` |

Stopping the proxy leaves agents running. Stop each disposable agent separately.
[Agent launchers](docs/agent-launchers.md) describe persistent terminals,
foreground runs, sandbox-only starts and explicit supervision.
[Configuration](docs/CONFIGURATION.md) describes workspace, memory, mounts,
policy, trust and operator listeners. The [CLI guide](cli/README.md) links each
command family to its current operating instructions.

## Optional workflows

The [tested journey and limits](docs/installation.md#tested-onboarding-scope)
record the existing-account setup, first file and live return. The 15-second
goal is unmet. Clean Ubuntu ARM64 and macOS onboarding remain unproved.
Repeat the second quick-start command to return to the same matching live
session; repeat is not an upgrade. If a task fails, inspect its effects before
submitting it again.

| Need | Documentation |
| --- | --- |
| Manual installation, custom roots, builds or recovery | [Installation reference](docs/installation.md) |
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

- [Configuration](docs/CONFIGURATION.md) and [settings](docs/settings.md#runtime-settings)
- [Proxy architecture](docs/DEVELOPERS.md#architecture-overview) and [platform runtimes](docs/ARCHITECTURE.md#sandbox-runtime-and-networking)
- [Network routing and identity](docs/networking-vsock-uds.md)
- [Historical Python addons](docs/ADDONS.md)
- [Coord completion notes](docs/coord-completion-notes.md) and [factory proposals](docs/factory-proposals.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License.
