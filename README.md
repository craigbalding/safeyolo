# SafeYolo

SafeYolo runs coding agents in isolated Linux sandboxes with controlled network
and service access. Share a project directory and give the agent root access
inside its sandbox to install tools, run browsers, start services and debug
code. You choose its permissions. Works with Claude Code, OpenAI Codex, Pi
and other coding agents.

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
- Tools for experiments and agent coordination.

SafeYolo is pre-v1. Use the installer below; published Python CLI packages
belong to the earlier product.

## Quick start

On Ubuntu 24.04 AMD64 (x86_64), use your ordinary sudo-enabled account with
Bash, curl, tar and an existing Claude Code login on that host. In a host
terminal, open a project directory you own, without `index.html` or
`install-safeyolo.sh`.

These commands download and run the official GitHub installer; you trust the
project publisher. Run each separately. Stop if either fails.

```sh
curl -fLO https://github.com/craigbalding/safeyolo/releases/latest/download/install-safeyolo.sh
bash install-safeyolo.sh --launch
```

Setup explains host changes before sudo and asks before sharing files or
copying login/settings. Copied credentials are readable inside the sandbox.
Declining setup stops launch; you can decline copying and sign in inside Claude.
Claude runs tools without per-tool prompts. First use can take several minutes.
For access requests, follow SafeYolo's host prompts and read each effect before
approving.

When Claude opens, send:

> Create /workspace/index.html as a complete HTML page with the heading
> "Hello from SafeYolo". Use no external dependencies.

### Check the result

Follow the displayed terminal controls to return to your host.
In the same project directory:

```sh
cat index.html
```

> Expected: a complete HTML page containing the heading "Hello from SafeYolo".

Open `index.html` in your browser.

## Everyday commands

From the same project directory, run `safeyolo agent launch` to return to
Claude. SafeYolo reuses the matching agent and its persistent home. Launching
again does not upgrade it or resubmit a task. If a task fails, inspect its
effects before submitting it again.

The agent name comes from your project directory. Use `safeyolo status`
to find it, then replace `NAME` below with the listed name. These commands
use the default installation. For another instance, use the
[custom-instance reference](docs/installation.md#other-installation-paths).

| Task | Command |
| --- | --- |
| Start or return to Claude in this project | `safeyolo agent launch` |
| Read proxy and agent state | `safeyolo status` |
| Reconnect to a running agent terminal | `safeyolo agent attach NAME` |
| Open a separate shell | `safeyolo agent shell NAME` |
| Open the running desktop | `safeyolo agent present NAME` |
| Stop the agent | `safeyolo agent stop NAME` |
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
