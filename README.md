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
Production downloads are available in the release linked below;
published Python CLI packages describe the earlier product. Python is used by
repository tests and black-box instruments. Automatic and later release
publication remain stopped.

## Quick start

### 1. Install on your host

Use your ordinary account on Ubuntu 24.04 or an Apple Silicon Mac with macOS
26.0 or later. Download the production archive for your host from the published
[release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796).

| Host | Production download |
| --- | --- |
| Ubuntu x86_64 | [safeyolo-linux-amd64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-linux-amd64-production.tar.gz) |
| Ubuntu arm64 | [safeyolo-linux-arm64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-linux-arm64-production.tar.gz) |
| Apple Silicon macOS | [safeyolo-darwin-arm64-production.tar.gz](https://github.com/craigbalding/safeyolo/releases/download/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796/safeyolo-darwin-arm64-production.tar.gz) |

In a host terminal, change to the directory containing the downloaded archive.
Both platforms need Bash, curl, tar and network access for guest and runtime
downloads. macOS supplies these and the OpenSSH tools used by the VM; skip the
Ubuntu setup below.

Use a fresh `$HOME/.safeyolo`, the default installation directory. Preserve any
existing installation; this path does not convert earlier state. Other roots
are an [optional installation path](docs/installation.md#other-installation-paths).
The installer creates configuration, trust and private tokens, checks the bundle
internally and downloads the compatible public guest. It may ask for sudo to
create the command entry or preserve Linux guest ownership. Instance files
stay owned by your account. Run commands individually and stop on an error.

The linked published release needs the Ubuntu setup below. New Linux source
bundles prepare the host through their ordinary installer; see
[automatic Linux host preparation](docs/installation.md#linux-host-preparation-in-new-source-bundles).

On Ubuntu 24.04, these commands install gVisor and its host tools, add the signed
gVisor package repository, and permit your account's required user namespaces.
They need host sudo and change package sources, your subordinate user/group
ID ranges and the AppArmor profile. The installer does not perform this setup.
First read your account identity and both allocation files:

```sh
id
cat /etc/subuid
cat /etc/subgid
```

Each row is `account:first-ID:count`; its last ID is `first-ID + count - 1`.
Your account's name or numeric user ID from `id` needs a range covering
100000–165535 in both files, for example `your-login:100000:65536`.
If another account owns any part of that range, stop: this release cannot
select a different range. Use a host where the range is available;
do not overlap another account's allocation. If your account already has a
covering range, keep it. Only when a file lacks your range and the range is free,
run its corresponding command:

```sh
sudo usermod --add-subuids 100000-165535 "$USER"
sudo usermod --add-subgids 100000-165535 "$USER"
```

Then install the host tools and gVisor, and load the namespace profile:

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg uidmap acl iproute2 util-linux apparmor-utils
curl -fL -o gvisor-archive.key https://gvisor.dev/archive.key
sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg gvisor-archive.key
echo 'deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main' | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update
sudo apt-get install -y runsc
curl -fL -o apparmor-safeyolo-runsc https://raw.githubusercontent.com/craigbalding/safeyolo/7a38dff14e7e4eacb4095da732ffe06d7c7c5796/cli/src/safeyolo/templates/apparmor-safeyolo-runsc
sed 's|/usr/local/bin/runsc|/usr/bin/runsc|' apparmor-safeyolo-runsc > safeyolo-runsc
sudo install -m 0644 safeyolo-runsc /etc/apparmor.d/safeyolo-runsc
sudo apparmor_parser -r /etc/apparmor.d/safeyolo-runsc
```

The commands below use the Ubuntu x86_64 download. For Ubuntu arm64, replace
`linux-amd64` with `linux-arm64`; for Apple Silicon, replace it with
`darwin-arm64`.

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
terminal.
Claude runs with its own permission prompts disabled inside SafeYolo; SafeYolo
still enforces sandbox and access policy.

The fresh policy allows network access and prompts for unfamiliar credentials.
If Claude reports a credential request, open a second host terminal and run:

```sh
safeyolo services approvals
```

Find `work`'s credential entry. Read its destination in `approval.target` and
fingerprint in `approval.key`. Approval saves that fingerprint and destination
in the instance's shared host policy; network and service permissions remain
separate. To refuse, leave it unapproved so the request stays blocked. If you
intend that permission, replace `FINGERPRINT` and `HOST` with those exact values:

```sh
safeyolo credentials approve FINGERPRINT --destination HOST
safeyolo policy show
```

When policy reports `saved_matches_active: true`, return to Claude and retry.
For a network request instead, run `safeyolo inspect` in the second host terminal.
At `inspect>`, enter `select work`, then `pending`. Use the full `request_id`
in `approval REQUEST_ID` to read the `SafeYolo effect`. Network approval allows
reusable access for this agent to the displayed host and port. Enter
`approve REQUEST_ID` only if you intend that scope, or `reject REQUEST_ID` to
refuse. Return to Claude and retry after approval.

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
[custom-instance reference](docs/installation.md#other-installation-paths).

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

- [Configuration](docs/CONFIGURATION.md) and [settings](docs/settings.md#runtime-settings)
- [Proxy architecture](docs/DEVELOPERS.md#architecture-overview) and [platform runtimes](docs/ARCHITECTURE.md#sandbox-runtime-and-networking)
- [Network routing and identity](docs/networking-vsock-uds.md)
- [Historical Python addons](docs/ADDONS.md)
- [Coord completion notes](docs/coord-completion-notes.md) and [factory proposals](docs/factory-proposals.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License.
