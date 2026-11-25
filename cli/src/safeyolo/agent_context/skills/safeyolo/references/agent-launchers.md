# Agent creation, launch and support

## Contents

- [Choose the next step](#choose-the-next-step)
- [Create a worker and delegate support](#create-a-worker-and-delegate-support)
- [Use current support authority](#use-current-support-authority)
- [Launch and terminal troubleshooting](#launch-and-terminal-troubleshooting)

## Choose the next step

Host commands in this reference run on the owning host, under the account that
owns the selected instance. Preserve the operator's actual command and instance
selection; do not silently switch to a default installation. Use installed help
to check version-specific syntax when available. A guest workspace path is not
necessarily the host workspace path.

For an existing worker, inspect relevant state and current support authority
before asking the operator to act. For a new worker, explain the host creation
step and how you can support that worker afterward. Do not replace a requested
host-managed agent with a nested agent inside your sandbox.

The built-in peer-support interface operates on existing configured agents.
It can grant inspection, guest repair and selected start/stop/restart actions.
It does not create the host agent definition or select new host scripts,
mounts or credentials. A missing host CLI or a desktop-only `/operator-actions`
listing does not mean peer support is unavailable. Use
[the relevant discovery surface](agent-api.md#discover-the-right-capability).

## Create a worker and delegate support

First reuse any known name, host workspace and harness choice. If the worker
already exists, continue with it. Do not recreate its identity to repair a
launch or obtain a grant.

For a new saved agent without starting a coding harness, prepare this host
command. In this example, `worker` is the chosen new name and
`/absolute/host/project` must be replaced with the existing host workspace.
Use the selected installation's command prefix in place of `safeyolo`:

```sh
safeyolo agent create worker --workspace /absolute/host/project
```

The command saves the agent definition and workspace. It does not set up or
start a coding harness. When the operator instead wants to launch a coding
agent interactively, use `agent launch` with the selected harness. For example,
after choosing Codex and the same host workspace, use:

```sh
safeyolo agent launch /absolute/host/project --name worker --harness codex
```

Launch guides host setup and authentication, starts the selected services and
opens the agent terminal. Reuse a saved harness choice when one exists; do not
invent a preference or repeat completed setup. Give the operator the one path
that fits the request, not both commands as compulsory steps.

If your existing grants do not cover the requested servicing, prepare the
guided support command on that same host and instance. Here `worker-support`
is the chosen grant name, not an agent name:

```sh
safeyolo configure support worker-support
```

Tell the operator which support agent to select (your current durable
identity), which target to select (`worker` in this example), and the access
the task needs. For same-instance support, select that instance as the support
agent's source. Inspection is included. Guest administration permits commands
and guest sudo, including access to the target's writable mounts, credentials,
services and delegations. Select it for repairs that need that authority.
Lifecycle rights select individual start, stop or restart actions using saved
configuration. Choose the intended duration or standing grant, then review and
apply the command's preview. Do not add permissions or shorten an agreed scope
merely because a different example uses them.

Keep the human handoff concise: "Create the worker on this host, then grant me
the selected support access. Once the grant is active, I can inspect it and
carry out the agreed work." Include the actual command and selections, not
only that sentence. Never ask the operator to construct grant JSON or copy
durable IDs when the guided command can select them.

## Use current support authority

Call `support_grants` or `GET /support/grants`. Use the returned durable target
identity and current grant. A successful empty result means no current visible
grant, not an unsupported feature. A failed read remains unknown. If the task
needs a new grant, use the guided handoff above or the existing
[policy proposal workflow](../../policy-authoring/SKILL.md) when appropriate;
there is no generic agent-creation or self-grant endpoint to invent.

After a grant is adopted, refresh discovery and start with a support
`inspect` operation. Use its current run identity for subsequent permitted
commands or lifecycle actions. Verify the requested result after the operation;
do not infer a running coding harness from a saved definition or live sandbox.
After a lost reply, read the original operation before retrying.
[Delegated local peer support](agent-api.md#delegated-local-peer-support)
contains the request shapes and recovery rules.

Local support needs neither a shared Coord room nor a responsive target model.
A diagnostic disclosure grant permits its selected evidence reads; it does
not grant guest repair or lifecycle actions. A support grant does not confer
arbitrary host administration. For another instance, use the existing remote
support route and its owner; do not invent a direct host connection.

## Launch and terminal troubleshooting

Sandbox readiness and coding-agent activity are separate. When an agent appears
running but does nothing, use permitted support inspection first. If the needed
host observation is unavailable to you, prepare
`safeyolo agent diagnostics NAME` for that selected agent on its owning host.
Use host `safeyolo status` when configured-agent inventory is needed. Do not
infer a live harness from sandbox existence or a successful start request.

- `agent start NAME` starts a persistent host session or selected manager.
- `agent start NAME --foreground` uses the caller's terminal without host tmux.
- `agent start NAME --sandbox-only` starts no harness, launcher, or launch hooks.
- `agent attach NAME` connects to the existing agent session, without starting one.
- `agent shell NAME` opens a separate guest shell. It does not attach to the agent.
- `agent stop NAME` stops that agent and sandbox, not unrelated terminal sessions.

For ordinary agents, set shared defaults in the instance's `config.toml`
under `[agent_launcher]`. `agent configure NAME --launcher tmux-pane` sets a
per-agent override. Remove that agent's `launcher` entry from `policy.toml` to
restore inheritance. The running session retains its original launcher when
defaults change. See `docs/agent-launchers.md` for the defaults and script contract.

Factories explicitly select the SafeYolo supervisor. Do not replace it with
an ordinary tmux launcher. Use `agent shell NAME` to inspect its guest independently.
Headless supervisor runs have no terminal to attach; use their Coord output
or diagnostics.

Host launchers are distinct from guest `.safeyolo-command`. They must live
outside every guest-writable share and are selected by local host configuration,
not Agent API messages. Do not try to install a host script through guest sudo.
In a mounted SafeYolo checkout, use `docs/agent-launchers.md`,
`contrib/agent-launcher-template.sh`, and `contrib/agent-launcher-prompt.md`
for operator setup; prepare the file locally and ask the operator to install
it at a host-only path if this sandbox cannot reach one.

Tailscale is the default remote route. An operator-managed SSH tunnel is an
alternative. A loopback URL can therefore refer to a remote instance. Terminal
attachment uses separately configured SSH access to the correct host; the
Admin credential does not grant SSH or arbitrary host-command access. Losing
a viewer or tunnel must not kill the host-owned coding agent.
