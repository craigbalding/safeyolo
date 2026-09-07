# Agent launch and terminal troubleshooting

Sandbox readiness and coding-agent activity are separate. Ask for host
`safeyolo agent list` or `safeyolo agent diag NAME` when the operator says an
agent is running but doing nothing. Do not infer a live harness from sandbox
existence or a successful start request.

- `agent run NAME` uses the current terminal unless a launcher/manager is configured.
- `agent run NAME --detach` starts a persistent host session or selected manager.
- `agent run NAME --sandbox-only` starts no harness, launcher, or launch hooks.
- `agent attach NAME` connects to the existing agent session, without starting one.
- `agent shell NAME` opens a separate guest shell. It does not attach to the agent.
- `agent stop NAME` stops that agent and sandbox, not unrelated terminal sessions.

For ordinary agents, `agent config --default-launcher tmux-window
--tmux-session agents` sets one shared host default. `agent config NAME
--launcher tmux-pane` overrides it for one agent; `--launcher interactive`
overrides an inherited script. An empty per-agent launcher restores inheritance.
The running session retains its original launcher when defaults change.
`safeyolo agent config` without a name shows the shared defaults and installed
template/prompt paths, including on a wheel-only installation.

Factories explicitly select the SafeYolo supervisor. Do not replace it with
an ordinary tmux launcher. For a stopped managed agent, `agent run NAME
--interactive --detach` temporarily uses its separately staged interactive
entrypoint. Stop that debug run before resuming normal managed operation.
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
