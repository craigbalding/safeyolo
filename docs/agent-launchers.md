# Agent launchers

An agent has two separate states: its sandbox can be ready while its coding
agent is stopped. `safeyolo agent list`, `agent diag NAME`, and Command Centre
report both. A successful launch script does not, by itself, prove an agent is
running.

Recorded launch transitions refresh Command Centre through the existing event
stream. Opening its menu also requests current status; Refresh Agent Status
lets the operator recheck after host/session-manager failure, which cannot
reliably emit its own final event. These are observations, not a heartbeat or
a new recovery manager.

## Run, attach, or open a shell

| Command | Result |
| --- | --- |
| `safeyolo agent run NAME` | Run in the current terminal unless a host launcher or manager is configured. No guest tmux is required. |
| `safeyolo agent run NAME --detach` | Run persistently through the configured launcher or manager. The ordinary default is a host tmux window. |
| `safeyolo agent run NAME --sandbox-only` | Boot the sandbox without a coding agent, launch script, or launch hooks. |
| `safeyolo agent attach NAME` | Connect to the existing agent session. Never start a new agent. |
| `safeyolo agent shell NAME` | Open an independent guest shell, not the agent's terminal. |
| `safeyolo agent stop NAME` | Stop this agent's manager/session and sandbox. Leave unrelated host panes alone. |

A second run request reuses the current live launch. A ready sandbox with a
stopped agent can start a new launch without rebooting. The default local
foreground command retains the existing behavior: a clean exit stops the
sandbox; an interrupted or failed command leaves it available for diagnosis.
For persistent launchers, command exit leaves the sandbox ready. Attaching and
disconnecting never stop the agent.

When `run` is invoked over SSH outside host tmux, SafeYolo starts a persistent
host session and then attaches the terminal as a viewer. Inside host tmux, the
existing host session already owns the terminal. Command Centre always requests
a persistent launch. Missing host tmux produces an actionable error, not a
headless fallback for an interactive coding agent.

## Shared defaults and overrides

Run `safeyolo agent config` without a name to see the shared defaults and the
installed optional launcher template/configuration prompt.

```sh
safeyolo agent config --default-launcher tmux-window --tmux-session agents
safeyolo agent config writer --launcher tmux-pane
safeyolo agent config debugger --launcher interactive
safeyolo agent config worker --launcher supervisor
safeyolo agent config writer --launcher ''
```

The final command removes the per-agent override. An explicit manager or
per-agent launcher wins over the shared host default. `interactive` overrides
an inherited script; for a background operation it uses the built-in host
tmux window. With no configured default, ordinary local foreground runs use
the caller's terminal and background runs use host tmux.

Configuration is stored as `agent_launcher.default` and
`agent_launcher.tmux_session` in host `config.yaml`, and `launcher` in each
agent's existing record. Defaults are resolved at launch, not copied into
every agent. The current launch remembers its selected script and session:
changing a default does not redirect attach/stop to another session.

`tmux-window` creates a window in the named host session; `tmux-pane` creates
a pane. Both create the session if absent. Custom scripts must be executable
absolute host paths outside every agent-writable share. An external manager
is selected with `manager:/absolute/host/script.sh`; its management behavior
belongs in that script, not in a new SafeYolo scheduler.

The tmux presets retain the server socket as well as the pane ID. An attachment
from SSH therefore reaches the same server that created the agent session,
even if the proxy or operator uses a non-default tmux server. On the same
server, attach switches the existing client. From another server or a plain
terminal, attach opens a viewer; disconnecting that viewer leaves the agent
running.

## Host script contract

Copy `contrib/agent-launcher-template.sh` outside guest-writable shares and edit
its optional `pre_launch`, `post_launch`, and `on_exit` functions. Select that
one script for many agents with `--default-launcher /absolute/host/script.sh`,
or select it for one agent with `--launcher`. This is a runtime launcher;
`--host-script` remains the separate setup operation that installs the guest
harness and its configuration.

SafeYolo calls the script with one action: `launch`, `attach`, `status`, `stop`,
`pre_launch`, `post_launch`, or `on_exit`. The template handles all actions,
including optional hooks as no-ops. `launch` starts a persistent session and
returns; it must not wait for a terminal viewer. Use stderr for diagnostics.
Stdout is either empty or one JSON object. The tmux presets return
`{"tmux_socket":"/path/to/tmux.sock","pane_id":"%12"}`; the current launch
retains both handles. A script without an observable process/session reports
`unknown`, not `running`.

A custom manager's `status` returns a JSON object with `state` equal to
`starting`, `running`, `exited`, `failed`, `stopped`, or `unknown`. Its `stop`
must stop only that agent and prevent its manager from relaunching it. A manager
with no terminal should return a useful explanation from `attach`. The
SafeYolo supervisor already does this through `agent diag` and Coord output.

Context arrives as environment data, not shell source:

| Variable | Value |
| --- | --- |
| `SAFEYOLO_AGENT_NAME`, `SAFEYOLO_AGENT_ID` | Validated name and stable identity. |
| `SAFEYOLO_LAUNCH_ID` | Identity of this launch, also available to attach/stop. |
| `SAFEYOLO_WORKSPACE` | Workspace for this launch. |
| `SAFEYOLO_LAUNCH_MODE` | `foreground` or `background`. |
| `SAFEYOLO_CONFIG_DIR` | This host's selected SafeYolo configuration. |
| `SAFEYOLO_PYTHON` | Interpreter of the running SafeYolo installation. |
| `SAFEYOLO_LAUNCHER_PRESETS` | Installed directory containing the two tmux presets. |
| `SAFEYOLO_TMUX_SESSION`, `SAFEYOLO_LAUNCH_PANE` | Selected host session and recorded pane, where applicable. |
| `SAFEYOLO_TMUX_SOCKET` | Recorded tmux server socket for this launch, where applicable. |
| `SAFEYOLO_AGENT_EXIT_CODE`, `SAFEYOLO_AGENT_EXIT_REASON` | Actual guest-command result for `on_exit`. |

The host environment, including proxy/CA and terminal-manager settings, is
preserved. Custom launchers can use this fixed entrypoint inside their terminal:

```sh
"$SAFEYOLO_PYTHON" -m safeyolo.cli agent shell "$SAFEYOLO_AGENT_NAME" \
  --agent-command --launch-id "$SAFEYOLO_LAUNCH_ID"
```

This runs the configured command **inside the ready sandbox**, without
recursively selecting a host launcher. It claims the launch once, runs the
pre-launch hook, starts the command with a terminal, calls the post-launch
hook, waits for actual exit, then calls the exit hook. The wrapper must live
in the persistent host session, not in the temporary Admin API/SSH request.

A pre-launch hook failure prevents that new command. A post-launch hook failure
is reported without killing it. Exit-hook errors remain separate from the
command's exit code. Host or terminal-manager failure can prevent the exit
hook from running; diagnostics then show the lost process rather than inventing
a successful callback. Current launch state lives in the host-owned agent
directory, not the guest home or workspace.

## Managed agents

Factory staging explicitly selects `supervisor`. It bypasses inherited
ordinary launchers/hooks and preserves the existing guest PID 1 → runtime
supervisor → Coord supervisor → harness chain, including intentional-stop
handling and checkpoints. The bundled `@codex-coord` and `@pi-coord` setups
also select supervision explicitly.

Those setups retain `.safeyolo-interactive-command` separately from the
supervised `.safeyolo-command`. To debug a stopped managed agent:

```sh
safeyolo agent stop worker
safeyolo agent run worker --interactive --detach
safeyolo agent attach worker
# After debugging:
safeyolo agent stop worker
safeyolo agent run worker --detach
```

The temporary override does not rewrite its manager selection, harness
configuration, credentials, or Coord checkpoints. A live managed agent must
first be stopped so debugging cannot start a competing harness.

## Remote connections

Tailscale is the default remote transport. Use Command Centre's Tailnet
Admin/events URLs. The authenticated `/admin/instance` response reports
`host_user`, the OS account running the proxy (looked up by effective UID).
Open Agent Terminal defaults to that username and the connected Tailnet
hostname; it does not use the Mac's login or the Admin URL's port.
Standard SSH works over the tailnet, including
when Tailscale SSH provides authentication on that host.

For the initial non-Tailscale fallback, set up your own SSH forwards, select
**SSH tunnel**, and enter their loopback Admin/events URLs. For example, forward
local ports 19090 and 19091 to the remote host's loopback ports 9090 and 9091.
Keep the existing Admin credential and instance-ID check. The app treats this
as a remote instance even though its forwarded URLs use localhost. Set the
optional SSH target to the real host or an SSH configuration alias; the
forwarded loopback URL cannot identify an SSH destination.

Run Agent uses the named Admin API operation and needs no SSH connection.
Open Agent Terminal opens Terminal.app and runs `ssh -t TARGET` followed by
the server's reported `host_python` executable with
`-m safeyolo.cli agent attach -- NAME` on that host. This uses the running
instance's SafeYolo installation even when the non-interactive SSH shell has
no `safeyolo` on its PATH. The interpreter's virtual-environment path is kept
intact, not resolved to its base Python. An explicit SSH target in local
connection settings overrides discovery, for example to use another login.
If the host's effective UID has no OS account entry, `host_user` is null and an
explicit SSH target is needed. No command, script path, or arbitrary argv is accepted by the Admin
API. SSH configuration can select users, ports, identities, or a jump host.
Closing either connection loses the view, not the running agent.

Desktop previews also need a reachable preview endpoint. Forwarding only the
Admin/events ports does not forward a dynamically allocated preview port.
The app does not create or silently rewrite SSH tunnels.

The menu has a fixed **Error details…** entry. It opens full, selectable errors
in a resizable window with **Copy Details**; long errors do not resize the menu.
An unresolved request error remains until that operation succeeds. A successful
identity request does not clear a failed inventory request. Live event gaps
remain available in the details window until dismissed.
Failed user actions (run, stop, open terminal, or present desktop) open the
details window immediately. Background retries update the menu entry without
opening windows repeatedly.

## Upgrade and acceptance

Replace old boot-only `--detach` calls with `--sandbox-only`. Supervision is
no longer inferred from the presence of `.safeyolo-command`: stage the factory
or explicitly select `--launcher supervisor`. Existing managed setups need
one reapplication to retain the separate interactive entrypoint; this does not
require reinstalling or recreating the agent.
Stop and start existing sandboxes once after upgrading so guest PID 1 receives
the updated explicit-supervisor selection support.

`tests/nested-linux/launcher_acceptance.py` exercises real terminal I/O,
concurrent launch reuse, retained attachment, viewer loss, callbacks, relaunch
in a ready sandbox, and narrow stop. Run it with the candidate Python against
an operator-approved SafeYolo configuration with guest images installed and
the proxy already running. It adds a unique 1 GiB disposable agent and retains
its stopped state/evidence. It does not reinstall SafeYolo or restart existing
agents or the proxy. Run on both
Linux/gVisor and a macOS host capable of VZ; a macOS GUI VM without nested
virtualization cannot substitute for the latter.
