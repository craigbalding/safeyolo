# Agent launchers

The native CLI reports runtime liveness, control health, coding-agent state
and terminal-session state separately. Use `safeyolo status`,
`agent status NAME`, or `agent diagnostics NAME`. Command Centre reports the
same observations. A successful launch script does not, by itself, prove the
coding agent is running. Install the [native host commands](native-policy.md)
before following this reference.

Recorded launch transitions refresh Command Centre through the existing event
stream. Opening its menu also requests current status; Refresh Agent Status
lets the operator recheck after host/session-manager failure, which cannot
reliably emit its own final event. These are observations, not a heartbeat or
a new recovery manager.

Agent rows keep the status icon on the left and show a harness mark beside the
name: `>_` for Codex, `π` for Pi, and `✳` for Claude Code. The configured bundled
setup script supplies this identity; it is not a process-liveness check. Shells
and custom or unknown setups use a generic keyboard mark. Submenus name the
configured harness and retain the full agent and sandbox state.

**Run Agent** starts the agent without opening a viewer. **Run Agent
and Open Terminal** waits until the persistent launch is attachable, then
opens its terminal once. A failed launch reports the error instead of opening
an unusable terminal. **Open Sandbox Shell** opens a separate, persistent operator
shell in a ready sandbox. It does not start or attach to the coding agent.
The shell runs inside host tmux, so a dropped SSH connection or closed viewer
does not end the shell. Reopening the action attaches to the same shell.

## Run, attach, or open a shell

| Command | Result |
| --- | --- |
| `safeyolo agent start NAME --foreground` | Run in the caller's terminal without host tmux. |
| `safeyolo agent start NAME` | Run persistently through the configured launcher or manager. The ordinary default is a host tmux window. |
| `safeyolo agent start NAME --sandbox-only` | Boot the sandbox without a coding agent, launch script, or launch hooks. |
| `safeyolo agent attach NAME` | Connect to the existing agent session. Never start a new agent. |
| `safeyolo agent shell NAME` | Open an independent guest shell, not the agent's terminal. |
| `safeyolo agent shell --persistent NAME` | Open or reattach an independent operator shell protected by host tmux. |
| `safeyolo agent stop NAME` | Stop this agent's manager/session and sandbox. Leave unrelated host panes alone. |

A second start request reuses the current live launch. A ready sandbox with a
stopped coding agent can start a new launch without rebooting. Command exit
leaves the sandbox available for diagnosis; `agent stop NAME` stops it.
Attaching and disconnecting never stop the coding agent.

Command Centre uses `agent shell --persistent` for both local and remote
sandbox shells. Host tmux is required; the command reports a missing dependency
instead of falling back to an unprotected shell. Persistent shells use a
dedicated tmux server per SafeYolo configuration, with separate sessions for
each agent identity and guest user. They do not use or modify coding-agent
launcher records. Multiple viewers of the same shell share its input and output.
Exiting the guest shell ends that shell session; reopening then creates a new
one. Host or sandbox shutdown is outside this connection-loss protection.

Inside an operator shell, you can start guest tmux and then start a coding
agent manually. That nested tmux server remains available to the coding agent
for lab panes and other guest-side work. The outer host tmux session protects
the operator connection. With the default tmux prefix on both servers, press
`Ctrl-b` twice to send a prefix to the inner server.

After staging and booting an agent, manually running `/home/agent/.safeyolo-command`
reports the agent as running with a `manual` launcher. A second `agent start`
leaves it running; return to the original guest terminal to interact with it.
Exiting the command reports it as exited while the sandbox stays ready.

Command Centre requests a persistent launch before opening a terminal viewer.
For a CLI launch, use `agent start NAME`, then `agent attach NAME`. Use
`--foreground` when the command must use the current terminal, including an
SSH terminal. Missing host tmux produces an actionable error for a persistent
launch.

## Shared defaults and overrides

Set shared defaults in the instance's `config.toml`:

```toml
[agent_launcher]
default = "tmux-window"
tmux_session = "agents"
```

Use `agent configure writer --launcher tmux-pane` for a per-agent override.
Remove `launcher` from the agent's `policy.toml` entry to restore inheritance.
An explicit manager or per-agent launcher wins over the shared host default.
With no configured default, background runs use host tmux.

Configuration is stored as `agent_launcher.default` and
`agent_launcher.tmux_session` in host `config.toml`, and `launcher` in each
agent's `policy.toml` entry. Defaults are resolved at launch, not copied into
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
script as `agent_launcher.default` in `config.toml`, or select it for one agent
with `agent configure NAME --launcher PATH`. This is a runtime launcher;
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
SafeYolo supervisor already does this through `agent diagnostics` and Coord output.

Context arrives as environment data, not shell source:

| Variable | Value |
| --- | --- |
| `SAFEYOLO_AGENT_NAME`, `SAFEYOLO_AGENT_ID` | Validated name and stable identity. |
| `SAFEYOLO_LAUNCH_ID` | Identity of this launch, also available to attach/stop. |
| `SAFEYOLO_WORKSPACE` | Workspace for this launch. |
| `SAFEYOLO_LAUNCH_MODE` | `foreground` or `background`. |
| `SAFEYOLO_CONFIG_DIR` | This host's selected SafeYolo configuration. |
| `SAFEYOLO_EXECUTABLE` | Installed native host executable. |
| `SAFEYOLO_NATIVE_CONFIG_PATH` | Selected native `config.toml` path. |
| `SAFEYOLO_LAUNCHER_PRESETS` | Installed directory containing the two tmux presets. |
| `SAFEYOLO_TMUX_SESSION`, `SAFEYOLO_LAUNCH_PANE` | Selected host session and recorded pane, where applicable. |
| `SAFEYOLO_TMUX_SOCKET` | Recorded tmux server socket for this launch, where applicable. |
| `SAFEYOLO_AGENT_EXIT_CODE`, `SAFEYOLO_AGENT_EXIT_REASON` | Actual guest-command result for `on_exit`. |

The host environment, including proxy/CA and terminal-manager settings, is
preserved. Custom launchers can use this fixed entrypoint inside their terminal:

```sh
"$SAFEYOLO_EXECUTABLE" --config "$SAFEYOLO_NATIVE_CONFIG_PATH" \
  agent entrypoint "$SAFEYOLO_AGENT_NAME" "$SAFEYOLO_LAUNCH_ID"
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

A live managed agent must first be stopped before replacing its harness.
Use `agent shell worker` to inspect the guest independently of its command.
`agent diagnostics worker` reports the recorded supervisor state.

## Remote connections

Tailscale is the default remote transport. Use Command Centre's Tailnet
Admin/events URLs. The authenticated `/admin/instance` response reports
`host_user`, the OS account running the proxy (looked up by effective UID).
Open Agent Terminal defaults to that username and the connected Tailnet
hostname; it does not use the Mac's login or the Admin URL's port.
Standard SSH works over the tailnet, including
when Tailscale SSH provides authentication on that host.

On an installed SafeYolo host with Tailscale connected, enable the explicit
Tailnet share and restart the native proxy. Select two free Tailnet HTTPS ports;
the defaults are 9443 for Admin and 9444 for events.

```sh
safeyolo command-centre enable --share tailnet
safeyolo stop
safeyolo start
safeyolo command-centre status
```

The status command reports the Admin and event URLs after both Serve mappings
are ready. The proxy owns the mappings and removes them when it stops. The
existing Admin credential authorizes both endpoints. Keep that credential in
the app's Keychain profile; Tailnet access alone does not authorize Admin
requests.

For the initial non-Tailscale fallback, set up your own SSH forwards, select
**SSH tunnel**, and enter their loopback Admin/events URLs. For example, forward
local ports 19090 and 19091 to the remote host's loopback ports 9090 and 9091.
Keep the existing Admin credential and instance-ID check. The app treats this
as a remote instance even though its forwarded URLs use localhost. Set the
optional SSH target to the real host or an SSH configuration alias; the
forwarded loopback URL cannot identify an SSH destination.

Run Agent uses the named Admin API operation and needs no SSH connection.
Open Agent Terminal opens Terminal.app and runs `ssh -t TARGET` followed by
the server's reported `host_executable` with its `host_root` and
`agent attach -- NAME` on that host. This uses the running instance's native
SafeYolo installation even when the non-interactive SSH shell has no `safeyolo`
on its PATH. An explicit SSH target in local
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

When the host publishes WebMITM, **Open WebMITM** uses its current URL from
`/admin/instance`, including the actual port. It does not guess the URL from
the Tailnet hostname. The action is absent when the host reports no active
WebMITM share. The action copies the active connection's Admin key to the
clipboard before opening the browser. Paste it into WebMITM's token field to
sign in. Commander shows a native notification and a menu message confirming
the copy. It reuses the credential already loaded for that connection; it does
not read Keychain again or put the key in the URL.

Security observations use native macOS notifications. Allow notifications for
SafeYolo Command Centre in macOS settings to see banners. Permission and
submission failures appear in Error details. The menu retains security events
even if macOS does not show a banner. Repeated matching events update their
count rather than send another banner. Long menu summaries end with an
ellipsis; opening the event retains the complete summary and details.

The macOS app uses SwiftUI and native Keychain support. SafeYolo no longer
installs the earlier Qt/PySide frontend or a Python Keychain wrapper. Build
the app with `bash command-centre/macos/build-app.sh` on the Mac, install the
resulting app in Applications, then open its icon or use
`safeyolo command-centre run`. Linux hosts provide the Admin API and event
stream; the graphical app runs on the operator's Mac.

Installing the app does not enable the host's live-event listener. For a local
connection, enable the listener on the Mac that runs SafeYolo:

```sh
safeyolo command-centre enable
safeyolo stop
safeyolo start
```

The restart briefly interrupts agent networking and Coord. Agents stay running
unless you add `--all` to the stop command. Local mode loads the existing local
Admin API credential automatically; it does not require pasting a key.

If the running host reports live events disabled, the app shows **Live events
disabled** and **Set Up Live Events…** with the commands. A working Admin API
can still provide agent status and actions when live events are unavailable.
The client paces retries and does not republish unchanged status snapshots.
Older hosts that do not report listener state receive conditional setup
guidance; a connection failure alone does not establish that events are disabled.

Use **Copy Diagnostics** in the main menu or the connection error window to
share connection state, endpoint origins, retry counts, timestamps, and recent
failures. The report retains failures after reconnecting. History is kept only
for the current connection session, with the latest 100 entries and consecutive
duplicates combined. It excludes credentials, headers, URL paths and queries,
and response bodies. Hostnames remain visible. **Copy Details** continues to
copy the displayed error text.

The native installation uses fresh TOML configuration. It does not convert an
existing Python installation. Native host acceptance uses installed CLI and
guest assets on Ubuntu/gVisor and physical macOS/VZ; a graphical macOS VM
without nested virtualization cannot substitute for the latter.
