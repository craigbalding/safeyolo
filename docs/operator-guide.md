# Manage SafeYolo access and traffic

Use SafeYolo on the host to inspect an agent's activity and decide its access
requests. You are the operator: the person managing the installation. An
instance is one installation's configuration and runtime state. An agent is
a named sandbox with its own persistent home and the workspace you selected.
You can manage an individual agent without a factory or an assistant agent.

## Start with an installed instance

Use your ordinary account on the Ubuntu or Apple Silicon macOS host that owns
the instance. For a new installation, follow [install and start](installation.md#install-and-start),
including its platform prerequisites and prepared guest assets. Then follow
[configure and use an agent](installation.md#configure-and-use-an-agent).
That example creates `work` and opens its guest shell. A shell is sufficient
for the access example below; no model login is required.

Open a second terminal on the same host, under the same account. The installed
command uses `$HOME/.safeyolo` automatically. These examples use that default
installation. For another instance, use the
[custom-instance reference](installation.md#other-installation-paths) and the
matching file paths. Do not reinstall over existing state.

```sh
safeyolo --version
safeyolo status
```

`--version` identifies the executable's source and build profile. `status`
reports the selected `root`, `proxy_state` and configured `agents`. Use the
agent's `name` from that inventory. The examples below use the `work` agent
created during setup. Check that the root and agent match the guest terminal
you opened. A running proxy alone does not mean that the agent is running.

Keep the operator credential in the instance's `data/admin_token` on the host.

## Open an agent desktop

Use the host account and instance selected above. The proxy must be running.
The guest needs the desktop packages and noVNC assets from its prepared guest
image. Opening a presentation can start the guest desktop if it is absent.
Opening a presentation does not start the agent.

```sh
safeyolo agent present work
```

The command returns a `url` and an `unlock_code`. Open that URL in your browser
and enter the code. The Command Centre's approved desktop presentation opens
the same SafeYolo page. Keep the code private. The existing five-minute,
single-use unlock rules still apply.

The desktop appears inside this page. Use the page's full-screen, keyboard,
clipboard and view controls. The page stays open if the desktop disconnects.
Its status explains what SafeYolo observed. **Show diagnostics** opens a live,
timestamped history; checks also run while that panel is closed. **Copy
diagnostics** copies up to 120 observations. That copy excludes credentials,
unlock codes, cookies, URLs, clipboard text and screen content.

If the desktop service accepts connections but sends no VNC greeting on two
fresh guest-local checks, the page reports a suspected stuck service. Ask your
agent to restart x11vnc. A failed guest or runtime inspection remains unknown.
The page does not restart a service or agent, or repair saved agent state.
When the service recovers, the page reconnects without a reload and retains
its diagnostic history. Browser network events and a return to a visible page
trigger fresh checks. A browser's offline hint alone does not disable a working
local preview.

The page checks both legs of its existing viewer connection with WebSocket
Ping/Pong messages. The replies verify the existing browser-to-SafeYolo and
SafeYolo-to-guest WebSocket paths. They do not check the relay's existing TCP
connection to VNC or the browser's rendering loop. The checks send no keyboard
or mouse input. They can detect a stalled WebSocket transport
while a separate diagnostic request and a fresh VNC greeting still work. An
active page checks at five-second intervals, with deadlines of 14 seconds for
diagnostics and five seconds for viewer transport status. A covered transport
stall is detected within 45 seconds while the browser runs and the diagnostic
endpoint replies within those deadlines. Sleeping or suspended tabs have no
timer guarantee. Ping/Pong and a VNC greeting do not prove that a guest
application, window manager or screen is responding. A static screen is allowed.

Guest checks use a two-second TCP connection deadline and a three-second total
VNC greeting deadline. The host bounds each guest inspection at eight seconds.
The page bounds viewer asset loading at 20 seconds and a connection handshake
at 20 seconds. A request for desktop credentials or server verification waits
for your input before resuming the handshake deadline. Failed connection
attempts use backoff from one to 30 seconds. After eight failed attempts, use
**Check again** to request fresh checks and retry. **Close viewer** stops that
page's automatic attempts. Confirmed access failure or target replacement also
stops attempts. Reopen the intended presentation to renew access; the page does
not extend access or follow a replacement agent or run.

## Inspect and decide one request

A network policy with `egress = "prompt"` creates a pending access request.
The fresh policy permits network access by default, so a successful request
will not appear in `pending`. If your agent already has a pending network
request, continue with `safeyolo inspect` below.

For a first example, use `work` to request `http://example.com/`. On the host,
copy the current policy to a candidate in the instance root. This creates or
replaces `access-example.toml`; choose another filename if you need to keep an
existing candidate. The copy retains configured agent identities and settings.

```sh
cp "$HOME/.safeyolo/policy.toml" "$HOME/.safeyolo/access-example.toml"
```

Edit `access-example.toml` with your text editor. Add this destination entry
under the existing `[hosts]` heading, alongside the default `"*"` entry.
If the destination is already present, edit that entry instead of adding it
twice. Keep all other policy entries, including the generated agent identities.
This is the line to insert, not a complete policy:

```toml
"example.com:80" = { egress = "prompt" }
```

This example requests human approval at `example.com` port 80 for agents in
this instance. It is a policy choice for the fresh example, not an installation
requirement. Each resulting approval still grants access only to its requesting
agent. In an existing instance, agent-specific overrides take precedence; use
[per-agent policy](installation.md#check-show-and-apply) when you want a
different rule for one agent.

Check and apply the candidate on the host. Applying it replaces the saved
policy and activates it in this running instance.

```sh
safeyolo policy check "$HOME/.safeyolo/access-example.toml"
safeyolo policy apply "$HOME/.safeyolo/access-example.toml"
safeyolo policy show
```

Check reports `Policy is valid`. Apply returns `status: active`; show lets you
verify the effective `work` host entry. If activation fails or saved and active
state differ, use [policy recovery](installation.md#check-show-and-apply)
before continuing.

Now switch to the **guest shell for `work`** from setup. The following command
uses that guest's existing proxy route and makes a Hypertext Transfer Protocol
(HTTP) request without credentials:

```sh
curl --proxy "$HTTP_PROXY" -i http://example.com/
```

Expect HTTP 428 and `type: egress_approval_required`. The request is waiting
for your decision. Other 428 responses can have different causes; read the
reported type before treating one as a network approval.

Return to the **second host terminal** with the instance selection above:

```sh
safeyolo inspect
```

Inspect lists configured agent names and their durable IDs. Type `select work`
at `inspect>`; for an existing installation, use a name from that list instead.
`Workflow: instance agents` means all configured agents in this instance.
The banner repeats the instance ID and selected agent on each prompt:

```text
Instance: sy-… | Workflow: instance agents | Agent: work
inspect>
```

Type these inputs at the inspect prompt, not in your host shell:

```text
state
pending
```

`state` reads the live agent inventory. `pending` lists requests for this agent,
including each `request_id`, summary and target. An empty list means there is
no pending item for the selection. Choose the request for `example.com:80`.
Replace `REQUEST_ID` below with its full `request_id` from `pending`:

```text
approval REQUEST_ID
```

A representative network approval display follows. The IDs are abbreviated
here; use the complete IDs from your own session.

```text
Request: req-…
Status: pending
SafeYolo effect: Allow reusable network access for work (ag-…) to example.com port 80 until explicitly removed.
```

Read the effect before deciding. Approval permits future requests by this
agent to that host and port until you remove the permission. It is not limited
to one HTTP request and does not grant credential permission. If the scope is
what you intend, type the following input with the same full ID:

```text
approve REQUEST_ID
```

Expect `Status: approved`. To refuse the request instead, use
`reject REQUEST_ID`; expect `Status: rejected`. Rejection records the decision
without adding a deny rule. Exit the viewer with `quit`.

After approval, return to **`work`'s guest shell** and repeat the curl command.
The network approval should no longer block that destination. The site's
response is separate from SafeYolo's decision; an upstream error is not an
approval failure. After rejection, the permission remains unchanged.

To remove the example's grant later, edit a copy of the current policy and set
the `work` grant for `example.com:80` to your intended `prompt` or `deny` value,
then check and apply it. The resolver saves this agent-specific grant in
`agents`, separately from the instance-wide `hosts` entry. Use the current
policy so you retain decisions made since setup.
See [policy configuration](installation.md#check-show-and-apply).

## Read traffic and save evidence

In inspect with an agent selected, `traffic` lists its HTTP exchanges, called
flows. `traffic ~c 428` selects flows with response code 428. Copy a full flow
`id` from the result and replace `FLOW_ID` before entering these inputs:

```text
show FLOW_ID
body FLOW_ID response
logs
```

`show` opens the exchange; `body` reads its retained bytes. Bodies include
exact `data_base64` bytes and `text` when the bytes are UTF-8. JavaScript Object Notation (JSON) output escapes terminal controls. Missing or pruned bytes retain their availability and
reason fields. `logs` reads the configured host-local audit file.

For scripts or a terminal without interactive input, direct commands carry
their own agent selection. Use the actual name from `status`; these examples
use `work` and return JSON:

```sh
safeyolo traffic list --agent work --filter '~c 200' --json
safeyolo approvals list --agent work --json
```

Interactive selection and another viewer's filter cannot change these explicit
targets. `traffic show`, `body`, `websocket` and `message` open an exchange,
HTTP body, WebSocket transcript or message body. `message` accepts `--offset`
for subsequent 64 KiB pages and reports `offset`, `total_size` and `end`.

To save a response, replace `FLOW_ID` with the full `id` from `traffic list`.
Run on the host in the directory where you want the file. A complete successful
download replaces `response.raw`; a failed download preserves an existing file.

```sh
safeyolo traffic export FLOW_ID raw_response response.raw --agent work
```

All seven export formats are supported:

| Format | Use |
| --- | --- |
| `raw`, `raw_request`, `raw_response` | Reconstructed HTTP observations and retained bytes. Combined raw can include WebSocket payloads. |
| `curl`, `httpie` | Saved request commands for inspection. SafeYolo never executes them. |
| `har`, `zhar` | HTTP archives for other tools; zhar uses zlib compression. |

A flow pruned before the byte read returns unavailable. Retention and exporter
limits are described in [live traffic inspection](DEVELOPERS.md#live-traffic-inspection).

To return to an existing agent terminal, use `attach` in inspect. It requires
a running, attachable command. A missing terminal produces an error and keeps
your selection; attach does not launch another command. Returning from the
terminal or using `back` also keeps the selected agent.

## Inspect a pending approval

When a request needs approval, SafeYolo gives it an `approval_id` that starts
with `apr-`. Each traffic attempt also has its own `request_id`. Equivalent
retries share the pending approval. A changed method, destination, resource,
credential binding or offered scope gets a new approval.

On the host, use your configured agent name in place of `work`. Copy
`APPROVAL_ID` from the pending list. These commands leave the approval pending:

```sh
safeyolo approvals list --agent work --json
safeyolo approvals show APPROVAL_ID --agent work --json
```

You can inspect traffic, logs and the approval again before deciding. The
approval retains its original authority and options. Expect `status: pending`
after inspection. Agent prose and Helper reasons cannot change that authority.

Read the stated effect before deciding. Network approval changes the existing
agent-specific host/port policy until removed. Credential approval changes the
existing shared fingerprint/destination policy for all current and future
agents in the instance. Rejection changes neither policy. Gateway route
approval uses the exact method and path, including case and literal wildcard
characters. Approval defaults to the existing `once` grant. Use
`--option session` or `--option remembered` only when the approval offers that
option. Service access can require an offered `credential:NAME` option. Contract binding saves the
fixed contract values and does not authorize service access by itself.

To decide the selected approval, run one of these host commands:

```sh
safeyolo approvals approve APPROVAL_ID --agent work --json
safeyolo approvals reject APPROVAL_ID --agent work --json
```

The command returns the recorded `approved` or `rejected` result. After approval,
repeat the original request from the agent to use the existing permission.

An approval can have a `pending`, `approved`, `rejected`, `expired` or
`superseded` state. Inspection does not change that state. Expiry or a material
policy, service or identity change prevents approval of old authority. An old
session option expires when the proxy restarts. Other pending authority can
survive restart while its bound inputs remain valid. Known credential expiry
also expires a request bound to that credential. Ordinary network and inline
credential approvals have no added pending timeout.

Terminal decisions remain inspectable. Repeating a decision returns its saved
result; it cannot create another grant or change the chosen lifetime. A
successful response still consumes a `once` grant under the existing gateway
rules. The approval record does not restore that consumed grant. If a new request
still needs approval after a terminal decision, it gets a new approval ID.

SafeYolo keeps pending authority in the instance's host-owned data directory.
Audit events correlate traffic IDs, approval IDs, inspection and decisions.
Audit display text does not supply permission. Historical audit-only requests
remain inspectable; assisted approval needs a new durable request. Missing
approval state fails closed; it is not reconstructed from traffic logs. Direct
policy and service commands remain available for explicit operator changes.

## Recover from a failed operation

If `inspect` reports `inspect requires a terminal`, open it in an interactive
host terminal or use direct commands with `--agent` and `--json`. Inspect
prompt inputs cannot be piped to a noninteractive process.

If a decision reports `decision not confirmed`, do not assume approval or
immediately repeat the mutation. The client already attempts one canonical
read after a lost reply. On the host, replace `REQUEST_ID` with that request's
ID and read it again:

```sh
safeyolo approvals show REQUEST_ID --agent work
```

`approved` or `rejected` is the recorded outcome. If the item is still pending,
restore the connection and read its current scope before deciding. A relevant
policy change or recreated agent can supersede the action; approval returns
409. Expired and superseded IDs remain inspectable. Obtain a new request from
the agent and review its new approval ID.

The Admin API is the host's administrative application programming interface.
If inspect cannot reach it, leave with `quit` and run these commands in the same host terminal. Logs and diagnose use the configured local
files; missing or invalid files produce their own errors.

```sh
safeyolo status
safeyolo logs --agent work --lines 50 --json
safeyolo diagnose --agent work --json
safeyolo agent diagnostics work
```

Diagnosis distinguishes saved policy and last recorded launch from verified
live state. Local evidence does not confirm the active policy or a decision.
For a stopped proxy, inspect the named startup error and
`$HOME/.safeyolo/logs/proxy.log`; repair the named input or occupied
endpoint, then use `safeyolo start` and `safeyolo policy show`. For agent runtime
or shell failures, follow [agent diagnosis and recovery](installation.md#configure-and-use-an-agent).
Keep the selected root and executable when retrying. Direct human decisions
remain usable when an optional assistant's model is unavailable.

## Optional: inspect a factory

A factory runs agents with approved roles and declared handoffs. It is not
the human operator. To set one up, follow [factory check, approve, prepare,
login and run](factories.md#fresh-setup-check-approve-and-run).

After setup, use its configured factory name with
`safeyolo inspect --factory NAME`. For the documented `backlog` example,
`safeyolo inspect --factory backlog` lists only its declared agents. Roles
come from its approved snapshot; live inventory supplies their current state.
An approved snapshot alone does not establish readiness.

## Optional: ask another agent for help

A Helper is a separate agent that reads one selected network request and can
prepare a reason for your decision. The requesting agent is called the Worker
in the shared-approval protocol. Helper cannot approve, reject or grant itself
reads. You can decide directly without using a Helper.

First create a separate agent through [agent setup](installation.md#configure-and-use-an-agent).
Use `adviser` as the new name in those setup commands and select its workspace;
do not recreate the existing `work` agent.
For a model-assisted diagnosis, choose its [host setup script and login](../contrib/HOST_SCRIPT_GUIDE.md#bundled-setups).
Keep its own durable identity and authentication. This example names that agent
`adviser`; replace it with your configured name. Sharing does not launch a model
or send it an instruction. Tell the running assistant which shared request to
investigate through its ordinary terminal or communication channel.

The Helper commands also require a Linux `safeyolo` executable inside that
guest. Ordinary guest staging supplies `safeyolo-guest` and `safeyolo-coord`,
which do not implement these commands. On Ubuntu, you can stage the installed
host executable in the Helper's read-only configuration share. Stop `adviser` first;
these host commands replace `operator-client` in its share and then restart
its configured command:

```sh
safeyolo agent stop adviser
cp "$HOME/.safeyolo/bin/safeyolo" "$HOME/.safeyolo/agents/adviser/config-share/operator-client"
chmod 0755 "$HOME/.safeyolo/agents/adviser/config-share/operator-client"
safeyolo agent start adviser
```

On macOS, the host executable is a macOS executable and cannot run in the Linux guest.
Supply a Linux `safeyolo` built from the selected source for the guest's
architecture through the [Linux bundle build](installation.md#build-a-bundle),
then copy that executable to the same stopped agent's share. A macOS bundle
does not supply this additional Linux executable. Do not copy an Admin API credential
into the guest. The read-only share appears at `/safeyolo` there.

On the host, replace `REQUEST_ID` with a pending ID obtained for `work` above
and grant `adviser` only that request's diagnostic and approval reads:

```sh
safeyolo approvals share REQUEST_ID --agent work --helper adviser
```

Sharing reports whether the Helper session is available or unverified. It
grants no network permission. The [selected-evidence reference](installation.md#selected-evidence-and-network-approvals)
describes the exact read scope, durable identities and withdrawal behavior.

Inside **`adviser`'s guest**, use the staged client with the same full request
ID. Its normal proxy and `/app/agent_token` supply transport and identity:

```sh
/safeyolo/operator-client helper diagnostic REQUEST_ID
/safeyolo/operator-client helper show REQUEST_ID
/safeyolo/operator-client helper prepare REQUEST_ID --reason 'The selected diagnostic identifies the destination needed by the task.'
```

Preparation rereads and submits the canonical typed action. It does not execute
a host command or copy scope from model prose. Back on the **host**, read
`safeyolo approvals show REQUEST_ID --agent work`. The display separates the
trusted effect from the quoted `Helper reason (untrusted text)`. Decide with
`approvals approve` or `approvals reject` for that ID, or return to inspect.
If the model or client fails, the request remains subject to your direct decision.

Installed contributor procedures, including real Helper/client observations,
model failure, ownership and teardown, are in the
[shared-approval test reference](../tests/blackbox/README.md#installed-shared-approval-witness).
