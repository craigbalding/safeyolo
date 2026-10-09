# Manage SafeYolo access and traffic

Use SafeYolo on the host to inspect an agent's activity and decide its access
requests. You are the operator: the person managing the installation. An
instance is one installation's configuration and runtime state. An agent is
a named sandbox with its own persistent home and the workspace you selected.
You can manage an individual agent without a factory or an assistant agent.

## Start with an installed instance

Use your ordinary account on the Ubuntu or Apple Silicon macOS host that owns
the instance. For a new installation, follow [install and start](native-policy.md#install-and-start),
including its platform prerequisites and prepared guest assets. Then follow
[configure and use an agent](native-policy.md#configure-and-use-an-agent).
That example creates `work` and opens its guest shell. A shell is sufficient
for the access example below; no model login is required.

Open a second terminal on the same host, under the same account. Select the
root you installed. This example uses `$HOME/.safeyolo`; if you chose another
root, replace that path before running these commands. Existing installations
keep their current root. Do not reinstall over their state.

```sh
export SAFEYOLO_CONFIG_DIR="$HOME/.safeyolo"
export PATH="$SAFEYOLO_CONFIG_DIR/bin:$PATH"
safeyolo --version
safeyolo status
```

`--version` identifies the executable's source and build profile. `status`
reports the selected `root`, `proxy_state` and configured `agents`. Use the
agent's `name` from that inventory. The examples below use the `work` agent
created during setup. Check that the root and agent match the guest terminal
you opened. A running proxy alone does not mean that the agent is running.

`--root PATH` before a command overrides the environment selection. Without
that option, the command uses `SAFEYOLO_CONFIG_DIR`, then `SAFEYOLO_HOME`, then
`$HOME/.safeyolo`. Set the root and PATH in each new host terminal. These
settings select this terminal's commands; they do not move an installation.
Keep the operator credential in the instance's `data/admin_token` on the host.

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
cp "$SAFEYOLO_CONFIG_DIR/policy.toml" "$SAFEYOLO_CONFIG_DIR/access-example.toml"
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
[per-agent policy](native-policy.md#check-show-and-apply) when you want a
different rule for one agent.

Check and apply the candidate on the host. Applying it replaces the saved
policy and activates it in this running instance.

```sh
safeyolo policy check "$SAFEYOLO_CONFIG_DIR/access-example.toml"
safeyolo policy apply "$SAFEYOLO_CONFIG_DIR/access-example.toml"
safeyolo policy show
```

Check reports `Policy is valid`. Apply returns `status: active`; show lets you
verify the effective `work` host entry. If activation fails or saved and active
state differ, use [policy recovery](native-policy.md#check-show-and-apply)
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
See [policy configuration](native-policy.md#check-show-and-apply).

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
policy change or recreated agent can make the action stale; approval returns
409. Obtain a new request from the agent and review that new ID. You can still
reject the stale item without changing network permission.

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
`$SAFEYOLO_CONFIG_DIR/logs/proxy.log`; repair the named input or occupied
endpoint, then use `safeyolo start` and `safeyolo policy show`. For agent runtime
or shell failures, follow [agent diagnosis and recovery](native-policy.md#configure-and-use-an-agent).
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

First create a separate agent through [agent setup](native-policy.md#configure-and-use-an-agent).
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
cp "$SAFEYOLO_CONFIG_DIR/bin/safeyolo" "$SAFEYOLO_CONFIG_DIR/agents/adviser/config-share/operator-client"
chmod 0755 "$SAFEYOLO_CONFIG_DIR/agents/adviser/config-share/operator-client"
safeyolo agent start adviser
```

On macOS, the host executable is a macOS executable and cannot run in the Linux guest.
Supply a Linux `safeyolo` built from the selected source for the guest's
architecture through the [Linux bundle build](native-policy.md#build-a-native-bundle),
then copy that executable to the same stopped agent's share. A macOS bundle
does not supply this additional Linux executable. Do not copy an Admin API credential
into the guest. The read-only share appears at `/safeyolo` there.

On the host, replace `REQUEST_ID` with a pending ID obtained for `work` above
and grant `adviser` only that request's diagnostic and approval reads:

```sh
safeyolo approvals share REQUEST_ID --agent work --helper adviser
```

Sharing reports whether the Helper session is available or unverified. It
grants no network permission. The [selected-evidence reference](native-policy.md#selected-evidence-and-network-approvals)
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
