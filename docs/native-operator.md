# Native operator and Helper commands

Use these commands on the host of an already prepared native instance. The
examples use the installation at `$HOME/.safeyolo-native`. Its `config.toml`
selects the Admin API, audit log and policy. Worker and Helper must already have
distinct durable identities and trusted agent listeners. Keep the operator
credential on the host.

## Select once and inspect

For an existing Factory named `operator`, open one terminal session:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" inspect --factory operator
```

Select `worker` once. Each prompt shows the instance, workflow and selected
agent. Factory choices come from the existing approved snapshot; live state
comes from the host inventory. An approved snapshot does not establish readiness.

The following lines are inputs to the `inspect>` prompt. Replace `REQUEST_ID`
and `FLOW_ID` with IDs returned by `pending` and `traffic` in this session.

```text
select worker
state
pending
traffic ~c 428
show FLOW_ID
body FLOW_ID response
logs
approval REQUEST_ID
share REQUEST_ID helper
approve REQUEST_ID
attach
back
quit
```

`approval` shows the canonical action, its reusable Worker/host/port effect and
the separate quoted Helper reason. `share` grants only that request's diagnostic
and approval reads. It reports whether the Helper session is available or
unverified. If Helper's model or command is unavailable, human decisions remain
usable. `approve` and `reject` use the common resolver. A lost reply triggers a
canonical read, without another mutation.

`attach` delegates the selected name and instance to the native host owner's
`agent attach` command. It requires that installed operation and an existing
attachable terminal. At this component boundary, #817 still owns that operation
and terminal proof. If it is unavailable, inspect reports the problem and keeps
the selection. Returning from the terminal or using `back` preserves the target.
This command does not provision or start a Factory; #820 owns those entries.

## Direct commands and evidence

Direct commands carry their own target. Changing an interactive target or
another viewer's scope/filter cannot change a script's explicit selection.
These examples select Worker's records and return JSON:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" traffic list --agent worker --filter '~c 200' --json
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" approvals list --agent worker --json
```

The `traffic` subcommands `show`, `body`, `websocket`, and `message` open a
selected exchange, HTTP body, WebSocket transcript, or message body. Bodies
retain exact `data_base64` bytes and add `text` when those bytes are UTF-8.
JSON escapes terminal controls. Unavailable bytes retain their availability
and reason fields. `message` accepts `--offset` for subsequent 64 KiB pages;
its response reports `offset`, `total_size` and `end`.

After selecting `FLOW_ID`, export it to a host-local file. Replace `FLOW_ID`
with the actual ID. This command replaces `response.raw` only after a complete
successful download:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" traffic export FLOW_ID raw_response response.raw --agent worker
```

Retain all seven formats under the #821 first-handoff decision:

| Format | Operator use |
| --- | --- |
| `raw`, `raw_request`, `raw_response` | Reconstructed HTTP observations and retained bytes. Combined raw can include WebSocket payloads. |
| `curl`, `httpie` | Saved request commands for inspection. The client never executes them. |
| `har`, `zhar` | Interoperable HTTP archives; zhar uses zlib compression. |

These commands reuse the existing native exporter. A pruned selection returns
unavailable, including when it is pruned before the byte read. Failed downloads
preserve the previous file. Retained bytes and exporter limits are described in
[live traffic inspection](DEVELOPERS.md#live-traffic-inspection).

If the API stops, these host-local commands still read the configured audit file
and check the saved policy. Diagnosis labels active state as unverified:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" logs --agent worker --lines 50 --json
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" diagnose --agent worker --json
```

## Helper preparation

On the host, select a pending `REQUEST_ID` and grant Helper its reads:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" approvals share REQUEST_ID --agent worker --helper helper
```

Inside Helper, use the native client supplied by its approved installation or
read-only fixture mount. These examples use `/safeyolo/native-operator`;
replace that path with the supplied executable and `REQUEST_ID` with the shared
ID. Helper's normal proxy and `/app/agent_token` supply transport and identity:

```sh
/safeyolo/native-operator helper diagnostic REQUEST_ID
/safeyolo/native-operator helper show REQUEST_ID
/safeyolo/native-operator helper prepare REQUEST_ID --reason 'The selected diagnostic shows Worker needs this owned origin.'
```

Preparation rereads the canonical action and sends that typed action. It does
not copy arbitrary parameters from model prose or execute a host command.
Helper cannot decide or grant itself reads. The host operator reads the trusted
scope with `approvals show REQUEST_ID` and decides with `approvals approve` or
`approvals reject`. Approval permits Worker at that one host/port until explicitly
removed. Rejection changes the disposition without adding a deny rule.

## Bounded installed witness

Run from this checkout on the existing owned Ubuntu/systrap fixture. The selected
native proxy and two guests must already be running. The marked disposable root
must expose each guest's existing read-only `config-share` mount. Supply the
full candidate commit and installed matching CLI/proxy. `TRANSPORT_CLI` is the
maintained test transport that already controls those guests; it needs `agent
shell` and `agent stop`. Those host entries remain #817's responsibility.

For the real Helper mode, Helper must already have its ordinary Codex launcher,
model access and guest authentication. The probe imports no host credential and
does not select another model. It preserves the configured model route and
credential controls. Replace `ROOT`, `TRANSPORT_CLI` and `FULL_COMMIT` before
running. This command changes the disposable policy, invokes one Codex session,
then stops both guests, the owned proxy and the two origins:

```sh
uv run --frozen --no-sync python tests/blackbox/installed_shared_approvals.py \
  --config-dir ROOT --transport-cli TRANSPORT_CLI \
  --native-cli ROOT/bin/safeyolo --native-proxy ROOT/bin/safeyolo-proxy \
  --commit FULL_COMMIT --interfaces --real-helper
```

The result requires native diagnostic/show/preparation commands executed by
Codex, a canonical Helper-attributed typed preparation, unchanged network
permission before the human decision, two exact Worker marker deliveries,
refusal for Helper and the second port, and owned cleanup. Model prose and a
successful process exit do not establish that result. Omitting `--real-helper`
selects deterministic native preparation; it does not establish U3.

Physical Commander cross-client observation still needs the physical Mac GUI
against this Ubuntu instance. Tart source checks do not establish that journey.
See the [entry responsibility map](native-settings.md#operator-entry-responsibilities)
for the retained component boundaries.
