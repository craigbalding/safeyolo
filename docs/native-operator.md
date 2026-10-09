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
Use the [native Factory entry](factories.md#fresh-setup-check-approve-and-run) to prepare and start a Factory. Inspect reads its approved roles and live state.

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
credential controls. Start Helper's sandbox with `agent start helper
--sandbox-only`; the probe launches its one Codex command through native `agent
start helper --foreground`. It preserves an already active coding session by
refusing to replace it. Before the run, verify the ordinary launcher version and
login status inside Helper. An operator may privately copy an existing
provisioned Codex token into this owned test home under the standing test
authority. Keep the managed configuration and proxy/CA settings. Do not copy
the Admin API credential into Helper.

`TRANSPORT_CLI` is the installed native CLI for this root. `FULL_COMMIT` identifies
the installed CLI/proxy/guest source, separately from the checkout containing
the test driver. `ROOM` is an existing ordinary Coord room in this disposable
instance, with Helper send/receive and Worker receive permission. Keep it
separate from a running factory's work room. Both guests use the ordinary staged
`/home/agent/.safeyolo/safeyolo-coord` binary with their own Agent API identities.
The real run saves raw Codex events and stderr before parsing them, including
when the command fails. `--helper-events FILE` selects the events file in
an existing host-owned directory outside guest writable mounts. The default
is a unique file in the root's logs directory; stderr uses `FILE.stderr`.
Both files have private permissions. Preserve a failed run's events
for diagnosis instead of starting another model session to recover its operands.

Replace these operands before running as the disposable instance's owner.
Connect the approved Tart Commander client to this Ubuntu instance before the
decision. Use its existing remote connection settings and separate Admin API
and SSH credentials. For an SSH tunnel, loopback HTTP and WebSocket endpoints
are supported; the event path is `/admin/events`. This command changes the
disposable policy, invokes one Codex session and waits up to 600 seconds for a
human decision through CLI or Commander:

```sh
uv run --frozen --no-sync python tests/blackbox/installed_shared_approvals.py \
  --config-dir ROOT --transport-cli TRANSPORT_CLI \
  --native-cli ROOT/bin/safeyolo --native-proxy ROOT/bin/safeyolo-proxy \
  --commit FULL_COMMIT --interfaces --real-helper --shared-room ROOM \
  --operator-timeout 600 --reconcile-seconds 120
```

The result requires native diagnostic/show/preparation commands executed by
Codex, a canonical Helper-attributed typed preparation, unchanged network
permission before the human decision, two exact Worker marker deliveries,
refusal for Helper and the second port, and owned cleanup. The driver prints
the native trusted scope and separately quoted Helper diagnosis before the
human decides. Helper's successful native preparation does not grant network
permission. Rejection, an expired decision window or a changed action stops
the journey without a Worker retry. Model prose and a successful process exit
do not establish U3.

The fixed disclosure inputs place a synthetic secret in selected raw evidence
and a separate peer record outside Helper's reads. Helper responses, routine
native logs and the shared-room notification must exclude both. A deterministic
Helper call appends the fixed terminal-control/Markdown/HTML reason to the
real diagnosis on the same typed action. The native display quotes that reason;
the shared notification carries only the permitted canonical projection.
Raw evidence remains available to its authorized owner.

When `client_reconciliation` appears, the same action has its canonical CLI
outcome and two exact Worker marker deliveries. The proxy and guests remain
live for the selected 120 seconds. Reconnect the other client during this window
and observe the same terminal state and reusable Worker/host/port effect.
Record the actual Commander display and backend/source separately. The driver
does not infer a GUI result. Its teardown then stops both guests, proxy,
listeners and origins, and restores the saved fixture policy after proxy exit.
Cleanup errors remain failures.

Omitting `--real-helper` selects deterministic preparation. Add
`--wait-for-operator` to use the same human/client window without a model turn.
These controls do not establish the real U3 action or isolated model failure in
a running Helper. That U6 failure observation remains separate from tool/login
readiness. Reuse the accepted lost-reply, authority and race controls at their
tested revisions.

For the separate U6 model failure case, use the same owned Ubuntu/systrap setup
with both sandboxes and the proxy running. Helper's ordinary Codex command must
be stopped before the probe. Verify its installed launcher version and login
status. Replace `ROOT`, `TRANSPORT_CLI` and `FULL_COMMIT` with the installed
instance operands described above. Run from the checkout containing the probe:

```sh
uv run --frozen --no-sync python tests/blackbox/installed_shared_approvals.py \
  --config-dir ROOT --transport-cli TRANSPORT_CLI \
  --native-cli ROOT/bin/safeyolo --native-proxy ROOT/bin/safeyolo-proxy \
  --commit FULL_COMMIT --interfaces --model-unavailable
```

The probe prepares the selected pending action with deterministic native Helper
calls. It uses its second owned listener at `127.0.0.3` as a model endpoint
returning HTTP 503. Only Helper receives fixture access to that listener. A
command-scoped Codex provider override selects that endpoint without changing
the saved model configuration or credentials. HTTP and stream retries are zero;
no paid model request or repeat U3 witness is needed.

Before returning the 503, the endpoint records Helper's running sandbox,
coding-agent and launch identities, the same pending action, unchanged policy
and zero Worker deliveries. The probe requires an actual model request naming
the selected request, an initialized Codex thread and the matching failed-turn
diagnosis. A missing launcher, authentication failure or successful process exit
cannot supply this result. The printed `model_unavailable` phase contains the
diagnosis and pending action. Raw events and stderr retain private permissions.
The native CLI then displays the trusted scope and directly approves through
the common resolver. The final result requires the approved canonical action,
exact Worker marker deliveries, refused Helper/second-port controls and owned
cleanup. The model failure itself must leave the action pending and policy
unchanged. Add `--wait-for-operator --reconcile-seconds 0` when a human should
make the direct decision instead of the fixture's explicit operator call.

Commander can run on approved Tart against the same Ubuntu pending item.
Physical-host GUI placement is not a prerequisite. A client source test does
not establish the actual cross-client journey.
See the [entry responsibility map](native-settings.md#operator-entry-responsibilities)
for the retained component boundaries.
