# Signals and adopted responses

The native proxy follows selected NATS Key Value (KV) keys, retains accepted
evidence, assesses local applicability and reconciles operator-selected
responses. Each instance follows current state independently. Instances do not
compete for updates in a shared work queue. Policy admission uses complete local
snapshots and does not contact the source or broker.

The supported push interface is native NATS JetStream KV. HTTP-only maintained
lists use the existing [feed downloader](https://github.com/craigbalding/safeyolo/blob/master/docs/policy-feeds.md) and can publish their
accepted snapshots to NATS. Other providers need an adapter that publishes the
envelope below. There is no general webhook, Server-Sent Events or provider
WebSocket receiver.

## Configure the selected host

Use an existing instance in an operator host shell. Prepare a KV bucket and
host-held credentials through the broker's existing administration interface.
The broker's subject permissions own publication and subscription authority.
Keep credentials and configuration outside guest mounts.

Save this example in a private host file. Replace the endpoint, credential path,
bucket, source identity and agent with the selected values. Loopback mode
requires a literal loopback address. Remote connections reuse the existing
protected NATS endpoint: TLS with its selected CA, or explicitly verified
Tailscale mode. There is no unprotected remote fallback.

```toml
[sources.advisories]
username = 'signal-reader'
credential_file = '/private/instance/signal-reader-token'
bucket = 'signals'
keys = 'advisories.debian.>'
source_id = 'adopted-debian-adapter'
max_bytes = 16384
max_signals = 4096
max_age_seconds = 86400
retry_seconds = 5

[sources.advisories.endpoint]
mode = 'loopback'
url = 'nats://127.0.0.1:4222'

[rules.web]
source = 'advisories'
agents = ['research']
distribution = 'debian:trixie'
min_severity = 8
authority = 'approval'
on_stale = 'retain'
on_inactive = 'release'

[rules.web.response]
kind = 'list'
feeds = { research = 'research-quarantine' }
body = "affected.example\n"
```

The threshold, distribution, scope, membership and authority are operator
choices. `standing` authority needs no recurring prompt. `approval` uses the
existing scoped pending-approval owner. `retain` preserves the previous response
when evidence is stale, unavailable or inactive; `release` selects its inactive
state. Expiry does not establish safety. `max_bytes` and `max_signals` bound the
source's local retention. Rejected input retains the accepted view.
Removing a source or rule stops its following or reconciliation. Retained list
snapshots still follow the feed's selected stale behavior and authored policy.

```sh
safeyolo --root /private/instance signals configure /private/signal-rules.toml
safeyolo --root /private/instance signals status
```

`configure` validates and saves mode `0600` configuration. A running proxy adopts
changes during its next policy-control pass. Without that proxy, sources and
responses do not run. Status shows retained evidence, freshness, applicability,
selected rule, authority, approval ID and response result. It does not assert
model receipt or completed maintenance.

## Publish evidence

An authorised adapter retains an envelope as a KV value. The key equals `id`.
Use increasing source revisions for corrections and withdrawals. The Unix
timestamps describe source evidence, not delivery. Replace the example times
with actual observation and expiry times.

```json
{
  "source_id": "adopted-debian-adapter",
  "id": "advisories.debian.example",
  "revision": 1,
  "observed_at": 1795132800,
  "expires_at": 1795219200,
  "withdrawn": false,
  "evidence_refs": ["https://provider.example/advisory/example"],
  "evidence": {
    "kind": "advisory",
    "distribution": "debian:trixie",
    "severity": 9,
    "subject": {"kind": "service", "name": "public-proxy"}
  }
}
```

A host publisher can use the command below with a credential that permits
publication. Set `follow = false` on a source used only for publishing. Broker
acceptance is not an applied or verified response.

```sh
safeyolo --root /private/instance signals publish advisories advisories.debian.example /private/advisory.json
```

Keep withdrawals as higher-revision envelopes with `withdrawn = true`.
Distribute corrections even when severity falls below the selected threshold.
A KV deletion has no source observation time and does not establish safety.
Receivers report deletion and keep accepted evidence under its existing
freshness policy. Reconnect and process restart recover current values. Older,
conflicting, malformed or unauthorised source identities cannot replace an
accepted revision or renew its age.

Authentication attributes a publisher; it does not prove its assertions correct.
Adopt source and disclosure scope before relaying evidence to other instances or
agents. Envelope fields cannot select a command, effect, credential or recipient.

## Assess current subjects

Service findings match currently listening named proxy TCP ingress bindings and
their selected agents. A binding change reassesses existing findings without a
new publication. Destination findings use
`{"kind":"destination","hostname":"affected.example"}` and assess the
selected agent's current network rules for an HTTPS `GET /` on port 443.
This assessment does not probe credentials or prove access for other requests.

For application services or packages, select an absolute host-owned `inventory`
file and positive `inventory_max_age_seconds` in a rule. An existing adopted
check/job must produce complete effective-state evidence with these fields:

```json
{
  "agent_id": "ag-11111111111111111111111111111111",
  "run_id": "11111111111111111111111111111111",
  "observed_at": 1795132800,
  "distribution": "debian:trixie",
  "packages": {"curl": "8.14.1-2+deb13u2"},
  "services": ["web"]
}
```

Use the effective guest, including modifications. A base-image manifest or saved
transaction is insufficient. The reader checks the current owned run, durable
identity and evidence age. Missing, stale, malformed or replaced-run evidence
remains unknown. An absent package in a complete fresh inventory is unaffected.
A package subject has `kind = "package"`, `name`, `distribution`
and `fixed_version`. The built-in comparison supports Debian epoch, upstream and
Debian revision ordering, including backports and `~`; other distributions stay
unknown. Package repair, required process restarts, guest selection and actual
remediation verification remain with the maintenance owner. Retained state is
recovery input and grants no policy authority.

## Select an existing response owner

For a list response, configure one separate managed feed per selected agent in
`policy-feeds.toml`, with `distributed = true` and its existing format, size,
change and freshness limits. Reference that feed in the intended agent's network
rules. The response writes a complete local snapshot; the existing policy
chooses its effect. This controls new admissions and does not terminate already
admitted connections. Choose the feed's `on_stale` behavior consistently: a feed
that denies unavailable evidence can still deny traffic after membership is
released. With `on_stale = 'retain'`, an explicit empty response snapshot releases
membership. Before the first snapshot, existing unavailable behavior applies.

For a notification, select `kind = 'notify'`, `room` and explicit durable agent
IDs in `recipients`. The existing targeted Coord owner retains publication and
attention receipts. Operators can read the selected room and canonical audit.

For assessment, check/job execution, remediation or a lifecycle request, select
`kind = 'work'`, `room`, a durable `assignee`, `title` and a `requirement`
reference. Complete findings are retained in that room. Ordinary assigned native
Work links to those inputs. Its executor must use the existing effect authority.
Network restriction, workload stop and configuration change remain distinct
operations. Keep any required maintenance path authorised through existing
policy; signal receipt creates no such authority.

`pending_approval`, `attempted`, `applied`, `verified`, `notified`, `dispatched`,
`failed` and `uncertain` have separate meanings. A list becomes `verified` after
the running policy captures its current snapshot. Renewed evidence updates the
list's validity without repeating the approval or changing the completed-effect
identity. The snapshot expires at the earliest selected finding's expiry or
source freshness deadline. Dispatched Work has not yet performed
its requested external effect. Duplicate delivery and unchanged findings reuse
the prior receipt, including a newer revision with the same finding content.
An unchanged refresh does not extend a pending approval's original expiry.
A withdrawal does not undo a completed external operation.

Inspect the displayed ID with `approvals show` or `approvals explain`. Decide it
with `approvals approve ID --option once` or `approvals reject ID`. A delayed
decision over withdrawn or superseded findings performs no effect. List approvals
also bind the adopted feed interpretation and its authored global and agent
network effects; changing those effects requires a current decision. The running
proxy rechecks current scope after approval; the decision itself executes no
action.

## Distribute maintained lists

A receiver's signal source sets `list = 'local-feed-name'` and selects the
publisher's key through `keys`. Its local feed sets `distributed = true` to
disable HTTP acquisition there. Publish the ordinary envelope with
`evidence = {"kind":"list","body":"member.example\n"}`. Validation uses the
local feed's existing format and change limits. Source age and expiry survive
distribution.

An HTTP publisher adds `publish = {source = 'publisher', key = 'lists.current'}`
to its feed. The selected signal source owns the protected broker connection.
The existing refresh loop publishes each accepted view with compare-and-swap,
reuses unchanged publications and retries through its existing refresh schedule.
Local accepted data survives a distribution failure. Broker payload and
configured byte limits apply.

## Diagnose a response

Read `signals status`. Separate saved configuration, broker connection, watch
state, rejected input and unavailable evidence. Check original source age,
selected agent, applicability, approval and effect-owner receipt. For a list,
`policy feeds status` shows saved data and `policy show` shows active capture.
For dispatched Work, read its canonical result. Creating Work is not completing
repair.

After a failed or uncertain effect, inspect the original receipt before selecting
a changed response. Reconnect does not repeat completed prompts, notifications
or actions. Processing stays in the existing host/proxy and policy-control loop.
No intelligence stack or language runtime is added to a guest.
