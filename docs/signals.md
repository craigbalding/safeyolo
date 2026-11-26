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
safeyolo --instance-dir /private/instance signals configure /private/signal-rules.toml
safeyolo --instance-dir /private/instance signals status
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
safeyolo --instance-dir /private/instance signals publish advisories advisories.debian.example /private/advisory.json
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
and optional `fixed_version`. Omit the version or use `null` when the advisory
reports no available fix. An installed matching package then has unknown version
applicability. Status retains the no-fix state and the operator's stale-evidence
response applies. Do not invent a fixed version. The built-in
comparison supports Debian epoch, upstream and
Debian revision ordering, including backports and `~`; other distributions stay
unknown. Package repair, required process restarts, guest selection and actual
remediation verification remain with the maintenance owner. Retained state is
recovery input and grants no policy authority.

### Assess running Debian guests

The instance owner can explicitly adopt collection from selected running agents.
On the trusted host, extend a private signals configuration with a rule like
the following. Use an already-adopted advisory source and replace the agent,
room and durable recipient ID with authorised targets. Severity, freshness,
cadence and authority are operator choices. This example notifies under standing
authority; it does not authorise patch execution or interruption.

```toml
[rules.packages]
source = 'advisories'
agents = ['research']
distribution = 'debian:trixie'
min_severity = 7
authority = 'standing'
on_stale = 'respond'
on_inactive = 'release'
inventory_max_age_seconds = 600

[rules.packages.guest_inventory]
interval_seconds = 300
timeout_seconds = 30
max_output_bytes = 1048576

[rules.packages.response]
kind = 'notify'
room = 'maintenance'
recipients = ['ag-11111111111111111111111111111111']
```

From that host shell, save the file and request an assessment using the selected
instance. The request targets the rule's configured agents, including each
agent's current owned run. It starts no stopped agent. Commands work from any
working directory.

```sh
safeyolo --instance-dir /private/instance signals configure /private/signal-rules.toml
safeyolo --instance-dir /private/instance signals assess packages
safeyolo --instance-dir /private/instance signals status
```

`assess` returns `requested` with a request ID. The running proxy consumes the
latest request on its existing control pass and retains the ID in collection
status. This receipt is not a completed assessment. Requests made before the
next pass coalesce into the latest request. Collection does not need a harness
restart. Omit `interval_seconds` for explicit-request-only collection; a positive
interval also collects on adoption and reassesses continuously running guests.
Missed intervals coalesce into one current assessment; there is no catch-up
burst. Removing the collection table stops collection. Instances without this
adoption retain manual operation.

The collector reads `os-release` and `dpkg-query` from the selected effective
guest. Each agent has its own complete host-owned package inventory, bound to
durable identity and current run. Multiarch packages keep their qualified names;
an advisory applies if any installed architecture is below its fixed version.
The built-in collection covers Debian packages, including local modifications.
It does not attest application-service exposure or home-installed dependencies.
An external `inventory` file remains available for adopted checks that supply
that evidence; select one inventory producer per rule.

The existing proxy control pass collects and reassesses retained advisories at
each due interval, even if the publisher sends nothing. A failed, truncated,
malformed, unsupported or replaced-run capture invalidates the last inventory
for assessment. Evidence older than `inventory_max_age_seconds` remains unknown.
The configured output bound is at most 1 MiB per stream; increase an insufficient
selected bound within that limit or use a supported external inventory check.

For a notification or Work rule, `on_stale = 'respond'` uses the same selected
response for unknown/stale evidence, including a missing advisory source view.
`retain` and `release` keep their existing meanings. Choose
`authority = 'approval'` when a response needs a decision, or select the existing Work
response to assign maintenance. Pending decisions bind current inventory
content and applicability as well as source, rule, identity and run. A changed
package, stale capture or replaced run cannot reuse the old decision. An
unchanged fresh capture does not create another approval or notification.

Status and notifications show the assessed agent/run, inventory attempt,
distribution, package count, source observation/expiry, applicability, authority,
response and next action. Status retains the observation time; it is not a new
guest observation when the proxy is stopped. A complete package list or an
unaffected finding does not prove running code adopted a fix. An explicitly
adopted maintenance response below executes and verifies a guest recipe.
Guest-image selection remains an explicit acquisition operation. See the
[manual procedure and backend limits](guest-oci.md#assess-and-maintain-installed-agents).

### Execute adopted Debian maintenance

Select `kind = 'maintenance'` to run an existing guest maintenance and recovery
recipe. The rule still owns the affected agents, source, severity, distribution,
freshness and standing or approval authority. No maintenance rule is enabled by
default. Commands run with guest sudo through the existing bounded transport;
they cannot execute host commands. Keep credentials in their existing stores.

For example, extend the `packages` rule above with the following host-owned
configuration. The `/usr/local/sbin/web-os-*` commands represent your installed
application-specific checkpoint, restart, health and recovery recipe: replace
them with actual commands for that guest before adoption. They are not supplied
SafeYOLO commands. A checkpoint must preserve mutable OS state affected by the
chosen package operation, including dependencies and configuration; restoring
only a base selection is insufficient.

```toml
[rules.packages]
source = 'advisories'
agents = ['research']
distribution = 'debian:trixie'
min_severity = 8
authority = 'standing'
on_stale = 'retain'
on_inactive = 'release'
inventory_max_age_seconds = 3600
startup_before_work = true

[rules.packages.guest_inventory]
interval_seconds = 300
timeout_seconds = 30
max_output_bytes = 1048576

[rules.packages.response]
kind = 'maintenance'
checkpoint_command = '/usr/local/sbin/web-os-checkpoint "$SAFEYOLO_MAINTENANCE_DIRECTORY"'
patch_command = 'apt-get update && safeyolo-guest-state restore --apply'
restart_command = '/usr/local/sbin/web-os-restart'
health_command = '/usr/local/sbin/web-os-health'
recover_command = '/usr/local/sbin/web-os-recover "$SAFEYOLO_MAINTENANCE_DIRECTORY"'
timeout_seconds = 900
max_output_bytes = 1048576
utc_hours = [1, 2]
```

Replace the example risk threshold, cadence and UTC hours with your policy.
An omitted or empty `utc_hours` allows any hour. Outside the selected hours,
status reports `deferred_window`; it does not catch up with repeated disruptive
operations. `standing` performs the adopted procedure without another prompt.
`approval` uses the existing scoped approval and revalidates evidence, inventory,
rule, identity and run before execution. Omitting `restart_command` performs no
service restart. The health command must check the affected service and its
actual running code; a listening port alone does not show adoption of a fix.

Before patching, the helper retains each distribution/advisory/minimum-version
requirement separately in the existing persistent guest state. The requirement
survives a new root and does not disappear when a feed expires or a transaction
finishes. A later satisfactory package is reused; the requirement does not pin
an old exact patch version. Review or retire requirements through the existing
`safeyolo-guest-state require` and `forget` commands under the applicable
authority. An incompatible retained constraint stays unresolved.

The helper records the previous effective packages and covered configuration,
then runs the adopted checkpoint and patch commands if restoration is needed.
`restore --apply` consumes retained package choices and configuration. It reports
missing APT candidates, conflicting pins/holds and configuration conflicts rather
than claiming repair. A satisfactory new base avoids redundant installation.
Custom profiles need the retained-state helper, baseline and an appropriate
recipe; there is no generic migration of arbitrary overlays.

Verification checks actual dpkg versions and package-file checksums, allowing
declared configuration changes only when they match retained state. It records
old package files still mapped by continuing processes. Those mappings produce
`pending_restart`, including when a package database says the fixed version is
installed. A deliberately masking executable therefore cannot be accepted from
the base digest or package version alone. Checksum coverage and the adopted
health check define the verification scope; this is not exhaustive process or
application assurance.

`startup_before_work` is optional. When selected, boot leaves the maintenance
transport available while user init hooks, guest schedulers and coding launches
wait for the current run's assessment and adopted response. An approval,
unavailable evidence, deferred window, failed repair or pending restart keeps
that work gated. Inspect `signals status`, resolve the named condition, then
repeat `agent start` for the same target when a prior start returned pending.
No rule means the existing manual startup behavior. Interval assessment also
works on continuously running guests; stopped agents remain stopped.

A missing fix, unsupported or incomplete inventory, or stale source remains
unavailable evidence. Known applicable fixes can be maintained while other
findings remain unknown; status then reports partial assessment. A full startup
maintenance gate requires complete current evidence and verified maintenance.
`on_inactive = 'retain'` keeps the previous response. With `release`, maintenance
can check or restore existing retained requirements even when no new advisory
applies; it does not retire those requirements.

On patch, restart or health failure after a completed checkpoint, the selected
recovery command runs once. `recovered` requires the actual previous package and
covered-file state plus a successful recovery health check. Otherwise the result
is `recovery_failed`. The original failure, recovery result and private logs
remain separate. Recovery does not mean the vulnerability is repaired.

A timeout or lost reply is uncertain: the guest process may still be active.
Read the original operation before another effect. The following commands run
inside the affected guest, with its original operation ID from `signals status`
or `safeyolo-guest-state status`:

```sh
sudo -n safeyolo-guest-state maintenance-status OPERATION
sudo -n safeyolo-guest-state maintenance-recover OPERATION
```

The first command only reads the receipt. The second explicitly selects one
unused completed checkpoint for an interrupted operation, after inspection.
The receipt includes the original command's process identity and group.
An active original command, unknown interrupted identity or already attempted
recovery is refused. Recipes must finish their package/configuration writes
synchronously; a remaining writer group prevents verification or recovery.
Do not leave background patch processes outside that group. Reusing the
original maintenance operation reads its result without repeating patching;
another operation cannot pass an unresolved uncertain operation. Inspect an
incomplete checkpoint or failed recovery through the selected recovery owner.
After resolving the original result, `signals assess packages` requests fresh
assessment; it does not authorize a wider recipe or host operation.

Status identifies the target/run, adopted requirement, command outcomes, actual
verification, pending restart and next action. Detailed package/file snapshots
and command output stay in the private persistent guest-state directory. The
ordinary signal audit records authority, approval and the reached result.
Published guest eligibility, instance-wide default selection, per-agent rootfs
overrides, the gVisor runtime and VZ boot kernel retain their existing update
paths. Use `guest upgrade` and explicit affected-agent lifecycle operations when
selecting a suitable published image. If acquisition or compatibility fails,
inspect that result before changing the selected guest.

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

For versioned check and challenge updates, use the separate adoption controls
below. Permission to receive a signal does not authorize its publisher to
change controls.

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

## Adopt versioned checks and challenges

A `control_update` signal carries an immutable `SignedBundle`. Its Ed25519
signature binds the native check definitions, sandbox job specifications,
challenge selectors and steps, revision, evidence times and withdrawal state.
The receiver checks the configured publisher key independently of broker access.
Receiving or signing content executes nothing and changes no active policy.

On the publisher's trusted host, select a private directory and the installed
CLI. The first command creates a new private PKCS#8 key file and reports its
public key. It refuses an existing key file. The second signs an authored JSON
bundle and writes `signed.json`. Keep the private key outside guest mounts.

```sh
safeyolo signals keygen-update /private/publisher/key.der
safeyolo signals sign-update /private/publisher/bundle.json /private/publisher/key.der /private/publisher/signed.json
```

The bundle format is `safeyolo.control-update/v1`. Fields are `name`, `publisher`,
positive integer `revision`, Unix-second `observed_at` and `expires_at`, Boolean
`withdrawn`, optional `previous` SHA-256, `requires`, `changes`, `checks`, `jobs`,
`challenge` and `fixtures`. `checks` uses the existing native named-check format.
Each check name starts with the bundle name and a dot. A job check's `source.spec`
names a job in `jobs`; it cannot select an arbitrary host file. The signed job
specification fixes its executable arguments and existing sandbox limits.

This runtime supports the `gateway-route-v1` and `platform-job-v1` primitives.
New implementations use the platform sandbox: gVisor on Linux or
Virtualization.framework on macOS. Unknown required primitives, external job
references and unsupported engines are rejected visibly. Such a candidate
cannot silently omit a required check. Existing native service/job definitions
remain available to directly authored route challenges.

The native `challenge` has `agents`, `service`, `capability`, `methods`, `path`,
`revision` and ordered `steps`. Service, capability and path use native glob
matching. Activation sets its revision to the signed content digest. Supported
steps are:

```json
[
  {"kind":"question","field":"origin","question":"Identify the instruction origin"},
  {"kind":"check","check":"exports.destination","on_positive":{"kind":"question","field":"conflict","question":"Explain the conflict with the adopted task constraints"}}
]
```

A positive finding can instead use `on_positive = {kind = 'deny'}`. A check
receives a host-generated value with the action, authority digest, challenge
name and revision. Agent answers are labelled `untrusted_answers`. Required
questions stop the sequence before the next check. A failed, unsupported,
incomplete or unavailable finding prevents escalation. A negative finding is
distinct from those states. Reflective answers are context, not proof that
prompt injection is absent.

Publish through the existing `signals publish` command. The envelope uses
`evidence = {"kind":"control_update","candidate":SIGNED_BUNDLE}`. Its revision,
times and withdrawal Boolean must equal the signed bundle. The source ID and
key must match the receiver's selected source. Repeated current-state delivery
does not create another activation or approval.

### Select adoption and qualification authority

On the receiving host, add the following table to its existing signal
configuration before running `signals configure FILE`. Replace the source,
key, publisher, public key and scope with the operator's choices. These are
fixture names, not product policy. Omitting `automatic` requires review for
each distinct candidate. Qualification has its own bounds; a candidate outside
either selected bound needs the existing operator approval before execution.

```toml
[control_updates.exports]
source = 'updates'
key = 'controls.exports'
publisher = 'selected-defender'
public_key = 'BASE64_ED25519_PUBLIC_KEY'
on_withdraw = 'retain'
fixtures = []

[control_updates.exports.qualification]
agents = ['research']
services = ['controlled-export']
capabilities = ['writer']
methods = ['POST']
paths = ['/export']
effects = ['passive']
network_gates = []
max_timeout_ms = 30000
max_memory_mb = 512
max_input_bytes = 16384
max_output_bytes = 8192
max_concurrent = 1
max_pending = 0
max_cached = 16
allow_network = false
allow_guest_root = false
```

To permit automatic adoption, add an `automatic` table with the same fields
and the selected limits. Scope values match exactly, or use `'*'` explicitly.
No tightening-only rule or staged rollout is imposed. Removing ineffective
checks can be authorized. Qualification and automatic-adoption bounds include
additional manual check invokers, effects, guest privilege and network use.
Existing gate, service, credential and network authority still applies to jobs.
If network use is allowed, select exact existing `network_gates` whose
permissions the publisher may use. A publisher cannot choose a different
gate under automatic authority. Effect labels remain adopted declarations;
the gate's enforced permissions bound actual network and service use.

Every new check needs publisher positive/negative fixtures and at least one
operator-defined regression fixture in the adoption table. A fixture has
`check`, typed `subject`, and expected Boolean `positive`. Replace `fixtures = []`
with those independently chosen cases before adopting a bundle with checks.
Publisher code and fixtures execute only through the existing adopted check
executor and sandbox, including during qualification. Publisher PASS text,
exit zero alone and agent assertions cannot satisfy a typed finding.

Outside standing authority, `signals status` identifies the canonical approval
and `proposed` native before/after definitions, job arguments, effects and
limits. Use the selected instance's ordinary `approvals show ID --json` and
`approvals approve ID --option once --json`, or reject it. The decision selects
qualification and activation of that candidate; it grants no service route or
credential. Current source, authority, saved/live policy, job bytes and
qualification evidence are rechecked before activation.

### Inspect activation and recovery

The existing policy transaction activates the complete check/challenge revision
together. A failed save, preparation or activation retains the previous usable
policy. `control_update_revisions` in the native policy records publisher,
content digest, qualification/adoption basis and previous revision. Unrelated
policy and grants remain under their existing owners.

`signals status` shows the recorded candidate, qualification, pending approval,
active, rejected, failed, withdrawn or rolled-back outcome and its observation
time. The audit stream records state changes and superseded candidates.
Use `policy show` to inspect current saved/active state; a recorded result is
not a new live observation. Job findings retain their existing execution audit.

Changing applicable requirements supersedes pending route challenges and
approvals. Read the challenge's `guidance.active_control_update`, then retry the
original operation through normal controls to obtain a new challenge. Old
service tokens can be replaced during policy activation; read
`/gateway/services` for the current authorized token before that retry. Old
answers, cached findings and expired evidence cannot satisfy the replacement.
A completed answer never grants access, and explicit denials remain enforced.

For recovery, set `pin = 'IDENTIFIED_RETAINED_SHA256'` in the adoption table and
save the configuration through `signals configure FILE`. The running proxy
requalifies that signed revision under current authority and replaces only
that update's definitions. The pin overrides later announcements until the
operator removes it. With `on_withdraw = 'retain'`, a signed withdrawal retains
protection. With `on_withdraw = 'previous'`, it selects the signed `previous`
revision, requalifies it and applies the same authority checks. A missing,
incompatible or failed replacement leaves current protection active. Recovery
does not restore unrelated grants or undo disclosures and external effects.

After failure, inspect the retained status and check audit first. Unchanged
failed qualification is not repeatedly executed. Correct the candidate or
adopted inputs, then save the changed authority or publish a new signed revision.
There is no separate updater daemon, guest runtime or central registry.
