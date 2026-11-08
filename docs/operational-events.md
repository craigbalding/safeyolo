# Selected operational events

An operator can select operational notices in the same preview and apply
workflow as a [support grant](peer-support.md#preview-and-grant). The recipient
and subjects use durable agent identities qualified by their owning instances. Notifications
require observation authority. Guest administration and lifecycle actions remain
independent selections. Room membership and target participation are unnecessary.

## Event meanings

Select explicit `notifications` in the support proposal. An empty list disables
notices. These kinds have no common severity ordering.

| Kind | Surviving producer and meaning | Expected stop and recovery |
|---|---|---|
| `launch_failed` | The host start owner recorded a failed sandbox or harness start request. | A failed request is not proof that the sandbox stopped. Inspect its current state before retrying. |
| `sandbox_availability` | The host observed a change in sandbox availability: starting, running, stopped, degraded or unknown. | The saved stopping/stopped lifecycle fence identifies an expected stop. Unknown or degraded does not mean dead. |
| `control_availability` | The host observed a change in the existing backend control path. | A failed control transport does not prove sandbox failure. Missing proxy attachment is not a crash signal. |
| `sandbox_recovered` | The host observed running sandbox and ready control after an unavailable condition or recorded launch failure. | This proves those observed controls, not model progress or completion of a repair. |
| `command_exit` | The guest command supervisor reaped its configured long-running child. Status and signal describe that child. | Intentional stop and clean completion remain explicit. A Coord harness invocation finishing inside its live supervisor is not this supervisor's death. |
| `command_restart` | The guest command supervisor started a replacement child after an exit. | Restart is an observed attempt, not proof of sustained model health. |
| `command_failed` | The guest command supervisor reached its existing terminal failure state. | No new restart policy is introduced. Separately authorized recovery remains available. |
| `supervisor_exit` | Guest PID 1 reaped its command supervisor before an expected stop or terminal result. | PID 1 retains the exit reference before restarting the supervisor. Quiet rooms, unchanged checkpoints and missing attachments are not evidence for this kind. |
| `supervisor_restart` | The replacement guest command supervisor resumed its saved launch after PID 1 observed the previous owner exit. | The launch and sandbox generation remain explicit. Guest-produced facts remain guest evidence. |
| `needs_operator` | The canonical Coord signal owner has a selected subject's material signal with `needs_operator: true`. | The notice retains the signal identity and revision. Resolution reads its current state; notification does not resolve the signal. |

For `needs_operator`, also select `signal_rooms` by room name. This explicitly
discloses the selected subjects' material signal summaries and references from
those rooms. It grants no room history or unrelated signals. Signal bodies are
agent-authored claims, including when their basis is `observed`. They can
contain sensitive text. The preview explains this disclosure. Eligible delegated
approval notices continue on their existing approval path.

## Attention and evidence

Recipients use ordinary identity-wide `wait_for_coord` and `read_attention`.
The `operational_event` object names the owning instance, durable target,
run/launch where available, event kind, source, expected-stop context and
canonical event identity. Its message explains whether to inspect. Reading or
replaying attention creates no work and executes no repair.
`source_time` uses the source's clock, including the guest clock for guest
supervision. `observed_at` is the owning host's first retained observation time.
Both use Unix seconds. Neither is a delivery or model-receipt timestamp.
For `supervisor_exit`, child state is `unknown`. Reaping the supervisor does
not prove that its child stopped. The replacement owner fences the saved child
before resuming the launch.

Delivery checks the selected kind and current observation/source authority.
Resolution checks the current observation grant, target identity and signal
disclosure. Deselection stops new notices. A revoked, expired, narrowed or replaced
grant refuses disclosure. A matching regrant can make retained references
readable again; there is no approval-result withholding tombstone. Earlier
disclosures cannot be recalled. A denied read explains which current authority
must be inspected without exposing the source content.

Source owners keep their saved facts. Coord retains references and delivery
state, not guest logs or another audit archive. A reference can outlive its
source details. A later launch, sandbox generation or bounded guest transition
retention can replace the detailed source. Resolution reports that loss and
returns only currently authorized evidence. It never reconstructs missing
historical evidence from a current observation.

Host availability records include the previous runtime/control state and
previous expected-stop context. A normal start after an expected stop can
produce a recovery observation. That does not make the earlier stop a fault.
Guest transitions contain enumerated states, reasons and numeric exit facts;
commands and output are excluded from notices and observation-only evidence.
Guest-written state remains untrusted even when the installed helper produced
the observation during a controlled run.

## Loss and recovery

One host observer performs bounded local reconciliation. Recipients use the
existing long wait; they do not poll every worker. Retained attention is
authoritative and wake messages are hints. A lost final hint needs no later
business event: the outbox retries retained hints, and a resumed wait reads the
canonical feed before waiting again. The owner also repairs accepted room
messages whose publisher exited before attention projection. Observer restart
resumes saved transition positions and scans current actionable conditions.
An unavailable broker leaves hints pending while local references and audit
delivery remain independent.

For remote recipients, the owner uses its scoped TLS NATS federation account.
JetStream retains the latest wake hint for each qualified recipient; the hint
contains no target evidence. The owner's canonical attention ledger retains the
selected references. After reconnect, a recipient reads that ledger from its
own source cursor and resolves each object under current observation rights.
`wait_for_coord` accepts several selected sources with independent instance IDs,
cursors and availability. A disconnected source does not prevent useful work
from another source. No global cross-instance order or copied audit archive is
created. See the [source selection example](coord-reference.md#collaborate-through-a-home-safeyolo).
Notification or JetStream failure can make event waiting unavailable while
Core NATS support requests still work. A full request/reply outage makes remote
support unavailable; owner-side controls remain the recovery path where usable.

Each host pass visits at most eight selected subjects and reads at most 64
signal revisions per selected subject/room. The next pass starts after five
seconds. Signal scans cycle through the canonical revisions; the bound is a
page size, not a limit on selected signals. A damaged guest or launch record
does not suppress independently available host observations.

Operational references share the existing Coord store and attention retention.
Deleting that state loses its references and cursors. Guest supervision retains
the latest 64 transition references for its current launch; earlier details can
be lost during a prolonged observer outage. A current terminal failure remains
discoverable from saved state. The observer reports current conditions after
restart, not unobserved intermediate transitions.
The host retains its latest 64 availability transitions per durable subject.
The last failed start remains until another failed start replaces it. A later
successful start records its recovery context. Asynchronous launcher failure
details remain in the current launch record until replacement. A new selection
can deliver these retained source references. Previously delivered references
retain their identity after source replacement and report missing details.

The existing JSON Lines (JSONL) audit log and human Admin event stream remain
the audit path. A recovered source condition does not prove that an earlier
audit write succeeded. Pending audit writes and their failures remain visible
through the existing outbox and stderr diagnostics. Event time and observation
time are distinct. This feature does not detect arbitrary live but wedged
models or monitor a whole host from outside it.

## Observe source health

`observation_health` is an additional notice for a source selected by an active
support grant. It reports an unhealthy or recovered observer source, separately
from the target's availability. Host-run, launch, failed-start, runtime-probe,
guest-supervisor and selected signal-room sources retain separate last-success
times and unavailable reason classes. A quiet readable source is available.
An unreadable record, invalid source, changed generation or timed-out probe is
missing evidence; it does not establish target failure.

A second source can become unhealthy while another remains unavailable. Each
transition uses ordinary operational attention and the existing audit outbox.
Current source selection, target identity, peer epoch and grant lifetime are
checked before staging, before remote hints and before returning evidence.
Revocation or expiry stops disclosure, including reads of retained health
references. The trusted operator can inspect per-source `last_success_at`,
`last_observed_at` and `unavailable_reason` through `coord status` or the
authenticated `GET /admin/coord/diagnostics` endpoint. These diagnostic times use
Unix milliseconds. When no active notification selection remains for a target,
the observer stops scanning that target. Its diagnostic timestamps then retain
the last observations. For targets that remain selected, record sources are
observed together; current source selections govern disclosure.

The runtime probe and its observation-record lock share a two-second deadline
per subject. When that deadline expires, the other record sources still report
their own results. Observation runs separately
from local hints, federation hints, audit delivery and projection repair. A
slow probe cannot consume their delivery pass. Within an observation batch,
at most eight subjects run in sequence; additional subjects continue in the
next batch. The five-second pause begins after that batch completes.
