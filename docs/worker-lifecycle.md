# Configure a worker's operating lifecycle

The host lifecycle owner starts and stops the existing worker. The running
proxy consumes schedules from its managed NATS JetStream. The guest supervisor
continues to own harness turns, its checkpoint and native Coord Work. No
worker receives a host command, an Admin credential or another worker's target.

The worker needs its existing workspace, staged launcher and authentication.
For a supervised worker, prepare its approved Factory role and retain its valid
checkpoint. A lifecycle edit does not prepare a guest or waive the first-start
identity checks. A one-role Factory uses the same path as a role in a larger
Factory.

## Select and adopt configuration

On the owning host, select the existing instance with --root. This example
uses an already prepared worker named catalogue. The host operator, or an
agent with existing host configuration authority, can save a complete JSON
configuration:

~~~sh
safeyolo --root /srv/safeyolo agent lifecycle catalogue configure lifecycle.json
safeyolo --root /srv/safeyolo agent lifecycle catalogue status
~~~

The command saves agents.catalogue.lifecycle in the existing policy. A
constrained commissioning agent can instead use the existing full-policy
assessment and exact adoption path. The human review explains lifecycle
effects with the other worker settings. Neither proposal authorship nor Coord
membership grants permission to adopt the change.

For scheduled operation, a configuration can contain:

~~~json
{
  "mode": "scheduled",
  "schedule": "0 0 2 * * *",
  "timezone": "Europe/Budapest",
  "window_seconds": 14400,
  "completion_room": "catalogue",
  "completion_check": "catalogue-complete",
  "completion_require": {
    "op": "finding",
    "check": "catalogue-complete"
  },
  "completion_excluded_work_ids": []
}
~~~

These task, time and recurrence values are example configuration. They are not
product defaults. The named check must already be an adopted executable job
or service check with a value subject. Its selected predicate must use only
that check. The host supplies a JSON scope as the subject value. The existing
check input, output, timeout, freshness and execution limits still apply.

| Setting | Behavior |
| --- | --- |
| mode = on_demand | Explicit agent start activates the retained worker. |
| mode = continuous | Explicit start has no implicit completion stop or deadline. |
| mode = scheduled | Native NATS delivers the selected schedule to the host. |
| schedule, timezone | NATS owns calendar validation and timezone behavior. Calendar expressions require an explicit timezone. For native elapsed @every or timestamp @at schedules, omit the calendar timezone. |
| window_seconds | A positive elapsed operating window from the broker occurrence. Delayed delivery cannot start after that window expires. This is elapsed time, not a separate local-clock end schedule. |
| stop_after_seconds | A positive elapsed limit from activation. |
| stop_by | An explicit RFC 3339 stop-by timestamp. |
| completion_room, completion_check, completion_require | Select checked voluntary stop. Omit all three when that behavior is not selected. |
| completion_excluded_work_ids | Explicit future Work outside this activation's completion scope, including future Work in the same room. |
| paused | Disable future scheduled starts. Omitted means false. |

When several stop boundaries are selected, the earliest applies. An expired
window does not start a sandbox. A configuration with no selected boundary
acquires none. Changing saved settings does not extend the cutoff already
captured by an active run.

Status separates saved configuration, broker adoption, the current activation,
accepted requests and host-observed stop results. The next_occurrence field
comes from the broker's Nats-Schedule-Next header. Before its first delivery,
or when the last advertised occurrence is past or belongs to another revision,
the next occurrence is unknown. It is not calculated by another calendar
implementation. Native NATS can skip a local time during a forward
daylight-saving change and produce two distinct occurrences during a backward
change. Choose the schedule with those semantics in mind.

When native NATS reports no further occurrence, reconciliation does not re-arm
that configuration after stop or proxy restart. For a one-shot @at schedule,
select a new timestamp through configuration to schedule another occurrence.
An explicit agent start remains a manual activation of the same worker.

## Perform work and request checked early stop

The worker creates authorized self-assigned native Work and receives ordinary
actionable attention. It claims, publishes retained outputs and explicitly
completes execution. Independent acceptance remains separate. A model exit or
empty attention page establishes none of those outcomes.

The host checks this worker's assigned and claimed Work in the selected room,
plus its assigned checks, challenge responses and required native decisions.
Unfinished execution, a pending acceptance or challenge decision, or selected
acceptance that is not accepted refuses early stop. Receiving an action does
not settle it. Follow-up Work in the same scope participates in that check.
The operator's explicit future-work
exclusions and Work in other rooms do not. The adopted job or service must
also return the selected, fresh result for the exact scope.

Each activation binds the unfinished Work references and its existing native
attention position. Work received during that activation joins the scope.
Already completed earlier work does not become another occurrence's output.
These are references to canonical Work, not a second task queue or an ordering
rule.

To request shutdown, the worker creates and claims a self-assigned ordinary
Work item whose immutable external_ref is safeyolo:lifecycle/self-stop. It
then calls request_self_stop with a chosen operation_id and that item's
shutdown_work_id. The host infers the worker and run from transport. It
excludes only this identified shutdown action. An existing ordinary assignment
cannot be renamed into the exclusion.

The accepted request is retained before the guest disappears. Read the original
ID with read_self_stop_request after a lost reply or a subsequent activation.
Read read_lifecycle for current observations. These tools are also available
through the installed safeyolo-coord call interface. An accepted request is
not proof of stop. The shutdown Work remains unfinished until its holder
reconciles the observed outcome and explicitly completes it.

The host checks the same scope again before closing it. An arrival before that
transaction invalidates the earlier check. After closure, new claims wait for
the next activation. Their native deliveries remain visible to the supervisor
checkpoint. The host never creates a second task queue or completes unfinished
Work as a side effect of stopping.

## Stop, pause and resume

On the selected host and instance:

~~~sh
safeyolo --root /srv/safeyolo agent stop catalogue
safeyolo --root /srv/safeyolo agent lifecycle catalogue pause
safeyolo --root /srv/safeyolo agent lifecycle catalogue resume
safeyolo --root /srv/safeyolo agent start catalogue
~~~

Stop ends the current run and retains its schedule. Pause disables future
scheduled starts; it does not stop an already active run. Resume enables the
configured schedule; it does not itself start a run. An explicit start is a
manual activation of the same identity and selected boundaries. It does not
change the recurring schedule. This explicit one-off activation is bound to
its captured run and window. An older scheduled event cannot replace it.

A configured mandatory cutoff starts the existing bounded command and backend
termination sequence before the boundary. A voluntary check cannot veto it.
Duplicate occurrences do not create another run. An old cutoff cannot stop a
replacement run. After a verified stop, host receipts record resource release
while identity, home, workspace, Work and checkpoints remain.

Status distinguishes verified running state, intentional dormancy, pause,
unexpected stop and unavailable observations. Factory doctor accepts an
intentionally dormant role with intact staging and access without describing
that role as running. Other roles can continue.

If the proxy or broker is unavailable, automatic execution is unavailable.
The product does not claim an unconditional real-time guarantee during platform
failure. An interrupted effect retains its original receipt. Inspect the
actual worker before another effect. On activation, the existing supervisor
recovers retained Work and uncertain task effects; no arbitrary process-memory
continuation is implied.

## Verify an installed worker

Use an owned test instance with a matching host and guest package, a prepared
worker, an adopted value-subject completion check and the selected Factory
checkpoint. Keep the production instance separate. On that test host, use
the lifecycle commands above and the worker's authenticated Coord tools.

| Observation | Procedure and expected result |
| --- | --- |
| Native activation | Select a near-term native schedule and named calendar timezone. Check broker adoption, the delivered occurrence, its advertised next occurrence and the new exact run ID. Change supported schedule parameters through configuration and repeat. |
| Retained self-tasking | Create self-assigned Work, receive its action and claim it. Interrupt a model turn and restart the same sandbox. The existing Work ID, producer claim, persistent files and supervisor checkpoint must remain. Publish the actual output and complete execution separately. |
| Checked stop | Request stop while scoped Work or selected acceptance is unfinished; expect refusal. Finish that scope and request again with a new operation ID. The adopted check must pass before the exact run stops. Read the original result after restart. |
| Cutoff and resources | Keep one task incomplete. Select a finite boundary and observe ordinary termination, force when needed, backend process exit and host CPU/RAM release. The task must remain unfinished and resume on the next activation. |
| Arrival and replay | Submit follow-up Work during the completion check; expect refusal or retention for the next activation. Duplicate or stale schedule/cutoff delivery must produce no replacement run, repeated uncertain effect or stop of another run. |
| Independent role patterns | Keep one existing role running while another is deliberately stopped or paused. Factory doctor must report the dormant role truthfully while retaining the running role and staging. Resume the same dormant identity. |

After the test, pause its schedules, stop only its owned workers and verify
backend absence. Stop the test proxy and broker through their existing owners.
Retain Work, checkpoints, configuration and compact observations for recovery.
An API fixture or a broker-only test does not establish these sandbox effects.
