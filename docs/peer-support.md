# Delegate peer support

An operator can grant a support agent authority to inspect and repair selected
agents in the same instance or in an explicitly selected remote instance. The support agent uses the authenticated
Agent application programming interface (API) or the existing Model Context
Protocol (MCP) tools. Neither agent
needs a shared Coord room. The target model, terminal and Coord loop can be
unresponsive. Local calls do not depend on Coord or NATS notifications.

The owning API, policy and required runtime controls must still work. Remote
calls also require Core NATS connectivity. [Configure authenticated TLS NATS](coord-reference.md#collaborate-through-a-home-safeyolo)
between the separately initialized instances. Guests continue to use their own
local API; broker credentials and the remote Admin token remain on the hosts.

## Choose the authority

Each grant binds the owning instance, one durable support identity and explicit
durable targets. Recreating an agent with the same name does not transfer a
grant. Ordinary restarts preserve the durable identity.

| Permission | Effect |
|---|---|
| Inspection, always included | Read selected host-observed runtime, control, harness, terminal and proxy attachment facts. Read launch/run identities and exit status. No caller command, host secret or unrelated worker record is returned. |
| `guest_logs` | Read the exact selected paths through guest execution. Guest links can expose any target-accessible data. Output is untrusted. |
| `guest_admin` | Execute arbitrary commands inside the target guest, including its existing passwordless guest sudo. Investigate and repair files through those commands. |
| `lifecycle` | Use selected actions on the saved worker configuration: `start_sandbox`, `start_harness`, `restart_harness`, `stop_sandbox`, or `restart_sandbox`. No new host script, mount, credential or host command is accepted. |
| `factory_directions` | Read role identities and observed state for the selected approved factory. Send only its explicitly selected direction types. This grants no room history, native work or approval-decision privileges. |

Guest administration includes the target's writable mounts, shared data,
credentials, network and service permissions, Agent API access and existing
delegations. If the target can administer another agent or decide approvals,
the support agent can exercise those powers through the target. A standing
grant follows capabilities subsequently given to the target. Controlling an
approval reviewer removes independence from that reviewer. The preview names
known approval and support delegations; it does not calculate recursive reach
or prohibit these combinations.

Guest administration can read and change secrets present in the target. It
can also use the target's authorized service-gateway permissions. The outer
SafeYolo vault remains protected when it is on the owning host outside the
guest. A support grant adds no vault-management or Admin API operation.

If a nested SafeYolo stores its vault inside the administered guest, that
vault is within guest filesystem authority. Accessible local-key vault files
and their key permit plaintext recovery. Locked passphrase ciphertext alone
does not permit plaintext recovery. Writable vault files can still be changed
or deleted.

An operator can deliberately expose host files through a mount or copy secrets
into the guest. Those exposed files are then accessible within the target's
guest authority. Host-side service-gateway injection keeps the underlying
credential outside the guest; the guest can use the authorized service routes.
When an authorized request needs provider-credential renewal, the existing
host-side refresh owner performs that renewal under its normal checks. Renewal
adds no support approval or vault-management permission. Access to the Admin API
still requires independent Admin authentication; guest administration does not
grant it.

A temporary grant has an `expires_at` timestamp. A standing grant has
`expires_at: null` and remains until changed or revoked. Both lifetimes permit
routine in-scope operations without another prompt. Inspection-only grants
have `guest_admin: false`, `guest_logs: []`, `lifecycle: []` and no
`factory_directions` selection.

## Preview and grant

On the operator host, use the installed CLI for the selected instance. Set
`ROOT` to that instance directory. Obtain the support and target IDs from
`status`, and the owning instance ID from `support grants`:

```sh
safeyolo --root "$ROOT" status
safeyolo --root "$ROOT" support grants --json
```

Save a proposal as `support.json` in an operator-owned directory. Replace the
example instance and agent identities with the values just inspected. This
example grants standing inspection of `worker` to `support`:

```json
{
  "expected_revision": null,
  "grant": {
    "instance_id": "sy-11111111111111111111111111111111",
    "support": {"name": "support", "agent_id": "ag-22222222222222222222222222222222"},
    "targets": [{"name": "worker", "agent_id": "ag-33333333333333333333333333333333"}],
    "guest_admin": false,
    "guest_logs": [],
    "lifecycle": [],
    "notifications": [],
    "signal_rooms": [],
    "expires_at": null,
    "acknowledgment": null
  }
}
```

For temporary authority, set `expires_at` to the selected future RFC 3339 time,
including its UTC offset. For repairs, select `guest_admin: true` and the
required lifecycle actions before previewing. Read the effective permissions
and composition warnings. The following commands need `jq`. They acknowledge
that exact preview and apply the grant named `incident`:

```sh
safeyolo --root "$ROOT" support preview incident --file support.json --json > preview.json
jq --slurpfile preview preview.json '.grant = $preview[0].after | .grant.acknowledgment = $preview[0].acknowledgment' support.json > acknowledged.json
safeyolo --root "$ROOT" support apply incident --file acknowledged.json --json
```

For a remote support identity on A, add `support_instance_id` with A's durable
instance ID before previewing on B. Keep `support.agent_id` as A's actual durable
agent ID. Choose a B-side display handle distinct from local agent names. The
preview adds `support_peer_epoch` from B's current trust in A. Apply the returned
`after` grant and acknowledgment together. Applying the grant registers the
qualified manager through B's existing principal mapping; no dummy room or
membership is needed. Later room or display-name changes do not rebind that
manager. Re-trusting a revoked peer does not revive the old target grant.

A changed grant or durable identity refuses the proposal. Inspect the current
state and preview the revised proposal. A support agent cannot edit its own
grant through the Agent API.

For selected operational notices, set `notifications` in this same proposal
before preview and apply. For example, select `launch_failed`,
`sandbox_availability`, `control_availability`, `sandbox_recovered`,
`command_exit`, `command_restart`, `command_failed`, `supervisor_exit` and
`supervisor_restart`. The recipient is `support`; the subjects are `targets`.
The grant's temporary or standing lifetime applies to observation and notices.
Repair choices remain independent. For `needs_operator`, also select named
`signal_rooms` to disclose only the subjects' material signals from those
rooms. Read the [event meanings, source rights and loss behavior](operational-events.md)
before selecting notices. Removing a kind stops new notices; an already
retained reference still requires current observation and source disclosure.

## Investigate and repair

Factory direction is a separate explicit selection within a support grant.
See [delegated factory direction](factories.md#delegate-direction-to-an-operator-agent)
for its snapshot binding, preview and typed actions. Ordinary support grants
contain no factory direction or approval-decision authority.

Inside the authorized support agent, call `support_grants()` to discover its
current authority. For a remote target, use `support_grants(home="primary")`
and the same `home` on `support_operation` and `read_support_operation`.
Use B's returned instance and target IDs. Select a new `operation_id` before
each deliberate operation.
Use `support_operation` with the selected grant and durable target ID. The
equivalent Agent API routes are:

| Request | Route |
|---|---|
| Discover current grants | `GET /support/grants` |
| Execute one operation | `POST /support/operations` |
| Read the original result without replay | `GET /support/operations/OPERATION_ID` |

For example, submit this body with the Agent API token through the configured
proxy at `http://_safeyolo.proxy.internal/support/operations`. Replace the grant
and target with the values from discovery. Inspection selects the durable
target even when no live run is available:

```json
{
  "operation_id": "incident-inspect-1",
  "grant": "incident",
  "target_id": "ag-33333333333333333333333333333333",
  "expected_run": null,
  "operation": {"action": "inspect"}
}
```

The result separates `runtime_state`, `control_state`, `exec`, `guest_exec_state`,
`agent_state`, `terminal_state` and `proxy_attachment`. On macOS, inspection
checks the existing SSH-banner diagnostic independently of VM/control liveness.
Lifecycle responses can show `guest_exec_state: "not_probed"`; inspect again
to obtain that diagnostic after a change. A missing proxy attachment alone does
not justify starting a worker. An unavailable guest execution path does not
prove that its sandbox stopped. Preserve degraded runtime evidence.

For subsequent commands or lifecycle operations, set `expected_run` to the
`run_id` from inspection. A start of a target that has never run uses null.
Each request also accepts the exact `instance_id`; omission selects the local
owning instance. For remote calls, the configured `home` selects the owner;
include its returned `instance_id` to make that selection explicit. B also
checks the transport request's expected destination before any effect. A
misrouted request cannot act on another trusted instance. The operation contains
one of these forms:

```json
{"action": "guest_command", "command": "df -h; ps -ef", "timeout_seconds": 30}
```

```json
{"action": "guest_log", "path": "/home/agent/application.log"}
```

```json
{"action": "lifecycle", "operation": "restart_harness"}
```

Guest execution is independent of the coding harness. Harness restart preserves
the sandbox generation and verifies the recorded command's exit before starting
its replacement. Sandbox restart stops and starts the saved worker. Starting
only a sandbox does not launch its coding harness. Lifecycle controls refuse
unverified ownership and changed runs.

To verify a repair independently, use the owning host's ordinary `agent status`
and `agent shell` commands for the selected instance. Check the target's durable
agent ID, sandbox run, current launch and guest supervisor together. Confirm
the configured workload's process and useful output, such as its readiness
marker. A model report or a successful API response alone does not establish
recovery.

A harness restart creates a new launch ID inside the same sandbox run. The
saved command begins with `export SAFEYOLO_GUEST_LAUNCH_ID=LAUNCH_ID; `, followed
by the configured command. Check each saved wrapper against its own recorded
launch ID before comparing the remaining command. The full wrapper strings
must change when the launch ID changes. Also verify the workload's configuration
and script when the repair depends on them.

A lifecycle owner can publish a launch before the guest observes it. If the
returned observation does not verify the requested running or stopped state,
the receipt reports `outcome_unknown` and `completion_verified: false`. Inspect
the resulting run and launch until their actual state is known. Do not repeat
the mutation to obtain a newer observation. The original receipt retains the
result observed when that operation finished.

When guest execution is unavailable, a guest administrator can select
`{"action":"guest_probe","timeout_seconds":15}`. This uses the existing
shared-home/PID-1 health probe without SSH. It requires a verified live target
and idle command supervision. It does not replace an active command or grant
privileged host access. Its process and SSH-banner observations are guest
evidence; a successful probe is not a completed repair.
After a successful probe, SafeYolo restores the previous terminal harness
observation without rerunning its command. The run, launch and current support
authority must still match. Repair the diagnosed guest fault, then deliberately
select an authorized `start_harness` or `restart_harness` action. Verify the
configured harness identity and process independently. A timed-out probe keeps
its uncertain state; it does not establish that the harness can safely restart.

Each output stream retains at most 8192 bytes and reports truncation. Invalid
UTF-8 bytes are replaced in the returned text. `transport_exit_code` and
`transport_signal` describe the host transport. `exit_code` is the status
reported through that transport. A failure can originate before the guest
command begins; use output and a separate state check to diagnose it. SSH
status 255 is ambiguous, so macOS reports `transport_error` and no command
exit code for that status. A signalled transport reports `transport_cancelled`.
A timeout or transport failure does not establish command completion or termination of
guest descendants. Narrow the next diagnostic command if its output was
truncated. Treat every guest result as untrusted evidence.

Remote request envelopes share the managed NATS broker's 8 MiB payload limit.
Oversized requests are refused before a remote operation is attempted.

## Recover an uncertain result

After a lost reply, use `read_support_operation(operation_id="incident-inspect-1")`
or the GET route for the original ID. An identical POST returns its original
receipt. Reusing an ID with different inputs is refused. No duplicate command
or lifecycle action is silently replayed. A proxy restart can leave
`outcome_unknown`; inspect the target before deliberately choosing a new ID.
The original initiating support run and target run remain in the receipt.
Remote receipts also retain the authenticated source instance and B-qualified
principal. A support-agent restart can read an earlier result under its standing
grant without rebinding the original execution to its new run.

The process owns an admitted operation even if its HTTP caller disconnects.
Disconnecting that caller is not command cancellation. The operation can keep
running. If a command times out, SafeYolo stops its host transport; that does
not prove that guest descendants stopped. No automatic rollback is performed.

Private receipts under the owning instance's `data/support-operations` retain
bounded guest output. Current support authority is required for subsequent
result reads. A local operation's pending response can still deliver output
after narrowing, expiry or revocation. Remote pending responses recheck B's
current disclosure authority before returning a saved result; A also rechecks
the source run and selected route. Already-started commands can still finish,
including during a partition or source restart. Routine audit events bind the
initiator, owning instance, target/run,
grant/revision, operation and result. They exclude command text and guest
output.

Before saving a support-grant change, the owner persists a stable audit event
ID and a retry obligation under `data/support-grant-audit`. A saved operation
outcome carries its final audit obligation in the same private receipt as its
execution result. The existing delivery owner retries these records through
the configured canonical JSON Lines (JSONL) writer, including after a proxy
restart or a local NATS outage. Delivery is confirmed after the audit file and
its required directories are synced. Successful delivery removes the staged
envelope; private receipts retain execution results and delivery metadata.

If delivery fails, `audit_status` reports the pending record and `audit_event_id`
identifies it. An identical operation-ID retry can reconcile missing final audit
without executing the operation again. A receipt can be `queued`, `running`,
`refused`, `completed` or `outcome_unknown`; `execution_started` separately
records admission to execution. Recovery keeps an unverified interrupted
operation `outcome_unknown`, with `completion_verified: false`. If a grant
transaction terminates before its saved outcome is recorded, its audit record
also reports `outcome_unknown`. Inspect the current saved authority before
another policy change. An interruption after audit append but before delivery
acknowledgment can repeat an event with the same ID; this is one logical event.

The destination records well-formed federation refusals with its phase, reason,
qualified peer identity and separately labeled untrusted claims. A refusal
after dispatch can withhold a response after an effect; it does not roll back
that effect. Refusal records use the existing writer's bounded admission,
without a persistent retry obligation for each input. If the destination cannot
confirm its refusal record, its response includes an `audit_status` warning.
Malformed inputs do not create audit retry work.

Do not copy raw credentials or host secrets into Coord or a support
report. Report observed facts, diagnosis, changes, observed recovery and
unresolved uncertainty separately.

For selected events from several instances, use ordinary `wait_for_coord`
with each source's durable instance ID and cursor. The [multi-source example](coord-reference.md#collaborate-through-a-home-safeyolo)
explains availability, reconnection and position advancement. The owner retains
canonical evidence; attention delivers selected references. Notification or
JetStream failure does not itself prevent a permitted support operation over
healthy Core NATS. A full Core outage reports remote control unavailable.
Use local owner-side controls to recover NATS where those controls work.
Unreachable does not mean that the target died.

## Narrow or revoke

On the operator host, run `support grants --json` again. For narrowing, use the
current grant's `revision` as `expected_revision`, reduce its selected
permissions or lifetime, clear `acknowledgment`, then repeat preview and apply.
For revocation, save only the current revision in `revoke.json`:

```json
{"expected_revision": "REPLACE_WITH_CURRENT_REVISION"}
```

```sh
safeyolo --root "$ROOT" support revoke incident --file revoke.json --json
```

Authority is checked at execution, including after setup, launch and guest-control
waits. The current authorized target must still match the captured name and
durable ID. Command and probe checks also retain their verified runtime binding.
Narrowing, revocation or expiry prevents newly unauthorized operations and
reads. Already-started commands can continue; earlier file changes, repairs
and disclosure remain. Inspect the actual target before deciding what to do
next. A permission needed for a new action requires the operator to change
the grant; a denied action does not create or widen one.
