# Delegate local peer support

An operator can grant a support agent authority to inspect and repair selected
agents in the same SafeYolo instance. The support agent uses the authenticated
Agent application programming interface (API) or the existing Model Context
Protocol (MCP) tools. Neither agent
needs a shared Coord room. The target model, terminal and Coord loop can be
unresponsive. Local calls do not depend on Coord or NATS notifications.

The owning API, policy and required runtime controls must still work. This
interface does not implement support across instances. Remote support will
require its inter-instance transport.

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

Guest administration includes the target's writable mounts, shared data,
credentials, network and service permissions, Agent API access and existing
delegations. If the target can administer another agent or decide approvals,
the support agent can exercise those powers through the target. A standing
grant follows capabilities subsequently given to the target. Controlling an
approval reviewer removes independence from that reviewer. The preview names
known approval and support delegations; it does not calculate recursive reach
or prohibit these combinations.

A temporary grant has an `expires_at` timestamp. A standing grant has
`expires_at: null` and remains until changed or revoked. Both lifetimes permit
routine in-scope operations without another prompt. Inspection-only grants
have `guest_admin: false`, `guest_logs: []` and `lifecycle: []`.

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
jq --slurpfile preview preview.json '.grant.acknowledgment = $preview[0].acknowledgment' support.json > acknowledged.json
safeyolo --root "$ROOT" support apply incident --file acknowledged.json --json
```

A changed grant or durable identity refuses the proposal. Inspect the current
state and preview the revised proposal. A support agent cannot edit its own
grant through the Agent API.

## Investigate and repair

Inside the authorized support agent, call `support_grants()` to discover its
current local authority. Select a new `operation_id` before each operation.
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
owning instance. The operation contains one of these forms:

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

## Recover an uncertain result

After a lost reply, use `read_support_operation(operation_id="incident-inspect-1")`
or the GET route for the original ID. An identical POST returns its original
receipt. Reusing an ID with different inputs is refused. No duplicate command
or lifecycle action is silently replayed. A proxy restart can leave
`outcome_unknown`; inspect the target before deliberately choosing a new ID.
The original initiating support run and target run remain in the receipt.

The process owns an admitted operation even if its HTTP caller disconnects.
Disconnecting that caller is not command cancellation. The operation can keep
running. If a command times out, SafeYolo stops its host transport; that does
not prove that guest descendants stopped. No automatic rollback is performed.

Private receipts under the owning instance's `data/support-operations` retain
bounded guest output. Current support authority is required for subsequent
result reads. An admitted operation's pending response can still deliver output
after narrowing, expiry or revocation. Routine audit events bind the initiator, owning instance, target/run,
grant/revision, operation and result. They exclude command text and guest
output. Do not copy raw credentials or host secrets into Coord or a support
report. Report observed facts, diagnosis, changes, observed recovery and
unresolved uncertainty separately.

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

Authority is checked at execution, including after a lifecycle-lock wait.
Narrowing, revocation or expiry prevents newly unauthorized operations and
reads. Already-started commands can continue; earlier file changes, repairs
and disclosure remain. Inspect the actual target before deciding what to do
next. A permission needed for a new action requires the operator to change
the grant; a denied action does not create or widen one.
