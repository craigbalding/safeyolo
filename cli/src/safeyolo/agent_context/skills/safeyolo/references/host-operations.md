# Commission and use a host task

Use an existing binding when one is suitable. For a new Unix target, prepare
first trust through the existing vault and human policy-change owners.
Installation, operation discovery and proposals grant no authority.
Use the ordinary Agent API and its existing bearer, not a target signing key.

For a service plan, the selected listener entries become the fixed
`endpoint-inspect` operation's ordered probe choices. If the application consumes
an inherited socket, select `network.listener_handoff` with the exact alternatives;
that same selector supplies inspection, and the native adapter passes descriptor 3
at launch. Ordinary programs can retain their adopted broader TCP mode without
socket inheritance. Byte staging uses a disconnected operation and reserves no
service listener. No task code can replace the fixed inspection helper.

Resolve this skill's `scripts/host-operation.py` path and set `HOST_CLIENT` to
that path. The helper requires Python 3 inside the agent sandbox. It adds no
target-side Python dependency or daemon. Keep successful and failed JSON results
with their original request IDs in the existing task evidence.

## Prepare a new target

Recover the selected host, actual account/access route, intent and material limits.
For a service, recover its function, audience, data/functions, authentication and
lifetime. Use the existing scoped endpoint-inspection operations to resolve
permitted addresses and candidate ports. Compare the concrete proposed exposure
with intent through private deterministic assessment. Ask only about missing
material choices. Do not change the audience, kill a port occupant or require
broad process/socket inventory to work around a collision.

`GET /gateway/host-setup` exposes the current plan and enrolment schemas without
an effect. Prepare `plan.json` from that schema; the agent writes it. Select the
target hostname/control listener, task root, readable paths, native network and
resource bounds, executable/dependency byte ceilings, finite duration/call budget and the explicit `allow_agent_code`
and `allow_run_refresh` choices. The intent fields are the agent's interpretation;
they do not confer authority. The human reviews derived concrete authority.
No account, application catalogue or loopback-only policy is imposed by setup.
The target receipt includes its native network-enforcement report and observation
time. Normal approval review shows this recorded report, the concrete grant and
its code class separately from the agent's intent. In particular, explicit
broader TCP modes do not gain address/port isolation from a selected endpoint.
Current discovery and job observations still establish the reached runtime state.

Inside the authorised issuing agent, with that complete plan, run:

```sh
python3 "$HOST_CLIENT" setup --plan plan.json > preparation.json
```

The result retains one original operation, a public enrolment request and the
small target bootstrap action. The signing key stays in the issuer vault.
If credential storage is unavailable, resume through its existing owner; do not
copy signing secrets into the sandbox or choose another store automatically.

The selected target's existing trusted install/transfer owner acquires the
matching prebuilt executor and carries the public request to its `enrol`
command. The command creates private control/TLS state, derives the actual
account and executable pins, qualifies native bounds and can serve the protocol.
Linux also needs bubblewrap and a delegated cgroup v2 memory/pids scope.
Run bootstrap inside that delegated hierarchy. It creates its own task cgroup
and enables the two controllers there; it preserves the parent and peer groups.
Unsupported guarantees remain refused. This bootstrap executes no task program.
Its returned `enrolment.json` comes back through the same trusted transfer route;
the human does not assemble keys, identity documents, scopes or bindings.
Automatic `enrol` is implemented for Linux and macOS. Windows retains the
explicit native preparation/installation path in the operator guide.
On macOS the prepared task interpreter is pinned directly to `/bin/bash`.
For a task with more than one process, its plan must explicitly select broader
`processes` authority alongside `memory` and `executor_restart`. Selected
read/write paths also bound child executables. Fork/exec and `posix_spawn`
children inherit Seatbelt but can change groups or sessions. Only the original
group is counted, memory-polled and stopped on cancellation or deadline.
Escaped children can outlive both, even without a controller crash. Every
multi-process result remains `Uncertain` with `processes_stopped=false` and a
retained concurrency reservation and executable snapshot, including after
restart. Group quiescence and output end-of-file cannot prove tree cleanup.
Output capture ends with the original group; an open writer is reported as
truncated. Complete tree cancellation and automatic reservation release are
unsupported. Use an enforced-tree backend when required. Restart never signals
recovered PIDs or groups. Preserve that uncertainty during recovery.
The built-in inspection and byte-staging recipes use one interpreter process.
Adopted task code still uses the full standing task-code class selected by the
operator; fixed preparation does not narrow that class. Check output and the
enrolment's `task:*` boundary facts expose that full class before approval.

Inside the issuing agent, after the trusted owner returns that original file, run:

```sh
python3 "$HOST_CLIENT" submit-setup --enrolment enrolment.json > submitted.json
```

The existing policy-change request presents the exact candidate for human review
in `safeyolo watch` or the explicit approvals interface. Read its canonical
status and current effective access. A notification or saved target receipt is
not permission or current readiness. The setup result identifies the binding.
After adoption, use `resume BINDING` and authenticated discovery. Resume can
activate only the exact task document selected in that binding; it accepts no
caller replacement policy. A conflicting active task must be resolved explicitly.

After a lost setup reply, use `setup-status --original-request-id ORIGINAL_ID`
and the original policy-change request before another effect. On the target,
inspect the original private directory and `enrolment.json`. Reusing the same
bootstrap request recovers its protected preparation; changed content conflicts.
A prepared receipt does not establish that the listener is currently serving.

## Discover, adapt and execute

```sh
python3 "$HOST_CLIENT" bindings
python3 "$HOST_CLIENT" discover case --request-id case-discovery-1
```

Replace `case` with the returned binding. The listing identifies the target,
trusted principal and service; it contains only bindings available to this
current eligible run, including resumable bindings whose task is inactive.
Read `task_active` and `resume_available` before use. An empty successful list does not prove that a target has no
other operations or grants. Discovery returns current package/authority
revisions, supported features, definitions, bounds and scope indicators.
Unavailable binding, expired authority, unsupported guarantee and denied
invocation are different from an empty result.

For an explicitly adopted agent-code class, author a task script and use
`adopt BINDING --operation task:NAME --script SCRIPT`. The helper carries the
ceiling and current package/revision pins; a typed `--definition` supports other
approved recipes. `--dependencies` supplies exact target path/hash/byte pins.
This permission is separate from trusted-publisher maintenance. The target
qualifies code and dependencies under its actual native boundary before adoption.
Preparation does not execute that code. Changes outside the class need private
assessment and the existing material authority decision, not an in-scope hash approval.

Use `stage BINDING --file SOURCE --path ABSOLUTE_TARGET_PATH` to carry selected
bytes through the same code-adoption/propose/invoke path. Inspect the returned
job and file before treating the write as complete. If the target changes or
another call replaces the staging operation, the helper stops before proposing
that replacement.
Inspect the returned original adoption before preparing another stage.
The selected root and
current native scope still apply; control files, TLS/signing keys and adoption
authority remain outside workload permissions. Staging adds no target decoder,
Python runtime or transfer daemon. Large inputs must fit the existing request,
program-argument and resource limits; this helper does not stream them.

If a code-adoption reply is lost, read `adoption BINDING
--original-request-id ORIGINAL_ID`. The target retains the signed original
request. Its protected catalogue recovers a commit interrupted before ledger
publication. The issuer reconciles the same exact package through its existing
catalogue transaction. Another current base needs owner reconciliation; do not
resubmit or invoke from an uncertain mixed target/issuer state.

Select a listed literal operation and resource. Typed arguments go in a JSON
object, passed with `--arguments FILE`; omitted arguments use the operation's
declared defaults only when the actual grant permits those defaults.

```sh
python3 "$HOST_CLIENT" propose case --request-id metadata-proposal-1 --operation bundle-metadata --resource evidence:bundle-metadata > prepared.json
```

Read the normalized invocation, intersected budgets, expiry and assessment digest.
The helper derives exact operation/revision pins from discovery. A proposal does
not reserve budget or execute code. Within the task's existing authority, invoke
the unchanged preparation without another routine confirmation.

```sh
python3 "$HOST_CLIENT" invoke case --request-id metadata-invoke-1 --prepared prepared.json
```

Retain `receipt.job_id` and the original invocation request ID. Use the same
binding and substitute the returned job ID below. `output` reports bounded
base64 bytes, offsets, end indicator and retained digest. Preserve operation
completeness and native truncation separately; a successful read is not a
successful job or proof of a forensic conclusion.

```sh
python3 "$HOST_CLIENT" job case --request-id metadata-status-1 --job JOB_ID
python3 "$HOST_CLIENT" output case --request-id metadata-output-1 --job JOB_ID --offset 0 --bytes 65536
```

For an authorised Unix job that wrote files, `prepared.file_roots` gives the
selected host paths. The issuer grant and target must explicitly permit `file`;
`output` alone grants no file access. Select a regular file within both the
admitted and current writable scope. Replace `/selected/result` with its actual
target path and `JOB_ID` with the retained job ID:

```sh
python3 "$HOST_CLIENT" file case --request-id file-read-1 --job JOB_ID --path /selected/result --offset 0 --bytes 4096
```

The response contains base64 bytes, the observed total length, a chunk SHA256,
observation time and `file_revision`. For later chunks, pass that revision with
`--file-revision REVISION` and advance the offset by the decoded chunk length.
Replacement or observed modification returns a stale result. A file read is a
live observation, not an atomic snapshot or proof that this job produced every
byte. Select writable roots and file paths without symlink components. Retrieval
refuses symlinks at every component and refuses special files. Ordinary file or
directory replacement through those paths remains supported. Missing or
unreadable files remain unavailable, including after host storage failure.
Windows file retrieval is not implemented. Job/stream inspection still works.

Files remain at their selected host paths after completion, failure, cancellation
and executor restart. This route does not copy files into a retained artifact
store, extend their lifetime, undo writes, or impose a file-storage quota.
The target operator controls host-file retention and removal. Current file and
operation/resource authority must still permit retrieval; revocation/expiry
can remove agent access without deleting the files. Stream truncation and job
failure do not imply that partial files are absent. Read their observed length
and bytes separately from the job's termination and stream result.

For cancellation, read the current job revision, then use `cancel BINDING
--request-id ID --job JOB_ID --revision REVISION`. Inspect the next receipt;
requesting cancellation is not observed termination.

If the helper reports an uncertain invocation or cancellation, its error JSON retains
`possible_job_id`, the original request ID and selected target context. Inspect that possible job
with `job --job POSSIBLE_JOB_ID` before any retry. A possible ID does not prove
admission or execution. If the binding changed, ask the original target operator
to inspect its ledger. Changed content with an old mutation ID conflicts; a new ID can
repeat a real effect. If grant revocation removes read access, the target
operator must inspect retained state. Neither revocation nor expiry undoes an
admitted effect. The helper never automatically retries a failed call.

For missing capability, prepare an untrusted operation/scope proposal and use
the existing [policy-capability discovery and private assessment sequence](../../policy-authoring/references/capabilities.md). Reuse the
adopted effects, narrower alternatives and explicit unresolved dependencies.
An absent operation cannot execute just because a proposal names it. Target
ceiling, package adoption, issuer policy and credential changes belong to their
existing owners. Do not install executable bytes or create a route through a
discovery/proposal request.

A required check's unavailable/negative result follows the selected policy
fallback. Inspect the private challenge/finding, revise or abandon, or explicitly
escalate through its existing eligible approval route. An approval notification
grants no permission and does not retry the request. Read current approval and
effective access before any authorized next action. Model evidence is optional
by adopted policy, supplementary and fallible; explain selected provider/data
scope when it matters to a decision.

For stale revisions, rediscover the same target and prepare anew. For unsupported
version/enforcement, report the exact mismatch to its owner. Keep desired,
observed and active catalogue status distinct. Routine permitted execution and
authorized catalogue updates remain quiet. Use the packaged platform index and
operator guide for actual installation, account exposure and source/dependency
limits; target metadata alone cannot prove containment.

Native task registration and the separately activated document survive issuer
restart. If the grant explicitly selects run refresh, a later host-observed run
of the same durable agent and task can use the binding and retained jobs.
Refresh does not reset expiry, revocation or ledger budgets. Another agent with
the same name cannot inherit access. Without this standing choice, exact-run
binding remains required. Task notes retain intent and result locations; they
grant no authority. Clearing a task deactivates it; revoking the grant removes
the standing ability to resume it. Neither action reverses prior effects.
