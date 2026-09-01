# Coord kernel capabilities

This document is the design source of truth for the coordination-kernel
capabilities that follow the initial NATS room/chat substrate. Treat the work
as a sequence of independently useful stages, with acceptance tests proving
semantics rather than UI.

The current implementation is a good base precisely because it is still small: SQLite owns room/membership control state; JetStream owns messages; the agent surface is essentially `join_room`, `send`, `read_room`, `wait_for_message`.   Issue #371 explicitly deferred addressing, operator summons, voting and summarisation until dogfood demonstrated what was actually needed. It has now done that.

Implement the capabilities in this order.

### 0. Coordination kernel foundations

Do this before adding features.

Add a real SQLite schema migration/version mechanism, stable object-ID
conventions, optimistic/version fields where appropriate, generic mutation
idempotency, immutable revision/transition history, and a `coord.*` audit-event
family. The kernel invariants are:

* SafeYolo owns identity, membership, brief, work ownership, claims, current coordination state and attestations.
* JetStream owns conversation history.
* External systems own rich work descriptions.
* Message addressing affects **attention, not visibility**.
* Coord work claims are not resource locks.
* Services remain authoritative for actual resource leases.
* Agent-authored content is attributed but untrusted; operator brief is trusted operator state.
* Each room ultimately has one authoritative SafeYolo for mutable state.
* Work claims are durable generation-protected ownership, not automatically
  expiring leases.
* Every agent has one identity-derived, multiplexed attention feed across its
  authorized rooms.
* Attention delivery is at-least-once and deduplicable; an attention edge
  points to canonical state and never becomes a second copy of it.
* Current-state tables support efficient projections; immutable
  revisions/transitions preserve canonical history.
* JSONL records operational metadata, object IDs, revisions, actors, and
  hashes. It does not duplicate chat bodies, briefs, long work descriptions,
  or signal prose.

Every new kernel mutation accepts an `operation_id` scoped by principal and
operation type. SafeYolo retains the operation ID, a canonical request hash,
and the result. Replaying the same operation ID with the same request returns
the original result; reusing it with different input returns a conflict.
`operation_id` handles ambiguous retries. Object revisions and claim
generations independently reject stale concurrent mutations.

Stage 0 deliberately uses the existing local `operator` sentinel as the scope
for operator mutations. It does not introduce or imply a real authenticated
operator-ID model. The first implementation boundary is:

| Mutation | Stage-0 `operation_id` contract |
|---|---|
| `grant` / `revoke` | Caller-visible, generation or explicit CLI retry handle |
| grant suboperations inside `room_create` | Internal generated IDs only |
| `room_create` | Unsupported at the caller boundary |
| `send` | Unsupported; JetStream recovery is designed with the cross-store stage |

Do not partially claim caller-visible idempotency across SQLite and
JetStream. `room_create` and `send` need explicit cross-store recovery
semantics before they can make that promise.

The migration foundation matters because the current store simply creates
three tables idempotently; once several durable object classes appear, ad-hoc
`CREATE TABLE IF NOT EXISTS` evolution becomes debt quickly. Migrations use
explicit SQLite transaction control and individual statements, never
`sqlite3.executescript()`. An unversioned database is classified as either
fresh/empty or the semantically compatible current-master legacy schema. A
partial or malformed legacy schema is rejected rather than stamped current.

Stage 0 also introduces a generic transactional outbox with stable event IDs.
Canonical state and its logical event commit together. JSONL is an
at-least-once projection: a crash after append but before delivery marking may
produce a duplicate with the same `event_id`. Each append is flushed and
`fsync()`ed, along with each newly created containing directory entry, before
the outbox records successful delivery; any file or directory `fsync()` failure
leaves the edge pending for retry. All `coord.*` JSONL events flow through this
outbox. A failure before migration 0→1 creates the outbox is
reported only through normal operational logging. Later migration failures
may use an already-existing older-version outbox through a recovery-only path,
even while normal candidate operations refuse the outdated schema.

Key acceptance tests:

* Upgrade a real current-master coord database containing rooms, grants and retained messages; everything remains usable.
* Fresh/unversioned classification accepts semantically compatible legacy DDL
  independent of incidental SQLite SQL text, but rejects partial tables,
  missing keys/uniqueness, and incompatible foreign keys without stamping it.
* Fresh bootstrap and repeated bootstrap produce the same schema/state.
* Two simultaneous bootstraps/migrations cannot corrupt or partially migrate the DB.
* Simulated failure halfway through a migration rolls back cleanly.
* Failure before the outbox exists produces operational logging but no direct
  `coord.*` JSONL write; a later failure is recoverably enqueued through the
  older valid outbox while ordinary API use remains schema-gated.
* New code refuses a database schema newer than it understands rather than silently operating on it.
* Existing chat dogfood tests remain green with no semantic change.
* `coord.*` events round-trip through the shared audit schema and `watch` without schema-drift warnings. The existing audit envelope is already designed as the shared contract for future PEPs/control-plane consumers.
* Retrying a mutation with the same `operation_id` and request returns the
  original result; changing the request under that ID returns a conflict.
* A minimal test-local typed object proves that a current-state projection and
  immutable revision append commit atomically, enforce expected revisions,
  roll back together and replay deterministic outcomes. Typed brief, work and
  signal schemas remain in their own stages; Stage 0 adds no generic object
  store.
* `room_create` gives each grant suboperation a distinct internal operation ID
  without exposing or claiming room-level caller idempotency.
* Audit events contain only the object identity, revision/transition,
  content hash where relevant, actor, and operational metadata; prohibited
  content is absent.

Make the foundation its own PR.

---

### 1. First-class targeted attention

Solve the amplification problem before adding more things for agents to discuss.

Extend message sending with an explicit attention target:

```text
notify = none | room | [agent...]
```

SafeYolo resolves names to durable `agent_id`s. The stored message remains ordinary retained room history available to every authorized member. `notify=[bob]` means only Bob gets interrupted; it does **not** make the message private.

Add one identity-derived `wait_for_attention()` feed per agent, multiplexing
all authorized rooms. A model must not maintain one wait loop per room. The
feed is capable eventually of returning:

```text
message
brief_changed
work_changed
blocker
decision_needed
...
```

An edge contains identifiers rather than canonical content:

```text
attention_id
room_id
kind
object_id
revision_or_sequence
```

One logical edge is created per intended recipient. Delivery is at-least-once
and recipients deduplicate by `attention_id`. The recipient reads the
authoritative message, brief, work item or signal after waking. Authorization
is checked before returning the edge and independently when the referenced
object is read.

Compatibility is deliberate:

* an old/raw Agent API `send()` that omits `notify` preserves the current
  room-wake behaviour;
* the updated MCP `send()` explicitly defaults to `notify=none`;
* operator chat explicitly sends `notify=room`.

Message attention has an explicit cross-store recovery contract. Before
publishing, SafeYolo resolves the intended recipients and generates one
stable `attention_id` for each exact `(msg_id, recipient agent_id, active
membership/grant generation)` tuple. `notify=room` selects every active
receive-capable agent membership except the sending agent; operator
membership never creates an agent-feed edge. An explicit target list may
include the sending agent. Targeting snapshots the exact active membership
generation so revoke followed by re-grant cannot resurrect attention created
for the revoked generation.

JetStream remains the canonical message store and the recovery source for the
message's generated attention intent. SafeYolo persists a versioned internal
attention manifest in NATS headers or equivalent internal JetStream metadata;
it is not part of the ordinary agent-visible message envelope. Agent
`read_room()` calls do not expose target metadata. Operator reads and accepted
send results expose only the canonical public mode (`none`, `room`, or
`targeted`), without recipient identities or membership counts. Every message
written by Stage-1 code has an internal manifest, including `notify=none` and
raw omitted `notify`. A missing manifest therefore identifies pre-Stage-1
retained history, whose legacy room-wake semantics remain intact. Malformed or
unsupported Stage-1 intent is a storage-integrity error and fails loud rather
than being treated as no notification.

Projection initialization relies on a narrow upgrade invariant: every Stage-1
sender durably creates the room projection before it can publish a Stage-1
manifest. Consequently, if no projection row exists, every message already in
that stream is pre-Stage-1 history and the new projection baselines at the
current `last_seq`; it does not scan retained legacy history. Concurrent
initializers insert the baseline once before any of them publish. This
classification assumes the supported upgrade/restart model preserves SQLite;
restoring JetStream and SQLite from inconsistent points is not reclassified as
a normal upgrade.

After a definite JetStream PubAck, the message is accepted. SafeYolo
materializes its manifest into the canonical SQLite attention feed and
transactionally enqueues any NATS wake hints. If materialization is not yet
complete, the send still returns success with explicit pending-attention
status; it must never report that an accepted message was unsent. Recovery
replays accepted manifests idempotently. This internal recovery does not add
caller-visible `send` idempotency: separate caller retries that create
distinct canonical messages may each create their own logical attention
edges. A publish failure before dispatch is a definite non-acceptance. A
failure after dispatch but without a PubAck has an unknown outcome and must be
reported as such: JetStream may have accepted the message, and a caller retry
may create a second canonical message.

If retention removes the just-accepted canonical object before synchronous
projection reaches it, send reports its attention status as `lost`, not
`ready` or indefinitely `pending`. Canonical message acceptance remains a
fact; the loss audit records that its attention was not materialized.

A room projection watermark is the highest contiguous JetStream sequence that
has been fully examined and, where required, fully materialized. Concurrent
projectors may repeat work but must never advance a watermark past an
unprocessed earlier message. SQLite enforces one logical edge per canonical
`msg_id` and intended recipient membership generation.

Retention can overtake an interrupted projection. If the current retained
floor is above `watermark + 1`, the missing interval is irrecoverable. SafeYolo
atomically enqueues one stable `coord.attention_projection_lost` audit event
for that interval and advances the projection frontier to immediately before
the retained floor, then continues with retained messages. It creates no edges
for lost canonical objects and does not describe the interval as successfully
materialized. The frontier compare-and-swap and audit enqueue share one SQLite
transaction, so repeated or concurrent recovery is idempotent. Multi-room
recovery attempts every room before reporting room-local integrity failures;
a corrupt retained Stage-1 manifest still fails loud for its room without
preventing unrelated healthy rooms from being projected.

SQLite attention edges are authoritative. Per-agent NATS subjects are only
low-latency wake hints. `wait_for_attention()` uses a caller-owned numeric
cursor over a per-agent feed sequence; returning an edge never advances a
server-side consumed cursor. The feed allocator high-watermark, returned rows
and authorization checks are read from one SQLite snapshot, so a page cannot
return an edge above its `next_cursor`. Its wait path checks the SQLite ledger
before subscribing, checks again after subscribing to close the race, and
checks again after a hint or bounded wait window. Lost or duplicate hints
therefore cannot lose or duplicate the logical delivery. Authorization is tied
to the captured membership generation immediately before returning an edge,
and canonical object reads independently enforce current authorization.

The blocking MCP tool is a harness integration point, not a universal
scheduler. Coord messages with matching attention can release the coord wait.
While a blocking tool call owns a harness turn, unrelated UI, operator or
control-channel messages may remain invisible to that model until the tool
returns. The durable feed preserves coord attention across a dropped or
unrearmed wait, but Stage 1 does not claim it can preempt a busy harness.

Stage 1 does not garbage-collect durable edges, delivered hint-outbox rows or
edges whose canonical message has expired. Cleanup must first define
caller-owned cursor truncation and disclosure semantics; that lifecycle design
is tracked separately in [#394](https://github.com/craigbalding/safeyolo/issues/394).

The legacy per-room `wait_for_message()` remains available. It is
target-aware for messages carrying Stage-1 intent, while pre-Stage-1 messages
and raw sends whose `notify` field was omitted retain broadcast wake
semantics.

For durable state mutations, use a transactional outbox or equivalent recovery mechanism so "DB commit succeeded but process died before wake publication" eventually produces the wake. Do not make NATS delivery itself the source of truth.

Key acceptance tests:

* Alice sends a message notifying Bob. Bob wakes; Codey remains blocked/quiet.
* Codey can nevertheless subsequently read the Alice→Bob message from room history.
* Broadcast creates one logical edge for every current recipient; repeated
  delivery is harmless and deduplicable by `attention_id`.
* `notify=none` records history without waking anyone.
* Targeting a non-member is rejected without leaking otherwise-undiscoverable identities.
* Revocation between notification creation and delivery cannot expose the message to the revoked recipient.
* SafeYolo/NATS restart during notification delivery causes no lost canonical message or permanently lost state notification.
* Process death after JetStream acceptance but before SQLite materialization is
  recovered by a fresh process, including across NATS restart; repeated
  recovery returns the same logical edge.
* Retention loss of an unmaterialized canonical message is audited and does not
  prevent later retained manifests from materializing.
* Duplicate/retried wake delivery does not cause duplicate state mutation or
  duplicate agent handling after deduplication.
* Operator broadcast retains the convenient "everyone pay attention" behaviour.
* Three idle agents can run for 30 minutes with ordinary targeted collaboration without every message waking every model.

That last dogfood measurement is important: measure **LLM wakeups per useful work event**, not just HTTP/NATS correctness.

---

### 2. Sticky operator brief

Next add the strongest source of coordination truth: what the human currently wants.

One versioned Markdown document per room is enough:

```text
coord brief show huddle
coord brief set huddle <file/text>
```

Avoid structured workflow settings. Put goals, priorities, working style and communication expectations in ordinary operator-authored prose.

Store the current brief for efficient reads and retain every immutable brief
revision in canonical SQLite history. Expose the latest version prominently.
An update generates attention to all room members. Its JSONL event records the
room, revision, content hash and actor, not the Markdown body.

Key acceptance tests:

* Only the operator/admin surface can mutate the brief.
* An agent cannot forge/update the brief through the Agent API or by sending specially formatted chat.
* Every agent joining a room sees the same current brief and version.
* Brief persists across SafeYolo/NATS/agent restart.
* Updating v4→v5 wakes all current members and their next state read shows v5.
* A revoked agent cannot read updates.
* Concurrent operator edits using the same expected version produce one update and one conflict rather than silently losing an edit.
* Previous versions remain auditable.
* Operator changes "messages succinct; evidence before inference" once; agents joining later receive it without replaying transcript history.

This directly addresses repeated transient operator interventions in the dogfood such as brevity, role timing and inference discipline.

---

### 3. Authoritative room inventory: identity, capabilities and resources

Before asking agents to allocate work, give them an accurate answer to **who is here and what can they actually do?**

Extend `get_room_state()` with member state assembled from existing
authoritative sources rather than copied into coord. Do not compress
configured existence, authorization, provider availability, resource
ownership and agent declaration into one `available` boolean:

```text
bob
  agent_id: ag-...
  instance: sy-...
  verified:
    - capability: rundeck:acceptance_runner
      authorized: true
      availability: available | unavailable | unknown
      observed_at: ...
      valid_until: ...
  declared:
    - capability: skill:acceptance-test
      asserted_at: ...
```

The operator surface is explicit and room-scoped:

```text
coord state huddle
coord inventory advertise-capability huddle bob rundeck:acceptance_runner
coord inventory unadvertise-capability huddle bob rundeck:acceptance_runner
coord inventory advertise-resource huddle rundeck acceptance_runner
```

Provider adapters receive only room ID, stable member IDs, advertised granted
labels and advertised resource labels. Their raw payloads and errors never
enter room state: coord allow-lists availability/lease fields, bounds the call
and output, and changes missing, failed, malformed or stale evidence to
`unknown`.

The production adapter boundary is provider-neutral. A service integration
atomically replaces a bounded public observation file at
`~/.safeyolo/coord-providers/<provider>.json`; coord discovers those adapters
at process bootstrap and reconstructs them after restart. The JSON object uses
the same narrow `capabilities` and `leases` evidence shape as the adapter
contract and must not contain credentials or connection configuration. Coord
never writes provider state. Missing, unreadable, oversized, malformed, stale,
or removed snapshots produce `unknown`. The complete provider call, including
incorrectly blocking implementations, runs outside the Agent API event loop
behind its timeout. Global and per-provider in-flight caps bound abandoned
daemon workers, so a hung integration cannot consume the shared executor used
for authoritative state reads or spawn new work indefinitely.

Keep provenance explicit:

* `verified`: SafeYolo-derived. `authorized` is a current platform grant.
  `availability=available` requires positive evidence from an authoritative
  provider. Stale or failed provider information becomes `unknown`, never a
  silently retained positive.
* `declared`: harness/agent supplied.
* unknown is different from false.

Room state exposes an explicit room-visible/advertised capability projection,
not the agent's complete SafeYolo grant inventory. Collaborators see only the
labels needed for coordination. Tokens, credential identities, account/persona
details, sensitive route scopes and unadvertised grants never enter the
projection.

Expose **service-owned resource leases** as separate provider-owned objects
when a service supplies them. Coord displays them; it does not merge them into
capability availability or pretend to own them.

The dogfood spent a striking number of messages establishing who really had Rundeck, Heartbeat, GitHub write, the acceptance harness and which workspace was mounted where.

Key acceptance tests:

* Grant Bob `rundeck:acceptance_runner`; room state immediately shows it.
* Revoke it; room state immediately stops showing it. No stale coordination cache.
* A message claiming `"I have rundeck"` cannot alter verified capability state.
* Agent rename preserves the durable `agent_id`; remove/re-add produces a distinct identity as #371 requires.
* Capability output never exposes service credentials, gateway tokens or unnecessarily sensitive route details.
* Capability provider failure produces `unknown`, never last-known state silently presented as current truth.
* An agent with a declared skill cannot cause that declaration to appear under `verified`.
* A peer sees advertised collaboration labels but cannot enumerate Bob's
  complete grant inventory or recover tokens, accounts, credential names, or
  sensitive route details.
* If an authoritative service reports an exclusive resource lease held by Bob, coord displays Bob as holder.
* Manually writing "Codey owns devstack" into chat cannot supersede that resource lease.

This is where the platform starts becoming genuinely better than a generic collaboration tool.

---

### 4. Minimal work objects and atomic task claims

Now introduce the smallest thing that could reasonably be called task management:

```text
work_id
room_id
title
external_ref?
state = open | claimed | done
claim_agent_id?
claim_generation
claimed_at?
claim_expires_at? = NULL  # reserved for a future optional lease mode
created_by
short_result?
timestamps/version
```

No boards. No subtasks. No arbitrary workflow states. No dependency graph.

Agents and operator may create work. There is no first-class priority in the
initial model; the sticky operator brief carries priorities until dogfood
demonstrates a need for machine-orderable work.

Claims are atomic, durable generation-protected ownership. They do not expire
or transfer automatically. A claimant may release; the operator may
force-release or reassign. Every successful claim or reassignment increments
`claim_generation`, and release/completion must name the current generation.
Agent liveness never renews or releases work: an MCP process being alive does
not prove that the model is still doing the work.

Status may flag an old claim as potentially stale using age/activity evidence,
but that is advisory and never changes ownership. If later dogfood proves
abandoned claims are an operational problem, the reserved nullable
`claim_expires_at` permits an optional lease mode with explicit claimant
renewal. Until then, reserve the term **lease** for actual resource ownership.

All mutations use the foundation's `operation_id` idempotency contract.
`operation_id` protects ambiguous retries; `version` and `claim_generation`
protect against stale concurrent mutations.

Core operations:

```text
create_work
claim_work
release_work
complete_work
```

`external_ref` is deliberately opaque:

```text
github://craigbalding/safeyolo/issues/391
```

SafeYolo doesn't need GitHub to resolve it in order to coordinate ownership.

Key acceptance tests:

* Bob and Codey concurrently claim the same open work item: exactly one succeeds.
* 100 simultaneous claim attempts still produce exactly one owner.
* Repeating Bob's successful claim after an ambiguous client timeout returns the same ownership rather than creating anything new.
* Reusing that `operation_id` with different claim input returns a conflict.
* Claim is tied to durable `agent_id`, not display name.
* Delete/recreate "bob" cannot inherit old Bob's claim.
* A durable claim remains Bob's after 30 minutes of work and across restart;
  elapsed time alone never transfers it.
* Releasing and re-claiming increments `claim_generation`.
* Former holder cannot `complete_work` or release using a stale claim
  generation after losing the claim.
* Only holder or operator can release an active claim.
* Operator can force-release/reassign.
* An operator may mark/reclaim an apparently abandoned claim without relying
  on agent-process liveness.
* Revoking room membership prevents release/completion by the former member;
  the operator remains able to reclaim the work.
* Restart during a claim mutation preserves one valid result.
* GitHub being unavailable does not affect claim/release/complete.
* Rich external description can change without changing SafeYolo's claim.
* Three agents shown three open items independently converge on ownership without a chat negotiation.

That last test should deliberately reproduce the README/issue-filing duplication seen in the transcript.

---

### 5. Material signals and operator attention

Once work exists, give agents a constrained way to say something **matters** without making every chat message important.

Initially support exactly:

```text
blocker
decision
result
correction
```

Each has:

```text
short bounded summary
author identity
work_id?
refs[]
basis = observed | inferred
supersedes?
```

Signals retain immutable canonical revisions/history in SQLite alongside their
efficient current-state projection. The author identity is trusted. The claim
itself remains attributed agent data. `basis=observed` means "Bob says this is
observed", not "SafeYolo independently proved it."

Semantics:

* unresolved `blocker` → potentially operator-visible;
* `decision` → specifically asks the operator for an answer;
* `result` → state/status material, normally no page;
* `correction` → supersedes the same author's prior claim;
* operator can resolve anything;
* an agent cannot silently supersede another agent's result.

Separate signal creation from operator interruption. Any ordinary collaboration
member may initially create an attributed signal (`create_signal`), but only a
principal with the independently revocable `page_operator` permission causes
an unresolved blocker/decision to create an operator attention edge.
Operator-created local collaboration rooms enable `page_operator` by default,
with bounded rate and deduplication controls.

Feed permitted blocker/decision pages into the existing `safeyolo watch` path
rather than inventing a second notification product. JSONL records signal ID,
kind, author and revision, not signal prose. `watch` retrieves the bounded
canonical signal revision through the Admin API when rendering it. A detached
`watch` loses no truth because unresolved signals remain in canonical state.

Work completion and result signals remain distinct. `complete_work()` says the
work item is finished and records its concise completion summary. A `result`
signal elevates a separately material finding, optionally linked to work.
Completing work never manufactures a result signal.

Key acceptance tests:

* Bob raises one blocker → one visible operator attention item, not repeated toast spam.
* Removing Bob's `page_operator` permission still records his blocker in room
  state but does not interrupt the operator.
* A newly operator-created local room pages by default; the permission remains
  independently revocable.
* Operator resolves it → it disappears from "needs operator".
* Bob corrects his own erroneous result → old result remains auditable but is no longer current.
* Codey cannot issue a correction that silently supersedes Bob's result.
* Agent cannot create an event that appears to have `sender_kind=operator`.
* An inferred claim is visibly distinguished from an observed claim.
* Oversize/free-form payloads are rejected/bounded.
* A malicious summary containing terminal controls/markup renders inert.
* If `watch` is detached, unresolved items are still present when the operator returns.
* The JSONL event contains signal identity/revision metadata but not the signal
  summary; `watch` fetches the correct immutable revision from canonical state.
* Completing work records one completion summary and does not create a
  duplicate `result` signal.

Bob's rlimit episode is an almost perfect acceptance fixture: initial observed symptom → incorrect inference → later explicit correction. Current-state output must end with the corrected fact, while retaining the forensic history.

---

### 6. Deterministic `room_state` and `coord status`

At this point build the operator experience around state rather than transcript.

`get_room_state()` becomes the canonical bounded projection, and:

```text
safeyolo coord status huddle
safeyolo coord status huddle --json
```

renders it.

Something like:

```text
Brief v7    Merge both branches safely; policy correctness takes precedence...

Members
  claude    github:write (authorized; availability unknown)
  codey     reviewer skill (declared)
  bob       rundeck:acceptance_runner (available; observed 2m ago)

Work
  merge candidate      claude   claimed
  review candidate     codey     claimed
  acceptance           bob       claimed

Needs operator
  none

Latest material results
  review approved candidate ...
  acceptance running ...
```

No LLM involved.

Key acceptance tests:

* Reproduce a synthetic version of the real dogfood with crossed messages, abandoned claims, corrections and changed capabilities. `status` always reflects authoritative latest state.
* Operator detaches for 30 minutes, returns, invokes one command and can answer:

  * what are we trying to achieve?
  * who owns each active item?
  * who can perform each specialist action?
  * what needs me?
  * what has completed?
* Superseded/retracted signals are not shown as current.
* Released/reassigned claims are not shown as active; an old durable claim may
  be marked potentially stale but remains owned until explicitly changed.
* Revoked capabilities disappear immediately.
* Result is deterministic for identical state.
* Stable ordering makes it diff/test friendly.
* Large rooms/worksets remain bounded and report truncation/counts rather than flooding an LLM context.
* Status does not require replaying or summarising the chat transcript.
* Status does not invent a structured goal or priority from Markdown; it shows
  the brief version and a deterministic bounded excerpt.

At this point the core operator-noise problem is substantially solved.

---

### 7. Attestations, not voting

Only after the work model is stable would I add independent review/acceptance semantics.

Add a mutable **work target**:

```text
target_ref
target_generation
```

Changing the candidate increments `target_generation`.

Then agents can attach attestations:

```text
kind: review | acceptance | ...
verdict: approve | reject | abstain
work_id
target_generation
summary
evidence_refs[]
```

Don't hardwire "2 of 3 wins". Status displays evidence; the operator or higher-level policy decides what it means.

This directly solves one of the best lessons from the dogfood: Bob accepted `654724a`, then CodeQL-driven changes moved the candidate to `79a626c`, making the acceptance stale. The agents noticed manually and reran C.

Key acceptance tests:

* Bob approves target generation 3.
* Claude updates candidate → generation 4.
* Bob's generation-3 approval remains in history but **does not appear as approval of generation 4**.
* Status clearly says generation 4 lacks acceptance.
* Bob reruns and approves generation 4; current status becomes green.
* Codey cannot forge an attestation authored by Bob.
* Two independent agents can submit conflicting attestations; both remain visible.
* No majority result is invented.
* An attestation includes evidence references but does not automatically trust referenced external content.
* Squash/rebase/change of external target requires explicit target change rather than silently carrying prior approval.

This is much more valuable than a generic `vote()` primitive.

---

### 8. External work adapters — GitHub first

Now implement the principle:

> **SafeYolo owns the claim and runtime truth. GitHub owns the rich work description.**

Start read-only.

A work item containing a GitHub reference may be enriched with:

```text
title
issue/PR state
URL
perhaps current head SHA
```

through an adapter. SafeYolo still owns claim state.

Only later, if useful, add explicitly configured outbound projection such as posting a completion/result comment.

Do not make bidirectional state synchronization the starting point.

Key acceptance tests:

* Import/seed from GitHub creates a SafeYolo work item pointing to the issue; it does not clone the entire issue model.
* GitHub outage leaves SafeYolo work/claim operations fully functional.
* Someone changing the GitHub assignee cannot seize the SafeYolo claim.
* Someone closing the GitHub issue does not automatically mark SafeYolo work complete unless an explicit mapping policy exists.
* SafeYolo claim changes do not modify GitHub unless the adapter is explicitly enabled for writes.
* Adapter obtains credentials through normal SafeYolo service controls; agents never receive the PAT.
* An agent lacking GitHub access can still participate in the SafeYolo work object according to room policy.
* External metadata is clearly labelled external rather than authoritative runtime truth.

Only after GitHub proves the adapter contract would I consider Plane/OpenProject/etc.

---

### 9. Cross-SafeYolo federation

Do this last, after local semantics have been heavily dogfooded.

The architectural constraint is explicit now:

> **Every mutable room has one authoritative SafeYolo instance.**

Remote agents participate through it. Do not replicate claims as multi-master mutable state.

#371 already establishes `safeyolo_instance_id`, the distinction between `SY_LOCAL` and future federated accounts, and the rule that NATS is transport rather than principal authority.

Key acceptance tests with two real SafeYolos:

* Agent A on instance 1 and Agent B on instance 2 both see retained authorized room state.
* Both concurrently claim the same work item → home SafeYolo chooses exactly one winner.
* Network partition during mutation produces failure/unavailability rather than two independent winners.
* Remote agent cannot forge its `origin_instance_id`/agent identity.
* Local-only `SY_LOCAL` data is not accidentally exported.
* Revoking federation/member access prevents subsequent state/message access.
* Targeted attention reaches the remote intended agent without waking unrelated remote agents.
* Remote brief update observation preserves the home instance's version.
* External GitHub reference behaves identically regardless of which instance the agent sits behind.
* Reconnect after partition converges from authoritative room state, not by merging two claim histories.

That deliberately buys availability less aggressively than consistency. For coordination ownership, split-brain is worse than temporary inability to claim.

---

### 10. Richer UI and optional narrative summaries

Only now spend meaningful effort on UX.

The deterministic state remains primary. An optional LLM summary can answer "what happened while I was away?" using current state plus recent/superseded transcript context.

It must be labelled derived, and it never feeds coordination state back automatically.

Acceptance tests:

* Deliberately make narrative summary contradict an authoritative claim; UI still displays authoritative state as truth.
* Re-generating a different summary changes nothing operational.
* Very long transcript can be summarised without loading it into every collaborating agent.
* Operator can inspect the underlying evidence/messages for any material summary assertion.

Similarly postpone TUI dashboards, boards, filtering, colour schemes and rich notification configuration until this point.

---

## Cross-cutting acceptance gate for every stage

Require every behavioural stage to pass four levels before moving on:

1. **Model/API tests** — authorization, validation, state transitions, bounds.
2. **Concurrency/restart tests** — simultaneous agents, ambiguous retries, process/NATS restart, revocation races.
3. **Real Agent-API/NATS black-box tests** — don't just call Python functions; prove transport-derived identity and real substrate behaviour.
4. **Three-agent dogfood** — give agents a real SafeYolo task and measure whether the feature actually reduces transcript negotiation.

For control-plane mutations, use the same philosophy as the new assurance work: deliberately interrupt operations around commit/publication boundaries and prove the invariant survives. The coordination state is becoming security-relevant platform state; it deserves stronger testing than a normal task tracker.

The most useful quantitative dogfood metrics would be:

* total agent messages;
* total agent words;
* model wakeups;
* crossed/stale responses;
* duplicate work attempts;
* operator interventions required to resolve ownership;
* false "current" facts later corrected;
* time from operator `status` request to a correct answer.

The attached dogfood transcript then becomes your **baseline fixture**, not merely anecdotal evidence.

### The dependency chain

In compact form:

```text
schema/invariants
      ↓
targeted attention
      ↓
operator brief
      ↓
verified member/capability projection
      ↓
work + atomic claims
      ↓
material signals / operator attention
      ↓
deterministic status
      ↓
attestations tied to exact work target
      ↓
GitHub/external adapters
      ↓
cross-SafeYolo federation
      ↓
richer UI / generated summaries
```

Do not combine these into one giant issue/PR. Write the **full design first**,
including schemas and invariants for the later stages, then execute it as this
sequence of independently acceptance-tested slices. That gives the coding
agent a coherent destination without turning "systematic" into a six-month
big-bang branch.
