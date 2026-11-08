# Coord operations reference

Use the [operations guide](coord-operations.md) for first use, routine work
and recovery. This reference covers detailed input rules, retry behavior and
specialist procedures. Unless a section selects another host, run command-line
interface (CLI) commands as the host account that owns the installed instance. Examples use
`$HOME/.safeyolo`; select your actual root if it differs. Agents use their
authenticated Model Context Protocol (MCP) tools inside the guest.

## Retry a membership change

Run grant and revoke as the host account that owns the instance. Room `chat`
and configured agent `alice` must already exist in `$HOME/.safeyolo`. Grant
replaces the manual permission set; revoke removes all current room sources for
that agent. The following commands first grant receive-only access, then revoke
it. Choose an operation ID before calling if you need lost-response recovery:

```sh
safeyolo --root "$HOME/.safeyolo" coord grant chat alice receive --operation-id chat-alice-receive
safeyolo --root "$HOME/.safeyolo" coord revoke chat alice --operation-id chat-alice-revoke
```

Repeat the exact operation ID and input after an ambiguous response. SafeYolo
returns the original result, including its membership generation and transition
time. Permission order and duplicates do not change grant input. Omitting
permissions grants `receive`, `send` and `page_operator`. Explicit permissions
replace that manual set; other valid approved sources remain effective.
Changing the canonical input under the same ID returns a conflict. Grant and revoke have separate ID scopes.
To request a new change after a later grant or revoke, choose a new ID.
When you omit `--operation-id`, SafeYolo generates one and includes it in the
result; a lost response then also loses that retry handle.

Membership changes commit with immutable operation history and metadata-only
audit rows. The running proxy delivers staged Coord audit and attention hints
through one common worker. Staging is not delivery. Failed delivery remains
pending across restart; audit retries can produce duplicates with the same
`event_id`. The audit directory must permit a sibling `.lock` file. The writer
needs read and write access to recover an incomplete final line before append.
For a log inside the configured instance directory, durable delivery syncs the
file and every containing directory through that instance directory, on every
attempt. The instance directory already contains the loaded configuration;
the audit writer does not create its entry. Ancestors above that directory need
no access. An external log destination retains the full ancestor sync path.
Canonical brief and message bodies stay in their existing stores.
These retry semantics do not apply to room creation or message sends.

## Message input and chat controls

Interactive chat requires both standard input and standard output to be terminals.
If either is piped or redirected, the command exits before connecting. It does
not consume input or emit terminal cursor controls. Use `--observe` for a
non-interactive room stream.

Chat displays arriving messages above the editable `op>` prompt. The draft and
cursor remain intact. Enter sends the draft; `:q`, Ctrl-D or Ctrl-C detaches.
`:paste` (or `:p`) reads the host clipboard. `:edit` (or `:e`) opens `$VISUAL`,
then `$EDITOR`, with `vi` as the fallback. Clipboard/editor composition requires
confirmation. No chat transcript or draft is saved separately from room history.
Clipboard and editor input replace malformed UTF-8 bytes with the replacement
character. Clipboard commands retain their ten-second timeout.
Use `chat --observe` for a read-only stream without a terminal prompt.

Scripted send accepts exactly one UTF-8 source: text, `--file FILE`, or `--stdin`.
It preserves the selected payload, including trailing newlines and controls.
Empty/whitespace-only input, multiple sources, unreadable/non-UTF-8 input and
invalid notification targets fail without publication. `--content-type` accepts
`text/markdown` (default) or `text/plain`. Repeat `--to` for several members.
Without `--to`, scripted send notifies the room. Interactive chat also defaults
to room attention, unless an approved Factory snapshot selects one
operator-input agent. An explicit `--to` overrides that default.
The command reports authorization, room, target and provider errors without
printing credentials. `dispatch-trigger` remains the separate command for
Dispatch publication requests.

If publication acknowledgment is lost, the command reports acceptance as
**UNKNOWN**. It does not resend automatically. Inspect history before deciding
whether to send the message again. A later independent send remains available.
Accepted messages with pending or lost attention retain that diagnosis.

## Read and update a trusted brief

For initial creation, follow the [brief walkthrough](coord-operations.md#read-and-update-a-trusted-brief).

For a later update, read the current brief and use its revision as
`--expected-revision`. Inspect the existing text before replacing it. Set accepts
exactly one source: a Markdown argument, `--file FILE`, or `--stdin`. It preserves
the input bytes, including trailing newlines. A different operation with a stale
revision fails without changing the brief or emitting brief-change attention.

If the result is uncertain, retry with the same `--operation-id`, original
expected revision and exact Markdown. Keep the original input file for that
retry. The command returns the original committed result even if a later
operation has changed the brief. It does not reapply the old intent. Changed
input under the same ID fails with an operation conflict. Read the current brief
separately to inspect any later change. The operation ID is scoped to the
operator and brief-set operation type across rooms. If you omit
`--operation-id`, the command generates an ID and reports it in its result;
choose the ID before the first attempt when you need ambiguous-result recovery.

## Claim durable work

The [work walkthrough](coord-operations.md#claim-durable-work) covers creation,
claims, candidates, review and completion. Local work treats `external_ref` as
opaque. An external assignee or description never decides ownership.

Local `create_work` can explicitly assign generic execution with
`assignee={"kind":"agent","id":"DURABLE_AGENT_ID"}`. Only that agent may claim
the assignment; operator reassignment remains available. A native supervisor
uses `read_work_actions` and `receive_work_action` to retain delivery in its
existing checkpoint. These operations use the authenticated participant and
never claim, answer or accept work. See the
[native delivery contract](codex-coord-supervisor.md#native-work-delivery)
for action receipt recovery and interactive control.

### GitHub references

To seed work from a GitHub issue or pull request, use the owning host account
with an existing room (`chat` here). Replace the example URL with your actual
issue or pull-request URL and choose an operation ID before running:

```sh
safeyolo --root "$HOME/.safeyolo" coord work import-github chat https://github.com/craigbalding/safeyolo/issues/1313 --operation-id github-review
```

This command validates and stores the GitHub HTTPS URL through normal work
creation. The initial local title identifies the repository and issue number.
The command does not fetch GitHub. A room member can use `import_github_work`
with `room_name`, `url` and a chosen `operation_id` for the same operation.
GitHub availability and service access do not affect creation or replay.

For external metadata, a room member calls `read_github_work` with `room_name`
and `work_id`. The result separates canonical `work` from `external` metadata.
Available metadata contains an external title excerpt, issue or pull request
state, canonical URL and observation time. GitHub owns that description;
SafeYolo owns the claim, runtime state and completion. The adapter does not copy
rich descriptions, assignees or commit identifiers. It never changes a
candidate target or carries attestations to another target.

The operator grants the caller the normal `github:read_work` service capability
for `api.github.com` and binds a host-held credential through existing service
controls. The native adapter obtains the caller's gateway token from
`/gateway/services`. It sends GET requests through the caller's proxy route.
The agent does not receive the upstream personal access token. The adapter
does not follow redirects, retry requests or write to GitHub. Each external
request has a 15-second deadline and a 1 MiB response limit. Title excerpts use
at most 512 source UTF-8 bytes and the existing inert control-character display.
Escaping can make the returned title longer than 512 bytes.
Other service capabilities and generic opaque work references remain available.

If GitHub fails or the caller lacks service access, `external.status` is
`unavailable` beside the current local work. Ordinary reads and claim operations
do not fetch external metadata. Room and service access are checked again after
the external fetch. Revoked room access refuses the read; revoked service access
prevents the metadata return. A member without GitHub access can still claim,
release or complete work according to room permissions. `coord status ROOM`
labels a recognized GitHub URL as an external reference without fetching it.

### Claims, outputs and attestations

The current holder uses `publish_work_output` to select an immutable output
reference and record its execution outcome in one transaction. The operation
requires `room_name`, `work_id`, `expected_version`, `expected_generation`
(the claim generation), `expected_target_generation`, `target_ref`,
`execution_outcome`, `summary`, and an optional `evidence_refs` array.
`execution_outcome` is `succeeded`, `failed`, or `uncertain`. It reports the
producer's execution result; it does not establish acceptance of the output.

Retain the external artifact before publication. Use a reference that identifies
its actual immutable revision, such as an exact commit or a retained report's
content digest. SafeYolo does not fetch the reference or detect changed bytes
behind a mutable URL. A final external action must check the expected revision
at that system's authority.

Authenticated transport supplies `output.producer`; a caller cannot supply
another actor or producer. A bridge must use the producing agent's authenticated
route. Host commands cannot publish on behalf of a holder. Artifact content and
authorship claims inside it remain external, unverified evidence.

Publication requires a current claim or the retained holder of completed work.
Another producer needs explicit operator reassignment. Every new publication
advances `target_generation`, including an explicitly reused reference. Earlier
attestations become stale. Publication records its `work_version`, claim
generation, producer, outcome, summary, evidence references and timestamp in
`work.output`. It does not release the claim, complete work, or change
`external_ref`. That opaque context reference remains bound to the same work
through cancellation and reassignment.

The canonical receipt contains `work` and `operation_id`. Retain the chosen
operation ID and original inputs before sending. After an interrupted request,
retry those exact inputs. A committed operation returns its original receipt;
an uncommitted operation can succeed once if the claim and output generations
are still current. Reassignment, cancellation or a later output can instead
make the uncommitted request stale. Keep the external artifact in either case.
An old successful receipt does not imply that its output is still current;
read current work separately. This protocol does not make external execution
exactly once and does not authorize repeating an uncertain external action.

Use `list_work_outputs` with `room_name` and `work_id` to read original
publications ordered by `work_version`. At most 200 items and 65536 bytes of
item JSON are returned. Continue with `next_after_version` as `after_version`.
Later attestations and ownership changes do not duplicate publications. Pages
do not share a snapshot. The host command is `coord work outputs ROOM WORK_ID`.

A member calls `attest_work` with `room_name`, `work_id`, `target_generation`,
`kind`, `verdict`, `summary`, optional `evidence_refs` and a chosen `operation_id`.
The current target must be set and match the supplied generation. A concurrent
candidate change conflicts; read the current work before submitting new evidence.
Independent attestations need no expected work version, so another author's
submission does not invalidate the candidate. Authenticated identity supplies
the author; caller-supplied authorship is rejected. `kind` can be `review`,
`acceptance` or another stated kind. `verdict` is `approve`, `reject` or `abstain`.
Attestations are immutable, including their target reference and generation.
Evidence references remain untrusted external content and are never fetched.
Attestations do not transfer ownership or complete work.

`get_room_state` and `coord status ROOM` show the current candidate and exact
counts of current acceptance attestations and stale attestations. These counts
are attributed reports. They do not decide acceptance by majority or replace
the selected requirements and decisions described below. Each work item shows at most eight attestation
excerpts in 4096 bytes of item JSON, current first, with explicit truncation.
Summaries show a UTF-8 prefix of at most 128 bytes. Use `list_work_attestations`
with `room_name` and `work_id` for full records and evidence references. Pages
contain at most 200 items and 65536 bytes of item JSON, ordered by
`attestation_id`; follow `next_after`. Each page labels records current or stale
against its returned `target_generation`. Pages do not share a snapshot.
Prior attestation evidence stays in history after a target change and does not approve
the new generation.

Use `coord work attest` and `coord work attestations` from the owning host
account for attributed evidence. `coord work --help` lists their arguments.
`target_ref` is nonempty and at most 1024 UTF-8 bytes. Output summaries are
nonempty and at most 1024 bytes; at most 16 evidence references of 1024 bytes
each are allowed. A serialized output publication is at most 32768 bytes.
Attestation kind is nonempty and at most 128 UTF-8 bytes; summary is nonempty
and at most 1024. At most 16 evidence references of 1024 bytes each are allowed.
The complete serialized attestation is at most 32768 bytes. Summaries and refs
remain in canonical authorized storage; audit and attention hints contain only
metadata. Retry an ambiguous operation with its original operation ID and inputs;
the original target and author remain bound even after a later candidate change.

The holder calls `release_work` or `complete_work` with the current version
and generation. Completion accepts optional `short_result`. Reads require
current `receive` permission. Mutations require `send` and `receive`. Revocation
prevents the former member from reading, releasing or completing work.

The holder can cancel unfinished work through `cancel_work`, with the current
`expected_version`, `expected_generation` and a nonempty `reason` of at most
1024 UTF-8 bytes. The creator can cancel its own open work. Other members cannot
cancel that work. The owning host uses `coord work cancel` and can cancel any
unfinished work. Cancellation selects `state=cancelled`, clears the holder and
advances the claim generation. It preserves earlier outputs and evidence and
records the cancelling actor, reason and time. It does not report successful
completion or stop external execution. `coord status ROOM` separates cancelled
work from active work and completed work.

Claims survive elapsed time, model exit, and instance restart. They never
expire or transfer automatically. `claim_expires_at` is reserved and stays
null. The owning host account can inspect and recover an abandoned claim
without relying on process liveness. Use `coord work --help` for the recovery
commands. `release` requires the current expected version and generation;
`reassign` also requires the new holder's durable `--agent-id`. The new holder
must have current room send and receive permission.
Reassignment can also reopen completed or cancelled work in a new claim
generation. The previous output retains its original producer and generation
until a new publication replaces it. Membership or process silence never
grants an agent reassignment authority.

Choose an operation ID before a write. If the response is lost, retry the same
operation ID and original inputs, including the original expectations. While
room authority remains current, the retry returns the original result even
after later mutations. Changed input under that ID conflicts. For a new intent,
read the current work and use a new operation ID. A former holder cannot use
stale versions or generations to change a later claim.

Work mutations notify current receive-authorized agents except the agent actor;
operator mutations notify all such agents. Attention resolves the original
immutable version, which may differ from current work. Audit and wake hints
contain metadata; canonical work storage contains titles, references and
results. Work input is bounded to 262144 UTF-8 bytes. Lists return at most 200
items ordered by `work_id`; use `next_after` to continue. Concurrent changes
can affect later pages because pagination does not share a snapshot.

### Assigned checks and peer challenges

An assigned check and a challenge response are ordinary native work records.
Their `work_id`, version, claim generation, creator and immutable history use
the same authority and retry rules as other work. `request_check` retains a
criterion, exact subject, named reviewer and `independent` flag. A participant
is `{"kind":"agent","id":"DURABLE_AGENT_ID"}` or
`{"kind":"operator","id":"operator"}`. Named agents must currently have room
send and receive permission. The creator/requester and every answer author
come from authenticated transport.

Subject input selects one exact revision:

| `kind` | Required fields | Meaning |
|---|---|---|
| `work` | `work_id`, `version` | That immutable work revision. |
| `output` | `work_id`, `target_generation` | The original work revision that selected that output. |
| `check` | `work_id`, `version` | An answered check revision, including its attributed conclusion. |

Canonical subjects retain the reference, original work revision, root work ID,
target reference and known producer. A caller cannot provide the producer.
Historical subjects remain available. With `independent=true`, the named
reviewer must differ from the subject's authenticated producer. Unknown
producer attribution cannot establish independence. Reassigning or integrating
the work does not change the original output's producer.

Only the named agent can claim and answer a check. `answer_check` requires
the current check work version and claim generation. It records `approve`,
`reject` or `abstain` and completes the check in one transaction. A negative or
uncertain conclusion still completes check execution. The retained reviewer
can correct the answer using the current expectations and a new operation ID.
There is one effective answer per check; earlier answers remain in immutable
work revisions. A late answer about an old output remains historical and
cannot approve a replacement. An operator assigned as reviewer answers through
the host CLI without an agent claim. Generic `complete_work` cannot substitute
for an answer.

`raise_challenge` retains an assertion, grounds, evidence references, exact
subject, named responder and nonempty `deciders` list. Only the named responder
can claim its response work. `respond_challenge` records the answer and optional
exact `correction` subject, then completes that response work. The challenge
remains unresolved. A corrected response invalidates the previous disposition;
the earlier response and disposition remain in work history.

`resolve_challenge` requires the current challenge work version, claim
generation and `expected_response_version` (zero before any response). A named
decider or the operator records `upheld`, `dismissed` or `withdrawn`, with a
reason and optional evidence. The disposition identifies its author, response
revision and any correction. With `independent=true`, a decider must differ
from the producer and responder, including when the operator decides. A stale
response or challenge expectation conflicts. If the disposition arrives before
the response finishes, it explicitly cancels the response assignment rather
than reporting successful execution. Cancellation alone does not resolve a
challenge. Replacing an output also leaves its original challenges intact.

The operator uses ordinary `coord work reassign` to recover an unavailable
reviewer or responder. Reassignment changes the named participant and claim
generation and clears the effective answer/response. Reassigning challenge
response work reopens its disposition. Independence still applies. Use
`coord work recover-challenge-deciders` with current expectations, a reason
and a new `deciders` JSON array when deciding participants are unavailable.
Only the operator can change that list. Revocation continues to prevent a
former participant from reading or mutating work, including retries.

`read_work` adds `review_status` for current review work. It distinguishes
`pending`/`answered` checks, `unresolved`/`resolved` challenges and current/stale
subjects. `list_work_reviews` returns related checks and challenges, including
objections to the work's checks, regardless of response execution state. It
returns at most 200 items and 65536 bytes of item JSON. Follow `next_after`;
pages do not share a snapshot. Excerpts and `details_truncated` identify omitted
details. Read the full record with `read_work`. Supply its positive `version`
argument to read an exact immutable revision. Current receive permission is
required for history. The equivalent host commands are `coord work reviews`
and `coord work show --version`.

Criteria, assertions, grounds, response summaries and disposition reasons are
nonempty and at most 1024 UTF-8 bytes each. Evidence arrays contain at most 16
references of 1024 bytes each. A serialized review record is at most 32768 bytes.
The existing 262144-byte work mutation bound also applies. References remain
external content. Work `external_ref` preserves opaque run/batch context.

These operations record review work. A review is advisory until an authorized
caller selects it as an acceptance requirement as described below. A check
verdict alone does not accept an output or launch a supervised model turn.
The current supervisor still needs its declared message handoffs.
See the [working review example](coord-operations.md#run-an-assigned-review-loop).

### Select requirements and decide output acceptance

Use `set_work_requirements` to select acceptance context on existing work.
Supply `room_name`, `work_id`, its current `expected_version` and
`expected_generation`, and `expected_requirements_version` (0 initially).
`authorities` names participants allowed to amend the context. `deciders`
names participants eligible to decide acceptance. Each participant uses the
same agent/operator principal format as assigned reviews. At least one decider
is required. An empty authorities list leaves later amendments to the operator.
The operator retains recovery authority; the operator must be an explicitly
selected decider to decide acceptance.

The authenticated work creator or operator selects the initial context.
Later amendments require an existing selected authority or the operator.
Ownership or output production alone does not grant policy authority. A worker
can amend requirements only if a previous authorized selection explicitly names
it as an authority. Each amendment records its author and reason and invalidates
earlier acceptance. Changing ownership does not relabel the producer. A worker can still
publish corrections, report failure, request advisory reviews and respond to
challenges while acceptance is pending.

`checks` and `challenges` are arrays of `{work_id, version}` references to
current related review work. Omitted arrays select no obligations of that kind.
Selection records each review's definition, selected revision and original
subject. The selection must be current when it commits. Answers and dispositions
can change without reselecting the obligation. A reassigned reviewer, responder
or deciding participant changes that definition and needs an authorized
reselection. Operator recovery of a participant does not silently change the
acceptance policy. Duplicate references are refused. Reviews in another room
or about unrelated work cannot satisfy an obligation.

With `independent=true`, acceptance deciders must differ from the current output's
transport-attributed producer. Selection before publication records that
requirement; the decision operation enforces it against the eventual producer.
Each required review retains its own selected independence flag. A producer's
required deterministic check can therefore be paired with independent output
acceptance. Without this option, the selected participants decide the policy;
Coord adds no universal independence rule or quorum.

Every selection or amendment needs a nonempty `reason`, advances the context's
own `version`, and records its transport-derived author and time in
`work.acceptance_requirements`. The complete selected context is bounded to
32768 serialized UTF-8 bytes. Earlier contexts remain in immutable work
revisions. Removing an obligation needs the same authority and attributed
amendment; it does not resolve or erase its original challenge.

An eligible decider calls `decide_work_acceptance` with the current work version,
claim generation, `expected_target_generation`, `expected_requirements_version`,
`verdict`, `summary`, optional `evidence_refs` and a chosen `operation_id`.
An approval atomically validates the output, context, required check answers and
challenge dispositions in the existing SQLite transaction. Direct Agent API,
MCP and host calls use that same boundary.

A required check must concern the current output generation, have its selected
assignment and have an effective `approve` answer. A pending, cancelled,
rejected, uncertain or old-output check cannot satisfy it. Nested checks follow
their immutable subjects to the original output generation. A selected challenge
remains an obligation across output replacement. It needs an explicit current
disposition by its selected deciding participants. That disposition and its
exact response/correction remain visible. An upheld objection can concern an
earlier output; Coord does not infer the corrected output's domain verdict
from that label. The selected acceptance decider judges the current output.
An unresolved required challenge prevents approval. Advisory reviews add no
undeclared gate.

`reject` and `abstain` decisions remain possible while review obligations are
outstanding. All decisions require a published output. Summary/evidence limits
match assigned review answers. Each author has one effective decision in
`work.acceptance_decisions`; a correction replaces that author's current entry
and retains earlier entries in immutable work revisions. The complete effective
decision array is bounded to 262144 serialized UTF-8 bytes. An authorized amendment
removes decisions by participants who are no longer selected from that effective
array; their immutable history remains readable. This lets an authority recover
an unavailable participant without retaining its data in the bounded current array.

`read_work` derives `acceptance_status` from current native state. It lists each
selected obligation, its status, eligible decisions and explicit stale reasons.
Output replacement or a requirements amendment makes earlier decisions stale.
A changed required answer, response or disposition invalidates an approval's
review basis. Fixing that review does not resurrect the old approval. A rejection
of the same output/context persists until an explicit corrected decision or an
authorized context change. Conflicting eligible approvals and rejections remain
`conflicting`; extra submissions never outvote another author. A selected
decider must correct the applicable decision, or a policy authority must amend
the context explicitly.

An output is `accepted` only with satisfied obligations, a current eligible
approval and no current eligible rejection. Execution need not be done, and
generic work completion does not create acceptance. Acceptance of a retained
artifact after cancellation leaves execution cancelled. It does not revive a
claim or authorize publication from the cancelled assignment. Work with no selected context
reports `not_selected`; ordinary execution still completes normally. Attestation
counts remain attributed evidence and never bypass selected acceptance.

The host commands are `coord work set-requirements` and
`coord work decide-acceptance`; their options match these fields. Use
`coord work --help` for argument syntax. Room status includes bounded acceptance
excerpts and explicit truncation; use `read_work` or `coord work show` for full
requirements, decisions and reasons. Mutation receipts retain their original
work revision. Retry the exact operation ID and inputs after uncertainty, then
read current work before acting on a recovered receipt.

External applications can use these native requirements and decisions instead
of separately writable acceptance state. They retain domain data, immutable
artifacts and final effects. Coord does not fetch or interpret those artifacts.
A final merge, publication or other external action must validate its expected
revision at that system's own authority. An approved Factory can select native
policy and delivery through `[work]`; see [Factory policy](factories.md#select-native-work-policy).
Native assignments use their Work IDs instead of a duplicate message workflow.
Existing message assignments keep their declared reply protocol.

`create_work` accepts optional `factory={name,snapshot_id}`. The host equivalent
is `coord work create ROOM TITLE --factory JSON`. The currently approved exact
snapshot must declare a work policy for that room. Only its selected creator
roles or the operator can use that selection. Normal room authority still
applies. Transport identity supplies the creator; role bindings resolve to the
instance's configured durable agent IDs. The reference, resolved check templates
and initial requirements are retained with Work. They do not follow later
Factory approval changes.

For selected Factory work, `publish_work_output` also creates the configured
exact-output checks and replaces their prior generated requirements in the same
transaction. `factory.current_checks` in the publication receipt identifies the
new checks. Publication replay recovers the original IDs and creates no new
logical assignment. Explicitly selected additional checks and challenges are
preserved. The requirements version advances, making earlier acceptance stale.
An authorized requirements amendment can change current obligations or delegate
authority; ownership alone cannot. The next publication reapplies the retained
templates. Generic work without `factory` keeps explicit policy selection.

A revoked or ineligible reviewer does not prevent retention of an output.
Acceptance explains the pending obligation. Independence still prevents the
actual producer from claiming or answering the check. The operator can use
ordinary review reassignment and authority recovery; no process timeout grants
that authority. Advisory challenges do not become required automatically.

### Open retained native state

Before installing a release that changes native work storage, stop the affected
factory roles and other Coord writers. Preserve the instance root, role homes,
checkpoints, source trees and retained artifacts. Install matching host and
guest executables before resuming those roles.

The current store uses native schema 10. Bootstrap transactionally upgrades the
retained native schema 5 work projection to admit cancellation and fences
schema 5/6/7/8/9 writers before storing reviews, requirements, decisions,
execution assignments or selected Factory policy. It preserves
claim IDs and generations, immutable revision bytes, operation receipts,
attention, outbox rows and retained messages. A failed upgrade rolls back. An
older executable refuses schema 10; do not run mixed writers or overwrite the
store to make an older executable start. Unsupported implementation generations
remain refused.

A retained target without an output publication has no inferred producer or
execution outcome. Its holder can publish an attributed output under its current
claim and target generations. Earlier successful operation retries still return
their original receipts. Check current state separately before acting on a
recovered receipt, and inspect uncertain external effects before any repeat.

## Raise a material signal

The [signal walkthrough](coord-operations.md#raise-a-material-signal) covers
creation, observation and resolution. Signal references are opaque strings
and are never fetched. An optional `work_id` must identify work in the same room.

On the owning host account, select existing room `chat` and configured member
`bob`. If Bob's paging permission comes only from his manual grant, the following
command removes it while preserving signal creation. Other valid approved
permission sources remain effective:

```sh
safeyolo --root "$HOME/.safeyolo" coord grant chat bob send receive
```

The change affects future pages. Existing pending signals remain pending.
An identical current blocker or decision from the same author deduplicates
to the existing signal, even with another operation ID. A room permits at
most five new pages per author and 20 total pages in 60 seconds. Excess claims
are stored with `page_status=rate_limited` and `needs_operator=false`.
Permission-denied pages likewise retain the claim with
`page_status=permission_denied`. Granting permission later does not page an
older claim automatically.

Watch reads bounded metadata pages, then fetches each exact immutable revision
through the administrative application programming interface (Admin API). Audit
JSON Lines (JSONL) contains signal identity, kind, author, basis, revision, state
and hash;
it contains no summary or refs. `watch --jsonl FILE` and
`coord watch --jsonl FILE` fetch the revision named by each signal event from
the selected running instance. Historical revisions are labelled as revisions,
not current pending claims. Terminal controls are escaped. Markup is displayed
as text.

An author corrects their own claim by creating a `correction` with
`supersedes={"signal_id":"the prior signal ID","expected_revision":1}`.
The prior signal's current projection becomes `superseded`; its original
revision remains readable through `read_signal` with `revision=1`.
A peer or a replacement durable identity cannot supersede that author's claim.
Current lists omit resolved and superseded claims by default. Use
`list_signals` with `state=all`, or read an exact revision, to inspect history.

Choose an operation ID before writing. An identical retry returns its original
result while current room authority remains valid. Changed input under the same
ID conflicts. Correction expectations and resolution expectations refer to the
current revision, not the creation revision. Each changed signal revision,
current projection, operation outcome and metadata audit event commits in one
SQLite transaction. A correction updates both claims in that transaction.

Summaries permit 1–1024 UTF-8 bytes. References permit at most 16 strings of
1024 bytes each. The complete mutation permits at most 32768 bytes. Unknown
fields and unrecognised kinds or bases are refused. Lists contain at most 100
items and 65536 bytes of items per page, ordered by `signal_id`. Follow
`next_after`; pages do not share a snapshot. Room state includes bounded
`signals` and `needs_operator` pages with counts and continuation values.

## Observe messages and harness events

Watch renders ordinary messages and published Codex/Pi session, turn, reasoning,
tool, usage, stderr and supervisor events. Tool summaries show routing arguments;
they do not dump tool request bodies or results. Unknown events appear with
`--show-unknown`. Oversize summaries retain the omitted-middle marker.

Text is complete by default. `--max-text COUNT` limits rendered text only.
`--history COUNT` selects the retained tail; `--once` prints it and exits.
`--since SEQUENCE` reads every message after the selected cursor. A live watcher
retains its rendered cursor during NATS reconnection and reports loss/recovery.
Terminal controls are shown as visible text in chat, rendered and raw modes.
Bidirectional text controls are also named visibly.

`--raw` displays message bodies without event summarization. `--json` emits
canonical envelopes and exact payloads as JSONL, with controls JSON-escaped.
`--redact` optionally hides common credential patterns and URL queries in each
mode; stored messages are unchanged. `--no-color` or `NO_COLOR` disables color.
`coord watch --jsonl FILE` renders a local harness JSONL stream; use `-` for stdin.

`--compact` selects a concise transcript. It shows
`$` for commands, `@` for tools and Coord receipts, `#` for agent text and
lifecycle events, `>` for canonical operator messages, and `!` for failures.
The operator marker comes from the Coord envelope. In a terminal, each wrapped
body continuation carries a gutter, including with color disabled.
Matching successful completions do not
repeat their start line. A completion whose start precedes the selected history
is still shown. Failed commands include a redacted final output line. Compact
mode also shows file-change totals, short token counts and successful skill-file
reads. A file-read line confirms the read, not that the agent followed the skill.
Use `--plain` as an alias for `--no-color`. Raw, JSON and compact modes are
mutually exclusive.

The installed `bin/watch-backlog-factory` wrapper opens the existing Relay,
Forge and Lens rooms in three tmux panes. Run it inside your operator tmux
session. Set `SAFEYOLO_FACTORY_CONFIG_DIR` to the instance root first.
Its default CLI is that root's `bin/safeyolo`; `SAFEYOLO_FACTORY_CLI` can select
another installed executable. `SAFEYOLO_FACTORY_NATIVE_CONFIG` can select a
different configuration file. The wrapper starts observers; it does not
start or resume a factory. Its panes select `--compact --redact`, show unknown
events, and cap rendered text at 600 characters with `--max-text 600`.

## Request an optional catch-up narrative

On the owning host account, select an existing room (`chat` here) in the
instance. The proxy must be running. Use a host directory where you can save
the catch-up files. The command below shows current canonical state without
running a model or reading the transcript:

```sh
safeyolo --root "$HOME/.safeyolo" coord catch-up chat
```

To generate a narrative, export the bounded request below. Redirection creates
or overwrites `catch-up-input.json` in your current directory. The file contains
room data. Give that file to an already authorized model through its existing
text interface. Request only the JSON response described by `output_example`.
The model needs no Coord tools or mutation permissions. Save its returned JSON
as `catch-up-summary.json` in your current directory.

```sh
safeyolo --root "$HOME/.safeyolo" coord catch-up chat --prompt > catch-up-input.json
safeyolo --root "$HOME/.safeyolo" coord catch-up chat --summary catch-up-summary.json --evidence
```

The second command reads fresh canonical state first. It then displays a
visibly derived narrative and its cited sources. Each assertion requires text
and at least one source from the request: `state:<SHA256>` identifies the exact
canonical projection, and `message:<SEQUENCE>` identifies a retained message in
that room and instance. The response must repeat the request's `room_id` and
`origin_instance_id`. References to another instance or room are rejected.
Evidence reads use the selected instance and current room permissions.
`--evidence` shows each available source with its original structured
attribution. Message bodies remain historical author claims. External links
and model text are never fetched or executed.

Citations do not establish that the narrative is correct. If a narrative
contradicts ownership, completion or acceptance, the canonical state displayed
first takes precedence. If the state digest changed, the command marks that
source unavailable; retain the original input to inspect the earlier
projection. Missing, expired, deleted or inaccessible message evidence is also
marked unavailable. The command never substitutes a nearby sequence.

The default request selects the last 100 sequence positions without replaying
the full transcript. `--max-messages` accepts 1 through 200. History contains at
most 256 KiB of item JSON, with message bodies excerpted at 4096 UTF-8 bytes.
Original body sizes, excerpt flags, earlier omissions and continuation values
remain visible. Current state retains its existing bounds. State and history
are separate reads, not one atomic snapshot. A history failure produces an
explicit unavailable result with current state still present.

For an older or longer interval, select its starting sequence with `--since`
and follow `history.next_cursor` while `history.has_more` is true. Summarize
these bounded chunks in the chosen model, preserving original source
references in every combined assertion. Collaborating agents do not need to
load those chunks. This example starts at the retained beginning:

```sh
safeyolo --root "$HOME/.safeyolo" coord catch-up chat --prompt --since 0 --max-messages 200
```

Summary input is limited to 65536 UTF-8 bytes, 32 assertions, 4096 bytes per
assertion, eight sources per assertion and 64 distinct sources. Missing sources,
unknown fields and invalid formats are rejected. Model output is inert text,
with terminal controls made visible and every physical line kept inside a
gutter. Generation, import and regeneration never create messages, claims,
targets, attestations, acceptance or other operational changes. SafeYolo stores
no summary and launches no model for this command. If generation or import
fails, use `coord status` normally; an import failure still leaves the fetched
canonical state visible.

## Inspect room capabilities and resource leases

On the owning host account, use an existing room and configured agent in the
selected instance. Start that instance's proxy before reading state. The
following examples use room `chat`, agent `bob` and the
public collaboration label `rundeck:acceptance_runner`:

```sh
safeyolo --root "$HOME/.safeyolo" coord inventory advertise-capability chat bob rundeck:acceptance_runner --operation-id chat-bob-runner
safeyolo --root "$HOME/.safeyolo" coord inventory advertise-resource chat rundeck acceptance_runner
safeyolo --root "$HOME/.safeyolo" coord state chat
```

Advertising selects room visibility. It does not grant service access. A member's
`verified` list contains only advertised labels that match current host service
grants and the active gateway policy. A saved, rejected policy edit cannot
create verified authorization. Revocation removes a label on the next state
read. An agent can replace its expiring `declared` skills through
`declare_capabilities`; those declarations
cannot create verified authorization or availability. The Agent application
programming interface (Agent API) and MCP expose the same projection to
receive-authorized members.

A trusted provider integration must atomically replace
`<root>/coord-providers/<provider>.json` with public observations from that
provider. Keep the directory outside agent-writable mounts. Coord only reads
these observations; writing a JSON file does not establish provider provenance.
The file contains `capabilities` and `leases` arrays. Capability observations
identify `agent_id`, `capability` and `availability` (`available` or
`unavailable`). Lease observations identify `resource`, `state` (`held` or
`unleased`) and `holder_agent_id` (a current room member for `held`, null for
`unleased`). Each observation contains integer Unix-millisecond `observed_at`
and `valid_until` timestamps. Fresh evidence requires
`observed_at <= now < valid_until`, with at most five minutes between the
timestamps. Do not put credentials, accounts, connection configuration or raw
errors in this file.

Only fresh provider evidence can establish availability or lease ownership.
Missing, failed, malformed or expired evidence produces `unknown`. An expired
observation retains its timestamps and reports `freshness: "stale"`. Coord does
not renew or transfer provider leases. Chat cannot change their holders. State
reads select advertised provider filenames without registration, including
after restart. Each file is limited to 512 KiB and 1,024 observations. Reads
have a one-second deadline, a process-wide limit of 32 in flight and a limit
of two per provider. A blocked file cannot consume the executor used for room
authorization reads.

To stop sharing a label, use `unadvertise-capability ROOM AGENT LABEL` or
`unadvertise-resource ROOM PROVIDER RESOURCE` with the same command prefix.
Advertisement changes accept an optional `--operation-id ID`; an identical retry
returns the original result, while changed input under that ID conflicts.
They use the existing atomic operation ledger and audit outbox. Raw provider
payloads and errors are never returned in room state or those audit events.

## Collaborate through a home SafeYolo

Each room has one home SafeYolo. Remote agents use that home's canonical
messages, memberships, work, briefs and attention. Reconnection reads the home;
it does not merge independent records. Delegated [peer support](peer-support.md)
uses the same transport without requiring a room.

Run setup as the trusted host account on each separately initialized instance.
Keep each instance's root, runtime and writable administration files separate,
including when both instances run on one host. The examples use destination B
at `/srv/home-safeyolo` and source A at `/srv/peer-safeyolo`. Replace `sy-HOME`,
`sy-PEER` and `ag-BOB` with the actual instance and source agent IDs. The remote
agent must have a current sandbox run authenticated by A's local ingress.

B's operator must select a reachable NATS listener address and port. Obtain a
Transport Layer Security (TLS) certificate and key through the existing trusted
host setup. The certificate must cover B's external broker name and the name
used by B's local clients. Install the public certificate authority (CA) file
on both hosts. Do not infer permission for a new listener or network route from
existing SSH access. Keep credentials, certificate keys, instance roots and
broker configuration outside guest-writable mounts.

On A's host, create a private peer credential:

```sh
/srv/peer-safeyolo/bin/safeyolo --root /srv/peer-safeyolo coord federation credential /srv/peer-safeyolo/federation-secret
```

Transfer a private copy to `/srv/home-safeyolo/peer-secret` on B. B records A's
transport trust through its own CLI:

```sh
/srv/home-safeyolo/bin/safeyolo --root /srv/home-safeyolo coord federation trust sy-PEER /srv/home-safeyolo/peer-secret
```

On B, save `coord-federation.json` in B's root. This example selects all host
interfaces and a certificate covering `home.example.test` and `localhost`.
Use an explicitly authorized listener address for the actual host.

```json
{
  "listen": "0.0.0.0",
  "cert_file": "/srv/home-safeyolo/home-cert.pem",
  "key_file": "/srv/home-safeyolo/home-key.pem",
  "ca_file": "/srv/home-safeyolo/home-ca.pem",
  "local_server_name": "localhost",
  "peers": [{"instance_id": "sy-PEER", "credential_file": "/srv/home-safeyolo/peer-secret"}]
}
```

Stop B's owned proxy and Coord before changing broker setup. Start Coord with
B's selected client port, then start B's proxy through its ordinary owned
lifecycle. For example, if port 7443 is authorized:

```sh
/srv/home-safeyolo/bin/safeyolo --root /srv/home-safeyolo coord start --client-port 7443
```

The managed NATS client listener now requires TLS. B's local clients use the
recorded CA and certificate name. The proxy serves defined Coord and support
operations in the separate `SY_FED` account. Each peer credential can publish
only that peer's source request subject. It can receive its own replies,
notices and selected JetStream consumer delivery. It cannot publish or subscribe
to unrelated private subjects or use arbitrary JetStream administration.
No imports or exports connect the private local account to `SY_FED`.
The native runtime uses `SY_LOCAL` for private streams both with and without
federation. There is no inter-instance HTTPS listener or HTTPS fallback.

On A, configure B's durable identity, TLS NATS endpoint, public CA and A's
host-held credential:

```sh
/srv/peer-safeyolo/bin/safeyolo --root /srv/peer-safeyolo coord federation home primary sy-HOME tls://home.example.test:7443 /srv/peer-safeyolo/home-ca.pem /srv/peer-safeyolo/federation-secret
```

A connects outbound to B's broker. A needs no application listener to receive
B's notifications. This topology supports separate roots on one host and hosts
with authorized connectivity between them. A leaf-node or full-mesh topology
is not required. NATS [accounts](https://docs.nats.io/learn/security/accounts-and-multitenancy)
and [subject permissions](https://docs.nats.io/learn/security/authorization)
provide the broker boundary; B still checks every operation against its own
current authority.

For room participation, B grants the qualified remote identity ordinary room
permissions. In this example `shared` already exists on B:

```sh
/srv/home-safeyolo/bin/safeyolo --root /srv/home-safeyolo coord federation member shared sy-PEER ag-BOB remote-bob --operation-id grant-remote-bob
```

Trust alone grants no room or target access. Omitting membership permissions
grants `send`, `receive` and `page_operator`, as for local membership. An explicit
list replaces that set. `member` and `unmember` retain the membership operation
ID retry contract. The display handle must differ from local names and handles
held by another identity with active room or support grants. Renaming a handle
does not rebind the qualified identity. Reusing an inactive handle does not
change old authorship, work history or operation replay.

Bob uses ordinary tools through A's authenticated local Agent API. Set `home`
to `primary` for remote operations, for example:

```json
{"room_name":"shared","home":"primary"}
```

The same selection applies to room tools, support tools and attention tools.
Omitting `home` selects A. Approvals and service credentials remain local.
`read_github_work` reads B-owned work and then uses the caller's own GitHub
grant, rechecking B's room access before disclosing external metadata.
Remote envelopes retain authenticated source instance and agent IDs alongside
B's qualified principal. Agent-authored body text cannot choose those fields.

For several sources, use `wait_for_coord` with each source's durable instance
ID and position. Use zero only for a source with no retained caller position:

```json
{
  "sources": [
    {"instance_id":"sy-PEER","since_sequence":0},
    {"home":"primary","instance_id":"sy-HOME","since_sequence":0}
  ],
  "limit":20,
  "timeout_seconds":60
}
```

Each result identifies its owning instance, availability, resolved objects and
next cursor. Advance only that source's returned cursor after processing its
objects. An unavailable source keeps its old cursor; another source can return
work. `waiting` means the call returned for another source before this source
finished. There is no global order across sources. An alias changed to another
instance cannot inherit the previous instance's cursor. Reconnection resolves
B's retained references under current rights. JetStream retains wake hints;
B's canonical attention ledger and operational owners retain the actual facts.
Removing delivery authority withholds new evidence; it cannot retract data
already delivered.

After a lost mutation reply, inspect B's canonical outcome. Retry a durable
mutation only with its original operation ID and inputs. Inspect room history
before repeating an uncertain send. Support receipts never silently rerun an
arbitrary guest command. A source run replacement prevents new input from the
old run. A command already admitted by B retains its original source identity
and can continue through a partition or source restart. Loss of connectivity
does not establish cancellation or target death.

Notification or JetStream failure alone does not block permitted Core NATS
support requests while B's policy, canonical and runtime owners work. If Core
NATS is unavailable, remote control is unavailable. Use B's existing local
owner-side API or CLI to recover the transport where those controls work.

On B, revoke one membership or all peer trust:

```sh
/srv/home-safeyolo/bin/safeyolo --root /srv/home-safeyolo coord federation unmember shared sy-PEER ag-BOB --operation-id revoke-remote-bob
/srv/home-safeyolo/bin/safeyolo --root /srv/home-safeyolo coord federation revoke sy-PEER
```

Peer revocation disables authentication and revokes memberships atomically.
Old requests cannot acquire a later trust generation. Re-trust restores neither
revoked room membership nor old target grants. Preview a new support grant
against current trust when restoring that authority. On A, `coord federation
unhome primary` removes the route and withholds replies already in flight.

## Schedule an operator message

Use a host scheduler when a message must be sent while the target sandbox is
stopped. This recipe runs as the trusted host account that owns the instance.
Its proxy and Coord must be running; the target guest may be stopped.
First create the room and grant its intended recipient through the
[room setup procedure](coord-operations.md#prepare-the-room-and-its-members).
The example uses room `scheduled-work` and recipient `alice`.

On that host, create `~/scheduled-coord-message.txt` with the intended UTF-8
message. Keep the file and wrapper in host-owned paths outside agent-writable
mounts. Create `~/bin/post-scheduled-coord` with this content and make it
executable. Replace `/absolute/instance` with the selected instance path before
running it:

```sh
#!/bin/sh
set -eu
exec /absolute/instance/bin/safeyolo --root /absolute/instance coord send scheduled-work --file "$HOME/scheduled-coord-message.txt" --to alice --content-type text/plain
```

On a Linux host with cron already running, use the owning account's
`crontab -e` to add an entry in Coordinated Universal Time (UTC). Replace
`/absolute/operator-home` with that account's home. This entry runs every day
at 09:00 UTC when the host timezone is UTC; check `date '+%F %T %Z'` first.

```cron
0 9 * * * /absolute/operator-home/bin/post-scheduled-coord >>/absolute/operator-home/scheduled-coord.log 2>&1
```

On macOS, the same wrapper can be invoked by an operator-maintained LaunchAgent
or the host account's existing cron setup. Use that scheduler's timezone and
missed-run rules. No automatic wake or guest start is provided. History must
show `sender_kind=operator`, with no agent identity. Check the log and retained
message after execution; do not repeat an uncertain send without checking
history. This recipe gives guest jobs no host scheduler or operator credentials.

## Runtime files and credentials

The current runtime resolves Coord under the selected configuration's `data_dir`.
For the default instance this is `$HOME/.safeyolo/data/coord`. Select the
instance with `--root` and its configuration.

SafeYolo creates the Coord directory with mode `0700`. Its managed NATS runtime
reuses `nats/creds` across ordinary stop/start cycles. When that file is absent,
startup creates it with mode `0600`. Generated `nats/server.conf` is also mode
`0600` and contains the NATS password. Keep both files private; do not print,
copy into a command line, attach or log their contents. The runtime keeps
retained JetStream data separately in `nats/jetstream` and canonical room state
in `v0.db`. Preserve those stores during diagnosis.

Federation adds host-held `coord-federation.json`, the private responder
credential `nats/federation-creds`, and generated local TLS settings. The
generated server configuration also contains the selected peer passwords.
Protect these files with the same ownership and mount boundaries. The recorded
peer credential digests bind the running broker configuration to current trust;
changing a credential file alone does not rotate an existing broker connection.
Restart the owned broker and proxy after changing this setup.

Status, doctor and lifecycle diagnostics provide health information without
printing the credential. File modes protect against other host accounts;
they do not protect a compromised owning account from its own files. Recover
that account and host after suspected compromise.

### Coord upgrade recovery

Before upgrading an existing instance, stop its owned proxy and Coord. Use the
updated CLI to start Coord before restarting the proxy. Keep the existing
instance root, `v0.db`, NATS credentials and JetStream store together.

The previous generated NATS configuration stored private streams in the global
account, `$G`. At startup, SafeYolo moves that account directory to `SY_LOCAL`
while the broker is stopped and the runtime lock is held. This is an atomic
directory rename on the existing filesystem. NATS places these accounts under
`nats/jetstream/jetstream/`; the repeated directory name is intentional. Messages,
stream sequences and consumer positions remain in their original files. SQLite work, attention
references and cursors are not rewritten. The move applies with federation
disabled or enabled. `SY_LOCAL` and `SY_FED` remain separate roles inside each
independently owned broker; this does not configure a shared broker or bridge
private local traffic.

If activation fails or the startup process exits before activation, preserve
the stores. Correct the reported startup error, then repeat `coord start` with
the updated CLI for the same root. Startup accepts the complete account at
either the previous or current path and resumes the move if necessary. It does
not create a replacement for the previous account or replay room mutations.
Inspect the owned NATS log when the broker fails to start. Before restarting,
stop any surviving owned broker through the existing lifecycle; do not start a
second broker against the same store.

If both `$G` and `SY_LOCAL` account stores exist, startup reports the conflict
and leaves both unchanged. Preserve both accounts and their paired `v0.db`;
do not delete, reset or overwrite either account to clear the error. Inspect
each account with its matching stopped-instance configuration to determine
whether both contain retained data. This correction does not merge independently
created account histories. To roll back the account move before accepting new
operations, stop the owned proxy and Coord, then rename `SY_LOCAL` back to `$G`
only when `$G` is absent, and restore the previous CLI and generated
configuration. Keep the same SQLite database and credentials. Never overwrite
an existing account during rollback.

## Focused proof and remaining work

For developers with the repository's acceptance tooling, these drivers exercise
different boundaries:

- `tests/proxy_contracts/test_native_coord_operator.py` runs installed CLI input,
  pseudo-terminal (PTY) drafts, publication-count and observer scenarios against
  disposable NATS. Only the test driver uses Python.
- `tests/nested-linux/operator_coord_acceptance.py` uses an already running
  disposable installed proxy and Ubuntu systrap guest. Supply their root,
  guest name and exact commit with `--root`, `--agent` and `--commit`. The matching
  guest helper must be staged at `/home/agent/.safeyolo/safeyolo-coord`. It
  observes guest send/read, guest arrival during a PTY draft, attribution and
  the room timeline, then stops that guest, proxy and Coord. Select disposable
  inputs because the driver stops them. A host-only probe does not prove this
  guest boundary.

The [responsibility map](settings.md#operator-entry-responsibilities) retains
installed exchange and physical Apple Virtualization framework observations
at their actual driver/package revisions. Use the same installed CLI for
[Dispatch period requests](dispatch-publication.md),
[generation/site validation](dispatch-generation.md), and
[Mattermost exchange and semantic actions](coord-mattermost.md).
