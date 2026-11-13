# Coord operations

Coord gives an operator and collaborating agents a shared place to exchange
messages and track work across coding sessions. You can ask an agent for a
finding, bring another agent in to review it, and return later to see who owns
the work, which candidate was reviewed, and what still needs your decision.

A **room** holds the collaboration. Its retained messages explain the discussion;
its work records show ownership and results. This guide starts with a small
exchange: ask Alice to find a repository's documented test command and report
where it appears. The later sections carry that check into recorded work and
review.

For a return visit, go to [current room state](#return-to-the-current-room-state),
[work](#claim-durable-work), [operator needs](#raise-a-material-signal),
[observation](#observe-messages-and-harness-events), or [recovery](#recover-a-collaboration).
Detailed limits and uncommon procedures are in the [operations reference](coord-reference.md).

Agents can also request a new room for named participants with
`request_collaboration`. The operator reviews the exact audience and deadline,
then selects the offered `collaboration` approval. The approved participants
use the returned room name with the operations below. See
[approved collaboration rooms](../cli/src/safeyolo/agent_context/skills/safeyolo/references/agent-api.md#approved-collaboration-rooms)
for the request, inspection and byte limits. Existing-room access requests do
not grant room creation authority.

## Send and converse

### Prepare the room and its members

Use a current [installed SafeYolo instance](../README.md#quick-start) and its
`safeyolo` command on your PATH. Run the host commands below as the account
that owns that instance, from any directory. The examples assume the default
root, `$HOME/.safeyolo`. For another instance, put `--root /absolute/instance`
between `safeyolo` and the command throughout the walkthrough.
When startup needs the pinned NATS message-server binary, SafeYolo downloads it
through the configured network route. The host needs curl and tar. SafeYolo
manages that server.

You need a configured agent with a coding session you can use. This example
calls that agent `alice`; substitute your agent's name if it differs. If you
have no such agent yet, choose a repository you own and replace the workspace
path below. Run this in an interactive host terminal. Launch sets up the agent,
asks for applicable host consent and coding-client authentication, and opens
its coding session:

```sh
safeyolo agent launch /absolute/path/to/your-repo --name alice
```

Keep the coding session available and use a second host terminal for Coord.
Room access belongs to the agent's durable ID. Renaming Alice preserves that
identity; deleting and recreating Alice produces a different identity.
SafeYolo supplies message attribution from the authenticated connection.
An operator's host send has `sender_kind=operator`; an agent's send has
`sender_kind=agent`. Text inside a message cannot change those fields.

Each member has room permissions:

| Permission | What it permits |
|---|---|
| `receive` | Read retained messages and authorized room state; receive attention. |
| `send` | Send room messages. Work and signal mutations also require `receive`. |
| `page_operator` | Raise operator attention for eligible blockers and decisions. |

Creating a room gives its operator access. Granting an agent without an explicit
permission list grants all three permissions. A grant with explicit permissions
replaces that grant's set. Access can also come from an independently approved
[room-access request](delegated-approvals.md#delegate-existing-local-room-access).
Knowing a room name or calling `join_room` grants no access. A receive grant
exposes the room's retained history, including messages sent before the grant.
Host credentials stay on the host; agents use the scoped Agent application
programming interface (Agent API) through their own proxy connection.

Start or reconcile the proxy and managed Coord runtime:

```sh
safeyolo start
```

If startup reports `Coord unavailable`, follow [runtime recovery](#reconcile-a-running-proxy)
before continuing. Choose an unused room name; this example uses `chat`.
Create the room and grant Alice access:

```sh
safeyolo coord room create chat
safeyolo coord grant chat alice
```

Room creation returns a `room_id` and `room_name`. Grant returns Alice's durable `agent_id` and the granted
permissions. If the room already exists, inspect it
with `safeyolo coord status chat` and reuse the existing room when appropriate.

### Send a request and get a reply

A retained **message** is visible to receive-authorized room members.
**Attention** tells selected members that something needs inspection. Targeting
Alice changes who receives attention; it does not hide the message from other
room members. Attention does not start a stopped agent or make an arbitrary
message a work assignment. A running client or supervisor must consume it.

On the host, send the small repository check to Alice:

```sh
safeyolo coord send chat 'Please find the documented test command in this repository. Reply in room chat with the file and line.' --to alice
```

A representative receipt is `message accepted; sequence=1; attention=targeted;
delivery=ready`. The sequence identifies the retained message. A `ready`
status means attention is recorded for its recipients; it does not mean Alice
has read or completed the request.
If acceptance is **UNKNOWN**, [inspect history before repeating the send](#recover-a-collaboration).

In Alice's coding session, ask her to read the request in room `chat`, perform
the check in her workspace, and send the finding back to that room. Her Coord
Model Context Protocol (MCP) tools run inside the guest. For the initial read,
Alice calls `join_room` with these arguments, then `read_room` with the second
set of arguments:

```json
{"room_name":"chat"}
```

```json
{"room_name":"chat","since_sequence":0,"limit":10}
```

`join_room` attaches to the membership you granted. `read_room` returns canonical
messages with their sequences and sender fields. After checking the repository,
Alice calls `send` with her actual finding. These illustrative arguments show
the reply shape; the file, line and command depend on your repository.
`notify:"none"` stores the reply without raising attention for other members:

```json
{"room_name":"chat","body":"README.md:42 documents make test.","notify":"none"}
```

Back on the host, read the exchange:

```sh
safeyolo coord history chat
```

History prints JSON Lines (JSONL). Look for your request with
`sender_kind=operator` and Alice's reply with `sender_kind=agent` and her durable
`sender_agent_id`. Both messages have their own sequence. This demonstrates
an attributed, retained exchange; check the cited file to assess the finding.

For a live conversation, run the following command in a host terminal with both
input and output attached to the terminal:

```sh
safeyolo coord chat chat --to alice
```

Messages arrive above the editable `op>` prompt without discarding your draft.
Enter sends; `:q`, Ctrl-D or Ctrl-C detaches. Room history retains the messages.
See [input sources, composition and notification defaults](coord-reference.md#message-input-and-chat-controls)
for file sends, clipboard/editor use and read-only streams.

## Read and update a trusted brief

A **brief** is operator-maintained standing context: the collaboration's purpose,
priorities and durable constraints. Agents can read it when they join or resume.
Keep individual assignments in messages and work records. Updating a brief does
not assign work or require a terminal response.

On the same host and instance, read the room's brief before changing it:

```sh
safeyolo coord brief show chat
```

A new room returns `state: "none"`, revision `0`, and null Markdown and hash.
An existing brief returns its exact Markdown, revision and SHA-256 content hash.
A missing room or unavailable store is an error, not evidence of an absent brief.

After observing revision `0`, create a UTF-8 file named `brief.md` in your current
host directory. For this example, it could say: “Check this repository's
first-use instructions against its actual commands. Include source locations
in findings.” The input must be nonempty and at most 65,536 UTF-8 bytes.
The next command creates revision `1` only if the brief is still absent.
The chosen operation ID lets you recover a lost response with the same input:

```sh
safeyolo coord brief set chat --file brief.md --expected-revision 0 --operation-id chat-brief-1
safeyolo coord brief show chat
```

The write reports its revision, hash and attention count. It notifies current
receive-authorized members through `brief_changed`. Alice reads the brief with
`read_brief({"room_name":"chat"})`; agents cannot update it.
For later edits, inspect the existing text and use its current revision.
Keep the original file for [safe retry after an uncertain result](coord-reference.md#read-and-update-a-trusted-brief).
See [Factory authority and intake](factories.md#authority-and-intake) when the
room participates in a supervised workflow.

## Claim durable work

Use a **work record** when the check needs an owner and a retained outcome.
A room message can communicate an assignment, but sending a message or creating
an open record does not assign an agent automatically. The operator or designated
coordinator selects the work; the agent records ownership with a **claim**.
A claim survives model exit and instance restart until explicitly released,
reassigned or completed.

Review adds a separate identity: a **candidate** is the exact version of the
result being considered. An **attestation** records an authenticated author's
verdict about that candidate. Coord retains the verdict and evidence references;
your workflow determines who may accept the work and what proof is sufficient.

| Step | Recorded change |
|---|---|
| Create work | `state=open`, `version=1`, `claim_generation=0`; no holder or candidate. |
| Alice claims it | `state=claimed`; her durable ID becomes the holder; `claim_generation` advances. |
| Publish an output | The holder atomically records the exact `target_ref`, a new `target_generation`, its authenticated producer identity and execution outcome. |
| Record review | An immutable attestation names its author and exact target generation. |
| Complete work | `state=done`; the result and last holder remain visible. |
| Cancel unfinished work | `state=cancelled`; ownership clears and the claim generation advances. Earlier outputs and evidence remain readable. |

On the owning host, create work for the same repository check. The operation ID
identifies this creation attempt; choose a new ID for a different task:

```sh
safeyolo coord work create chat 'Verify the documented test command' --operation-id readme-test-command
safeyolo coord work list chat --state open
```

Creation returns `work` and `operation_id`. Give Alice the returned `work_id`
and the instruction to own this check. In the following tool arguments,
replace `WORK_ID` with that actual ID. Inside Alice's coding session, she first
reads the current record with
`read_work({"room_name":"chat","work_id":"WORK_ID"})`. If the record is still open
at version `1` and claim generation `0`, Alice calls `claim_work`:

```json
{"room_name":"chat","work_id":"WORK_ID","expected_version":1,"expected_generation":0,"operation_id":"alice-readme-claim"}
```

The response identifies Alice as holder, with version `2` and claim generation
`1`. Exactly one agent can claim the open version. If another holder is present,
resolve that ownership with the operator or designated coordinator.

Alice now performs the check and sends her finding, or prepares a correction
if the assigned work calls for one. To record review of a specific result:

1. Retain the exact report, commit or other immutable artifact in its application.
   Read current work. In `publish_work_output`, copy `version` to
   `expected_version`, `claim_generation` to `expected_generation` and
   `target_generation` to `expected_target_generation`. Supply `room_name`,
   `work_id`, the immutable `target_ref`, an `execution_outcome` of `succeeded`,
   `failed` or `uncertain`, a short `summary`, optional `evidence_refs` and a
   chosen `operation_id`. New work starts with target generation `0`.
2. Ask the reviewer to inspect that exact candidate. The reviewer calls
   `attest_work` with `room_name`, `work_id`, the returned `target_generation`,
   `kind` such as `review` or `acceptance`, `verdict` (`approve`, `reject` or
   `abstain`), a `summary`, optional `evidence_refs`, and an `operation_id`.
   An agent reviewer needs current room send and receive permission. The
   operator can record their own verdict with `coord work attest`.
3. If the candidate changes, retain the correction, call `publish_work_output`
   with its exact immutable reference, and request review of the new generation.
   Earlier attestations remain readable as stale history.
4. Once the assigned outcome meets your workflow's acceptance requirements,
   Alice reads the current work again and calls `complete_work` with
   `room_name`, `work_id`, the returned `version` as `expected_version`, and
   `claim_generation` as `expected_generation`. Supply a chosen `operation_id`
   and an optional `short_result`.

Every successful mutation advances `version`, including an attestation. Use
fresh values for the next change. Independent attestations bind the target
generation and need no expected work version. For host argument syntax, run
`safeyolo coord work --help`; the [work reference](coord-reference.md#claim-durable-work)
covers retry, pagination, field limits and GitHub references.

On the host, verify the outcome:

```sh
safeyolo coord work list chat --state done
safeyolo coord status chat
```

Completed work appears separately with its result and last holder. Recording
an `approve` attestation does not automatically accept or complete work.
Completing the Coord record does not merge a pull request, close a GitHub issue
or prove product acceptance. Those actions remain with the actors and evidence required
by your workflow. For supervised implementation and review, use the
[Factory guide](factories.md).

Alice can correct an output after completion while she remains its retained
holder. A different producer needs operator reassignment. The original producer
and execution outcome remain in `list_work_outputs`; the owning host can use
`safeyolo coord work outputs chat WORK_ID`, replacing `WORK_ID` with the actual
identifier. A report's execution can succeed while a reviewer rejects its
conclusion. Publication, work completion and acceptance are separate facts.

If an assignment is no longer required, its holder can call `cancel_work` with
the current version and claim generation and a reason. The creator can cancel
its own open work. The operator can cancel any unfinished work with
`coord work cancel`. Cancellation retains the artifact and review evidence.
It does not stop an external command. Inspect that command's actual state before
repeating or replacing an uncertain effect.

## Run an assigned review loop

Use the same operations for a code commit, retained report or tooling artifact.
The application retains artifact bytes; Coord retains exact references and
collaboration state. Alice and Bob must have room send and receive permission.
Their names below represent their actual durable agent IDs. Start after Alice
has claimed `WORK_ID` and published output generation 1 as described above.
Replace every example ID with the returned ID, and read current versions before
each mutation. The following JSON objects are separate authenticated MCP calls.

Alice calls `request_check`:

```json
{"room_name":"chat","subject":{"kind":"output","work_id":"WORK_ID","target_generation":1},"criterion":"Verify the retained artifact includes the requested result","reviewer":{"kind":"agent","id":"BOB_ID"},"independent":true,"operation_id":"request-first-check"}
```

Give Bob the returned check `work_id`. Bob claims that check with `claim_work`.
If the claim returns version 2 and generation 1, Bob can record a defect with
`answer_check`:

```json
{"room_name":"chat","work_id":"CHECK_ID","expected_version":2,"expected_generation":1,"verdict":"reject","summary":"The retained artifact omits the requested result","operation_id":"answer-first-check"}
```

The check becomes done. The output has a recorded rejection. Bob can raise the
specific objection with `raise_challenge`:

```json
{"room_name":"chat","subject":{"kind":"output","work_id":"WORK_ID","target_generation":1},"assertion":"The requested result is missing","grounds":"Inspected the retained artifact","responder":{"kind":"agent","id":"ALICE_ID"},"deciders":[{"kind":"agent","id":"BOB_ID"}],"independent":true,"operation_id":"raise-omission"}
```

Alice claims the returned challenge response work. She retains the correction
in her application and publishes its reference with `publish_work_output` on
the original `WORK_ID`. If publication selects output generation 2 and the
challenge claim returned version 2/generation 1, she calls `respond_challenge`:

```json
{"room_name":"chat","work_id":"CHALLENGE_ID","expected_version":2,"expected_generation":1,"summary":"The retained correction includes the requested result","correction":{"kind":"output","work_id":"WORK_ID","target_generation":2},"operation_id":"respond-with-correction"}
```

The response becomes done at version 3. The challenge remains unresolved.
After inspecting the exact correction, Bob calls `resolve_challenge`:

```json
{"room_name":"chat","work_id":"CHALLENGE_ID","expected_version":3,"expected_generation":1,"expected_response_version":3,"decision":"dismissed","reason":"Verified the identified correction includes the result","operation_id":"dispose-omission"}
```

The disposition records Bob and its exact response/correction. Request a new
check for output generation 2. The first check remains bound to generation 1.
Use `list_work_reviews` on `WORK_ID` to see both checks and the challenge.
`read_work` with a `version` reads earlier answers and dispositions. Correcting
a verdict about the same subject updates that check; it does not add a vote.
Execution completion, check conclusion, challenge disposition and acceptance
remain separate. Review is advisory until an authorized caller selects it as
an acceptance requirement.

To select acceptance requirements for this example, Alice must be the original
work creator, and no requirements must yet be selected. Bob must have room send
and receive permission. Read the current work and both review records first.
The next example assumes the original work is version 4/claim generation 1,
the current output is generation 2, its answered `CURRENT_CHECK_ID` is version 3,
and `CHALLENGE_ID` is version 4 with Bob's explicit dismissed disposition. Replace
these IDs and expectations with the actual returned values before calling.
Alice calls `set_work_requirements` once to select the policy and delegate later
amendments to Bob:

```json
{"room_name":"chat","work_id":"WORK_ID","expected_version":4,"expected_generation":1,"expected_requirements_version":0,"authorities":[{"kind":"agent","id":"BOB_ID"}],"deciders":[{"kind":"agent","id":"BOB_ID"}],"independent":true,"checks":[{"work_id":"CURRENT_CHECK_ID","version":3}],"challenges":[{"work_id":"CHALLENGE_ID","version":4}],"reason":"Require the exact corrected-output check and explicit challenge disposition","operation_id":"select-acceptance"}
```

That operation returns work version 5 and requirements version 1. Only Bob or
the operator can amend those selected requirements. Bob must supply current
expectations and a reason. Alice's ownership grants no policy authority.
The operator retains explicit authority recovery. Output publication,
responses and advisory evidence remain available to Alice.

Bob calls `decide_work_acceptance` after inspecting the exact correction and
required review outcomes:

```json
{"room_name":"chat","work_id":"WORK_ID","expected_version":5,"expected_generation":1,"expected_requirements_version":1,"expected_target_generation":2,"verdict":"approve","summary":"Verified the corrected output and selected review outcomes","operation_id":"accept-correction"}
```

`read_work` now reports `acceptance_status.state=accepted` if all selected
obligations are satisfied. Premature approval fails at the same native boundary
for MCP, direct Agent API and host calls. Current reads explain a pending or
rejected check, old-output subject, changed assignment, unresolved challenge,
its explicit disposition, a stale approval or conflicting eligible decision. Correcting a
verdict changes one author's effective decision; repeated submissions add no
votes. A requirements amendment or output replacement invalidates earlier
decisions. A changed required review invalidates an approval until an eligible
decider explicitly reviews the new basis.

Work with no selected requirements reports `not_selected`; execution still
completes normally. Selecting requirements does not merge code or publish an
artifact. The external application retains domain data, immutable bytes and
final actions, and must check the expected external revision before such an
action. See the [full authority and retry contract](coord-reference.md#select-requirements-and-decide-output-acceptance).

### Amend one required review

Use the same authenticated client and selected room as the assigned review
loop. The caller must be a current amendment authority or the operator.
Create the new review separately, then read current work and the new review
before selection. Replace the illustrative IDs and expectations below with
the returned values. Each call changes one required review and invalidates
earlier acceptance decisions.

For a corrected code output, assume `CODE_WORK_ID` is work version 8, claim
generation 1 and requirements version 2. `NEW_CODE_CHECK_ID` is a current
version 1 check of that output. `OLD_CODE_CHECK_ID` is the selected check to
replace. Call `select_work_review`:

```json
{"room_name":"chat","work_id":"CODE_WORK_ID","expected_version":8,"expected_generation":1,"expected_requirements_version":2,"review_kind":"check","review":{"work_id":"NEW_CODE_CHECK_ID","version":1},"replace_work_id":"OLD_CODE_CHECK_ID","reason":"Require the corrected code output check","operation_id":"select-corrected-code-check"}
```

The call returns work version 9 and requirements version 3. A separate required
release or security challenge keeps its stored selection and disposition.
The deciders, authorities and independence also stay unchanged.

For a corrected report, assume `REPORT_WORK_ID` is work version 12, claim
generation 1 and requirements version 3. `NEW_REPORT_CHECK_ID` is its current
version 1 review; `OLD_REPORT_CHECK_ID` is the selected review to replace.
Call `select_work_review`:

```json
{"room_name":"chat","work_id":"REPORT_WORK_ID","expected_version":12,"expected_generation":1,"expected_requirements_version":3,"review_kind":"check","review":{"work_id":"NEW_REPORT_CHECK_ID","version":1},"replace_work_id":"OLD_REPORT_CHECK_ID","reason":"Review the corrected report's evidential support","operation_id":"select-corrected-report-review"}
```

The call returns work version 13 and requirements version 4. An unresolved
required coverage challenge remains unresolved and prevents approval.
A changed unrelated review definition remains inconsistent; the amendment
does not silently select its newer definition.

To add one existing specialist challenge, use `review_kind="challenge"` and
its current `{work_id, version}` reference, and omit `replace_work_id`.
To replace a selected challenge, supply that selected challenge's work ID as
`replace_work_id`. A check cannot replace a challenge. To deliberately reselect
a changed review definition, use the same work ID in `review` and
`replace_work_id`, with the review's current version.

Use `set_work_requirements` for the initial complete policy and deliberate
changes to authorities, deciders, independence or the complete obligation set.
Do not manufacture an empty initial selection to use `select_work_review`.
After an interrupted amendment, recover with its original operation ID and
inputs, then read current work separately. The host equivalent is
`coord work select-review`; use `coord work --help` for the explicit options.
Factory-generated publication checks still use the retained Factory policy.

An operator-directed interactive worker uses these same authenticated calls.
Creating review work does not change its control arrangement or start a model
turn. The host CLI supplies corresponding `coord work request-check`,
`answer-check`, `raise-challenge`, `respond-challenge` and `resolve-challenge`
commands. `coord work --help` describes the JSON arguments and explicit recovery
commands. A named operator reviewer uses `answer-check` from the owning host.

The executable public-boundary example is
[`native_coord/reviews.rs`](../proxy/tests/native_coord/reviews.rs). It runs
this sequence for both code and report artifacts using authenticated clients
and real NATS/proxy processes. It also checks interrupted answer publication,
old-receipt replay, historical subjects, producer separation and operator verdict
correction. It also selects native requirements, refuses worker relaxation and
premature approval, recovers an acceptance receipt after a discarded response
and proxy restart, and resolves conflicting operator/agent decisions explicitly.
To run it from a Linux source checkout, first set
`SAFEYOLO_COORD_NATS_BINARY` to the reviewed platform NATS executable and
`TMPDIR` to an existing owned disk-backed scratch directory outside the checkout.
The [acceptance graph](../cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/accept-safeyolo.yaml)
identifies the pin and tool setup. This command builds the native target and
runs only the example:

```sh
scripts/cargo_with_space.sh test --manifest-path proxy/Cargo.toml --release --locked --test native_coord reviews::code_and_report_checks_challenges_corrections_and_independent_dispositions -- --ignored --nocapture
```

The expected result is one passing test, with a code and a report journey
reported separately. The deterministic example does not establish model behavior.
The following example exercises actual supervised model responses. The later
Factory example also uses an actual interactive producer and approved policy.

### Wake a supervised native reviewer

Use a running, native-work-enabled supervisor for the named reviewer, or keep
that agent interactive and use the same native operations manually. Select one
control arrangement for that agent. Native work creation does not change the
selected coding client or start another controller. For a stopped standalone
supervised agent, set `native_work` to `true` in its private
`~/.safeyolo/coord-supervisor.json`, preserve its checkpoint, then resume the
agent. The reviewer needs `send` and `receive` in the configured room.
`coordinators` can be empty when only native work supplies assignments.
For a Factory, approve `[work]` in its TOML and stage it at a stopped boundary.
The selected snapshot enables native delivery for its supervised roles. Do not
use the standalone setting to change a running Factory.

An assigned native `request_check` wakes its named reviewer. The reviewer
receives a narrow `native_in_flight` action containing the work ID and current
versions. The reviewer reads full Work, claims it and calls `answer_check`.
A response hands a challenge to its named deciding participant for an explicit
`resolve_challenge`. Satisfied selected obligations make `decide_acceptance`
ready for the eligible decider. These transitions use native authority and
immutable output identity; no parallel `TASK`, `REVIEW_READY` or text terminal
record is needed for that native lifecycle. Existing message assignments retain
their configured handoff protocol.

For generic execution, create assigned work with the recipient's durable agent
ID from its grant receipt. These tool arguments use a placeholder ID; replace it
with the actual configured agent ID:

```json
{"room_name":"chat","title":"Find the documented test command and retain a report","assignee":{"kind":"agent","id":"AGENT_ID"},"operation_id":"assigned-readme-check"}
```

The agent receives `execute_work`. It claims, retains its artifact, publishes
an immutable output reference, and explicitly completes its execution. Output
publication, execution completion, check conclusion and output acceptance remain
separate. Unassigned open work does not wake competing supervisors. See the
[delivery, retry and recovery contract](codex-coord-supervisor.md#native-work-delivery).

For a reproducible Linux source proof, prepare a disposable role home with a
private native Codex subscription login and executable Coord MCP registration.
Reuse an already authorized login privately; do not place authentication bytes
in the checkout or output. Set `SAFEYOLO_COORD_MODEL_HOME` to that absolute role
home, and set the NATS and scratch variables used by the preceding example.
The test binds its own authenticated native socket paths to the MCP subprocess
and preserves the selected provider. It starts an owned NATS/proxy instance,
runs bounded real model turns, retains its private fixture and stops its owned
runtime:

```sh
scripts/cargo_with_space.sh test --manifest-path proxy/Cargo.toml --release --locked --test native_coord supervision::real_model_wakes_for_report_check_challenge_disposition_and_acceptance -- --ignored --nocapture
```

Expected output is one passing test. The model independently rejects a report
that lacks the exact requested line, reads its retained correction, explicitly
disposes of the challenge, approves the corrected check and decides acceptance.
The controller supplies the producer's interactive native calls; it does not
supply the review verdict or disposition. This proves native API attribution and
actual supervisor/model behavior in one owned Linux process environment. It does
not establish separate guest isolation, deployment, approved Factory policy
selection or actual interactive coding-client participation.

The companion
`supervision::native_delivery_is_not_completed_by_narration_and_restart_uses_current_work`
uses a deterministic model event seam with real NATS and the Agent API. It proves
that a completed model turn leaves execution pending until a canonical native
transition, and that restart can retire the settled delivery without another
model invocation.

### Share work with an interactive producer

Approve a Factory with [native work policy](factories.md#select-native-work-policy)
for its supervised reviewer. Keep the producer as an ordinary interactive
agent outside the Factory's supervised roles. Grant both participants send and
receive access to the shared room. The operator creates assigned Work with the
exact approved `factory={name,snapshot_id}` reference. The interactive producer
then claims and publishes through its authenticated Coord client. Publication
creates the policy's required exact-output checks atomically. The reviewer
receives those native assignments through its existing supervisor.

The compact executable example is
[`native_coord/factory.rs`](../proxy/tests/native_coord/factory.rs), with its
[interactive client driver](../proxy/tests/native_coord/factory_interactive.py).
It uses one native Work loop:

1. The operator creates policy-selected Work assigned to interactive Alice.
2. Alice's actual Codex terminal retains and publishes an incomplete report,
   then completes execution. Supervised Bob independently rejects its check.
3. The operator directs the same Alice terminal to raise a challenge, retain a
   corrected report, publish the correction and respond to the challenge.
4. The operator explicitly selects the challenge as required. Bob reads the
   correction, answers its generated check, records a challenge disposition and
   decides current output acceptance. Alice reads that independent result.

The controller supplies operator prompts and the explicit policy amendment. It
does not perform Alice's producer mutations or supply Bob's conclusions. Alice
has no supervisor; Bob has one. Terminal markers only synchronize observation;
the test verifies each outcome from canonical native Work. Native client
sessions retain their own history. The example creates no parallel task or
review state.

From a Linux source checkout, set the preceding NATS and disk-backed scratch
variables. Set `SAFEYOLO_COORD_INTERACTIVE_HOME` and `SAFEYOLO_COORD_MODEL_HOME`
to distinct owned private homes with an authorized native Codex login and
selected provider configuration. Set `SAFEYOLO_CODEX_BIN` to the existing native
Codex executable. Keep those credentials outside the checkout and test output.
The fixture binds its own authenticated MCP sockets, approves its own Factory,
stages only Bob's disposable supervisor, and stops its owned clients and runtime.
Run the focused public API control, then the actual interactive journey:

```sh
scripts/cargo_with_space.sh test --manifest-path proxy/Cargo.toml --release --locked --test native_coord factory::factory_selection_enforces_native_obligations_for_direct_callers -- --ignored --nocapture
scripts/cargo_with_space.sh test --manifest-path proxy/Cargo.toml --release --locked --test native_coord factory::interactive_coding_client_and_factory_supervisor_share_native_work -- --ignored --nocapture
```

Each command should report one passing test. The API control refuses an
unauthorized Factory creator, worker policy relaxation and premature acceptance.
The interactive journey proves the approved-policy/API/terminal/supervisor/model
boundary in an owned Linux process environment. It does not establish separate
guest isolation or deployment and does not change a live Factory. Applications
can retain their domain artifacts and canonical Work IDs while removing writable
assignment, claim, required-check, challenge and acceptance copies. Rebuildable
display projections remain possible. External final actions still validate
their exact revision at the external authority.

## Raise a material signal

A **signal** retains an attributed blocker, decision, result or correction so
that important needs and outcomes can be found outside the discussion. For
example, Alice can report that the documented test command names a missing
script and ask which supported command should replace it.

With the instance proxy running, Alice uses `create_signal` inside her coding
session. She needs `send` and `receive` permission. These tool arguments show an
observed blocker; use the actual finding and optionally the room's `work_id`:

```json
{"room_name":"chat","kind":"blocker","summary":"The documented test command names a missing script. Which supported command should the README use?","basis":"observed","operation_id":"readme-missing-script"}
```

The response contains `signal`, `content_hash` and `operation_id`. `observed`
means the author reports an observation; `inferred` labels an inference.
Neither establishes independent proof. Only eligible unresolved blockers and
decisions create operator attention, and the author needs `page_operator`.
Results and corrections do not page. Completing work does not create a result
signal.

On the owning host, list this room's pending operator needs or attach the
instance-wide signal watcher:

```sh
safeyolo coord signal list chat --needs-operator
safeyolo watch
```

Watch shows pending revisions and reports when an item no longer needs the
operator. Ctrl-C detaches; unresolved signals remain across detachment and
proxy or NATS restart. For a one-time structured view, use
`safeyolo watch --once --json`.

Live watch subscribes to the authenticated Admin stream before reading current
pending signals and approvals. Recorded events come from the shared JSONL log.
A shared host check also detects missed pending-state changes and pushes a
separate refresh control. Healthy idle viewers do not poll across the network.
The target is convergence within five seconds with healthy state/API and
connections. Feed loss reports a gap and reconnects; the new snapshots refresh
current work without replaying history. Unavailable state retains a stale view.
Operator attachment and reads do not require NATS.
See the [live operator event limits](operator-controls-627-evidence.md#live-operator-events).

Before resolving a signal, use `coord signal list chat` to get its actual ID
and current revision. Replace `SIGNAL_ID` and `REVISION` below with those
values. Inspect the claim and address the need, then resolve it on the host:

```sh
safeyolo coord signal show chat SIGNAL_ID --revision REVISION
safeyolo coord signal resolve chat SIGNAL_ID --expected-revision REVISION --operation-id resolve-readme-command
```

Only the operator resolves signals. Resolution clears `needs_operator` and
retains the original author and revisions. A stale expected revision fails.
Authors can supersede their own claims with a `correction`; peers cannot.
See [signal revisions, paging limits and audit behavior](coord-reference.md#raise-a-material-signal).

## Return to the current room state

On the owning host account, use the existing room in the same instance. The
proxy must be running. To catch up on current facts, run:

```sh
safeyolo coord status chat
safeyolo coord status chat --json
```

The text view shows the brief revision and its first 2048 UTF-8 bytes, current
agent members, specialist capabilities, resource leases, active work, completed
work, pending operator needs and latest current results or corrections. It uses
the same canonical projection as `get_room_state()` and `coord state ROOM`.
It reads current tables without replaying chat or asking a model to summarize it.
The brief excerpt is text; status does not infer goals or priorities from
Markdown. Use `coord brief show ROOM` for the full brief.

Active ownership comes from the current work version. Releasing a claim removes
its owner; reassignment replaces its owner. Time and process liveness do not
release a durable claim. Completed work appears separately with its retained
result and last holder. Resolved or superseded signals do not appear as current
needs or results.

Each section contains at most 50 items and 64 KiB of item JSON. Counts and
truncation identify omitted items. Members and leases are ordered by durable
agent ID and provider/resource respectively. Active work is ordered by work ID;
completed work and current material results use newest update first, with
durable IDs breaking ties. Current signals and operator needs retain their
signal-ID ordering and continuation values. Per-member verified and declared
arrays have limits of 50 entries and 16/8 KiB respectively. Work titles and
completion results contain at most 512 UTF-8 bytes each. Excerpts preserve code
point boundaries and report original byte counts. The complete projection is
limited to 512 KiB. Use `coord work show` and `coord signal show` for complete
records, and their list commands to inspect larger worksets.

Authorized specialist labels require current grants. Declarations remain
unverified. Availability requires fresh provider evidence; missing or stale
evidence yields unknown availability. Revocation is rechecked after provider
reads. Reads add no changing generation timestamp: identical current facts and
freshness give identical JSON and text. Text and JSON output escape terminal
and direction controls; signal markup remains text. Bare `coord status`
reports the managed NATS process, independently of a room's work state.

### Request an optional catch-up narrative

For an explanation of recent discussion alongside current state, use
[catch-up export and cited summaries](coord-reference.md#request-an-optional-catch-up-narrative).
The command exports bounded input for a model you already use; it does not run
a model or store a summary. A derived narrative cannot override canonical
ownership, completion or acceptance.

## Observe messages and harness events

Use `coord watch` to follow activity in an existing room on the owning host.
The same instance's proxy and Coord must be running:

```sh
safeyolo coord watch chat
```

Watch shows the last 30 retained messages, then follows the room. Alongside
ordinary messages it renders published coding-session and supervisor events.
This lets you follow what the agents are doing; activity alone does not prove
that work met its acceptance requirements.

For a concise display, use `--compact`. Add `--redact` to hide common credential
patterns and URL queries in the display; stored messages remain unchanged.
`--once` prints the retained tail and exits. `--since SEQUENCE` resumes after a
known room sequence. Ctrl-C detaches without stopping the agents.
See [watch modes and the tmux observer wrapper](coord-reference.md#observe-messages-and-harness-events)
for JSONL, raw bodies, harness events and display controls. Use the separate
`safeyolo watch` command for pending operator signals.

## Recover a collaboration

Start with the selected instance's canonical records. Check the actor, room
and work target before repeating an operation.

| Situation | Next action |
|---|---|
| Send reports acceptance **UNKNOWN** | Read `coord history ROOM` for the intended message and its canonical sender. Do not resend automatically. Message sends have no operation-ID retry contract. |
| A durable write's response was lost | Retry the original operation ID with the exact original inputs and expectations. Changed input conflicts. For a new intent, read current state and choose a new ID. |
| An agent has stopped with a claim | Read current work and preserve the agent's checkout. Claims do not expire. Resume the holder, or use host `coord work release` or `reassign` with the current version and claim generation. Reassignment also needs the new holder's durable `--agent-id` and current send/receive permission. Reassignment can reopen done or cancelled work; it does not change the original output's producer. |
| Output publication was interrupted | Keep the retained external artifact. Retry `publish_work_output` with the exact original operation ID and inputs. A committed request returns its original receipt. An uncommitted stale request is refused after cancellation, reassignment or a later output. Read current work to distinguish a recovered old receipt from the current output. |
| A review refers to an older candidate | Read current work and its attestations. Bind the new candidate and review that generation. Old approval does not approve the replacement. |
| A member cannot read or write | Check current membership and the durable agent ID with `coord status ROOM`. A recreated agent does not inherit the old identity's grants or claims. |
| Coord is unavailable while the proxy runs | Follow [runtime reconciliation](#reconcile-a-running-proxy). Preserve the store and managed runtime. |

An agent resumes from current `get_room_state` and `read_work` results. For a
needed earlier finding at room sequence `N`, call `read_room` with
`since_sequence=N-1` and `limit=1`; verify the returned sequence and canonical
sender. A room-history cursor is separate from the attention cursor. Retained
history supplies context, not a new assignment.

When a coding harness owns its attention loop, let that harness resume from
its checkpoint. An ordinary agent-managed loop uses the foreground
`wait_for_coord` tool, acts on every returned object and adopts `next_cursor`.
An empty bounded return means no attention arrived. Keep cursor ownership and
recovery rules with the [supervisor](codex-coord-supervisor.md) or
[agent coordination protocol](../cli/src/safeyolo/agent_context/skills/safeyolo/references/coord.md)
you are using.

### Retry a membership change

On the owning host, the room and configured agent must already exist. Choose
an operation ID before a grant or revoke when you need lost-response recovery.
This example changes Alice's manual grant to receive-only access. Other valid
approved permission sources remain effective:

```sh
safeyolo coord grant chat alice receive --operation-id chat-alice-receive
```

To recover an uncertain result, repeat that exact ID and permission input.
Read current room state separately to inspect any later changes. For a new grant or revoke after
a later transition, choose a new ID. See [membership retries and audit delivery](coord-reference.md#retry-a-membership-change).

### Reconcile a running proxy

Run the following as the owning host account for the selected instance:

```sh
safeyolo start
```

When stopped, SafeYolo starts the proxy and managed NATS concurrently and waits
for both startup attempts. Each service retains its ownership and readiness
checks. A Coord startup failure warns and leaves a healthy proxy available.
The first-agent launch also checks Coord readiness before starting the sandbox
and coding client.

When the proxy is already running, `start` bootstraps the Coord store and checks
the managed NATS runtime. It leaves healthy NATS running or starts the absent
managed process. It preserves the instance identity, credentials, rooms,
memberships, control state and retained JetStream history.

If NATS startup or Coord bootstrap fails, `start` reports `Coord unavailable`
and leaves the running proxy available. Use `safeyolo coord status` and
`safeyolo doctor` to inspect the runtime before retrying. If a managed NATS log
exists, inspect `nats/nats-server.log` under the configured Coord data directory.

An agent's attention wait reads recorded attention first. When no recorded
attention remains at its cursor, the wait recovers pending message projections
from retained room messages. Recovery failures are reported through that wait.
The startup message `Coord ready` establishes managed runtime readiness;
it does not establish successful attention recovery.

Do not launch a second NATS server or edit its generated configuration. See
[runtime files and credential protection](coord-reference.md#runtime-files-and-credentials)
for private paths; deleting Coord data is not a repair procedure.

## Specialist operations

### Schedule an operator message

Use a trusted host scheduler when a message must be sent while an agent is
stopped. The proxy and Coord must still run; sending does not wake or start the
guest. The [scheduler recipe](coord-reference.md#schedule-an-operator-message)
covers host-owned inputs, cron and macOS scheduling, and checking retained
publication before retrying.

### Inspect room capabilities and resource leases

Advertise the public labels that collaborators need, then inspect current
authorization and provider evidence. An advertised label grants no service
access, an agent's skill declaration remains unverified, and stale provider
evidence means unknown availability. See [inventory and lease procedures](coord-reference.md#inspect-room-capabilities-and-resource-leases).

### Collaborate through a home SafeYolo

For agents on separate instances, each room keeps one authoritative home.
Remote agents select an explicitly configured home; reconnecting reads that
home's state. See [federation setup and revocation](coord-reference.md#collaborate-through-a-home-safeyolo)
for peer identities, private credentials, certificate trust, permissions and
per-home attention cursors.

The inter-instance path uses authenticated TLS NATS with a separate federation
account and peer-specific subjects. Each owner retains its own root, grants,
canonical records and runtime. A remote support grant needs no shared room.
For support setup, event selection and repair, use [delegated peer support](peer-support.md).
The ordinary `wait_for_coord` tool can select several owning instances with
independent cursors and availability. Notification failure alone does not block
permitted Core NATS support requests. A full Core transport outage requires
local owner-side recovery where those controls remain usable.

### Room storage

Messages are retained within storage limits. Rooms share the managed NATS
server's 1 GiB file-storage budget without per-room byte reservations. Each
room retains messages for at most seven days and 100,000 messages, with a
2 MiB message-size limit. If the shared budget fills, new writes can fail
across rooms; the server does not evict another room's history to make room.
Durable work and claims have their own canonical storage; message retention
does not release a claim.

### Focused proof and remaining work

For developer acceptance drivers and the boundaries they exercise, see
[focused proof](coord-reference.md#focused-proof-and-remaining-work). The same
installed CLI also supports [Dispatch publication requests](dispatch-publication.md),
[Dispatch generation and validation](dispatch-generation.md), and
[Mattermost exchange](coord-mattermost.md).
