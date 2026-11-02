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
| Bind a candidate | `target_ref` identifies the candidate; `target_generation` advances independently of the claim. |
| Record review | An immutable attestation names its author and exact target generation. |
| Complete work | `state=done`; the result and last holder remain visible. |

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

1. Read the current work. In `change_work_target`, copy its `version` to
   `expected_version` and its `target_generation` to `expected_target_generation`.
   Supply `room_name`, `work_id`, a `target_ref` identifying the exact report or
   commit, and a chosen `operation_id`. New work starts with target generation `0`.
2. Ask the reviewer to inspect that exact candidate. The reviewer calls
   `attest_work` with `room_name`, `work_id`, the returned `target_generation`,
   `kind` such as `review` or `acceptance`, `verdict` (`approve`, `reject` or
   `abstain`), a `summary`, optional `evidence_refs`, and an `operation_id`.
   An agent reviewer needs current room send and receive permission. The
   operator can record their own verdict with `coord work attest`.
3. If the candidate changes, call `change_work_target` again and request review
   of the new generation. Do this even if a squash or rebase reuses the same
   reference. Earlier attestations remain readable as stale history.
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
| An agent has stopped with a claim | Read current work and preserve the agent's checkout. Claims do not expire. Resume the holder, or use host `coord work release` or `reassign` with the current version and claim generation. Reassignment also needs the new holder's durable `--agent-id` and current send/receive permission. |
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
