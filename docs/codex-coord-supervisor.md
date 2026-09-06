# Supervised factory workers

The `@codex-coord` and `@pi-coord` host setups run factory roles under the same
event-driven supervisor. The ordinary `@codex` and `@pi` setups stay
interactive and have no supervisor. A role's factory TOML selects its harness;
that choice does not create another queue or state machine.

Configure the rooms that the worker must receive from and the agent names that
the operator designated as coordinators:

```bash
SAFEYOLO_CODEX_COORD_ROOMS=backlog \
SAFEYOLO_CODEX_COORDINATORS=relay \
  safeyolo agent run worker --host-script @codex-coord
```

Each supervised setup uses its normal harness setup first and preserves that
agent's own subscription login, SafeYolo instructions, proxy, and TLS
environment. Codex uses the bundled Coord MCP adapter. Pi uses a small native
`send` and `read_room` extension. Neither setup imports a host credential.
The only changed boundary is the foreground command: the guest runs the common supervisor,
which runs bounded JSON-mode harness turns.

## Turn contract

The supervisor waits directly on the identity-wide Coord attention feed. It
resolves the complete returned page before exposing its `next_cursor`, applies
the configured room, sender, message-type, brief, and handoff checks, and
atomically checkpoints the result. Empty, brief-only, and irrelevant pages
re-arm the wait without launching a harness.

An actionable page launches the selected harness and creates one session.
Later actionable pages resume that exact session while an inbound request or
outbound handoff remains pending. Once both lists are empty, the supervisor
retires the session before admitting new attention. The next work starts a
fresh session; Coord state, local files, and old transcripts are retained.
This uses the existing checkpoint, not role names, response labels, or URL
heuristics. Forge therefore normally keeps its session through a pending review
and repair. An explicit stronger-model selection starts a fresh session scoped
to that task, as described below. After Lens sends a disposition, its review request is settled; a later
review starts fresh and can retrieve still-valid findings from Coord.
The injected prompt explains conditional recovery with `read_room`. For a
known room message sequence N, `since_sequence=N-1, limit=1` retrieves the
next retained message; the agent checks that its sequence really is N before
reusing it. The room-history cursor is separate from the supervisor's attention
cursor. History reads do not complete requests, create assignments, or wake
agents. The role contracts keep ordinary handoffs self-contained and give
follow-up reviews a direct reference to the prior disposition.
Each launched turn receives
the resolved canonical checkpoint and performs the work. If the role contract
requires an outbound handoff before the inbound request can complete, the turn
sends that handoff and exits; the supervisor records its correlation and waits
outside the harness. Absence of the downstream response at the start of the
turn is not itself a blocker. Once the request has a genuine terminal outcome, the
turn sends its declared response to every role in the handoff's `response_to`
list and exits. It does not call or re-arm `wait_for_coord`; waiting is
supervisor transport behavior rather than an agent task.

Codex and Pi expose the same canonical `send` operation through their native
tool interfaces. The supervisor normalizes each successful result into one
outbound-send event before it evaluates a terminal response or records an
outbound handoff. Downstream behavior does not depend on the selected harness.

A failed wait or canonical-object resolution cannot advance the safe cursor.
Harness exit code 0 and model text are not work-completion evidence.

Each factory agent also has a room named `<agent>-agent`. The supervisor sends
useful harness events to that room without attention. Codex JSONL is retained
as emitted. Pi telemetry retains sessions, turn lifecycle, complete tool
calls/results, final assistant text and usage, errors, and stderr; its
token-by-token deltas and duplicate transcript payloads are not stored.
Pi completion event retains summed token usage for that agent loop, including
tool-only assistant responses. The watcher shows these counts on its completion
line. `uncached` and `cached` are separate input counts; `reasoning` is part of
output, not an extra amount to add to the provider's `total`. The summary is
not a session lifetime total or a subscription charge. If an older retained
event has no usage, the watcher reports that the counts are unavailable.
The operator can send targeted natural-language direction to the agent in the same
room. Other agents can receive the retained stream when the operator grants
them receive permission; receive permission does not let them send or steer
the supervised agent.

The supervisor also sends start, handled-error, trapped-signal, crash, and exit
events to this room. Harness stderr is retained as labelled stderr events. It
does not emit idle or heartbeat messages. An abruptly killed supervisor cannot
report its own death; runtime supervision is a separate concern.

Render the retained stream and continue watching it with:

```bash
uv run python contrib/watch-agent-room.py <agent>-agent
```

The default view renders a concise mixed operator and agent timeline. Use
`--raw` to show each message body unchanged, or `--json` to emit canonical
Coord messages as JSONL. The rendered view uses colour on a terminal; use
`--no-color` or `NO_COLOR` for plain output. The default shows the complete
rendered content after canonical log-safe control-character handling; use
`--redact` to hide common credential patterns. Raw and JSON modes preserve the
retained message unless `--redact` is set. Use `--max-text` to opt in to a
rendered event-text limit. The watcher also supports `--history`, `--once`, and
`--show-unknown`. File selection, agent-home selection, and filesystem polling
do not apply because this watcher reads one retained Coord room.

If NATS becomes unavailable, the watcher reports the lost connection and
retries with bounded exponential backoff from the same cursor. It reports
recovery after a successful read or wait. A large harness event is retained as
one bounded record with a short summary, the beginning and end of the original
event, its original byte count, and its SHA-256. The watcher marks the omitted
middle explicitly.

In factory mode, the approved snapshot may declare one `operator_input` edge.
Only its destination role admits bounded natural-language direction, and only
when coord reports the canonical sender kind as `operator`. Declared leading
types remain compatibility shorthand; neither the CLI, coord server, nor
supervisor parses natural language. Canonical operator messages have no agent
ID or agent name. The supervisor normalizes those null fields only after
checking the sender kind and checkpoints the message as non-terminal input.
Operator messages use the supervisor's shared 64 KiB UTF-8 message limit, with
no separate operator limit. It never lets an operator message impersonate an agent
handoff or peer text impersonate operator direction.

Factory workers also admit canonical `brief_changed` attention as trusted
operator-authored standing context. Preflight refreshes the current brief for
every configured room where the worker still has receive permission, so a
restart cannot lose a brief whose attention cursor already advanced. A brief
does not create in-flight work, require a terminal response, or trigger an
automatic runtime transition. Peer message text that looks like a brief has no
such authority.

For each returned object, the supervisor atomically stores a narrow canonical
checkpoint before it adopts the returned cursor. Only a `TASK` from a
configured coordinator with an absolute `target` URL and exactly
`assignee=<worker-name>` becomes work. That task stays in flight until the
supervisor observes a canonical `DONE`, `BLOCKED`, or `FAILED` in the same room
with the same target and its exact `attention_id`. The URL locates the work; it
does not create a durable work object or claim. If a terminal send reached
coord but the local execution event was lost, the supervisor checks
bounded canonical room history after the task sequence.

The coord wait is identity-wide. Attention from an authorized room that is not
configured for this worker is checkpointed as ignored before the cursor moves.
It cannot route work to the worker or wedge later waits.

If the harness stops after delivery, the supervisor tries the exact session first.
If that session is unavailable, a new thread receives the bounded canonical
in-flight checkpoint. An older cursor can replay retained attention safely;
the supervisor keeps a bounded set of stable attention IDs for deduplication.
That historical list stays in the state file and is not included in the model
prompt. Active work and handoff identifiers remain in the supplied checkpoint.

## State and failure bounds

The private state file is
`~/.safeyolo/codex-coord-supervisor-state.json`. Atomic replacement and a
single-owner lock protect it across supervisor restarts. It contains only:

- one harness session ID;
- one safe attention cursor;
- at most 256 recent attention IDs;
- at most 16 narrow returned objects that are still in flight;
- at most 16 independently correlated outbound handoffs awaiting responses;
- one current, bounded brief revision and Markdown body per configured room;
- an optional task-local repair selection and its canonical selecting message;
- one process-group PID plus at most 64 PID-reuse-safe descendant identities
  while an invocation is running; and
- a bounded consecutive-failure count.

It does not contain harness execution transcripts, provider responses, proxy
credentials, subscription credentials, agent tokens, or room history. Coord
remains the source of truth. The file is recovery bookkeeping, not a second
queue.

For operator-requested abandonment of checkpointed work, use the host-side
[`factory release` recovery action](factories.md#release-stuck-work-after-stopping-its-agents).
It requires affected agents to be stopped, preserves unrelated work, and uses
this supervisor's decoder and atomic writer. It does not add a runtime cancel
protocol or a new checkpoint schema.

Startup checks the Agent API, the selected harness's agent-local subscription
login, and its Coord adapter. Every later cycle checks Agent API health and
receive permission for each configured room. A failed preflight, failed or
invalid wait, or unavailable dependency does not advance the cursor or launch
the harness. Repeated failures use exponential backoff with a cap. Agent API failures
retain their bounded path, HTTP status, and retry classification in supervisor
events. A successful later cycle emits a recovery event.

### Deadlines

The external attention long poll has its own bounded HTTP timeout. Once work
is accepted, harness startup and work have separate absolute deadlines. The work
deadline is set once when the turn starts; later output cannot extend it. The
invocation also keeps a hard overall bound.

### Process cleanup

On timeout or abnormal exit, the supervisor signals only the process group
that it created for that harness invocation while its leader fingerprint is
still verified. After the leader exits, cleanup never signals the numeric
process-group ID. It uses PID handles and matching start-time fingerprints for
recorded descendants.

On Linux, the supervisor also acts as a child subreaper, so repeated recovery
does not accumulate orphaned code-mode children or zombies. The supervisor
requires Linux PID handles and fails closed before recovery if the kernel does
not provide them. It uses the CPython pidfd wrappers when present and the Linux
syscalls directly when a supported CPython build omits those optional
wrappers.

### Restart recovery

On supervisor restart, cleanup opens a PID handle for the recorded leader and
rechecks its start fingerprint and process-group identity. While that verified
handle remains open, it snapshots and terminates the live invocation group.
Recorded descendants that escaped into other groups still use individual PID
handles and fingerprints.

The upgrade from the model-owned Coord wait to the supervisor-owned wait keeps
the canonical cursor, pending work, and handoff correlations but starts one
clean harness session. This avoids replaying an interrupted legacy tool call with a
missing tool result. Subsequent restarts preserve the healthy external-wait-era
thread, including across an outbound handoff and its response.

## Configuration

### Context messages and protocol warnings

Factory TOML can declare informational routes separately from work handoffs:

```toml
[[updates]]
type = "CONTEXT"
from = "coordinator"
to = "owner"
fields = ["target"]
```

The matching message starts `CONTEXT target=<absolute-url>`. The declared
sender role, receiver role and exact header fields must match. Its body carries
the update. It is supplied once as context, creates no assignment, and needs no
terminal response. Other factories can name their own update types and fields.

An unknown or malformed agent message targeted into a configured factory room
is retained with `protocol_warning` and delivered as information. It cannot
create an assignment, satisfy a response, or clear a waiting handoff. The
supervisor also reports the message reference and mismatch on stderr, in its
agent room, and in a factory-room `PROTOCOL_WARNING` notifying the sender and
coordinator. The operator can see that shared diagnostic. Publication is
best-effort: a send failure is reported on stderr and never removes the
checkpointed original. Canonical sender identity still governs authority;
the diagnostic's body prefix does not prove supervisor authorship.

Diagnostics themselves are informational and generate no further warning or
acknowledgement. Ordinary attention deduplication prevents repeat delivery.
An unrelated room remains outside this worker's configuration.

### One stronger repair round

An optional role `repair` table selects one stronger set of arguments. See
[`backlog.toml`](factories/backlog.toml) for the complete Codex example.
For a Pi owner, both ordinary `roles.owner.args` and `roles.owner.repair.args`
use Pi syntax: `--provider openai-codex --model MODEL --thinking LEVEL`.
The harness itself does not change.

`after_rounds` and `max_rounds` are coordinator instructions: the coordinator
counts completed fix-and-review rounds from Coord, selects escalation, and
asks the operator if the stronger rounds are exhausted. They are not supervisor
invocation counters. The selecting message has this exact first line:

```text
REPAIR target=<original-task-url> attention_id=<original-task-attention-id>
```

`REPAIR` is the example's configured `request` value. Only the policy's `from`
role can select a matching active task it originally assigned. Its body must
supply the relevant findings or exact Coord references. A stale or mismatched
selection becomes a visible protocol warning, not a new task.

The supervisor checkpoints that selection, uses only the named task and
selecting message as invocation inputs, and preserves other pending work for
later. It overrides matching model arguments while retaining the launcher's
instructions and other arguments. It does not alter the checkout or saved
agent defaults. Selection takes effect at the next invocation, not by
interrupting a running harness. It survives a restart while that repair is
unfinished, but expires at the next configured `release_on` handoff or the
original task's terminal result. Retained history recovers expiry if the send
event was lost. A changed factory snapshot or released task also clears it.
Selection and expiry appear in the agent room.

The selected turn is instructed to finish after its handoff. The next task uses
ordinary arguments and a fresh session. This is model selection, not a sandbox
restriction: the model still has the agent's ordinary tools and workspace.
Checkpoint version 7 adds the optional selection; version 6 work and cursors
upgrade without a drain because the target protocol is unchanged.

### Runtime settings

The host setup writes the private, non-secret configuration file
`~/.safeyolo/codex-coord-supervisor.json`. In factory mode that configuration
also binds the immutable operator edge and handoff table from the approved
snapshot. Its `harness` value is exactly the role's approved `codex` or `pi`
selection. It contains no inferred workflow state. The defaults are:

| Setting | Default | Purpose |
|---|---:|---|
| `wait_seconds` | 300 | One supervisor-owned Coord long poll. |
| `page_limit` | 16 | Maximum returned and in-flight objects. |
| `startup_timeout_seconds` | 480 | Bound before a launched harness turn starts. |
| `work_timeout_seconds` | 3600 | Bound after a harness turn starts. |
| `completion_grace_seconds` | 90 | Compatibility bound for an old thread that returns an empty MCP wait. |
| `backoff_initial_seconds` | 5 | First retry delay. |
| `backoff_max_seconds` | 300 | Crash-loop retry cap. |

Stop the agent before you edit these values. Keep `wait_seconds` at or below
the Agent API maximum of 300 seconds. Codex's MCP timeout is independent of the
supervisor-owned wait. The supervisor rejects invalid or unbounded values.

## Debugging with a fake Codex harness

`--debug` prints bounded supervisor decisions to stderr without publishing
idle or debug events to Coord. The same mode can be enabled with
`SAFEYOLO_COORD_SUPERVISOR_DEBUG=1`. `SAFEYOLO_COORD_SUPERVISOR_ONCE=1` is the
environment equivalent of `--once`, which is useful when the staged command
owns the supervisor arguments. Debug output reports cursor movement, page and
accepted-object counts, re-arming, and harness invocation boundaries; it never
prints message bodies.

For a nested lab, `contrib/codex-coord-supervisor-fake-codex.sh` can replace
Codex through `SAFEYOLO_CODEX_BIN`. It satisfies the subscription-login
preflight, captures each invocation's argv and stdin prompt, and emits minimal
valid Codex JSONL without making a model request:

```bash
export SAFEYOLO_CODEX_BIN="$PWD/contrib/codex-coord-supervisor-fake-codex.sh"
export SAFEYOLO_FAKE_CODEX_CAPTURE_DIR=/tmp/safeyolo-fake-codex
python3 contrib/codex-coord-supervisor.py --once --debug
```

Use a disposable nested agent and state file because a real Coord attention
page is still resolved and checkpointed. Set `SAFEYOLO_FAKE_CODEX_EVENTS` to a
JSONL file when a test needs events other than the default `thread.started`,
`turn.started`, and `turn.completed` sequence.

Pi parity is exercised with a fake JSON-mode Pi process in the supervisor test
suite. That proof covers session creation and exact resume, direct `send` tool
results, the common terminal checkpoint, and agent-room telemetry without a
model request.

To exercise Pi's extension tool definitions with synthetic HTTP and token reads,
run `node cli/tests/run_pi_coord_extension.mjs /path/to/pi-coding-agent` using
an already installed Pi package directory. This checks model-visible history,
pagination metadata, cancellation, errors, and send results. It does not prove
that a model chooses to recover history in a live task.
