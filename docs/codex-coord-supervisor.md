# Supervised Codex coord workers

The `@codex-coord` host setup is an opt-in mode for a factory worker. The
normal `@codex` setup stays interactive and has no supervisor.

Configure the rooms that the worker must receive from and the agent names that
the operator designated as coordinators:

```bash
SAFEYOLO_CODEX_COORD_ROOMS=backlog \
SAFEYOLO_CODEX_COORDINATORS=relay \
  safeyolo agent run worker --host-script @codex-coord
```

The host setup uses the normal Codex setup first. It preserves the staged
ChatGPT subscription login, SafeYolo developer instructions, proxy and TLS
environment, and coord MCP registration. It does not use an OpenAI API key.
The only changed boundary is the foreground command: the guest runs the
supervisor, and the supervisor runs bounded `codex exec --json` turns.

## Turn contract

The first turn creates one Codex thread. Later turns resume that exact thread.
Each ordinary turn calls `wait_for_coord` once, processes the complete page,
sends any required `DONE`, `BLOCKED`, or `FAILED` messages, and exits. It does
not re-arm the wait. The supervisor starts the next turn.

The supervisor accepts idle only from a successful structured MCP result with
an empty `objects` list and a valid `next_cursor`. Codex exit code 0 and model
text are not idle or success evidence. A failed MCP result cannot advance the
safe cursor.

For each returned object, the supervisor atomically stores a narrow canonical
checkpoint before it adopts the returned cursor. Only a `TASK` from a
configured coordinator with exactly `assignee=<worker-name>` becomes work.
That task stays in flight until the supervisor observes a canonical `DONE`,
`BLOCKED`, or `FAILED` in the same room with its exact `attention_id`.
Correlation labels such as `task=` cannot complete work. If a terminal send
reached coord but the local execution event was lost, the supervisor checks
bounded canonical room history after the task sequence.

The coord wait is identity-wide. Attention from an authorized room that is not
configured for this worker is checkpointed as ignored before the cursor moves.
It cannot route work to the worker or wedge later waits.

If Codex stops after delivery, the supervisor tries the exact session first.
If that session is unavailable, a new thread receives the bounded canonical
in-flight checkpoint. An older cursor can replay retained attention safely;
the supervisor keeps a bounded set of stable attention IDs for deduplication.

## State and failure bounds

The private state file is
`~/.safeyolo/codex-coord-supervisor-state.json`. Atomic replacement and a
single-owner lock protect it across supervisor restarts. It contains only:

- one Codex thread ID;
- one safe attention cursor;
- at most 256 recent attention IDs;
- at most 16 narrow returned objects that are still in flight; and
- one process-group PID plus at most 64 PID-reuse-safe descendant identities
  while an invocation is running; and
- a bounded consecutive-failure count.

It does not contain Codex execution transcripts, provider responses, proxy
credentials, subscription credentials, agent tokens, or room history. Coord
remains the source of truth. The file is recovery bookkeeping, not a second
queue.

Every cycle checks the Agent API, the ChatGPT subscription login, the coord
MCP registration and executable, and receive permission for each configured
room. A failed preflight, failed or invalid wait, or unavailable dependency is
not idle and does not advance the cursor. Repeated failures use exponential
backoff with a cap.

The initial provider and wait phase and the later work phase have separate
absolute deadlines. The work deadline is set once when a non-empty wait
completes; later output cannot extend it. The invocation also keeps a hard
overall bound. On timeout or abnormal exit, the supervisor signals only the
process group that it created for that Codex invocation while its leader
fingerprint is still verified. After the leader exits, cleanup never signals
the numeric process-group ID. It uses PID handles and matching start-time
fingerprints for recorded descendants. On Linux the supervisor also acts as a
child subreaper, so repeated recovery does not accumulate orphaned code-mode
children or zombies. The supervisor requires Linux PID handles and fails
closed before recovery if the kernel does not provide them. It uses the
CPython pidfd wrappers when present and the Linux syscalls directly when a
supported CPython build omits those optional wrappers.

On supervisor restart, cleanup opens a PID handle for the recorded leader and
rechecks its start fingerprint and process-group identity. While that verified
handle remains open, it snapshots and terminates the live invocation group.
Recorded descendants that escaped into other groups still use individual PID
handles and fingerprints.

## Configuration

The host setup writes the private, non-secret configuration file
`~/.safeyolo/codex-coord-supervisor.json`. The defaults are:

| Setting | Default | Purpose |
|---|---:|---|
| `wait_seconds` | 300 | One foreground coord wait. |
| `page_limit` | 16 | Maximum returned and in-flight objects. |
| `startup_timeout_seconds` | 480 | Bound before a successful wait result. |
| `work_timeout_seconds` | 3600 | Bound after a non-empty page. |
| `completion_grace_seconds` | 90 | Time for Codex to finish after an empty wait. |
| `backoff_initial_seconds` | 5 | First retry delay. |
| `backoff_max_seconds` | 300 | Crash-loop retry cap. |

Stop the agent before you edit these values. Keep `wait_seconds` at or below
the Agent API maximum of 300 seconds and keep the Codex MCP tool timeout above
that value. The supervisor rejects invalid or unbounded values.
