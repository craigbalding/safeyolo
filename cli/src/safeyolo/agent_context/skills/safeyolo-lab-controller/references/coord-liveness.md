# Coordination liveness experiments

Read this reference only when testing coord waits, attention cursors,
continuation turns, queued work, or harness/MCP absence.

Follow the installed SafeYolo coord guidance for room membership, envelope
attribution, foreground waiting, and task authority.

## Cursor and completion are separate

A caller-owned attention cursor records which attention objects have been
exposed to that caller. It is not a durable completion checkpoint for the work
described by those objects.

After a wait result:

1. process every returned object;
2. retain the returned next cursor as attention progress;
3. separately observe the workflow's authoritative completion signal;
4. classify a crash after delivery but before completion as uncertain work.

A valid older cursor may deliberately replay already exposed attention. That
is caller-owned replay behavior, not automatically a coord defect. A malformed
or out-of-range cursor should be distinguished from a valid replay.

## Foreground liveness

Keep the wait foreground and visible to the coding harness. A detached poller
may consume durable attention without returning a result that resumes the
model.

Record:

- wait invocation start and requested timeout;
- actual result/error time and duration;
- input cursor and returned next cursor;
- every returned attention identity and room sequence;
- harness and MCP process presence before and after;
- external message time while the harness is present or absent;
- continuation start and end;
- authoritative completion messages;
- duplicate or replay observations.

Set the surrounding MCP/tool timeout strictly longer than the requested coord
wait. Give the experiment supervisor its own bounded deadline as well.

An empty bounded result means no matching attention arrived during that wait.
It does not prove the room is authorized, the backend is healthy, or work was
completed unless the structured result and surrounding health evidence support
those claims.

## Continuation and crash recovery

Conversation continuation may preserve a delivered object, cursor, and prior
tool result, but it is recoverable context rather than the durable task ledger.
Persist externally whatever the experiment must survive losing: conversation
ID, last adoptable cursor, attention/task IDs, delivery state, and canonical
completion signals.

Do not use CLI exit zero alone to classify a wait or recovery turn. Correlate
the structured MCP result, coord state, process state, and product health/audit
evidence.

## Optional factory-agent example

In one supervised non-interactive factory-agent experiment, a targeted task was
returned by `wait_for_coord` together with an advanced cursor. The harness was
then killed before it sent the expected completion message. Resuming the exact
conversation retained both the task and advanced cursor and completed the work
without replaying the wait. A separate test showed that the required
continuation session could be unavailable.

That observation illustrates the invariant: advancing attention did not prove
completion, and successful conversation recovery was helpful but not a
durability guarantee. It is not a requirement to use factory-style TASK/DONE
messages or that experiment's recovery procedure in other workflows.
