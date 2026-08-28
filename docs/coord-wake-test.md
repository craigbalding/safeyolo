# Coord targeted-attention harness test

This is a scripted protocol-conformance runbook for validating a model
harness against the coord MCP adapter. It is useful before behavioural
dogfood, but it is not behavioural evidence: the participant is explicitly
coached through the expected loop. The normative feed and recovery contract is
in [Coord kernel capabilities](coord-kernel-capabilities.md#1-first-class-targeted-attention).

## Why this test exists

MCP is an adapter, not the durable attention mechanism. Stage 1 stores a
per-agent multiplexed attention feed in SQLite; NATS hints only shorten the
wait. This runbook separately checks that **Claude Code** resumes when the
blocking tool returns:

1. Claude calls foreground `wait_for_coord` and is otherwise idle
2. A peer / operator sends
3. The tool call returns
4. Claude resumes reasoning with every canonical object already resolved
5. Claude responds
6. Claude advances its caller-owned feed cursor and re-arms

Step 6 is the load-bearing part. If Claude handles one wake-up and then
ends its turn, you've built one-shot notification, not unattended
collaboration.

## Prerequisites

- SafeYolo running (`safeyolo start`).
- One agent registered with the bundled harness setup, for example:
  `safeyolo agent add wake-test-bob <folder> --host-script @claude`.
- Coord initialized: `safeyolo coord init`.
- A room with wake-test-bob granted:
  `safeyolo coord room create wake-loop --member wake-test-bob`.
- For an existing bundled agent, reapply its normal setup with
  `safeyolo agent run wake-test-bob --host-script @claude`. The setup stages
  and registers `safeyolo-coord`; no manual MCP config edit is needed.

## Setup — Claude's system prompt

Give wake-test-bob a short, explicit system prompt (via Claude Code's
`--system` or the equivalent) so the loop behaviour is unambiguous:

> You are in a chat room called `wake-loop`. Your job is to:
>
> 1. Set an attention cursor to 0 and call `safeyolo-coord.wait_for_coord(since_sequence=cursor, timeout_seconds=60)` in the foreground.
> 2. Process every canonical object in the returned `objects` list.
> 3. If a canonical message body is `:done`, stop. Otherwise call `safeyolo-coord.send(room_name="wake-loop", body="ack: <one-line summary>", notify="none")`.
> 4. Only after processing the complete page, set the cursor to `next_cursor` and call `wait_for_coord` again.
> 5. Repeat without operator prompting. Never start a detached/background coord waiter.
>
> Do not ask the operator questions. Do not summarise progress at the end
> of a turn. Just keep the loop running.

## Run

In one terminal:

```sh
safeyolo agent run wake-test-bob
# Claude Code should start, load the system prompt, and call wait_for_coord
```

In another terminal, attach as operator:

```sh
safeyolo coord chat wake-loop
```

Then, one at a time, type these prompts and hit Enter. **Wait for bob's
`ack:` response before sending the next one**:

```
first message
second message
third message with slightly more content
:done
```

## Pass criteria

- Each of the three real messages produces exactly one `ack:` from bob,
  within a few seconds of you sending.
- Bob's messages carry `sender_agent_id` = bob's `agent_id` (verify in the
  transcript header or via `safeyolo coord chat wake-loop --observe`).
- After each ack, bob re-arms `wait_for_coord` without you doing
  anything.
- On `:done`, bob stops.

## Fail modes to watch for

- **One-shot**: bob acks the first message and then goes idle / ends
  its turn. You send message 2, nothing happens. → Attention loop is
  broken; system prompt or Claude Code behaviour prevents re-arming.
- **Timeout-panic**: bob's `wait_for_coord` times out at 60s and it
  gives up rather than looping. → System prompt needs to make the
  "call again" step explicit.
- **Background-buffered wake**: a detached shell waiter receives an edge but
  Claude never resumes to inspect its output. → Stop the background waiter;
  the ordinary wait must be the foreground MCP tool call.
- **Poll spam**: bob calls the feed or `read_room` in a tight loop instead of
  using the bounded long-poll. → System prompt needs to prefer the wait tool.
- **Identity mismatch**: bob's messages show up as `operator` or blank.
  → The MCP server isn't reaching the Agent API through the sandbox's
  proxy attribution; check `HTTP_PROXY` and `/app/agent_token` inside
  the sandbox.

## Only after this passes

The three-agent dogfood assumes wake→respond→re-arm works. If any of
the fail modes above appears, resolve it before starting three agents
in parallel — you'll spend the whole session diagnosing which agent
got stuck otherwise.

## Harness limitation and durable recovery

A long blocking MCP call can own the harness's current turn. Matching coord
attention releases `wait_for_coord`, but an unrelated harness UI,
operator or control-channel message may not be processed until that tool call
returns. That is a harness scheduling limitation, not evidence that the coord
API lost an edge.

- The operator initiates a side conversation in the harness (Claude Code /
  Codex / shell) — the agent may switch context, finish the side task, and
  forget to re-arm the wait.
- The agent runs its own local testing between messages and drops the
  wake for the duration.
- The agent's previous wake times out empty and it doesn't re-arm because
  it's in the middle of responding to something else.

The wake loop remains a **per-turn discipline**, not a background daemon.
Unlike Stage 0, however, Stage 1 has a durable shared attention buffer. A
dropped wait does not consume or erase edges: recovery is a feed read from the
participant's last saved cursor followed by explicit re-arm. The cursor is
caller-owned; the server does not maintain a consumed position.

For an N-agent behavioural dogfood, record each participant's feed cursor and
replay from it afterward. Prove non-delivery from the durable feed state, not
from model testimony or merely because a wait did not wake. A detached raw
poller may prove that the API delivered an edge, but it does not prove the
coding harness resumed. The foreground MCP tool return is the acceptance
boundary for ordinary coordination.
