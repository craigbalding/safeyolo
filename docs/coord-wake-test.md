# Coord v0 attention (wake) test

Runbook for validating Claude Code's attention behaviour with the coord MCP
adapter **before** launching the three-agent dogfood for #371.

## Why this test exists

Per the #371 reviewer note: "MCP is not the delivery or attention mechanism."
The plumbing test (peer message → SQLite → `read_room` returns it) only
proves that the *substrate* wakes. The dogfood requires that **Claude Code**
wakes:

1. Claude calls `wait_for_message` and is otherwise idle
2. A peer / operator sends
3. The tool call returns
4. Claude actually resumes reasoning
5. Claude reads the message and responds
6. Claude re-arms `wait_for_message` without operator intervention

Step 6 is the load-bearing part. If Claude handles one wake-up and then
ends its turn, you've built one-shot notification, not unattended
collaboration.

## Prerequisites

- SafeYolo running (`safeyolo start`).
- One agent registered: `safeyolo agent add wake-test-bob <folder>`.
- Coord initialized: `safeyolo coord init`.
- A room with wake-test-bob granted:
  `safeyolo coord room create wake-loop --member wake-test-bob`.
- MCP config staged in the agent's sandbox: `safeyolo coord mcp-config`
  → paste into wake-test-bob's `.mcp.json`.

## Setup — Claude's system prompt

Give wake-test-bob a short, explicit system prompt (via Claude Code's
`--system` or the equivalent) so the loop behaviour is unambiguous:

> You are in a chat room called `wake-loop`. Your job is to:
>
> 1. Call `safeyolo-coord.wait_for_message(room_name="wake-loop", since_sequence=0, timeout_seconds=60)`.
> 2. When a message arrives, call `safeyolo-coord.send(room_name="wake-loop", body="ack: <one-line summary of what you received>")`.
> 3. Track the highest `sequence` you have seen. Call `wait_for_message` again with that value as `since_sequence`.
> 4. Repeat forever. Stop only when you receive a message whose body is exactly `:done`.
>
> Do not ask the operator questions. Do not summarise progress at the end
> of a turn. Just keep the loop running.

## Run

In one terminal:

```sh
safeyolo agent run wake-test-bob
# Claude Code should start, load the system prompt, and call wait_for_message
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
- After each ack, bob re-arms `wait_for_message` without you doing
  anything.
- On `:done`, bob stops.

## Fail modes to watch for

- **One-shot**: bob acks the first message and then goes idle / ends
  its turn. You send message 2, nothing happens. → Attention loop is
  broken; system prompt or Claude Code behaviour prevents re-arming.
- **Timeout-panic**: bob's `wait_for_message` times out at 60s and it
  gives up rather than looping. → System prompt needs to make the
  "call again" step explicit.
- **Poll spam**: bob calls `read_room` in a tight loop instead of
  `wait_for_message`. → System prompt needs to prefer the long-poll.
- **Identity mismatch**: bob's messages show up as `operator` or blank.
  → The MCP server isn't reaching the Agent API through the sandbox's
  proxy attribution; check `HTTP_PROXY` and `/app/agent_token` inside
  the sandbox.

## Only after this passes

The three-agent dogfood assumes wake→respond→re-arm works. If any of
the fail modes above appears, resolve it before starting three agents
in parallel — you'll spend the whole session diagnosing which agent
got stuck otherwise.
