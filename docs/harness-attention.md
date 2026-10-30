# External harness attention

Coord retains external messages and supplies canonical sender identities.
The harness integration selects how an authorized event enters a conversation.
Message text cannot select its own priority or delivery mode.

The integrations below are opt-in. They do not change a running factory.
The shared five-harness contract in [issue 373](https://github.com/craigbalding/safeyolo/issues/373)
remains unfinished. A native receipt establishes input acceptance. Observe native
conversation events and a model response separately to establish application.

## Codex App Server

Use a complete native Codex client with its existing configuration and authorized
model access. Run the candidate `safeyolo-coord` inside the agent, with its normal
Agent API token and proxy settings. A frontend that speaks the native App Server
protocol can select this command as its server process:

```sh
safeyolo-coord codex-attention --mode queue
```

The frontend still sends `initialize`, `initialized` and `thread/start` or
`thread/resume`. Enable the native experimental API capability for
`thread/inject_items`. Native requests, notifications, tools and approval replies
pass through. `SAFEYOLO_CODEX_BIN` selects the complete native Codex executable.
Arguments after `--` pass to `codex app-server`.

Attention binds to the first opened thread. `--thread ID` binds an explicit
thread that the frontend resumes. `--home NAME` selects a configured Coord home;
omission selects the local instance. This connection does not attach to an
unrelated interactive Codex terminal.

| Operator-selected mode | Native delivery |
|---|---|
| `queue` (default) | Wait for the current turn, then use `turn/start`. An idle thread wakes. |
| `steer` | Use `turn/steer` with the active turn ID; use `turn/start` when idle. |
| `context` | Use `thread/inject_items` with an attributed user-level item. No turn starts. |
| `interrupt` | Request `turn/interrupt`, wait for completion, then use `turn/start`. |

The `safeyolo/attention/bound` notification identifies the selected thread and
available primitives. `safeyolo/attention/pending` identifies a resolved canonical
event that still needs native delivery. `safeyolo/attention/delivered` reports native acceptance,
the canonical attention ID and `next_cursor`. A native rejection produces
`safeyolo/attention/rejected`. An unavailable or unauthorized external read
produces `safeyolo/attention/stopped`. Both errors disable external ingress and
preserve the native frontend connection. Neither error advances the delivery
cursor or silently changes the selected mode.

Keep the delivered cursor with the native thread ID in the calling application.
After restart, resume the native thread and pass `--since CURSOR`. Coord remains
the retained content source. The connection suppresses its most recent 128
delivered attention IDs in memory. If a response was lost, inspect native
conversation history and canonical retention before replaying the event.
Native acceptance does not establish that a model completed a successful turn.

## Pi extension

Use the complete Pi client and its already configured model access. Load
[the Coord extension](../contrib/pi-coord-extension.ts) in an ordinary interactive
session or RPC session. Enable external delivery with `--coord-attention`.
The extension's send and history tools remain available without this flag.

`--coord-attention-mode` selects `queue`, `steer`, `context` or `interrupt`.
The default is `queue`. The extension uses Pi's `followUp`, `steer`, `nextTurn`
and abort primitives respectively. Interrupt waits for the native `agent_settled`
event before starting delivery. Context waits for a subsequent prompt and
does not wake the model. Other modes wake an idle session.

The native Coord helper owns authentication, proxy routing and canonical reads.
`SAFEYOLO_COORD_BIN` selects that helper; the default is
`/home/agent/.safeyolo/safeyolo-coord`. `--coord-home NAME` selects a configured
home. The extension uses a background native long wait; the model does not poll.

Pi's normal session history records delivered custom messages and a cursor
receipt. Content still waiting in Pi's native queue has no cursor receipt.
After restart, the extension recovers that content from Coord using the saved
cursor. `--coord-attention-since CURSOR` explicitly selects another starting
cursor. The extension suppresses the most recent 128 recorded attention IDs.
A failed read stops the receiver and reports the error without retrying.
Restart the receiver after resolving the error. Keep Pi session files private.

## Gemini and Hermes ACP

Use the complete native client with its normal model configuration and authorized
access. An ACP frontend can select either command as its stdio server:

```sh
safeyolo-coord acp-attention gemini --mode queue
safeyolo-coord acp-attention hermes --mode queue
```

The frontend sends native `initialize` and `session/new`, `session/load` or
`session/resume` requests. Tools, permission requests and their replies pass
through. The first opened session receives attention; `--session ID` selects an
explicit session that the frontend loads. `--home NAME` selects the Coord home.
`SAFEYOLO_GEMINI_BIN` selects `gemini`; `SAFEYOLO_HERMES_BIN` selects `hermes-acp`.
Arguments after `--` pass to that native executable. Gemini runs with `--acp`.

Queue waits for an active frontend prompt to complete, then sends a native
`session/prompt`. Interrupt sends `session/cancel`, waits for the active prompt's
response, then delivers. Hermes cancellation applies to this frontend's native
admission; it does not grant control over another client's work. Hermes steer
uses its native `/steer` command and checks its active-turn acknowledgment.
Native session updates and the resulting model response remain separate evidence.
Hermes's own gateway retains its normal execution and session ownership.

Standard Gemini ACP has no steer or context-only primitive. Hermes ACP has no
context-only primitive. An unsupported mode fails before launching the client.
`--degrade-to queue` explicitly permits those requests to become queue/wake;
the bound notification reports both requested and effective modes. Peer text
cannot select fallback. This connection does not attach to an unrelated TUI.

The bound notification reports this integration's capabilities. Pending means
canonical resolution; submitted means a native request was written; delivered
means a native prompt or command response completed. Its `stop_reason` may still
report cancellation or refusal. None of these receipts alone proves a successful
model response. Hermes does not echo live user input on this ACP path; its normal
session history records that input.

Keep `next_cursor` with the native session ID. After restart, load that session
and pass `--since CURSOR`. The connection keeps at most 128 recent attention IDs
in memory. External read failures and rejected native deliveries stop ingress
while keeping the native connection.
An unconfirmed Hermes steer may have become a native queued prompt. Inspect
native history and canonical retention before repeating any uncertain input.

## Claude Code channel

Register the native helper as a Claude MCP server, using its absolute installed
path in the normal MCP configuration:

```json
{
  "mcpServers": {
    "coord": { "command": "/absolute/path/to/safeyolo-coord", "args": ["claude-channel"] }
  }
}
```

Select that server through Claude's supported channel setup and native consent.
For a custom channel in the research preview, Claude's development command is
`claude --dangerously-load-development-channels server:coord`. The native client
requires an interactive confirmation for that flag; print/SDK mode ignores it.
Organization policy and matching Anthropic authentication still apply. See the
[Claude channel reference](https://code.claude.com/docs/en/channels-reference).

The channel keeps the existing Coord tools and advertises `claude/channel` after
MCP initialization. Canonical events enter through `notifications/claude/channel`
with their source attribution. Native channels queue busy input. This path
exposes no context-only, steer, interrupt or permission relay primitive. Actual
idle wake still needs verification against an authorized pinned Claude client.
The initialization response exposes these limits separately from tool discovery.
The helper requires no additional Node runtime.

Claude supplies no channel delivery acknowledgment. The helper's stderr receipt
reports `stdio_queued`, the attention ID and a cursor; it does not establish model
visibility or application. Verify Claude's native conversation before retaining
that cursor for restart. `--since CURSOR` and `--home NAME` select the starting
cursor and Coord home. An external read error stops notifications while leaving
the normal tools available. Native session history and canonical retention supply
recovery; there is no separate durable message store.

## Focused real model probe

From a repository checkout, use the existing locked Python test environment,
current native production artifacts, the pinned NATS binary and an installed,
authorized native client. The test creates an owned Coord instance and private
session files below the chosen disk-backed pytest scratch root. Select a model
explicitly through `SAFEYOLO_CODEX_ATTENTION_MODEL`, `SAFEYOLO_PI_ATTENTION_MODEL`
or `SAFEYOLO_HERMES_ATTENTION_MODEL`, then run
`tests/proxy_contracts/test_native_harness_attention.py` with pytest.
Hermes also uses its normal `HERMES_HOME` profile and the native MCP extra for
the controlled tool-boundary cases. Keep its login and session history private.

The probe retains broker acceptance, native session events and the model's
response separately. The probes cover idle wake, busy delivery, supported
context-only, restart and attribution. Transport controls exercise the Claude
MCP channel without claiming Claude model execution. These results do not
establish the five-harness minimum.
Unselected model probes skip without making inference requests.
