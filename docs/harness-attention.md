# External harness attention

Coord retains external messages and supplies canonical sender identities.
The harness integration selects how an authorized event enters a conversation.
Message text cannot select its own priority or delivery mode.

The integrations below are opt-in. They do not change a running factory.
The five-harness scope comes from [issue 373](https://github.com/craigbalding/safeyolo/issues/373).
A native receipt establishes input acceptance. Observe native
conversation events and a model response separately to establish application.

The operator selects the mode. A peer message cannot change the mode or select
degradation. These are the external-input capabilities of each integration;
native controls sent by the frontend remain available.
Claude's streaming interface uses JavaScript Object Notation (JSON).
Gemini and Hermes use the Agent Client Protocol (ACP).

| Integration | Context without a turn | Queue after current work | Idle wake | Steer | Interrupt |
|---|---|---|---|---|---|
| Claude streaming JSON | No | Yes | Yes | No | No |
| Claude native channel | No | No | Yes | Yes | No |
| Codex App Server | Yes | Yes | Yes | Yes | Yes |
| Pi extension | Yes | Yes | Yes | Yes | Yes |
| Gemini ACP | No | Yes | Yes | No | Yes |
| Hermes ACP | No | Yes | Yes | Yes | Yes |

Each integration uses canonical Coord reads and attribution. Queued content
remains in Coord or the native harness. The integrations keep no separate
durable inbox. Recent attention-ID suppression is bounded to 128 entries;
restart uses the saved native session and verified cursor. Inspect native
history before repeating input whose application is uncertain.

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
session or remote procedure call (RPC) session. Enable external delivery with
`--coord-attention`.
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
access. An ACP frontend can select either command as its standard input/output
(stdio) server:

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

Gemini runs with `GEMINI_CLI_NO_RELAUNCH=1`. Its launcher does not fork a second
Node runtime that can survive the stdio owner's shutdown during a permission
request. Explicit heap settings in `NODE_OPTIONS` still apply.

Standard Gemini ACP has no steer or context-only primitive. Hermes ACP has no
context-only primitive. An unsupported mode fails before launching the client.
`--degrade-to queue` explicitly permits those requests to become queue/wake;
the bound notification reports both requested and effective modes. Peer text
cannot select fallback. This connection does not attach to another interactive
terminal.

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

## Claude Code streaming JSON

Use the complete native Claude Code client with its normal configuration and
authorized model access. Claude documents this persistent interface as
[streaming input](https://code.claude.com/docs/en/agent-sdk/streaming-vs-single-mode).
A frontend that sends and reads Claude's native
streaming JSON can select this command as its stdio process:

```sh
safeyolo-coord claude-attention --mode queue -- --model sonnet
```

The command launches `claude --print` with streaming JSON input and output,
verbose events and user-message replay. `SAFEYOLO_CLAUDE_BIN` selects the
complete executable or an authorized gateway launcher. This path needs no
additional software development kit (SDK) package or Node runtime.
Native user messages, controls, tools and permission replies pass through.
Native authentication, configuration and
permissions still apply. This connection owns its native session; it does not
attach to an unrelated interactive terminal.

Queue waits for the current native turn and queued frontend work to finish,
then sends attributed user input. An idle process wakes without terminal input.
This integration implements queue/wake only. Context-only, steer and interrupt
modes fail before the native client launches. `--degrade-to queue` explicitly
permits those requests to become queue/wake. The bound notification identifies
the requested and effective modes and the selected native session.

Pending means canonical resolution. Submitted means the native input was
written. Delivered means Claude replayed the matching user-message universally
unique identifier (UUID). This receipt identifies the echoed input. Inspect
assistant events and the native `result` separately for model application or
failure. A missing
matching replay stops external ingress and preserves the cursor and native
connection. A failed canonical read also stops ingress while keeping the
native connection.

Retain the delivered `next_cursor` with the native session ID. After restart,
pass `--session ID --since CURSOR` to resume that session and recover later
canonical input. An uncertain submission requires native-history inspection
before replay. Closing this connection stops its owned native consumer and
leaves the native session history available.

## Claude Code channel preview

Register the native helper as a Claude Model Context Protocol (MCP) server.
Use its absolute installed path in the normal MCP configuration:

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
with their source attribution. On the pinned Claude Code 2.1.303 client, a channel
event wakes an idle session without terminal input. During active work, Claude
can absorb an event after the running tool completes, before the current turn
finishes. This is safe-point steering, rather than queueing after current work.
`--mode steer` explicitly selects this behavior; omission uses the same mode.
Context-only, completion-boundary queue and interrupt requests are unsupported.
The initialization response exposes these capabilities separately from tool
discovery. No permission relay is declared. The helper requires no additional
Node runtime.

Use the native channel when attaching external events to an interactive session
with these semantics. Use the streaming connection when events must wait until
the current turn finishes. The native comparison demonstrated both idle wake
and a busy event influencing the same turn. Channels therefore do not replace
the streaming connection's completion-boundary queue behavior.

The native client must also enable the channel feature and applicable
organization policy. The Claude service catalogue permits the native client's
exact bootstrap, policy, settings and feature-configuration requests alongside
inference. Treat a failed setup request separately from a model request or an
upstream feature decision. A connected MCP server and successful model request
do not establish channel registration. Keep the native consent and policy
checks; the streaming integration uses its separate native input interface.

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
explicitly through `SAFEYOLO_CODEX_ATTENTION_MODEL`, `SAFEYOLO_PI_ATTENTION_MODEL`,
`SAFEYOLO_GEMINI_ATTENTION_MODEL`, `SAFEYOLO_HERMES_ATTENTION_MODEL` or
`SAFEYOLO_CLAUDE_ATTENTION_MODEL`, then run
`tests/proxy_contracts/test_native_harness_attention.py` with pytest.
Hermes also uses its normal `HERMES_HOME` profile and the native MCP extra for
the controlled tool-boundary cases. Keep its login and session history private.
Gemini can read an optional `SAFEYOLO_GEMINI_ATTENTION_KEY_FILE` into only its
child's `GEMINI_API_KEY`. Keep the credential outside the checkout and public
proof. Its disposable fixtures use the supported per-invocation `--skip-trust`
flag, preserving global trust and the existing participant home.
The Gemini frontend selects the native authentication method before reloading
a session; the key remains in the child environment.

The probe retains broker acceptance, native session events and the model's
response separately. The probes cover idle wake, busy delivery, supported
context-only, restart and attribution. The Claude streaming probe checks native
2.1.303, preserves its version with `DISABLE_AUTOUPDATER=1`, and uses private
session files. Select an authorized launcher with `SAFEYOLO_CLAUDE_BIN` when
needed. Transport controls exercise the separate Claude MCP channel's capability
report, canonical submission and refusal behavior. Native channel application
requires the interactive setup and consent described above. Synthetic native
controls test refusal and protocol handling; they do not substitute for the model
probes.
Unselected model probes skip without making inference requests.
