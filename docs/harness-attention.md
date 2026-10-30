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
available primitives. `safeyolo/attention/delivered` reports native acceptance,
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
and abort primitives respectively. Context waits for a subsequent prompt and
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

## Focused real model probe

From a repository checkout, use the existing locked Python test environment,
current native production artifacts, the pinned NATS binary and an installed,
authorized native client. The test creates an owned Coord instance and private
session files below the chosen disk-backed pytest scratch root. Select a model
explicitly through `SAFEYOLO_CODEX_ATTENTION_MODEL` or
`SAFEYOLO_PI_ATTENTION_MODEL`, then run
`tests/proxy_contracts/test_native_harness_attention.py` with pytest.

The probe retains broker acceptance, native session events and the model's
response separately. The initial probe covers idle wake and peer attribution.
It does not establish all nine issue checks or the five-harness minimum.
Unselected model probes skip without making inference requests.
