# Native operator communication

Use the installed native CLI to send an operator message, chat with agents, or
watch a room's messages and harness events. These commands use the instance's
existing Coord store and NATS runtime. Host credentials stay on the host.
Guest `safeyolo-coord` calls retain agent attribution.

## Send and converse

Run commands as the host account that owns your
[native instance](native-policy.md#install-and-start). The following examples
use `$HOME/.safeyolo-native`. Agent `alice` must already be configured in that
instance. Starting Coord acquires its pinned NATS binary if needed. Creating
`chat` grants the operator room access; the next command grants `alice` access.
`--to alice` sends attention only to that receive-authorized member.

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord start
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord room create chat
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord grant chat alice
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord send chat 'Please inspect the failing command.' --to alice
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord history chat
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord chat chat --to alice
```

Send reports its sequence, attention intent and delivery status. History emits
canonical messages as JSON Lines (JSONL). The marker has `sender_kind` set to
`operator` and no agent identity. A guest cannot select operator attribution.

Chat displays arriving messages above the editable `op>` prompt. The draft and
cursor remain intact. Enter sends the draft; `:q`, Ctrl-D or Ctrl-C detaches.
`:paste` (or `:p`) reads the host clipboard. `:edit` (or `:e`) opens `$VISUAL`,
then `$EDITOR`, with `vi` as the fallback. Clipboard/editor composition requires
confirmation. No chat transcript or draft is saved separately from room history.
Use `chat --observe` for a read-only stream without a terminal prompt.

Scripted send accepts exactly one UTF-8 source: text, `--file FILE`, or `--stdin`.
It preserves the selected payload, including trailing newlines and controls.
Empty/whitespace-only input, multiple sources, unreadable/non-UTF-8 input and
invalid notification targets fail without publication. `--content-type` accepts
`text/markdown` (default) or `text/plain`. Repeat `--to` for several members.
Without `--to`, scripted send notifies the room. Interactive chat also defaults
to room attention, unless an approved native Factory snapshot selects one
operator-input agent. An explicit `--to` overrides that default.

If publication acknowledgment is lost, the command reports acceptance as
**UNKNOWN**. It does not resend automatically. Inspect history before deciding
whether to send the message again. A later independent send remains available.
Accepted messages with pending or lost attention retain that diagnosis.

## Observe messages and harness events

On the same host, watch the existing room with:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" coord watch chat
```

Watch displays the last 30 retained messages and then follows the room. It
renders ordinary messages and existing Codex/Pi session, turn, reasoning, tool,
usage, stderr and supervisor events. Tool summaries show routing arguments;
they do not dump tool request bodies or results. Unknown events appear with
`--show-unknown`. Oversize summaries retain the omitted-middle marker.

Text is complete by default. `--max-text COUNT` limits rendered text only.
`--history COUNT` selects the retained tail; `--once` prints it and exits.
`--since SEQUENCE` reads every message after the selected cursor. A live watcher
retains its rendered cursor during NATS reconnection and reports loss/recovery.
Terminal controls are shown as visible text in chat, rendered and raw modes.
Bidirectional text controls are also named visibly.

`--raw` displays message bodies without event summarization. `--json` emits
canonical envelopes and exact payloads as JSONL, with controls JSON-escaped.
`--redact` optionally hides common credential patterns and URL queries in each
mode; stored messages are unchanged. `--no-color` or `NO_COLOR` disables color.
`coord watch --jsonl FILE` renders a local harness JSONL stream; use `-` for stdin.

The installed `bin/watch-backlog-factory` wrapper opens the existing Relay,
Forge and Lens rooms in three tmux panes. Run it inside your operator tmux
session. Set `SAFEYOLO_FACTORY_CONFIG_DIR` to the native instance root first.
Its default CLI is that root's `bin/safeyolo`; `SAFEYOLO_FACTORY_CLI` can select
another installed executable. `SAFEYOLO_FACTORY_NATIVE_CONFIG` can select a
different native configuration file. The wrapper starts observers; it does not
start or resume a factory.

## Focused proof and remaining work

`tests/proxy_contracts/test_native_coord_operator.py` binds the installed G5
PTY, input, publication-count and observer scenarios to real disposable NATS.
Only the test driver uses Python. For the required Ubuntu systrap observation,
`tests/nested-linux/operator_coord_acceptance.py` uses an already running
disposable installed proxy and guest. Supply their root, guest name and exact
commit with `--root`, `--agent` and `--commit`. It observes native guest
send/read, guest arrival during a PTY draft, exact operator/agent attribution
and the room timeline, then stops
that guest, proxy and Coord. It needs the matching native guest helper staged
at `/home/agent/.safeyolo/safeyolo-coord`. A host-only probe does not prove that
guest boundary.

Mattermost remote/mobile exchange and semantic actions, and Dispatch period
requests/rendering, are retained for their separate native G6 implementation.
They are outside this communication increment. Other staging dependencies and
unfinished G2/G4/G7 proof remain in the
[responsibility map](native-settings.md#operator-entry-responsibilities).
