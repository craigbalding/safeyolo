# Coord operations

Use the installed CLI to send an operator message, chat with agents, or
watch a room's messages and harness events. These commands use the instance's
existing Coord store and NATS runtime. Host credentials stay on the host.
Guest `safeyolo-coord` calls retain agent attribution.
SafeYolo owns the host-local, authenticated NATS server's lifecycle. Do not
launch a second server or edit its generated configuration.

## Schedule an operator message

Use a host scheduler when a message must be sent while the target sandbox is
stopped. This recipe runs as the trusted host account that owns the instance.
Its proxy and Coord must be running; the target guest may be stopped.
Create the room and grant its intended recipient as described below first.
The example uses room `scheduled-work` and recipient `alice`.

On that host, create `~/scheduled-coord-message.txt` with the intended UTF-8
message. Keep the file and wrapper in host-owned paths outside agent-writable
mounts. Create `~/bin/post-scheduled-coord` with this content and make it
executable. Replace `/absolute/instance` with the selected instance path before
running it:

```sh
#!/bin/sh
set -eu
exec /absolute/instance/bin/safeyolo --root /absolute/instance coord send scheduled-work --file "$HOME/scheduled-coord-message.txt" --to alice --content-type text/plain
```

On a Linux host with cron already running, use the owning account's
`crontab -e` to add a UTC entry. Replace `/absolute/operator-home` with that
account's home. This entry runs every day at 09:00 UTC when the host timezone
is UTC; check `date '+%F %T %Z'` first.

```cron
0 9 * * * /absolute/operator-home/bin/post-scheduled-coord >>/absolute/operator-home/scheduled-coord.log 2>&1
```

On macOS, the same wrapper can be invoked by an operator-maintained LaunchAgent
or the host account's existing cron setup. Use that scheduler's timezone and
missed-run rules. No automatic wake or guest start is provided. History must
show `sender_kind=operator`, with no agent identity. Check the log and retained
message after execution; do not repeat an uncertain send without checking
history. This recipe gives guest jobs no host scheduler or operator credentials.

## Send and converse

Run commands as the host account that owns your
[instance](installation.md#install-and-start). The following examples
use `$HOME/.safeyolo`. Agent `alice` must already be configured in that
instance. Starting Coord acquires its pinned NATS binary if needed. Creating
`chat` grants the operator room access; the next command grants `alice` access.
`--to alice` sends attention only to that receive-authorized member.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord start
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord room create chat
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord grant chat alice
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord send chat 'Please inspect the failing command.' --to alice
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord history chat
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord chat chat --to alice
```

Send reports its sequence, attention intent and delivery status. History emits
canonical messages as JSON Lines (JSONL). The marker has `sender_kind` set to
`operator` and no agent identity. A guest cannot select operator attribution.

Interactive chat requires both standard input and standard output to be terminals.
If either is piped or redirected, the command exits before connecting. It does
not consume input or emit terminal cursor controls. Use `--observe` for a
non-interactive room stream.

Chat displays arriving messages above the editable `op>` prompt. The draft and
cursor remain intact. Enter sends the draft; `:q`, Ctrl-D or Ctrl-C detaches.
`:paste` (or `:p`) reads the host clipboard. `:edit` (or `:e`) opens `$VISUAL`,
then `$EDITOR`, with `vi` as the fallback. Clipboard/editor composition requires
confirmation. No chat transcript or draft is saved separately from room history.
Clipboard and editor input replace malformed UTF-8 bytes with the replacement
character. Clipboard commands retain their ten-second timeout.
Use `chat --observe` for a read-only stream without a terminal prompt.

Scripted send accepts exactly one UTF-8 source: text, `--file FILE`, or `--stdin`.
It preserves the selected payload, including trailing newlines and controls.
Empty/whitespace-only input, multiple sources, unreadable/non-UTF-8 input and
invalid notification targets fail without publication. `--content-type` accepts
`text/markdown` (default) or `text/plain`. Repeat `--to` for several members.
Without `--to`, scripted send notifies the room. Interactive chat also defaults
to room attention, unless an approved Factory snapshot selects one
operator-input agent. An explicit `--to` overrides that default.
The command reports authorization, room, target and provider errors without
printing credentials. `dispatch-trigger` remains the separate command for
Dispatch publication requests.

If publication acknowledgment is lost, the command reports acceptance as
**UNKNOWN**. It does not resend automatically. Inspect history before deciding
whether to send the message again. A later independent send remains available.
Accepted messages with pending or lost attention retain that diagnosis.

## Read and update a trusted brief

On the owning host account, select an existing room in the instance.
The following examples use `chat` from the setup above. Read its current brief:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord brief show chat
```

The JSON output contains the exact Markdown, revision and SHA-256 content hash.
If the room has no brief, the output has `state: "none"`, revision `0`, and
null Markdown and hash. A missing room or unavailable store produces an error;
neither result means that a brief is absent.

To create a brief after observing revision `0`, write your standing context
in a UTF-8 file named `brief.md` in your current directory. The input must be
nonempty and no larger than 65,536 UTF-8 bytes. This command creates revision
`1` only if the room still has no brief:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord brief set chat --file brief.md --expected-revision 0
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord brief show chat
```

For a later update, read the current brief and use its revision as
`--expected-revision`. Inspect the existing text before replacing it. Set accepts
exactly one source: a Markdown argument, `--file FILE`, or `--stdin`. It preserves
the input bytes, including trailing newlines. A stale revision fails without
changing the brief or emitting brief-change attention. If a command's result
is uncertain, read the canonical brief before deciding whether to write again.

Successful writes report the new revision/hash and attention count. Each write
retains operator attribution and notifies current receive-authorized members
through `brief_changed`. Agents can read authorized briefs but cannot update
them. A brief is optional standing context: it does not assign work, require a
terminal response, or change workflow state. See [Factory authority and
intake](factories.md#authority-and-intake).

## Observe messages and harness events

On the same host, watch the existing room with:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord watch chat
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

`--compact` selects a concise transcript. It shows
`$` for commands, `@` for tools and Coord receipts, `#` for agent text and
lifecycle events, `>` for canonical operator messages, and `!` for failures.
The operator marker comes from the Coord envelope. In a terminal, each wrapped
body continuation carries a gutter, including with color disabled.
Matching successful completions do not
repeat their start line. A completion whose start precedes the selected history
is still shown. Failed commands include a redacted final output line. Compact
mode also shows file-change totals, short token counts and successful skill-file
reads. A file-read line confirms the read, not that the agent followed the skill.
Use `--plain` as an alias for `--no-color`. Raw, JSON and compact modes are
mutually exclusive.

The installed `bin/watch-backlog-factory` wrapper opens the existing Relay,
Forge and Lens rooms in three tmux panes. Run it inside your operator tmux
session. Set `SAFEYOLO_FACTORY_CONFIG_DIR` to the instance root first.
Its default CLI is that root's `bin/safeyolo`; `SAFEYOLO_FACTORY_CLI` can select
another installed executable. `SAFEYOLO_FACTORY_NATIVE_CONFIG` can select a
different configuration file. The wrapper starts observers; it does not
start or resume a factory. Its panes select `--compact --redact`.

## Focused proof and remaining work

`tests/proxy_contracts/test_native_coord_operator.py` binds the installed G5
PTY, input, publication-count and observer scenarios to real disposable NATS.
Only the test driver uses Python. For the required Ubuntu systrap observation,
`tests/nested-linux/operator_coord_acceptance.py` uses an already running
disposable installed proxy and guest. Supply their root, guest name and exact
commit with `--root`, `--agent` and `--commit`. It observes guest
send/read, guest arrival during a PTY draft, exact operator/agent attribution
and the room timeline, then stops
that guest, proxy and Coord. It needs the matching guest helper staged
at `/home/agent/.safeyolo/safeyolo-coord`. A host-only probe does not prove that
guest boundary.

Use the same installed CLI for [Dispatch period requests](dispatch-publication.md)
and [generation/site validation](dispatch-generation.md), and for
[Mattermost exchange and semantic actions](coord-mattermost.md). The [responsibility map](settings.md#operator-entry-responsibilities)
records the accepted Ubuntu G2/G4 exchange and physical VZ G7 result at their
actual driver/package revisions. Final whole-product packaging and
execution coverage remain with #822.

## Room storage

Rooms share the managed NATS server's total storage budget. They do not reserve
a fixed number of bytes per room. Age and message-count retention still remove
old messages within each room. The message-size limit is unchanged.

At normal Coord startup and before creating a room, SafeYolo upgrades the former
100 MiB room byte reservation in place. The upgrade preserves messages,
sequences, subjects, and other stream settings. It only changes streams whose
enforced settings match the known old contract; unrelated configuration drift
is not overwritten. No room deletion or server restart is required for the
stream update.

Removing reservations removes the accidental ten-room ceiling; it does not
make storage unlimited. Rooms compete for the shared budget. If actual stored
data exhausts that budget, new writes can fail across rooms. The server does
not evict another room's history to make space for a write.

## Reconcile a running proxy

If the proxy is already running, `safeyolo start` reconciles the managed Coord
runtime. A healthy NATS process stays running. If the managed NATS process is
absent, SafeYolo starts it, bootstraps the existing Coord registry, and recovers
pending attention data. This operation preserves the instance identity,
credentials, rooms, memberships, control state, and retained JetStream history.

If NATS startup, Coord bootstrap, or attention recovery fails, the command
reports that Coord is degraded and gives diagnostic commands and log paths. It
does not restart the proxy, and the proxy remains available. Run `safeyolo
doctor` and inspect the reported log before you retry.

## Historical Python credential lifecycle

The following credential and rotation procedures describe the earlier Python
installation. They do not convert old state. For current instance commands,
use [send and converse](#send-and-converse).

On the first coord start, SafeYolo generates a random password and stores it at
`~/.safeyolo/data/coord/nats/creds`. The host account that runs SafeYolo owns
the credential. The `nats` directory is mode `0700` and the credential file is
mode `0600`.

`SAFEYOLO_COORD_DATA_DIR` is the coord-specific path override. When it is set,
the credential is at `$SAFEYOLO_COORD_DATA_DIR/nats/creds`. In that Python release, setting only
`SAFEYOLO_CONFIG_DIR` does **not** relocate coord data;
for an isolated non-default instance, also set `SAFEYOLO_COORD_DATA_DIR` to the
intended coord directory and use the same environment for every `safeyolo`
lifecycle command.

The credential is reused across ordinary `safeyolo stop` / `safeyolo start`
cycles. It is not rotated on restart or on a schedule. If the credential file
is absent at startup, SafeYolo atomically generates a replacement. The
generated `nats.conf` contains an environment-variable reference, not the
password; the password is supplied only in the managed NATS child process's
environment. Retained JetStream data lives separately under
`nats/jetstream`.

### Manual rotation

Rotation is disruptive and has no old/new overlap or grace period. Stop the
whole SafeYolo instance first, fail closed unless both stop checks prove the
message plane stopped, remove exactly the credential file, and then start it
again:

```bash
coord_data_dir="${SAFEYOLO_COORD_DATA_DIR:-${HOME}/.safeyolo/data/coord}"
credential_file="${coord_data_dir}/nats/creds"

stop_output="$(safeyolo stop 2>&1)"
printf '%s\n' "${stop_output}"
case "${stop_output}" in
  *"coord message plane stopped"*) ;;
  *) printf '%s\n' "Rotation aborted: coord stop was not confirmed." >&2; exit 1 ;;
esac

doctor_output="$(safeyolo doctor --json || true)"
if ! jq -e '
  [.checks[] | select(
    .name == "Coord message plane" and
    .message == "nats-server not running; coord API will 503"
  )] | length == 1
' >/dev/null <<<"${doctor_output}"; then
  printf '%s\n' "Rotation aborted: coord is not confirmed stopped." >&2
  exit 1
fi

if [ ! -f "${credential_file}" ]; then
  printf '%s\n' "Rotation aborted: credential file was not found." >&2
  exit 1
fi
if ! rm -- "${credential_file}"; then
  printf '%s\n' "Rotation aborted: credential file was not removed." >&2
  exit 1
fi
safeyolo start
```

Do not continue merely because `safeyolo stop` returned normally. Stop is
best-effort: it can warn about a healthy, wedged, or unknown NATS process and
still let the rest of SafeYolo shut down, and it does not stop coord again when
the proxy was already absent. The success line plus the independent doctor
check close both cases. Abort and investigate any warning, failed guard, or
state other than the exact `not running` result; do not delete the credential
while a NATS process may still be alive.

Do not remove `${coord_data_dir}/nats`, its `jetstream` child, or the wider
coord data directory. Those paths hold retained room history and control
state. If `test -f` fails, stop and confirm the environment and path instead
of deleting a broader directory.

Every connected NATS client is disconnected during the stop. After startup,
only the replacement password works, so clients must reconnect; agents may see
temporary coord-unavailable responses during the rotation. SafeYolo's managed
clients reconnect as the instance starts.

Verify the legacy runtime and room list without displaying either credential:

```bash
safeyolo status
safeyolo coord room list
```

`safeyolo status` should report `Coord (nats-server)` as healthy. Confirm the
expected rooms remain registered. This check does not prove
message history. Current operator communication uses the separate fresh
instance described in [send and converse](#send-and-converse).


### Historical secret-handling boundary

Status, doctor output, lifecycle diagnostics, generated configuration, and
logs must never contain the raw credential. Do not print, copy into a command
line, attach, or log the contents of `creds`; use the health and history checks
above as the verification signal.

The file modes protect the credential from other host accounts. They are not a
security boundary against a compromised operator account: a same-UID host
process can read host-local files and may be able to inspect process state or
environment. Rotate after suspected operator-account compromise only as part
of recovering that account and host.
