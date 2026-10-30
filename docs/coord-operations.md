# Coord operations

Use the installed CLI to send an operator message, chat with agents, or
watch a room's messages and harness events. These commands use the instance's
existing Coord store and NATS runtime. Host credentials stay on the host.
Guest `safeyolo-coord` calls retain agent attribution.
SafeYolo owns the host-local, authenticated NATS server's lifecycle. Do not
launch a second server or edit its generated configuration.

## Retry a membership change

Run grant and revoke as the host account that owns the instance. The room and
agent must already exist. In this example the instance is `$HOME/.safeyolo`,
the room is `chat`, and the agent is `alice`. Choose an operation ID before
calling if you need to recover from a lost response:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord grant chat alice receive --operation-id chat-alice-receive
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord revoke chat alice --operation-id chat-alice-revoke
```

Repeat the exact operation ID and input after an ambiguous response. SafeYolo
returns the original result, including its membership generation and transition
time. Permission order and duplicates do not change grant input. Omitting
permissions grants `receive`, `send` and `page_operator`. Explicit permissions
replace that set. Changing the canonical input under
the same ID returns a conflict. Grant and revoke have separate ID scopes.
To request a new change after a later grant or revoke, choose a new ID.
When you omit `--operation-id`, SafeYolo generates one and includes it in the
result; a lost response then also loses that retry handle.

Membership changes commit with immutable operation history and metadata-only
audit rows. The running proxy delivers staged Coord audit and attention hints
through one common worker. Staging is not delivery. Failed delivery remains
pending across restart; audit retries can produce duplicates with the same
`event_id`. The audit directory must permit a sibling `.lock` file. The writer
needs read and write access to recover an incomplete final line before append.
Canonical brief and message bodies stay in their existing stores.
These retry semantics do not apply to room creation or message sends.

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
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord brief set chat --file brief.md --expected-revision 0 --operation-id chat-intent-1
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord brief show chat
```

For a later update, read the current brief and use its revision as
`--expected-revision`. Inspect the existing text before replacing it. Set accepts
exactly one source: a Markdown argument, `--file FILE`, or `--stdin`. It preserves
the input bytes, including trailing newlines. A different operation with a stale
revision fails without changing the brief or emitting brief-change attention.

If the result is uncertain, retry with the same `--operation-id`, original
expected revision and exact Markdown. Keep the original input file for that
retry. The command returns the original committed result even if a later
operation has changed the brief. It does not reapply the old intent. Changed
input under the same ID fails with an operation conflict. Read the current brief
separately to inspect any later change. The operation ID is scoped to the
operator and brief-set operation type across rooms. If you omit
`--operation-id`, the command generates an ID and reports it in its result;
choose the ID before the first attempt when you need ambiguous-result recovery.

Successful writes report the operation ID, revision/hash and attention count. Each write
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

## Claim durable work

On the owning host account, select an initialized instance with an existing
room and authorized agents. For example, create local work in room `chat`:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord work create chat 'Review the README first-use instructions' --external-ref github://craigbalding/safeyolo/issues/1303 --operation-id readme-review
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord work list chat --state open
```

Creation returns `work` and `operation_id`. The work starts at `version=1`
and `claim_generation=0`. The reference is opaque. SafeYolo never fetches it
or uses an external assignee or description to decide ownership.

With the instance proxy running, a room member uses `list_work` and `read_work`
through the native Coord MCP tools. The member calls `claim_work` with
`room_name`, `work_id`, `expected_version`, `expected_generation` and a chosen
`operation_id`. Exactly one caller can claim an open version. The response
identifies the holder by durable `claim_agent_id`. Rename preserves that ID;
delete/recreate does not inherit it. Each successful claim or reassignment
increments `claim_generation`; every mutation increments `version`.

The holder calls `release_work` or `complete_work` with the current version
and generation. Completion accepts optional `short_result`. Reads require
current `receive` permission. Mutations require `send` and `receive`. Revocation
prevents the former member from reading, releasing or completing work.

Claims survive elapsed time, model exit, and instance restart. They never
expire or transfer automatically. `claim_expires_at` is reserved and stays
null. The owning host account can inspect and recover an abandoned claim
without relying on process liveness. Use `coord work --help` for the recovery
commands. `release` requires the current expected version and generation;
`reassign` also requires the new holder's durable `--agent-id`. The new holder
must have current room send and receive permission.

Choose an operation ID before a write. If the response is lost, retry the same
operation ID and original inputs, including the original expectations. While
room authority remains current, the retry returns the original result even
after later mutations. Changed input under that ID conflicts. For a new intent,
read the current work and use a new operation ID. A former holder cannot use
stale versions or generations to change a later claim.

Work mutations notify current receive-authorized agents except the agent actor;
operator mutations notify all such agents. Attention resolves the original
immutable version, which may differ from current work. Audit and wake hints
contain metadata; canonical work storage contains titles, references and
results. Work input is bounded to 262144 UTF-8 bytes. Lists return at most 200
items ordered by `work_id`; use `next_after` to continue. Concurrent changes
can affect later pages because pagination does not share a snapshot.

## Raise a material signal

With the selected instance's proxy running, a room member uses the native
`create_signal` tool. The member needs `send` and `receive` permission.
For example, a member of room `chat` reports an observed failure:

```json
{"room_name":"chat","kind":"blocker","summary":"The acceptance command failed with EMFILE; I need help checking the child limit.","basis":"observed","refs":["opaque:retained-command-output"],"operation_id":"child-limit-symptom"}
```

The response contains `signal`, `content_hash` and `operation_id`.
The trusted listener supplies the durable author identity. `observed` means
the author reports an observation. `inferred` labels an inference. Neither
basis independently proves the claim. References are opaque strings and are
never fetched. An optional `work_id` must identify work in the same room.

The four kinds are `blocker`, `decision`, `result` and `correction`.
Only unresolved blockers and decisions with `page_operator` permission create
operator attention. Ordinary members can still create signals without that
permission. Results and corrections do not page. Work completion retains its
own `short_result` and never creates a result signal.

On the owning host account, newly created local rooms use default member
grants that include `page_operator`. To remove Bob's paging permission while
preserving signal creation in an existing room `chat`, replace his grant:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord grant chat bob send receive
```

The change affects future pages. Existing pending signals remain pending.
An identical current blocker or decision from the same author deduplicates
to the existing signal, even with another operation ID. A room permits at
most five new pages per author and 20 total pages in 60 seconds. Excess claims
are stored with `page_status=rate_limited` and `needs_operator=false`.
Permission-denied pages likewise retain the claim with
`page_status=permission_denied`. Granting permission later does not page an
older claim automatically.

On that host account, watch pending signals through the running Admin API:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" watch
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" watch --once --json
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord signal list chat --needs-operator
```

Each attachment displays a pending revision once and reports when an item
leaves needs-operator. Ctrl-C detaches. Canonical unresolved signals survive
watch detachment, proxy restart and NATS restart. Watch reads bounded metadata
pages, then fetches each exact immutable revision through Admin API. Audit
JSONL contains signal identity, kind, author, basis, revision, state and hash;
it contains no summary or refs. `watch --jsonl FILE` and
`coord watch --jsonl FILE` fetch the revision named by each signal event from
the selected running instance. Historical revisions are labelled as revisions,
not current pending claims. Terminal controls are escaped. Markup is displayed
as text.

To inspect or resolve a signal, first use `coord signal list chat` to obtain
its ID and current revision. For example, if it returns the values assigned
to `signal_id` and `revision` below, use those exact values on the host:

```sh
signal_id='sig-REPLACE_WITH_RETURNED_ID'
revision=1
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord signal show chat "$signal_id" --revision "$revision"
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord signal resolve chat "$signal_id" --expected-revision "$revision" --operation-id answer-child-limit
```

Only the operator resolves signals. Resolution removes needs-operator while
preserving the original author and every revision. A stale expectation fails.
An author corrects their own claim by creating a `correction` with
`supersedes={"signal_id":"the prior signal ID","expected_revision":1}`.
The prior signal's current projection becomes `superseded`; its original
revision remains readable through `read_signal` with `revision=1`.
A peer or a replacement durable identity cannot supersede that author's claim.
Current lists omit resolved and superseded claims by default. Use
`list_signals` with `state=all`, or read an exact revision, to inspect history.

Choose an operation ID before writing. An identical retry returns its original
result while current room authority remains valid. Changed input under the same
ID conflicts. Correction expectations and resolution expectations refer to the
current revision, not the creation revision. Each changed signal revision,
current projection, operation outcome and metadata audit event commits in one
SQLite transaction. A correction updates both claims in that transaction.

Summaries permit 1–1024 UTF-8 bytes. References permit at most 16 strings of
1024 bytes each. The complete mutation permits at most 32768 bytes. Unknown
fields and unrecognised kinds or bases are refused. Lists contain at most 100
items and 65536 bytes of items per page, ordered by `signal_id`. Follow
`next_after`; pages do not share a snapshot. Room state includes bounded
`signals` and `needs_operator` pages with counts and continuation values.

## Return to the current room state

On the owning host account, select an existing room in the instance whose proxy
is running. For room `chat`, run:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord status chat
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord status chat --json
```

The text command shows the brief revision and its first 2048 UTF-8 bytes, current
agent members, specialist capabilities, resource leases, active work, completed
work, pending operator needs and latest current results or corrections. It uses
the same canonical projection as `get_room_state()` and `coord state ROOM`.
It reads current tables without replaying chat or asking a model to summarize it.
The brief excerpt is text; status does not infer goal or priority fields from
Markdown. Use `coord brief show ROOM` for the full brief.

Active ownership comes from the current work version. Releasing a claim removes
its owner; reassignment replaces its owner. Time and process liveness do not
release a durable claim. Completed work appears separately with its retained
result and last holder. A signal's `observed` or `inferred` basis remains its
author's report, not an independent attestation. Resolved or superseded signals
do not appear as current needs or results.

Each section contains at most 50 items and 64 KiB of item JSON. Counts and
truncation identify omitted items. Members and leases are ordered by durable
agent ID and provider/resource respectively. Active work is ordered by work ID;
completed work and current material results use newest update first, with
durable IDs breaking ties. Reads add no changing generation timestamp; identical
current facts and freshness give identical JSON and text. Current signals and operator needs retain their
signal-ID ordering and continuation values. Per-member verified and declared
arrays have limits of 50 entries and 16/8 KiB respectively. Work titles and
completion results contain at most 512 UTF-8 bytes each. Excerpts preserve code
point boundaries and report original byte counts. The complete projection is
limited to 512 KiB. Use `coord work show` and `coord signal show` for complete
records, and their list commands to inspect larger worksets.

Authorized specialist labels require current grants. Declarations remain
unverified. Availability requires fresh provider evidence; missing or stale
evidence yields unknown availability. Revocation is rechecked after
provider reads. Text and JSON output escape terminal and direction controls;
signal markup remains text. Bare `coord status` continues to report the owned
NATS process, independently of a room's work state.

## Inspect room capabilities and resource leases

On the owning host account, use an existing room and configured agent in the
selected instance. Start that instance's proxy before reading state. The
following examples use room `chat`, agent `bob` and the
public collaboration label `rundeck:acceptance_runner`:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord inventory advertise-capability chat bob rundeck:acceptance_runner --operation-id chat-bob-runner
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord inventory advertise-resource chat rundeck acceptance_runner
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord state chat
```

Advertising selects room visibility. It does not grant service access. A member's
`verified` list contains only advertised labels that match current host service
grants and the active gateway policy. A saved, rejected policy edit cannot
create verified authorization. Revocation removes a label on the next state
read. An agent can replace its expiring `declared` skills through
`declare_capabilities`; those declarations
cannot create verified authorization or availability. The Agent API and Model
Context Protocol (MCP) expose the same projection to receive-authorized members.

A trusted provider integration must atomically replace
`<root>/coord-providers/<provider>.json` with public observations from that
provider. Keep the directory outside agent-writable mounts. Coord only reads
these observations; writing a JSON file does not establish provider provenance.
The file contains `capabilities` and `leases` arrays. Capability observations
identify `agent_id`, `capability` and `availability` (`available` or
`unavailable`). Lease observations identify `resource`, `state` (`held` or
`unleased`) and `holder_agent_id` (a current room member for `held`, null for
`unleased`). Each observation contains integer Unix-millisecond `observed_at`
and `valid_until` timestamps. Fresh evidence requires
`observed_at <= now < valid_until`, with at most five minutes between the
timestamps. Do not put credentials, accounts, connection configuration or raw
errors in this file.

Only fresh provider evidence can establish availability or lease ownership.
Missing, failed, malformed or expired evidence produces `unknown`. An expired
observation retains its timestamps and reports `freshness: "stale"`. Coord does
not renew or transfer provider leases. Chat cannot change their holders. State
reads select advertised provider filenames without registration, including
after restart. Each file is limited to 512 KiB and 1,024 observations. Reads
have a one-second deadline, a process-wide limit of 32 in flight and a limit
of two per provider. A blocked file cannot consume the executor used for room
authorization reads.

To stop sharing a label, use `unadvertise-capability ROOM AGENT LABEL` or
`unadvertise-resource ROOM PROVIDER RESOURCE` with the same command prefix.
Advertisement changes accept an optional `--operation-id ID`; an identical retry
returns the original result, while changed input under that ID conflicts.
They use the existing atomic operation ledger and audit outbox. Raw provider
payloads and errors are never returned in room state or those audit events.

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

When the proxy is stopped, `safeyolo start` starts the proxy and managed NATS
concurrently. The command waits for both startup attempts. Each service retains
its own ownership and readiness checks. If Coord startup fails, the command
warns and leaves a healthy proxy available. The first-agent launch also checks
Coord readiness before it starts the sandbox and coding client.

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
