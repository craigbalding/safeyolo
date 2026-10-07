# Native Mattermost Coord adapter

The optional native Mattermost adapter projects selected Coord rooms to one operator.
Coord remains authoritative. Mattermost is neither a coordination backend nor
a coord principal, and message text, usernames, thread IDs, and button labels
are never trust evidence.

The adapter uses Mattermost REST API v4 with a dedicated non-admin [bot
account and bot access
token](https://developers.mattermost.com/integrate/reference/bot-accounts/).
Routine messages need only outbound post creation and bounded channel polling.
Optional operator buttons use Mattermost's supported legacy [interactive
message attachments](https://developers.mattermost.com/integrate/plugins/interactive-messages/),
which remain compatible with Mattermost 11.9.x and the stock Android client.
No Mattermost plugin or PikaPods-specific feature is required.

Use the native CLI installed with your [native instance](native-policy.md#install-and-start).
Run the adapter as the host account that owns that instance. The native bundle's
`bin/safeyolo` supplies the adapter; no Python package, guest helper or additional
Mattermost executable is required. The retired Python CLI no longer registers
`coord mattermost`.

## Projection and trust

Routine or unrecognized messages put the useful body first and one quiet
`Canonical provenance` footer last. The footer keeps the exact canonical agent
and message IDs in copyable code spans and, when present, the canonical public
attention mode (`none`, `room`, or `targeted`). It never exposes recipient
identities or membership counts. Only that final footer is trusted; sender text
cannot create its divider or marker. An exact leading protocol `ACCEPTED` is
displayed as `TASK ACCEPTED` in Mattermost only. The canonical coord message is
unchanged, and the adapter does not infer workflow state.

The body sanitizer preserves paragraphs, headings, lists, emphasis, inline and
fenced code, and ordinary HTTPS links. It applies this fixed safety matrix:

| Sender input | Routine projection |
|---|---|
| `@user`, `@channel`, `@all`, `@here`, or group mentions | full-width, non-notifying `＠` text |
| `~channel` | full-width, non-linking `～` text |
| Markdown image | a normal HTTPS text link labelled `image:` |
| non-HTTPS or Mattermost `mmaction://` link | visible `[blocked link]` text |
| controls or Unicode ordering controls | visible `\uXXXX` text |
| horizontal rule or provenance-like sender text | inert sender text, distinct from the final footer |
| oversized body | bounded complete text, balanced code delimiters, and a SHA-256 truncation marker |

Routine post creation uses Mattermost's `silent=true` mode, so it does not
increment mentions/unreads or send push, desktop, or email notifications. An
exact empty legacy-attachment property prevents automatic link/image previews
without registering an action. Arbitrary Markdown therefore cannot create a
button or callback: only the exact semantic schema below can produce a
non-empty attachment with an action integration.

A semantic attachment is rendered only when all of the following match:

- the transport-derived envelope says `sender_kind=agent`;
- `sender_agent_id` exactly matches an ID in
  `trusted_action_agent_ids`;
- `content_type` is exactly `text/plain`; and
- the whole body is the exact fixed
  `safeyolo.coord.operator-request/v1` JSON schema described below.

Copied JSON, Markdown, prose that resembles a request, an untrusted agent, an
unknown field, duplicate JSON key, invalid kind/action pair, or malformed value
falls back to an inert routine projection with no button. The adapter does not
infer intent from prose.

Buttons do not directly approve, publish, open an issue, or execute any other
workflow. A valid click appends one structured canonical coord operator
message. The coordinator or workflow consuming coord decides what that action
means.

### Fixed operator-request schema

The body has exactly these keys:

```json
{
  "schema": "safeyolo.coord.operator-request/v1",
  "kind": "decision",
  "title": "Release candidate ready",
  "summary": "The reviewed tree is ready for live acceptance.",
  "reference": "PR #450",
  "details": ["CI passed", "Lens READY"],
  "allowed_actions": ["approve", "reject", "revise"]
}
```

Send it as declared `text/plain`, not Markdown. This is a deliberately closed
schema, not a generic card or forms framework:

| Kind | Allowed button vocabulary |
|---|---|
| `status` | none |
| `decision` | `acknowledge`, `approve`, `reject`, `defer`, `revise` |
| `factory-proposal` | `open-issue`, `revise`, `defer`, `reject` |
| `dispatch-publication` | `publish`, `revise`, `defer` |

The current complete vocabulary is `acknowledge`, `approve`, `reject`,
`defer`, `revise`, `publish`, and `open-issue`. Free-form input remains an
ordinary Mattermost thread reply.

### Interactive callback boundary

Each actionable projection gets one random opaque capability. Only its
SHA-256 digest and correlations are stored locally; the raw capability exists
only in Mattermost's server-confidential action context and the callback.
Before a click becomes a coord append, the adapter
validates the exact configured human user, channel, post/root, durable coord
projection, adapter identity, projection key, permitted action, capability,
expiry, and one-shot state. It revalidates that the configured Mattermost
operator is still an active human immediately before consuming the capability.

The durable state changes from `issued` to `pending` before the coord append
and to `used` only after a canonical coord message ID is returned. A replay is
rejected. If append success is uncertain, the capability stays `pending` and
is never retried automatically, so a crash cannot duplicate a trusted operator
message. Ordinary room projection and thread replies continue. Inspect the
canonical coord room before manually recovering an uncertain action.

After success the operator gets ephemeral feedback and the bot best-effort
patches its post to remove the buttons. A patch failure cannot undo or repeat
the accepted coord action.

The callback HTTP server is intentionally narrow: one POST path and one GET
health path, loopback bind only, HTTPS public-base canonicalization, fixed
header/body limits, a whole-request timeout, duplicate-header rejection,
bounded concurrency, sanitized failures, and clean bind/shutdown/restart
lifecycle. Listener or tunnel failure is isolated from ordinary projection and
replies; new posts simply contain no interactive buttons. The adapter does not
start or supervise a tunnel.
Incomplete or malformed wire requests return HTTP 400. Processing timeouts
return HTTP 503; any pending action still requires reconciliation.

## Operator-owned setup

On a fresh or self-hosted Mattermost deployment, a Mattermost System Admin may
first need to enable **System Console > Integrations > Bot Accounts > Enable
Bot Account Creation**. Create a dedicated SafeYolo bot, add it directly as a
normal member of every mapped channel, and do not grant it System Admin.

Keep these operator-owned files outside the repository:

1. `~/.safeyolo-native/mattermost-bot-token`, mode `0600`, containing only the bot
   token.
2. `~/.safeyolo-native/coord-mattermost.toml`, containing the adapter configuration.

Start with a new state filename. The native adapter refuses an older Python
adapter database and does not convert it. Preserve the old database. Changing
the action configuration also requires a fresh state path because that
configuration is part of the adapter's durable identity:

```toml
version = 1
server_url = "https://YOUR-MATTERMOST-ORIGIN"
bot_token_file = "~/.safeyolo-native/mattermost-bot-token"
bot_user_id = "26_CHARACTER_MATTERMOST_BOT_USER_ID"
operator_user_id = "26_CHARACTER_MATTERMOST_OPERATOR_USER_ID"
state_file = "~/.safeyolo-native/data/coord-mattermost-actions.sqlite3"
poll_interval_seconds = 2.0

action_listener_host = "127.0.0.1"
action_listener_port = 8765
public_callback_base_url = "https://YOUR-NODE.YOUR-TAILNET.ts.net/safeyolo"
action_capability_ttl_seconds = 86400
trusted_action_agent_ids = ["ag-32_LOWERCASE_HEX_CHARACTERS"]

[[rooms]]
coord_room = "ROOM_NAME"
channel_id = "26_CHARACTER_MATTERMOST_CHANNEL_ID"
backfill = false
```

Use the exact HTTPS Mattermost origin and exact IDs returned by the server.
Read the designated coordinator's `sender_agent_id` from its canonical message
envelope with the installed native CLI's `coord history ROOM_NAME`. Do not copy
an ID from message text. Every Coord room and channel may appear only once.
The local Coord operator must already have `send,receive` on each room.
Coord and its NATS server must be running for this instance; start them with
the installed native CLI's `coord start` command if needed.

Without `--config`, the adapter reads `coord-mattermost.toml` beside the selected
native instance configuration. Relative token and state paths resolve against
the adapter TOML file's directory. `~/` paths resolve against the host account's
home directory. The explicit commands below select the example instance and
adapter configuration.

`public_callback_base_url` may contain a safe path prefix. The final callback
above is
`https://YOUR-NODE.YOUR-TAILNET.ts.net/safeyolo/mattermost/actions`; the local
health path is `/safeyolo/mattermost/healthz`. The listener host must be a
literal loopback IP. The public URL must be HTTPS and cannot contain
credentials, query, fragment, percent encoding, or ambiguous path segments.

There is no new operator-managed signing or callback secret. The existing bot
token stays in its `0600` file. Per-projection capabilities are generated by
the adapter, stored only as digests, expire after the configured TTL, and are
never logged.

The adapter creates the state file and sibling `.lock` lease file with mode
`0600`. Do not pre-create, edit, or replace them. Configuration drift fails
closed. Stop the old process and use another empty state path for an intentional
server/operator/room/action remapping.

### Generic HTTPS ingress

Run any operator-owned HTTPS reverse proxy that preserves the path and forwards
only to `http://127.0.0.1:8765`. Its public origin/path must exactly equal
`public_callback_base_url`. Keep the adapter bound to loopback; do not expose
its port directly. Tunnel and certificate lifecycle belong to that external
proxy or host supervisor, not SafeYolo core.

### Tailscale Funnel recipe

Current Tailscale Funnel accepts an HTTP loopback target and terminates public
HTTPS. On the same host as the adapter:

```sh
sudo tailscale funnel --bg --https=443 http://127.0.0.1:8765
sudo tailscale funnel status --json
```

Set `public_callback_base_url` to that node's stable `https://…ts.net` URL plus
the optional prefix shown in the config. Funnel forwards the original request
path, so do not use `--set-path` for this recipe. Funnel requires MagicDNS,
tailnet HTTPS, and the Funnel node attribute; public ports are limited to 443,
8443, and 10000. See the current [Tailscale Funnel command
reference](https://tailscale.com/docs/reference/tailscale-cli/funnel).

To disable this exact Funnel listener:

```sh
sudo tailscale funnel --https=443 off
```

The `--bg` configuration survives adapter restarts. A missing or unhealthy
Funnel does not stop routine Mattermost projection, but buttons already posted
cannot reach the loopback listener until ingress is restored.

## Validate, run, stop, and restart

On the host, use the account that owns the initialized native instance at
`$HOME/.safeyolo-native`. Its Coord runtime must be running and the bot must
belong to every mapped channel. Keep configured proxy and Certificate Authority
(CA) environment settings, including `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`NODE_EXTRA_CA_CERTS`. Validate credentials, identities, Coord grants, strict
configuration, private state and the callback socket:

```sh
chmod 600 "$HOME/.safeyolo-native/mattermost-bot-token"
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" \
  coord mattermost check --config "$HOME/.safeyolo-native/coord-mattermost.toml"
```

`check` briefly binds and releases the configured loopback port. It cannot
prove the independently operated public tunnel. A successful check prints
`Mattermost adapter configuration is valid.` Start the foreground daemon
under the operator's normal host supervisor:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" \
  coord mattermost run --config "$HOME/.safeyolo-native/coord-mattermost.toml"
```

Status checks for the example prefix are:

```sh
curl -fsS http://127.0.0.1:8765/safeyolo/mattermost/healthz
sudo tailscale funnel status --json
```

Health reports only listener state and the count of action appends awaiting
manual reconciliation; it exposes no credentials or capabilities. To stop,
press Ctrl-C in the foreground terminal or have the host supervisor send SIGTERM
to its owned adapter process. Wait for that process to exit before restarting
with the same command and state file. Stop closes the listener and releases
the state lease. Only one process may own a state file or callback port.
Stopping the adapter does not stop the independently operated HTTPS ingress,
Coord, NATS or the proxy.

`safeyolo coord mattermost run --once` remains available for a bounded
projection/reply diagnostic. It intentionally does not expose a callback
listener or issue buttons; do not use it to consume an intended interactive
acceptance request.

## Delivery and failure semantics

SQLite suppresses inbound replay across retries/restarts and marks outbound
projection pending before calling Mattermost. Each post carries a deterministic
correlation property. After an interrupted post request, the adapter reconciles
one visible match and refuses an automatic retry if the remote outcome cannot
be established. An uncertain free-text coord append still stops the adapter,
as before; an uncertain button append disables only that capability.

Authentication, identity, mapping, malformed response, and ambiguous
correlation errors are sanitized. The bot token and action capabilities never
appear in URLs, command lines, repository files, state rows, health responses,
or logs.

If an append reports an unknown outcome, inspect the mapped room's canonical
history for the exact Mattermost post, original Coord message and action
correlations before deciding whether a separate operator send is needed. Do
not repeat a button click or reset a cursor to force a retry. A pending button
remains unavailable while routine projection and replies continue. A pending
free-text append stops the adapter and is not replayed on restart.

For an uncertain outward post, inspect the mapped Mattermost channel for its
deterministic projection correlation. On restart the adapter accepts one exact
matching post; no match or multiple matches require operator reconciliation.
Preserve the state database, adjacent SQLite write-ahead log (WAL) files and
lease file. Do not delete or edit pending records to claim success. If an
operator deliberately replaces a stopped mapping after reconciling its pending
effects, use a fresh state path with `backfill = false` to skip existing room
history and establish a new channel baseline. Preserve the previous store.

The native client-contract tests in
`tests/proxy_contracts/test_native_mattermost.py` exercise installed native
commands, a controlled HTTPS Mattermost server and real NATS. They cover
exchange, authority, hostile text, expiry/replay, publication counts, uncertain
outcomes and owned stop/restart. Rust units cover private state, WAL, leases,
replacement guards and rendering. These checks establish the selected client
contract; live-account/mobile deployment acceptance is outside that scope.
The older Python fixtures and macOS probe scripts remain repository test
tooling under `tests/legacy_mattermost` and `scripts/accept_mattermost_macos*.py`.
They are excluded from production packages and do not establish native behavior.
