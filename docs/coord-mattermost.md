# Mattermost coord operator adapter

The optional Mattermost adapter projects selected coord rooms to one operator.
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

## Projection and trust

Routine or unrecognized messages are compact: canonical sender kind/name,
coord room, canonical message ID, then an inert rendering of the sender body.
Mentions, Markdown-active punctuation, controls, and Unicode ordering controls
are escaped. Oversized bodies are explicitly truncated and hashed.

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

## Operator-owned setup

On a fresh or self-hosted Mattermost deployment, a Mattermost System Admin may
first need to enable **System Console > Integrations > Bot Accounts > Enable
Bot Account Creation**. Create a dedicated SafeYolo bot, add it directly as a
normal member of every mapped channel, and do not grant it System Admin.

Keep these operator-owned files outside the repository:

1. `~/.safeyolo/mattermost-bot-token`, mode `0600`, containing only the bot
   token.
2. `~/.safeyolo/coord-mattermost.toml`, containing the adapter configuration.

For a new interactive deployment, use a new state filename rather than an
existing non-interactive adapter database because the action configuration is
part of the adapter's durable identity:

```toml
version = 1
server_url = "https://YOUR-MATTERMOST-ORIGIN"
bot_token_file = "~/.safeyolo/mattermost-bot-token"
bot_user_id = "26_CHARACTER_MATTERMOST_BOT_USER_ID"
operator_user_id = "26_CHARACTER_MATTERMOST_OPERATOR_USER_ID"
state_file = "~/.safeyolo/data/coord-mattermost-actions.sqlite3"
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
Use `safeyolo coord state ROOM_NAME` to read the transport-owned canonical
agent ID for the operator-designated coordinator; do not copy an ID from chat
text. Every coord room and channel may appear only once. The local coord
operator must already have `send,receive` on each room.

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

## Validate, run, status, and restart

Validate credentials, bot/operator/channel identities, coord grants, strict
configuration, state ownership, and the ability to bind the callback socket:

```sh
chmod 600 ~/.safeyolo/mattermost-bot-token
safeyolo coord mattermost check --config ~/.safeyolo/coord-mattermost.toml
```

`check` briefly binds and releases the configured loopback port. It cannot
prove the independently operated public tunnel. Start the foreground daemon
under the operator's normal host supervisor:

```sh
safeyolo coord mattermost run --config ~/.safeyolo/coord-mattermost.toml
```

Status checks for the example prefix are:

```sh
curl -fsS http://127.0.0.1:8765/safeyolo/mattermost/healthz
sudo tailscale funnel status --json
```

Health reports only listener state and the count of action appends awaiting
manual reconciliation; it exposes no credentials or capabilities. To restart,
have the supervisor stop the foreground adapter cleanly and run the same
command. Only one process may own a state file or callback port.

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
or logs. Live acceptance must still exercise the operator-owned Mattermost
11.9.x server and stock client; the repository tests cover protocol shapes,
trust failures, expiry/replay, uncertain outcomes, listener bounds, and clean
lifecycle without coupling core code to a particular tunnel or host.
