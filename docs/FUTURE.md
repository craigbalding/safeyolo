# SafeYolo Future Ideas

**Status**: Ideas under consideration, not committed features. These solve real problems but aren't prioritized yet. Kept here to avoid forgetting them.

## Policy-Driven Response Actions

**Problem**: Currently each addon handles detection responses independently. Users can't configure what happens when something is detected (block, warn, alert, kill session, webhook).

**Goal**: Standard action vocabulary in policy, so users can configure response behavior per-addon, per-domain, per-client.

**Proposed schema**:
```yaml
domains:
  "api.openai.com":
    addons:
      prompt_injection:
        enabled: true
        on_detection: block          # block | warn | alert | kill_session
        on_false_negative: alert     # when Ollama disagrees with DeBERTa
        alert_webhook: "https://..."

      credential_guard:
        enabled: true
        on_violation: block
        alert_webhook: "https://..."
```

**Standard actions**:
| Action | Description |
|--------|-------------|
| `warn` | Log warning, allow request to proceed |
| `block` | Return 403/429, don't forward request |
| `alert` | Log + send webhook/notification |
| `kill_session` | Terminate connection, revoke session if possible |

**Work required**:
- [ ] Define action enum/constants in policy.py
- [ ] Add `on_detection` field to AddonPolicy
- [ ] Add webhook/callback mechanism
- [ ] Update prompt_injection.py to read actions from policy
- [ ] Update other security addons (credential_guard, yara_scanner, pattern_scanner)
- [ ] Document in README

**Context**: Async Ollama verification can catch false negatives after the request has already been forwarded. Users need to decide what to do in that case (alert, kill session, etc).

**Current Status (2026-01)**: Runtime mode switching (warn/block) exists via admin API. Missing: policy-driven per-domain actions, webhooks, kill_session.

## API Key Host Binding

**Problem**: Compromised or leaked API keys could be exfiltrated to attacker-controlled hosts. Currently credential_guard only detects keys in requests, not where they're being sent.

**Goal**: Track first use of each API key, bind it to the host it was first used with, alert if the same key is later sent to a different host.

**Example scenario**:
1. `sk-proj-abc123` first seen going to `api.openai.com` → bind key to host
2. Later, same key sent to `evil-proxy.com` → ALERT: key exfiltration attempt

**Proposed schema** (addons.yaml):
```yaml
credential_guard:
  host_binding:
    enabled: true
    mode: alert              # alert | block | learn_only
    learning_period: 24h     # time before bindings are enforced
    allow_subdomains: true   # api.openai.com key ok for *.openai.com
    allowlist:               # hosts that can receive any key
      - localhost
      - 127.0.0.1
```

**Work required**:
- [ ] Add key→host binding storage (SQLite or in-memory with persistence)
- [ ] Hash keys before storage (don't store plaintext keys)
- [ ] Track first-seen timestamp per key
- [ ] Add learning mode (observe but don't alert during initial period)
- [ ] Add subdomain matching logic
- [ ] Integrate with credential_guard.py detection flow
- [ ] Add stats to admin API (bindings count, violations)
- [ ] Add policy configuration for mode/thresholds

**Privacy considerations**: Store key hashes only, not plaintext. Consider TTL for old bindings.

**Current Status (2026-01)**: Not implemented. Credential guard blocks wrong-host usage upfront, but doesn't track key→host bindings.

## Hot-reload .env for Addons

**Problem**: `OLLAMA_URL` and other env vars are only read at container startup. Changing `.env` requires container restart.

**Goal**: Addons should re-read `/app/.env` on file change, allowing runtime config updates without restart.

**Work required**:
- [ ] Add `.env` file watcher (similar to policy/rate_limits watchers)
- [ ] Update `prompt_injection.py` to re-read `OLLAMA_URL` on reload
- [ ] Expose `/plugins/prompt-injection/reload` endpoint in admin_api.py
- [ ] Document hot-reload capability

**Current Status (2026-01)**: Not implemented. Env vars read at startup only. Container restart required for changes.

## Denial Persistence for Approval Workflow

**Problem**: When a credential is denied via mobile notification (Deny button), the denial is not persisted. If the same credential is retried, it triggers a new approval request and notification.

**Current Workaround**: Use "Dismiss" instead of "Deny" - the pending approval stays in memory for 24h and deduplication prevents duplicate notifications during that window.

**Goal**: Make "Deny" create a persistent denial record that prevents future approval requests for the same credential+host combination.

**Proposed behavior**:
1. User taps "Deny" on notification
2. Denial persisted with TTL (e.g., 24h or configurable)
3. Future requests with same credential+host check denial cache
4. If denied, return 403 Forbidden (or still 428?) without creating new pending approval or sending notification

**Work required**:
- [ ] Add `self.denials: dict[tuple[str, str], float] = {}` to store (fingerprint, host) → denial_timestamp
- [ ] Update `deny_pending()` to add to denials dict with timestamp
- [ ] Update `create_pending_approval()` to check denials before creating pending approval
- [ ] Add denial TTL cleanup (similar to pending approval 24h cleanup)
- [ ] Decide on response status: 403 Forbidden vs 428 Precondition Required for denied credentials
- [ ] Optional: Persist denials to disk to survive container restarts

**Open questions**:
- Should denials be persistent across restarts (disk storage) or in-memory only?
- What TTL for denials? Same as pending approval (24h), or configurable?
- Should denied credentials get different HTTP status than pending ones?

**Current Status (2026-01)**: Not implemented. Use "Dismiss" workflow instead - pending approval stays for 24h and prevents duplicate notifications.

- [ ] Fix duplicate log lines in ntfy_approval_listener.py (prints + writes, but shell also redirects)

## State File Unbounded Growth

**Problem**: Rate limiter and circuit breaker state files grow forever as new domains are tracked. For long-running proxies with many unique domains, state files could grow unbounded.

**Current behavior**:
- `rate_limiter_state.json`: Stores TAT (Theoretical Arrival Time) per domain
- `circuit_breaker_state.json`: Stores circuit state per domain
- No TTL or max entries limit
- Old/stale domains never removed

**Goal**: Prevent unbounded state file growth while preserving state for active domains.

**Proposed solutions**:

1. **TTL-based cleanup**: Remove entries older than N days (e.g., 7 days since last access)
2. **Max entries limit**: LRU eviction when state exceeds threshold (e.g., 10,000 domains)
3. **Periodic cleanup task**: Run cleanup on snapshot thread (every 10 minutes)

**Proposed schema** (state file with metadata):
```json
{
  "tats": {
    "api.openai.com": {"value": 1704307200000, "last_access": 1704307200},
    "api.anthropic.com": {"value": 1704307100000, "last_access": 1704307100}
  },
  "saved_at": 1704307200,
  "version": 2
}
```

**Work required**:
- [ ] Add `last_access` timestamp to state entries
- [ ] Implement TTL-based cleanup (configurable, default 7 days)
- [ ] Optional: Add max entries limit with LRU eviction
- [ ] Add cleanup stats to admin API (`stale_entries_removed`)
- [ ] Migrate existing state files (version 1 → 2)

**Current Status (2026-01)**: Not implemented. State files grow unbounded. Low priority for small deployments, but could be problematic for high-traffic proxies with many unique domains.

## Coord: server-side byte-bounded fetch via the modern NATS JetStream API

`read_room` bounds a page at `READ_PAGE_MAX_BYTES` (4 MiB) alongside the
200-message ceiling, but the trim happens **after receipt**. The bytes still
cross the wire; only what the caller is handed is bounded.

NATS itself supports `max_bytes` on pull requests. The blocker is the client:
in nats-py 2.15 — the version this repo pins — the legacy
`PullSubscription.fetch()` exposes only `batch` and `timeout`, and its
`ConsumerConfig` does not surface `MaxRequestMaxBytes` either. The newer
`nats-jetstream` Python API does expose `consumer.fetch(max_bytes=...)`.

Writing raw pull-request protocol against the private client internals to get
this on the current dependency was judged not worth it during the #327 review.
The follow-up is the migration, not a workaround:

- move coord's JetStream usage to the modern `nats-jetstream` consumer API
- enforce the page byte bound server-side, keeping the post-receipt trim as a
  belt-and-braces check
- revisit the wait-consumer lifecycle at the same time — `wait_for_message`
  currently holds one ephemeral consumer open per call via
  `nats_client.pull_session()`, and the newer API may offer a cleaner
  primitive for a long poll than an ephemeral pull consumer

Until then the byte bound is a client-side protection against handing a caller
an unbounded page, not a defence against a large transfer.

## Harness maintenance: minimum supported mise version and release-age policy

Agent host scripts set `MISE_MIN_RELEASE_AGE` and verify it took, because the
setting does not exist on every mise. The mise in an agent sandbox observed
during the #327 dogfood was `2026.4.19`, where `mise settings get
min_release_age` returns `Unknown setting`; the feature landed shortly after,
around `2026.4.28`. A persistent agent home can therefore carry an old mise
indefinitely and silently have **no delayed-deployment protection at all**.

The scripts now say so on stderr rather than assuming the default is present,
which is the right behaviour for coord but not a fix. The fix is a harness
decision:

- establish a minimum supported mise version for agent sandboxes
- upgrade or refuse below it, rather than inheriting whatever an old
  persistent home contains
- then configure the release-age policy explicitly on a version that honours it

Note that mise's minimum-release-age implementation has had bugs during 2026
(prereleases being selected, `mise upgrade` not respecting the setting), so
treat it as defence in depth against a compromised or hastily-published
release, not as a security guarantee.
