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

**Proposed schema** (policy.yaml):
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

**Goal**: Addons should re-read `/app/.env` on SIGHUP or file change, allowing runtime config updates without restart.

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
