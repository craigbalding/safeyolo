# SafeYolo Addons Reference

Complete documentation for SafeYolo's mitmproxy addons.

## Overview

Addons are loaded in this order (order matters for security):

| Layer | Addon | Purpose | Default Mode |
|-------|-------|---------|--------------|
| 0 | admin_shield | Block proxy access to admin API | Always on |
| 0 | request_id | Request ID for event correlation | Always on |
| 0 | sse_streaming | SSE/streaming for LLM responses | Always on |
| 0 | policy_engine | Unified policy evaluation and budgets | Always on |
| 1 | access_control | Network allow/deny rules | **Block** |
| 1 | rate_limiter | Per-domain rate limiting (via PolicyEngine) | **Block** |
| 1 | circuit_breaker | Fail-fast for unhealthy upstreams | Always on |
| 2 | credential_guard | Block credentials to wrong hosts | **Block** |
| 2 | pattern_scanner | Regex scanning for secrets | Warn |
| 3 | request_logger | JSONL audit logging | Always on |
| 3 | metrics | Per-domain statistics | Always on |
| 3 | admin_api | REST API on :9090 | Always on |

**Layers:**
- **Layer 0 (Infrastructure):** Must run first - request IDs, policy engine, streaming
- **Layer 1 (Access Control):** Deny decisions before budget checks
- **Layer 2 (Security Inspection):** Credential routing, content scanning
- **Layer 3 (Observability):** Logging, metrics, admin API

**Default behavior:**
- `access_control`, `credential_guard`, and `rate_limiter` block by default (core protections)
- `pattern_scanner` warns by default (higher false positive rate)
- Other addons are always active with no mode toggle

---

## request_id.py

Assigns a unique request ID to every request for event correlation.

**How it works:**
- Runs first in the addon chain
- Generates `request_id` like `req-abc123def456`
- Stores in `flow.metadata["request_id"]`
- All downstream addons include this in log events

**Example correlation:**
```bash
grep "req-abc123def456" logs/safeyolo.jsonl | jq
```

---

## policy_engine.py

Unified policy engine using IAM-style vocabulary with **destination-first** credential routing. Handles credential authorization, rate limiting (budgets), and per-domain addon configuration.

**Architecture:** The policy system is split into focused modules:
- `policy_engine.py` (~950 lines) - Evaluation logic and policy matching
- `policy_loader.py` (~320 lines) - File loading, watching, SIGHUP handling
- `budget_tracker.py` (~190 lines) - GCRA-based rate limiting state

**Configuration:** `config/baseline.yaml`

```yaml
metadata:
  version: "1.0"
  description: "SafeYolo baseline policy"

permissions:
  # Destination-first credential routing
  # Resource = destination pattern, condition.credential = what can access it
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]  # Type-based: any OpenAI key

  - action: credential:use
    resource: "api.anthropic.com/*"
    effect: allow
    condition:
      credential: ["anthropic:*"]

  # HMAC-based approval for specific credential
  - action: credential:use
    resource: "api.custom.com/*"
    effect: allow
    condition:
      credential: ["hmac:a1b2c3d4"]  # Specific credential fingerprint

  # Unknown destinations require approval
  - action: credential:use
    resource: "*"
    effect: prompt

  # Rate limits (requests per minute)
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000  # 50 rps

budgets:
  network:request: 12000  # Global cap

required:
  - credential_guard
  - rate_limiter

addons:
  credential_guard: {enabled: true, detection_level: standard}
  rate_limiter: {enabled: true}

domains:
  "*.internal":
    bypass: [pattern_scanner, yara_scanner]
```

**Credential condition formats:**
- `openai:*` - type-based matching (any credential of that type)
- `hmac:a1b2c3d4` - HMAC-based matching (specific credential fingerprint)

**Policy effects:**
- `allow` - permit immediately
- `deny` - block immediately
- `prompt` - trigger human approval workflow
- `budget` - allow up to N requests/minute, then deny

**Features:**
- Pydantic schema validation
- Hot reload via file watching
- GCRA-based budget tracking (smooth rate limiting)
- Per-domain and per-client overrides
- Thread-safe with RLock

**How credential routing works (destination-first):**
1. Credential detected in request (pattern matching → type, HMAC fingerprint)
2. PolicyEngine finds permission matching destination (`resource` pattern)
3. Checks if credential matches `condition.credential` (type or HMAC)
4. If match found with `effect: allow` → permit
5. If no match → fall through to catch-all (typically `effect: prompt`)

---

## service_discovery.py

Maps client IPs to projects for per-project credential policy isolation.

**Use case:** Different agents get different credential approval policies.

**How it works:**
- Reads `services.yaml` (static configuration, no Docker socket access)
- CLI manages services.yaml when adding agents (`safeyolo agent add`)
- Pro teams provide their own services.yaml with IP ranges
- No Docker socket mount required

**Setup:** See [SERVICE_DISCOVERY.md](SERVICE_DISCOVERY.md) for configuration.

**Options:**
```bash
--set discovery_network=safeyolo-internal
```

---

## rate_limiter.py

Per-domain rate limiting via PolicyEngine's GCRA-based budget tracking.

**Default: Block mode**

**Use case:** Prevent IP blacklisting when an LLM loops on API calls.

**Configuration:** Rate limits are defined in `baseline.yaml` as permissions with `effect: budget`:

```yaml
permissions:
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000  # requests per minute (50 rps)

  - action: network:request
    resource: "api.anthropic.com/*"
    effect: budget
    budget: 3000

  # Default for all other domains
  - action: network:request
    resource: "*"
    effect: budget
    budget: 600  # 10 rps

budgets:
  network:request: 12000  # Global cap across all domains
```

**Response when limited (429):**
```json
{
  "error": "Rate limited by proxy",
  "domain": "api.openai.com",
  "reason": "budget_exceeded",
  "message": "Too many requests to api.openai.com. Please slow down."
}
```

**How it works:**
1. Request comes in for domain
2. RateLimiter calls `PolicyEngine.evaluate_request()`
3. PolicyEngine finds matching `network:request` permission
4. GCRA budget tracker checks if budget allows request
5. If budget exhausted, returns 429 with Retry-After header

---

## access_control.py

Network access control for client internet reach limits.

**Default: Block mode**

**Use case:** Restrict which domains coding agents can access (allowlist/denylist).

**Configuration:** Access rules are defined in `baseline.yaml` as permissions with `effect: allow` or `effect: deny`:

```yaml
permissions:
  # Allowlist mode: allow specific, deny rest
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit

  - action: network:request
    resource: "api.anthropic.com/*"
    effect: allow
    tier: explicit

  - action: network:request
    resource: "*"
    effect: deny  # Catch-all deny
    tier: explicit

  # Or denylist mode: deny specific domains
  - action: network:request
    resource: "malware.com/*"
    effect: deny
    tier: explicit
```

**Response when denied (403):**
```json
{
  "error": "Access denied by proxy",
  "domain": "blocked.com",
  "reason": "Access denied to blocked.com",
  "message": "Network access to blocked.com is not permitted."
}
```

**How it works:**
1. Request comes in for domain
2. AccessControl calls `PolicyEngine.evaluate_request()`
3. PolicyEngine finds matching `network:request` permission
4. If `effect: deny`, returns 403 Forbidden
5. If `effect: allow` or `effect: budget`, passes through to rate_limiter

**Addon chain order:** Load `access_control` before `rate_limiter`:
- AccessControl blocks denied requests (403)
- RateLimiter enforces budgets on allowed requests (429)

**Options:**
```bash
--set access_control_enabled=true   # Enable access control (default: true)
--set access_control_block=true     # Block mode (default: true, false = warn only)
--set access_control_homoglyph=true # Enable homoglyph detection (default: true)
```

### Homoglyph Detection

Detects mixed-script domain attacks like `api.оpenai.com` (Cyrillic 'о' instead of Latin 'o'). When enabled, requests to domains with mixed Unicode scripts are blocked before any credential checking.

**Response when blocked (403):**
```json
{
  "error": "Homoglyph domain detected",
  "domain": "api.оpenai.com",
  "reason": "Domain contains mixed scripts (possible lookalike attack)",
  "message": "Request blocked due to suspicious domain encoding"
}
```

**Requirements:** Requires `confusable-homoglyphs` package (`pip install confusable-homoglyphs`).

---

## circuit_breaker.py

Fail-fast for unhealthy upstreams.

**Always active** (blocks when circuit is open)

**States:**
- CLOSED - Normal, requests pass through
- OPEN - Service unhealthy, immediate 503
- HALF_OPEN - Testing recovery

**Triggers:** 5 consecutive failures opens circuit for 60 seconds.

**Response when open (503):**
```json
{
  "error": "Service temporarily unavailable",
  "circuit_state": "open",
  "retry_after_seconds": 45
}
```

---

## credential_guard.py

Core security addon. Ensures credentials only reach authorized hosts.

**Default: Block mode**

**~475 lines** - focused on credential detection and routing, designed for easy security audit.

### What It Does

1. **Detects credentials** in HTTP headers
2. **Validates destinations** against allowed hosts
3. **Decides**: allow, warn, or block
4. **Emits events** to JSONL for external processing

### Detection

**Standard auth headers** scanned by default:
- `Authorization`, `X-API-Key`, `API-Key`, `X-Auth-Token`, `APIKey`

**Tier 1 - Pattern matching (high confidence):**
- Matches known credential patterns (OpenAI, Anthropic, GitHub)
- Checks destination against allowed hosts for that credential type

**Tier 2 - Entropy heuristics (medium confidence):**
- For auth headers that don't match known patterns
- Triggered when: length ≥20, charset diversity ≥0.5, Shannon entropy ≥3.5
- Results in "unknown_secret" requiring approval

**Detection levels** (via `config/credential_guard.yaml`):
- `patterns-only` - Only Tier 1 pattern matching
- `standard` (default) - Tier 1 + Tier 2 on auth headers
- `paranoid` - Tier 1 + Tier 2 on all headers

### Decisions

| Internal Decision | Log Decision | Response |
|-------------------|--------------|----------|
| allow | allow | Pass through |
| greylist_mismatch | block/warn | 428 - known credential, wrong host |
| greylist_approval | block/warn | 428 - unknown credential needs approval |

### Configuration

**Credential patterns:** `config/credential_rules.json`
```json
{
  "credentials": [
    {
      "name": "openai",
      "pattern": "sk-proj-[a-zA-Z0-9_-]{80,}",
      "allowed_hosts": ["api.openai.com"]
    },
    {
      "name": "anthropic",
      "pattern": "sk-ant-api[a-zA-Z0-9-]{90,}",
      "allowed_hosts": ["api.anthropic.com"]
    }
  ]
}
```

**Entropy settings:** `config/credential_guard.yaml`
```yaml
detection_level: standard  # patterns-only | standard | paranoid

entropy:
  min_length: 20
  min_charset_diversity: 0.5
  min_shannon_entropy: 3.5

standard_auth_headers:
  - authorization
  - x-api-key
  - api-key
  - x-auth-token
  - apikey
```

**Safe headers** (skipped in entropy analysis): `config/safe_headers.yaml`
```yaml
safe_patterns:
  - "x-request-id"
  - "x-trace-id"
  - "x-correlation-id"
```

### Response Format

**Destination mismatch (428):**
```json
{
  "error": "Credential routing error",
  "type": "destination_mismatch",
  "credential_type": "openai",
  "destination": "httpbin.org",
  "expected_hosts": ["api.openai.com"],
  "credential_fingerprint": "hmac:a1b2c3d4",
  "action": "self_correct",
  "reflection": "You sent a openai credential to httpbin.org, but it should go to ['api.openai.com']. Please verify the URL."
}
```

**Requires approval (428):**
```json
{
  "error": "Credential requires approval",
  "type": "requires_approval",
  "credential_type": "unknown_secret",
  "destination": "api.example.com",
  "credential_fingerprint": "hmac:a1b2c3d4",
  "reason": "unknown_credential",
  "action": "wait_for_approval",
  "reflection": "This credential requires human approval before use."
}
```

### Approval Workflow

Credential guard emits events to JSONL. The CLI handles the interactive workflow:

1. Credential blocked → `security.credential` event with `decision: block`
2. `safeyolo watch` displays the event
3. User approves → CLI calls `POST /admin/policy/baseline/approve`
4. Admin API adds permission to baseline policy (destination-first)
5. PolicyEngine hot reloads (within 1s)
6. Subsequent requests with matching credential to that destination pass through

### Policy-Based Approvals (Destination-First)

Approvals are stored as permissions in `baseline.yaml` using destination-first schema:

```yaml
permissions:
  # Type-based: allow any custom-api credential to api.example.com
  - action: credential:use
    resource: "api.example.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["custom-api:*"]

  # HMAC-based: allow specific credential to api.example.com
  - action: credential:use
    resource: "api.example.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["hmac:a1b2c3d4"]
```

**Credential condition formats:**
- Type-based (`openai:*`, `anthropic:*`, `custom:*`) - matches any credential of that type
- HMAC-based (`hmac:a1b2c3d4`) - matches specific credential by fingerprint

**When to use each:**
- **Type-based:** When key rotation is expected (new keys auto-approved)
- **HMAC-based:** When you want to approve only a specific credential (more secure for unknown types)

**HMAC fingerprinting:** Credentials are never logged raw. First 16 chars of HMAC-SHA256 used for logging, policy matching, and temp allowlist.

### Temp Allowlist

For immediate one-off approvals (not persisted across restarts):

```bash
# Via admin API
curl -X POST http://localhost:9090/plugins/credential-guard/allowlist \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"credential_prefix": "sk-abc", "host": "api.example.com", "ttl_seconds": 300}'
```

### Options

```bash
--set credguard_block=true          # Block mode (default: true)
--set credguard_rules=/path/to.json # Rules file path
--set credguard_scan_urls=false     # Scan URL query params (default: false)
--set credguard_scan_bodies=false   # Scan request bodies (default: false)
--set credguard_log_path=/path.jsonl # Separate log file (optional)
```

### Related Features

**Homoglyph detection:** Mixed-script attacks like `api.оpenai.com` (Cyrillic 'о') are detected by `access_control.py`, not credential_guard. See access_control section below.

---

## pattern_scanner.py

Fast regex scanning for secrets and suspicious patterns.

**Default: Warn mode**

**Built-in patterns:**

*Response scanning:*
- API keys (OpenAI, AWS, GitHub)
- Private keys
- Database connection strings

*Request scanning:*
- Jailbreak phrases ("ignore previous instructions")
- LLM instruction markers

**Options:**
```bash
--set pattern_block_input=false   # Block matching requests
--set pattern_block_output=false  # Block matching responses
```

---

## request_logger.py

JSONL structured logging with unified event taxonomy.

**Always active**

**Event types:**
| Prefix | Description |
|--------|-------------|
| `traffic.*` | Request/response lifecycle |
| `security.*` | Security addon decisions |
| `admin.*` | Admin API actions |
| `ops.*` | Operational events |

**Output:**
```json
{"timestamp": "...", "event": "security.credential", "request_id": "req-abc123", "data": {"decision": "block", ...}}
```

**Filtering:**
```bash
# All security events
jq 'select(.event | startswith("security."))' logs/safeyolo.jsonl

# All blocks
jq 'select(.data.decision == "block")' logs/safeyolo.jsonl
```

---

## metrics.py

Per-domain statistics collection.

**Always active**

**Tracks:**
- Request counts and success rates
- Latency per domain
- Block counts by addon
- Upstream errors

**Access:**
```bash
curl http://localhost:9090/stats    # JSON
curl http://localhost:9090/metrics  # Prometheus
```

---

## admin_api.py

REST API on port 9090 for runtime control.

**Always active**

### Authentication

All endpoints except `/health` require Bearer token:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/stats
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/stats` | Aggregated addon stats |
| GET | `/metrics` | Prometheus format |
| GET | `/modes` | Current addon modes |
| PUT | `/modes` | Set all addon modes |
| PUT | `/plugins/{addon}/mode` | Set specific addon mode |
| GET | `/admin/policy/baseline` | Read baseline policy |
| PUT | `/admin/policy/baseline` | Update baseline policy |
| POST | `/admin/policy/baseline/approve` | Add credential permission |
| GET | `/admin/policy/task/{id}` | Read task policy |
| PUT | `/admin/policy/task/{id}` | Create/update task policy |
| GET | `/admin/budgets` | Current budget usage |
| POST | `/admin/budgets/reset` | Reset budget counters |
| GET | `/plugins/credential-guard/allowlist` | List temp allowlist |
| POST | `/plugins/credential-guard/allowlist` | Add temp allowlist entry |
| DELETE | `/plugins/credential-guard/allowlist` | Clear temp allowlist |

### Mode Switching

```bash
# View all modes
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/modes

# Set credential-guard to warn (for debugging)
curl -X PUT http://localhost:9090/plugins/credential-guard/mode \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode": "warn"}'

# Set all addons to block
curl -X PUT http://localhost:9090/modes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode": "block"}'
```

### Adding Approvals (Destination-First)

```bash
# Type-based approval: allow any custom-api credential to api.example.com
curl -X POST http://localhost:9090/admin/policy/baseline/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "api.example.com",
    "credential": "custom-api:*",
    "tier": "explicit"
  }'

# HMAC-based approval: allow specific credential to api.example.com
curl -X POST http://localhost:9090/admin/policy/baseline/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "api.example.com",
    "credential": "hmac:a1b2c3d4",
    "tier": "explicit"
  }'
```

### Budget Management

```bash
# View current budget usage
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/admin/budgets

# Reset all budget counters
curl -X POST http://localhost:9090/admin/budgets/reset \
  -H "Authorization: Bearer $TOKEN"

# Reset specific resource budget
curl -X POST http://localhost:9090/admin/budgets/reset \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resource": "api.openai.com"}'
```

### Temp Allowlist

For temporary one-off approvals (not persisted):
```bash
curl -X POST http://localhost:9090/plugins/credential-guard/allowlist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credential_prefix": "sk-abc", "host": "api.example.com", "ttl_seconds": 300}'
```

---

## Writing Custom Addons

See [DEVELOPERS.md](DEVELOPERS.md) for addon development guide.

Basic structure:
```python
from mitmproxy import ctx, http
from .utils import write_event

class MyAddon:
    name = "my-addon"

    def request(self, flow: http.HTTPFlow):
        if self.should_block(flow):
            flow.response = http.Response.make(403, b'{"error": "blocked"}')
            flow.metadata["blocked_by"] = self.name
            write_event("security.custom", addon=self.name, decision="block")

addons = [MyAddon()]
```
