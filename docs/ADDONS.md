# SafeYolo Addons Reference

Complete documentation for SafeYolo's mitmproxy addons.

## Overview

| Addon | Purpose | Default Mode |
|-------|---------|--------------|
| request_id | Request ID for event correlation | Always on |
| policy | Per-domain addon configuration | Always on |
| service_discovery | Docker container discovery | Always on |
| rate_limiter | Per-domain rate limiting | **Block** |
| circuit_breaker | Fail-fast for unhealthy upstreams | Always on |
| credential_guard | Block credentials to wrong hosts | **Block** |
| pattern_scanner | Regex scanning for secrets | Warn |
| request_logger | JSONL audit logging | Always on |
| metrics | Per-domain statistics | Always on |
| admin_api | REST API on :9090 | Always on |

**Default behavior:**
- `credential_guard` and `rate_limiter` block by default (core protections)
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

## policy.py

Per-domain addon configuration. Controls which addons run where.

**Configuration:** `config/policy.yaml`
```yaml
defaults:
  addons:
    rate_limiter: { enabled: true }
    credential_guard: { enabled: true }

domains:
  "*.internal":
    bypass: [pattern_scanner]

  "pypi.org":
    bypass: [credential_guard]
```

**Features:**
- Hot reload on file change
- Wildcard domain patterns
- Bypass lists per domain

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

Per-domain rate limiting using GCRA algorithm.

**Default: Block mode**

**Use case:** Prevent IP blacklisting when an LLM loops on API calls.

**Configuration:** `config/rate_limits.json`
```json
{
  "default": {"rps": 10, "burst": 30},
  "domains": {
    "api.openai.com": {"rps": 50, "burst": 100},
    "api.anthropic.com": {"rps": 50, "burst": 100}
  }
}
```

**Response when limited (429):**
```json
{
  "error": "Rate limited by proxy",
  "domain": "api.openai.com",
  "retry_after_seconds": 2
}
```

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

**~760 lines** - designed for easy security audit.

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
3. User approves → CLI calls `POST /admin/policy/{project}/approve`
4. Admin API writes to policy file
5. PolicyStore file watcher reloads (within 1s)
6. Subsequent requests with same fingerprint+host pass through

### Policy Files

Approvals stored in `data/policies/{project}.yaml`:
```yaml
approved:
  - token_hmac: "a1b2c3d4..."
    hosts: ["api.example.com"]
    paths: ["/**"]
    added: "2025-01-03T14:30:00Z"
```

**Project isolation:** Requests are mapped to projects via Docker service discovery (container → `com.docker.compose.project` label). Host requests use "default" project.

**HMAC fingerprinting:** Credentials are never stored raw. First 16 chars of HMAC-SHA256 used for matching.

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

### Additional Features

**Homoglyph detection:** Detects mixed-script attacks like `api.оpenai.com` (Cyrillic 'о'). Requires `confusable-homoglyphs` package.

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
| GET | `/admin/policies` | List policy files |
| GET | `/admin/policy/{project}` | Get project policy |
| PUT | `/admin/policy/{project}` | Write project policy |
| POST | `/admin/policy/{project}/approve` | Add approval rule |
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

### Adding Approvals

```bash
# Add approval rule (used by CLI)
curl -X POST http://localhost:9090/admin/policy/default/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token_hmac": "a1b2c3d4...",
    "hosts": ["api.example.com"],
    "paths": ["/**"]
  }'
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
