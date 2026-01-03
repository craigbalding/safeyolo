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

Auto-discovers Docker containers on the internal network.

**Use case:** Map requests to projects for per-project policy isolation.

**How it works:**
- Queries Docker API for containers on `safeyolo-internal` network
- Maps client IP to container to `com.docker.compose.project` label
- Credential guard uses this to write project-specific policies

**Options:**
```bash
--set discovery_network=safeyolo-internal
--set discovery_refresh_interval=30
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

**~750 lines** - designed for easy security audit.

### What It Does

1. **Detects credentials** in HTTP headers using:
   - Pattern matching for known providers (OpenAI, Anthropic, GitHub, etc.)
   - Entropy heuristics for unknown secrets (length, charset diversity, Shannon entropy)

2. **Validates destinations** against allowed hosts per credential type

3. **Decides**: allow, block, or require approval

4. **Emits events** to JSONL for external processing (CLI picks these up)

### Detection Tiers

**Tier 1 (high confidence):** Standard auth headers (`Authorization`, `X-API-Key`)
- Pattern matching against known credential types
- Destination validation against allowed hosts

**Tier 2 (medium confidence):** All other headers
- Entropy heuristics: length ≥20, charset diversity ≥0.5, Shannon entropy ≥3.5
- Requires approval for unknown destinations

### Decisions

| Decision | Meaning | Response |
|----------|---------|----------|
| allow | Credential approved for this destination | Pass through |
| block (destination_mismatch) | Known credential, wrong host | 428 |
| block (requires_approval) | Unknown credential or destination | 428 |

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

**Safe headers** (skipped in entropy analysis): `config/safe_headers.yaml`
```yaml
safe_patterns:
  - "x-request-id"
  - "x-trace-id"
```

### Response Format

**428 Precondition Required:**
```json
{
  "error": "Credential routing error",
  "type": "destination_mismatch",
  "credential_type": "openai",
  "destination": "httpbin.org",
  "expected_hosts": ["api.openai.com"],
  "action": "self_correct",
  "reflection": "You sent an API credential to the wrong destination."
}
```

### Approval Workflow

Credential guard does NOT handle approvals directly. It emits events to JSONL, and the CLI handles the workflow:

1. Credential blocked → event written to `logs/safeyolo.jsonl`
2. `safeyolo watch` displays the event
3. User approves → CLI calls admin API
4. Admin API writes to policy file
5. PolicyStore file watcher reloads (within 1s)
6. Subsequent requests pass through

### Policy Files

Approvals are stored in `data/policies/{project}.yaml`:
```yaml
approved:
  - token_hmac: "a1b2c3d4..."
    hosts: ["api.example.com"]
    paths: ["/**"]
    added: "2025-01-03T14:30:00Z"
```

**HMAC fingerprinting:** Credentials are never stored raw. HMAC-SHA256 fingerprints are used for matching.

### Options

```bash
--set credguard_block=true          # Block mode (default)
--set credguard_scan_urls=false     # Scan URL query params
--set credguard_scan_bodies=false   # Scan request bodies
```

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
