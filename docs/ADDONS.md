# SafeYolo Addons Reference

**[← Back to README](../README.md)** | **[Quick Start](../README.md#quick-start-30-seconds)** | **[Architecture](../README.md#architecture)**

This document provides detailed documentation for all 11 SafeYolo addons.

**For a quick overview**, see the [addon table in the main README](../README.md#addons).

## Build Targets

SafeYolo addons are split across build targets to keep the default image lightweight:

- **Base (~200MB)** - 9 core addons, recommended for most users
- **Extended (~700MB)** - Adds 2 optional addons with ML/YARA dependencies

To use extended addons, edit docker-compose.yml and change `target: base` to `target: extended`.

---

## Table of Contents

**Base build (included by default):**
1. [policy.py](#policypy) - Unified policy engine
2. [service_discovery.py](#service_discoverypy) - Docker container auto-discovery
3. [rate_limiter.py](#rate_limiterpy) - Per-domain rate limiting (GCRA)
4. [circuit_breaker.py](#circuit_breakerpy) - Fail-fast for unhealthy upstreams
5. [credential_guard.py](#credential_guardpy) - Block API keys to wrong hosts (v2: smart detection + approval workflow)
6. [pattern_scanner.py](#pattern_scannerpy) - Fast regex for secrets/jailbreaks
7. [request_logger.py](#request_loggerpy) - JSONL structured logging
8. [metrics.py](#metricspy) - Per-domain stats (Prometheus/JSON)
9. [admin_api.py](#admin_apipy) - REST API on :9090

**Extended build (optional):**
10. [yara_scanner.py](#yara_scannerpy) - YARA rules for threats/credentials
11. [prompt_injection.py](#prompt_injectionpy) - ML classifier (DeBERTa + Ollama)

---

## policy.py

Unified policy engine. Controls which addons run on which domains/clients.

**Use case:** You want YARA scanning on LLM APIs but not on internal services. You want to bypass pattern scanning for admin users.

**Configuration:** `config/policy.yaml`
```yaml
defaults:
  addons:
    rate_limiter: { enabled: true }
    credential_guard: { enabled: true }
    yara_scanner: { enabled: true }

domains:
  # LLM APIs get full scanning
  "api.openai.com":
    addons:
      prompt_injection: { enabled: true, mode: dual }

  # Internal services - trust them
  "*.internal":
    bypass: [yara_scanner, pattern_scanner]

  # Package registries - skip heavy scanning
  "pypi.org":
    bypass: [yara_scanner, prompt_injection]

clients:
  # Admin clients (via X-Client-ID header)
  "admin-*":
    bypass: [pattern_scanner]
```

**Features:**
- Hot reload on file change or SIGHUP
- Wildcard patterns for domains and clients
- Per-addon settings override
- Bypass lists to disable specific addons
- LRU cache for fast policy lookups

---

## service_discovery.py

Auto-discovers Docker containers on the internal network.

**Use case:** You have multiple project containers joining `safeyolo-internal` and want SafeYolo to know about them for routing decisions, health checks, or metrics tagging.

**Example:** SafeYolo discovers your `webapp` container at `172.30.0.3:8000` and your `api` container at `172.30.0.4:3000`.

**Requirements:**
- Docker socket mounted: `-v /var/run/docker.sock:/var/run/docker.sock:ro`
- `pip install aiodocker`

**Options:**
```bash
--set discovery_network=safeyolo-internal   # Network to discover containers on
--set discovery_skip_containers=safeyolo    # Containers to ignore
--set discovery_refresh_interval=30        # Seconds between refreshes
```

**Other addons can query:**
```python
from addons.service_discovery import get_service_discovery

sd = get_service_discovery()

# Look up by port
service = sd.get_service_by_port(8000)
if service:
    print(f"Port 8000 is {service.container_name} at {service.internal_ip}")

# Look up by internal IP (used by credential_guard for project identification)
service = sd.get_service_by_ip("172.30.0.5")
if service:
    project = service.labels.get("com.docker.compose.project", service.container_name)
    print(f"Request from project: {project}")
```

---

## rate_limiter.py

Per-domain rate limiting using GCRA (Generic Cell Rate Algorithm).

**Use case:** Prevent your IP from getting blacklisted when an LLM goes into a loop making API calls, or when you're scraping too aggressively.

**Example:** LLM tries to make 50 requests/sec to `api.openai.com`. Rate limiter blocks after the burst allowance, returns 429 with `Retry-After` header.

**Configuration:** `config/rate_limits.json`
```json
{
  "default": {"rps": 10, "burst": 30},
  "domains": {
    "api.openai.com": {"rps": 50, "burst": 100},
    "api.anthropic.com": {"rps": 50, "burst": 100},
    "api.github.com": {"rps": 5, "burst": 20},
    "*.googleapis.com": {"rps": 2, "burst": 10}
  }
}
```

- `rps` - Requests per second (steady state rate)
- `burst` - Max requests in a burst before throttling

**Defaults are generous** (10 rps = 600/min) to allow normal usage while catching runaway loops. LLM APIs get higher limits (50 rps = 3000/min) since they're already expensive and rate-limited upstream.

**Response when limited:**
```json
{
  "error": "Rate limited by proxy",
  "domain": "api.openai.com",
  "retry_after_seconds": 2,
  "message": "Limit: 50 req/sec with burst of 100"
}
```

---

## circuit_breaker.py

Fail-fast for unhealthy upstreams. Stops hammering a service that's down.

**Use case:** External API starts returning 500s. Instead of retrying forever and wasting time, circuit breaker opens and returns 503 immediately. After timeout, it tests with a few requests and auto-recovers if healthy.

**States:**
- **CLOSED** - Normal operation, requests pass through
- **OPEN** - Service unhealthy, requests fail fast (503)
- **HALF_OPEN** - Testing recovery, limited requests allowed

**Example flow:**
1. `api.example.com` returns 5 consecutive 500s
2. Circuit opens -> immediate 503 for 60 seconds
3. After 60s, circuit goes half-open -> allows 3 test requests
4. If 2 succeed -> circuit closes (recovered)
5. If any fail -> circuit reopens with exponential backoff

**Options:**
```bash
--set circuit_failure_threshold=5   # Failures before opening
--set circuit_success_threshold=2   # Successes in half-open to close
--set circuit_timeout=60            # Seconds before open -> half-open
```

**Response when open:**
```json
{
  "error": "Service temporarily unavailable",
  "domain": "api.example.com",
  "circuit_state": "open",
  "retry_after_seconds": 45,
  "message": "Service has failed 5 times. Will retry in 45 seconds."
}
```

---

## credential_guard.py

Core security addon. Ensures credentials only go to authorized hosts with smart detection and human-in-the-loop approval.

**Use case:** LLM hallucinates `api.openal.com` instead of `api.openai.com`, or a prompt injection tricks it into sending your API key to `evil.com`. Credential guard blocks it with a 428 response that helps the agent self-correct.

**Threats covered:**
- Typosquat domains (`api.openal.com` vs `api.openai.com`)
- Subdomain attacks (`api.openai.com.evil.com`)
- Unicode homographs (`api.оpenai.com` with Cyrillic 'о')
- URL parameter leakage (`?api_key=sk-...`)
- Request body exfiltration
- Unknown high-entropy secrets in headers

### v2 Features

**Smart 2-Tier Detection:**
- **Tier 1 (high confidence)**: Standard auth headers (`Authorization`, `X-API-Key`, etc.) - pattern matching against known credential types
- **Tier 2 (medium confidence)**: All other headers - entropy heuristics detect unknown secrets (length ≥20, charset diversity ≥0.5, Shannon entropy ≥3.5)

**HMAC Fingerprinting:**
- Credentials are never logged or stored in raw form
- HMAC-SHA256 fingerprints used for allowlisting and audit trails
- Secret auto-generated on first run, stored in `data/hmac_secret`

**3-Way Decision Engine:**
- **Allow**: Credential in policy for this destination
- **Greylist Type 1 (destination mismatch)**: Known credential going to wrong host → 428 with self-correction prompt
- **Greylist Type 2 (requires approval)**: Unknown credential or not in policy → 428 with approval workflow

**Human-in-the-Loop Approval (via Ntfy):**
- Push notifications with Approve/Deny buttons
- Topic auto-generated on first run, stored in `data/ntfy_topic`
- Pending approvals queryable via admin API
- Approved credentials added to temp allowlist AND persistent policy files

**Persistent Policy Storage (Phase 5):**
- Approved credentials written to `data/policies/{project}.yaml`
- Files are human-readable YAML, editable on host
- File watcher detects changes and hot-reloads (1s polling)
- Policies persist across container restarts
- Atomic writes prevent corruption

**Project Identification (Phase 6):**
- Requests are mapped to projects via Docker service discovery
- Client IP → container → `com.docker.compose.project` label
- Falls back to container name, then "default" if no match
- Enables per-project policy isolation:
  - Requests from `webapp` container → `data/policies/webapp.yaml`
  - Requests from host machine → `data/policies/default.yaml`
- Graceful degradation: uses "default" when service discovery unavailable

**Policy file format:**
```yaml
# data/policies/webapp.yaml (for requests from 'webapp' compose project)
# data/policies/default.yaml (for host machine or unknown containers)
approved:
  - token_hmac: "abc123def456"
    hosts: ["api.example.com"]
    paths: ["/v1/*"]
    approved_at: "2025-01-02T14:30:00Z"
    approved_by: "ntfy"
    credential_type: "unknown_secret"
```

### Configuration

**Credential patterns:** `config/credential_rules.json`
```json
{
  "credentials": [
    {
      "name": "openai",
      "pattern": "sk-[a-zA-Z0-9]{48}",
      "allowed_hosts": ["api.openai.com"]
    },
    {
      "name": "anthropic",
      "pattern": "sk-ant-[a-zA-Z0-9-]{95}",
      "allowed_hosts": ["api.anthropic.com"]
    }
  ]
}
```

**v2 settings:** `config/credential_guard.yaml`
```yaml
# Detection level: paranoid | standard | patterns-only
detection_level: standard

# Entropy thresholds for heuristic detection
entropy:
  min_length: 20
  min_charset_diversity: 0.5
  min_shannon_entropy: 3.5

# Approval backend
approval:
  backend: ntfy
  ntfy:
    server: https://ntfy.sh
    topic: null  # Auto-generated, or set NTFY_TOPIC env var
    priority: 4
```

**Safe headers (skipped in entropy analysis):** `config/safe_headers.yaml`
```yaml
# Headers containing trace IDs, request IDs, etc.
safe_patterns:
  - "x-request-id"
  - "x-trace-id"
  - "x-correlation-id"
```

### Response Format

**428 Precondition Required** (replaces 403):
```json
{
  "error": "Credential routing error",
  "type": "destination_mismatch",
  "credential_type": "openai",
  "destination": "httpbin.org",
  "expected_hosts": ["api.openai.com"],
  "suggested_url": "https://api.openai.com/v1/...",
  "action": "self_correct",
  "reflection": "You appear to have sent an API credential to the wrong destination. Please verify the URL and retry."
}
```

For approval-required responses:
```json
{
  "error": "Credential requires approval",
  "type": "requires_approval",
  "credential_type": "unknown_secret",
  "action": "wait_for_approval",
  "approval_token": "abc123...",
  "retry_strategy": {
    "interval_seconds": 30,
    "max_attempts": 120
  }
}
```

### Options

```bash
--set credguard_block=true          # Block violations (default: true)
--set credguard_llm_response=true   # Use LLM-friendly error messages
--set credguard_scan_urls=true      # Scan URLs for credentials (default: false)
--set credguard_scan_bodies=true    # Scan request bodies (default: false)
--set credguard_rules=/path/to/rules.json
--set credguard_log_path=/app/logs/credguard.jsonl
```

### Scanning Scope

- **Headers only (default)**: Catches credential leakage in auth headers. Smart 2-tier detection catches both known patterns and unknown high-entropy secrets.
- **+ URL scanning**: Catches credentials in query params like `?api_key=sk-...`
- **+ Body scanning**: Scans request bodies. Useful for detecting credentials in API payloads.

---

## yara_scanner.py

Enterprise-grade pattern matching using YARA rules.

**Use case:** Scan requests and responses for credentials, jailbreak patterns, PII, or custom threats specific to your organization.

**Built-in rules detect:**
- **Credentials**: AWS keys, GitHub tokens, private keys, JWTs
- **Jailbreaks**: "Ignore instructions", DAN mode, developer mode
- **PII**: SSN, credit cards
- **Injection markers**: `[INST]`, `<<SYS>>`, `<|im_start|>`

**Load custom rules:**
```bash
--set yara_rules=/path/to/custom.yar
```

**Example custom rule:**
```yara
rule Company_Internal_Token {
    meta:
        description = "Internal API token"
        severity = 5
        category = "credential"
    strings:
        $token = /MYCO-[A-Z0-9]{32}/ ascii
    condition:
        $token
}
```

---

## pattern_scanner.py

Fast regex scanning (lighter than YARA, runs on everything).

**Use case:** Quick detection of common patterns without the overhead of YARA. Good for jailbreak phrases in requests and leaked secrets in responses.

**Built-in patterns:**

*Output scanning (responses):*
- OpenAI API keys (`sk-...`)
- AWS access keys (`AKIA...`)
- GitHub tokens (`ghp_...`, `gho_...`)
- Private keys (`-----BEGIN ... PRIVATE KEY-----`)
- Database connection strings

*Input scanning (requests):*
- "ignore previous instructions"
- "you are now DAN"
- "developer mode enabled"
- LLM instruction markers (`[INST]`, `<<SYS>>`)

---

## prompt_injection.py

Dual ML classifier for prompt injection - an 80% solution, not a silver bullet.

**Use case:** Detect when user input is trying to hijack an LLM's behavior. Catches obvious jailbreaks and injection patterns. Sophisticated attacks will get through.

**Dual classifier approach:**
1. **DeBERTa** (~15ms) - ONNX model, runs inline for immediate blocking
2. **Ollama/phi3.5** (~200ms) - Runs async as second opinion

If Ollama catches something DeBERTa missed, logs a false negative for model improvement.

**Options:**
```bash
--set injection_deberta_url=http://localhost:8081   # ONNX classifier
--set injection_ollama_url=http://localhost:11434   # Ollama API
--set injection_confidence_threshold=0.5            # Block threshold
--set injection_async_verify=true                   # Run Ollama as backup
```

---

## request_logger.py

JSONL structured logging for all requests.

**Use case:** Audit trail, debugging, alerting on blocked requests.

**Output format:**
```json
{"ts": "2025-12-06T10:30:00Z", "method": "POST", "host": "api.openai.com", "path": "/v1/chat/completions", "status": 200, "latency_ms": 150}
{"ts": "2025-12-06T10:30:01Z", "method": "POST", "host": "evil.com", "blocked_by": "credential-guard", "block_reason": "openai key to unauthorized host"}
```

**Options:**
```bash
--set safeyolo_log_path=/app/logs/safeyolo.jsonl
```

Logs are tailed to Docker stdout, so `docker logs -f safeyolo` shows them in real-time.

---

## metrics.py

Per-domain statistics in JSON and Prometheus formats.

**Use case:** Monitor proxy health, track which domains are getting rate limited or blocked, identify problem upstreams.

**Tracks:**
- Request counts, success rates
- Latency (avg, max) per domain
- Block counts by source (credential, yara, pattern, injection)
- Upstream errors (429s, 5xx, timeouts)
- Problem domain identification

**Access via admin API:**
```bash
curl http://localhost:9090/stats    # JSON
curl http://localhost:9090/metrics  # Prometheus format
```

---

## admin_api.py

REST API on port 9090 for runtime control.

**Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/stats` | GET | Aggregated stats from all addons |
| `/metrics` | GET | Prometheus format metrics |
| `/modes` | GET | Get all addon modes (warn vs block) |
| `/modes` | PUT | Set multiple addon modes at once |
| `/plugins/{name}/mode` | GET | Get mode for specific addon |
| `/plugins/{name}/mode` | PUT | Set mode for specific addon |
| `/plugins/credential-guard/allowlist` | GET | List temp allowlist entries |
| `/plugins/credential-guard/allowlist` | POST | Add temp allowlist entry |
| `/plugins/credential-guard/allowlist` | DELETE | Clear all allowlist entries |
| `/admin/approvals/pending` | GET | List pending approval requests |
| `/admin/approve/{token}` | POST | Approve a pending credential request |
| `/admin/deny/{token}` | POST | Deny a pending credential request |
| `/admin/policy/{project}` | GET | Get persistent policy for a project |
| `/admin/policy/validate` | POST | Validate YAML content |

**Example: Temporarily allow a blocked credential:**
```bash
# Add 5-minute allowlist for discussing OpenAI API usage
curl -X POST http://localhost:9090/plugins/credential-guard/allowlist \
  -H "Content-Type: application/json" \
  -d '{"credential_prefix": "sk-abc", "host": "api.anthropic.com", "ttl_seconds": 300}'
```

**Example: Human-in-the-loop approval workflow:**
```bash
# List pending approvals (includes project_id for each request)
curl http://localhost:9090/admin/approvals/pending | jq
# Returns: [{token, credential_type, host, path, project_id, ...}, ...]

# Approve a request (token from Ntfy notification or pending list)
# Approval writes to the project's policy file (e.g., data/policies/webapp.yaml)
curl -X POST http://localhost:9090/admin/approve/abc123xyz...

# Deny a request
curl -X POST http://localhost:9090/admin/deny/abc123xyz...
```

Ntfy notifications include clickable Approve/Deny buttons that call these endpoints automatically.

**Example: View and validate persistent policies:**
```bash
# View policy for default project
curl http://localhost:9090/admin/policy/default | jq

# Validate YAML before manual editing
curl -X POST http://localhost:9090/admin/policy/validate \
  -H "Content-Type: application/json" \
  -d '{"content": "approved:\n  - token_hmac: abc123"}'
```

**Example: Switch addons between warn and block modes:**

Core protections (credential-guard, rate-limiter) default to **block mode**. Other security addons default to **warn-only mode**. You can dynamically switch them at runtime:

| Addon | Option | Default |
|-------|--------|---------|
| credential-guard | `credguard_block` | **block** |
| rate-limiter | `ratelimit_block` | **block** |
| pattern-scanner | `pattern_block_input` | warn |
| yara-scanner | `yara_block_on_match` | warn |
| prompt-injection | `injection_block` | warn |

```bash
# Get current modes for all addons
curl http://localhost:9090/modes

# Disable blocking for development (set credential guard to warn mode)
curl -X PUT http://localhost:9090/plugins/credential-guard/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "warn"}'

# Disable rate limiting for testing bursts
curl -X PUT http://localhost:9090/plugins/rate-limiter/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "warn"}'

# Enable blocking for a warn-only addon (e.g., prompt injection)
curl -X PUT http://localhost:9090/plugins/prompt-injection/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "block"}'

# Set ALL addons to warn mode for debugging
curl -X PUT http://localhost:9090/modes \
  -H "Content-Type: application/json" \
  -d '{"mode": "warn"}'

# Set ALL addons to block mode (production)
curl -X PUT http://localhost:9090/modes \
  -H "Content-Type: application/json" \
  -d '{"mode": "block"}'
```

Note: The circuit-breaker always blocks when open (that's its purpose - fail fast for unhealthy services).
