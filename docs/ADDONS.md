# SafeYolo Addons Reference

Complete documentation for SafeYolo's mitmproxy addons.

## How It Works

```
                    ┌─────────────────────┐
                    │      Internet       │
                    │  api.openai.com     │
                    │  api.anthropic.com  │
                    │  github.com         │
                    └──────────▲──────────┘
                               │
┌──────────────────────────────┼──────────────────────────────┐
│                      Your Machine                           │
│                              │                              │
│  ┌────────────────┐  ┌───────┴───────────────────────────┐  │
│  │  safeyolo CLI  │  │      SafeYolo Container (:8080)   │  │
│  │                │  │                                   │  │
│  │  start, watch, │  │  network_guard    - deny/limit?   │  │
│  │  agent add     │  │  credential_guard - wrong dest?   │  │
│  │                │  │  pattern_scanner  - secrets?      │  │
│  │                │  │  test_context     - tagged test?  │  │
│  └───────┬────────┘  │  circuit_breaker  - unhealthy?    │  │
│          │           └───────────────────▲───────────────┘  │
│          │ manages                       │                  │
│          ▼                               │ all traffic      │
│  ┌───────────────────────────────────────┼───────────────┐  │
│  │  ~/.safeyolo/                         │               │  │
│  │    config.yaml    ┌───────────────────┴────────────┐  │  │
│  │    policy.toml  │                                │  │  │
│  │    policies/      │  ┌──────────┐  ┌──────────┐    │  │  │
│  │    logs/          │  │  Claude  │  │  Codex   │ ...│  │  │
│  │                   │  └──────────┘  └──────────┘    │  │  │
│  │                   │         Agent Containers       │  │  │
│  └───────────────────┴────────────────────────────────┴──┘  │
└─────────────────────────────────────────────────────────────┘
```

In **Sandbox Mode**, agent containers have no direct internet access. All traffic routes through SafeYolo where addons inspect, control, and log requests.

## Overview

Addons are loaded in this order (order matters for security):

| Layer | Addon | Purpose | Default Mode |
|-------|-------|---------|--------------|
| 0 | file_logging | Structured JSONL file logging setup | Always on |
| 0 | memory_monitor | Process memory and connection tracking | Always on |
| 0 | admin_shield | Block proxy access to admin API | Always on |
| 0 | agent_api | Read-only PDP agent API for agent self-service | Always on |
| 0 | loop_guard | Detect and break proxy loops (Via header) | Always on |
| 0 | request_id | Request ID for event correlation | Always on |
| 0 | sse_streaming | SSE/streaming for LLM responses | Always on |
| 0 | policy_engine | Unified policy evaluation and budgets | Always on |
| 1 | network_guard | Access control + rate limiting + homoglyph detection | **Block** |
| 1 | circuit_breaker | Fail-fast for unhealthy upstreams | Always on |
| 2 | credential_guard | Block credentials to wrong hosts | **Block** |
| 2 | pattern_scanner | Regex scanning for secrets | Warn |
| 2 | service_gateway | Credential injection for agent→service routing | Always on |
| 2 | test_context | Require X-Test-Context header on target hosts | **Block** |
| 3 | request_logger | JSONL audit logging | Always on |
| 3 | metrics | Per-domain statistics | Always on |
| 3 | admin_api | REST API on :9090 | Always on |
| 3 | flow_recorder | Record HTTP flows to SQLite for agent queryability | Always on |
| TUI | flow_pruner | Prune old flows to prevent TUI memory growth | TUI-only |

**Layers:**
- **Layer 0 (Infrastructure):** Must run first - logging, memory tracking, loop detection, request IDs, policy engine, streaming
- **Layer 1 (Network Policy):** Access control, rate limiting, circuit breakers
- **Layer 2 (Security Inspection):** Credential routing, content scanning, test context
- **Layer 3 (Observability):** Logging, metrics, admin API
- **TUI-only:** Loaded only in interactive TUI mode (`SAFEYOLO_TUI=true`)

**Default behavior:**
- `network_guard`, `credential_guard`, and `test_context` block by default (core protections)
- `pattern_scanner` warns by default (higher false positive rate)
- `test_context` is only active when `target_hosts` is non-empty in the policy file
- Other addons are always active with no mode toggle

---

## file_logging.py

Configures structured JSONL file logging at mitmproxy startup.

**Always active**

**How it works:**
- Runs in the `running()` hook (fires once at startup, before any traffic)
- Configures a `RotatingFileHandler` for `LOG_DIR/safeyolo.jsonl`
- All subsequent `write_event()` calls from any addon go to this file

---

## memory_monitor.py

Tracks process memory and active connection/WebSocket state for OOM diagnostics.

**Always active** (infrastructure, not a security sensor)

**How it works:**
- Reads RSS and HWM from `/proc/self/status` (zero stored state)
- Tracks active connections (`client_connected`/`client_disconnected` hooks)
- Tracks WebSocket sessions (`websocket_start`/`websocket_end` hooks)
- Emits `ops.memory` events every 60 seconds with snapshot of state
- All tracked state self-cleans on disconnect/close

**Key design:** Does NOT inherit SecurityAddon. Uses the simpler standalone pattern.

**Stats (via admin API):**
```json
{
  "rss_mb": 142.3,
  "rss_hwm_mb": 155.1,
  "rss_start_mb": 98.5,
  "uptime_s": 3600,
  "total_flows": 1523,
  "active_connections": 3,
  "active_websockets": 1
}
```

---

## agent_api.py

Read-only PDP agent API on virtual hostname `_safeyolo.proxy.internal` for agent self-service diagnostics.

**Always active** (infrastructure, not a security sensor)

**How it works:**
- Intercepts requests to `_safeyolo.proxy.internal` (virtual hostname, doesn't resolve)
- Validates HMAC-signed readonly bearer tokens
- Returns PDP data as synthetic HTTP responses (never touches the network)
- Sets `flow.metadata["blocked_by"]` so downstream addons skip agent API requests

**Important:** Agents must use `http://` (not `https://`) since the virtual hostname doesn't resolve and CONNECT tunnels would fail.

**Endpoints:**

| Path | Description |
|------|-------------|
| `/health` | Health check (no auth required) |
| `/status` | Aggregated addon stats |
| `/policy` | Current baseline policy |
| `/budgets` | Budget usage per resource |
| `/config` | Sensor config (credential rules, scan patterns) |
| `/explain?host=X&cred=Y` | Explain what would happen for a request |
| `/memory` | Memory and connection stats |
| `/gateway/services` | Authorized capabilities and available services for the agent |
| `/gateway/request-access` | Submit an access request for a risky route (POST, returns 202) |

**Token management:**
```bash
# On host: create a readonly token
safeyolo token create

# Agent uses token in requests
curl -H "Authorization: Bearer <token>" http://_safeyolo.proxy.internal/status
```

---

## loop_guard.py

Detects and breaks proxy loops using the RFC 7230 Via header mechanism.

**How it works:**
- Runs in the `requestheaders` hook (fires before all `request` hooks)
- Checks if the `Via` header contains our token (`safeyolo`)
- If found: request has already passed through us → respond 508 Loop Detected
- If not found: inject `1.1 safeyolo` into `Via` so looped-back requests carry it

**Why this matters:**
When a request targets an address that resolves back to SafeYolo's own listen port (e.g. `host.docker.internal:8080`), it creates an infinite request amplification loop — thousands of requests per second filling logs and consuming resources.

**Example blocked response:**
```json
{"error": "Loop Detected", "message": "Request would create a proxy loop"}
```

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

Unified policy engine with **host-centric** policy format. Handles credential authorization, rate limiting (budgets), and per-domain addon configuration. The host-centric format compiles to IAM-style rules at load time.

**Architecture:** The policy system is split across addons and the PDP package:

*Addons (mitmproxy integration):*
- `policy_engine.py` (~970 lines) - PolicyEngineAddon, mitmproxy integration
- `policy_loader.py` (~300 lines) - File loading, watching, hot reload
- `budget_tracker.py` (~190 lines) - GCRA-based rate limiting state

*PDP package (policy evaluation core):*
- `pdp/schemas.py` (~500 lines) - HttpEvent, PolicyDecision, Effect enums
- `pdp/core.py` (~650 lines) - PDPCore engine, evaluation logic
- `pdp/client.py` (~600 lines) - PolicyClient interface (local/HTTP modes, incl. admin)
- `pdp/app.py` (~380 lines) - FastAPI adapter for running PDP as a service

Addons use `get_policy_client()` to access the configured PolicyClient instance.

**Configuration:** `config/policy.toml` (hosts and credentials) + `config/addons.yaml` (addon tuning)

```toml
# policy.toml — host-centric format
version = "2.0"
budget = 12_000

required = ["credential_guard", "network_guard", "circuit_breaker"]
scan_patterns = []

[hosts]
"api.openai.com"    = { allow = ["openai:*"],    rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"],  rate = 3_000 }
"api.github.com"    = { allow = ["github:*"],     rate = 300 }
"*"                 = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]
```

```yaml
# addons.yaml — addon tuning (sibling to policy.toml)
addons:
  credential_guard:
    enabled: true
    detection_level: standard
    entropy: { min_length: 20, min_charset_diversity: 0.5, min_shannon_entropy: 3.5 }
  circuit_breaker:
    enabled: true
    failure_threshold: 5
  pattern_scanner:
    enabled: true
    builtin_sets: []
```

Each host entry can include: `allow`, `rate`, `bypass`, `egress`, `unknown_creds`, `rules` (IAM escape hatch). The wildcard `"*"` sets defaults. `allowed_hosts` for credential rules are auto-derived from the `[hosts]` section.

**Credential condition formats:**
- `openai:*` - type-based matching (any credential of that type)
- `hmac:a1b2c3d4` - HMAC-based matching (specific credential fingerprint)

**Policy effects** (internal IAM model):
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

**How credential routing works (host-centric):**
1. Credential detected in request (pattern matching -> type, HMAC fingerprint)
2. PolicyEngine looks up the destination host in the `hosts` section
3. Checks if credential matches the host's `credentials` list (type or HMAC)
4. If match found -> permit
5. If no match -> fall through to wildcard `"*"` entry (typically `unknown_creds = "prompt"`)

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
--set discovery_network=safeyolo_internal
```

---

## network_guard.py

Unified network policy addon combining access control, rate limiting, and homoglyph detection in a single evaluation.

**Default: Block mode**

**Use cases:**
- Restrict which domains coding agents can access (allowlist/denylist)
- Prevent IP blacklisting when an LLM loops on API calls
- Detect and block domain lookalike attacks (homoglyphs)

**Key design:** Single `PolicyEngine.evaluate_request()` call per request prevents double budget consumption.

**Configuration:** Network policies are defined in `policy.toml` using the host-centric format:

```toml
budget = 12_000   # Global cap across all domains

[hosts]
"api.openai.com"    = { allow = ["openai:*"],  rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"], rate = 3_000 }
"*"                 = { egress = "allow", unknown_creds = "prompt", rate = 600 }
```

Each host's `rate` controls requests per minute. The `budget` caps total traffic across all hosts. Hosts listed in `[hosts]` are implicitly allowed; unlisted hosts fall through to the `"*"` wildcard.

**Response when denied (403):**
```json
{
  "error": "Access denied by proxy",
  "domain": "blocked.com",
  "reason": "Access denied to blocked.com",
  "message": "Network access to blocked.com is not permitted."
}
```

**Response when rate limited (429):**
```json
{
  "error": "Rate limited by proxy",
  "domain": "api.openai.com",
  "reason": "budget_exceeded",
  "message": "Too many requests to api.openai.com. Please slow down."
}
```

**Response when egress approval required (428):**
```json
{
  "error": "Network access requires approval",
  "type": "egress_approval_required",
  "destination": "unknown-api.example.com",
  "action": "wait_for_approval",
  "reflection": "Access to unknown-api.example.com is not in the allowed hosts list. Check if this is an expected destination, then approve or deny via safeyolo watch."
}
```

**How it works:**
1. Request comes in for domain
2. NetworkGuard checks for homoglyph attacks (mixed Unicode scripts)
3. NetworkGuard calls `PolicyEngine.evaluate_request()` (single call)
4. PolicyEngine evaluates `network:request` permissions
5. Results:
   - `effect: deny` → returns 403 Forbidden
   - `effect: prompt` → returns 428 Egress Approval Required
   - `effect: budget_exceeded` → returns 429 with Retry-After header
   - `effect: allow` or `effect: budget` (within budget) → pass through

**Options:**
```bash
--set network_guard_enabled=true   # Enable network guard (default: true)
--set network_guard_block=true     # Block mode (default: true, false = warn only)
--set network_guard_homoglyph=true # Enable homoglyph detection (default: true)
```

### Egress Control

NetworkGuard handles egress approvals for unlisted hosts when the wildcard entry has `egress = "prompt"`. This lets operators lock down outbound access so agents cannot reach arbitrary hosts without approval.

**Egress postures** (set on the wildcard `"*"` entry or per-host):
- `egress = "allow"` -- unlisted hosts are permitted (default)
- `egress = "prompt"` -- unlisted hosts trigger a 428 requiring human approval via `safeyolo watch`
- `egress = "deny"` -- unlisted hosts are blocked outright (403)

```toml
[hosts]
"api.openai.com"    = { allow = ["openai:*"],  rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"], rate = 3_000 }
"$known_bad"        = { egress = "deny" }
"*"                 = { egress = "prompt", unknown_creds = "prompt", rate = 600 }
```

With `egress = "prompt"`, any request to a host not explicitly listed in `[hosts]` gets a 428 response. The operator sees the pending request in `safeyolo watch` and can approve or deny it. Approved hosts are added to the policy file automatically.

Note that `egress` and `unknown_creds` are independent controls. `egress` governs whether the host itself is reachable; `unknown_creds` governs what happens when an unrecognized credential is sent to any host.

### Homoglyph Detection

Detects mixed-script domain attacks like `api.оpenai.com` (Cyrillic 'о' instead of Latin 'o'). When enabled, requests to domains with mixed Unicode scripts are blocked before any policy evaluation.

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

**~390 lines** - focused on credential detection and routing. Detection logic lives in `addons/detection/credentials.py`; policy evaluation via `PolicyClient`.

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

**Credential patterns:** `config/policy.toml` (credential sections)
```toml
[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]

[credential.anthropic]
match   = ['sk-ant-api[a-zA-Z0-9-]{90,}']
headers = ["authorization", "x-api-key"]
```

`allowed_hosts` are auto-derived from the `[hosts]` section -- any host with `allow = ["openai:*"]` becomes an allowed host for the `openai` credential type.

**Entropy settings:** `config/addons.yaml` (credential_guard section)
```yaml
addons:
  credential_guard:
    enabled: true
    detection_level: standard  # patterns-only | standard | paranoid
    entropy:
      min_length: 20
      min_charset_diversity: 0.5
      min_shannon_entropy: 3.5
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

Approvals are stored in the policy file as host entries:

```toml
[hosts]
# Type-based: allow any custom-api credential to api.example.com
"api.example.com" = { allow = ["custom-api:*"], rate = 600 }

# HMAC-based: allow specific credential to api.example.com
"api.example.com" = { allow = ["hmac:a1b2c3d4"], rate = 600 }
```

**Credential condition formats:**
- Type-based (`openai:*`, `anthropic:*`, `custom:*`) - matches any credential of that type
- HMAC-based (`hmac:a1b2c3d4`) - matches specific credential by fingerprint

**When to use each:**
- **Type-based:** When key rotation is expected (new keys auto-approved)
- **HMAC-based:** When you want to approve only a specific credential (more secure for unknown types)

**HMAC fingerprinting:** Credentials are never logged raw. First 16 chars of HMAC-SHA256 used for logging and policy matching.

### Options

```bash
--set credguard_block=true          # Block mode (default: true)
--set credguard_scan_urls=false     # Scan URL query params (default: false)
--set credguard_scan_bodies=false   # Scan request bodies (default: false)
--set credguard_log_path=/path.jsonl # Separate log file (optional)
```

### Related Features

**Homoglyph detection:** Mixed-script attacks like `api.оpenai.com` (Cyrillic 'о') are detected by `network_guard.py`, not credential_guard. See network_guard section above.

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

## service_gateway.py

### service_gateway

**Purpose:** Routes agent requests to external services through the gateway, injecting real credentials from the vault so agents never see secrets. Enforces capability-based access control and risky route approval via the PDP.

**How it works:**
1. Policy compiler processes the `agents:` section and mints gateway tokens (`sgw_` prefix)
2. Agent containers receive gateway tokens as environment variables
3. When an agent makes a request with a gateway token in the Authorization header, service_gateway:
   - Strips the `sgw_` token
   - Looks up the agent's capability for this service
   - Evaluates the request against capability routes (positive list — no deny rules)
   - If the route matches a **risky route**, queries the PDP with ATT&CK tactics, enables, irreversible signals, and account persona
   - PDP checks risk appetite rules in the policy file (`[[risk]]` in TOML / `gateway:` in YAML) and active grants
   - If a matching **grant** exists (approved by operator via watch or admin API), the request bypasses PDP risk evaluation
   - Looks up the real credential from the vault and injects it using the service's auth config (bearer, API key, etc.)
   - Forwards the request to the target host
4. **Once-grants** are consumed after a successful (2xx) response. Non-2xx responses (4xx, 5xx) do not consume the grant, allowing retry. Grant TTL defaults to 1 hour, configurable via `gateway.grant_ttl_seconds` in the policy file.
5. Flow store redacts injected credentials as `[GATEWAY:...last4]`

**Service definitions** describe external APIs using v2 format: auth methods, capabilities (named sets of allowed routes), and risky routes (tagged with ATT&CK tactics). Builtins ship for common APIs (gmail, slack, github). Users can add custom service YAMLs in `~/.safeyolo/services/`.

**Vault** stores encrypted credentials referenced by policy.toml agent service bindings. Auto-refreshes OAuth2 tokens when `refresh_on_401: true`.

**Hot-reload:** Service definitions are watched for changes (2s poll). Vault requires proxy restart.

**Related CLI:**
- `safeyolo agent authorize <agent> <service> --capability <name>` -- wire an agent to a service
- `safeyolo services list/show` -- inspect service definitions
- `safeyolo vault add/list/remove/oauth2` -- manage credentials

---

## test_context.py

Links HTTP traffic to test activities via `X-Test-Context` header on operator-declared target hosts.

**Default: Block mode** (428 soft-reject)

**Activation:** Active when `target_hosts` is non-empty in the policy file. No separate enable flag — add target hosts to activate, remove to deactivate.

**How it works:**
1. Requests to non-target hosts pass through untouched
2. Requests to target hosts must include `X-Test-Context` header
3. Missing or malformed header → 428 response with instructions
4. Valid header → parsed, stored in metadata, stripped before upstream
5. Response phase logs the response with the test context

**Header format:** `X-Test-Context: run=<run_id>;agent=<agent_id>;test=<test_id>`

Required keys: `run`, `agent`. Optional: `test`, `phase`.

**Configuration (addons.yaml):**
```yaml
addons:
  test_context:
    target_hosts:
      - "target.example.com"
      - "*.target-corp.com"   # Wildcards supported
```

**Response when missing (428):**
```json
{
  "error": "Test context required",
  "type": "missing_context",
  "destination": "target.example.com",
  "header": "X-Test-Context",
  "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
  "example": "X-Test-Context: run=sec1;agent=idor;test=IDOR-003"
}
```

**Options:**
```bash
--set test_context_block=true   # Block mode (default: true, false = warn only)
```

---

## flow_pruner.py

Prunes old completed flows from mitmproxy's in-memory view to prevent TUI memory growth.

**TUI-only** (loaded only when `SAFEYOLO_TUI=true`)

**Why this exists:** mitmproxy's TUI retains every flow object in memory for the scrollable list. After ~1500-2000 flows, memory grows until the process is killed (exit code 137). This addon caps the retained flow count.

**How it works:**
- Checks every 30 seconds via the `response()` hook
- When flow count exceeds the limit, removes oldest completed flows
- Uses `ctx.master.view.remove(flow)` to free the flow objects

**Options:**
```bash
--set flow_pruner_max=500   # Maximum flows to retain (default: 500)
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
| `gateway.*` | Service gateway decisions (risky routes, grants, capability checks) |
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
curl http://localhost:9090/stats    # JSON (includes metrics)
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
| GET | `/modes` | Current addon modes |
| PUT | `/modes` | Set all addon modes |
| GET | `/plugins/{addon}/mode` | Get specific addon mode |
| PUT | `/plugins/{addon}/mode` | Set specific addon mode |
| GET | `/admin/policy/baseline` | Read baseline policy |
| PUT | `/admin/policy/baseline` | Update baseline policy |
| POST | `/admin/policy/baseline/approve` | Add credential permission |
| POST | `/admin/policy/validate` | Validate policy YAML |
| GET | `/admin/policy/task/{id}` | Read task policy |
| PUT | `/admin/policy/task/{id}` | Create/update task policy |
| GET | `/admin/budgets` | Current budget usage |
| POST | `/admin/budgets/reset` | Reset budget counters |
| POST | `/admin/grants` | Add a grant (operator approves a risky route for an agent) |
| GET | `/admin/grants` | List active grants |
| DELETE | `/admin/grants/{grant_id}` | Revoke a specific grant |
| GET | `/debug/addons` | Debug: list loaded addons |

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
