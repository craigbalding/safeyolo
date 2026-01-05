# Security

SafeYolo is security software. This document outlines our security principles and how they inform architectural decisions.

## Principles

### 1. Minimize Trust

**Principle:** Grant the minimum access required. Don't trust what you don't have to.

**In practice:**
- SafeYolo container has no Docker socket access. Service discovery uses static config written by the CLI, not runtime Docker queries. (`addons/service_discovery.py`)
- Agents run in isolated networks with no direct internet (`internal: true`). Bypass attempts fail rather than leak.
- Admin API requires bearer token auth for all mutating operations. (`addons/admin_api.py`)
- Token comparison uses `secrets.compare_digest()` to prevent timing attacks. (`addons/admin_api.py:71`)
- Admin API ports bind to localhost only (`127.0.0.1:9090`), not all interfaces. (`docker-compose.yml`)
- Container runs as non-root via host UID/GID mapping (`user: "${SAFEYOLO_UID}:${SAFEYOLO_GID}"`).

### 2. Fail Closed

**Principle:** When uncertain, block. False positives are recoverable; credential leaks are not.

**In practice:**
- Unknown credentials trigger approval workflow, not silent passthrough. PolicyEngine evaluates `effect: prompt` permissions.
- Destination mismatches return HTTP 428 with actionable feedback, not silent drops. (`addons/credential_guard.py:242`)
- Circuit breaker fails fast on unhealthy upstreams. (`addons/circuit_breaker.py`)
- Policy validation uses Pydantic `model_validate()`. Invalid policies are rejected, not silently ignored. (`addons/policy_loader.py:150`)
- Startup script verifies network guard is in block mode, exits if verification fails. (`scripts/start-safeyolo.sh:307`)
- Test suite asserts container does not run as root. (`tests/test_policy_loader.py:389`)

### 3. Never Store Secrets

**Principle:** Credentials should not appear in logs, policies, or anywhere on disk.

**In practice:**
- Credentials are fingerprinted via HMAC-SHA256. Only the fingerprint is stored/logged. (`addons/utils.py:405`)
- Policy files use human-readable credential types (`openai`, `anthropic`), never raw tokens. (`~/.safeyolo/baseline.yaml`)
- Log entries include fingerprint for correlation, never the credential itself.
- HMAC secret uses atomic write with secure permissions (`O_CREAT|O_EXCL`, mode 0o600). (`addons/utils.py:395`)
- Admin API token files created with mode 0o600. (`scripts/start-safeyolo.sh:238`)

### 4. Destination-First Policy

**Principle:** Define what credentials can access each endpoint, not what endpoints each credential can access.

**Why destination-first:**
- **IAM-aligned:** Resource = thing being protected (endpoint). Condition = what can access it.
- **Prevents format collision:** Different services may use same credential format. Destination-first ensures approving `api.service-a.com` for unknown credentials doesn't accidentally allow access to `api.service-b.com`.
- **Flexible approval:** Supports both type-based (`openai:*` - good for key rotation) and HMAC-based (`hmac:a1b2c3d4` - specific credential only).

**In practice:**
- Policy resource = destination pattern (`api.openai.com/*`)
- Policy condition.credential = what can access it (`["openai:*"]` or `["hmac:abc123"]`)
- Unknown credentials can be approved per-destination with HMAC precision

### 5. Defense in Depth

**Principle:** Multiple independent checks. Don't rely on a single layer.

**In practice:**
- Tier 1: Pattern matching for known credential formats (OpenAI, Anthropic, GitHub, etc.)
- Tier 2: Shannon entropy analysis catches unknown high-entropy secrets in auth headers. (`addons/utils.py:309`)
- Homoglyph detection flags mixed-script domain attacks (`api.οpenai.com` with Cyrillic 'ο'). (`addons/network_guard.py:55`)
- GCRA rate limiting prevents runaway loops independent of credential checks. (`addons/budget_tracker.py`)
- Thread-safe operations across all stateful addons via Lock/RLock. (`addons/metrics.py:88`, `addons/policy_loader.py:85`)
- `blocked_by` metadata coordinates between addons in the chain. (`addons/base.py:140`)

### 6. The Eager Intern Problem

**Principle:** Agents aren't malicious - they're like an inexperienced but energetic intern. Confident, fast, helpful, and occasionally wrong in ways that matter.

An intern might email the wrong client, cc the wrong list, or paste credentials into a public Slack channel. Not malicious, just moving fast without the experience to know what can go wrong. AI agents have the same failure mode: hallucinating an endpoint, confusing `api.openai.com` with `api.openai.com.example.io`, or helpfully sending your GitHub token to a diagnostics endpoint.

**In practice:**
- Sandbox Mode enforces network isolation because agents will find creative ways around process-level controls - not to bypass you, but because they're problem-solving
- HTTP 428 responses are machine-readable so agents can self-correct ("oh, wrong endpoint") without human intervention for obvious mistakes
- Humans approve policy changes because "are you sure?" only works if someone experienced is asking
- Try Mode bypass is documented, not hidden - know your intern's access level

### 7. Audit Everything

**Principle:** Every decision should be traceable. When something goes wrong, you need to know what happened.

**In practice:**
- All requests logged to JSONL with unique request IDs (uuid4 prefix + timestamp). (`addons/request_id.py:30`)
- Security decisions include reasoning: credential type, destination, expected hosts, decision.
- `blocked_by` field in logs shows which addon blocked the request. (`addons/request_logger.py:295`)
- Logs are structured for grep/jq analysis, not just human reading.

### 8. Minimal Attack Surface

**Principle:** Reduce what can be exploited. Every package, port, and capability is a potential attack vector.

**In practice:**
- Single OS package in container (tmux only). No curl, procps, net-tools, iproute2. (`Dockerfile:35`)
- `--no-install-recommends` prevents transitive package bloat. (`Dockerfile:35`)
- Addons are passive - they inspect traffic but never initiate network connections. No httpx/requests/aiohttp imports.
- Stream large bodies (10MB threshold) prevents OOM from media downloads. (`scripts/start-safeyolo.sh:152`)
- Health checks use Python httpx instead of curl - one less binary in image.
- Non-root execution set at runtime via docker-compose, not baked into image. (`docker-compose.yml:43`)

## Architecture Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ HOST (trusted)                                          │
│                                                         │
│  CLI: manages config, starts containers, no secrets     │
│  Config: ~/.safeyolo/ - policies, rules, logs           │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ SAFEYOLO CONTAINER (semi-trusted)                       │
│                                                         │
│  Sees all traffic including credentials in transit      │
│  Cannot access Docker, host filesystem (except mounts)  │
│  Admin API on :9090 (token-protected)                   │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ AGENT CONTAINERS (untrusted)                            │
│                                                         │
│  Network-isolated, only route is through SafeYolo       │
│  Cannot reach internet directly                         │
│  Cannot reach other agents                              │
└─────────────────────────────────────────────────────────┘
```

## Known Limitations

We're explicit about what SafeYolo does NOT protect against:

| Limitation | Status | Notes |
|------------|--------|-------|
| **Try Mode bypass** | By design | Agents can unset proxy vars or open direct sockets. Use Sandbox Mode for autonomous agents. |
| **Credentials in URL query params** | Off by default | Enable with `--set credguard_scan_urls=true`. Performance tradeoff. |
| **Credentials in request bodies** | Off by default | Enable with `--set credguard_scan_bodies=true`. Performance and false-positive tradeoff. |
| **Credentials in URL path segments** | Not implemented | `/api/sk-proj-abc123/resource` - rare pattern, not currently scanned. |
| **Prompt injection** | Out of scope (v1) | SafeYolo operates at network layer, not prompt layer. |
| **Non-HTTP exfiltration** | Out of scope (v1) | DNS tunneling, ICMP, etc. Use network-level controls if needed. |
| **Compromised ~/.safeyolo/** | Out of scope (v1) | If an attacker controls your config directory, all bets are off. |

## For Security Researchers

We welcome security research on SafeYolo.

**What we're looking for:**
- Credential bypass techniques (ways to leak credentials past SafeYolo)
- Policy isolation breaks (Agent A accessing Agent B's approvals)
- Admin API auth bypass
- Log injection or forgery
- Fingerprint collisions that could confuse policy matching

**How to report:**
- Email: craig@threatspotting.com
- Or open a GitHub issue if the finding is not sensitive

**What to expect:**
- No financial rewards (we're not funded for bounties)
- No CVEs until the project matures (we're pre-1.0)
- Acknowledgment in this document for credible finds
- We genuinely appreciate fix suggestions and PRs - not expected, but welcomed

**Current acknowledgments:**
- (None yet - be the first!)

## Code Pointers

Addons use standalone imports (e.g., `from utils import ...`) matching mitmproxy's `-s` execution model.

| Area | File | Notes |
|------|------|-------|
| Policy engine | `addons/policy_engine.py` | Unified IAM-style policy evaluation |
| Destination-first matching | `addons/policy_engine.py:329` | `evaluate_credential()` - resource=destination, condition.credential=what can access |
| Credential detection | `addons/credential_guard.py` | Pattern matching, entropy analysis |
| Credential type mapping | `addons/credential_guard.py:104` | `detect_credential_type()` - maps patterns to types |
| HMAC fingerprinting | `addons/utils.py:405` | `hmac_fingerprint()` - never stores raw credentials |
| Atomic secret write | `addons/utils.py:369` | `load_hmac_secret()` - O_CREAT\|O_EXCL with 0o600 |
| Shannon entropy | `addons/utils.py:309` | `calculate_shannon_entropy()` - high-entropy secret detection |
| Condition matching | `addons/policy_engine.py:55` | `Condition` class with `matches()` - type-based and HMAC-based credential matching |
| Budget tracking | `addons/budget_tracker.py:34` | `GCRABudgetTracker` - rate limiting via GCRA |
| Homoglyph detection | `addons/network_guard.py:55` | `detect_homoglyph_attack()` - mixed-script domain spoofing |
| Circuit breaker | `addons/circuit_breaker.py` | Fail-fast for unhealthy upstreams |
| Service discovery | `addons/service_discovery.py` | Static config, no Docker socket |
| Admin API auth | `addons/admin_api.py:71` | `_check_auth()` - bearer token with `secrets.compare_digest()` |
| Base addon class | `addons/base.py:48` | `SecurityAddon` - stats, blocking, decision logging |
| Request ID | `addons/request_id.py` | UUID correlation for audit trail |
| Request logging | `addons/request_logger.py` | JSONL audit trail with `blocked_by` field |
| Network isolation | `cli/src/safeyolo/templates/` | Docker compose templates for agent containers |
| Non-root execution | `docker-compose.yml` | Host UID/GID mapping |
| Startup verification | `scripts/start-safeyolo.sh` | Block mode verification |
