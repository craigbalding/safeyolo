# Security

SafeYolo is security software. This document outlines our security principles and how they inform architectural decisions.

## Principles

### 1. Minimize Trust

**Principle:** Grant the minimum access required. Don't trust what you don't have to.

**In practice:**
- SafeYolo container has no Docker socket access. Service discovery uses static config written by the CLI, not runtime Docker queries. (`addons/service_discovery.py`)
- Agents run in isolated networks with no direct internet. Bypass attempts fail rather than leak.
- Admin API requires bearer token auth for all mutating operations. (`addons/admin_api.py`)

### 2. Fail Closed

**Principle:** When uncertain, block. False positives are recoverable; credential leaks are not.

**In practice:**
- Unknown credentials trigger approval workflow, not silent passthrough. (`addons/credential_guard.py:_decide()`)
- Destination mismatches return HTTP 428 with actionable feedback, not silent drops.
- Circuit breaker fails fast on unhealthy upstreams. (`addons/circuit_breaker.py`)

### 3. Never Store Secrets

**Principle:** Credentials should not appear in logs, policies, or anywhere on disk.

**In practice:**
- Credentials are fingerprinted via HMAC-SHA256. Only the fingerprint is stored/logged. (`addons/credential_guard.py:_fingerprint()`)
- Policy files contain `token_hmac`, never raw tokens. (`~/.safeyolo/policies/`)
- Log entries include fingerprint for correlation, never the credential itself.

### 4. Defense in Depth

**Principle:** Multiple independent checks. Don't rely on a single layer.

**In practice:**
- Tier 1: Pattern matching for known credential formats (OpenAI, Anthropic, GitHub, etc.)
- Tier 2: Entropy analysis catches unknown high-entropy secrets in auth headers
- Homoglyph detection flags mixed-script domain attacks (`api.οpenai.com` with Cyrillic 'ο')
- Rate limiting prevents runaway loops independent of credential checks

### 5. The Eager Intern Problem

**Principle:** Agents aren't malicious - they're like an inexperienced but energetic intern. Confident, fast, helpful, and occasionally wrong in ways that matter.

An intern might email the wrong client, cc the wrong list, or paste credentials into a public Slack channel. Not malicious, just moving fast without the experience to know what can go wrong. AI agents have the same failure mode: hallucinating an endpoint, confusing `api.openai.com` with `api.openai.com.example.io`, or helpfully sending your GitHub token to a diagnostics endpoint.

**In practice:**
- Secure Mode enforces network isolation because agents will find creative ways around process-level controls - not to bypass you, but because they're problem-solving
- HTTP 428 responses are machine-readable so agents can self-correct ("oh, wrong endpoint") without human intervention for obvious mistakes
- Humans approve policy changes because "are you sure?" only works if someone experienced is asking
- Quick Mode bypass is documented, not hidden - know your intern's access level

### 6. Audit Everything

**Principle:** Every decision should be traceable. When something goes wrong, you need to know what happened.

**In practice:**
- All requests logged to JSONL with unique request IDs (`addons/request_id.py`, `addons/request_logger.py`)
- Security decisions include reasoning: credential type, destination, expected hosts, decision
- Logs are structured for grep/jq analysis, not just human reading

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
| **Quick Mode bypass** | By design | Agents can unset proxy vars or open direct sockets. Use Secure Mode for autonomous agents. |
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

| Area | File | Notes |
|------|------|-------|
| Credential detection | `addons/credential_guard.py` | Pattern matching, entropy analysis |
| HMAC fingerprinting | `addons/credential_guard.py:_fingerprint()` | Never stores raw credentials |
| Policy enforcement | `addons/credential_guard.py:_check_policy()` | Per-project isolation |
| Service discovery | `addons/service_discovery.py` | Static config, no Docker socket |
| Admin API auth | `addons/admin_api.py` | Bearer token validation |
| Request logging | `addons/request_logger.py` | JSONL audit trail |
| Network isolation | `cli/src/safeyolo/templates/` | Docker compose templates |
