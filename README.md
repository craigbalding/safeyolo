# SafeYolo

**Guardrails for "YOLO mode" coding agents.**

You sandboxed your coding agent to protect your machine. Now protect your keys when it hallucinates endpoints.

SafeYolo is a mitmproxy-based sidecar that prevents credential leakage, dampens runaway loops, and provides audit logs for agent HTTP/tool calls.

---

## Quick Start

**Note:** Using `curl -k` for quick testing from your host machine. For production, [run your coding agent in a container](#setup-option-1-claude-code-in-a-container-recommended) with the SafeYolo CA cert properly mounted.

```bash
# Get SafeYolo running
git clone https://github.com/craigbalding/safeyolo
cd safeyolo
docker compose up -d

# Verify it's running
curl http://localhost:9090/health
# Expected: {"status": "healthy", "proxy": "safeyolo"}

# Test it blocks credential leakage (fake key to httpbin.org)
curl -k -x http://localhost:8888 \
  -H "Authorization: Bearer sk-test1234567890abcdefghijklmnopqrstuvwxyz123456" \
  https://httpbin.org/get
# → 428 Precondition Required (credential detected, wrong destination)

# Check what happened (requires auth token)
export ADMIN_TOKEN=$(docker exec safeyolo cat /app/data/admin_token)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats | jq

# Verify the block was logged
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats | jq '.["credential-guard"].violations_total'
# Expected: 1 (or higher if you ran the test multiple times)
```

Your fake OpenAI key was blocked from reaching httpbin.org.

**Watch logs in real-time:**
```bash
# Live log monitoring with colored output and 5-second summaries
docker logs -f safeyolo 2>&1 | python scripts/logtail.py
```

**Next steps:**
- Add your missing API providers to `config/credential_rules.json` (patterns + allowed hosts, not actual keys)
- Adjust rate limits in `config/rate_limits.json` if needed
- Point your coding agent at `http://localhost:8888` as its proxy
- [See detailed setup for Claude Code](#use-case-claude-code-sidecar)

### How do I know it's working?

**Quick validation checklist:**

- [ ] Health endpoint returns 200: `curl http://localhost:9090/health`
- [ ] Fake credential blocked: Returns 428 status code
- [ ] Block logged in stats: `violations_total` increases
- [ ] Logs are being written: `tail logs/safeyolo.jsonl`

**What you should see:**

```bash
# 1. Health check
$ curl http://localhost:9090/health
{"status": "healthy", "proxy": "safeyolo"}

# 2. Stats show the credential guard is active
$ curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats | jq '.["credential-guard"]'
{
  "violations_total": 1,
  "violations_by_type": {
    "openai": 1
  },
  "rules_count": 5,
  ...
}

# 3. JSONL logs contain the block event with request_id correlation
$ tail logs/safeyolo.jsonl | jq 'select(.event | startswith("security."))'
{
  "ts": "2026-01-03T...",
  "event": "security.credential",
  "request_id": "req-abc123def456",
  "decision": "block",
  "host": "httpbin.org",
  ...
}
```

### Admin API Authentication

**All admin API endpoints require authentication** (except `/health`).

**Get your token:**
```bash
# From container
docker exec safeyolo cat /app/data/admin_token

# Or from host (if data/ is mounted)
cat data/admin_token
```

**Usage:**
```bash
# Set token as environment variable
export ADMIN_TOKEN=$(docker exec safeyolo cat /app/data/admin_token)

# Use in all API requests
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats | jq
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/admin/approvals/pending
```

**Security notes:**
- Token is generated on first startup
- Token persists in `/app/data/admin_token` (survives restarts)
- Token is shown once during first startup (save it!)
- Rotate token: Delete `data/admin_token` and restart
- `/health` endpoint exempt (for monitoring tools)

---

## Block-by-Default for Core Protections

SafeYolo runs in **block mode by default** for credential guard and rate limiting:
- **Credential guard scans HTTP headers by default** - low false positive rate
- **Rate limits are generous** - 10 req/sec default, 50 req/sec for LLM APIs (600+ requests/min)
- **Easy to disable for development** - `--set credguard_block=false --set ratelimit_block=false`

Other security addons (pattern_scanner in base, prompt_injection and yara_scanner in extended) default to warn-only mode.

## Choosing Your Image

SafeYolo has three build targets:

**Base (default, ~200MB)** - Core addons only, recommended for most users
```bash
docker compose up -d  # Uses base target
```
Includes: credential_guard, rate_limiter, circuit_breaker, pattern_scanner (regex), policy, metrics, admin_api

**Extended (~700MB)** - Adds ML + YARA for advanced detection
```bash
# Edit docker-compose.yml: change target to 'extended'
docker compose up -d
```
Adds: prompt_injection (experimental ML classifier), yara_scanner (enterprise pattern matching)

**Dev** - Development and testing environment
```bash
docker build --target dev -t safeyolo:dev .
```
Includes all extended addons plus pytest, ipython, and tools for model export/testing. For contributors only.

**Why separate?** Most teams just need credential protection and rate limiting. ML models add ~500MB for experimental prompt injection detection that generates many false positives. Only use if you're prepared to tune it for your workload.

## Key Features

- **Credential routing** - API keys only go to authorized hosts (OpenAI key -> api.openai.com only)
- **Smart detection** - 2-tier header analysis with entropy heuristics catches unknown secrets
- **Human-in-the-loop** - Push notifications via Ntfy for approve/deny decisions; approvals persist to per-project YAML files
- **Domain defense** - Blocks typosquats (`api.openal.com`) and homograph attacks (`api.оpenai.com` with Cyrillic 'о')
- **Runaway loop dampening** - Per-domain rate limiter + circuit breaker
- **Auditability** - JSONL logs, Prometheus metrics, admin API on :9090 (credentials never logged raw, only HMAC fingerprints)

## Who It's For

- Solo developers using coding agents daily
- Small teams running agents in CI
- Security-conscious teams needing egress policy + audit trails

**Questions?** Built by [craig@threatspotting.com](mailto:craig@threatspotting.com) · If you need an independent view on controls and evidence visit [safeyolo.com](https://safeyolo.com/#help)

## Safety Net, Not a Firewall

SafeYolo catches accidents and obvious attacks at the network layer. It won't stop a sophisticated attacker, but it will catch problems from LLM hallucinations, typosquatted domains, and copy-paste errors.

---

## Why SafeYolo Exists (optional reading)

*Already running SafeYolo and want to understand the philosophy? Read on. Otherwise, [skip to demos](#5-minute-demo).*

### Design Philosophy

### The Problem: Agents Are Untrusted Insiders

We've built identity controls, zero-trust networks, and least-privilege access. But AI coding agents introduce a new challenge: whether you're vibe coding or running serious dev workflows, your agent ends up with project API keys - yet makes decisions based on statistical patterns, not deterministic logic you can audit or predict.

When you give Claude Code your OpenAI API key and say "build me a chat app," you're handing credentials to a system that might hallucinate `api.openai.com` as `api.openal.com`. Or get prompt-injected into sending your keys to an attacker's server.

**How many API keys have already leaked this way?** After context window compaction, an agent loses details and starts guessing service URLs. We've seen production API keys leak when agents tried authenticating to the wrong host - infrastructure management via API is powerful, but dangerous when the agent loses context about service URLs. `api.service-provider.com` vs `api.serviceprovider.com`, or worse, completely wrong domains. No error, no warning, just credentials sent to someone else's server. In YOLO mode, you'd never know until you see unexpected charges or security incidents.

This is a new threat model: *untrusted insiders* - systems you want to use, but shouldn't fully trust with unrestricted network access.

### The Missing Layer: Network Security

We sandbox the filesystem (containers). We limit CPU and memory (cgroups). But we give AI agents unrestricted internet access with production credentials. The network layer was missing.

SafeYolo is egress control for the API economy:
- Credentials only reach authorized destinations
- Runaway loops get dampened before they blacklist your IP
- Every HTTP request is logged
- The agent gets clear feedback when blocked

### Trust, But Verify

Use AI agents with intentional constraints:
- **Fail closed for high-risk operations** - violations that cause immediate damage (wrong-host credential routing, runaway loops) are blocked by default
- **Make exceptions easy** - temp allowlist, admin API, runtime mode toggling
- **LLM-friendly error messages** - the agent learns from blocks, not just fails silently
- **Catch accidents, not APTs** - Focus on hallucinations, typosquats, and configuration errors, not sophisticated attacks

### What Gets Logged

Every request generates JSONL audit events with a unified taxonomy for easy filtering:

- **traffic.*** - Request/response events (`traffic.request`, `traffic.response`)
- **security.*** - Security decisions (`security.credential`, `security.ratelimit`, `security.circuit`, etc.)
- **admin.*** - Admin API actions (`admin.approve`, `admin.deny`, `admin.auth_failure`)
- **ops.*** - Operational events (`ops.startup`, `ops.config_reload`)

All events include a `request_id` for correlation across the request lifecycle. Security events include a `decision` field (`allow`, `block`, `warn`) for clear audit trails. Metrics track per-domain request counts, error rates, and block sources. You know what your agent is doing.

---

*SafeYolo adds the missing network security layer for AI coding agents. Containers protect your filesystem. SafeYolo protects your API keys and downstream services.*

---

## Threat Model

### What SafeYolo helps with:

- **Hallucinated endpoints** - Model misremembers `api.openai.com` as `api.openal.com`
- **Credential exfil via tool calls** - Prompt injection tricks model into sending keys to wrong host
- **Runaway loops** - LLM gets stuck making 1000 API calls per second
- **Audit trails** - You need to know what your agent actually did

### What SafeYolo does NOT do:

- Detect prompt injection reliably (experimental addon with high false positive rate)
- Replace app-layer authentication or authorization
- Inspect streamed/huge response bodies (>10MB are passed through)
- Stop attacks that don't go through the proxy

---

## 5-Minute Demo

**Note:** These demos use `curl -k` for quick testing from your host machine. For production, [run your coding agent in a container](#setup-option-1-claude-code-in-a-container-recommended) with the SafeYolo CA cert properly mounted.

### Quick Start

```bash
cd safeyolo
docker compose up -d

# Test basic proxy
curl -k -x http://localhost:8888 https://httpbin.org/ip

# Check admin API
export ADMIN_TOKEN=$(docker exec safeyolo cat /app/data/admin_token)
curl http://localhost:9090/health
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats

# Attach to mitmproxy TUI
docker exec -it safeyolo tmux attach
# Detach with Ctrl-B, D
```

### Demo 1: Credential Routing Detection

```bash
# OpenAI key pattern going to wrong host - blocked by default
curl -k -x http://localhost:8888 \
  -H "Authorization: Bearer sk-abcd1234567890abcd1234567890abcd1234567890abcdef" \
  https://httpbin.org/get
# → 428 Precondition Required (destination mismatch - should go to api.openai.com)

# Check the log to see what happened:
tail -1 logs/safeyolo.jsonl | jq .

# To disable blocking for development:
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  -X PUT http://localhost:9090/plugins/credential-guard/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "warn"}'

# Now the same request succeeds but logs a warning
```

### Demo 2: Typosquat Detection

```bash
# Typosquat of openai.com - blocked before reaching destination
curl -k -x http://localhost:8888 \
  -H "Authorization: Bearer sk-abcd1234567890abcd1234567890abcd1234567890abcdef" \
  https://api.openal.com/v1/chat
# → 428 Precondition Required (destination mismatch)

# Credential guard caught the typo before your key could leak
# Response includes expected hosts and a reflection prompt for the agent
```

### Demo 3: Rate Limiter

```bash
# Fire 10 rapid requests - rate limiter kicks in
for i in {1..10}; do
  curl -k -x http://localhost:8888 -s -o /dev/null -w "%{http_code}\n" \
    https://httpbin.org/get
done

# Expected: Mix of 200 and 429 responses as rate limiter enforces 10 req/sec
```

### Demo 4: Circuit Breaker

```bash
# Trigger 5 consecutive failures to open the circuit
for i in {1..5}; do
  curl -k -x http://localhost:8888 -s -o /dev/null -w "%{http_code}\n" \
    https://httpbin.org/status/500
done
# → Five 500 responses

# Circuit breaker opens - now returns 503 immediately
curl -k -x http://localhost:8888 -s -o /dev/null -w "%{http_code}\n" \
  https://httpbin.org/status/500
# → 503 (circuit open, protecting the failing service)

# After 60 seconds, circuit enters half-open state and allows test requests
```

### Demo 5: Human-in-the-Loop Approval

When credential guard detects an unknown credential or a request needing approval, it returns 428 and sends a push notification via Ntfy:

```bash
# Unknown credential triggers approval workflow
curl -k -x http://localhost:8888 \
  -H "X-Custom-Auth: secret-abc123xyz789def456ghi012jkl345mno" \
  https://api.example.com/endpoint
# → 428 Precondition Required (requires approval)

# Check pending approvals
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/admin/approvals/pending | jq

# Approve via admin API (or click button in Ntfy notification)
curl -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost:9090/admin/approve/{token}

# Deny instead
curl -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost:9090/admin/deny/{token}

# Clear all pending approvals (restart mitmproxy - in-memory state resets)
docker compose restart safeyolo

# Approvals persist to per-project YAML files - view them on host
# Project detected from source container's Docker compose project label
cat data/policies/default.yaml    # Default project (host requests)
cat data/policies/webapp.yaml     # Requests from 'webapp' compose project
# approved:
#   - token_hmac: abc123...
#     hosts: [api.example.com]
#     paths: [/api/*]
```

**Mobile Approvals Setup** (for solo devs):

1. **Configure notifications** - choose your platform:

   **iOS (Pushcut - recommended):**
   ```bash
   # Save your Pushcut webhook URL to data/pushcut_url
   echo 'https://api.pushcut.io/xxx/notifications/SafeYolo' > data/pushcut_url
   ```

   **Android (ntfy):**
   ```bash
   # Enable ntfy notifications in config/credential_guard.yaml
   # ntfy_enabled: true
   # Install ntfy app: https://ntfy.sh/docs/subscribe/phone/
   # Subscribe to topic in data/ntfy_topic
   ```

2. **Approve from your phone** - when a credential needs approval:
   - Push notification with Approve/Deny buttons
   - Button tap posts to ntfy topic
   - Approval listener (auto-started) calls admin API
   - Request proceeds (or is denied)

The approval listener starts automatically with SafeYolo. Logs at `logs/approval_listener.log`.

### If mitmproxy crashes

```bash
# Check the startup log
docker exec safeyolo cat /app/logs/mitmproxy.log
```

---

## Architecture

SafeYolo runs mitmproxy with a chain of native addons (10 in base, 12 in extended):

```
┌─────────────────────────────────────────────────────────────────┐
│                           SafeYolo                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Request flow (10 base addons + 2 extended):                    │
│                                                                 │
│  ┌──────────────────┐                                           │
│  │   request_id     │ -> Assigns unique request_id for tracing  │
│  └────────┬─────────┘    (runs FIRST for event correlation)     │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │     policy       │ -> Unified config [config/policy.yaml]    │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │service_discovery │ -> Docker container discovery + project ID │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │  rate_limiter    │ -> Per-domain GCRA config/rate_limits.json│
│  └────────┬─────────┘    Outbound rate limiing active by default│
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │circuit_breaker   │ -> Fail-fast for unhealthy upstreams      │
│  └────────┬─────────┘    Always active                          │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │ credential_guard │ -> Block keys to wrong hosts              │
│  └────────┬─────────┘    config/credential_rules.json           │
│           │              HTTP header detection by default       │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │  yara_scanner    │ -> YARA rules [extended build only]       │
│  └────────┬─────────┘    Warn mode by default                   │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │ pattern_scanner  │ -> Fast regex for secrets/jailbreaks      │
│  └────────┬─────────┘    Warn mode by default                   │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │prompt_injection  │ -> ML classifier [extended build only]    │
│  └────────┬─────────┘    Warn mode by default                   │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │ request_logger   │ -> JSONL structured logging               │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │    metrics       │ -> Per-domain stats (Prometheus/JSON)     │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │   admin_api      │ -> REST API on :9090                      │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│       Upstream                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Each addon is a standalone Python file using mitmproxy's addon API. No framework, no abstraction layer - just `request()` and `response()` hooks on `http.HTTPFlow` objects.

---

## Addons

SafeYolo includes 12 addons for security, reliability, and observability: 10 in the base build (~200MB), plus 2 optional addons in the extended build (~700MB). Each addon is a standalone Python file using mitmproxy's addon API.

**For detailed documentation**, see [docs/ADDONS.md](docs/ADDONS.md).

| Addon | Build | Description | Config File | Default Mode |
|-------|-------|-------------|-------------|--------------|
| **request_id.py** | Base | Assigns unique request_id to every request for event correlation across addons | Options only | Always active |
| **policy.py** | Base | Unified policy engine - controls which addons run on which domains/clients | `config/policy.yaml` | Always active |
| **service_discovery.py** | Base | Auto-discovers Docker containers on internal network for routing decisions | Options only | Always active |
| **rate_limiter.py** | Base | Per-domain rate limiting using GCRA - prevents IP blacklisting from runaway loops | `config/rate_limits.json` | **Block** (10 rps default, 50 for LLM APIs) |
| **circuit_breaker.py** | Base | Fail-fast for unhealthy upstreams - stops hammering services that are down | Options only | Always active (blocks when open) |
| **credential_guard.py** | Base | **Core security** - blocks API keys to unauthorized hosts with smart 2-tier detection, HMAC fingerprinting, and human-in-the-loop approval via Ntfy | `config/credential_guard.yaml` | **Block** (428 greylist responses) |
| **pattern_scanner.py** | Base | Fast regex scanning - lightweight detection of common secrets and jailbreak phrases | Built-in patterns | Warn only |
| **request_logger.py** | Base | JSONL structured logging for all requests - audit trail and debugging | Options only | Always active |
| **metrics.py** | Base | Per-domain statistics in JSON and Prometheus formats - monitoring and alerting | Options only | Always active |
| **admin_api.py** | Base | REST API on port 9090 - runtime control, mode switching, stats, allowlist management, approval endpoints | Options only | Always active |
| **yara_scanner.py** | Extended | Enterprise pattern matching - scans for credentials, jailbreaks, PII using YARA rules | `config/yara_rules/` | Warn only |
| **prompt_injection.py** | Extended | **Experimental** - ML classifier for prompt injection detection (high false positive rate, needs tuning) | Options only | Warn only |

**See [docs/ADDONS.md](docs/ADDONS.md) for complete reference** - configuration options, use cases, response formats, and examples for all addons (10 base + 2 extended).

---

## Use Case: Claude Code Sidecar

SafeYolo's primary use case is as an internet chokepoint for AI coding assistants:

```
┌─────────────────────────────────────────────────────┐
│                    Host Machine                     │
└─────────────────────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │    safeyolo-internal    │
              │       (network)         │
              └────────────┬────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Claude Code   │  │   Project     │  │   SafeYolo    │
│  (no direct   │  │  Container    │  │   (proxy)     │
│   internet)   │  │               │  │               │
└───────────────┘  └───────────────┘  └───────┬───────┘
                                              │
                                         Internet
```

All traffic routes through SafeYolo for credential routing, rate limiting, circuit breaking, and audit logging.

### Setup Option 1: Claude Code in a Container (Recommended)

**If you run Claude Code in Docker**, join the SafeYolo network:

```yaml
# docker-compose.yml for your coding environment
services:
  claude-code:
    # ... your existing config ...
    networks:
      safeyolo-internal:
        ipv4_address: 172.30.0.20
    volumes:
      - safeyolo-certs:/certs:ro
    environment:
      # Route all traffic through SafeYolo
      - HTTP_PROXY=http://172.30.0.10:8080
      - HTTPS_PROXY=http://172.30.0.10:8080
      - http_proxy=http://172.30.0.10:8080
      - https_proxy=http://172.30.0.10:8080
      # Trust mitmproxy CA cert for HTTPS inspection
      - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem
      - SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem
      - REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem

networks:
  safeyolo-internal:
    external: true

volumes:
  safeyolo-certs:
    external: true
```

**Validate the setup:**

1. Verify network connectivity:
```bash
docker run --rm --network safeyolo-internal alpine ping -c 1 172.30.0.10
# Expected: 1 packets transmitted, 1 received
```

2. Verify certificate mount:
```bash
docker exec claude-code ls -l /certs/mitmproxy-ca-cert.pem
# Expected: -rw-r--r-- ... mitmproxy-ca-cert.pem
```

3. Test proxy from container:
```bash
docker exec claude-code curl -x http://172.30.0.10:8080 http://httpbin.org/ip
# Expected: JSON response with your IP address
```

### Setup Option 2: Claude Code on Host Machine

**If you run Claude Code directly on your host**, set proxy environment variables:

```bash
# Add to ~/.bashrc or ~/.zshrc
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888

# Install mitmproxy CA cert (one-time setup)
# Linux:
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates

# macOS:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**Then start Claude Code** - all traffic now routes through SafeYolo.

**Validate the setup:**

1. Verify CA cert installed:
```bash
# Linux:
ls -l /usr/local/share/ca-certificates/mitmproxy.crt

# macOS:
security find-certificate -c mitmproxy -a | grep "CN=mitmproxy"
```

2. Test proxy works:
```bash
curl http://httpbin.org/ip
# Expected: JSON response (request went through proxy at localhost:8888)
```

3. Verify HTTPS interception:
```bash
curl https://httpbin.org/ip
# Expected: Should succeed without -k flag (CA cert trusted)
```

---

## Troubleshooting

Quick solutions to common problems. For detailed addon configuration, see [docs/ADDONS.md](docs/ADDONS.md).

### SafeYolo blocks legitimate requests

**Symptoms:** 428 responses for valid API calls

**Diagnosis:**
```bash
# Check which addon blocked it
export ADMIN_TOKEN=$(docker exec safeyolo cat /app/data/admin_token)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats | jq '.["credential-guard"]'

# Review recent blocks
tail -20 logs/safeyolo.jsonl | jq 'select(.blocked_by != null)'
```

**Solutions:**

1. **For development**: Switch all addons to warn-only mode:
   ```bash
   curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     -X PUT http://localhost:9090/modes \
     -H "Content-Type: application/json" \
     -d '{"mode":"warn"}'
   ```

2. **For production**: Approve the credential (writes to policy file):
   ```bash
   # List pending approvals
   curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/admin/approvals/pending | jq

   # Approve by token
   curl -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost:9090/admin/approve/{token}
   ```

3. **Permanent allowlist**: Add to `config/credential_rules.json` allowed_hosts

---

### Admin API returns connection refused

**Symptoms:** `curl http://localhost:9090/health` fails

**Diagnosis:**
```bash
# Check if admin API started
docker logs safeyolo 2>&1 | grep -i "admin api"

# Check if port is listening
docker exec safeyolo netstat -tlnp | grep 9090
```

**Common causes:**
- Admin API failed to start → Check logs for Python traceback
- Port not exposed in docker-compose.yml → Add `- "9090:9090"` to ports section
- Firewall blocking localhost:9090 → Check firewall rules

---

### Proxy works with curl -k but not from application

**Symptoms:** `curl -k -x http://localhost:8888` succeeds, but application fails with SSL errors

**Diagnosis:**
```bash
# Verify certificate is accessible
docker exec claude-code ls -l /certs/mitmproxy-ca-cert.pem

# Test HTTPS without -k flag (requires CA cert trust)
docker exec claude-code curl https://httpbin.org/ip
```

**Common causes:**
- CA cert not installed/trusted → Follow [Setup Option 1](#setup-option-1-claude-code-in-a-container-recommended) cert installation
- Application doesn't respect `SSL_CERT_FILE` env var → Check app docs for cert config
- Certificate path mismatch → Verify volume mount path matches env var

**Solution for containers:**
```yaml
environment:
  - SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem
  - REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem
  - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem
volumes:
  - safeyolo-certs:/certs:ro
```

---

### State behavior after restart

**What persists across restarts:**
- ✅ Approved credentials → `/app/data/policies/{project}.yaml`
- ✅ Block/warn mode (if set via `SAFEYOLO_BLOCK=true` env var)
- ✅ Rate limiter state → `/app/data/rate_limiter_state.json` (new in this update)
- ✅ Circuit breaker state → `/app/data/circuit_breaker_state.json` (new in this update)
- ✅ HMAC secret, Ntfy topic, admin token

**What is reset on restart:**
- ❌ Pending approvals (not yet approved) → Retry the request to regenerate
- ❌ Temp allowlist entries → Use permanent policy approvals instead
- ❌ Runtime mode changes via admin API → Set `SAFEYOLO_BLOCK=true` in docker-compose.yml

**To make mode changes persistent:**
```yaml
# docker-compose.yml
services:
  safeyolo:
    environment:
      - SAFEYOLO_BLOCK=true  # Block mode persists across restarts
```

---

### Logs growing too large

**Current status:** No automatic log rotation implemented

**Manual rotation:**
```bash
# Rotate logs manually
docker exec safeyolo mv /app/logs/safeyolo.jsonl /app/logs/safeyolo-$(date +%Y%m%d).jsonl

# Restart to create new log file
docker compose restart safeyolo
```

**External logrotate (recommended):**
```
# /etc/logrotate.d/safeyolo
/path/to/safeyolo/logs/*.jsonl {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        docker compose -f /path/to/safeyolo/docker-compose.yml restart safeyolo > /dev/null
    endscript
}
```

---

### Container won't start

**Symptoms:** `docker compose up -d` fails or container exits immediately

**Diagnosis:**
```bash
# Check container logs
docker logs safeyolo

# Check mitmproxy startup log
docker exec safeyolo cat /app/logs/mitmproxy.log 2>/dev/null || echo "Container not running"
```

**Common causes:**
- Port 8888 or 9090 already in use → Change ports in docker-compose.yml
- Addon syntax error → Check logs for Python traceback
- Missing config files → Verify `config/*.json` files exist
- Permissions error → Check data/ directory is writable

---

## Large Response Streaming

By default, mitmproxy buffers entire responses before passing them through addons. This can cause OOM crashes on large downloads (e.g., 200MB podcast files).

SafeYolo enables `stream_large_bodies=10m` - responses over 10MB are streamed without buffering.

**Security tradeoff:** Streamed responses bypass body inspection. We accept this because:
- 10MB threshold is high enough to scan most text-based responses (LLM outputs, API responses, logs)
- Large binary files (podcasts, videos, model weights) rarely contain scannable secrets
- Pattern/regex scanning 500MB+ files is expensive and low-signal
- The alternative is OOM crashes on legitimate large downloads

**If you need to scan large responses:** Lower the threshold or disable streaming entirely (may cause OOM on media downloads):
```bash
# Edit scripts/start-safeyolo.sh
MITM_OPTS="${MITM_OPTS} --set stream_large_bodies=50m"  # Higher threshold
MITM_OPTS="${MITM_OPTS} --set stream_large_bodies=0"    # Disable streaming (scan everything)
```

---

## Reloading Addons

To pick up addon code changes without full container restart:

```bash
docker exec safeyolo /app/scripts/reload-mitmproxy.sh
```

**How it works:** At startup, `start-safeyolo.sh` saves the full mitmproxy command to `/tmp/mitmproxy-cmd.sh`. The reload script stops mitmproxy and re-runs that exact command. This ensures reload always matches the startup configuration - no duplicated config to maintain.

For config file changes (policy.yaml, rate_limits.json, credential_rules.json), most addons hot-reload automatically. Check individual addon docs.

**Important: Runtime settings are reset on restart.** Any changes made via the admin API (warn/block modes, temp allowlists) are in-memory only. On restart, SafeYolo returns to its startup defaults:
- All security addons start in warn-only mode (unless `SAFEYOLO_BLOCK=true` is set)
- Temp allowlist entries are cleared

If you need blocking mode to persist across restarts, set `SAFEYOLO_BLOCK=true` in your docker-compose.yml or environment.

---

## Running Without Docker

```bash
# Install deps
pip install mitmproxy httpx yara-python pyyaml aiodocker

# Run with addons
mitmproxy -p 8080 \
  -s addons/policy.py \
  -s addons/service_discovery.py \
  -s addons/rate_limiter.py \
  -s addons/circuit_breaker.py \
  -s addons/credential_guard.py \
  -s addons/yara_scanner.py \
  -s addons/pattern_scanner.py \
  -s addons/request_logger.py \
  -s addons/metrics.py \
  -s addons/admin_api.py \
  --set policy_file=config/policy.yaml \
  --set ratelimit_config=config/rate_limits.json \
  --set credguard_rules=config/credential_rules.json \
  --set safeyolo_log_path=logs/safeyolo.jsonl \
  --set admin_port=9090 \
  --set stream_large_bodies=10m
```

---

## Writing Custom Addons

SafeYolo addons are just mitmproxy addons. Here's the pattern:

```python
from mitmproxy import ctx, http

class MyAddon:
    name = "my-addon"

    def load(self, loader):
        """Register options."""
        loader.add_option(
            name="myaddon_enabled",
            typespec=bool,
            default=True,
            help="Enable my addon",
        )

    def request(self, flow: http.HTTPFlow):
        """Called for each request."""
        # Check policy first
        from addons.policy import get_policy_engine
        policy = get_policy_engine()
        if policy and not policy.is_addon_enabled(self.name, flow):
            return  # Disabled by policy

        if should_block(flow):
            flow.response = http.Response.make(403, b"Blocked")
            flow.metadata["blocked_by"] = self.name

    def response(self, flow: http.HTTPFlow):
        """Called for each response."""
        pass

# mitmproxy discovers this
addons = [MyAddon()]
```

Key patterns:
- Use `flow.metadata` for inter-addon communication
- Set `flow.metadata["blocked_by"]` when blocking (logger picks it up)
- Check policy before processing if you want per-domain control
- Register options via `load()` for runtime config
- Access options via `ctx.options.your_option`

**Shared utilities** in `addons/utils.py`:
```python
from .utils import write_jsonl, make_block_response

# Structured JSONL logging
write_jsonl(self.log_path, "my_event", log, domain=host, details="...")

# Standard JSON block response with X-Blocked-By header
flow.response = make_block_response(
    403,
    {"error": "Blocked", "reason": "..."},
    self.name,
    {"X-Custom-Header": "value"},  # optional extra headers
)
```

See mitmproxy docs: https://docs.mitmproxy.org/stable/addons-overview/

---

## Files

```
safeyolo/
├── addons/                    # Native mitmproxy addons (12 total)
│   ├── utils.py               # Shared utilities (logging, responses, write_event)
│   ├── request_id.py          # Request ID assignment (runs first)
│   ├── sse_streaming.py       # SSE/streaming response handler
│   ├── policy.py              # Unified policy engine
│   ├── service_discovery.py   # Docker container discovery
│   ├── rate_limiter.py        # Per-domain rate limiting (GCRA)
│   ├── circuit_breaker.py     # Fail-fast for unhealthy upstreams
│   ├── credential_guard.py    # API key protection
│   ├── yara_scanner.py        # YARA threat detection (extended)
│   ├── pattern_scanner.py     # Regex scanning for secrets/jailbreaks
│   ├── prompt_injection.py    # ML classification (extended, experimental)
│   ├── request_logger.py      # JSONL structured logging
│   ├── metrics.py             # Per-domain statistics
│   └── admin_api.py           # REST API on :9090 (with audit logging)
├── config/
│   ├── policy.yaml            # Per-domain/client addon config
│   ├── credential_guard.yaml  # Credential Guard v2 config
│   ├── credential_rules.json  # Credential patterns + allowed hosts
│   ├── safe_headers.yaml      # Headers to skip in entropy analysis
│   ├── rate_limits.json       # Per-domain rate limits
│   └── yara_rules/            # YARA rules (extended build)
│       ├── default.yar        # Default threat detection rules
│       └── README.md          # YARA rule documentation
├── scripts/
│   ├── start-safeyolo.sh      # Docker entrypoint
│   ├── ntfy_approval_listener.py  # Mobile approval handler (subscribes to ntfy)
│   ├── test_build.sh          # Build target testing (base/extended/dev)
│   ├── logtail.py             # Live log viewer with summaries
│   ├── export_piguard_onnx.py # Export PIGuard model to ONNX
│   └── test_*.py              # Classifier evaluation scripts
├── models/
│   └── piguard-onnx/          # PIGuard ONNX model files
│       ├── config.json        # Model configuration
│       ├── modeling_piguard.py # Custom model code
│       ├── tokenizer_config.json
│       └── special_tokens_map.json
├── data/                      # Runtime-generated secrets (gitignored)
│   ├── ntfy_topic             # Auto-generated Ntfy topic
│   ├── hmac_secret            # Auto-generated HMAC key
│   └── policies/              # Persistent approval policies
│       └── {project}.yaml     # Per-project approved credentials
├── tests/                     # Pytest test suite (345+ tests)
│   ├── conftest.py            # Fixtures and setup
│   ├── test_credential_guard.py
│   ├── test_rate_limiter.py
│   ├── test_circuit_breaker.py
│   ├── test_pattern_scanner.py
│   ├── test_policy.py
│   ├── test_prompt_injection.py
│   ├── test_admin_api.py
│   ├── test_integration.py
│   ├── test_ntfy_integration.py
│   ├── test_request_id.py     # Request ID addon tests
│   └── test_utils_logging.py  # Logging utilities and taxonomy tests
├── docs/
│   ├── ADDONS.md              # Complete addon reference
│   ├── FUTURE.md              # Ideas under consideration
│   └── prompt-injection-classifier-evaluation.md
├── requirements/              # Python dependencies by build target
│   ├── base.txt               # Core deps (mitmproxy, httpx, tenacity)
│   ├── extended.txt           # + ML/YARA (onnxruntime, yara-python)
│   └── dev.txt                # + testing (pytest, torch)
├── Dockerfile                 # Multi-stage: base/extended/dev
├── docker-compose.yml
├── LICENSE                    # MIT License
└── README.md
```

**Running tests:**
```bash
# In Docker
docker exec -it safeyolo python -m pytest tests/ -v

# Locally (requires mitmproxy installed)
cd safeyolo && python -m pytest tests/ -v
```

---

## License & Attribution

SafeYolo is released under the **MIT License**. See [LICENSE](LICENSE) for details.

**Built with [mitmproxy](https://mitmproxy.org/)** - SafeYolo is based on mitmproxy's addon architecture but is not affiliated with or endorsed by the mitmproxy project.
