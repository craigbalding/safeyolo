# SafeYolo

**Policy-based cyber hygiene for autonomous coding agents.**  
Because your agent is helpful, fast… and occasionally over-enthusiastic on the internet.

SafeYolo is an **egress control plane** for AI coding agents: it sits between your agent and the internet, enforcing **per-agent policies** and producing an **audit trail** of outbound HTTP(S) calls.

It’s built for the uncomfortable reality that agents can be too *resourceful* sometimes: if an agent hallucinates an API endpoint and leaks your key, or simply “tries something” that would harm your IP reputation (or overwhelm someone else's service), SafeYolo helps keep that enthusiasm **on-policy**.

### What you get
- **Controlled egress:** place limits on where your agent can wander and ensure your API keys in HTTP requests only reach approved hosts.
- **Evidence by default:** JSONL logs with decisions + correlation (useful for reviews, audits, and “what happened?” moments).
- **Two ways to run it:** a fast “try it” mode, and an enforced mode where bypass attempts fail.

### Trust & Risk

SafeYolo is a local TLS-intercepting proxy (MITM). It can only block leaked credentials if it can see where they're going.

**What SafeYolo guarantees (by design):**
- **Sandbox Mode reduces risk:** agent runs in unprivileged container with no direct internet; proxy is the only egress path
- **Try Mode is for evaluation, not enforcement:** agents can bypass by unsetting proxy vars
- **Evidence by default:** decisions logged locally (JSONL) for review

**What SafeYolo does not claim:**
- Not a malware sandbox; doesn't defend against determined adversaries
- Doesn't "solve" prompt injection; constrains outbound behavior only

**Supply-chain:** Don't trust a prebuilt image? Build locally from source.

### How Does It Intercept Claude/Codex Traffic?

- **Try Mode:** SafeYolo prints standard proxy + CA env vars; your agent respects them and routes HTTP(S) through the local proxy.
- **Sandbox Mode:** Agent runs in Docker network with no direct internet access; SafeYolo proxy is the only route out.

No "routing magic" - just standard proxying with explicit TLS inspection.

### Who SafeYolo is for
- **Builders using agentic tools** who want **simple egress control** without slowing down shipping.
- **Security pros and platform engineers** who want a **low-friction, defensible sandbox** to try agents safely.
- **Teams heading into security reviews** (ISO 27001 / SOC 2 / enterprise procurement) who need **policy + enforcement + evidence** for agent governance.

## Status

SafeYolo is **pre-v1** and currently undergoing breaking changes. The CLI and container image are **not published yet**, so the Quick Start commands below won’t work today.

If you want to follow along (or be an early tester), star the repo and watch releases — v1 is the first “stable install” milestone.

## Quick Start (v1 preview)

```bash
# Install CLI (pick one)
pipx install safeyolo          # classic
uv tool install safeyolo       # faster, modern

# Start proxy (auto-configures on first run)
safeyolo start

# Print what would be set (safe, no changes)
safeyolo cert env

# If it looks right, apply it
eval "$(safeyolo cert env)"

# Run your agent
claude
```

`safeyolo cert env` prints standard `HTTP_PROXY`/`HTTPS_PROXY` env vars - inspect them first if you don't like `eval`.

That's it. SafeYolo is now inspecting all HTTPS traffic from your shell session.

## Profiles

| Profile | Setup | Typical use |
|---------|-------|-------------|
| **Managed** (default) | CLI handles everything | Most users |
| **Integrated** | Bring your own config | Teams with existing Docker/K8s infrastructure |

Both profiles support single or multiple agents with per-agent policies.

## Deployment Modes

| Mode | Enforcement | Use case |
|------|-------------|----------|
| **Try Mode** (default) | Per-process - agents can bypass | Fast proxy setup; bypassable |
| **Sandbox Mode** | Enforced - bypass attempts fail | Container network isolation; proxy is the only egress path |

### Try Mode (Default)

Try Mode uses per-process environment variables to route traffic through SafeYolo. It's the fastest way to try things out:

```bash
safeyolo start
eval $(safeyolo cert env)
# Your agent now goes through SafeYolo
```

**Limitation:** In **Try Mode** agents may bypass the proxy in response to getting blocked - just as an eager intern might - by unsetting proxy variables or opening direct sockets. This is expected and not the intended deployment mode (use Sandbox Mode for that). Try Mode is for evaluating SafeYolo UX, not for security research or properly constraining agents.

### Sandbox Mode (Enforced)

In **Sandbox Mode**, SafeYolo runs your coding agent in an **unprivileged container** with **no direct internet access**. The only outbound path is through the **SafeYolo proxy container**, where outbound HTTP(S) traffic is **inspected, controlled, and logged**.

This materially reduces host + network risk while keeping the workflow smooth — you get guardrails and evidence without turning every request into a permission-prompt-fest.

Install SafeYolo on your laptop — or run it on a home server / VPS for an always-on “agent box” you can connect to remotely:

```bash
# Generate agent container template
safeyolo sandbox setup

# Run agent in isolated container
cd claude-code
docker compose run --rm claudecode
```

The agent container connects to an internal Docker network where SafeYolo is the only route to the internet. Bypass attempts fail rather than leak.

**Multi-agent:** Run multiple agents with separate policies:

```bash
safeyolo agent add claude-code
safeyolo agent add openai-codex
safeyolo agent run claude-code  # Each agent gets isolated policy
```

See `safeyolo agent list` for available templates.

**Authentication:** If you've already logged into your coding agent from your host (via `claude` or `codex`), your credentials are mounted into the container automatically. Otherwise, when the containerized agent starts up, you can choose how to authenticate following the agent providers first-run screen.

## What SafeYolo Does

Implements a policy layer to control agent network egress.  SafeYolo doesn’t try to detect why a request happened — it constrains what can happen next.  Features include:

**Credential routing** - help prevent credentials being sent to unexpected destinations. An OpenAI key to `api.openai.com.attacker.io` (e.g., from a bad link, agent mistake, or untrusted content) gets blocked with HTTP 428 + JSON payload (machine-readable, agent can retry after approval).

**Smart detection** - Pattern matching for known providers (OpenAI, Anthropic, GitHub, etc.) plus entropy analysis may catch unknown secrets.

**Human-in-the-loop** - Unknown credentials trigger approval prompts. Approve once, and it's remembered.

**Rate limiting** - Per-domain limits prevent runaway loops from blacklisting your IP.

**Audit trail** - Every request logged to JSONL with decision reasons and request correlation.

For security principles, threat model, and vulnerability reporting, see [SECURITY.md](docs/SECURITY.md).

## CLI Commands

| Command | Description |
|---------|-------------|
| `safeyolo start` | Start the proxy container (auto-configures on first run) |
| `safeyolo stop` | Stop the proxy |
| `safeyolo status` | Show health and stats |
| `safeyolo cert env` | Print CA trust and proxy environment variables |
| `safeyolo cert show` | Show CA cert location and fingerprint |
| `safeyolo agent add <name>` | Add agent container (multi-agent setup) |
| `safeyolo agent run <name>` | Run agent in isolated container |
| `safeyolo agent list` | List available agent templates |
| `safeyolo setup check` | Verify Docker access and prerequisites |
| `safeyolo init` | Setup wizard (for customization) |
| `safeyolo check` | Verify setup, proxy, and HTTPS working |
| `safeyolo watch` | Monitor and approve credentials |
| `safeyolo logs -f` | Follow logs in real-time |
| `safeyolo mode` | View/change addon modes |
| `safeyolo test` | Test request through proxy |

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
│  │  start, watch, │  │  credential_guard - wrong dest?   │  │
│  │  cert env      │  │  rate_limiter     - too fast?     │  │
│  │                │  │  pattern_scanner  - secrets?      │  │
│  └───────┬────────┘  │  request_logger   - audit trail   │  │
│          │           └───────────────────▲───────────────┘  │
│          │ manages                       │                  │
│          ▼                               │ all traffic      │
│  ┌───────────────────────────────────────┼───────────────┐  │
│  │  ~/.safeyolo/                         │               │  │
│  │    config.yaml    ┌───────────────────┴────────────┐  │  │
│  │    rules.json     │                                │  │  │
│  │    policies/      │  ┌──────────┐  ┌──────────┐    │  │  │
│  │    logs/          │  │  Claude  │  │  Codex   │ ...│  │  │
│  │                   │  └──────────┘  └──────────┘    │  │  │
│  │                   │         Agent Containers       │  │  │
│  └───────────────────┴────────────────────────────────┴──┘  │
└─────────────────────────────────────────────────────────────┘
```

## Approval Workflow

When SafeYolo blocks a credential:

1. Agent gets HTTP 428 with details (credential type, expected hosts)
2. Event appears in `safeyolo watch`
3. You approve or deny interactively
4. Approved credentials are saved to policy file
5. Subsequent requests pass through

```bash
$ safeyolo watch

Watching: ~/.safeyolo/logs/safeyolo.jsonl

╭─ Credential Blocked 14:32:15 ─────────────────────────────╮
│ Credential   anthropic                                    │
│ Destination  api.example.com                              │
│ Fingerprint  hmac:a1b2c3d4...                             │
│ Reason       destination_mismatch                         │
├───────────────────────────────────────────────────────────┤
│ [A]pprove | [D]eny | [S]kip                               │
╰───────────────────────────────────────────────────────────╯
Action (a/d/s): a
Approved - a1b2c3d4... -> api.example.com
```

## Configuration

Configuration lives in `~/.safeyolo/` (auto-created on first `safeyolo start`).

```
~/.safeyolo/
├── config.yaml          # Proxy settings
├── baseline.yaml        # Policy: credentials, rate limits, addon config
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
└── data/                # Admin token, HMAC secret
```

### baseline.yaml

Unified policy using IAM-style vocabulary with **destination-first** credential routing:

```yaml
permissions:
  # Destination-first: what credentials can access each endpoint
  - action: credential:use
    resource: "api.openai.com/*"      # destination pattern
    effect: allow
    condition:
      credential: ["openai:*"]        # credential types allowed

  - action: credential:use
    resource: "api.anthropic.com/*"
    effect: allow
    condition:
      credential: ["anthropic:*"]

  # HMAC-based approval for specific unknown credentials
  - action: credential:use
    resource: "api.custom.com/*"
    effect: allow
    condition:
      credential: ["hmac:a1b2c3d4"]   # specific credential fingerprint

  # Unknown destinations require approval
  - action: credential:use
    resource: "*"
    effect: prompt

  # Rate limits (requests per minute)
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000  # 50 rps

required:
  - credential_guard
  - rate_limiter

addons:
  credential_guard: {enabled: true}
  rate_limiter: {enabled: true}

domains:
  "*.internal":
    bypass: [pattern_scanner]
```

**Credential condition formats:**
- `openai:*` - type-based (any OpenAI key)
- `hmac:a1b2c3d4` - HMAC-based (specific credential fingerprint)

**Policy effects:**
- `allow` - permit immediately
- `deny` - block immediately
- `prompt` - trigger human approval
- `budget` - allow up to N requests/minute, then deny

## Addon Modes

Addons can run in `block` or `warn` mode:

```bash
# View all modes
safeyolo mode

# Set credential-guard to warn-only (for debugging)
safeyolo mode credential-guard warn

# Set back to blocking
safeyolo mode credential-guard block
```

## Requirements

- Python 3.10+
- Docker

## Threat Model

SafeYolo is designed to reduce accidental outbound risk from helpful-but-sloppy (and sometimes persistent) agentic automation, not to defend against a determined adversary running arbitrary code.

**SafeYolo catches:**
- Hallucinated endpoints (wrong host due to lost context: my-app.podhost.example → other-app.podhost.example)
- Runaway agent loops that hammer 3rd party services
- Lookalike domains and Unicode confusables (e.g., Cyrillic 'a' in `аpi.openai.com`)
- Proxy bypass attempts (Sandbox Mode only - they fail rather than leak)

**SafeYolo does NOT:**
- Detect or "solve" prompt injection
- Replace application-layer authentication / authorization
- Prevent non-proxied egress in Try Mode (agents can bypass by going direct)

## Architecture

SafeYolo runs mitmproxy with a chain of addons. See [docs/ADDONS.md](docs/ADDONS.md) for full reference.

| Addon | Purpose | Default |
|-------|---------|---------|
| request_id | Assigns unique ID for correlation | Always on |
| policy_engine | Unified policy evaluation and budgets | Always on |
| access_control | Allow/deny rules for network access | Block |
| rate_limiter | Per-domain rate limiting (via PolicyEngine) | Block |
| circuit_breaker | Fail-fast for unhealthy upstreams | Always on |
| credential_guard | Block credentials to wrong hosts | Block |
| pattern_scanner | Regex scanning for secrets | Warn |
| request_logger | JSONL audit logging | Always on |
| metrics | Per-domain statistics | Always on |
| admin_api | REST API on :9090 | Always on |

## Files

```
safeyolo/
├── addons/              # mitmproxy addons
│   ├── policy_engine.py      # Unified policy evaluation
│   ├── access_control.py     # Network allow/deny rules
│   ├── credential_guard.py   # Credential routing
│   ├── rate_limiter.py       # Rate limiting (via PolicyEngine)
│   ├── circuit_breaker.py
│   ├── pattern_scanner.py
│   ├── admin_api.py
│   └── ...
├── cli/                 # safeyolo CLI package
├── config/              # Default configurations
│   └── baseline.yaml         # Default policy
├── contrib/             # Example integrations
├── tests/               # Test suite
└── docs/                # Additional documentation
```

## Contributing

See [docs/DEVELOPERS.md](docs/DEVELOPERS.md) for architecture and integration guides.

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
