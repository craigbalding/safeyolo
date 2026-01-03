# SafeYolo

**Guardrails for AI coding agents.**

SafeYolo is a security proxy that prevents credential leakage, dampens runaway loops, and provides audit logs for agent HTTP calls. When your AI assistant hallucinates an endpoint, SafeYolo catches the credential before it leaks.

## Quick Start

```bash
# Install CLI
pipx install safeyolo

# Start proxy (auto-configures on first run)
safeyolo start

# Set up CA trust and proxy for your shell
eval $(safeyolo cert env)

# Run your agent
claude
```

That's it. SafeYolo is now inspecting all HTTPS traffic from your shell session.

## Deployment Modes

| Mode | Enforcement | Use case |
|------|-------------|----------|
| **Quick Mode** (default) | Per-process - agents can bypass | Fast setup, interactive use |
| **Secure Mode** | Enforced - bypass attempts fail | Production use with autonomous agents |

### Quick Mode (Default)

Quick Mode uses per-process environment variables to route traffic through SafeYolo. It's the fastest way to get started:

```bash
safeyolo start
eval $(safeyolo cert env)
# Your agent now goes through SafeYolo
```

**Limitation:** Autonomous agents could bypass by unsetting proxy variables or opening direct sockets.

### Secure Mode (Enforced)

For autonomous agents that might try to bypass the proxy, Secure Mode runs your agent in a container with no direct internet access:

```bash
# Generate agent container template
safeyolo secure setup

# Run agent in isolated container
cd claude-code
docker compose run --rm claudecode
```

The agent container connects to an internal Docker network where SafeYolo is the only route to the internet. Bypass attempts fail rather than leak.

See `safeyolo secure list` for available agent templates.

## What It Does

**Credential routing** - API keys only reach authorized hosts. An OpenAI key to `api.openai.com.attacker.io` (exfil attempt) gets blocked with HTTP 428 + JSON payload (machine-readable, agent can retry after approval).

**Smart detection** - Pattern matching for known providers (OpenAI, Anthropic, GitHub, etc.) plus entropy analysis may catch unknown secrets.

**Human-in-the-loop** - Unknown credentials trigger approval prompts. Approve once, and it's remembered.

**Rate limiting** - Per-domain limits prevent runaway loops from blacklisting your IP.

**Audit trail** - Every request logged to JSONL with decision reasons and request correlation.

## CLI Commands

| Command | Description |
|---------|-------------|
| `safeyolo start` | Start the proxy container (auto-configures on first run) |
| `safeyolo stop` | Stop the proxy |
| `safeyolo status` | Show health and stats |
| `safeyolo cert env` | Print CA trust and proxy environment variables |
| `safeyolo cert show` | Show CA cert location and fingerprint |
| `safeyolo secure setup` | Generate agent container template (Secure Mode) |
| `safeyolo secure list` | List available agent templates |
| `safeyolo init` | Setup wizard (for customization) |
| `safeyolo check` | Verify setup, proxy, and HTTPS working |
| `safeyolo watch` | Monitor and approve credentials |
| `safeyolo logs -f` | Follow logs in real-time |
| `safeyolo mode` | View/change addon modes |
| `safeyolo test` | Test request through proxy |

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Machine                           │
│                                                             │
│  ┌────────────────┐       ┌───────────────────────────────┐ │
│  │  safeyolo CLI  │       │  ~/.safeyolo/                 │ │
│  │                │       │    config.yaml                │ │
│  │  start, watch, │◄─────►│    rules.json                 │ │
│  │  cert env      │       │    policies/                  │ │
│  └───────┬────────┘       │    logs/safeyolo.jsonl        │ │
│          │                └───────────────────────────────┘ │
│          │                                                  │
│          │ Manages container, tails logs                    │
│          ▼                                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              SafeYolo Container                       │  │
│  │                                                       │  │
│  │  mitmproxy + addons:                                  │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │ credential_guard.py                              │ │  │
│  │  │ - Detect credentials (patterns + entropy)        │ │  │
│  │  │ - Validate destinations (allowed hosts)          │ │  │
│  │  │ - Return 428 for blocks (agent gets feedback)    │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                       │  │
│  │  + rate_limiter, circuit_breaker, pattern_scanner,    │  │
│  │    request_logger, metrics, admin_api                 │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │                                 │
│                           │ :8080 (proxy)                   │
│                           ▼                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  AI Coding Agent (Claude Code, etc.)                  │  │
│  │  via eval $(safeyolo cert env)                        │  │
│  └───────────────────────────────────────────────────────┘  │
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
├── rules.json           # Credential patterns & allowed hosts
├── policies/            # Approved credentials (auto-managed)
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
└── data/                # Admin token, HMAC secret
```

### rules.json

Define credential patterns and their allowed destinations:

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

**SafeYolo catches:**
- Hallucinated endpoints (`api.openai.com.attacker.io` instead of `api.openai.com`)
- Credentials sent to wrong hosts
- Runaway API loops
- Typosquats and homograph attacks (e.g., Cyrillic 'a' in `аpi.openai.com`)
- Proxy bypass attempts (Secure Mode only - they fail instead of leak)

**SafeYolo does NOT:**
- Detect prompt injection
- Replace application-layer auth
- Prevent non-proxied egress in Quick Mode (agents can bypass by going direct)

## Architecture

SafeYolo runs mitmproxy with a chain of addons. See [docs/ADDONS.md](docs/ADDONS.md) for full reference.

| Addon | Purpose | Default |
|-------|---------|---------|
| request_id | Assigns unique ID for correlation | Always on |
| rate_limiter | Per-domain rate limiting | Block |
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
│   ├── credential_guard.py   # Core security
│   ├── rate_limiter.py
│   ├── circuit_breaker.py
│   ├── pattern_scanner.py
│   ├── admin_api.py
│   └── ...
├── cli/                 # safeyolo CLI package
├── config/              # Default configurations
├── contrib/             # Example integrations
├── tests/               # Test suite
└── docs/                # Additional documentation
```

## Contributing

See [docs/DEVELOPERS.md](docs/DEVELOPERS.md) for architecture and integration guides.

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
