# SafeYolo

**Guardrails for AI coding agents.**

SafeYolo is a security proxy that prevents credential leakage, dampens runaway loops, and provides audit logs for agent HTTP calls. When your AI assistant hallucinates an endpoint, SafeYolo catches the credential before it leaks.

## Quick Start

```bash
# Install CLI
pipx install safeyolo

# Initialize (interactive wizard)
safeyolo init

# Build the container image
docker build -t safeyolo:latest .

# Start proxy
safeyolo start

# Install CA certificate (required for HTTPS inspection)
safeyolo cert install

# Verify everything works
safeyolo check
```

## TLS Certificate Setup

SafeYolo inspects HTTPS traffic to detect credentials in headers. This requires your system to trust SafeYolo's CA certificate.

```bash
# Install CA cert into system trust store (macOS/Linux)
safeyolo cert install

# Verify HTTPS inspection is working
safeyolo check
```

The `cert install` command auto-detects your OS and runs the appropriate commands (requires sudo). Use `--dry-run` to see what it would do first.

`safeyolo check` verifies the full chain:
- ✓ Config and Docker available
- ✓ Container running
- ✓ Admin API responding
- ✓ CA certificate exists
- ✓ Proxy reachable (HTTP)
- ✓ HTTPS inspection working

**Agent in Docker?** Mount the CA cert and update the trust store:

```bash
# In your docker run or compose:
-v ~/.safeyolo/certs/mitmproxy-ca-cert.pem:/usr/local/share/ca-certificates/safeyolo.crt

# Then in the container:
update-ca-certificates
```

## Configuring Your Agent

Set these environment variables for your AI agent:

```bash
# Standard proxy configuration
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
```

**Agent running in Docker?**

```bash
# macOS / Windows (Docker Desktop)
export HTTP_PROXY=http://host.docker.internal:8080
export HTTPS_PROXY=http://host.docker.internal:8080

# Linux (add host alias)
docker run --add-host=host.docker.internal:host-gateway ...
export HTTP_PROXY=http://host.docker.internal:8080
export HTTPS_PROXY=http://host.docker.internal:8080
```

Then start watching for approval requests:

```bash
safeyolo watch
```

## What It Does

**Credential routing** - API keys only reach authorized hosts. An OpenAI key to `api.openai.com.attacker.io` (exfil attempt) gets blocked with a helpful error message.

**Smart detection** - Pattern matching for known providers (OpenAI, Anthropic, GitHub, etc.) plus entropy analysis catches unknown secrets.

**Human-in-the-loop** - Unknown credentials trigger approval prompts. Approve once, and it's remembered.

**Rate limiting** - Per-domain limits prevent runaway loops from blacklisting your IP.

**Audit trail** - Every request logged to JSONL with decision reasons and request correlation.

**What gets logged:**
- Method, host, path, status code, decision, rule ID, request ID
- Credential fingerprints (HMAC hash, never raw secrets)
- Body logging off by default (opt-in for debugging)

## CLI Commands

| Command | Description |
|---------|-------------|
| `safeyolo init` | Interactive setup wizard |
| `safeyolo start` | Start the proxy container |
| `safeyolo stop` | Stop the proxy |
| `safeyolo status` | Show health and stats |
| `safeyolo cert install` | Install CA cert for HTTPS inspection |
| `safeyolo cert show` | Show CA cert location and status |
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
│  │  safeyolo CLI  │       │  ./safeyolo/                  │ │
│  │                │       │    config.yaml                │ │
│  │  init, start,  │◄─────►│    rules.json                 │ │
│  │  watch, logs   │       │    policies/                  │ │
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
│  │  │ credential_guard.py (~750 lines)                 │ │  │
│  │  │ - Detect credentials (patterns + entropy)        │ │  │
│  │  │ - Validate destinations (allowed hosts)          │ │  │
│  │  │ - Emit events to JSONL (CLI picks them up)       │ │  │
│  │  │ - Return 428 for blocks (agent gets feedback)    │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                       │  │
│  │  + rate_limiter, circuit_breaker, pattern_scanner,    │  │
│  │    request_logger, metrics, admin_api                 │  │
│  │                                                       │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │                                 │
│                           │ :8080 (proxy)                   │
│                           ▼                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  AI Coding Agent (Claude Code, etc.)                  │  │
│  │  HTTP_PROXY=http://localhost:8080                     │  │
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

*Why 428?* SafeYolo uses HTTP 428 (Precondition Required) to signal "needs approval" rather than permanent denial. This lets agents retry after approval, and distinguishes SafeYolo blocks from upstream 403s.

```bash
$ safeyolo watch

Watching: ./safeyolo/logs/safeyolo.jsonl

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

Configuration lives in `./safeyolo/` (project) or `~/.safeyolo/` (global).

```
safeyolo/
├── config.yaml          # Proxy settings
├── rules.json           # Credential patterns & allowed hosts
├── policies/            # Approved credentials (auto-managed)
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

## Testing

Test that requests go through the proxy:

```bash
# Test with a fake credential
safeyolo test -H "Authorization: Bearer sk-test123..." https://api.openai.com/v1/models

# Should show: 428 (blocked - destination mismatch or requires approval)
```

## Requirements

- Python 3.10+
- Docker

## Threat Model

**SafeYolo catches:**
- Hallucinated endpoints (`api.openai.com.attacker.io` instead of `api.openai.com`)
- Credentials sent to wrong hosts
- Runaway API loops
- Typosquats and homograph attacks (е.g., Cyrillic 'а' in `аpi.openai.com`)

**SafeYolo does NOT:**
- Detect prompt injection
- Replace application-layer auth
- Stop attacks that bypass the proxy

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
│   ├── credential_guard.py   # Core security (~750 lines)
│   ├── rate_limiter.py
│   ├── circuit_breaker.py
│   ├── pattern_scanner.py
│   ├── admin_api.py
│   └── ...
├── cli/                 # safeyolo CLI package
├── config/              # Default configurations
├── contrib/             # Example integrations (notifications, etc.)
├── tests/               # Test suite
└── docs/                # Additional documentation
```

## Contributing

See [docs/DEVELOPERS.md](docs/DEVELOPERS.md) for architecture and integration guides.

Example integrations live in [contrib/](contrib/) - use these as templates for your own.

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
