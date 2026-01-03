# SafeYolo CLI Design Document

## Overview

SafeYolo CLI is a host-side command-line tool that provides a friendly interface for managing the SafeYolo security proxy. It replaces manual docker-compose workflows and extracts complex features (approval workflow, notifications) from the mitmproxy addon into a separate, auditable process.

## Goals

1. **Easy onboarding** - Single command to get started
2. **Auditable proxy** - Slim credential_guard.py (~200 lines) that security engineers can quickly review
3. **Extensible integrations** - Event-driven architecture; users can build their own tooling
4. **Separation of concerns** - Proxy detects and decides; CLI reacts and manages

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Host Machine                            │
│                                                              │
│  ┌────────────────┐       ┌──────────────────────────────┐  │
│  │  safeyolo CLI  │◄─────►│  ~/.safeyolo/ (or ./safeyolo)│  │
│  │                │       │    config.yaml                │  │
│  │  Commands:     │       │    rules.json                 │  │
│  │  - init        │       │    policies/                  │  │
│  │  - start/stop  │       │    logs/                      │  │
│  │  - watch       │       └──────────────────────────────┘  │
│  │  - approve     │                                         │
│  │  - logs        │                                         │
│  └───────┬────────┘                                         │
│          │                                                  │
│          │  Admin API (HTTP :9090)                          │
│          │  Log volume (tail JSONL)                         │
│          ▼                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              safeyolo container                       │  │
│  │                                                       │  │
│  │  mitmproxy + addons:                                  │  │
│  │  ┌─────────────────────────────────────────────────┐ │  │
│  │  │ credential_guard.py (slim ~200 lines)           │ │  │
│  │  │ - Detect credentials (patterns + entropy)       │ │  │
│  │  │ - Validate destinations (allowed hosts)         │ │  │
│  │  │ - Decide (allow/block/greylist)                 │ │  │
│  │  │ - Emit structured events to JSONL               │ │  │
│  │  │ - Return 428 for greylist (no notification)     │ │  │
│  │  └─────────────────────────────────────────────────┘ │  │
│  │                                                       │  │
│  │  Mounted volumes:                                     │  │
│  │  - /config (rules.json, policy.yaml)                  │  │
│  │  - /logs (safeyolo.jsonl)                             │  │
│  │  - /certs (mitmproxy CA)                              │  │
│  │  - /data (hmac_secret, policies/)                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│          │                                                   │
│          │ Proxy traffic (:8080)                             │
│          ▼                                                   │
│  ┌──────────────────┐                                       │
│  │ Claude Code      │                                       │
│  │ (or other agent) │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

## CLI Commands

### Setup & Lifecycle

```bash
safeyolo init [--dir PATH]
```
Interactive setup wizard:
- Select API providers (OpenAI, Anthropic, etc.)
- Configure notification method (ntfy, macOS, none)
- Generate config files and docker-compose.yml
- Create credential rules from templates

```bash
safeyolo start [--detach]
```
Start the proxy container:
- Validate config before starting
- Pull latest image if needed
- Start container with correct volume mounts
- Wait for health check
- Display connection instructions

```bash
safeyolo stop
```
Stop the proxy container gracefully.

```bash
safeyolo status
```
Show current state:
- Container health
- Proxy stats summary (requests, blocks, rate limits)
- Pending approvals count
- Active mode (warn/block per addon)

### Approval Workflow

```bash
safeyolo watch [--notify METHOD] [--auto-deny DURATION]
```
Tail logs and handle approval requests:
- Interactive TUI mode (default): show prompts, accept keyboard input
- `--notify ntfy`: send to ntfy topic, wait for callback
- `--notify macos`: use macOS Notification Center with actions
- `--notify webhook:URL`: POST to custom endpoint
- `--auto-deny 5m`: automatically deny after timeout

```bash
safeyolo pending
```
List pending approval requests with details.

```bash
safeyolo approve <token>
```
Approve a credential for its requested destination.

```bash
safeyolo deny <token>
```
Deny a credential request.

### Logs & Monitoring

```bash
safeyolo logs [OPTIONS]
```
Tail formatted logs:
- `--raw`: output raw JSONL
- `--security`: filter to security.* events
- `--request-id ID`: filter to specific request
- `--follow` (default): continuous tail
- `--since DURATION`: start from time offset

```bash
safeyolo stats [--json]
```
Show detailed metrics from all addons.

### Configuration

```bash
safeyolo mode <addon> <warn|block>
```
Set addon mode at runtime.

```bash
safeyolo rules [--edit]
```
Show or edit credential rules.

```bash
safeyolo allow <pattern> <host> [--ttl DURATION]
```
Add credential pattern to allowlist.

### Testing & Debugging

```bash
safeyolo test <url>
```
Make a test request through the proxy and show what would happen.

```bash
safeyolo check
```
Verify proxy is working:
- Container running
- Ports accessible
- CA cert valid
- Test request succeeds

## Event-Driven Approval Flow

### Current State (in-addon)

The credential_guard.py addon currently:
1. Detects credential in request
2. Determines if approval needed
3. Stores pending approval in memory
4. Sends notification via Pushcut/ntfy
5. Waits for callback or timeout
6. Manages policy file updates

This is ~800+ lines with multiple concerns mixed together.

### Proposed State (event-driven)

**credential_guard.py (~200 lines):**
1. Detect credential in request
2. Check against mounted policy files
3. Decide: allow, block, or greylist
4. Emit structured event to JSONL
5. Return appropriate response (200 passthrough, 403 block, 428 greylist)

**safeyolo watch (separate process):**
1. Tail safeyolo.jsonl
2. Filter for `security.credential` events with `decision: greylist`
3. Send notification via configured method
4. On approval callback: `POST /admin/approve/{token}`
5. On deny callback: `POST /admin/deny/{token}`
6. Manage timeouts and retries

### Event Format

```jsonl
{
  "ts": "2025-01-03T14:30:00Z",
  "event": "security.credential",
  "request_id": "req-abc123",
  "decision": "greylist",
  "greylist_type": "requires_approval",
  "credential_type": "unknown_secret",
  "token_hmac": "abc123def456...",
  "host": "api.example.com",
  "path": "/v1/chat",
  "project_id": "webapp",
  "tier": 2,
  "confidence": "medium"
}
```

The `token_hmac` serves as the approval token - it's deterministic for the same credential, so retries get the same token.

### Benefits

1. **Auditable**: Security engineers can review 200 lines of detection logic
2. **Testable**: Core logic has no I/O dependencies beyond logging
3. **Flexible**: Users can build custom approval flows
4. **Resilient**: Notification failures don't affect proxy operation
5. **Optional**: Don't want approvals? Don't run `safeyolo watch`

## Configuration

### Directory Structure

```
~/.safeyolo/                    # Global config (fallback)
./safeyolo/                     # Project-specific (preferred)
├── config.yaml                 # Main configuration
├── rules.json                  # Credential patterns + allowed hosts
├── policies/                   # Approved credentials per project
│   ├── default.yaml
│   └── {project}.yaml
├── logs/                       # JSONL audit logs
│   └── safeyolo.jsonl
└── certs/                      # mitmproxy CA certificate
    └── mitmproxy-ca-cert.pem
```

### config.yaml

```yaml
# SafeYolo configuration
version: 1

proxy:
  port: 8080
  admin_port: 9090
  image: ghcr.io/craigbalding/safeyolo:latest

modes:
  credential_guard: block    # block | warn
  rate_limiter: block        # block | warn
  pattern_scanner: warn      # block | warn

notifications:
  method: ntfy               # ntfy | macos | webhook | none
  ntfy:
    topic: auto              # 'auto' generates secure topic
    server: https://ntfy.sh
  webhook:
    url: null
    secret: null

approval:
  auto_deny_after: null      # e.g., "5m" - null means wait forever
  require_for:
    - unknown_secrets        # Tier 2 entropy-detected secrets
    - destination_mismatch   # Known credential, wrong host
```

### rules.json

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
  ],
  "entropy_detection": {
    "enabled": true,
    "min_length": 20,
    "min_entropy": 3.5
  }
}
```

## Distribution

### Installation

```bash
# Recommended: pipx (isolated environment)
pipx install safeyolo

# Alternative: pip
pip install --user safeyolo

# From source
pipx install git+https://github.com/craigbalding/safeyolo-cli
```

### Package Structure

```
safeyolo-cli/
├── pyproject.toml
├── README.md
├── src/
│   └── safeyolo/
│       ├── __init__.py
│       ├── cli.py              # Typer app entrypoint
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── init.py         # Setup wizard
│       │   ├── lifecycle.py    # start, stop, status
│       │   ├── watch.py        # Approval daemon
│       │   ├── logs.py         # Log tailing
│       │   └── admin.py        # approve, deny, mode, stats
│       ├── config.py           # Config loading/validation
│       ├── api.py              # Admin API client
│       ├── docker.py           # Container management
│       └── notify/
│           ├── __init__.py
│           ├── ntfy.py
│           ├── macos.py
│           └── webhook.py
└── tests/
```

### Dependencies

```toml
[project]
dependencies = [
    "typer>=0.9.0",           # CLI framework
    "httpx>=0.25.0",          # HTTP client (admin API)
    "pyyaml>=6.0",            # Config parsing
    "rich>=13.0",             # Terminal formatting
    "watchfiles>=0.20.0",     # Log tailing
]

[project.optional-dependencies]
docker = ["docker>=6.0.0"]    # Direct Docker management (vs docker-compose)
```

## Security Considerations

1. **Admin API authentication**: CLI reads token from `~/.safeyolo/admin_token` or env var
2. **Secure topic generation**: ntfy topics are cryptographically random
3. **No credentials in config**: Rules contain patterns, not actual secrets
4. **HMAC fingerprints**: Credentials never stored or logged in raw form
5. **Policy file permissions**: CLI warns if policy files are world-readable

## Migration Path

### For Existing Users

1. Install CLI: `pipx install safeyolo`
2. Run migration: `safeyolo migrate` (reads existing docker-compose config)
3. Optionally enable new features (`safeyolo watch`)

### For New Users

1. Install CLI: `pipx install safeyolo`
2. Run setup: `safeyolo init`
3. Start proxy: `safeyolo start`
4. Configure agent: point at `localhost:8080`

## Future Considerations

- **Multi-proxy management**: Named proxy instances for different projects
- **Remote management**: Connect to proxy on remote host
- **Plugin system**: Custom notification backends, custom rules
- **TUI dashboard**: Rich terminal UI showing live stats
- **Config sync**: Sync config across machines (git-based or cloud)
