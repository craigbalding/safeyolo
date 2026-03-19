# SafeYolo CLI

Command-line interface for managing the SafeYolo security proxy.

## Installation

```bash
# From source (PyPI package coming soon)
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo/cli && uv tool install -e .
```

## Quick Start

```bash
# Initialize configuration (interactive wizard)
safeyolo init

# Start the proxy
safeyolo start

# Watch for credential approval requests
safeyolo watch

# Check status
safeyolo status

# Diagnose problems
safeyolo doctor
```

## Commands

### Setup & Lifecycle

| Command | Description |
|---------|-------------|
| `safeyolo init` | Initialize configuration with interactive wizard |
| `safeyolo start` | Start the proxy container |
| `safeyolo stop` | Stop the proxy container |
| `safeyolo status` | Show proxy status, addon stats, and memory usage |
| `safeyolo build` | Build SafeYolo Docker image from source |
| `safeyolo check` | Verify setup is working correctly |
| `safeyolo doctor` | Run 11-check diagnostic cascade (config, Docker, proxy, addons) |
| `safeyolo demo` | Guided tour of SafeYolo security features |

**Aliases:** `safeyolo up` = `start`, `safeyolo down` = `stop`

**Start options:**

```bash
safeyolo start              # Normal start
safeyolo start --dev        # Dev mode: mount addons/ and pdp/ from local repo
safeyolo start --build      # Rebuild image before starting
safeyolo start --headless   # Force headless mode (no TUI)
safeyolo start --pull       # Pull latest image before starting
```

**Doctor options:**

```bash
safeyolo doctor             # Run all checks, stop at first failure
safeyolo doctor --verbose   # Show details for passing checks too
safeyolo doctor --json      # Output results as JSON
safeyolo doctor --fix       # Attempt to fix problems automatically
```

### Monitoring & Logs

| Command | Description |
|---------|-------------|
| `safeyolo logs` | View formatted logs |
| `safeyolo logs -f` | Follow logs in real-time |
| `safeyolo logs --security` | Show only security events |
| `safeyolo logs --raw` | Output raw JSONL |

### Approval Workflow

| Command | Description |
|---------|-------------|
| `safeyolo watch` | Monitor logs and handle approval requests interactively |
| `safeyolo watch --log-only` | Display events without prompts |
| `safeyolo watch --tmux` | Optimized for tmux status bar integration |
| `safeyolo policies` | List approval policies |
| `safeyolo policies <project>` | Show policy details |

### Configuration

| Command | Description |
|---------|-------------|
| `safeyolo mode` | Show all addon modes |
| `safeyolo mode <addon>` | Show mode for specific addon |
| `safeyolo mode <addon> <warn\|block>` | Set addon mode |

### Agent Management (Sandbox Mode)

Sandbox Mode runs AI agents in isolated Docker containers with all traffic routed through SafeYolo.

| Command | Description |
|---------|-------------|
| `safeyolo agent add <name> <template> <folder>` | Add an agent and run it |
| `safeyolo agent run <name> [folder]` | Run an existing agent |
| `safeyolo agent list` | List templates and configured agents |
| `safeyolo agent shell <name>` | Open shell in running agent |
| `safeyolo agent config <name>` | View or update agent configuration |
| `safeyolo agent help <name>` | Show agent CLI help (runs `--help` inside container) |
| `safeyolo agent remove <name>` | Remove an agent |

**Quick start:**

```bash
# Initialize (sandbox mode is the default)
safeyolo init

# Add and run a Claude Code agent
safeyolo agent add myproject claude-code ~/code

# Later, just run by name
safeyolo agent run myproject

# Or run with a different folder
safeyolo agent run myproject ~/other-project

# Run with passthrough args to the agent CLI
safeyolo agent run myproject -- --verbose

# Yolo mode is on by default (auto-accepts permission prompts)
safeyolo agent run myproject

# Disable yolo mode (requires manual approval of prompts)
safeyolo agent run myproject --no-yolo

# Fresh session (new container, no state from previous runs)
safeyolo agent run myproject --fresh
```

**Available templates:**
- `claude-code` - Anthropic's Claude Code CLI
- `openai-codex` - OpenAI Codex CLI

**Notes:**
- Agent names must be lowercase alphanumeric with hyphens (hostname rules)
- `add` is idempotent: running it twice just runs the existing agent
- Use `--no-run` with `add` to create config without running
- Use `--ephemeral` with `add` for throwaway containers

### Token Management

Manage the readonly relay token for agent self-service diagnostics. Only one token exists at a time. Token survives proxy restarts and expires after the TTL (default: 1h).

| Command | Description |
|---------|-------------|
| `safeyolo token create` | Create a relay token (replaces any existing) |
| `safeyolo token show` | Show current token status and expiry |
| `safeyolo token revoke` | Delete the active token |

```bash
# Create a token (default: 1h TTL)
safeyolo token create

# Create a token with custom TTL
safeyolo token create --ttl 4h
safeyolo token create --ttl 30m

# Check token status
safeyolo token show

# Revoke (delete) the token
safeyolo token revoke
```

### Certificate Management

| Command | Description |
|---------|-------------|
| `safeyolo cert env` | Print env vars for CA trust and proxy config |
| `safeyolo cert show` | Show CA certificate location and status |

```bash
# Configure shell for proxy CA trust (useful for pip, curl, etc.)
eval $(safeyolo cert env)
```

### Tmux Integration

| Command | Description |
|---------|-------------|
| `safeyolo tmux setup` | Configure current tmux session for SafeYolo status line |
| `safeyolo tmux config` | Output tmux config snippet |
| `safeyolo tmux config --write` | Write config to `~/.config/tmux/safeyolo.conf` |
| `safeyolo tmux status` | Show current SafeYolo status (for status bar scripts) |

### Setup & Prerequisites

| Command | Description |
|---------|-------------|
| `safeyolo setup check` | Check system prerequisites (Docker group, network) |

## Configuration

Configuration is stored in `./safeyolo/` (project-specific) or `~/.safeyolo/` (global).

```
safeyolo/
├── config.yaml          # Main configuration
├── policy.yaml          # Host-centric policy (hosts, credentials, rate limits)
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── docker-compose.yml   # Generated compose file
├── logs/                # Audit logs (safeyolo.jsonl)
├── certs/               # mitmproxy CA certificate
├── policies/            # Approved credentials
└── data/                # Runtime data (admin token, HMAC secret, relay tokens)
```

### config.yaml

```yaml
version: 1
proxy:
  port: 8080           # Proxy port for agents
  admin_port: 9090     # Admin API port
  image: safeyolo:latest
  container_name: safeyolo
modes:
  credential_guard: block
  network_guard: block
  pattern_scanner: warn
  test_context: block
```

### policy.yaml

Host-centric policy defining hosts, credentials, and rate limits:

```yaml
hosts:
  api.openai.com:      { credentials: [openai:*],    rate_limit: 3000 }
  api.anthropic.com:   { credentials: [anthropic:*],  rate_limit: 3000 }
  "*":                 { unknown_credentials: prompt,  rate_limit: 600 }

global_budget: 12000

credentials:
  openai:
    patterns: ["sk-proj-[a-zA-Z0-9_-]{80,}"]
    headers: [authorization, x-api-key]

required: [credential_guard, network_guard, circuit_breaker]
```

### addons.yaml

Addon tuning lives in a separate file, sibling to `policy.yaml`:

```yaml
addons:
  credential_guard:
    enabled: true
    detection_level: standard
    entropy: { min_length: 20, min_charset_diversity: 0.5, min_shannon_entropy: 3.5 }
  circuit_breaker:
    enabled: true
    failure_threshold: 5
```

## Workflow

1. **Initialize** - Run `safeyolo init` to create configuration
2. **Start** - Run `safeyolo start` to launch the proxy container
3. **Configure agent** - Point your AI coding agent at `http://localhost:8080`
4. **Watch** - Run `safeyolo watch` to handle credential approval requests
5. **Monitor** - Use `safeyolo logs -f` to watch activity

When a credential is blocked:
- The proxy returns HTTP 428 with details
- The event appears in `safeyolo watch`
- You approve or deny interactively
- Approved credentials are added to the policy file
- Subsequent requests pass through

## Requirements

- Python 3.10+
- Docker

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFEYOLO_ADMIN_TOKEN` | Admin API authentication token |
| `SAFEYOLO_CONFIG_DIR` | Override config directory location |
| `SAFEYOLO_TUI` | Set to `true` for mitmproxy TUI mode (default: headless) |
| `SAFEYOLO_BLOCK` | Set to `true` to enable blocking for all security addons |

## License

MIT
