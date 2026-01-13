# SafeYolo CLI

Command-line interface for managing the SafeYolo security proxy.

## Installation

```bash
# Recommended: pipx (isolated environment)
pipx install safeyolo

# Alternative: pip
pip install safeyolo
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
```

## Commands

### Setup & Lifecycle

| Command | Description |
|---------|-------------|
| `safeyolo init` | Initialize configuration with interactive wizard |
| `safeyolo start` | Start the proxy container |
| `safeyolo stop` | Stop the proxy container |
| `safeyolo status` | Show proxy status and statistics |
| `safeyolo check` | Verify setup is working correctly |

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
| `safeyolo agent remove <name>` | Remove an agent |

**Quick start:**

```bash
# Initialize with sandbox mode
safeyolo init --sandbox

# Add and run a Claude Code agent
safeyolo agent add myproject claude-code ~/code

# Later, just run by name
safeyolo agent run myproject

# Or run with a different folder
safeyolo agent run myproject ~/other-project
```

**Available templates:**
- `claude-code` - Anthropic's Claude Code CLI
- `openai-codex` - OpenAI Codex CLI

**Notes:**
- Agent names must be lowercase alphanumeric with hyphens (hostname rules)
- `add` is idempotent: running it twice just runs the existing agent
- Use `--no-run` with `add` to create config without running

## Configuration

Configuration is stored in `./safeyolo/` (project-specific) or `~/.safeyolo/` (global).

```
safeyolo/
├── config.yaml          # Main configuration
├── rules.json           # Credential patterns
├── docker-compose.yml   # Generated compose file
├── logs/                # Audit logs (safeyolo.jsonl)
├── certs/               # mitmproxy CA certificate
├── policies/            # Approved credentials
└── data/                # Runtime data (admin token, HMAC secret)
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
  rate_limiter: block
  pattern_scanner: warn
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

## License

MIT
