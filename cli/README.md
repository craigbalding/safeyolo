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

**Aliases:** `safeyolo up` (start with `--pull` and `--wait` only), `safeyolo down` = `stop`

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
| `safeyolo watch` | Monitor logs and handle credential + risky route approval requests interactively |
| `safeyolo watch --log-only` | Display events without prompts |
| `safeyolo watch --tmux` | Optimized for tmux status bar integration |
| `safeyolo policies` | List approval policies |
| `safeyolo policies <project>` | Show policy details |

Watch handles both credential routing approvals and risky route grant approvals. On startup, it scans for pending approvals so nothing is missed. Route-based dedup prevents repeated prompts for the same route. Denied requests get a second-chance prompt before final rejection.

### Configuration

| Command | Description |
|---------|-------------|
| `safeyolo mode` | Show all addon modes |
| `safeyolo mode <addon>` | Show mode for specific addon |
| `safeyolo mode <addon> <warn\|block>` | Set addon mode |

### Agent Management (Sandbox Mode)

Sandbox Mode runs AI agents in isolated sandboxes (Apple VZ microVMs on macOS, rootless gVisor on Linux) with all traffic routed through SafeYolo.

| Command | Description |
|---------|-------------|
| `safeyolo agent add <name> <folder> [--host-script PATH]` | Add an agent and run it |
| `safeyolo agent run <name> [-f folder] [-- cmd args…]` | Run an existing agent |
| `safeyolo agent stop <name>` | Stop a running agent |
| `safeyolo agent list` | List configured agents |
| `safeyolo agent shell <name>` | Open shell in running agent |
| `safeyolo agent config <name>` | View or update agent configuration |
| `safeyolo agent remove <name>` | Remove an agent |

**Quick start:**

```bash
# Initialize (sandbox mode is the default)
safeyolo init

# Add and run a Claude Code agent using the bundled host script
safeyolo agent add myproject ~/code --host-script contrib/claude-host-setup.sh

# Later, just run by name
safeyolo agent run myproject

# Or run with a different folder
safeyolo agent run myproject -f ~/other-project

# Override the default command (the host script's .safeyolo-entrypoint)
safeyolo agent run myproject -- bash -l

# Yolo mode is on by default (auto-accepts permission prompts where supported)
safeyolo agent run myproject

# Disable yolo mode
safeyolo agent run myproject --no-yolo
```

**Host scripts** configure what the agent is. Ready-made examples in `contrib/`:
- `contrib/claude-host-setup.sh` — Claude Code (stages host auth/extensions, install-on-first-run entrypoint)
- `contrib/codex-host-setup.sh` — OpenAI Codex CLI
- `contrib/mise-shell-host-setup.sh` — BYOA interactive shell with mise
- See `contrib/HOST_SCRIPT_GUIDE.md` to write your own.

**Notes:**
- Agent names must be lowercase alphanumeric with hyphens (hostname rules)
- `add` is idempotent: running it twice with the same folder + script just runs the existing agent
- Use `--no-run` with `add` to create config without running
- Without `--host-script`, the sandbox boots to a plain bash shell

### Service Gateway

Authorize agents to access external services through the gateway. Services are defined in YAML under `services/` and describe a host, available capabilities, risky routes (with ATT&CK tactics), and auth configuration.

| Command | Description |
|---------|-------------|
| `safeyolo agent authorize <agent> <service>` | Authorize an agent to use a service (with `--capability`) |
| `safeyolo agent revoke <agent> <service>` | Revoke service access for an agent |
| `safeyolo services list` | List available service definitions |
| `safeyolo services show <name>` | Show service details (host, capabilities, risky routes) |

**Example flow:**

```bash
# List available services
safeyolo services list

# Authorize the agent to use the github service with a specific capability
safeyolo agent authorize myproject github --capability create_pr

# Verify the policy was updated
safeyolo policy show --section hosts

# Revoke access when no longer needed
safeyolo agent revoke myproject github
```

### Vault Management

Store and manage credentials used by service gateway integrations.

| Command | Description |
|---------|-------------|
| `safeyolo vault add <name>` | Store a credential (value prompted securely) |
| `safeyolo vault list` | List stored credentials (never shows values) |
| `safeyolo vault remove <name>` | Remove a credential |
| `safeyolo vault oauth2 <name> --provider google ...` | Run OAuth2 browser consent flow |

```bash
# Add a credential
safeyolo vault add github-token

# List stored credentials
safeyolo vault list

# Remove a credential
safeyolo vault remove github-token

# OAuth2 flow (opens browser for consent)
safeyolo vault oauth2 google-creds --provider google --client-id <id> --client-secret <secret> --scope gmail.readonly
```

**Note:** The vault is encrypted at rest. An encryption key is auto-generated at `~/.safeyolo/data/vault.key` on first use.

### Policy Inspection

Inspect the merged policy that the proxy enforces at runtime.

| Command | Description |
|---------|-------------|
| `safeyolo policy show` | Show merged policy (policy.toml + addons.yaml) |
| `safeyolo policy show --compiled` | Show compiled IAM format |
| `safeyolo policy show --section hosts` | Filter output to one section |

```bash
# View full merged policy
safeyolo policy show

# View only the hosts section
safeyolo policy show --section hosts

# View compiled IAM representation
safeyolo policy show --compiled
```

### Policy Management

Manage hosts, egress posture, and named lists in policy.toml.

**Host rules:**

| Command | Description |
|---------|-------------|
| `safeyolo policy host add <host> [options]` | Add a host rule |
| `safeyolo policy host remove <host>` | Remove a host rule |
| `safeyolo policy host deny <host>` | Deny all traffic to a host |
| `safeyolo policy host list` | List all host rules |
| `safeyolo policy host bypass <host>` | Bypass proxy for a host (no MITM) |
| `safeyolo policy host add-list <host> --list <name>` | Add a host from a named list |

**Egress posture:**

| Command | Description |
|---------|-------------|
| `safeyolo policy egress set <posture>` | Set egress posture (allow, prompt, deny) |
| `safeyolo policy egress show` | Show current egress posture |

**Named lists:**

| Command | Description |
|---------|-------------|
| `safeyolo policy list add <name> <host>` | Add a host to a named list |
| `safeyolo policy list remove <name> <host>` | Remove a host from a named list |
| `safeyolo policy list show <name>` | Show hosts in a named list |

### Token Management

Manage the readonly agent API token for agent self-service diagnostics. Only one token exists at a time. Token survives proxy restarts and expires after the TTL (default: 1h).

| Command | Description |
|---------|-------------|
| `safeyolo token create` | Create an agent API token (replaces any existing) |
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
├── policy.toml          # Host-centric policy (hosts, credentials, rate limits)
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── docker-compose.yml   # Generated compose file
├── services/            # User service definitions (one YAML per service)
├── logs/                # Audit logs (safeyolo.jsonl)
├── certs/               # mitmproxy CA certificate
├── policies/            # Approved credentials
└── data/                # Runtime data (admin token, HMAC secret, agent API tokens)
    ├── vault.yaml.enc   # Encrypted credential vault
    └── vault.key        # Vault encryption key (auto-generated)
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

### policy.toml

Host-centric policy defining hosts, credentials, and rate limits:

```toml
version = "2.0"
budget = 12_000
# egress posture is set on the wildcard [hosts] entry, not at top level

required = ["credential_guard", "network_guard", "circuit_breaker"]

[hosts]
"api.openai.com"    = { allow = ["openai:*"],    rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"],  rate = 3_000 }
"*"                 = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]
```

### addons.yaml

Addon tuning lives in a separate file, sibling to `policy.toml`:

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
