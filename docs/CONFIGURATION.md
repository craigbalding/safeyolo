# Configuration

SafeYolo configuration lives in `~/.safeyolo/` (global) or `./safeyolo/` (project-specific).

## Directory Structure

```
~/.safeyolo/
├── config.yaml          # Proxy settings
├── policy.yaml          # Policy: hosts, credentials, rate limits
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
├── policies/            # Per-project approval policies
├── agents/              # Agent container configurations
└── data/                # Admin token, HMAC secret, relay tokens
```

## config.yaml

Main proxy configuration:

```yaml
version: 1
proxy:
  port: 8080           # Proxy port for agents
  admin_port: 9090     # Admin API port
  image: safeyolo:latest
  container_name: safeyolo

sandbox: true          # Sandbox Mode enabled (default)

modes:
  credential_guard: block
  network_guard: block
  pattern_scanner: warn
  test_context: block
```

## policy.yaml

Host-centric policy format. Everything about one host lives in one place:

```yaml
hosts:
  api.openai.com:      { credentials: [openai:*],    rate_limit: 3000 }
  api.anthropic.com:   { credentials: [anthropic:*],  rate_limit: 3000 }
  api.github.com:      { credentials: [github:*],     rate_limit: 300 }
  "*":                 { unknown_credentials: prompt,  rate_limit: 600 }

global_budget: 12000

credentials:
  openai:
    patterns: ["sk-proj-[a-zA-Z0-9_-]{80,}"]
    headers: [authorization, x-api-key]

required: [credential_guard, network_guard, circuit_breaker]
scan_patterns: []
```

Each host entry can include:
- `credentials` - credential types allowed (e.g. `[openai:*]`, `[hmac:a1b2c3d4]`)
- `rate_limit` - requests per minute for this host
- `bypass` - addons to skip for this host
- `rules` - escape hatch for full IAM expressiveness when needed

The wildcard `"*"` entry sets defaults for unlisted hosts. `unknown_credentials: prompt` triggers human approval for unrecognized credentials.

`allowed_hosts` for credential rules are auto-derived from the `hosts` section -- you don't need to specify them separately.

> **Note:** The host-centric format compiles to IAM-style rules at load time. The IAM format remains the internal evaluation model.

## addons.yaml

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
  pattern_scanner:
    enabled: true
    builtin_sets: []
```

### Credential Condition Formats

- `openai:*` - type-based (any OpenAI key)
- `anthropic:*` - type-based (any Anthropic key)
- `hmac:a1b2c3d4` - HMAC-based (specific credential fingerprint)

### Policy Effects

| Effect | Behavior |
|--------|----------|
| `allow` | Permit immediately |
| `deny` | Block immediately |
| `prompt` | Trigger human approval |
| `budget` | Allow up to N requests/minute, then deny |

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

In `warn` mode, violations are logged but traffic is not blocked. Useful for:
- Debugging policy issues
- Gradual rollout of new rules
- Understanding traffic patterns before enforcement

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFEYOLO_ADMIN_TOKEN` | Admin API authentication token |
| `SAFEYOLO_CONFIG_DIR` | Override config directory location |
| `SAFEYOLO_ALLOW_ROOT` | Allow running CLI as root (not recommended) |
| `SAFEYOLO_TUI` | Set to `true` for mitmproxy TUI in tmux (default: headless mitmdump) |
| `SAFEYOLO_BLOCK` | Set to `true` to enable blocking mode for all security addons |

## Per-Agent Policies

Each agent can have its own policy in `~/.safeyolo/policies/<agent-name>.yaml`. If no per-agent policy exists, the baseline policy applies.

## See Also

- [CLI Reference](../cli/README.md) - Command documentation
- [Addons](ADDONS.md) - Security addon configuration
- [Security](../SECURITY.md) - Security principles and threat model
