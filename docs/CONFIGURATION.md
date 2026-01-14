# Configuration

SafeYolo configuration lives in `~/.safeyolo/` (global) or `./safeyolo/` (project-specific).

## Directory Structure

```
~/.safeyolo/
├── config.yaml          # Proxy settings
├── baseline.yaml        # Policy: credentials, rate limits, addon config
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
├── policies/            # Per-project approval policies
├── agents/              # Agent container configurations
└── data/                # Admin token, HMAC secret
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
```

## baseline.yaml

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
  - network_guard

addons:
  credential_guard: {enabled: true}
  network_guard: {enabled: true}

domains:
  "*.internal":
    bypass: [pattern_scanner]
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

## Per-Agent Policies

Each agent can have its own policy in `~/.safeyolo/policies/<agent-name>.yaml`. If no per-agent policy exists, the baseline policy applies.

## See Also

- [CLI Reference](../cli/README.md) - Command documentation
- [Addons](ADDONS.md) - Security addon configuration
- [Security](../SECURITY.md) - Security principles and threat model
