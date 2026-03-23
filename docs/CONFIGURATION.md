# Configuration

SafeYolo configuration lives in `~/.safeyolo/` (global) or `./safeyolo/` (project-specific).

## Directory Structure

```
~/.safeyolo/
├── config.yaml          # Proxy settings
├── policy.yaml          # Policy: hosts, credentials, rate limits
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── agents.yaml          # Machine-managed agent metadata (services, capabilities, grants)
├── services/            # User service definitions (override builtin services)
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
├── policies/            # Per-project approval policies
├── agents/              # Agent container configurations
├── data/                # Admin token, HMAC secret, relay tokens
│   ├── vault.yaml.enc   # Encrypted credential vault
│   └── vault.key        # Vault encryption key (auto-generated, 0600 permissions)
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

> **Tip:** Run `safeyolo policy show` to see the fully merged policy as the PDP sees it. This includes policy.yaml, addons.yaml, and agents.yaml merged together.

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

## agents.yaml

Machine-managed agent metadata, written by the CLI (`safeyolo agent authorize` / `safeyolo agent revoke`). Lives alongside `policy.yaml` and is merged at load time.

```yaml
# Machine-managed by CLI (safeyolo agent authorize/revoke)
# Lives alongside policy.yaml — merged at load time
boris:
  template: claude-code
  folder: /home/user/my-project
  services:
    gmail: { capability: read_and_send, token: gmail-cred, account: operator }
    minifuse: { capability: reader, token: minifuse-key }
  grants:
    - grant_id: grt_abc123
      service: minifuse
      method: DELETE
      path: /v1/feeds/999
      scope: once
      created: 2026-03-23T17:52:04Z
      expires: 2026-03-23T18:52:04Z
  mounts:
    - /home/user/data:/data:ro
  ports:
    - 127.0.0.1:6080:6080
```

Notes:
- The CLI writes `agents.yaml`; it never touches `policy.yaml`.
- The policy loader merges all sibling files (`policy.yaml` + `addons.yaml` + `agents.yaml`) at load time.
- Service bindings use `capability:` (not `role:`). The `account:` field declares whose account the credential belongs to (`agent`, `operator`, or a custom label).
- The `grants:` section tracks operator-approved one-time or session grants for risky routes. Once-grants are consumed after a successful (2xx) response. Grant TTL defaults to 1 hour, configurable via `gateway.grant_ttl_seconds` in policy.yaml.
- If you want to hand-manage agents, move the section into `policy.yaml` and delete `agents.yaml`.
- `safeyolo policy show` displays the merged result.

## Service Definitions

Service definitions describe APIs: auth methods, capabilities (named sets of allowed routes), and risky routes (tagged with ATT&CK tactics). They are used by the service gateway to enforce per-agent access control.

- Builtin services ship with SafeYolo (gmail, slack, etc.) in `config/services/`.
- User overrides go in `~/.safeyolo/services/`.
- The `service:` field in `policy.yaml` host entries links a host to a service definition.

Example service YAML (v2 format):

```yaml
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-Auth-Token
capabilities:
  reader:
    description: "Read-only access to feeds and entries"
    routes:
      - methods: [GET]
        path: "/v1/feeds"
      - methods: [GET]
        path: "/v1/feeds/*"
risky_routes:
  - group: "Feed management"
    tactics: [impact]
    routes:
      - path: "/v1/feeds/*"
        methods: [DELETE]
        description: "Delete feed — permanently removes feed and all its entries"
        irreversible: true
```

Key v2 changes from v1:
- **Capabilities** replace roles. Capability routes are a positive list (no `effect: allow/deny`).
- **Risky routes** replace deny rules. Tagged with ATT&CK `tactics`, `enables`, and `irreversible` signals.
- **Auth** is defined at service level (not per-role).
- **Risk appetite** rules in `policy.yaml` (`gateway:` section) determine which risky routes require operator approval based on tactics, account persona, and irreversibility.

## Vault

Encrypted credential store for the service gateway. Credentials are stored encrypted at rest and referenced by name in `agents.yaml` service bindings.

- Key auto-generated at `~/.safeyolo/data/vault.key` (0600 permissions).
- Credentials stored in `~/.safeyolo/data/vault.yaml.enc`.
- Managed via CLI: `safeyolo vault add`, `safeyolo vault list`, `safeyolo vault remove`, `safeyolo vault oauth2`.
- Referenced by name in agents.yaml service bindings (the `token:` field).

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
