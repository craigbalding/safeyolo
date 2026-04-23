# Configuration

SafeYolo configuration lives in `~/.safeyolo/` (global) or `./safeyolo/` (project-specific).

## Directory Structure

```
~/.safeyolo/
├── config.yaml          # Proxy settings
├── policy.toml          # Policy: hosts, credentials, rate limits, agents, lists
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── services/            # User service definitions (override builtin services)
├── certs/               # CA certificate for HTTPS inspection
├── logs/                # Audit logs (safeyolo.jsonl)
├── policies/            # Per-project approval policies
├── agents/              # Agent container configurations
├── data/                # Admin token, HMAC secret, agent API tokens
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

modes:
  credential_guard: block
  network_guard: block
  pattern_scanner: warn
  test_context: block
```

## policy.toml

Host-centric policy format in TOML. Everything about one host lives in one place:

```toml
version = "2.0"
description = "SafeYolo baseline policy"

budget = 12_000  # total req/min across all domains

required = ["credential_guard", "network_guard", "circuit_breaker"]
scan_patterns = []

[lists]
package_registries = "lists/package-registries.txt"
known_bad = "lists/stevenblack-hosts.txt"

[hosts]
"api.openai.com"      = { allow = ["openai:*"],    rate = 3_000 }
"api.anthropic.com"   = { allow = ["anthropic:*"],  rate = 3_000 }
"api.github.com"      = { allow = ["github:*"],     rate = 300 }
"$package_registries" = { rate = 1_200 }
"$known_bad"          = { egress = "deny" }
"*"                   = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]
```

Each host entry can include:
- `allow` - credential types allowed (e.g. `["openai:*"]`, `["hmac:a1b2c3d4"]`)
- `rate` - requests per minute for this host
- `egress` - network-level access posture for this host: `allow`, `prompt`, or `deny`
- `bypass` - addons to skip for this host
- `expires` - TOML native datetime; the entry is automatically removed after this time
- `rules` - escape hatch for full IAM expressiveness when needed

The wildcard `"*"` entry sets defaults for unlisted hosts. `unknown_creds = "prompt"` triggers human approval for unrecognized credentials. The `egress` field on the wildcard controls what happens when a request targets a host not listed in `[hosts]` -- `allow` permits it, `prompt` asks the operator, and `deny` blocks it.

`allowed_hosts` for credential rules are auto-derived from the `[hosts]` section -- you don't need to specify them separately.

> **Note:** The host-centric format compiles to IAM-style rules at load time. The IAM format remains the internal evaluation model. TOML field names are normalized to internal names during loading (`allow` -> `credentials`, `rate` -> `rate_limit`, `unknown_creds` -> `unknown_credentials`, etc.).

> **Tip:** Run `safeyolo policy show` to see the fully merged policy as the PDP sees it. This includes policy.toml and addons.yaml merged together.

> **Migration:** Existing `policy.yaml` files can be migrated with `safeyolo policy migrate`. Both formats are supported; the proxy prefers `.toml` when both exist.

### Named Lists

The `[lists]` section maps names to files containing host patterns (one per line, `#` comments supported, hosts-file format accepted). Reference a list in `[hosts]` with the `$name` syntax:

```toml
[lists]
package_registries = "lists/package-registries.txt"
known_bad = "lists/stevenblack-hosts.txt"

[hosts]
"$package_registries" = { rate = 1_200 }
"$known_bad"          = { egress = "deny" }
```

At load time, each `$name` entry expands to one permission per host in the file. The `simple_permissions` field in the policy response summarises bulk-expanded entries by action and effect count, so the policy endpoint stays readable even with large lists.

### Expires

Host entries support a `expires` field using TOML's native datetime type. Expired entries are cleaned up automatically at policy reload:

```toml
[hosts]
"sketchy.io" = { egress = "deny", expires = 2026-04-05T12:00:00Z }
```

The `safeyolo policy host deny` command sets expires by default (1 day) to prevent denied hosts from accumulating in the policy over time.

### Agents

Agent configuration lives in the `[agents]` section of policy.toml. Each agent can have its own hosts table and egress posture:

```toml
[agents.boris]
template = "claude-code"
folder = "/home/user/my-project"
egress = "prompt"

[agents.boris.hosts]
"api.stripe.com" = { allow = ["stripe:*"], rate = 600 }
"sketchy.io"     = { egress = "deny" }

[agents.boris.services]
gmail = { capability = "read_and_send", token = "gmail-cred", account = "operator" }
minifuse = { capability = "reader", token = "minifuse-key" }
```

Agent-scoped behaviour:

- `egress` on the agent sets the default posture for that agent when the target host has no explicit entry. If omitted, the agent inherits the proxy-wide wildcard egress posture.
- `[agents.<name>.hosts]` entries are evaluated before proxy-wide `[hosts]` entries. An agent deny beats a proxy-wide allow for the same host.
- Agents without a `hosts` section fall through to the proxy-wide `[hosts]` for all requests.
- Service bindings use `capability:` (not `role:`). The `account:` field declares whose account the credential belongs to (`agent`, `operator`, or a custom label).
- Grants (once-grants, session grants) are tracked under the agent section. Grant TTL defaults to 1 hour, configurable via `gateway.grant_ttl_seconds` in the policy file.

The CLI writes agent metadata (`safeyolo agent authorize` / `safeyolo agent revoke`). Run `safeyolo policy show` to see the merged result.

## addons.yaml

Addon tuning lives in a separate file, sibling to the policy file:

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

## Service Definitions

Service definitions describe APIs: auth methods, capabilities (named sets of allowed routes), and risky routes (tagged with ATT&CK tactics). They are used by the service gateway to enforce per-agent access control.

- Builtin services ship with SafeYolo (gmail, slack, etc.) in `config/services/`.
- User overrides go in `~/.safeyolo/services/`.
- The `service` field in host entries links a host to a service definition.

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
- **Risk appetite** rules in the policy file (`[[risk]]` in TOML / `gateway:` in YAML) determine which risky routes require operator approval based on tactics, account persona, and irreversibility.

## Vault

Encrypted credential store for the service gateway. Credentials are stored encrypted at rest and referenced by name in policy.toml agent service bindings.

- Key auto-generated at `~/.safeyolo/data/vault.key` (0600 permissions).
- Credentials stored in `~/.safeyolo/data/vault.yaml.enc`.
- Managed via CLI: `safeyolo vault add`, `safeyolo vault list`, `safeyolo vault remove`, `safeyolo vault oauth2`.
- Referenced by name in policy.toml agent service bindings (the `token:` field).

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

## Policy CLI Commands

The `safeyolo policy` command group manages policy.toml from the command line. All mutations are atomic writes.

### Host management

```bash
# Add or update a host entry
safeyolo policy host add api.stripe.com --rate 600
safeyolo policy host add api.stripe.com --rate 600 --agent boris
safeyolo policy host add temp-api.com --rate 100 --expires 1d

# Remove a host entry
safeyolo policy host remove api.stripe.com
safeyolo policy host remove api.stripe.com --agent boris

# Deny egress to a host (defaults to 1d expiry)
safeyolo policy host deny sketchy.io
safeyolo policy host deny sketchy.io --expires 7d
safeyolo policy host deny sketchy.io --expires 7d --agent boris

# List host entries
safeyolo policy host list
safeyolo policy host list --agent boris

# Add addon bypass for a host
safeyolo policy host bypass api.stripe.com circuit_breaker
safeyolo policy host bypass api.stripe.com pattern_scanner --agent boris

# Apply a named list as a host entry
safeyolo policy host add-list known_bad --egress deny
safeyolo policy host add-list package_registries --rate 1200
```

### Egress posture

```bash
# Set default egress posture (proxy-wide or per-agent)
safeyolo policy egress set prompt
safeyolo policy egress set deny --agent boris

# Show current egress posture
safeyolo policy egress show
safeyolo policy egress show --agent boris
```

### Named list management

```bash
# Register a named list
safeyolo policy list add known_bad lists/known-bad.txt
safeyolo policy list add custom /path/to/custom-hosts.txt

# Remove a named list reference (does not delete the file)
safeyolo policy list remove known_bad

# Show all lists or entries in a specific list
safeyolo policy list show
safeyolo policy list show known_bad
```

### Policy inspection

```bash
# Show merged policy (policy.toml + addons.yaml)
safeyolo policy show

# Show compiled IAM format as the PDP evaluates it
safeyolo policy show --compiled

# Show a specific section
safeyolo policy show --section hosts
safeyolo policy show --section agents
```

## Policy Visibility

The `/policy` relay endpoint returns the full baseline policy. For policies with large named lists (e.g. blocklists with tens of thousands of entries), bulk-expanded host permissions are summarised in the `simple_permissions` field as action/effect counts rather than individual entries, keeping the response compact.

The `/lookup?host=X` relay endpoint checks what would happen for a specific host, using the calling agent's identity. This is useful for agents to pre-check whether a request would be allowed before attempting it:

```bash
curl -s http://_safeyolo.proxy.internal/lookup?host=api.stripe.com \
  -H "Authorization: Bearer $(cat /app/agent_token)"
# Returns: {"host": "api.stripe.com", "agent": "boris", "effect": "allow", "reason": "..."}
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
