# Service YAML v2 — Schema Reference

Companion to [Service Gateway v2 Design](service-gateway-v2-design.md).

## Minimum Viable Service File

```yaml
schema_version: 2
name: gmail
description: "Gmail API"
default_host: gmail.googleapis.com
auth:
  type: bearer
```

Five fields. The gateway knows this host is a service and can inject
credentials. No capabilities = agent gets access to all routes on this
host. No risky routes = all risk decisions come from policy alone.

## Full Schema

```yaml
schema_version: int        # required — currently 2
name: string              # required — unique service identifier
description: string       # required — human-readable summary
default_host: string      # optional — primary API hostname

auth:                      # required — how to inject credentials
  type: string             # "bearer" or "api_key"
  header: string           # default: "Authorization"
  scheme: string           # default: "Bearer" (for type: bearer)
  refresh_on_401: bool     # default: false

risky_routes:              # optional — routes that need runtime approval
  - group: string          # optional — group name (clusters related routes)
    description: string    # required — the "so what" (security consequence)
    tactics: [string]      # ATT&CK tactics (see vocabulary below)
    enables: [string]      # what attack stages this unlocks
    irreversible: bool     # default: false
    routes:                # required if group is present
      - path: string       # glob pattern
        methods: [string]  # default: ["*"]
        description: string  # optional — override group description
        tactics: [string]  # optional — override/extend group tactics
        enables: [string]  # optional — override/extend group enables
        irreversible: bool # optional — override group value

  # Ungrouped routes also valid:
  - path: string
    methods: [string]
    description: string
    tactics: [string]
    enables: [string]
    irreversible: bool

capabilities:              # optional — named sets of allowed routes
  capability_name:
    description: string    # required
    scopes: [string]       # optional — informational, recommended API scopes
    routes:                # required
      - methods: [string]  # required
        path: string       # required — glob pattern
```

## ATT&CK Tactics Vocabulary

Service file authors pick from this list. No technique IDs needed.

| Tactic | Meaning | Example |
|--------|---------|---------|
| `collection` | Gathering data from the target | Reading email, listing secrets |
| `exfiltration` | Moving data out of the account | Forwarding rules, webhooks |
| `persistence` | Maintaining access after compromise | Mail filters, deploy keys, OAuth grants |
| `privilege_escalation` | Gaining broader access | Adding collaborators, changing perms |
| `defense_evasion` | Hiding traces or avoiding detection | Deleting logs, modifying filters |
| `impact` | Destructive or disruptive actions | Permanent deletion, impersonation |
| `credential_access` | Obtaining credentials for other systems | Reading password reset emails |
| `lateral_movement` | Using access to reach other systems | Harvesting tokens/API keys |

The `enables` field uses the same vocabulary — it describes what *further*
stages a route unlocks. Reading email (tactic: `collection`) enables
`credential_access`. Creating a mail filter (tactic: `persistence`) enables
`defense_evasion`.

## Route Groups

Groups cluster related risky routes for operator UX. The group carries
shared signals; individual routes can override.

```yaml
risky_routes:
  - group: "Mail routing"
    description: "Controls where email goes — persistent exfiltration vectors"
    tactics: [exfiltration, persistence]
    routes:
      - path: "/gmail/v1/users/me/settings/filters/**"
        description: "Mail filters — silent redirection, evidence hiding"
        enables: [defense_evasion]       # adds to group
      - path: "/gmail/v1/users/me/settings/forwardingAddresses/**"
        methods: [POST, PUT]
        description: "Forwarding — all incoming mail copied out"
      - path: "/gmail/v1/users/me/settings/delegates/**"
        methods: [POST, DELETE]
        description: "Delegate access — another account gets full access"
        enables: [lateral_movement]      # adds to group
```

In watch, the operator sees: "Mail routing (3 routes) — controls where
email goes" with option to drill into individual routes.

## Credential Binding and Account Persona

When an operator grants access (in watch or via `agent authorize`), the
binding includes an **account persona** — whose account the credential
belongs to. This flows to the PDP and drives context-dependent decisions.

```yaml
# agents.yaml — bindings with persona
boris:
  services:
    gmail:
      capability: read_and_send
      token: gmail-personal-cred
      account: operator           # operator's personal inbox
    gmail-support:
      capability: read_and_send
      token: team-gmail-cred
      account: team-support       # functional team inbox
    github:
      capability: create_pr
      token: github-cred
      account: agent              # agent's own github account
```

Standard personas:
- `agent` — the agent's own account. Least restrictive by default.
- `operator` — the operator's personal account. Most restrictive by default.
- Custom labels (`team-support`, `billing`, etc.) — operator-defined, with
  matching policy rules.

Watch prompts for persona when first binding a credential: "Whose account
is this? (agent / operator / custom label)"

## Policy: Risk Appetite

Service files declare facts. Policy expresses what the operator tolerates,
using risky route signals and account persona.

```yaml
# policy.yaml — operator risk appetite
gateway:
  risk_appetite:
    # Operator's inbox: credential_access routes need approval
    - account: operator
      enables: [credential_access]
      decision: require_approval
      approval_default: once

    # Agent's own account: collection is routine
    - account: agent
      tactics: [collection]
      decision: allow

    # Team inbox: sending is customer-facing, needs approval
    - account: team-support
      tactics: [impact]
      decision: require_approval

    # Exfiltration + persistence together = always require approval
    - tactics: [exfiltration, persistence]
      decision: require_approval

    # Irreversible actions need explicit "yes" confirmation
    - irreversible: true
      decision: require_approval
      confirm: true

    # Trust boris with github privilege_escalation
    - agent: boris
      service: github
      tactics: [privilege_escalation]
      decision: allow

    # Floor: no service file can make exfiltration routes safe
    - tactics: [exfiltration]
      minimum: require_approval
```

Policy is authoritative. A malicious service file that omits `tactics` on
a dangerous route is caught by floor rules. Service files cannot weaken
policy.

## Complete Example: Gmail

Gmail is the canonical example because it surfaces the ownership question.
The same route is routine on the agent's own account and dangerous on the
operator's inbox. The service file declares facts; the PDP evaluates them
against policy in context.

```yaml
schema_version: 2
name: gmail
description: "Gmail API — email read/send via Google OAuth2"
default_host: gmail.googleapis.com

auth:
  type: bearer
  refresh_on_401: true

risky_routes:
  - group: "Mail routing"
    description: "Controls where email goes — persistent exfiltration vectors"
    tactics: [exfiltration, persistence]
    routes:
      - path: "/gmail/v1/users/me/settings/filters/**"
        description: "Mail filters — silent redirection, evidence hiding"
        enables: [defense_evasion]
      - path: "/gmail/v1/users/me/settings/forwardingAddresses/**"
        methods: [POST, PUT]
        description: "Forwarding — all incoming mail copied out"
      - path: "/gmail/v1/users/me/settings/delegates/**"
        methods: [POST, DELETE]
        description: "Delegate access — another account gets full access"
        enables: [lateral_movement]

  - group: "Message content"
    description: "Reading email exposes credentials, 2FA codes, confidential comms"
    tactics: [collection]
    enables: [credential_access]
    routes:
      - path: "/gmail/v1/users/me/messages/**"
        methods: [GET]
      - path: "/gmail/v1/users/me/threads/**"
        methods: [GET]

  - group: "Send as account owner"
    description: "Sending email as the account owner — impersonation from a trusted address"
    tactics: [impact]
    irreversible: true
    routes:
      - path: "/gmail/v1/users/me/messages/send"
        methods: [POST]
      - path: "/gmail/v1/users/me/drafts/send"
        methods: [POST]

  - group: "Destructive actions"
    description: "Data loss — may hide evidence of compromise"
    tactics: [impact, defense_evasion]
    irreversible: true
    routes:
      - path: "/gmail/v1/users/me/messages/*/trash"
        methods: [POST]
        description: "Trash — reversible but hides messages"
        irreversible: false
      - path: "/gmail/v1/users/me/messages/*/delete"
        methods: [DELETE]
        description: "Permanent delete — irreversible data loss"

capabilities:
  manage_labels:
    description: "Create, update, and delete labels (no message content access)"
    scopes: ["gmail.labels"]
    routes:
      - methods: [GET, POST, PUT, PATCH, DELETE]
        path: "/gmail/v1/users/me/labels/**"

  search_headers:
    description: "Search message metadata (subject, from, date — no body access)"
    scopes: ["gmail.metadata"]
    routes:
      - methods: [GET]
        path: "/gmail/v1/users/me/messages"

  read_and_send:
    description: "Full read/write access to messages"
    scopes: ["gmail.modify"]
    routes:
      - methods: [GET, POST]
        path: "/gmail/v1/users/me/messages/**"
      - methods: [GET]
        path: "/gmail/v1/users/me/threads/**"
      - methods: [POST]
        path: "/gmail/v1/users/me/drafts/**"

  full_access:
    description: "Full access to all Gmail features"
    scopes: ["https://mail.google.com/"]
    routes:
      - methods: [GET, POST, PUT, DELETE, PATCH]
        path: "/gmail/v1/users/me/**"
```

On an **agent-owned account**, policy might allow the "Message content"
group freely. On an **operator-owned account**, policy requires per-request
approval because `enables: [credential_access]` intersects with the
operator's risk appetite. Same service file, different policy, different
outcome.

## Complete Example: GitHub

A service where agent access is natural. Risky routes focus on supply
chain, access control, and persistence.

```yaml
schema_version: 2
name: github
description: "GitHub API — repository and issue management"
default_host: api.github.com

auth:
  type: bearer

risky_routes:
  - group: "CI/CD and secrets"
    description: "Build pipeline and secrets management — supply chain risk"
    tactics: [credential_access, exfiltration]
    enables: [lateral_movement]
    routes:
      - path: "/repos/*/actions/secrets/**"
        methods: [PUT, DELETE]
        description: "Repository secrets — credentials used in CI/CD"
      - path: "/repos/*/actions/workflows/*/dispatches"
        methods: [POST]
        description: "Trigger workflow runs — arbitrary code execution in CI"
      - path: "/repos/*/environments/*/secrets/**"
        methods: [PUT, DELETE]
        description: "Environment secrets — production credentials"

  - group: "Access control"
    description: "Who can access the repository and with what permissions"
    tactics: [privilege_escalation]
    routes:
      - path: "/repos/*/collaborators/**"
        methods: [PUT, DELETE]
        description: "Collaborators — grant/revoke repository access"
      - path: "/repos/*/branches/*/protection"
        methods: [PUT, DELETE]
        description: "Branch protection — disabling review requirements"

  - group: "Persistence vectors"
    description: "Mechanisms that maintain access or exfiltrate data over time"
    tactics: [persistence, exfiltration]
    routes:
      - path: "/repos/*/hooks/**"
        methods: [POST, PATCH, DELETE]
        description: "Webhooks — exfiltrate code and events to external URLs"
      - path: "/repos/*/keys/**"
        methods: [POST, DELETE]
        description: "Deploy keys — push/pull access outside normal auth"
        enables: [lateral_movement]

  - path: "/repos/*/contents/**"
    methods: [PUT, DELETE]
    description: "Direct file commits — bypass PR review process"
    tactics: [defense_evasion]
    irreversible: false

capabilities:
  search_issues:
    description: "Search and read issues and comments"
    scopes: ["repo:read", "issues:read"]
    routes:
      - methods: [GET]
        path: "/repos/*/issues/**"
      - methods: [GET]
        path: "/search/issues"

  create_pr:
    description: "Create pull requests and push branches"
    scopes: ["repo:write", "pull_requests:write"]
    routes:
      - methods: [GET]
        path: "/repos/*/pulls/**"
      - methods: [POST]
        path: "/repos/*/pulls"
      - methods: [GET, POST]
        path: "/repos/*/git/**"

  manage_issues:
    description: "Create, update, close, and comment on issues"
    scopes: ["issues:write"]
    routes:
      - methods: [GET, POST, PATCH]
        path: "/repos/*/issues/**"

  repo_read:
    description: "Read-only access to repository contents"
    scopes: ["repo:read"]
    routes:
      - methods: [GET]
        path: "/repos/**"

  repo_full_access:
    description: "Full read/write access to repositories"
    scopes: ["repo"]
    routes:
      - methods: [GET, POST, PUT, DELETE, PATCH]
        path: "/repos/**"
```

## Migration from v1

| v1 concept | v2 concept |
|-----------|-----------|
| `roles:` | `capabilities:` |
| `role.auth` | `service.auth` (top-level) |
| `role.routes` with `effect: allow` | `capability.routes` (positive list) |
| `role.routes` with `effect: deny` | `risky_routes` with tactics/enables |
| `role.require_approval` | Removed — risky routes + policy |
| `role.description` | `capability.description` |
| (no equivalent) | `risky_routes[].tactics` |
| (no equivalent) | `risky_routes[].enables` |
| (no equivalent) | `risky_routes[].group` |

### Breaking changes

- `roles:` key no longer recognised. Use `capabilities:`.
- `effect` field removed from route rules. All capability routes are allow.
- `deny` routes must be moved to `risky_routes`.
- `auth` moves from role to service level.

## Future Schema Extensions

These are planned extensions. The current schema is designed to accommodate
them without breaking changes.

### Parameter-aware route matching

Path-only matching covers REST APIs well but is blind to query parameters
and request bodies. For GraphQL, RPC-style APIs (Slack uses POST for
everything), and APIs with meaningful query parameters, path matching alone
misses the actual risk.

A future `match` field on risky routes and capability routes:

```yaml
# GraphQL — the path is meaningless, the query carries the risk
risky_routes:
  - path: "/graphql"
    methods: [POST]
    match:
      body_json:
        query: "mutation delete*"
    description: "GraphQL delete mutations"
    tactics: [impact]
    irreversible: true

# Query parameter matching
risky_routes:
  - path: "/api/v1/users"
    methods: [GET]
    match:
      query_params:
        role: "admin"
    description: "Listing admin users — reconnaissance"
    tactics: [collection]
```

The `match` field is additive — `path` and `methods` still apply. `match`
adds conditions on query parameters (`query_params`) or request body fields
(`body_json` with glob/regex support). Routes without `match` continue to
work as today.

### Response tokenisation

The gateway can transform responses before the agent sees them — redact
PII, mask account numbers, swap real names for synthetic values. The agent
gets enough data to do its job without seeing sensitive content.

A future `response_policy` field on capabilities:

```yaml
capabilities:
  search_contacts:
    description: "Search customer contacts"
    routes: [...]
    response_policy:
      tokenise:
        - path: "$.results[*].email"
          strategy: consistent    # same input → same synthetic output
        - path: "$.results[*].phone"
          strategy: redact        # replace with [REDACTED]
      redact:
        - path: "$.results[*].ssn"
```

`tokenise` with `consistent` strategy produces deterministic synthetic
values — the agent can correlate "customer A" across multiple requests
without seeing the real email. `redact` replaces with a fixed placeholder.

This requires a tokenisation engine in the gateway (mapping real → synthetic
values, consistent hashing) and de-tokenisation support for outbound
requests where the agent sends synthetic values back. Significant scope —
planned for a future version.
