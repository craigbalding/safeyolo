# Service YAML — Schema Reference

This reference describes service definitions accepted by the
[current service loader](../proxy/src/services.rs). Service definitions use
`schema_version: 1`. For host credential storage and service authorization, use
[credentials and service access](credentials.md). Audit events have an independent
schema; their version number does not select the service format.

## Minimum Viable Service File

Before writing a definition, identify the application programming interface
(API) hostname, authentication header, and the methods and paths the agent
needs. For authenticated use, obtain the provider credential for the intended
account. The YAML declares how to inject a credential;
it contains no secret value and grants no access by itself.

This example is a complete, loadable definition. Replace `example`,
`api.example.com`, and `/v1/items` with your service's values before using it
with an upstream API. Its `reader` capability permits only the listed route.

```yaml
schema_version: 1
name: example
description: "Example API"
default_host: api.example.com
auth:
  type: bearer
capabilities:
  reader:
    description: "List items"
    routes:
      - methods: [GET]
        path: /v1/items
```

On the operator host, save a top-level `*.yaml` file in the instance's configured
operator service directory. Installed instances normally use `data/services`;
standalone `safeyolo init` uses `services`. Paths are relative to the instance
root. Operator definitions replace builtins with the same `name`.
Use [catalogue changes](credentials.md#catalogue-changes-and-removals) to check
activation with `services list` and `services show NAME`. A malformed change
leaves the previous accepted catalogue active.

Then follow [credential and service setup](credentials.md) to store the
credential and authorize an existing agent for `reader`. Authorization selects
the account and host mapping. Network permission and credential policy remain
separate. Loading YAML alone proves neither authorization nor an upstream API
call. Fetch the agent's current gateway token after catalogue activation.

The loader requires only `schema_version` and `name`. Omitting `capabilities`
or its routes creates no implicit route permission. Omitting `auth` describes
a credential-free service. An omitted `default_host` needs an explicit host
when authorizing access.

## Permissions and Trust

A capability is a positive list of allowed methods and paths. Narrow
capabilities and broad ones such as `full_access` use the same matching rules.
A risky-route declaration supplies signals for a separate policy decision; it
does not authorize the route. Network permission, service authorization,
contract binding and credential permission remain separate checks.

The gateway can limit routes even when the provider token has broader access.
A provider-scoped token adds an independent limit at the upstream service.
The service's `scopes` list describes provider permissions; SafeYolo does not
reduce a token's provider permissions from those labels.

Agents can discover services through `GET /gateway/services` and submit a
capability request to `POST /gateway/request-access` through their authenticated
Agent API. A supplied `reason` gives the operator task context; it is not proof
of intent or authorization. Contract capabilities can require binding values
before access. Use the [host approval workflow](credentials.md#authorization-binding-and-risk-approval)
to inspect and approve the applicable request.

The proxy does not follow upstream redirects. If the client follows a redirect,
its next request passes through the applicable destination, route and credential
checks. A redirect does not extend a service token's host or capability scope.

## Full Schema

The following is a field/type sketch, not a definition to install. Descriptions
are recommended for operator decisions but are not required by the loader.
Unknown fields can remain in the raw document without being enforced; parser
acceptance alone does not establish support for a proposed feature.
The optional `effect_model` is typed and validated. Use the
[service-authoring workflow](service-authoring.md) to generate a model, reusable
rules, alternatives and regression inputs from reviewed local evidence. Its
effects describe possibilities and do not grant access or change policy.

```yaml
schema_version: 1          # required — integer 1
name: string              # required — service identifier
description: string       # optional — human-readable summary
default_host: string      # optional — defaults to ""

auth:                     # optional — omit for credential-free services
  type: string            # required within auth: bearer or api_key for injection
  header: string          # default: Authorization
  scheme: string          # default: Bearer; used only for bearer
  refresh_on_401: bool    # default: false; expiry refresh before injection
  allow_http: bool        # default: false

risky_routes:             # optional — defaults to []
  - group: string         # optional — expands the routes below
    description: string   # optional — defaults to ""
    tactics: [string]     # optional — defaults to []
    enables: [string]     # optional — defaults to []
    irreversible: bool    # optional — defaults to false
    routes:               # optional — defaults to []
      - path: string      # required for each route — glob pattern
        methods: [string] # optional — defaults to ["*"]; scalar also accepted
        description: string # optional — replaces group description
        tactics: [string] # optional — adds to group tactics, without duplicates
        enables: [string] # optional — adds to group enables, without duplicates
        irreversible: bool # optional — overrides group value

  # A route without a group is also valid:
  - path: string
    methods: [string]
    description: string
    tactics: [string]
    enables: [string]
    irreversible: bool

capabilities:             # optional — defaults to {}
  capability_name:
    description: string   # optional — displayed during discovery
    scopes: [string]      # optional — informational provider scope guidance
    routes:               # optional — defaults to []
      - methods: [string] # required for each route; scalar also accepted
        path: string      # required for each route — glob pattern
    contract: {}          # optional — see Capability Contracts
effect_model: {}          # optional — see the service-authoring workflow
```

`auth.type: bearer` injects the stored value as `scheme + space + value`.
`api_key` injects the value directly into `header`; set the provider's header
explicitly when it is not `Authorization`. Use these two types for authenticated
services; an arbitrary type string can parse without implementing an injector.
With `allow_http: false`, a selected authenticated Hypertext Transfer Protocol
(HTTP) request is redirected to secure HTTP (HTTPS) without injecting the
secret. Setting `allow_http: true` permits
injection over HTTP. `refresh_on_401` is the retained field name: an expired
OAuth credential is refreshed before delivery when configured, rather than by
replaying a request after an upstream 401.

Methods are matched without case sensitivity. Route paths are case-sensitive.
`*` spans `/`; it is not limited to one path segment. `/**` also covers the
parent path. Ordinary routes match method and path, not query values or bodies
in JavaScript Object Notation (JSON). `scopes` does not restrict the
provider token or filter response fields.
Use contracts for supported request constraints and provider scopes for the
provider's own limits.

## Capability Contracts

A capability's optional `contract` describes its request checks and any declared
state or response work. The [current implementation](../proxy/src/contracts.rs)
enforces requests only.
See the shipped [Gmail read contract](../cli/src/safeyolo/services/gmail.yaml)
and [MiniFuse category contract](../cli/src/safeyolo/services/minifuse.yaml)
for complete loadable examples. Runtime state and response enforcement are
unavailable; use the implementation limits below when choosing a contract.

| Field | Current meaning |
|---|---|
| `template` | Template identifier matched against the approved binding. |
| `bindings` | Named values with type `string` (default), `enum` with nonempty `options`, `integer`, `boolean`, or `string_list`. String definitions can supply `pattern`; `required_if` can make a value required by other supplied values. |
| `operations` | Named operations. `requires_enforcement` defaults to `request_shape`; the named tier must be marked `enforced` to be grantable. |
| `operations[].request` | `method` defaults to GET. `path` selects the operation; `{name}` path parameters use `path_params` constraints. |
| `request.path_params` | `equals_var` resolves a path parameter from an approved binding. |
| `request.query.allow` | Supplied query values can be checked with `equals_var` or `integer_range`. `deny_unknown` defaults to true. |
| `request.body.allow` | Supplied body values can be checked with `equals_var`. `deny_unknown` defaults to true. Nonempty POST, PUT and PATCH bodies must be JSON objects. |
| `request.transport` | `require_no_body` defaults to false. Optional `allow_headers` must be a list. With no list, Accept and User-Agent are permitted in addition to implicit transport/auth headers; an empty list does not add them. |
| `enforcement` | Tier status values are `enforced` or `declared`. A missing tier does not make its operations grantable. |
| `state` | Retained as an untyped value; it creates no runtime sets or capture. |
| Operation `response` | Declarations in the definition; the request executor does not run response captures or validators. |

| Tier | Current implementation |
|---|---|
| `request_shape` | Supported request constraints. |
| `transport_hygiene` | Supported request transport checks. |
| `state_capture` | No runtime capture; operations requiring this tier cannot be granted. |
| `state_enforcement` | No runtime state enforcement; operations requiring this tier or using `in_state_set` cannot be granted. |
| `response_validators` | A required tier marked `enforced` can leave an operation grantable, but validators still do not run. Approval does not establish response enforcement. |

### Grantable operations and binding

An operation's required tier must be marked `enforced`, and the runtime must
support its requirements. Operations requiring `state_capture` or
`state_enforcement`, or using `in_state_set` in path, query or body constraints,
cannot be granted even if their tier is marked `enforced`. The definition can
still load, and supported operations in the same contract remain available.
These checks do not reject a `response_validators` requirement on the same
basis; that declaration can therefore accompany a grant without any runtime
response check.

For a contract capability, the running policy compiles routes from supported,
selected operations. The broad `capability.routes` list is not a fallback grant
for unsupported operations. Operations that use approved values need a matching
binding before those routes can activate. Before binding, only grantable
operations with a literal path, no path wildcard or template parameter, and no
binding or state references can contribute routes. The gateway applies their
request checks even in this discovery subset.

For example, the shipped Gmail `read_messages` contract can check a supplied
`labelIds` value in `list_messages` against an approved category. Its
`get_message` operation uses `in_state_set`, so it contributes no executable
route. Request bindings do not classify response content, track a list-before-get
sequence, or detect conflicts with another capability that can mutate the
selected data.

Binding does not grant service access. Use the host-side
[binding workflow](credentials.md#authorization-binding-and-risk-approval) to
approve values and selected operations, wait for policy activation and fetch
the current gateway token. The host checks binding names, value types and
values required by the selected operations. An agent's reason remains
untrusted task context; it does not establish the requested scope's safety.

### Request checks and limits

Among grantable operations with the requested method, the request executor
prefers a literal path over a parameterized path, then a wildcard path. If no
operation matches, the request is refused. Compiled policy supplies the
agent, service, capability and selected-operation scope before these checks.

Request constraint `type` labels and body `integer_range` fields are parsed but
do not enforce value types or body ranges. Allowing a field does not require
its presence. Binding-definition types are checked separately when binding
values are approved. Binding `source` and `visible_to_operator` fields are
retained metadata; they do not authorize a value. `deny_ambiguous_encoding` is a parsed transport field with
default false; current ambiguity checks run regardless of that flag. Duplicate
headers/query keys, method overrides and path tricks can therefore still be
refused when it is false. These limits matter when choosing a contract; a
declaration cannot supply a missing enforcement guarantee.

The header allowlist is case-insensitive and adds to the implicit transport
headers: Host, Connection, Content-Length, Content-Type, Transfer-Encoding,
Accept-Encoding, Via and Proxy-Connection. The service's configured
authentication header is also permitted. An explicit empty `allow_headers`
list removes the default Accept and User-Agent additions; it cannot remove
the implicit headers.

Request checks reject duplicate header names and decoded query keys,
method-override headers and `_method`, dot path segments, doubled path
separators, encoded path separators and ambiguous percent encodings.
Nonempty POST, PUT and PATCH bodies require an `application/json` object;
duplicate JSON keys and fields supplied in both query and body are refused.
These are request checks, not a response-content or workflow guarantee.

## ATT&CK Tactics Vocabulary

Use these MITRE ATT&CK tactic labels to describe risk. The loader accepts string
labels without checking this vocabulary. No technique identifiers are needed.

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

Groups cluster related risky routes for operator decisions. The loader expands
each group into routes. A route replaces the group description or irreversible
value when supplied. Tactics and enables are combined with the group values.

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

The group name and merged signals accompany a risky-route decision. Inspect
pending requests with `services approvals`.

## Credential Binding and Account Persona

When the operator authorizes a service, `services authorize` selects a
capability, credential reference and `--account` label. That label reaches risk
policy as `account`. It is independent of the service's auth format.

For an existing agent named `boris`, a host policy binding can have this form.
The credential names refer to host-stored records. This is a policy fragment,
not a service definition; use the [operator commands](credentials.md) for setup
and activation.

```toml
[agents.boris.services.gmail]
capability = "read_and_send"
token = "gmail-personal-cred"
account = "operator"

[agents.boris.services.github]
capability = "read_work"
token = "github-cred"
account = "agent"
```

Conventional personas are `agent` for the agent's account, `operator` for a
personal operator account, and custom labels such as `team-support` or `billing`
for functional accounts. These labels do not assign an automatic risk level.
A host service binding that omits `account` defaults to `agent`; specify the
intended owner rather than relying on that label. Risk decisions come from
authored policy, not an automatic ranking of account labels.

## Policy: Risk Appetite

Service files declare facts. Policy expresses what the operator tolerates,
using risky-route signals and the account label. In host `policy.toml`, the
current `[[risk]]` compiler accepts `account`, `agent`, `service`, `tactics`,
`enables`, `irreversible`, and `decision`. Decisions are `allow`, `deny`, or
`require_approval` (the default). Different conditions combine; a list of
tactics or enables matches any listed value. These rules apply only after a
request matches a declared risky route.

```toml
# policy.toml — operator risk appetite

# Operator's inbox: credential_access routes need approval
[[risk]]
account = "operator"
enables = ["credential_access"]
decision = "require_approval"

# Agent's own account: collection is routine
[[risk]]
account = "agent"
tactics = ["collection"]
decision = "allow"

# Team inbox: sending is customer-facing, needs approval
[[risk]]
account = "team-support"
tactics = ["impact"]
decision = "require_approval"

# Either exfiltration or persistence needs approval
[[risk]]
tactics = ["exfiltration", "persistence"]
decision = "require_approval"

# Irreversible actions need approval
[[risk]]
irreversible = true
decision = "require_approval"

# Trust boris with github privilege_escalation
[[risk]]
agent = "boris"
service = "github"
tactics = ["privilege_escalation"]
decision = "allow"
```

Without a matching allow rule or an existing risk grant, risky-route policy
defaults to an approval request (HTTP 428). An explicit risk denial returns 403.
The operator can inspect `services approvals` and approve the exact agent,
service, method and path with `services approve`. A matching risk grant is
checked before risk policy. It does not widen service routes, replace a contract
binding, or grant network or credential permission. A `once` grant reserves one
in-flight use; a 2xx response consumes it and other outcomes release it for retry.
Response-based consumption does not guarantee exactly-once external side effects
across a proxy crash. The [grant implementation](../proxy/src/grants.rs) retains
a reservation in the running proxy after a successful action if saving its
consumption fails.

`irreversible` is a policy signal, not a schema-enforced typed-confirmation prompt.
The risk compiler does not implement a minimum policy floor. A rule
matching `exfiltration` cannot catch an omitted tag, and a route omitted from
`risky_routes` does not enter this risk check. Review service definitions as
operator-controlled inputs; do not assume an independent floor detects omissions.
Other network, credential and authored route policy still applies.

For a missing route allow, the current agent run instead receives a
[route challenge](service-route-approval.md). Reconsideration creates no pending
operator work. Only explicit escalation can request a finite exact-route
exception with the existing credential. Explicit denials and other controls
remain in force. Existing risky-route grants do not supply admission permission.

## Complete Example: Gmail

Gmail illustrates the ownership question: reading an operator's inbox exposes
password resets and two-factor codes. Account-specific policy can therefore
make a different decision for the same route. The example below uses route
capabilities. The shipped [Gmail definition](../cli/src/safeyolo/services/gmail.yaml)
also includes a `read_messages` request contract with declared response/state
fields; inspect that definition before selecting a shipped capability.

```yaml
schema_version: 1
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
    description: "List messages; provider metadata scope limits content"
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

With the example risk rules, the `collection` allow rule can permit message
reads for account `agent`. The `credential_access` rule requires approval for
account `operator`, unless an applicable grant exists. This difference comes
from authored policy, not from the account label alone.

## Complete Example: GitHub

This extended authoring example illustrates supply-chain, access-control and
persistence risks. It is not the shipped GitHub grant.
The shipped [GitHub definition](../cli/src/safeyolo/services/github.yaml) has only
`read_work` for individual issue and pull-request metadata. The example uses a
different name so it does not replace that definition by name. Its broad
capabilities need an explicit operator choice and suitable provider permissions.

```yaml
schema_version: 1
name: github-example
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
    routes:
      - methods: [GET]
        path: "/repos/*/issues/**"
      - methods: [GET]
        path: "/search/issues"

  create_pr:
    description: "Create pull requests and access the Git data API"
    routes:
      - methods: [GET]
        path: "/repos/*/pulls/**"
      - methods: [POST]
        path: "/repos/*/pulls"
      - methods: [GET, POST]
        path: "/repos/*/git/**"

  manage_issues:
    description: "Create, update, close, and comment on issues"
    routes:
      - methods: [GET, POST, PATCH]
        path: "/repos/*/issues/**"

  repo_read:
    description: "Read-only access to repository contents"
    routes:
      - methods: [GET]
        path: "/repos/**"

  repo_full_access:
    description: "Full read/write access to repositories"
    routes:
      - methods: [GET, POST, PUT, DELETE, PATCH]
        path: "/repos/**"
```
