# Design: Capability Contracts

## Status

Design document. Draft 2026-03-25.

Extends the [Service Gateway v2 Design](service-gateway-v2-design.md) and the
[Service YAML v2 Spec](service-gateway-v2-yaml-spec.md).

## Overview

The current service gateway controls access at the **capability** level: a named
set of allowed HTTP method + path pairs. This is sufficient for gating *which
endpoints* an agent can reach, but insufficient for controlling *how* those
endpoints are used.

Capability contracts add a deterministic narrowing layer:

    authorisation = capability + contract template + operator-approved binding

The capability remains the coarse action the agent asks for. The contract
template defines how that capability can be narrowed. The binding is the
concrete set of values proposed at runtime and approved by the operator.

This keeps the existing service discovery shape (`services.available` with
capabilities) and the existing approval flow (`safeyolo watch`), but adds a
structured second step for capabilities that are too broad to approve directly.

## Request flow

```
Agent                       SafeYolo                      Operator
  │                            │                             │
  │  request-access            │                             │
  │  capability: read_messages │                             │
  │  purpose: summarise        │                             │
  │───────────────────────────▶│                             │
  │                            │                             │
  │  needs_contract_binding    │                             │
  │  template: gmail.read_...  │                             │
  │  fields: [...]             │                             │
  │◀───────────────────────────│                             │
  │                            │                             │
  │  submit binding            │                             │
  │  approved_category:        │                             │
  │    CATEGORY_PROMOTIONS     │                             │
  │───────────────────────────▶│                             │
  │                            │  watch prompt               │
  │                            │  "read_messages scoped to   │
  │                            │   CATEGORY_PROMOTIONS"      │
  │                            │────────────────────────────▶│
  │                            │                             │
  │                            │  approve                    │
  │                            │◀────────────────────────────│
  │                            │                             │
  │  approved                  │                             │
  │  (contract bound)          │                             │
  │◀───────────────────────────│                             │
  │                            │                             │
  │  GET /messages?labelIds=   │                             │
  │    CATEGORY_PROMOTIONS     │                             │
  │───────────────────────────▶│                             │
  │                            │  enforce against            │
  │                 ┌──────────│  bound contract             │
  │                 │ allowed  │                             │
  │  200 OK ◀───────┘          │                             │
```

For capabilities that don't need narrowing, the template has no fields and the
flow collapses to today's single-step approve/deny.

## Binding model

### Contract template

A contract template is attached to a capability in the service YAML. It defines:

- **Bindings** — named variables the agent proposes and the operator approves.
- **State** — bounded runtime sets that capture values from responses for use
  in later request validation (e.g., message IDs from a list call).
- **Operations** — the allowed request shapes and optional response validators,
  parameterised by the bound variables.

### Operator experience

The operator sees system-authored information in `safeyolo watch` — not
agent-supplied justifications. The operator does not write YAML, fill
templates, or understand API endpoint details. They see something like:

```
╭──── claude requests read_messages (gmail) ──────────╮
│  Capability   read_messages                          │
│  Scope        CATEGORY_PROMOTIONS                    │
│  Threads      no                                     │
│  Current      (none for gmail)                       │
│  Risk         can read message content in scope      │
│  Assessment   within contract, no conflicts detected │
╰───────────── [A]pprove · [D]eny · [L]ater ──────────╯
```

Every field in the prompt is computed by SafeYolo from policy facts — the
capability definition, the proposed binding values, the current grants, and
any detected conflicts. See [Approval UX trust boundary](#approval-ux-trust-boundary)
for why agent-supplied text is excluded.

### Session scope

A bound contract is valid for the current session. If the agent needs the same
capability with a different scope later, it submits a new binding. This avoids
the complexity of multiple active contracts per capability, merging, and
cross-session revocation.

## Contract template schema

A contract template defines the full multi-step workflow for a capability,
not just a single API call.

### Structure

```yaml
contract:
  template: service.capability.v1

  bindings:
    variable_name:
      source: agent              # agent proposes, operator approves
      type: string               # string | string_list | integer | boolean | enum
      visible_to_operator: true  # shown in watch prompt
      # For enum type — prefer enum over free string where the valid
      # values are known. Free strings allow the agent to propose
      # arbitrary values, pushing validation burden to the operator.
      options: [value1, value2]
      # For string type — optional regex constraint:
      pattern: "^[A-Z_]+$"
      # Optional conditional requirement:
      required_if:
        other_field: value

  state:
    set_name:
      type: set
      item_type: string
      max_items: 1000            # bounded to prevent unbounded growth

  operations:
    - name: operation_name
      request:
        method: GET
        path: /api/resource
        transport:
          require_no_body: true
          allow_headers: [Authorization, Accept, User-Agent]
          deny_ambiguous_encoding: true
          canonical_form: true        # see Transport hygiene section
        query:
          allow:
            param_name:
              equals_var: variable_name    # bound variable reference
            other_param:
              integer_range: [1, 100]
            page_token:
              type: string
          deny_unknown: true
        path_params:
          id:
            in_state_set: set_name        # state reference
        body:
          # For POST/PUT/PATCH operations
          allow:
            field_name:
              type: string
          deny_unknown: true
      response:
        capture:
          - jsonpath: $.items[*].id
            into: set_name                # populate state
        validators:
          - name: validator_name
            jsonpath: $.field
            contains_var: variable_name   # check against binding

  enforcement:
    # Explicit enforcement status per tier
    request_shape: enforced       # v1
    transport_hygiene: enforced   # v1
    state_capture: declared       # v1.1
    state_enforcement: declared   # v1.2
    response_validators: declared # v1.2
```

### Enforcement status

Each enforcement tier is explicitly marked as `enforced` or `declared`. A
`declared` tier is part of the contract schema and visible in audits, but not
yet enforced at runtime. This avoids implying stronger guarantees than exist.

As enforcement tiers ship, the status moves from `declared` to `enforced`.
The contract schema does not change — only the enforcement status field.

### Per-operation enforcement requirements

An operation can declare the minimum enforcement tier it requires to be
effective. If that tier is not yet `enforced`, the operation is excluded from
the grantable contract:

```yaml
operations:
  - name: get_message
    requires_enforcement: state_enforcement   # not grantable until tier 3
    ...
```

When `requires_enforcement` is set and the named tier is `declared`, the
operation is **not included in the active contract**. Requests matching that
operation's path are denied, not silently allowed without the intended checks.

If `requires_enforcement` is omitted, the operation is grantable as soon as
its request shape and transport hygiene are enforced (tier 1).

### Grantability

A contract is only grantable if the enforcement tiers needed for its narrowing
semantics are active. The rule:

> **A contract is grantable when every included operation's
> `requires_enforcement` tier (or `request_shape` by default) is `enforced`.**

This prevents a situation where a category-scoped `read_messages` grant
implies containment that doesn't actually exist at runtime — e.g., the
operator thinks the agent can only read discovered message IDs, but
`state_enforcement` is still `declared` so any `GET /messages/{id}` passes.

If a contract is not yet grantable, the agent's `request-access` call returns
`contract_not_enforceable` with the list of missing enforcement tiers. The
operator is never shown a prompt for a contract SafeYolo cannot enforce.

## Example: Gmail read_messages

A complete contract template for reading messages scoped to a category.

```yaml
capabilities:
  read_messages:
    description: "Read-only access to messages and threads"
    scopes: ["gmail.readonly"]
    routes:
      - methods: [GET]
        path: "/gmail/v1/users/me/messages"
      - methods: [GET]
        path: "/gmail/v1/users/me/messages/*"

    contract:
      template: gmail.read_messages.v1

      bindings:
        approved_category:
          source: agent
          type: enum
          options:
            - CATEGORY_PROMOTIONS
            - CATEGORY_SOCIAL
            - CATEGORY_UPDATES
            - CATEGORY_FORUMS
            - CATEGORY_PERSONAL
          visible_to_operator: true

      state:
        discovered_message_ids:
          type: set
          item_type: string
          max_items: 1000

      operations:
        - name: list_messages
          request:
            method: GET
            path: /gmail/v1/users/me/messages
            transport:
              require_no_body: true
              allow_headers: [Authorization, Accept, User-Agent]
              deny_ambiguous_encoding: true
            query:
              allow:
                labelIds:
                  equals_var: approved_category
                maxResults:
                  integer_range: [1, 100]
                pageToken:
                  type: string
              deny_unknown: true
          response:
            capture:
              - jsonpath: $.messages[*].id
                into: discovered_message_ids

        - name: get_message
          requires_enforcement: state_enforcement
          request:
            method: GET
            path: /gmail/v1/users/me/messages/{id}
            transport:
              require_no_body: true
              allow_headers: [Authorization, Accept, User-Agent]
              deny_ambiguous_encoding: true
            path_params:
              id:
                in_state_set: discovered_message_ids
          response:
            validators:
              - name: category_matches_binding
                jsonpath: $.labelIds[*]
                contains_var: approved_category

      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
        response_validators: declared
```

### What this enforces at each tier

**v1 — request shape + transport hygiene (list_messages only):**

The `get_message` operation declares `requires_enforcement: state_enforcement`,
so it is **excluded from the grantable contract** until tier 3. In v1, the
contract grants list-only access:

- `GET /messages?labelIds=CATEGORY_PROMOTIONS` — allowed
- `GET /messages?labelIds=INBOX` — denied (wrong value, not in enum)
- `GET /messages?labelIds=CATEGORY_PROMOTIONS&q=secret` — denied (unknown param)
- `GET /messages/{id}` — **denied** (operation not yet grantable)
- `POST /messages` — denied (wrong method)
- Request with `X-HTTP-Method-Override` header — denied (not in `allow_headers`)
- Request with double-encoded `%25` in query — denied (ambiguous encoding)

This is honest: the operator approves "list promotions", not "read promotions."
The watch prompt reflects this: `Scope: list messages in CATEGORY_PROMOTIONS`.

**v1.1 — state capture:**

- List responses populate `discovered_message_ids` with returned IDs
- `get_message` is still not grantable (state enforcement not yet active)

**v1.2 — state enforcement + response validators (get_message becomes grantable):**

- `GET /messages/{id}` — allowed only if `{id}` is in `discovered_message_ids`
- Response checked: message's `labelIds` must contain `approved_category`
- A message that was relabelled by another capability would fail response
  validation even if the request was structurally valid
- The contract is now fully grantable with both operations: list messages
  filtered to the approved category, then get individual messages whose IDs
  were returned by list and whose response labels still contain the approved
  category

## Routes vs operations

A capability defines **routes** (method + path pairs). A contract defines
**operations** (method + path + query/body/transport constraints).

For a capability with a contract, both exist. The relationship:

1. **Routes are the coarse first gate.** The existing gateway logic checks
   whether the request matches any route in the granted capability. This is
   unchanged.
2. **Operations refine within routes.** If the request passes the route check
   and a contract is bound, the gateway selects the matching operation and
   enforces its constraints (query params, body fields, transport).
3. **Operations that are not grantable are excluded.** If an operation's
   `requires_enforcement` tier is `declared`, the operation is removed from
   the active contract. Requests matching its path pattern are denied even
   though the route exists in the capability definition.

Operation matching: the gateway selects the **most specific path match** among
grantable operations. If no operation matches, the request is denied (the
contract is an allowlist, not a fallback).

## Transport hygiene

The `transport` block on each operation controls HTTP-level evasion vectors.

### Header allowlist

`allow_headers` is a per-operation list of permitted request headers. Any
header not in the list is rejected. The gateway also accepts headers it injects
itself (e.g., `Host`, `Via`, proxy-internal headers) — these are implicitly
allowed and cannot be set by the agent.

A sensible default for read-only operations:

```yaml
allow_headers: [Authorization, Accept, User-Agent]
```

Write operations may need `Content-Type` and `Content-Length` in addition.

### Canonical form and ambiguity rejection

`deny_ambiguous_encoding: true` means the gateway rejects requests that are
not in canonical form. Specifically:

- **Double-encoded values** — `%252F` instead of `%2F`
- **Mixed encoding** — literal `/` and encoded `%2F` in the same path segment
- **Non-canonical percent encoding** — `%2f` instead of `%2F`
- **Duplicate query parameters** — `?labelIds=X&labelIds=Y`
- **Override directives** — `X-HTTP-Method-Override`, `X-Method-Override`,
  `_method` query parameter

The gateway normalises the request into canonical form *before* evaluating
contract constraints. Anything that doesn't survive round-trip normalisation
is a hard reject.

## Agent API response types

The agent API returns machine-readable decision types so agents can adapt
without turning every miss into an operator interruption:

| Response | Meaning | Agent action |
|----------|---------|-------------|
| `approved` | Capability granted (with or without contract) | Proceed |
| `needs_contract_binding` | Template returned, agent must propose binding values | Submit binding |
| `contract_not_enforceable` | Contract exists but required enforcement tiers are `declared` | Cannot request this capability yet; inform user |
| `denied_out_of_scope` | Binding values are outside the valid set (e.g., not in enum) | Fix values and retry, or request a different capability |
| `denied_scope_escalation` | Request conflicts with current grants (e.g., capability composition risk) | Do not retry; inform user that SafeYolo flagged a conflict |
| `override_required` | Operator must explicitly override a security recommendation | Wait for operator decision; do not re-request |
| `denied` | Policy denial, no override path | Do not retry |

This lets a well-behaved agent distinguish between "fix your request" and
"stop asking" without reading operator-facing prose.

## Capabilities without contracts

Not every capability needs a contract. Simple capabilities where the route list
is sufficient — like `manage_labels` (CRUD on labels, no sensitive content) —
continue to work with today's approve/deny flow.

A capability without a `contract` block is directly approvable. A capability
with a `contract` block triggers the binding challenge flow.

## Relationship to existing concepts

| Existing concept | How contracts extend it |
|-----------------|------------------------|
| Capability routes | Still the first gate — contract enforcement runs after route matching |
| Risky routes | Orthogonal — risky routes trigger per-request approval; contracts scope a capability session |
| `safeyolo watch` | System-authored prompts with binding values, risk assessment, conflict detection; agent free-text excluded |
| Agent API `/gateway/request-access` | New response type: `needs_contract_binding`; new endpoint for binding submission |
| Service YAML | `contract` block added inside capability definitions |

## Implementation sequence

### Tier 1: Request shape + transport hygiene

- Contract template schema in service YAML
- Grantability gate: operations with `requires_enforcement` pointing to
  a `declared` tier are excluded from the active contract
- Agent API: `needs_contract_binding`, `contract_not_enforceable`,
  `denied_out_of_scope`, `denied_scope_escalation`, `override_required`
  response types; binding submission endpoint
- Watch: system-authored approval prompts (no agent free-text), scope
  assessment, conflict detection, override UX for escalations
- Gateway: enforce allowed methods, paths, query params, body fields against
  bound contract; operation matching by most-specific path
- Transport: per-operation `allow_headers` allowlist, request canonicalisation,
  reject double-encoding, duplicate params, method overrides

### Tier 2: State capture

- Gateway maintains bounded per-session state sets
- Response capture rules extract values (e.g., message IDs) into state
- State is visible in diagnostics but not yet used for enforcement
- Operations gated on `state_capture` alone become grantable (e.g., an
  operation that captures IDs for diagnostic logging but does not yet
  enforce `in_state_set` constraints — uncommon, but the tier exists for
  completeness)

### Tier 3: State enforcement + response validators

- Request validation against state sets (`in_state_set`)
- Response validators check structural containment using bound variables
- Enforcement status fields move from `declared` to `enforced`
- Operations gated on `state_enforcement` or `response_validators` become
  grantable (e.g., `get_message` in the Gmail example)

### Future tiers (out of scope)

- Content classification on response bodies (ML/pattern cascade)
- Cross-capability composition analysis
- Sequence rules beyond simple set membership

These are documented in the
[API Capability Contracts exploration](design-api-capability-contracts.md)
but are not part of this design.

## Approval UX trust boundary

The approval prompt is part of the attack surface. A prompt-injected agent
can craft persuasive justifications — "I need full inbox access to finish
summarising promotions" — designed to social-engineer the operator into
approving dangerous capabilities. If SafeYolo relays the agent's reason text
verbatim, the agent gets a trusted voice in the security decision.

### Principle

The operator's decision must be based on **system-computed facts**, not
agent-supplied persuasion. The question is "do I want to override SafeYolo's
computed boundary?", not "does the agent sound convincing?"

### What the agent supplies

The agent's request contains machine-readable fields only:

- **Requested capability** — e.g., `gmail.manage_labels`
- **Proposed binding values** — e.g., `approved_category: CATEGORY_PROMOTIONS`
- **Purpose code** (optional) — audit-only metadata. Machine-readable enum
  from a per-capability allowlist (e.g., `summarise`, `triage`, `search`).
  Validated against the allowlist; invalid codes are rejected. Logged in the
  audit event. Does not affect risk assessment, policy decisions, or
  grantability — it exists purely for post-hoc audit traceability
- **Note** (optional) — short free text, but **never rendered in the approval
  prompt**. Logged for audit only.

### What SafeYolo displays

Every line in the approval prompt is authored by SafeYolo from policy facts:

| Field | Source |
|-------|--------|
| Capability name | Service YAML definition |
| Proposed binding values | Agent request (validated against template schema) |
| Current grants | Session grant state |
| Contract delta | Computed: what changes if this is approved |
| Risk assessment | Computed from capability metadata, ATT&CK tactics, and conflict analysis |
| Scope assessment | Computed: is this inside or outside the current approved scope? |
| Default decision | Policy-derived: deny for out-of-scope, approve for in-scope |

### Automatic deny for out-of-scope escalation

When a request is inconsistent with the current approved scope, SafeYolo
should default to deny without prompting, or prompt with a hard warning:

```
╭──── claude requests manage_labels (gmail) ──────────────────╮
│                                                              │
│  ⚠  SCOPE ESCALATION                                        │
│                                                              │
│  Capability   manage_labels                                  │
│  Current      read_messages (CATEGORY_PROMOTIONS)            │
│  Risk         can relabel messages into readable scope       │
│  Conflict     manage_labels can mutate labels that           │
│               read_messages trusts for scope enforcement     │
│  Default      DENY                                           │
│                                                              │
│  Approving overrides SafeYolo's computed security boundary.  │
╰──────────────────────── [D]eny · [O]verride ────────────────╯
```

Note: the action labels change from `[A]pprove` to `[O]verride` to signal
that the operator is overriding a security recommendation, not making a
routine decision.

### Why agent free-text is excluded

1. **Prompt injection is the threat model.** A compromised agent is
   indistinguishable from a legitimate one at the text level. Persuasive
   language is the attack vector.

2. **The operator cannot verify claims.** "I need X to complete your task" is
   unfalsifiable in the moment. The operator has no way to check whether the
   agent actually needs the capability or is being manipulated.

3. **System-authored text is auditable.** Every field in the prompt can be
   traced to a policy fact. Agent free-text cannot.

4. **Purpose codes are sufficient.** If the agent's intent matters for the
   decision, it should be expressed as a machine-readable purpose code that
   SafeYolo can validate against policy — not as prose.

### Audit trail

The agent's raw `reason` and `note` fields are logged in the audit event but
never displayed in the approval UX. This preserves forensic value (what did the
agent claim?) without giving it influence over the decision.

## Open questions

1. **Session boundaries.** Bindings and state are session-scoped, but "session"
   is undefined. Candidates: agent container lifetime, proxy restart, explicit
   agent signal, time-based expiry. Container lifetime is the simplest and
   matches the current grant model. Needs a decision.

2. **Binding amendment.** Can the agent request a broader scope mid-session
   (e.g., add a second category)? Or must it submit a new binding and get fresh
   approval? New binding is simpler and safer.

3. **Template versioning.** When a contract template changes (new fields, new
   operations), what happens to active sessions bound to the old version? Session
   scope makes this mostly a non-issue — new sessions get the new template.

4. **Operator defaults.** Should contract templates support default bindings that
   the operator can accept without modification? E.g., `approved_category`
   defaults to `CATEGORY_PROMOTIONS` if that's the common case.

5. **Escape hatch.** `full_access` capability has no contract — it grants
   unrestricted access to all routes. This is the explicit "I trust this agent"
   path. Should there be a confirmation step that's more prominent than a
   standard approval?

6. **Block response detail for contract violations.** When a request fails
   contract enforcement, the response should include a coarse machine-readable
   code — enough for a good agent to back off or correct obvious mistakes, not
   enough to make the contract a probing oracle. Likely format: existing block
   response extended with `reason: contract_violation`, `operation: list_messages`,
   `field: labelIds` (the failing field name), but **not** the expected value or
   the full constraint. This lets an agent that sent `labelIds=INBOX` understand
   "labelIds was wrong" without learning which values would pass.
