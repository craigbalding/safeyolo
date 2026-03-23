# Service Gateway v2 — Design

## Status

Design document. Agreed 2026-03-23.

Supersedes the current role-based service gateway design (v1).

Companion documents:
- [Service YAML Spec](service-gateway-v2-yaml-spec.md) — schema reference,
  full examples, ATT&CK vocabulary
- [Implementation Plan](service-gateway-v2-implementation.md) — build order,
  file changes, migration, staging

## Motivation

The v1 service gateway uses **roles** with hard allow/deny route rules.
This has three problems:

1. **Deny rules assume persona.** Blocking `/settings/filters` makes sense
   when the credential belongs to the operator (exfiltration risk), but not
   when it's the agent's own account. The risk is context-dependent, not
   absolute.

2. **Roles are just broad capabilities.** A `readonly` role is structurally
   identical to a `search_issues` capability — the only difference is glob
   width. Two concepts for the same thing creates confusion.

3. **No runtime approval for risky actions.** An agent either has access or
   doesn't. There's no middle ground where the agent can attempt a risky
   action with operator oversight.

## Architecture

```
Service YAML          Policy                          PDP
┌──────────────┐     ┌─────────────────────┐     ┌──────────────┐
│ capabilities │     │ risk appetite       │     │ context-aware│
│ risky routes │────▶│ redirect policy     │────▶│ risk decision│
│ auth config  │     │ agent trust levels  │     │ + response   │
└──────────────┘     └─────────────────────┘     └──────────────┘
                                                        │
                                                        ▼
                                                 ┌──────────────┐
                                                 │   Gateway    │
                                                 │  enforces    │
                                                 └──────────────┘
                                                        │
                                                        ▼
                                                 ┌──────────────┐
                                                 │    Watch     │
                                                 │  approval UX │
                                                 └──────────────┘
```

**Service YAML** = declarative facts. What the API offers, what's risky,
how to authenticate.

**Policy** = authoritative appetite. Operator's risk posture. Cannot be
weakened by service files.

**PDP** = contextual decisions. Resolves service facts against policy
appetite with runtime context (agent identity, credential ownership,
recent activity).

**Gateway** = enforcement. Routes, credentials, redirects.

**Watch** = operator UX. Approval prompts driven by PDP decisions.

## Key Design Decisions

### 1. Capabilities replace roles

Everything is a **capability** — a named set of allowed routes. Some are
narrow (`search_issues`), some are broad (`full_access`). No structural
difference. The operator grants whichever fits their trust level.

Capability routes are a positive list. No `effect: allow/deny`. The old
`deny` concept is replaced by risky routes.

### 2. Agent-initiated access requests

The primary control surface. Agents request access with a **reason** and
proposed lifetime. The operator approves in watch with full context.

**Discovery**: `GET /gateway/services` returns authorized capabilities and
available services.

**Request**: `POST /gateway/request-access` with service, capability,
reason, and proposed lifetime. Returns 202 — queued for operator approval.

**Why reasons matter**: The reason gives the operator task context for the
decision. It creates an audit trail. If the agent was prompt-injected, the
reason may reveal the manipulation.

**Passive fallback**: When an agent hits a risky route without requesting
access first, the gateway does NOT prompt the operator to decide without
context. Instead:

1. Gateway returns 428 with reflection — prompts the agent to question its
   intent and submit a proper request if genuine.
2. Watch informs the operator: "boris is attempting to [route description]
   without submitting an approval request. Prompting boris to reflect and
   request approval if genuinely needed."
3. The operator is **not asked to decide** until the agent submits a reason.

Repeated unapproved attempts without follow-up requests are a signal —
possible prompt injection or misconfiguration.

### 3. Risky routes declare facts, not risk levels

Service files don't assign subjective labels like `elevated` or `critical`.
Risk is in the eye of the beholder — it depends on whose account, which
agent, what task.

Instead, risky routes declare **factual signals**:

- **`tactics`**: MITRE ATT&CK tactics this route implements (`collection`,
  `exfiltration`, `persistence`, `credential_access`, etc.)
- **`enables`**: What further attack stages this unlocks (the chain —
  reading email *enables* credential access)
- **`irreversible`**: Whether the action can be undone
- **`description`**: The "so what" — human-readable security consequence

Policy expresses the operator's **risk appetite** using these signals:
"require approval for any route with `enables: [credential_access]` on
operator-owned credentials" or "block `irreversible` actions without
typing 'yes'".

### 4. Route groups

Complex APIs can have dozens of risky routes. Groups cluster related routes
so operators can reason about them at a glance:

- Group carries shared tactics/enables/description
- Watch shows group summary by default, drill-in for per-route detail
- Policy can target groups
- Individual routes can override group signals

### 5. Service files are advisory, policy is authoritative

A malicious service file can omit risky routes or understate signals.
Policy floor rules catch this: "anything tagged `exfiltration` always
requires approval, regardless of what the service file says." Service files
enrich the operator's decision — they cannot weaken protections.

### 6. Account persona

The same service has completely different risk profiles depending on whose
account the credential belongs to. Reading email on the agent's own account
is routine. Reading the operator's inbox enables account takeover. Reading
a team support queue is low-risk but sending as the team is customer-facing.

Persona is declared at **binding time** — when the operator grants access
in watch or via `agent authorize`, they label the account:

- `agent` — the agent's own account. Least restrictive.
- `operator` — the operator's personal account. Most restrictive.
- Custom labels (`team-support`, `billing`, etc.) — operator-defined, with
  matching policy rules.

Persona flows through to the PDP as a first-class field in the evaluation
event. The PDP resolves the same risky route signals to different decisions
based on persona:

- `collection` + `enables: [credential_access]` + persona `operator`
  → require approval (password resets, 2FA in inbox)
- `collection` + `enables: [credential_access]` + persona `agent`
  → allow (it's the agent's own email)
- `impact` (sending email) + persona `team-support`
  → require approval (customer-facing)

Without persona, the PDP must treat every account the same — which is
exactly the v1 problem.

### 7. Auth model

Auth mechanics at service level (how to inject credentials). Optional
capability-level credential binding for operators who want least privilege.

A god-level token behind gateway enforcement is a valid posture — the
gateway limits what the agent can reach. Scoped tokens add defence in depth.
The UX frames this as a maturity signal, not a warning.

### 8. Redirect policy

Default deny — the gateway does not follow redirects. Prevents scope bypass,
open redirects, confused deputy attacks.

Override tiers:
- **Route pair**: specific known redirect (`/v1/x` → `/v2/x`). Permanent.
- **Same-host**: for major API migrations. Time-bound — watch re-prompts
  before expiry.
- **Cross-host**: never via policy. Service file change required.

Followed redirects still get full route evaluation.

### 9. Once = one successful response

A "once" lifetime means one 2xx response, not one attempt. 4xx (agent
fumbling with API) and 5xx (server errors) release for retry. Serialised
in-flight per grant to prevent timing attacks. Requires a `response()` hook
in the gateway.

### 10. Approval scope

Approval grants the **specific method + path** requested, not the risky
rule's glob. Approving `POST /settings/filters` does not unlock
`POST /settings/forwardingAddresses`.

## Security Properties

- **Defence in depth**: capability routes → risky route approval →
  credential scoping (optional). Three independent layers.
- **Facts vs appetite**: service files declare what routes can do. Policy
  says what the operator tolerates. PDP resolves in context.
- **Policy over service files**: floor rules ensure minimum protections
  regardless of service file content.
- **ATT&CK vocabulary**: industry-standard, familiar, googlable.
- **Redirect safety**: default deny, scoped overrides, time-bound.
- **Once means once**: timing-attack resistant. Only 2xx consumes.
- **Account persona**: same service file, different decisions based on
  whose account (agent's own, operator's personal, team functional).
  Persona declared at binding time, flows through to PDP.
- **Agent reflection**: block responses prompt security self-check before
  process guidance.
- **Route groups**: complex APIs stay manageable for operators.
- **Reason-first approvals**: operators never decide without context.
  Passive fallback informs but doesn't prompt.

## Future Work (v2.1+)

### Unknown service credential detection

When an agent makes an authenticated request to a host with no service
file, the system should detect and triage:

- **Operator-provided credential**: operator pasted a key into the agent's
  chat. Nudge toward vaulting — "Let's rotate the original and manage this
  through the gateway."
- **Agent-acquired credential**: agent signed up for a service
  autonomously. Security event — operator needs immediate awareness.
- **Hallucinated credential**: agent fabricated an auth header. Credential
  guard catches pattern-matching cases; unknown formats need heuristics.

The watch prompt would ask: "Did you provide this credential?" with options
to vault it (rotate original, gateway-manage), block (revoke and deny), or
allow once. This shapes operator behaviour toward managed credentials.

Detection of autonomous sign-ups (new credential type + unknown host +
no prior operator interaction) is a heuristic signal worth exploring.

### Security maturity nudges

After observed usage stabilises, suggest credential scoping based on
actual capability usage patterns. "boris only used search_issues and
create_pr over 30 days. Here's how to create two fine-grained PATs."

### Parameter-aware route matching

Path-only matching covers REST APIs but is blind to query parameters and
request bodies. GraphQL, RPC-style APIs, and APIs with meaningful query
parameters need deeper matching. A future `match` field on routes adds
conditions on query params and body fields without breaking existing
path-based rules. See [YAML Spec — Future Schema Extensions](service-gateway-v2-yaml-spec.md#future-schema-extensions).

### Response tokenisation

The gateway can transform responses before the agent sees them — redact
PII, swap real names for synthetic values. The agent works with enough
data to complete tasks without accessing sensitive content. A future
`response_policy` field on capabilities with consistent tokenisation
(same input → same synthetic output) and redaction. See [YAML Spec](service-gateway-v2-yaml-spec.md#future-schema-extensions).

### Posture dashboard

`safeyolo status` shows per-service security posture:
`github: gateway-enforced ✓ | credential-scoped: not yet`

Neutral framing — maturity signal, not a warning.
