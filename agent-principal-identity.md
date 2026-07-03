# SafeYolo Agent Principal Identity

## Summary

SafeYolo currently uses agent names as plain strings across config, policy, audit logs, and runtime request handling. That works, but it has a security smell: a string that came from trusted runtime attribution can look identical to a string supplied by an agent or CLI request.

SafeYolo should distinguish:

- runtime identity attestation
- durable agent identity
- untrusted agent-name references

Because SafeYolo is a small, solo-maintained project, this should be treated as a core refactor rather than deferred polish or a compatibility migration. New features should not add more raw-string identity plumbing, and existing security-sensitive paths should move to typed principals as part of the same architectural cleanup.

The target is not "strings now, principals later." The target is `AgentPrincipal` from the start of the refactor, SafeYolo-wide.

## Current Model

At runtime, agent traffic reaches mitmproxy through a per-agent Unix domain socket.

The socket filename encodes the attribution tuple:

```text
<attribution-ip>_<agent-name>.sock
```

`UnixInstance` / service discovery use that path to stamp flows with an agent name. That path is the runtime identity anchor. Request JSON, headers, `AGENT_IP`, and guest-controlled values are not identity anchors.

The agent name is also used as the human and policy handle:

- `safeyolo agent add cody ...`
- `[agents.cody]` policy sections
- `agent_map.json`
- audit `agent` fields
- watch display
- plumb participant lists

Those are related but not the same thing.

## Problem

Once runtime attribution resolves to `"cody"`, code tends to pass that value around as a bare string. Later, another bare string `"cody"` may come from request JSON, CLI input, a policy file, or storage.

Regex validation helps with boundary hygiene, but it does not prove identity. A string matching the agent-name regex is only well-formed, not trusted.

The risk is not only spoofing. It is also accidental confusion between:

- the caller proven by the per-agent ingress
- a target agent name requested by an untrusted caller
- a stored policy principal
- a displayed audit label

Plumb makes this more visible because the sender is trusted attribution, while participants are caller-requested references that must be resolved by the host.

## Proposed Model

Introduce a typed principal object for trusted runtime identity and use it as the internal identity currency across SafeYolo:

```python
from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class AgentPrincipal:
    name: str
    source: Literal["uds"]
    attribution_ip: str | None = None
    agent_id: str | None = None
```

Initial fields:

- `name`: canonical SafeYolo agent name, suitable for policy lookup and audit display.
- `source`: identity source. For today this is `uds`; future sources can be explicit.
- `attribution_ip`: the synthetic source IP or label associated with the per-agent ingress.
- `agent_id`: durable registry identity if SafeYolo chooses to mint one at `safeyolo agent add`.

The important property is that application code can tell the difference between a trusted principal and an untrusted string. After ingress resolution, security-sensitive code should accept `AgentPrincipal`, not raw agent-name strings.

## Resolution Rules

### Sender

Sender identity is resolved exactly once at the ingress boundary:

```python
sender = resolve_agent_principal(flow)
```

That resolver uses service discovery / UnixInstance attribution only. It never uses request JSON, headers, guest environment, or `AGENT_IP`.

If sender attribution is unknown, the request fails closed.

### Targets

Targets start as untrusted strings:

```python
raw_targets = body["participants"]
```

The host resolves them:

```python
targets = resolve_agent_targets(raw_targets)
```

Resolution should:

- validate name syntax
- verify the target exists in the host agent registry or current agent map
- apply discovery/collaboration policy
- reject unknown, malformed, duplicate, or over-limit requests
- return canonical target identities or canonical names

The caller never gets to assert that a target exists or that a sender is someone else.

## Plumb Example

Preferred shape:

```python
sender = resolve_agent_principal(flow)
targets = resolve_agent_targets(body.get("participants", []), requester=sender)

svc.request_chat(
    requester=sender,
    targets=targets,
    purpose_code=body.get("purpose_code"),
    note=body.get("note"),
    ttl_seconds=body.get("ttl_seconds"),
)
```

Avoid:

```python
svc.request_chat(
    requester="cody",
    participants=["web"],
)
```

The latter loses the trust distinction. It cannot tell whether `"cody"` came from attribution or from JSON.

## Agent Name Validation

SafeYolo should still validate agent names with the existing RFC 1123-style regex:

```text
^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$
```

But validation only means:

- the name is syntactically safe
- the UDS filename remains unambiguous
- config paths and policy keys are predictable
- terminal/log rendering is less risky

Validation does not make a string a trusted identity.

## Durable Identity

The UDS filename is a runtime proof of the current connection. It is not necessarily a durable identity across lifecycle events.

Today, SafeYolo treats agent name as the durable policy principal. That is probably acceptable for now.

If SafeYolo later needs to distinguish:

- old `cody` removed
- new `cody` created with different config
- restored `cody` from snapshot

then the agent registry should assign a stable `agent_id` or generation ID and include it in `AgentPrincipal`, grant records, and audit details.

This can be added without changing the core rule: runtime sender identity still comes from trusted ingress attribution.

## Implementation Direction

The refactor should be SafeYolo-wide, not plumb-only:

- `AgentPrincipal` in a small identity module.
- `resolve_agent_principal(flow)` helper shared by AgentAPI, gateway, credential guard, flow inspection, and plumb.
- `resolve_agent_targets(...)` helper for host-side target resolution.
- Tests proving JSON/header supplied sender fields are ignored.
- Tests proving malformed, unknown, duplicate, and over-limit target references are rejected.
- Audit details that can include both `agent` display name and optional `agent_id`.

Do not implement this by threading more parallel strings through the system. The goal is fewer ambiguous strings, not more.

Refactor scope:

1. Add `safeyolo.core.identity` with `AgentPrincipal`, name validation, sender resolution, and target resolution.
2. Convert the trusted ingress paths to return `AgentPrincipal` immediately, starting with AgentAPI/service discovery and the proxy paths that currently stamp `flow.metadata["agent"]`.
3. Convert security-sensitive consumers in the same refactor: plumb, service gateway, credential guard, flow-search scoping, diagnostic APIs, and admin/watch approval plumbing.
4. Keep raw strings only at external boundaries: CLI input, JSON request bodies, policy files, config files, persisted audit records, and display output.
5. Resolve those raw strings into `AgentPrincipal` or explicit target references before they enter trusted internal logic.
6. Decide whether to mint a durable `agent_id` during `safeyolo agent add`. If yes, include it in the principal and in runtime maps from the start rather than layering it on later.

This does not require changing every file format at once. Policy keys, audit display fields, and config sections can remain canonical agent names at the boundary. The important change is internal: after ingress, trusted sender identity is carried as `AgentPrincipal`, while JSON/config/CLI references remain untrusted strings until resolved.

Avoid a transitional design where new code accepts both `AgentPrincipal` and raw `str` for trusted callers. That kind of compatibility shim preserves the ambiguity the refactor is meant to remove.

## Security Rule

Well-formed strings are references.

Only host-resolved principals are identities.
