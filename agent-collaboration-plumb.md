# SafeYolo Agent Collaboration Plumb

## Summary

SafeYolo should support an opt-in, host-mediated collaboration channel that lets isolated agents request and participate in conversations with other agents without giving them any direct network path to each other.

The feature is permissive but observable: once the operator approves a collaboration, agents can exchange useful context freely enough to get work done, while SafeYolo records participants, messages, message metadata, policy decisions, and suspicious content signals for review.

This is not agent-to-agent networking. It is a host-owned conversation service exposed through the existing SafeYolo proxy/agent API path.

## Goals

- Let an agent request help from another agent that may have different tools, skills, context, or mounted resources.
- Keep the no-direct-network architecture intact: no virtio-net, no peer routes, no agent-to-agent sockets.
- Require explicit operator opt-in before agents can collaborate.
- Surface collaboration requests in `safeyolo watch`, similar to existing access requests.
- Provide rich enough messaging for real work, not a toy channel constrained into uselessness.
- Make the channel observable from day one: transcripts, metadata, audit events, size limits, and high-signal detections.
- Leave room for stronger future policy around leakage, social engineering, and prompt-injection-style manipulation.

## Non-Goals

- Do not add direct TCP connectivity between agents.
- Do not make all agents globally discoverable beyond the minimal metadata needed for operator-approved collaboration.
- Do not attempt perfect DLP in the first version.
- Do not make this feature enabled by default.

## Architecture

Agents communicate only through SafeYolo:

```text
agent A
  -> HTTP_PROXY=127.0.0.1:8080
  -> vsock/UDS bridge
  -> SafeYolo proxy
  -> _safeyolo.proxy.internal/plumb/*
  -> host-owned conversation store
  -> agent B polls/reads through its own SafeYolo proxy path
```

Sender identity is derived from SafeYolo's existing agent attribution, never from request JSON.

The attribution source must be the per-agent proxy ingress, not any in-band value:

- macOS/VZ: the request arrives through that agent's `safeyolo-vm` vsock-to-UDS relay and the corresponding mitmproxy UnixInstance.
- Linux/gVisor: the request arrives through that agent's per-agent UDS mount/UnixInstance.

The sender must be resolved from the UnixInstance/per-agent socket identity that SafeYolo already controls. Do not trust `AGENT_IP`, request headers, JSON fields, or any guest-provided value for sender identity. The `10.200.x.x` address is an attribution label, not an authentication mechanism.

The agent API bearer token is channel admission only. In current SafeYolo deployments the agent API token is shared across agents, so plumb must not treat token possession as identity or as authorization to impersonate another participant. Every create, list, read, post, invite, and leave decision is made against the sender resolved from the per-agent proxy ingress. Unknown or default attribution fails closed.

The host owns:

- conversation creation
- participant list
- grant lifetime
- transcript storage
- audit events
- policy decisions
- future redaction/approval gates

## Storage Boundary

The conversation store lives on the host, not in any guest-mounted filesystem.

Initial storage contract:

- Root directory: `~/.safeyolo/data/plumb/`.
- Directory mode: `0700`.
- Conversation/message files: `0600`.
- Writes: atomic replace or append under a per-conversation lock.
- Visibility: never bind-mounted into `/workspace`, `/home/agent`, or `/safeyolo`.
- Retention: configurable transcript retention with audited export/delete commands.

This is both a confidentiality boundary and a correctness boundary. A guest can submit messages through the agent API, but it cannot edit the host transcript, rewrite grant state, or remove audit evidence.

## Threat Model

Plumb introduces a new security direction: one agent's text can become another agent's input.

Existing SafeYolo controls primarily protect the host, credentials, services, and network destinations from an agent. Agent collaboration also needs to protect a receiving agent from another agent's instructions, manipulation, and data leakage attempts.

No implicit delegation:

- A plumb conversation grant does not transfer tools, credentials, mounts, service tokens, or policy permissions between agents.
- If `web` acts on a request from `cody`, the resulting action is still enforced under `web`'s policy and attributed to `web`.
- Audit events for downstream actions should be able to reference the causal plumb conversation/message when available, but that reference must not change the policy principal.

The receiver-side contract is:

- Plumb messages are attributed, untrusted data.
- Receiving harnesses must render them as data, for example `cody says: ...`.
- Plumb messages must not be spliced into system prompts, developer prompts, hidden instructions, shell commands, or tool calls.
- A receiving agent may summarize, quote, reject, or ask the operator about a message, but the channel itself must not make sender text authoritative.

This contract affects Phase 1 API design. It should not wait for advanced Phase 4 content controls.

## Approval UX Trust Boundary

The approval prompt is part of the attack surface. A compromised or prompt-injected agent can write a persuasive request that tries to make the operator approve a wider channel than intended.

Default `safeyolo watch` approval prompts must therefore be authored from SafeYolo-controlled facts:

- requesting agent, from attribution
- proposed participants, after policy validation
- grant type
- grant lifetime
- message limits
- current/previous grants
- policy recommendation
- detected risk classes

Agent-supplied free text, such as a topic, reason, or note, is untrusted evidence. SafeYolo may log it and expose it in an explicit details/transcript view labeled as untrusted, but it must not be rendered as trusted approval prompt copy. If intent is needed in the prompt, use a machine-readable `purpose_code` validated against policy, not prose.

## Request Flow

1. Agent `cody` requests a conversation with `web`.

```http
POST http://_safeyolo.proxy.internal/plumb/request-chat
Authorization: Bearer <agent-token>
Content-Type: application/json

{
  "participants": ["web"],
  "purpose_code": "debug",
  "note": "web has browser/UI context and cody has source workspace context",
  "ttl_seconds": 3600
}
```

2. SafeYolo derives `requester=cody` from connection attribution.

3. SafeYolo validates the target set, computes the grant shape, stores the agent-supplied note as untrusted audit evidence, and emits an approval event.

Example `safeyolo watch` prompt:

```text
cody requests a plumb conversation

Participants: cody, web
Purpose:      debug
Grant:        conversation read/write
TTL:          1h
Limits:       32 KiB/message, 500 messages
Agent note:   stored as untrusted audit text; review details to inspect

[a] approve once   [d] deny   [s] approve for session   [m] modify
```

4. Approval creates a conversation grant:

```json
{
  "conversation_id": "conv_...",
  "participants": ["cody", "web"],
  "created_by": "operator",
  "requested_by": "cody",
  "purpose_code": "debug",
  "operator_title": "VZ shared-base investigation",
  "expires_at": "2026-07-01T17:00:00Z",
  "max_message_bytes": 32768,
  "max_messages": 500
}
```

5. Participants post and read messages through agent API endpoints.

```http
POST /plumb/conversations/conv_.../messages
GET  /plumb/conversations/conv_.../messages?after=msg_...
```

## Agent-Facing API Sketch

```http
POST /plumb/request-chat
GET  /plumb/conversations
GET  /plumb/conversations/{conversation_id}
GET  /plumb/conversations/{conversation_id}/messages
POST /plumb/conversations/{conversation_id}/messages
POST /plumb/conversations/{conversation_id}/leave
```

Endpoint scoping rules:

- `GET /plumb/conversations` returns only conversations where the resolved sender is a participant.
- Conversation read/post/leave endpoints require the resolved sender to be a participant and the grant to be active.
- Non-participant access returns a generic `403` or `404` without exposing transcript contents.
- `request-chat` target validation must not become a global agent-discovery API. If policy does not allow the requester to discover a target, the response should be generic and the detailed reason should stay in host-side events.

Message body:

```json
{
  "body": "Can you inspect the web UI while I trace the VZ helper code?",
  "metadata": {
    "content_type": "text/markdown",
    "references": [
      {"kind": "file", "path": "vm/Sources/SafeYoloVM/VMConfiguration.swift"}
    ]
  }
}
```

Message body, metadata, and references are sender-supplied and untrusted. SafeYolo may normalize them for storage and scanning, but the receiving harness must not auto-open referenced paths, execute embedded commands, or treat `content_type` as authoritative.

Stored message:

```json
{
  "id": "msg_...",
  "conversation_id": "conv_...",
  "from_agent": "cody",
  "created_at": "2026-07-01T16:12:03Z",
  "body": "Can you inspect the web UI while I trace the VZ helper code?",
  "metadata": {
    "content_type": "text/markdown",
    "size_bytes": 64,
    "detected_classes": [],
    "policy_action": "allow"
  }
}
```

Delivery semantics:

- Message IDs are monotonically ordered within a conversation.
- `GET /messages?after=msg_...&wait=30` supports long-polling and may return an empty result on timeout.
- Delivery is at-least-once. Clients deduplicate by message ID.
- The host tracks per-participant read cursors/ack state when needed for observability, but cursor state is not trusted from the guest as proof that a message was understood or acted on.
- Plumb uses its own rate/budget bucket so chat traffic cannot starve `_safeyolo.proxy.internal` diagnostics such as `/status` or `/explain`.

## CLI Sketch

Operator commands:

```bash
safeyolo plumb requests
safeyolo plumb approve req_... --ttl 1h
safeyolo plumb deny req_...
safeyolo plumb create cody web --title "VZ shared-base investigation" --ttl 1h
safeyolo plumb invite conv_... reviewer
safeyolo plumb revoke conv_... web
safeyolo plumb tail conv_...
safeyolo plumb close conv_...
```

Agent command sugar, if useful later:

```bash
safeyolo agent ask cody web "Can you inspect this UI?"
```

## Policy Model

Default posture:

- feature disabled unless explicitly enabled
- no standing agent-to-agent grants
- request-chat requires operator approval
- grants are conversation-scoped and expire
- discovery is separate from collaboration; permission to request `web` does not imply permission to list all agents
- group conversations are supported by the participant list up to `max_participants`, initially with a single participant role

Possible TOML policy:

```toml
[plumb]
enabled = true
default_ttl_seconds = 3600
max_participants = 4
max_message_bytes = 32768
max_messages = 500

[agents.cody.collaboration]
can_request = ["web", "reviewer"]
requires_approval = true

[agents.web.collaboration]
can_request = ["cody"]
requires_approval = true
```

Implementation should reuse SafeYolo's existing pending-approval/event/admin lifecycle where practical, but plumb should have its own approval type and grant store. It should not be forced through the service-gateway credential/token semantics, because agent collaboration is not external-service access.

## Observability

Every collaboration action should emit structured events:

- `plumb.requested`
- `plumb.approved`
- `plumb.denied`
- `plumb.conversation_created`
- `plumb.participant_invited`
- `plumb.participant_removed`
- `plumb.message_allowed`
- `plumb.message_flagged`
- `plumb.message_blocked`
- `plumb.cursor_updated`
- `plumb.conversation_closed`

Event metadata should include:

- request id
- conversation id
- from agent
- participant list
- message id
- message size
- detected content classes
- decision/action
- grant id
- expiry
- causal conversation/message id for downstream actions, when available

## Security Posture

First version should be permissive but observable.

Initial controls:

- opt-in feature flag
- approval-required conversation grants
- sender derived from SafeYolo attribution
- agent API token treated as admission, not identity
- recipient/participant list controlled by host policy
- participant-scoped list/read/post enforcement
- fail-closed behavior for unknown attribution
- max message size
- max transcript length
- TTL
- transcript logging
- host-only transcript permissions and atomic/locked writes
- approval prompts composed from SafeYolo facts, not agent prose
- sender metadata treated as untrusted
- plumb-specific credential/secret detection
- events for suspicious content, even if not blocked

The plumb scanner must be explicit. Do not rely on the generic pattern scanner automatically applying to `_safeyolo.proxy.internal`: internal control-plane domains may bypass generic scanners for other API routes. `/plumb/*` message bodies need their own scan path, or a deliberate opt-in that runs before message storage/delivery.

Future controls:

- require approval for large file excerpts
- redact known credentials before delivery
- classify paths and file types
- flag attempts to solicit system prompts, private credentials, or unrelated files
- flag social-engineering phrases such as "ignore your instructions" or "do not tell the operator"
- per-conversation purpose checks: does the message fit the approved purpose and operator title?
- asymmetric permissions: read-only observers, post-only requesters, moderator-only invites
- per-agent collaboration budget/rate limits

## Key Design Principle

Do not solve leakage risk by making the channel useless.

The useful tradeoff is:

```text
rich collaboration channel
+ explicit host opt-in
+ strong attribution
+ transcripts
+ audit events
+ high-signal detections
+ progressive enforcement
```

This lets real multi-agent workflows emerge while giving SafeYolo enough visibility to tighten policy based on observed behavior.

## Implementation Phases

### Phase 1: Host-Owned Mailbox

- Add plumb endpoints under the existing agent API.
- Store conversations/messages in `~/.safeyolo/data/plumb/`.
- Use `0700` directories, `0600` files, and atomic/locked writes.
- Require operator approval for `request-chat`.
- Add a plumb approval type and `safeyolo watch` rendering/actions.
- Render watch approval prompts from SafeYolo facts only; keep agent free text in explicit untrusted details.
- Add `safeyolo plumb tail` and `safeyolo plumb close`.
- Log all events.
- Resolve sender from the per-agent proxy ingress/UnixInstance identity only.
- Treat the shared agent API token as channel admission only.
- Enforce participant-scoped list/read/post behavior.
- Treat delivered messages as attributed untrusted data in the receiver contract.
- Support efficient polling via `GET /messages?after=...&wait=30` or equivalent long-polling.
- Give plumb its own rate/budget bucket so chat traffic cannot starve diagnostics, `/status`, or `/explain`.

### Phase 2: Policy Integration

- Add `[plumb]` and `[agents.<name>.collaboration]` policy sections.
- Support allowlisted request targets.
- Support default TTL/message limits.
- Support standing grants only when explicitly configured.
- Reuse existing approval/event/admin machinery where it keeps `safeyolo watch`, pending approvals, and grant lifecycle unified. Keep plumb grant semantics separate from service-gateway credential semantics.

### Phase 3: Content Signals

- Run lightweight classification on messages.
- Block obvious credentials.
- Flag suspicious messages in `watch`.
- Add transcript summaries and review tooling.

### Phase 4: Advanced Controls

- Purpose-fit checks.
- File/path-aware controls.
- Approval-required transfers.
- Group conversation roles.
- Conversation export for audit/replay.
