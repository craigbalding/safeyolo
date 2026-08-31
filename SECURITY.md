# Security

SafeYolo is a human-centric security control point for AI agents.

Agents need controls that prevent accidents and limit the effects of prompt
injection or malicious behavior. SafeYolo sits between agents and external
systems. It gives the operator scoped control over local-data mounts and remote
services, and it fails closed when a request is ambiguous or outside policy.

## Security Model

```
┌──────────────────────────────────────────────────┐
│ HOST (trusted)                                   │
│  You: policy, approvals, config                  │
├──────────────────────────────────────────────────┤
│ SAFEYOLO (enforcement point)                     │
│  Policy evaluation, access control, credential   │
│  protection, capability contracts, audit          │
├──────────────────────────────────────────────────┤
│ AGENT CONTAINERS (untrusted)                     │
│  Network-isolated, no direct internet,            │
│  no inter-agent access                            │
├──────────────────────────────────────────────────┤
│ EXTERNAL SERVICES                                │
│  Reachable only through SafeYolo policy           │
└──────────────────────────────────────────────────┘
```

- **Host** is the trust root. You run the CLI, own config, and control the sandbox runtime (Apple Virtualization.framework on macOS, gVisor on Linux).
- **SafeYolo** enforces your policy — a host mitmproxy process, no privileged runtime, no host filesystem access beyond your explicit mounts, runs as your uid.
- **Agent sandboxes** have no direct internet access. Their only route to the outside world is through SafeYolo's policy enforcement.
- **External services** are reachable only if policy explicitly permits the destination.

## Core Security Properties

### Minimize trust

Grant the minimum access required. Agents run in isolated sandboxes with no
external network interface. SafeYolo runs mitmproxy as an unprivileged host
process. The Admin API binds directly to `127.0.0.1` and does not perform
hostname or reverse-DNS resolution. The host-local boundary and proxy readiness
therefore do not depend on the host resolver. The Admin API also requires a
bearer token and compares it with `secrets.compare_digest`. Host processes run
as the operator's user ID. On Linux, `safeyolo agent run` does not use host
`sudo`.

### Fail closed

When uncertain, block. Unknown credentials trigger an approval workflow, not silent passthrough. Destination mismatches return HTTP 428 with actionable feedback. Invalid policies are rejected at load time. The startup script verifies block mode before accepting traffic.
The Agent API virtual hostname is also contained independently of its handler.
An adjacent request guard runs before policy, credential, and observability
addons, so a missing, disabled, import-failed, or uncaught handler receives a
local diagnostic 5xx without exposing its bearer token or query downstream. A
separate final transport guard refuses the reserved destination before DNS or
an upstream connection.

### Human-governed access

You decide what gets through. SafeYolo enforces your decisions — agents request access, you approve or deny, and the policy builds up from there.

Think of agents like an eager intern: confident, fast, helpful, and occasionally wrong in ways that matter. An intern might email the wrong client or paste credentials into a public channel — not malicious, just moving fast without experience. AI agents have the same failure mode. SafeYolo ensures a human is in the loop for trust decisions, while giving agents clear machine-readable feedback (HTTP 428) so they can self-correct obvious mistakes without operator intervention.

Service capabilities scope what an agent can do within a service. Risky routes (destructive actions, data export, privilege changes) require explicit operator approval, with irreversible actions demanding typed confirmation. Grants can be scoped to once, session, or remembered.

### Auditability

Behind the scenes, every request gets a unique ID. Every security decision — credential detection, policy evaluation, gateway enforcement — is logged to structured JSONL with the reasoning: what was detected, where it was going, what the policy said, and what happened. The `watch` command gives operators a real-time view of all decisions.

## Enforcement Layers

**Granting agents access to your online data.**
Agents call APIs on your behalf, but not every operation carries the same risk. Services are described in terms of capabilities — named groups of related operations like "manage categories" or "read feeds." You grant specific capabilities to each agent; everything else in that service is off-limits. Within a granted capability, a contract constrains exactly which endpoints, methods, and parameters the agent can use. Actions flagged as risky — deleting data, bulk export, changing permissions — require your approval, which you can scope to once, for the session, or permanently. Service files are generated from API specifications and ship with SafeYolo — you don't need to write them yourself, but you can if you like. If a service you use isn't covered yet, open a [GitHub issue](https://github.com/craigbalding/safeyolo/issues) or submit a PR.

**Credential isolation.**
The service gateway keeps vaulted service credentials outside the agent
environment. An agent sends a request with a scoped gateway token. After policy
authorizes that request, the host proxy replaces the token with the vaulted
credential.

Credential injection requires HTTPS by default. A service YAML file can opt in
to plain HTTP with `auth.allow_http: true` only for a backend that the operator
asserts is reachable through trusted transport, such as a tailnet, WireGuard,
private VLAN, or same-host loopback. The gateway does not verify that transport
claim. Every HTTP injection under this flag emits a
`gateway.http_injection_allowed` audit event.

Coding-harness authentication is outside this vault guarantee. The bundled
Claude Code and Codex host scripts deliberately copy subscription state into
the persistent agent home. Those files enter the sandbox and are readable by
the agent process. Operators must treat `--host-script` as an explicit decision
to share the files that the selected script copies.

**Network and transport controls.**
Agents have no direct internet access. Each sandbox has no external network
interface. Its only egress path is a host-owned, per-agent Unix domain socket
that routes through SafeYolo. No host firewall rule participates in this
boundary.

The host owns the socket directory named `<ip>_<agent>`. At bind time,
mitmproxy's `UnixMode` listener derives the agent identity from that path and
stamps the accepted connection. The agent cannot choose another agent's socket
path. On Linux, a synthetic loopback address supplies the `<ip>` attribution
value. It is not an external interface or a direct egress path.

SafeYolo rejects noncanonical paths, duplicate security-sensitive headers, and
invalid encodings before policy evaluation. Homoglyph detection catches
mixed-script domain spoofing. Generic Cell Rate Algorithm (GCRA) rate limits
contain runaway request loops.

**Audit trail.**
Structured JSONL with unique request IDs, `blocked_by` attribution, credential fingerprints, and full decision reasoning. Designed for grep/jq analysis, not just human reading.

**Credential detection.**
As a safety net, SafeYolo also detects credentials in transit via pattern matching for known formats (OpenAI, Anthropic, GitHub, etc.) and Shannon entropy analysis for unknown high-entropy secrets. Detected credentials are fingerprinted via HMAC-SHA256 — only the fingerprint is stored or logged, never the raw value. Policy is destination-first: it defines what credentials can reach each endpoint, preventing one service's approval from accidentally authorising another.

## Out of Scope

| Limitation | Notes |
|------------|-------|
| **Prompt injection** | SafeYolo reduces prompt injection risk — through agent reflection prompts and limiting risky routes to prevent account takeover and credential theft — but doesn't eliminate it. |
| **Non-HTTP exfiltration** | DNS is resolved by SafeYolo (no direct DNS from the sandbox) and raw sockets are unavailable, blocking most non-HTTP channels. Exotic covert channels (e.g. steganography in allowed HTTP traffic) are not addressed. |
| **Host compromise** | If an attacker controls your host or `~/.safeyolo/`, all bets are off. |
| **Credentials in URL paths** | `/api/sk-proj-abc123/resource` — rare pattern, not currently scanned. |
| **Credentials in query/body** | Off by default. Enable with `--set credguard_scan_urls=true` / `credguard_scan_bodies=true`. |

## Reporting Security Issues

We welcome security research on SafeYolo.

**What we're looking for:**
- Credential bypass techniques (leaking credentials past SafeYolo)
- Policy isolation breaks (Agent A accessing Agent B's approvals)
- Admin API auth bypass
- Log injection or forgery
- Fingerprint collisions that could confuse policy matching

**How to report:**
- Email: craig@threatspotting.com
- Or open a GitHub issue if the finding is not sensitive

**What to expect:**
- No financial rewards (not funded for bounties)
- No CVEs until the project matures (pre-1.0)
- Acknowledgment in this document for credible finds
- Fix suggestions and PRs welcomed

**Current acknowledgments:**
- (None yet — be the first!)

## Further Reading

- [Security verification](docs/security-verification.md) — VM isolation, dependency trust, automated testing, build verification
- [Policy file assurance](docs/policy-assurance-threat-model.md) — threat-model-driven priorities and security invariants for policy mutation testing
- [Architecture](docs/ARCHITECTURE.md)
- [Service gateway v2 design](docs/service-gateway-v2-design.md)
