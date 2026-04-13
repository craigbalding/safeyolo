# Security

SafeYolo is a human-centric security control point for AI agents.

Agents need to be controlled to prevent accidents and limit the blast radius of prompt-injected or malicious agents. SafeYolo sits between them and external systems, giving you scoped control over access to both your local data and remote services — failing closed when anything is ambiguous or out of policy.

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

- **Host** is the trust root. You run the CLI, own config, and control the Docker runtime.
- **SafeYolo** enforces your policy — no Docker socket, no host filesystem access beyond mounts, runs non-root.
- **Agent containers** have no direct internet access in Sandbox Mode. Their only route to the outside world is through SafeYolo's policy enforcement.
- **External services** are reachable only if policy explicitly permits the destination.

## Core Security Properties

### Minimize trust

Grant the minimum access required. Agents run in isolated networks. The SafeYolo container has no Docker socket. Admin API binds to localhost only and requires token auth. The container runs as the host user's UID/GID, not root.

### Fail closed

When uncertain, block. Unknown credentials trigger an approval workflow, not silent passthrough. Destination mismatches return HTTP 428 with actionable feedback. Invalid policies are rejected at load time. The startup script verifies block mode before accepting traffic.

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
Agents shouldn't hold the keys to your accounts. SafeYolo lets agents access your services without ever seeing your credentials — it injects credentials at the proxy layer based on policy, so agents make requests and SafeYolo handles authentication. Your keys never enter the agent's environment.

**Network and transport controls.**
Agents have no direct internet access in Sandbox Mode. All HTTP traffic routes through SafeYolo. Non-canonical requests (path tricks, duplicate headers, encoding exploits) are rejected before policy evaluation. Homoglyph detection catches mixed-script domain spoofing. GCRA rate limiting prevents runaway loops.

**Audit trail.**
Structured JSONL with unique request IDs, `blocked_by` attribution, credential fingerprints, and full decision reasoning. Designed for grep/jq analysis, not just human reading.

**Credential detection.**
As a safety net, SafeYolo also detects credentials in transit via pattern matching for known formats (OpenAI, Anthropic, GitHub, etc.) and Shannon entropy analysis for unknown high-entropy secrets. Detected credentials are fingerprinted via HMAC-SHA256 — only the fingerprint is stored or logged, never the raw value. Policy is destination-first: it defines what credentials can reach each endpoint, preventing one service's approval from accidentally authorising another.

## Out of Scope

| Limitation | Notes |
|------------|-------|
| **Try Mode bypass** | By design — agents can unset proxy vars. Use Sandbox Mode for autonomous agents. |
| **Prompt injection** | SafeYolo reduces prompt injection risk — through agent reflection prompts and limiting risky routes to prevent account takeover and credential theft — but doesn't eliminate it. |
| **Non-HTTP exfiltration** | In Sandbox Mode, DNS is resolved by SafeYolo (no direct DNS) and raw sockets are unavailable, blocking most non-HTTP channels. Exotic covert channels (e.g. steganography in allowed HTTP traffic) are not addressed. |
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
- [Architecture](docs/ARCHITECTURE.md)
- [Service gateway v2 design](docs/service-gateway-v2-design.md)
