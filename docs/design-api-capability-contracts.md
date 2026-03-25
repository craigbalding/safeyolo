# Design: API Capability Contracts

## Problem Statement

SafeYolo is a security proxy for AI coding agents. It sits between agent containers and the internet, enforcing security policy on all HTTP traffic. Agents have no direct network access — everything routes through the proxy.

Today, SafeYolo controls access at three levels:

1. **Network level** — which domains the agent can reach (policy.yaml allowlist)
2. **Credential level** — which credentials can go to which destinations (credential_guard)
3. **Service level** — which services an agent is authorised to use, with route-based capability scoping (service_gateway)

The service gateway uses **method + path matching** to define what an agent can do within a service. A capability is a set of allowed routes:

```yaml
# Current model
capabilities:
  read_messages:
    routes:
      - methods: [GET]
        path: "/gmail/v1/users/me/messages"
      - methods: [GET]
        path: "/gmail/v1/users/me/messages/*"
```

This works for simple REST APIs where the URL path determines what you're accessing. It breaks down for APIs where the real access semantics live elsewhere.

## The Gap

Method + path matching is insufficient for real-world API security because:

**1. Query parameters carry access semantics.** Gmail's `messages.list` accepts `labelIds` and `q` parameters that determine which messages are returned. The path is the same whether you're listing promotions or reading the inbox. An agent authorised for "read promotions" can trivially call the same endpoint without the `labelIds` filter.

**2. Request bodies define actions.** GraphQL APIs route everything through `POST /graphql` — the operation is entirely in the request body. REST APIs like Gmail's `messages.send` carry recipients and content in the body. Path matching can't distinguish "send to a coworker" from "exfiltrate data to an external address."

**3. Response content is the real risk.** An operator who says "let the agent triage my email" doesn't mean "let it read password reset tokens and 2FA codes." The security boundary is about what's *in* the messages, not which API endpoint fetched them. Two calls to the same endpoint can return dramatically different risk levels depending on message content.

**4. Capabilities interact.** An agent with "read promotions" and "manage labels" can move a sensitive inbox message into the promotions category, then read it. Each capability is safe in isolation; the combination creates a bypass. This can't be detected by looking at routes.

**5. Sequences matter.** A legitimate workflow is "list messages, then get specific ones." A suspicious pattern is "get messages by guessing IDs without listing first" or "re-request a message that was blocked." Stateless per-request enforcement misses these signals.

## Design Goals

1. **Agents call real APIs.** No custom SDK, no abstraction layer. Standard HTTP tools (curl, client libraries) work unmodified. SafeYolo enforces transparently at the proxy layer.

2. **Fail closed.** API calls not explicitly described in a capability contract are denied. Allowlist, not blocklist.

3. **Response is the trust boundary.** Request constraints are defence in depth, but response inspection is the hard guarantee. The API server is authoritative about what data it returned.

4. **Operator decisions are simple.** Approve or deny a capability, perhaps with one or two parameter choices (which category, which channel). Operators don't write rules or YAML.

5. **Service authors write Python.** Constraint logic and validators are functions, not a YAML DSL. Testable with plain dicts, no framework to learn.

6. **Behavioural signal from repeated failures.** The enforcement layer generates security telemetry. An agent that keeps probing blocked paths is a signal for the operator, not just a series of 403s.

7. **Capability combinations are analysable.** SafeYolo can compute whether granting two capabilities together creates risks that neither has alone.

## Concepts

### Primitive

An atomic API operation with a request contract and response validation. Describes one valid API call shape.

```python
# Conceptual — syntax TBD
def list_messages(request, response):
    """List messages in a category."""
    # request enforcement
    assert set(request.params.keys()) <= {"labelIds", "maxResults", "pageToken"}
    assert "labelIds" in request.params
    # response check
    # (list only returns IDs — no sensitive content)
    return True, None
```

### Capability

A named bundle of primitives that together enable a useful workflow. The operator approves a capability, not individual primitives.

Examples: "read promotions", "triage inbox", "post to #engineering channel", "read GitHub issues in repo X".

### Sequence

An ordered composition of primitives where state flows between steps. Enables enforcement of "list before get" patterns and tracking of which resource IDs the agent legitimately obtained.

### Capability Composition Analysis

Each primitive declares what data it reads, what it trusts for security decisions, and what it can mutate. SafeYolo computes whether two capabilities together create conflicts — e.g., one capability can mutate data that another trusts.

## Areas Explored

### A. Constraint Language

How should request/response constraints be expressed?

**YAML operators (allow/deny/require/match)**
- Pros: Declarative, readable, no code to write for simple cases
- Cons: Limited expressiveness, can't do cross-field checks, invents a DSL that grows over time, verbose for complex constraints

**CEL (Common Expression Language)**
- Pros: Concise boolean expressions, handles cross-field checks, used in production (Google Cloud, Kubernetes, Envoy), Python library available (`celpy`)
- Cons: Another language to learn, string expressions lack IDE support, overkill for simple "deny these values" rules

**Python functions**
- Pros: Zero learning curve, full expressiveness, testable, IDE support, cross-field checks are just code, already the codebase language
- Cons: Can't be serialised into YAML, service definitions become code + config, harder to audit at a glance than declarative rules

**Hybrid: YAML operators for simple cases, Python for complex**
- Pros: Best of both — 80% of constraints are simple allow/deny lists, remaining 20% are Python functions
- Cons: Two systems to maintain, unclear boundary between "use YAML" and "use Python"

**Current leaning:** Python functions for constraint logic, YAML only for metadata (which primitives, descriptions, scopes). Service authors already write Python. The constraint function is the primitive.

### B. Response Inspection

What should happen when a response contains data outside the agent's approved scope?

**Block entirely** — return an error with a reflection prompt explaining what was denied and why.

**Redact** — strip the sensitive parts, return the rest. E.g., remove messages in a thread that don't belong to the approved category.

**Scan for patterns** — use the existing pattern_scanner to detect sensitive content (credentials, 2FA codes, PII) in response bodies regardless of category/label.

Open question: for a use case like "triage my inbox," the operator explicitly wants the agent to read inbox messages. The risk isn't the category — it's specific *content* within messages (password resets, 2FA codes, API keys). This is a content classification problem that label/category scoping can't solve. Pattern scanning on responses may be the right tool here.

### C. Stateful Enforcement

Should the gateway track state across requests within a capability session?

**Stateless (per-request)** — each request/response pair is evaluated independently. Simple, no memory management.
- Cons: can't enforce "list before get", can't track which IDs the agent obtained legitimately

**Capability-scoped state** — primitives within a capability share a state object (e.g., set of valid message IDs from a list call). State is bounded (e.g., last 1000 IDs) and scoped to the capability session.
- Cons: memory management, what defines a "session"

**Cross-capability state** — the gateway tracks all agent actions across capabilities. Enables detection of cross-capability attacks (relabel then read).
- Cons: complex, state explosion, unclear what to track

Open question: where is the right boundary? Capability-scoped state handles the common "list then get" pattern. Cross-capability awareness may be better handled at analysis time (flag risky combinations) rather than runtime.

### D. Capability Composition

How to detect that two safe capabilities become dangerous together?

**Manual enumeration** — service authors list known-dangerous pairs.
- Cons: doesn't scale, misses novel combinations

**Computed from primitive metadata** — each primitive declares reads/mutates/trusts. If capability A trusts field X and capability B mutates field X, flag the combination.
- Pros: automatic, scales with new primitives
- Cons: requires accurate metadata, scope matters (mutating "labels" is only dangerous if the mutated values overlap with the trusted values), content-level risks (e.g., message body containing a password reset) can't be expressed as field-level metadata

Open question: the reads/mutates/trusts model works for structural conflicts (relabelling attacks) but doesn't capture content-level risks. An agent reading inbox messages is risky not because of what *field* it reads but because of what *content* might be in those fields. This may be a fundamentally different layer of defence (pattern scanning) rather than a capability composition problem.

### E. Operator Experience at Approval Time

When an agent requests a capability, what does the operator see and decide?

The operator should understand:
- What the agent will be able to do (in plain language)
- What it won't be able to do (the constraints)
- Whether this capability combined with existing ones creates new risks
- What ongoing monitoring SafeYolo will provide (response scanning, behavioural alerts)

The operator should NOT need to:
- Write YAML or code
- Understand API endpoint details
- Enumerate edge cases

SafeYolo curates service definitions with pre-built capabilities for popular APIs. The operator's decision is "yes, claude can read my promotional emails" — SafeYolo handles the enforcement details.

## F. Content Classification

Label and category scoping controls which *bucket* an agent reads from. But the real risk is often the *content* — a password reset email can land in any category, and an operator who says "triage my inbox" is giving the agent access to everything structurally while expecting SafeYolo to protect sensitive content.

This is a content classification problem, not a routing problem.

### Why structural controls are insufficient

An operator grants "read promotions." The agent calls `messages.list` with `labelIds=CATEGORY_PROMOTIONS`, gets message IDs, then calls `messages.get` for each. The response check verifies the `CATEGORY_PROMOTIONS` label is present. So far, structural controls work.

Now the operator grants "triage inbox." The agent needs to read inbox messages to classify them. The inbox contains password reset emails, 2FA codes, financial statements, and newsletters. All have the same label (`INBOX`). The security boundary is the content, not the label.

Worse: an agent with "read promotions" and "manage labels" can relabel an inbox message as promotional and then read it. The structural response check passes because the label is now present. The attack succeeds because the constraint was structural, not content-based.

### Approach: staged content classification

A two-stage cascade running inline in the proxy, applied to response bodies before they reach the agent:

**Stage 1: Pattern matching (<0.1ms)**

Regex-based detection of known sensitive content patterns. Catches the obvious cases with perfect precision:

- Password reset phrases ("reset your password", "verification code", "one-time passcode")
- 2FA codes (6-8 digit codes with surrounding context)
- API keys and credentials (the pattern_scanner already does this)
- Financial data patterns (account numbers, sort codes, card numbers)
- Known sender patterns (security@, noreply@, no-reply@)

SafeYolo's pattern_scanner already implements this for request/response scanning. The same infrastructure can be extended with email-security-specific pattern sets.

Most security-relevant email content has strong lexical signals. Password reset emails from known providers follow predictable templates. This stage catches the majority of cases.

**Stage 2: ML classifier (3-8ms, invoked only when Stage 1 doesn't match)**

A lightweight transformer model classifies content into security-relevant categories:

- `password_reset` — account recovery, password change confirmations
- `two_factor` — 2FA codes, authentication prompts
- `credential` — API keys, tokens, secrets shared via email
- `financial` — bank statements, transaction alerts, invoices with account details
- `legal` — contracts, NDAs, legal notices
- `personal` — private correspondence, medical, HR
- `promotional` — marketing, newsletters, offers
- `transactional` — order confirmations, shipping updates, receipts
- `safe` — general correspondence with no sensitive content

The capability contract specifies which content classes are allowed. "Read promotions" allows `promotional` and `transactional`, blocks everything else. "Triage inbox" allows all classes except `password_reset`, `two_factor`, `credential`.

### Model choice

| Criterion | Recommendation |
|-----------|---------------|
| Model | `all-MiniLM-L6-v2` sentence transformer + linear classifier head |
| Runtime format | ONNX (INT8 quantised) — no PyTorch at inference time |
| Size | ~40 MB quantised |
| Inference speed | 3-8ms on CPU for short text |
| Training data | Bootstrap with SetFit (20-50 examples per class), expand over time |
| Runtime dependencies | `onnxruntime` + `tokenizers` + `numpy` (no PyTorch, no transformers library) |

Why this model: MiniLM-L6-v2 is the most proven small sentence transformer — battle-tested, fast, and well-supported. ONNX export with INT8 quantisation gives near-FastText speed with semantic understanding that catches paraphrased or novel phrasings.

FastText (<1ms, 5-50MB) is an alternative for maximum speed. It uses bag-of-n-grams without semantic understanding, so it handles direct keyword matches well but misses nuanced phrasings. Suitable if the latency budget is extremely tight or transformer dependencies are unwanted.

### How it integrates with capability contracts

The capability contract specifies allowed content classes alongside structural constraints:

```python
def get_message(request, response):
    """Read a single message — enforce category and content restrictions."""
    denied_labels = {"INBOX", "CATEGORY_PERSONAL", "SENT", "DRAFT"}
    allowed_content = {"promotional", "transactional", "safe"}

    # structural check
    labels = set(response.body.get("labelIds", []))
    if denied_labels & labels:
        return False, "Message is in a restricted category"

    # content check — stage 1 (patterns) then stage 2 (ML) if needed
    content_class = classify(response.body)
    if content_class not in allowed_content:
        return False, f"Message classified as '{content_class}' which is outside your approved scope"

    return True, None
```

The `classify()` function implements the staged cascade. Pattern matches short-circuit with high confidence; remaining content goes through the ONNX model.

### Complementary: entity detection for PII/credentials

Microsoft Presidio is a production-grade hybrid (regex + NER) for detecting sensitive entities in text — credit card numbers, email addresses, phone numbers, API keys. It solves a narrower problem than full document classification but is directly relevant for response scanning.

Presidio could run alongside or within the classification cascade:
- Classification answers: "what type of content is this?" (password reset, promotional, etc.)
- Entity detection answers: "does this content contain specific sensitive values?" (a credit card number, an API key, a social security number)

Both signals feed into the capability contract's response validation.

### Behavioural signal

Content classification generates security telemetry beyond simple allow/deny:

- Agent repeatedly requesting messages that get classified as `password_reset` → escalating alert
- Agent requesting messages across many categories (broad scanning behaviour) → alert
- Agent requesting the same blocked message ID multiple times → persistence signal
- Classification confidence scores logged for audit — low-confidence classifications flagged for operator review

### Training data and cold start

The model needs labelled examples. Bootstrapping approach:

1. Generate synthetic examples using an LLM (password reset templates from major providers, promotional email patterns, etc.)
2. Train initial model with SetFit (20-50 examples per class)
3. Deploy with logging — misclassifications are flagged for operator review
4. Retrain periodically with expanded, corrected dataset
5. Publish updated models with SafeYolo releases

SafeYolo ships a pre-trained model for common email content classes. Operators can extend with custom classes for their domain.

## Open Questions

1. **Classification accuracy requirements.** What false negative rate is acceptable for security-critical categories like `password_reset`? A missed password reset email reaching the agent is a security failure. Should certain categories fail closed (block if unsure) while others fail open (allow if unsure)?

2. **Classification scope beyond email.** The Gmail example drives the content classification design, but other APIs have different content risks. Slack messages could contain credentials. GitHub issues could contain secrets. Is the classification model per-service, or is there a universal "sensitive content" detector that works across all APIs?

3. **Session boundaries.** If state is capability-scoped, what starts and ends a session? Proxy restart? Time-based? Explicit agent signal?

4. **Service definition authoring.** Who writes these? SafeYolo ships curated definitions for popular APIs (Gmail, Slack, GitHub). Can operators extend them? Should there be a community contribution model?

5. **Escape hatch.** What happens when a legitimate use case doesn't fit the capability model? The operator needs a way to say "I trust this agent with full access to this service" without SafeYolo fighting them.

6. **Model distribution.** How are pre-trained classification models distributed with SafeYolo? Baked into the Docker image (adds ~40MB)? Downloaded on first use? Configurable?

7. **Operator override for classifications.** If the classifier blocks a message the agent legitimately needs, can the operator override? What does that UX look like in watch?
