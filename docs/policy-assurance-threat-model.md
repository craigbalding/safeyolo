# Policy File Assurance: Threat-Model Decision

This document records how SafeYolo should test `policy.toml` processing and why.
It applies the security model in [SECURITY.md](../SECURITY.md) to the policy
parser, normalizer, compiler, persistence helpers, CLI commands, Admin API, and
live reload behavior.

The executable trials and initial measurements are in
[`experiments/policy_assurance`](../experiments/policy_assurance/README.md).

## Decision

SafeYolo should prioritize **semantic policy-mutation assurance**, not generic
TOML parser fuzzing.

The host and `~/.safeyolo/` are trusted. Agent sandboxes are untrusted, but the
SafeYolo configuration share is read-only and agents do not directly write
`policy.toml`. Host compromise, including an attacker who can arbitrarily
replace files under `~/.safeyolo/`, is explicitly out of scope.

The credible policy attack path is therefore indirect:

1. An untrusted or prompt-injected agent shapes a request or access proposal.
2. SafeYolo derives the security facts shown to the operator.
3. The operator approves a narrowly understood change.
4. A CLI, watch, Admin API, or addon persistence path mutates `policy.toml`.
5. The loader normalizes and compiles the changed policy for enforcement.

The security failure to look for is not primarily "TOML parsing crashed." It is
"the resulting effective permission is broader than the operator approved," or
"a failed/concurrent mutation silently removed a restriction."

## Assets and security properties

`policy.toml` is the source of truth for operator approvals. Its integrity
protects:

- destination and credential restrictions;
- per-agent isolation;
- egress posture and host wildcard precedence;
- service capabilities, contract bindings, and risky-route grants;
- revocations, denials, expiration, and rate limits; and
- the correspondence between operator intent, persisted state, and live
  enforcement.

The main assurance property is a permission-delta constraint:

```text
newly allowed requests ⊆ exactly the requests covered by the operator action
```

That property must be evaluated against compiled policy decisions, not only
against TOML dictionaries. A serialization can round-trip cleanly while still
changing authorization semantics.

## In-scope threats

### Approval broadening

An approval for one agent, host, credential, service, method, path, or bound
value must not authorize a wider set. Generated tests should exercise wildcard,
canonical-host, case, IDN, Unicode, quoting, escaping, inheritance, and
precedence interactions.

### Cross-agent policy bleed

A mutation scoped to Agent A must leave every effective decision for Agent B
unchanged. Agent-controlled input must not select another agent's policy scope
or turn an agent-specific rule into a baseline rule.

### Fail-open parsing or normalization

Malformed, conflicting, missing, or incorrectly typed policy data must not be
interpreted using a more permissive default. Startup must reject an invalid
policy. Live reload must follow its explicit last-known-good contract rather
than partially applying an invalid document.

### Lost restrictions during concurrent mutation

CLI commands, Admin API requests, and addon persistence can legitimately run
concurrently. An approval racing with a denial or revocation must produce a
valid serialized ordering. It must not lose a completed change, expose partial
TOML, or leave enforcement inconsistent with the final file.

### Persistence failure and split-brain state

A parse error, mutation exception, write error, crash, or rename failure must
leave the prior file and effective policy intact. A successful response must
not be returned before the durable policy state represents the action.

### Unrelated-data corruption

A narrow policy mutation must preserve unrelated hosts, agents, services,
comments, and operator-authored fields. This is both an auditability property
and protection against accidentally deleting a denial or constraint.

## Lower-priority and out-of-scope threats

### Arbitrary hostile TOML bytes

Agents cannot directly supply the contents of `policy.toml` under the current
architecture. Raw parser fuzzing is useful dependency and reliability defense,
but it is not the highest-value test of SafeYolo's authorization boundary.

### Symlink and path replacement by the host operator

An attacker who controls the operator account or `~/.safeyolo/` already controls
the SafeYolo trust root. Extensive symlink-race fuzzing is not justified by the
current threat model. Basic regression coverage remains useful to prevent an
accidental expansion of the agent's read-only boundary.

### TOML implementation conformance

SafeYolo should rely primarily on the upstream TOML implementation's conformance
testing. A pinned standards corpus or differential check can supplement that
assurance, but it does not replace SafeYolo-specific authorization properties.

### Parser resource exhaustion

Very large or deeply nested TOML is principally a local reliability risk while
the policy file remains host-controlled. Production size limits may still be
worthwhile, but parser denial-of-service is secondary to permission integrity.

If SafeYolo later accepts complete policies from agents, remote APIs, shared
repositories, or other untrusted sources, these priorities must be revisited.

## Technique selection

| Technique | Decision | Threats addressed |
|---|---|---|
| Property-based generation | Primary | Scope bleed, precedence errors, fail-open defaults, semantic round trips |
| Stateful model testing | Primary | Approval/revoke sequences, persistence/reload consistency, unintended permission deltas |
| Real multiprocess tests | Primary | Lost updates, lock behavior, partial writes, live/disk divergence |
| Targeted implementation mutation testing | Primary assurance ratchet | Missing validation, inverted allow/deny logic, removed scoping, swallowed failures |
| Domain-aware coverage-guided fuzzing | Secondary | Unexpected combinations and deep paths after semantic oracles exist |
| Raw TOML byte fuzzing | Secondary/reliability | Parser crashes, pathological malformed input, dependency regressions |
| Parser differential/standards corpus | Secondary | TOML ambiguity and implementation drift |
| Extensive symlink/path fuzzing | Deferred under current model | Requires a hostile host/config owner, which is out of scope |

## Required test oracles

Random input without a security oracle is insufficient. Generated, stateful,
and fuzz tests should enforce these properties:

- **Approval:** the post-mutation allow set may grow only by the intended
  agent/resource/action tuple.
- **Denial:** the allow set may only shrink.
- **Revocation:** the allow set must not grow and the selected grant must no
  longer authorize a request.
- **Agent isolation:** mutations for one agent leave all other agents' decisions
  unchanged.
- **Round trip:** save and reload preserve effective decisions.
- **Metamorphic equivalence:** comments, key order, valid quoting, and equivalent
  formatting do not change decisions.
- **Failure atomicity:** a failed mutation leaves original bytes and effective
  decisions unchanged.
- **Reload integrity:** the active policy is always either the complete previous
  valid policy or the complete new valid policy, never a partial combination.
- **Narrow persistence:** unrelated document sections and operator-authored
  context survive a successful narrow mutation.

## Tooling implications

Hypothesis rule-based state machines are a strong fit for choosing both policy
values and operation sequences while shrinking failures. Tests should drive
real normalization, compilation, persistence, and decision objects wherever
practical, backed by a deliberately small reference model.

Implementation mutation testing should focus on the policy normalizer,
round-trip helpers, loader/compiler precedence, agent scoping, and mutation
handlers. Security-relevant mutants include removed conflict checks, reversed
precedence, missing agent filters, permissive exception fallbacks, skipped
locking, and retained revoked grants.

SafeYolo's existing Atheris and ClusterFuzzLite pipeline can later host a
domain-aware policy target. That target should let unexpected exceptions and
security-invariant violations escape as failures. It should not catch every
exception and continue, because doing so hides precisely the defects the target
is meant to find.

## Production controls derived from the experiments

The two experiment rounds changed the assurance design, independently of the
individual defects they happened to expose:

| Experimental learning | Production control |
|---|---|
| Serialized shape can agree while authorization differs | Focused tests compare active and fresh-process decisions |
| Ingress canonicalization can hide an engine defect | Hostname contracts are checked both directly and through real mitmproxy flows |
| Scheduler timing is not replayable evidence | Writer tests use explicit process barriers and published seeds |
| A mutation spans result, file, loader, audit, and residue | The shared observation records every state plane for one transaction |
| One broken operation can halt unrelated discovery | Generated sequences and runner groups remain split by mutation family |
| Failure meaning changes at rename | Faults are named by commit stage and have old/new visibility oracles |
| Child death is not storage power loss | Process death and abrupt disposable-VM death are reported as different evidence |
| Broad generation discovers; small examples prevent recurrence | Focused regressions run on pull requests and bounded Hypothesis groups run nightly |
| A source mutation may be behaviorally inert | Holdouts receive credit only after an independent probe proves an effective change |
| Runtime guesses are poor enrollment criteria | Reports retain measured distributions; timeouts are deadlock guards only |

The production engineering entrypoint is `uv run python -m tools.policy_chaos`.
Its default mode uses generated temporary policies. Its fault mode requires a
disposable-VM sentinel plus two explicit opt-ins, and exposes a prepare/recover
protocol so an external KVM VPS controller can perform abrupt guest power-off.
The repository tool does not provision, stop, or destroy outer VMs.

## Review trigger

Review this decision whenever any of the following changes:

- agent sandboxes gain a policy-write path;
- complete policy documents are accepted from a network API or integration;
- policy files can be imported automatically from an untrusted repository;
- the config share is no longer read-only;
- SafeYolo expands its threat model to hostile same-host processes; or
- parser/resource exhaustion becomes remotely triggerable.
