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

This table records pre-cutover learning. The Python experiment runner and its
scheduled workflow are retired in the Rust cutover; rows that describe them
do not claim current native coverage.

| Experimental learning | Production control |
|---|---|
| Serialized shape can agree while authorization differs | Focused tests compare active and fresh-process decisions |
| Ingress canonicalization can hide an engine defect | Hostname contracts are checked both directly and through real mitmproxy flows |
| Scheduler timing is not replayable evidence | Writer tests use explicit process barriers and published seeds |
| A mutation spans result, file, loader, audit, and residue | The shared observation records every state plane for one transaction |
| One broken operation can halt unrelated discovery | Generated sequences and runner groups remain split by mutation family |
| Failure meaning changes at rename | Faults are named by commit stage and have old/new visibility oracles |
| Child death is not storage power loss | Process death and abrupt disposable-VM death are reported as different evidence |
| Broad generation discovers; small examples prevent recurrence | Focused regressions remain; bounded native generated sequences are an open release assurance gap |
| A source mutation may be behaviorally inert | Holdouts receive credit only after an independent probe proves an effective change |
| Runtime guesses are poor enrollment criteria | Reports retain measured distributions; timeouts are deadlock guards only |

The historical engineering entrypoint `uv run python -m tools.policy_chaos`
is available only from the pinned pre-cutover checkout
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. Its temporary-policy and
guarded disposable-VM fault results describe the Python implementation.
The current native release still needs generated policy transaction and
failure-stage checks before those assurance claims can be accepted.

## Native chaos selection for #831

The ten historical `tools/policy_chaos.py` default groups are the finite
selection below. The [historical results](../experiments/policy_assurance/RESULTS.md)
describe the Python engine only. Existing native results used here are the
[#621 scope and precedence review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413),
[#621 revoke and reload review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779),
[#621 invalid-policy review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272),
and [#638 installed state transition review](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040).
The named tests establish only the assertions they run. An open obligation in
the last column is not satisfied by a historical Python pass.

| Historical default group and defect family | Existing proof reused | Incremental native chaos obligation or removed path |
|---|---|---|
| `catalogue`: agent allow leaking to baseline, lost agent catchall deny, wrong-agent edit, and deleted peer agent | [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), `test_agent_egress_scope.py::test_agent_and_destination_precedence_on_concurrent_reused_connections` and `test_shared_operator_approval.py::test_shared_operator_approval_is_scoped_and_retried` cover effective agent and destination scope. | C3 retains composed real-writer edits and peer preservation. C7 calibrates transaction oracles; pure matcher corruptions add no chaos run when these existing assertions detect the same effective change. |
| `catalogue`: broadened credential, deny becoming prompt, wildcard default becoming prompt, exact allow becoming wildcard budget | `test_operator_consumer_approval.py::test_retained_operator_client_approves_and_denies_native_credentials`, the [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), and `test_native_network_policy.py::test_native_policy_runtime_guard_modes` cover credential and network effects. | C3 retains generated combinations of precedence, wildcard, credential and writer histories that can expose an unintended increase in the allow set. |
| `properties`: semantic TOML round trip, selected-agent approval, denial monotonicity and unrelated-agent preservation | The [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413) checks a fixed real-proxy matrix; the [#621 reload result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779) checks live decisions after reload. | C3 generates policy edits, quoting and precedence combinations, then compares intended permission deltas with active and fresh Rust effects. A serialized TOML comparison alone cannot close this row. |
| `sequences-clean`: host allow, deny, rate, bypass, remove and reload; credential approval/reload; agent metadata and service edits; gateway grant and binding add/remove; transaction observation | `test_shared_operator_approval.py`, `test_operator_consumer_approval.py`, `test_gateway_risk_approval.py`, the [#621 reload result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779), and the [#638 installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) cover fixed effects and durable service/grant reuse. | C2 supplies the existing-state/observation seam. C3 retains bounded mixed histories through supported writers and checks each completed change plus the final fresh process. The removed Python `PolicyEngine` writer is inapplicable as a caller; its permission-integrity obligation transfers to the native writer. |
| `host-canonicalization`: case and DNS-label wildcard boundary; trailing dot, Internationalized Domain Names in Applications (IDNA), unusual dot, IP text and conflicting authority | The [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), `test_native_network_policy.py::test_native_policy_homoglyph_authority_forms`, and `test_native_network_policy.py::test_native_policy_raw_decodable_mixed_script_ace` cover selected real ingress, but not a suffix-sharing sibling of a wildcard host. | C3 retains an effective boundary probe: after a supported writer adds `*.scope.invalid`, a proper child can gain access but `evilscope.invalid` must not. This detects loss of the DNS-label boundary. C3 also retains canonical-host interactions that alter a mutation's scope. The old mitmproxy `HTTPFlow` ingress is removed, so replaying that object path is inapplicable. The historical non-normative observations do not become new policy guarantees. |
| `writer-matrix`: `cli-same`, `engine-same`, `agents-same`, `admin-same`, `gateway-same`, `cli-locked`, `engine-agents`, `admin-gateway`; lock controls, lock-before-read and revocation versus unrelated approval | The [#638 installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) establishes serial cross-version reuse. `policy_runtime.rs::expiry_write_after_a_concurrent_policy_change_keeps_the_earlier_watermark` establishes one native watermark edge. Neither proves the matrix's concurrent writes. | C4 maps retained CLI, agent-store, Admin and gateway writers to both serialized orders where a native/Python pair remains; it retains explicit barriers, lock-before-read and both completed edits. Historical `engine-*` calls into the removed Python engine are inapplicable, while their native writer/publication equivalents remain C4. |
| `failure-stages`: parse, normalization, serialization, temporary creation/write, file sync, rename, directory sync, activation/reload and audit | The [#621 invalid-policy result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272) and `test_native_network_policy.py::test_native_policy_failed_reload_retains_scoped_decisions` cover startup refusal and last-known-good reload. | C5 retains applicable actual-writer stages, including native validation, partial write, failed rollback and audit interaction. It checks response, file, active and fresh state at the stage's correct commit boundary. An absent native stage is recorded only after inspection, not manufactured. |
| `crash-recovery`: process death before/after rename and unrelated restriction preservation | [#638's clean installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) reuses durable state but does not cut a transaction. | C6 retains pre-rename, post-rename/pre-directory-sync and acknowledged-success process deaths, plus the same three actual disposable-KVM stops. Fresh Rust must read the surviving file without a fixture rewrite. |
| `known-no-rate`: an unrated allow disappeared or bypassed the aggregate budget | `test_operator_consumer_approval.py::test_retained_operator_client_approves_exact_native_network_scope` checks the native 600-rate approval and real origin effect; `test_native_network_policy.py::test_native_policy_budget_is_shared_and_survives_reload` checks budget reuse. | C3 retains an unrated host allowance in a composed host history, where disappearance or budget escape would change a later decision. |
| `known-persistence-failure`: save error reported success and broadened live access | The [#621 invalid-policy result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272) covers malformed reload, but not a writer save failure. | C5 injects a real native writer failure and requires a truthful result, preserved pre-commit bytes and decisions, and no premature success. |
| `known-public-concurrency`: policy-host lost update | `policy_runtime.rs::expiry_write_after_a_concurrent_policy_change_keeps_the_earlier_watermark` covers the native watcher watermark, not competing public writers. | C4 retains the two-writer lock-order and publication histories; both completed disjoint edits must remain effective. |

The five source holdouts are separate from the ten defaults. The case-sensitive
wildcard holdout was effective in the old matcher but invisible after mitmproxy
canonicalized ingress case; direct matching coverage remains necessary. The
agent-condition holdout is reused through the #621 scope tests above. The
wildcard-without-label-boundary holdout remains open for C3's suffix-sharing
sibling probe; the cited #621 cases exercise proper wildcard subdomains only.
The lock-before-read and swallowed-save holdouts remain C4 and C5 transaction
calibrations; C7 adds stale publication after a newer change or rollback. A
holdout counts only when a disposable mutation changes effective behavior and
the selected assertion catches it.

The historical `fault prepare-power-cut` / `fault recover` protocol is also
separate. It paused the Python writer and used that engine for recovery; no
native VM-death result is inherited. C6 restores a guarded native protocol
and requires an actual disposable-KVM stop at each named checkpoint. C8
restores the hermetic runner and recurring incremental profile. The old
Python-engine recovery oracle is inapplicable because that engine was removed;
the fresh Rust proxy and controlled origin supply the required recovery effects.

## Review trigger

Review this decision whenever any of the following changes:

- agent sandboxes gain a policy-write path;
- complete policy documents are accepted from a network API or integration;
- policy files can be imported automatically from an untrusted repository;
- the config share is no longer read-only;
- SafeYolo expands its threat model to hostile same-host processes; or
- parser/resource exhaustion becomes remotely triggerable.
