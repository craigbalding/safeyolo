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

Before rename, a handled parse, validation, write, or rename failure must
leave the prior file and effective policy intact. After rename, the native
Admin writer attempts rollback on a directory-sync or activation failure.
If rollback also fails, the error must identify that failure; the new file
may remain visible. The retained Python CLI writer does not roll back a
directory-sync failure after replacement. A successful response must not be
returned before the durable policy state represents the action.

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
- **Failure handling:** a handled pre-rename failure leaves original bytes and
  decisions unchanged. A handled native post-rename failure restores them when
  rollback succeeds. A failed rollback reports its failure and the test checks
  the actual remaining file and decisions.
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
| Broad generation discovers; small examples prevent recurrence | Focused regressions remain; C3 adds bounded native generated sequences |
| A source mutation may be behaviorally inert | Holdouts receive credit only after an independent probe proves an effective change |
| Runtime guesses are poor enrollment criteria | Reports retain measured distributions; timeouts are deadlock guards only |

The historical full `uv run python -m tools.policy_chaos` runner is available
from the pinned pre-cutover checkout
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. Its temporary-policy and
guarded disposable-VM fault results describe the Python implementation.
The current checkout has bounded native existing-state, host, state-history,
writer-contention, failure-stage, and process-death groups. On Linux, from the
repository root, use the [native runner setup](../experiments/policy_assurance/README.md#current-native-runner)
to install the project development environment and build the debug Rust proxy.
The hermetic runner needs no already running SafeYolo proxy
or target sandbox: its fixtures start and stop their own proxy and controlled
origins. Generated groups use the three published seeds; fixed groups run once:

```bash
uv run --frozen python -m tools.policy_chaos run --output "$HOME/policy-chaos.json"
```

The report records the source commit and dirty state, selected binary path,
version and SHA-256, selected and executed counts, each case result, and the
operation trace and replay command for a saved generated failure. It records
the writer, selected case stages, expected contract and observed result;
`existing-state` also emits the original/final file hashes, live and fresh
decisions, audit, residue, and list/HMAC preservation. `PASS` exits 0;
`FINDING` exits 1; an unexecuted or skipped required case, missing case report,
or timeout is `INCOMPLETE` and exits 2. Independent groups continue after a
finding. The hash identifies the binary bytes; this development binary does
not embed a source revision. `--group writer-contention` selects the fixed
contention cases. `--group failure-stages` selects the staged native and
retained Python writer cases. `--group crash-recovery` selects the three
process deaths and the guarded VM protocol checks. `--seed 26082601` selects
one generated seed.
The report's replay command includes the selected `--binary` and reruns the
saved operation trace. The credential group composes operator approvals,
denial, host-rule removal, and reload. The service group composes the retained
agent-store writer with native service, contract-binding, and risky-grant Admin
writers. Both groups check running and fresh Rust decisions through controlled
origin requests. The contention group holds the policy lock at actual read or
acquisition boundaries, then checks persisted edits and live Rust decisions.
Its native barrier exists only in debug builds. The existing fixed credential
and session-grant tests remain separate scope and revocation controls. The
runner does not execute a VM power cut. Use `--group` for an individual clean
control and `replay` with a saved trace to calibrate it separately against a
disposable mutant binary; no mutants run in the nightly profile. The restored
nightly/manual workflow uses only this hermetic profile. Lens accepted C6 after
review of the corrected on-guest recovery report. The C4
technical result was accepted at `ca224d39697bed1a8ba59ec23299ac859f840b1a`.
The C5 technical result was accepted at
`b445ee5736005c173bc3189d55cf57e317f635ff`.

On a disposable Linux host used for an integrated hermetic run, build and run
this profile from the current source checkout. No proxy or target sandbox
needs to be running before the command. Preserve the report before cleanup.
If the operator separately started SafeYolo and a disposable agent on that
host, run `safeyolo stop`, then `safeyolo agent stop NAME` for that named
agent. `safeyolo stop` alone leaves its sandbox running. Verify the agent is
stopped with `safeyolo agent status NAME`. The runner itself owns and stops
only its test proxy and origins.

The C4 candidate maps the historical writer rows as follows. Each listed row
uses the historical order unless both orders are named. The two Rust
publication histories use one proxy/Admin instance receiving concurrent
requests. Applicable matrix rows use separate Python writer processes with
the same policy file and lock.

| Historical row | Current writers and selected order |
|---|---|
| `cli-same` | Retained policy-host CLI against itself; left first. |
| `engine-same` | Native Admin host approval against itself; left first. The Python engine caller was removed. |
| `agents-same` | Retained agent-store save against itself; right first. |
| `admin-same` | Native service authorization against itself; left first. |
| `gateway-same` | Native contract binding approval against itself; left first. |
| `cli-locked` | Retained locked mutation against the policy-host CLI; left first. The separate locked control runs both orders. |
| `engine-agents` | Native Admin host approval against the retained agent store; both orders. The Python engine caller was removed. |
| `admin-gateway` | Native service authorization against native contract binding approval; left first. |

The same group also runs retained CLI against native Admin in both orders,
conflicting host allow and deny in both orders, and remembered-grant revocation
against an unrelated host approval. The Rust contention tests pause an older
load while a later scoped revocation commits, and pause a failed mutation after
save while an unrelated writer waits. The tests check controlled origin effects
at the active Rust boundary and check that a rejected candidate cannot be read
before rollback. The existing native expiry watermark test retains its narrower
claim about a write during compilation.

### C5 staged writer paths

The debug-only checkpoint channel in `proxy/src/approvals.rs` reports a run ID,
transaction ID, transaction kind, phase, and named stage. The test controller
binds one transaction ID from its begin event before it chooses a stage reply.
The controller can pause the writer, return an I/O error, or request a partial
temporary write followed by an I/O error. A default release build does not
compile the socket or environment lookup. The release negative control arms an
error, requires the Admin mutation to work, and checks that no checkpoint
connection occurs.

| Historical stage | Current path and C5 observation |
|---|---|
| Existing-file read and parse | Native Admin reads and parses under the shared lock. A read fault keeps the old bytes; malformed TOML rejects the Admin edit and fresh startup. The running proxy retains its last known good policy. |
| Normalization and validation | `NetworkScope::new` normalizes the destination before the transaction. `validate_rate` and the edit functions validate the locked document. Invalid endpoint and rate operations leave bytes and decisions unchanged. The old Python engine's separate normalization call has no native writer counterpart. |
| Serialization | `DocumentMut::to_string` and large-integer restoration return a `String`; this path has no fallible serialization operation to inject. The baseline Admin replacement parses its candidate before saving. |
| Temporary creation, write, file sync, and rename | Native `save_policy_in_transaction` executes these stages. The C5 test injects each error once and checks the original bytes, old live and fresh decisions, the unrelated allowed control, absence of a success audit, and temporary cleanup. The partial-write case leaves no published partial policy. |
| Directory sync and activation | Both follow rename. A handled native failure saves the original text and calls its activation callback under the same lock. A separate case fails the rollback temporary creation after an activation fault; Admin reports rollback failure and live and fresh Rust observe the remaining complete new policy. Native Admin currently passes a no-op activation callback; policy watcher reload is separate. The accepted #621 invalid-reload tests cover that loader boundary. |
| Expiry persistence | Expiry shares the native save function but logs a write failure and continues with its in-memory expired-host pruning. Its C5 case injects a file-sync error through the real startup path. It checks old bytes, no temporary residue, the warning, effective denial, and fresh startup pruning. Expiry does not use the Admin rollback path. |
| Retained Python callers | Policy-host CLI and agent-store mutations share `save_roundtrip`. The CLI catches a post-rename directory-sync error even though the complete new file is visible; agent-store propagates a pre-rename file-sync error and preserves old bytes. The C5 case checks both callers, temporary cleanup, and live and fresh Rust decisions. The unused `locked_policy_transaction` helper is not a current public writer. |
| Mutation-related audit | The native Admin listener test poisons the real audit writer. The host mutation commits and changes active and fresh decisions, while the listener closes the request without a success response or `admin.host_allowed` event. The accepted #635 audit visibility results remain separate. This path does not promise global policy and audit atomicity. |

### C6 process death and guarded VM recovery

`tests/proxy_migration/test_native_policy_crash_recovery.py` sends one native
Admin denial for Alice at `revoked.invalid`. Before the denial, Alice reaches a
controlled origin, Bob cannot reach that host, an unrelated allowed host
reaches the origin, and an unrelated denied host does not. The three cases kill
the actual debug Rust proxy at the native writer checkpoint or after Admin
returns success. The test reads the visible policy before death and starts
fresh Rust against that same file. The native transaction holds the policy
read lock while paused, so a new traffic request cannot report an active
decision at the two in-flight checkpoints. The test checks live effects before
the operation, and again after the acknowledged operation. It checks fresh
effects after each death.

| Checkpoint | Process-death expectation | Disposable-VM expectation |
|---|---|---|
| Before rename | The old complete policy remains. One fully written temporary file remains after process death. Fresh Rust still permits Alice's target access. | The old complete policy remains. The temporary file may survive or disappear according to the recorded storage configuration. |
| After rename, before directory sync | The complete new policy is visible on the still-running operating system. Fresh Rust denies Alice's target access. | The complete old or new policy may survive. Record the filesystem and virtual-disk configuration to interpret which version survived. |
| After the successful durable Admin response | The complete new policy remains; live and fresh Rust deny Alice's target access. | The complete new policy must survive. |

The unrelated allow and denies must remain effective in each recovered version.
A torn, invalid, or unexpected policy is a finding even if a proxy denies
traffic. The process-death tests require no success audit before an Admin
response. The acknowledged case records a success audit before process death.
VM runtime logs are kept off the policy filesystem. The VM recovery report
records the pre-cut audit count but does not claim that an unsynced audit log
survived VM death. Neither mode claims exactly-once external effects or
physical hardware power-loss durability.

The native disposable-VM protocol is `tools.policy_chaos fault`:

1. On a dedicated, already-supported KVM guest, create a new disk-backed
   `config-dir` with the exact `POLICY` fixture from
   `tools/policy_chaos_recovery.py` and a regular
   `.safeyolo-chaos-disposable` sentinel file. Create a separate disk-backed
   `state-dir`. Keep both outside the source checkout. The guard rejects
   symbolic links for the policy, sentinel, recovery run, and manifest. Build
   the debug Rust proxy from the candidate and install the Python development
   environment.
   Record the guest filesystem type and mount options, virtual-disk format,
   cache mode, backing store, and the outer controller's abrupt VM-stop command.
   The runner requires a writable `tmpfs` or `ramfs` runtime directory on a
   filesystem separate from the policy disk. `/tmp` is the default; pass
   `--runtime-dir` for a different volatile mount when necessary.
2. Inside the guest, set `SAFEYOLO_CHAOS_DISPOSABLE_VM=1` and run
   `uv run python -m tools.policy_chaos fault prepare-power-cut` with
   `--checkpoint`, `--config-dir`, `--state-dir`, `--binary`, and
   `--confirm-disposable-vm`. Use one fresh run ID and fixture directory per
   checkpoint. The accepted checkpoint names are `before-rename`,
   `after-rename-before-directory-sync`, and
   `after-acknowledged-response`. The command prints `PREPARED` only after it
   has synced a recovery manifest. The outer controller copies that manifest
   to its own disk before sending the exact printed
   `ARM <run-id> <checkpoint> <manifest-sha256>` line to the guest command's
   standard input. The guest prints `READY_FOR_POWER_CUT` only after the
   selected native stage or successful durable Admin response is observed.
   The readiness path writes to standard output and volatile runtime storage;
   it does not write or sync the policy filesystem. The controller has 300
   seconds to arm and 120 seconds after readiness to cut the VM. An expired
   window is unexecuted.
3. The outer controller captures both JSON lines outside the VM. In a checkout
   with the same candidate source, run
   `uv run python -m tools.policy_chaos fault ready` with `--manifest` set to
   the copied manifest and `--observation` set to the captured JSON Lines file.
   The manifest, observation, and later cut record must each be a regular file
   of at most 1 MiB; symbolic links and special files are rejected as incomplete.
   Cut the disposable VM only if that command confirms the exact run,
   manifest hash, transaction, and checkpoint. A missing, stale, or repeated
   checkpoint is unexecuted. The controller records the actual abrupt VM-stop
   mechanism, VM ID, filesystem, storage configuration, stop time, and restart
   time in a JSON cut record. The record must also copy `run_id`, `checkpoint`,
   `manifest_sha256`, `transaction`, `target: "vm"`, and
   `abrupt_vm_stop: true` from the confirmed run.
4. After VM restart, copy the outside observation and cut record into the
   guest. Set the opt-in variable again. Run
   `uv run python -m tools.policy_chaos fault recover` with `--run-id`, `--config-dir`,
   `--state-dir`, `--observation`, `--cut-record`, `--output`, and
   `--confirm-disposable-vm`. Recovery checks complete file versions, fresh
   Rust effects, unrelated controls, audit claims, and temporary residue
   before writing its report. Preserve that report and the original policy
   observations before any optional cleanup or restoration. A missing cut
   record returns `INCOMPLETE`; an invalid surviving policy returns `FINDING`.

The three actual disposable-KVM cuts have been executed. Lens
[accepted C6](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5873175078)
after independent review of the corrected report from the retained second-cut
state; all four C6 boxes are checked. This C8 slice requests no additional cut.
The hypervisor stop remains controller-attested. The corrected run reused the
retained state, and audit-log persistence across the cut was not independently
proved. The result makes no physical-power-loss or in-flight exactly-once
claim. Guard-only tests do not stop a VM and do not count as VM recovery
evidence. The recovery command checks a declared outside-VM cut record; it
cannot verify the hypervisor action by itself.

## Native chaos selection for #831

The ten historical `tools/policy_chaos.py` default groups are the finite
selection below. The [historical results](../experiments/policy_assurance/RESULTS.md)
describe the Python engine only. Existing native results used here are the
[#621 scope and precedence review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413),
[#621 revoke and reload review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779),
[#621 invalid-policy review](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272),
and [#638 installed state transition review](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040).
The named tests establish only the assertions they run. The `--group` entries
in the existing mapping below bind the finite native runner selection; each
name selects the exact test in `tools/policy_chaos.py::GROUPS`. C7's disposable
mutants stay outside the recurring selection. An open obligation in the last
column is not satisfied by a historical Python pass.

| Historical default group and defect family | Existing proof reused | Incremental native chaos obligation or removed path |
|---|---|---|
| `catalogue`: agent allow leaking to baseline, lost agent catchall deny, wrong-agent edit, and deleted peer agent | [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), `test_agent_egress_scope.py::test_agent_and_destination_precedence_on_concurrent_reused_connections` and `test_shared_operator_approval.py::test_shared_operator_approval_is_scoped_and_retried` cover effective agent and destination scope. | C3's selected `--group host-properties`, `host-histories`, `credential-histories`, and `service-histories` add composed real-writer edits and peer preservation. C7 calibrates transaction oracles separately; pure matcher corruptions add no recurring chaos run when these existing assertions detect the same effective change. |
| `catalogue`: broadened credential, deny becoming prompt, wildcard default becoming prompt, exact allow becoming wildcard budget | `test_operator_consumer_approval.py::test_retained_operator_client_approves_and_denies_native_credentials`, the [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), and `test_native_network_policy.py::test_native_policy_runtime_guard_modes` cover credential and network effects. | C3's selected `--group host-properties`, `host-histories`, and `credential-histories` add generated precedence, wildcard, credential and writer combinations that can expose an unintended increase in the allow set. |
| `properties`: semantic TOML round trip, selected-agent approval, denial monotonicity and unrelated-agent preservation | The [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413) checks a fixed real-proxy matrix; the [#621 reload result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779) checks live decisions after reload. | C3's selected `--group host-properties` and `host-histories` generate policy edits, quoting and precedence combinations, then compare intended permission deltas with active and fresh Rust effects. A serialized TOML comparison alone cannot close this row. |
| `sequences-clean`: host allow, deny, rate, bypass, remove and reload; credential approval/reload; agent metadata and service edits; gateway grant and binding add/remove; transaction observation | `test_shared_operator_approval.py`, `test_operator_consumer_approval.py`, `test_gateway_risk_approval.py`, the [#621 reload result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848982779), and the [#638 installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) cover fixed effects and durable service/grant reuse. | C2 selects `--group existing-state` for the list-backed original/final, audit, residue and fresh-state relationships. C3 selects `host-histories`, `host-rate`, `credential-histories`, and `service-histories` for bounded mixed histories and rate effects through supported writers. The removed Python `PolicyEngine` caller is inapplicable; its permission-integrity obligation transfers to the native writer. |
| `host-canonicalization`: case and DNS-label wildcard boundary; trailing dot, Internationalized Domain Names in Applications (IDNA), unusual dot, IP text and conflicting authority | The [#621 scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413), `test_native_network_policy.py::test_native_policy_homoglyph_authority_forms`, and `test_native_network_policy.py::test_native_policy_raw_decodable_mixed_script_ace` cover selected real ingress, but not a suffix-sharing sibling of a wildcard host. | C3 selects `--group host-boundary` and `host-properties`: after a supported writer adds `*.scope.invalid`, a proper child can gain access but `evilscope.invalid` must not. Canonical-host interactions also alter a mutation's scope. The old mitmproxy `HTTPFlow` ingress is removed, so replaying that object path is inapplicable. The historical non-normative observations do not become new policy guarantees. |
| `writer-matrix`: `cli-same`, `engine-same`, `agents-same`, `admin-same`, `gateway-same`, `cli-locked`, `engine-agents`, `admin-gateway`; lock controls, lock-before-read and revocation versus unrelated approval | The [#638 installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) establishes serial cross-version reuse. `policy_runtime.rs::expiry_write_after_a_concurrent_policy_change_keeps_the_earlier_watermark` establishes one native watermark edge. Neither proves the matrix's concurrent writes. | [#831 C4 acceptance](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5868912512) covers selected `--group writer-contention` and the two native publication histories in `service_catalog_tests::contention`. C7 calibrates lost update and stale publication separately. |
| `failure-stages`: parse, normalization, serialization, temporary creation/write, file sync, rename, directory sync, activation/reload and audit | The [#621 invalid-policy result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272) and `test_native_network_policy.py::test_native_policy_failed_reload_retains_scoped_decisions` cover startup refusal and last-known-good reload. | [#831 C5 acceptance](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5870453777) covers selected `--group failure-stages`: actual native writer stages, partial write, failed rollback and audit interaction. The debug profile filters out `test_default_release_build_cannot_activate_stage_control`, which requires a separate release binary and is covered by the cited C5 result. The selected cases check response, file, active and fresh state at each commit boundary. C7 calibrates false success separately. |
| `crash-recovery`: process death before/after rename and unrelated restriction preservation | [#638's clean installed transition](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040) reuses durable state but does not cut a transaction. | C6 selects `--group crash-recovery` (`test_native_policy_crash_recovery.py`) for all three process deaths and the guarded VM protocol. The three actual disposable-KVM stops and corrected-report review are [accepted for C6](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5873175078). Fresh Rust reads the surviving file without a fixture rewrite. |
| `known-no-rate`: an unrated allow disappeared or bypassed the aggregate budget | `test_operator_consumer_approval.py::test_retained_operator_client_approves_exact_native_network_scope` checks the native 600-rate approval and real origin effect; `test_native_network_policy.py::test_native_policy_budget_is_shared_and_survives_reload` checks budget reuse. | C3 selects `--group host-budget` and `host-histories` for an unrated host allowance, where disappearance or budget escape changes a later decision. |
| `known-persistence-failure`: save error reported success and broadened live access | The [#621 invalid-policy result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5819850272) covers malformed reload, but not a writer save failure. | C5 selects `--group failure-stages` to inject a real native writer failure and require a truthful result, preserved pre-commit bytes and decisions, and no premature success. |
| `known-public-concurrency`: policy-host lost update | `policy_runtime.rs::expiry_write_after_a_concurrent_policy_change_keeps_the_earlier_watermark` covers the native watcher watermark, not competing public writers. | [#831 C4 acceptance](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5868912512) covers selected `--group writer-contention` for two-writer lock order and publication histories. C7 tests the lost-update assertion against a stale-read mutant separately. |

The first two `catalogue` rows name all eight historical corruptions. They
reuse the cited native scope and credential results; C3 adds composed real-writer
histories. A new pure matcher or scope mutant would repeat those permission
checks without testing a new transaction behavior.

For C2, the selected `existing-state` module contains the success step and two
startup negatives. The success step begins with the stock external lists and
synthetic HMAC state, then checks the actual approval result, original/final
policy bytes, controlled-origin decisions before, live and after a fresh Rust
process, the scoped mutation audit, unrelated content and temporary residue.
The negatives require an explicit startup failure for a missing list or policy
file. C3's [accepted generated histories](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5868301471)
and C4/C5's accepted tests above provide the additional retained writers,
compositions and error-stage relationships; the [#638 installed result](https://github.com/craigbalding/safeyolo/issues/638#issuecomment-5851990040)
provides the installed cross-version state path. C2 remains for independent
review of this binding and the new per-step observation.

The five source holdouts are separate from the ten defaults:

| Historical holdout | Native disposition |
|---|---|
| Case-sensitive wildcard matching | The old mutation changed direct Python matching but mitmproxy's ingress canonicalization concealed it. [#831 C3 acceptance](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5868301471) includes `test_host_permission_properties`, which writes an uppercase wildcard in generated cases and checks lower-case hosts through the real Rust proxy. Do not credit the historical missed ingress assertion. |
| Agent-scoped mutation loses its condition | Reuse the [#621 native scope result](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5848762413) and C3's real writer/peer observations. A duplicate scope mutant adds no transaction coverage. |
| Wildcard loses its DNS label boundary | The C7 mutation below is detected by `test_written_wildcard_has_dns_label_boundary` after the supported CLI writer adds `*.scope.invalid`. The cited #621 cases check proper children, not the suffix-sharing sibling. |
| Locked mutation reads before its lock | C4's native `engine-same` contention assertion detects the C7 stale-read mutation below. The retained Python lock controls remain in the accepted C4 group. |
| Shared mutation swallows a save failure | C5's retained Python CLI assertion detects the C7 source holdout below. The native Admin failure assertion independently detects the same false-success responsibility. |

### C7 finite calibration

The clean controls ran on Linux from integration commit
`9d268155bc09314c6e94e977e5cad31d8b52670b`, with Python 3.13.15 and
Rust 1.94.0. The wildcard control uses the one-line fixture change in this
review candidate. Each source mutation ran in a disposable checkout outside
the working tree. The debug Rust binaries were copied to distinct paths before
the next build. No source mutation is committed or selected by the normal runner.

| Responsibility and disposable implementation change | Frozen assertion: clean control, then mutant | Independent effect at the real boundary |
|---|---|---|
| Lost update: move `approvals.rs::update_policy`'s source read before `lock_policy` | `test_writer_matrix_has_real_lock_overlap_and_live_effect[engine-same]` passed clean; the mutant failed because `engine-one.invalid` was absent after both Admin writers completed. | The second host survived. A fresh Rust proxy denied the lost first host (`403`, zero origin accepts), allowed the second (`200`, one accept), and kept `blocked.invalid` denied. |
| False native success: return `Ok` when `save_policy_in_transaction` fails | `test_native_staged_failure_restores_original_and_never_reports_success[file-sync]` passed clean; the mutant failed at the expected Admin error assertion. | The named file-sync checkpoint returned an error, but Admin replied `status=added`. The file stayed unchanged and live/fresh Rust still denied the target (`403`, zero origin accepts). |
| Swallowed retained Python save failure: catch `OSError` from `save_roundtrip` in `locked_policy_mutate` | `test_retained_python_callers_share_save_but_report_distinct_errors` passed clean; the mutant failed at the expected CLI error assertion. | An injected directory-sync error occurred, but the CLI exited zero and printed `Added host`. The replacement file and live Rust allowed the target (`200`, one origin accept) without confirmed durability. |
| Stale publication: omit `policy_runtime.rs::load`'s adoption of the earlier source watermark | `older_load_and_later_scoped_revoke_converge_without_resurrecting_access` passed clean; the mutant failed when the watcher reported no change. | The persisted policy contained Alice's newer scoped denial, but the published older snapshot still returned `200` after the watcher check. |
| Wildcard label boundary: replace `*.` with `*` before `services.rs::resource_matches` evaluates a pattern | `test_written_wildcard_has_dns_label_boundary` passed clean; the mutant failed after the CLI write at step 1: `evilscope.invalid` returned `200` instead of `428`. | Before the write, the sibling returned `428` with no origin accept. Afterward, the proper child and sibling each returned `200` with one accept; a fresh Rust process also allowed the sibling. |

The wildcard finding retained this actual one-operation trace:

```json
{
  "family": "wildcard",
  "root": "scope.invalid",
  "initial_wildcard": "*.separate.invalid",
  "operations": [{"action": "allow", "host": "*.scope.invalid"}]
}
```

On Linux, save that JSON to `/tmp/c7-wildcard.json`. From the repository root,
with the development Python environment installed, select a copied debug Rust
binary at `/absolute/path/to/copied-binary` and run:

```sh
uv run --frozen python -m tools.policy_chaos replay /tmp/c7-wildcard.json \
  --binary /absolute/path/to/copied-binary
```

The clean binary returned `PASS`. The wildcard mutant reproduced
`(step=1, alice, evilscope.invalid, expected=428, actual=200)` and returned
`FINDING` with exit 1. Invalid setup remains `INCOMPLETE`. These finite checks
do not claim an exhaustive mutation score or a VM recovery result.

The historical `fault prepare-power-cut` / `fault recover` protocol is also
separate. It paused the Python writer and used that engine for recovery; no
native VM-death result is inherited. The C6 candidate adds the guarded native
protocol described above. Actual disposable-KVM stops at all three named
checkpoints were executed and [accepted for C6](https://github.com/craigbalding/safeyolo/issues/831#issuecomment-5873175078).
C8 restores the recurring incremental profile. The old Python-engine recovery
oracle is inapplicable because that engine was removed;
the fresh Rust proxy and controlled origin supply the required recovery effects.

## Review trigger

Review this decision whenever any of the following changes:

- agent sandboxes gain a policy-write path;
- complete policy documents are accepted from a network API or integration;
- policy files can be imported automatically from an untrusted repository;
- the config share is no longer read-only;
- SafeYolo expands its threat model to hostile same-host processes; or
- parser/resource exhaustion becomes remotely triggerable.
