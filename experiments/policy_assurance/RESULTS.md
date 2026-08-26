# Initial Policy Assurance Experiment Results

Date: 2026-08-26

These are ground-truth measurements from the initial experiment implementation,
not claims that every policy defect class is solved. Commands ran in the project
`uv` environment on the development container. Full machine-readable reports
were written outside the repository under `/tmp`.

## Method

The experiment used real policy compilation, real `PolicyEngine` decisions,
real TOML serialization and reload, and real spawned writer processes. The
bounded decision surface deliberately crossed agents, hosts, wildcard and exact
rules, credentials, methods, paths, case variants, child domains, Unicode,
punycode, and unlisted names.

Precision was limited to the security boundaries under test: effective access
must not broaden unexpectedly; one agent's mutation must not change another
agent; active and durable decisions must agree; a failed save must not report
success or change live policy; and two completed independent writes must both
survive.

The calibration catalogue contained eight representative corruptions. During
construction, two proposed corruptions were rejected because they changed source
data but did not change effective authorization: a narrower denial was masked by
an agent-wide denial, and a wildcard budget was masked by a wildcard denial.
They were replaced with semantic corruptions. This guards against inflating the
detection score with ineffective mutations.

## Measured matrix

One complete run used Hypothesis seed 3000:

| Group | Result | Time | Evidence |
| --- | --- | ---: | --- |
| Calibration catalogue | Pass | 9.016 s | Detected all eight semantic corruptions |
| Generated properties | Pass | 4.257 s | Round-trip equivalence, agent isolation, denial monotonicity |
| Generated sequences | Finding | 1.341 s | Live and reloaded policy disagreed |
| Injected persistence failure | Finding | 0.791 s | Save error was swallowed and success returned |
| Common locked writer | Pass | 2.288 s | Both changes survived for four varied host pairs |
| Current policy-host writer | Finding | 2.836 s | One completed change was lost for all four host pairs |

The complete matrix took 20.529 seconds. The catalogue and generated properties
were then repeated with seeds 4000, 4001, and 4002. All six group runs passed;
catalogue runs took 9.176–10.204 seconds and property runs took 4.209–4.678
seconds. Generated sequences reproduced their finding with seeds 5000, 5001,
and 5002 in 1.209–1.508 seconds.

## Findings

### Allowance without a rate is not durable

A generated one-operation sequence called `add_host_allowance` without a rate.
The active engine allowed the host, but the persisted TOML reloaded as deny for
the baseline and an otherwise unknown agent. The durable representation is an
empty host table, which does not compile back into the live allow decision.

This violates the active-versus-durable consistency property. The public API
must either reject an incomplete allowance or persist enough policy to reproduce
the reported live result.

### Save failure is reported as success

When the TOML round-trip save raised an injected `OSError`, the policy mutation
method logged a warning but did not raise. It had already changed the live policy
and emitted an administrative success event. The file bytes remained unchanged.

This violates failure atomicity and makes the runtime, audit trail, API result,
and source of truth disagree.

### Policy-host writes can lose completed updates

Two spawned processes loaded the same policy snapshot. Controlled barriers made
the first writer complete before the second saved its stale snapshot. The second
write removed the first completed change. This reproduced for ordinary, case-
variant, Unicode/punycode, and deep host pairs.

The same four pairs passed when both processes used the shared locked mutation
helper. This is evidence that the deterministic interleaving is valid and that
the transaction helper addresses this defect family; it is not merely a flaky
scheduler test.

## Technique decisions

- Keep the finite compiled-decision surface as the calibration oracle. It found
  semantic broadening while rejecting source-only mutations.
- Keep generated policy properties. They add broad combinations at a modest and
  repeatable cost, though the passing runs are evidence only for the properties
  and inputs currently generated.
- Keep generation-only state-machine sequences. A generic shrinking pass was
  still running after 83.5 seconds and was stopped, while seeded generation
  produced a clear one-operation counterexample in roughly 1.2–1.5 seconds.
  Accepted findings should be minimized as focused regression tests instead.
- Keep deterministic process barriers for concurrency experiments. They cover a
  real interleaving reliably and have a passing locked-writer control.
- Do not prioritize generic parser fuzzing or large mutation campaigns yet. The
  modest semantic experiments already found three transaction/integrity defect
  families. Fixing and converting those findings into regression tests has more
  immediate security value; broader tooling remains a later holdout exercise.

## Next decision point

Before promotion to CI, fix each accepted product finding and add focused tests
at the owning boundary. Then rerun this matrix against temporary source-level
holdout mutations not present in the calibration catalogue. Promote only the
layers that detect their assigned defect families reliably and within the
measured CI budget.

## Expanded experiment results

Date: 2026-08-26

The second pass added independent clean sequences, real-ingress hostname
evidence, a representative writer matrix, staged failure injection,
process-death recovery, and five isolated source holdouts. Production policy
code was not changed. JSON reports distinguish assertions, known-finding
replays, non-normative observations, and infrastructure errors.

### Commands, seeds, and measured runtime

The generated groups ran with published replay seeds `26082601`, `26082602`,
and `26082603`:

```bash
uv run python experiments/policy_assurance/run_experiments.py \
  catalogue properties sequences-clean --published-seeds \
  --output /tmp/published-generated.json

uv run python experiments/policy_assurance/run_experiments.py \
  --output /tmp/policy-assurance-complete-final.json

uv run python experiments/policy_assurance/run_experiments.py \
  holdouts --output /tmp/holdouts.json
```

| Group | Runs/result | Measured wall time |
| --- | --- | ---: |
| Calibration catalogue | 3 pass | 8.966–10.276 s |
| Generated properties | 3 pass | 4.209–4.557 s |
| Clean generated sequences | 3 pass | 2.291–2.502 s |
| Host canonicalization | Pass, plus observations | 1.630 s |
| Writer matrix | Finding | 6.853 s |
| Failure stages | Finding | 3.577 s |
| Process-death recovery | Pass, plus observations | 1.300 s |
| Known no-rate allowance | Reproduced | 0.884 s |
| Known swallowed persistence failure | Reproduced | 0.703 s |
| Known policy-host lost update | Reproduced | 3.023 s |

These are runtime distributions and individual measurements, not a guessed CI
cutoff. The three generated runs support replay and short-run stability only;
they are not a statistical confidence claim.

### Unique findings and observations

The three prior findings reproduced independently and did not stop any clean
sequence, host, failure-stage, or crash-recovery test.

Two additional integrity failures were isolated for separate product work:

- two gateway instances can each report a successful disjoint contract-binding
  addition while the later snapshot removes the earlier binding;
- `add_host_bypass` reports success and emits a success audit when its reload
  returns `False`.

The writer matrix separately reproduced policy-host lost updates for same-writer
and mixed locked/CLI interleavings. Engine/engine, agent-store/agent-store,
Admin/Admin, engine/agent-store, Admin/gateway, and the denial-or-revocation
racing with an unrelated approval retained both changes in the exercised
orders. Every release order also had a passing shared-lock control.

All parse, normalization, serialization, temporary-write, file-fsync, and
rename injections before commit preserved the old bytes and decisions. A
directory-fsync failure left a complete parseable new file. Audit-write failure
left live and durable decisions coherent and is recorded as an observation
because its response/audit contract is not explicit.

Real ingress lowercased ordinary DNS case. Child and deep wildcard names were
allowed while a suffix-sharing sibling was denied. The wildcard apex was
denied; trailing-dot exact input was denied; Unicode and punycode inputs both
arrived as the same Unicode `request.host` and received the same decision; an
unusual Unicode dot canonicalized to the ordinary allowed hostname. These
apex, trailing-dot, IDNA, unusual-dot, IP-text, and authority results remain
non-normative observations pending an explicit product contract.

Killing a child before rename exposed the complete old policy and left a
recorded temporary file. Killing it after rename but before directory fsync
exposed the complete new policy with no residue. Both preserved unrelated
restrictions. This is process-death evidence only, not simulated power-loss
durability.

### Holdout matrix

Assertions were frozen before holdout definitions were imported. Every
mutation ran in a temporary source copy, never in the working tree, and had to
change observed behavior before detection could be awarded.

| Source holdout | Responsible group | Result | Runtime |
| --- | --- | --- | ---: |
| Case-sensitive wildcard-host matching | Host canonicalization | Missed | 2.859 s |
| Wildcard without DNS-label boundary | Host canonicalization | Detected | 2.928 s |
| Agent-scoped mutation loses condition | Clean sequences | Detected | 2.070 s |
| Locked mutation loads before lock | Writer matrix | Detected | 3.177 s |
| Shared mutation swallows save failure | Failure stages | Detected | 2.099 s |

The case holdout was effective at direct engine evaluation but mitmproxy had
already canonicalized the ingress hostname, so the real-ingress group missed
that lower-layer change. This is a genuine miss, not an equivalent mutant, and
the assertion was not changed afterward. No holdout was contaminated. No new
ineffective source mutation was counted; the two ineffective source-only
corruptions rejected during the initial catalogue design remain rejected.

The machine-readable report records a SHA-256 hash for every assertion file
before holdouts and verifies the same map afterward. The frozen manifest used
for the final holdout run was:

```text
2bfb5d1a2ffbbbd74d21a584df811dbfa68c84c90bf7ce93b33d4e0eb3553302  experiment_concurrency.py
86211766be7e92addc931d791df49d75321c9e05701148a222963f369e05f9d4  experiment_crash_recovery.py
fb4c5bd177f5d70a70ac34f5b646a650adcd12dab2a4be178147c88e7beb4ef8  experiment_failure_stages.py
19257f48c5d5f8917af07548000c0375cd519c78167028318b8879b17e462406  experiment_host_canonicalization.py
6749122078c6258554844f6c3f6fdc11a03ace1a333356085515e81465ec1f5c  experiment_permissions.py
600c0ce41cceb4f2bf179adb753d1a5a780bcc37ef339938186a284fcb6bf33a  experiment_sequences.py
ad930007980b0a46a2503f20189201659aa9999f27563e296f42f0925d424a6c  experiment_sequences_clean.py
22e3d0a7bd6a7b28dee8f5d11005c550478d7e9fe9fc60b9407c507e0f4a5706  experiment_writer_matrix.py
8a7381a1a7618c7cc70d787371117693aea20f3f170160563434eceea1e688ab  harness.py
63c43c78bf74afd6389feb132e43d5beedbf767b759369d7500d6f92edeb0b3a  strategies.py
4cbb7ec1ae373e853a24e7058cd052d48609379eaf3df602c107f584122b53dd  conftest.py
```

## Productionization results

The accepted policy contract and transaction fixes were then implemented and
the promoted hermetic campaign was run with:

```bash
uv run python -m tools.policy_chaos run \
  --published-seeds --output /tmp/policy-chaos-complete.json
```

The complete run took 72.374 seconds. Generated groups used the published seeds
`26082601`, `26082602`, and `26082603`; the other groups use deterministic
barriers or fixed ingress cases and therefore do not consume a Hypothesis seed.

| Group | Production result | Measured wall time |
| --- | --- | ---: |
| Calibration catalogue | 3 pass | 9.212–10.477 s |
| Generated properties | 3 pass | 4.259–4.681 s |
| Clean generated sequences | 3 pass | 2.782–2.891 s |
| Host canonicalization | Pass, plus observations | 2.216 s |
| Writer matrix | Pass | 8.066 s |
| Failure stages | Pass, plus audit observation | 3.622 s |
| Process-death recovery | Pass, plus residue observations | 1.432 s |
| Known no-rate allowance | Resolved | 1.070 s |
| Known swallowed persistence failure | Resolved | 1.212 s |
| Known policy-host lost update | Resolved | 3.517 s |

The writer matrix now preserves both successful disjoint updates, including the
gateway binding case. Failed reloads and failed persistence no longer report a
successful mutation or leave broader live access. A rate-less allowance now
persists an explicit allow and consumes the aggregate network budget. An
explicit host rate is an additional ceiling and is rejected when it exceeds
that aggregate budget.

The hostname evidence remains deliberately non-normative for terminal dots,
IDNA, unusual dots, IP text, and conflicting authority inputs. The audit-write
failure likewise remains an observation because the product response contract
for an otherwise coherent policy mutation has not been chosen. These have not
been silently converted into pass criteria.

The source holdouts were refreshed only where the production refactor made an
old mutation inapplicable or behaviorally equivalent; experiment assertions
were not strengthened. The post-fix holdout results were:

| Source holdout | Responsible group | Result | Runtime |
| --- | --- | --- | ---: |
| Case-sensitive wildcard-host matching | Host canonicalization | Missed | 2.916 s |
| Wildcard without DNS-label boundary | Host canonicalization | Detected | 3.883 s |
| Agent-scoped mutation loses condition | Clean sequences | Detected | 2.166 s |
| Locked mutation loads before lock | Writer matrix | Detected | 3.234 s |
| Shared mutation swallows save failure | Failure stages | Detected | 2.198 s |

The remaining case-sensitive holdout miss is intentional evidence about the
limits of the ingress technique: mitmproxy canonicalizes ordinary DNS case
before the policy matcher sees it. Direct matcher regressions cover the product
contract; the ingress experiment is not credited with detecting a defect it
cannot observe.

The recurring control is split by cost and threat. Focused semantic and
transaction regressions run in normal pull-request pytest discovery. The
bounded generated, real-ingress, writer, staged-failure, and process-death
groups run nightly and manually through `.github/workflows/policy-chaos.yml`.
The guarded prepare/recover protocol is the guest-side component for abrupt
power-off in a disposable KVM VPS; no KVM VPS power cycle was performed in this
development container, and the process-death evidence above is not presented
as physical power-loss durability.

The assertion hashes for this production run were:

```text
4cbb7ec1ae373e853a24e7058cd052d48609379eaf3df602c107f584122b53dd  conftest.py
e1684c7833e2a56ad5b2ec1f65f540cbfd09309b47c0514b674a0ba58ad605f6  experiment_concurrency.py
86211766be7e92addc931d791df49d75321c9e05701148a222963f369e05f9d4  experiment_crash_recovery.py
fb4c5bd177f5d70a70ac34f5b646a650adcd12dab2a4be178147c88e7beb4ef8  experiment_failure_stages.py
19257f48c5d5f8917af07548000c0375cd519c78167028318b8879b17e462406  experiment_host_canonicalization.py
6749122078c6258554844f6c3f6fdc11a03ace1a333356085515e81465ec1f5c  experiment_permissions.py
600c0ce41cceb4f2bf179adb753d1a5a780bcc37ef339938186a284fcb6bf33a  experiment_sequences.py
ad930007980b0a46a2503f20189201659aa9999f27563e296f42f0925d424a6c  experiment_sequences_clean.py
062ea2c57183a534efa3a3eda4ea8a2ef8ff2d750697f67d73dbc679febb3d9d  experiment_writer_matrix.py
4dd17b2c8f5bef13057e2640ed2616ab193c030f5e4b545a94076bd75de38f00  harness.py
63c43c78bf74afd6389feb132e43d5beedbf767b759369d7500d6f92edeb0b3a  strategies.py
```
