# Policy Assurance Experiments

These experiments evaluate which testing techniques genuinely detect policy
security failures under SafeYolo's documented threat model. They are not part of
the normal pytest collection and do not assume that the current implementation
is correct.

The threat-model decision is recorded in
[`docs/policy-assurance-threat-model.md`](../../docs/policy-assurance-threat-model.md).
The first measured run and technique decisions are recorded in
[`RESULTS.md`](RESULTS.md).

## Experimental questions

1. Does a broad but finite set of real policy decisions notice representative
   permission broadening and cross-agent corruption?
2. Do generated policies expose normalization, persistence, or authorization
   behavior missed by hand-written examples?
3. Do generated operation sequences expose live-versus-disk disagreement?
4. Do real ingress objects preserve hostname boundaries between URL parsing,
   `Host`, homoglyph detection, and PDP enforcement?
5. Do representative writers preserve completed disjoint changes under
   controlled same-writer and mixed-writer interleavings?
6. At which failure and process-death stages do file, live policy, result, and
   audit evidence stop agreeing?

The experiments intentionally vary more data than is strictly required for
each assertion. Generated worlds include several agents, hosts, credentials,
wildcards, case changes, Unicode and punycode names, child domains, methods,
and paths. Precision is concentrated in the security checks:

- which request became more permissive;
- whether an unrelated agent changed;
- whether a denial increased access;
- whether active and durable policies agree; and
- whether both completed concurrent mutations survive.

## Components

- `harness.py` compiles real policies and records effective network and
  credential decisions over a broad request surface. Its transaction record
  captures result or exception, original/final hashes, TOML validity, live and
  spawned-process decisions, unrelated-policy preservation, audit events, and
  temporary-file residue.
- `defects.py` contains calibration corruptions representing threat families,
  not parser trivia.
- `experiment_permissions.py` compares finite decision surfaces and Hypothesis
  properties.
- `experiment_sequences_clean.py` separates host, credential, agent metadata,
  and gateway state operations so one defect cannot stop another family.
- `experiment_sequences.py` retains the no-rate and swallowed-persistence
  known-finding replays.
- `experiment_host_canonicalization.py` sends real mitmproxy `HTTPFlow` objects
  through `NetworkGuard` and the configured PDP. Trailing-dot, IDNA,
  unusual-dot, IP-text, and ambiguous-authority results are evidence, not
  invented contracts.
- `experiment_writer_matrix.py` covers policy-host CLI, live-first engine,
  shared lock helper, agent store, Admin mutation, and gateway persistence.
- `experiment_failure_stages.py` injects parse-through-audit failures, while
  `experiment_crash_recovery.py` terminates child processes around rename. The
  latter is process-death testing, not a power-loss durability claim.
- `holdouts.py` copies source to temporary directories, changes only those
  copies, proves behavior changed, and measures the frozen assertion.
- `run_experiments.py` runs groups independently and can write a JSON evidence
  report.

## Running

Run everything and retain full evidence outside the repository:

```bash
uv run python experiments/policy_assurance/run_experiments.py \
  --output /tmp/safeyolo-policy-experiments.json
```

Run or repeat selected groups:

```bash
uv run python experiments/policy_assurance/run_experiments.py \
  catalogue properties sequences-clean --published-seeds

uv run python experiments/policy_assurance/run_experiments.py \
  host-canonicalization writer-matrix failure-stages crash-recovery holdouts

uv run pytest -q experiments/policy_assurance/experiment_sequences.py
```

The runner emits `PASS`, `FINDING`, `REPRODUCED`, `RESOLVED`, `OBSERVATION`, and
`INFRASTRUCTURE_ERROR` evidence. Known-finding reproduction does not hide clean
families or become a new finding. Synchronization timeouts are deadlock guards,
never performance requirements. The published seeds are replay and stability
evidence, not a statistical confidence statement. Generic state-machine
shrinking remains disabled; accepted findings receive focused regressions.

## Production chaos runner

The experiment techniques promoted for recurring use are composed by the
repository engineering command:

```bash
uv run python -m tools.policy_chaos run \
  --published-seeds --output /tmp/policy-chaos.json
```

This default is hermetic and cannot target an operator policy. The opt-in
`fault prepare-power-cut` and `fault recover` subcommands are intended for a
disposable KVM VPS. They require `SAFEYOLO_CHAOS_DISPOSABLE_VM=1`,
`--confirm-disposable-vm`, and a `.safeyolo-chaos-disposable` sentinel in the
target config directory. The prepare command emits `READY_FOR_POWER_CUT`; the
outer KVM VPS harness owns VM power and invokes recovery after reboot.

## Ground truth and holdout discipline

The initial calibration catalogue covers broadening, agent scope, credential
scope, deny/prompt drift, unrelated-agent loss, and wildcard expansion. It is
expected to evolve as real defects are recovered from history or discovered by
the experiments.

Tests are designed around general permission and transaction properties, not
assertions tailored to one corruption function. The runner hashes every
assertion file before lazily importing holdout definitions and checks those
hashes afterward. A holdout is awarded only when its baseline assertion passed
and an independent probe confirmed changed behavior. Assertions are not
strengthened after a result; a contaminated holdout is discarded and replaced.
The JSON report retains the technique-by-defect result, runtime, effective or
equivalent decision, complete output, and frozen assertion hashes.

## Interpretation

A technique is useful when it reliably detects an in-scope defect missed by a
simpler layer, or provides the same protection with meaningfully less bespoke
test machinery. No runtime cutoff is guessed in advance; the runner measures
the actual cost on the relevant environment.

Do not turn every experimental finding into a product requirement. First check
that the behavior violates the threat model and transaction contract, then add
a focused regression test and fix the production path.
