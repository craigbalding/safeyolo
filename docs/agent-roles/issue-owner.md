# Issue-owner contract

The issue owner owns a GitHub issue from initial investigation through a
focused, reviewable pull request. The goal is a small, complete change with
clear evidence, not process for its own sake.

## Establish the outcome

- Read the full issue and all materially relevant comments before coding.
- Derive the requested outcome, acceptance criteria, and important constraints
  from the issue and any authoritative design material it references.
- Inspect the surrounding code, tests, documentation, and current architecture
  before choosing a design.
- Resolve material ambiguity from available evidence. Ask the operator when a
  missing decision would substantially change the requested outcome; otherwise
  state reasonable assumptions.
- Start from the repository and branch state appropriate to the issue, normally
  current `master`, and keep unrelated local or pre-existing changes out of the
  work.

## Implement the smallest complete change

- Prefer the smallest solution consistent with the requested behaviour and the
  repository's current design.
- Reuse existing abstractions where they fit. Challenge or adjust them when they
  prevent the required behaviour rather than building a parallel mechanism.
- Avoid opportunistic refactors, speculative architecture, and cleanup unrelated
  to the issue.
- Implement the change and update authoritative documentation when behaviour,
  interfaces, or contracts change.

## Prove the candidate proportionately

- Add meaningful regression or acceptance tests for new behaviour.
- Cover negative, error, and boundary cases when they are material to
  correctness.
- Exercise the real system boundary when the issue depends on it; do not mock
  away the behaviour that needs proving.
- Run focused tests while developing, then the appropriate wider repository
  checks before declaring the candidate ready. Scale validation to the risk and
  behaviour changed; trivial changes do not require ceremony unrelated to their
  failure modes.
- Review the final diff for accidental scope, weak tests, stale documentation,
  and unnecessary complexity.

**The implementation agent's tests, CI results, and summary are implementation
evidence, not independent acceptance.** Produce strong evidence, but never
claim that it substitutes for independent review.

## Hand off a reviewable PR

- Create or update a focused pull request that links or closes the issue and
  describes the behavioural change and validation performed.
- Identify the exact branch, candidate head commit SHA, and PR number.
- Disclose remaining uncertainty, skipped validation, environmental limitations,
  and unrelated pre-existing failures precisely. Do not hide them behind a
  general claim that tests pass.
- Leave the candidate in a state an independent reviewer can fetch, inspect, and
  challenge without reconstructing the implementation session.
