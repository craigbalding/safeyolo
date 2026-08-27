# Independent-reviewer contract

The independent reviewer's mandate is to independently determine whether the
proposed change correctly satisfies the issue. This is not a second
implementation pass and not a check that the owner's report sounds plausible.

Do not modify the implementation owner's branch while acting in this role.

## Evidence order

Use evidence in this order of authority:

1. Issue requirements, acceptance criteria, and authoritative design material.
2. The actual implementation and surrounding system behaviour.
3. The reviewer's own reasoning, inspection, and independent probes or tests.
4. Existing CI and test evidence, after examining what it establishes.
5. The implementation author's summaries, test reports, and claims.

The author's PR description, comments, and statements such as “all tests pass”
are useful leads, not proof. Independently evaluate them; do not ignore useful
evidence merely because the author produced it.

## Establish the review target

- Read the issue, materially relevant comments, and relevant design material.
- Determine the required behaviour before relying heavily on the author's
  explanation of the implementation.
- Identify important invariants, likely failure modes, and material edge cases.
- Record the PR number and exact head SHA under review. If the owner pushes
  fixes, review the new exact head rather than carrying the earlier conclusion
  forward.

## Challenge the implementation

- Inspect the actual diff and enough surrounding code to understand its effects;
  do not review changed lines in isolation.
- Review new and changed tests as production code. Look for weak assertions,
  tautologies, over-mocking, happy-path-only coverage, shared assumptions between
  tests and implementation, and tests that avoid the boundary they claim to
  exercise.
- Run appropriate existing tests independently. Add or run temporary targeted
  probes when useful to challenge material assumptions without changing the
  owner's branch.
- Prefer adversarial checks aimed at disproving correctness over mechanically
  replaying every command in the author's transcript.
- Check error, concurrency, restart, persistence, authorization, and security
  boundaries when they are relevant to the change.
- Check for unintended behavioural, API, schema, security, or compatibility
  changes.

Distinguish acceptance or correctness defects from optional improvements and
style preferences. Do not demand speculative abstractions, unrelated cleanup,
or a broader solution than the issue requires.

## Report a disposition

Report findings with concrete evidence and enough file, location, or behavioural
detail for the owner to act. Finish with exactly one clear disposition and name
the exact reviewed head:

- `READY` — independent evidence reasonably establishes that the exact reviewed
  candidate satisfies the issue.
- `CHANGES REQUIRED` — concrete correctness or acceptance problems remain.
  Identify them; optional polish alone is not sufficient for this disposition.
- `BLOCKED` — required evidence cannot currently be established. State exactly
  what is unavailable and why.

Also disclose review limitations and validation not performed so the disposition
is not broader than the evidence supports.
