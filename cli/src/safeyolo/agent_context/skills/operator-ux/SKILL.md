---
name: operator-ux
description: Design, implement, or independently review SafeYolo operator workflows. Use for changes to command-line interface (CLI) interactions, approvals, configuration, recovery, Command Centre or browser actions, and their help or documentation.
---

# Operator UX

Read `AGENTS.md`, `SECURITY.md` and `docs/operator-interaction-contract.md` from
the target SafeYolo checkout at the revision being implemented or reviewed.
The contract owns the requirements and sources; this skill applies them.
Installed copies also read that checkout, not a bundled or remote replacement.
If the checkout or contract is unavailable, report the missing review basis.

## Establish the journey

1. Identify the operator's goal, starting interface, selected target and known
   context. Infer routine choices from the brief and existing product. Ask only
   when a missing decision materially changes the requested outcome.
2. Inspect the relevant implementation, help and tests before accepting a
   reported limitation. Distinguish interactive terminals, redirected input or
   output, explicit noninteractive modes, and the installed version when relevant.
3. Select the contract clauses affected by this change. Keep adjacent gaps as
   follow-ups; do not turn one workflow change into a product-wide audit.

## Design and implement

- Describe the before/after operator steps briefly, including what the human
  must choose or type and where the result appears. Reuse the existing interface
  and the owner of its authorization, state changes and recovery.
- Apply the selected clauses to the whole affected journey, including help,
  examples and errors. Check whether the system can carry context or supply
  inputs that the proposed design asks the operator to reconstruct.
- Keep explicit commands and application programming interfaces (APIs) complete.
  Do not copy generic confirmation or force flags into SafeYolo's authorization
  model. Use the existing authority and the operator's stated policy.
- Exercise the interaction through the actual terminal or browser, using an
  isolated fixture or other authorized environment. Check the affected scripted
  path too. Reuse focused tests; add regression coverage when a changed behaviour
  needs it. For prose-only work, verify the documented path against its source.

## Independently review

1. Identify the exact candidate and compare the claimed journey with the code
   and instructions. Read the operator's steps as a person using the product.
2. Exercise changed interactions independently. An API response or the owner's
   test report alone does not establish the human experience. Inspect selection,
   decision information, cancellation and outcome feedback in the affected path.
3. Check relevant failure cases: new arrivals during selection, changed review
   state, an interrupted effect or redirected input. Choose cases that could
   change this result; do not require a fixed matrix for every edit.
4. Report a blocking finding with the affected step, applicable contract clause,
   evidence and smallest sufficient correction. Separate proven defects from
   hypotheses and advisory improvements. Follow the existing review process.

## Record the result

Keep the normal pull request or handoff concise: before/after journey, applicable
clauses, mechanism reused, actions exercised and observed result. Name material
limits, including unrun paths. For guidance-only changes, walk through relevant
examples and distinguish source inspection from a runtime usability trial.
Do not add another approval gate, evidence bundle or acceptance record.

## Source reuse

Workflow adapted from Peter Steinberger's
[`create-cli`](https://github.com/steipete/agent-scripts/blob/51ee7e5ee6a7df568786125cf5c8107c9ead2317/skills/create-cli/SKILL.md).
Its MIT licence notice is retained in [LICENSE](LICENSE). The project contract
links the CLI and security-product guidance; it remains the single requirements
reference.
