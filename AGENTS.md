# SafeYolo repository agents

This file governs agents working on the SafeYolo repository. It complements,
and does not replace, the [sandbox baseline](docs/AGENTS.md) that SafeYolo host
scripts stage into running agents.

## Security boundaries and operator policy

Follow the existing [security model](SECURITY.md#security-model): the host and
operator are trusted; agent code may be compromised. SafeYolo enforces sandbox
isolation, explicit host mounts, mediated network access, agent identity,
authorization, and credential protection. Do not weaken those boundaries.
Within the operator-approved workspace and capabilities, support autonomous
coding, shell use, dependency installation, and guest administration. Guest
`sudo` is not host privilege. Writable mounts can contain real operator data;
isolation does not make destructive changes harmless.

Implementation authority does not include inventing operator policy. Before
coding and again when reviewing the diff, ask what the change newly forbids,
limits, hides, or makes harder. Check the requested outcome, existing security
requirements, evidenced technical constraints, and comparable implementations.
Do not treat a possible safety benefit as authority to impose a restriction.

If an additional policy choice is not required, leave it unimplemented. Surface
material suggestions as advisory: explain the benefit, behavioural cost, and
differences from existing implementations, and state that it was not applied.
Continue ordinary work without awaiting a response. If unsupported policy has
already become code, remove it and unnecessary compensating machinery during
self-review or independent review, before merge. Ask the operator only when
completing the requested work genuinely requires a new policy decision.

An actual vulnerability is not an optional policy suggestion. Identify the
concrete failure path and affected security property; fix an in-scope defect
and verify the repair. If repair needs additional scope or authority, report
the exposure promptly and ask for the specific decision needed. Do not silently
weaken a boundary or declare an unresolved material exposure acceptable under
the advisory rule.

## Roles

SafeYolo keeps implementation and independent acceptance separate:

- If assigned `You are the issue owner for #123. Work it through to a
  reviewable PR.`, read and follow the
  [issue-owner contract](docs/agent-roles/issue-owner.md).
- If assigned `You are the independent reviewer for #123 / PR #456. Review it
  under the repository reviewer contract.`, read and follow the
  [independent-reviewer contract](docs/agent-roles/independent-reviewer.md).

Do not silently combine these roles for the same change. The GitHub issue and
its materially relevant discussion define the requested outcome and acceptance
criteria; the selected role contract defines how the agent works.

Existing repository documentation, [security boundaries](SECURITY.md), operator
instructions, and SafeYolo sandbox instructions still apply. Identify the exact
branch and commit, and the PR when one exists, for work implemented or reviewed.

## Technical writing

Apply the project [technical-writing rule and lossless review
checklist](docs/technical-writing.md) to every authoritative prose change. Treat
factual contradictions, stale behavior, missing information, and changed
security claims as substantive corrections rather than style edits.

## Python changes

Apply the [Python defect-prevention rules](docs/DEVELOPERS.md#python-defect-prevention)
when implementing or reviewing Python. Reuse existing helpers, make exception
handling deliberate, and remove dead code without removing required behaviour.
Check scanner findings against the code; do not rewrite valid constructs merely
to silence an alert.

## Acceptance tooling

Use the [SafeYolo acceptance graph](cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/accept-safeyolo.yaml)
to select tools and environments for the behavior under review. Its annotations
explain how to obtain the tools and use them to create and run focused tests.
Use the [SafeYolo acceptance tooling guidance](docs/DEVELOPERS.md#acceptance-tooling)
for the dependency inventories and focused Python complexity check. Factory
contracts define the responsibilities; this repository supplies its specific
tools, and the operator brief can bind their current resource locations.

## Coordination

Repository agents using coord follow the SafeYolo
[low-chatter work-coordination protocol](cli/src/safeyolo/agent_context/skills/safeyolo/references/coord.md):
targeted handoffs are self-contained, and execution is silent between meaningful
work-state transitions. The role contracts above specialise that generic
protocol for the issue-owner / independent-reviewer loop.
