# SafeYolo repository agents

This file governs agents working on the SafeYolo repository. It complements,
and does not replace, the [sandbox baseline](docs/AGENTS.md) that SafeYolo host
scripts stage into running agents.

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
