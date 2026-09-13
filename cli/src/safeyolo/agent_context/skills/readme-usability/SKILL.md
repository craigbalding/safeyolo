---
name: readme-usability
description: Write, rewrite, or review repository READMEs for clear understanding and correct first use. Use for README.md, quickstarts, and repository onboarding or setup instructions.
---

# README Usability

## Objective

Make the README the shortest clear path from understanding what this is to using it correctly.

A README is a landing page and operational ramp, not a dumping ground for everything known about the project.

## Working scope

Match the work to the request:

- **Review:** identify problems and concrete corrections; do not edit unless asked.
- **Small edit:** fix the affected instructions and dependent steps or links; check surrounding context without automatically restructuring the document.
- **Creation or rewrite:** review the complete reader journey, duplication, and division between README and reference material.

Use the user's brief and project purpose to identify the primary reader. Inspect relevant code, configuration, and docs to verify commands, paths, defaults, versions, and effects. Do not invent capabilities; preserve project terminology.

Read applicable project guidance for owner priorities. For SafeYolo only, also read [the project notes](references/safeyolo.md); do not apply those examples to unrelated projects.

## Reader path

Organize around reader questions, not a prescribed section sequence:

- **Evaluator:** What is this? Is it for me?
- **New user:** How do I reach a useful first result?
- **Returning user:** Where is the command or link I need?
- **Troubleshooter:** How do I recognize success and recover from failure?

Up front, include only constraints that could change the decision to proceed. Put other prerequisites, defaults, and consequences near the action they affect. Avoid a wall of caveats before readers see anything useful.

Show one complete normal path, with a representative result. Route readers to required platform instructions before dependent steps; keep optional alternatives separate. A library may lead with a small illustrative example, clearly distinguished from a setup step.

## Context before action

**Never let the reader execute an instruction before telling them anything that could materially change whether or how they should execute it.** A warning after the command it qualifies is a documentation bug.

Make execution context explicit when it is not obvious from the documented workflow, and always when it changes. Carry forward clearly established context instead of repeating boilerplate before every block.

Use this mental checklist; include only what the reader needs:

- **Where:** environment and working directory.
- **Who:** user or privileges, when relevant.
- **Requirements:** prerequisites, versions, and compatibility.
- **Inputs:** real values or files, where to obtain them, and what to replace.
- **Changes:** affected files or state, persistence, and overwrites.
- **External effects:** downloads, network access, or published changes.
- **Behaviour:** defaults that affect results and useful supported overrides.

Label optional steps before execution. Keep commands copyable; do not present unresolved example values as ready to run. Short, valid comments may clarify a block, while required context belongs before it. Keep expected output outside runnable blocks. Explanation after a command must not change whether or how it should have been run.

## Reduce reader decisions

Moving a complicated explanation above a command does not make the procedure usable. Prefer supported defaults, examples, or helpers that resolve choices the software can reliably handle. Leave readers the decisions that require their judgment.

If documentation cannot simplify the workflow, identify the tooling improvement needed. Do not invent a helper or implement beyond the authorized scope. Document the actual required choices until that tooling exists.

## Verification

Choose a small check that demonstrates the claimed result and show its expected outcome. For a library, a successful import proves it loads; a representative input and expected output demonstrate useful behaviour. Do not treat availability as proof of correct configuration or a complete workflow.

Place verification after the relevant action. State material limits on what it establishes and qualify claims that remain unverified.

## Delete or move before adding

When improving a README, expect to delete or move material. Added text carries a burden of proof: it should help the intended reader understand, decide, act, verify, or recover. Never omit necessary information just to meet a length or step-count target.

Keep user-visible behaviour ahead of implementation detail. Link to authoritative reference for exhaustive options, architecture, contributor setup, and uncommon variants. Preserve expert explanations there; helpers should not become the only explanation of how a procedure works. Required steps must remain on the documented path.

Use meaningful headings, short paragraphs, and concrete language. Use lists for parallel items and tables for comparisons. A representative example or short `--help` excerpt can answer a question; an exhaustive inventory usually belongs in reference. Put decoration below useful information and avoid narrating obvious commands.

## Final review

Apply this to the requested scope:

1. **Navigation:** scan headings and the opening. Can readers understand the purpose and find first use, common tasks, and recovery?
2. **Execution:** read each command with its established context and preceding instructions. Are changes of context clear before action?
3. **Continuity:** trace prerequisites through the claimed result. Identify missing inputs, steps, or links.
4. **Decisions:** find avoidable choices and configuration reasoning that supported tooling could handle.
5. **Evidence:** check that verification demonstrates what the text claims.
6. **Density:** identify duplication and specialist detail to delete or move; justify additions within scope.

Finally, ask: **Have any prerequisites, defaults or consequences first appeared after the action they qualify?** In a review, flag each instance; when editing, move the relevant context before the action.
