# Technical writing

SafeYolo uses principles from Simplified Technical English (STE) for
procedural, normative, command-line interface (CLI), configuration, security,
and public engineering prose. This is a clarity standard. It is not a claim of
formal ASD-STE100 compliance, and it does not impose a controlled vocabulary.

The rule applies to current authoritative text in README files, documentation,
CLI help and messages, active issue and pull-request descriptions, release
notes, Dispatch material, comments, docstrings, examples, test descriptions,
and factory or coord instructions. Normally leave old discussions and other
historical records unchanged unless the repository still cites them as current
guidance.

## Writing rule

1. Put a condition before the action or result that depends on it.
2. Give each sentence one main instruction or assertion.
3. Name the actor when the actor matters. Use a concrete verb.
4. Preserve modality. `must`, `should`, `may`, `does`, and `does not` are not
   interchangeable.
5. Use one term for one concept. Define an alias before using it.
6. Expand an abbreviation at its first use in each document that readers can
   consume independently.
7. Replace vague references such as "this", "it", "others", and "above" when
   the referent can be named.
8. Keep metaphor, hype, and internal shorthand out of requirements, security
   guarantees, procedures, and failure descriptions.
9. Use bullets or tables for independent conditions, platform branches, or
   outcomes.
10. Treat line length as a review signal, not an acceptance criterion. A short
    sentence can still be ambiguous.

## Separate corrections from rewrites

A readability review must not conceal a behavior or security change.

- A **clarity-only rewrite** preserves the original meaning. It can split,
  reorder, or rename text without changing a material claim.
- A **substantive correction** changes a factual claim, resolves a
  contradiction, adds missing information, or updates stale behavior. Verify
  the current behavior from code, tests, or another authoritative source, and
  disclose the correction separately in the change summary.
- An **unresolved finding** identifies the exact conflicting claims and the
  evidence still needed. Ask the operator only when the choice would materially
  change behavior or a security claim.

Do not turn uncertain text into a stronger guarantee. Do not remove a detail
because the detail makes a sentence harder to shorten.

## Lossless review checklist

For every material old/new rewrite, compare the two versions for all of these
items:

- claims and required outcomes;
- actors and affected readers;
- conditions, defaults, precedence, and platform scope;
- exceptions, limitations, uncertainty, and failure behavior;
- rationale and provenance when they affect a decision or verification;
- modality and security properties;
- commands, paths, identifiers, numbers, and time bounds; and
- acceptance criteria and evidence requirements.

The rewrite is lossless only when every material item remains explicit or when
an evidence-backed substantive correction is identified as such.

## Review order

Use this order when a change spans multiple kinds of prose:

1. **P0:** README, installation and setup material, operator and user guidance,
   CLI help, and user-facing errors or warnings.
2. **P1:** Dispatch material and current public GitHub material, including
   active issue or pull-request bodies and release notes.
3. **P2:** Docstrings, comments, configuration descriptions, examples, and
   test descriptions.
4. **P3:** Internal factory and coord prose.

For an unrelated active issue or pull request, report a proposed edit instead
of silently changing its conversation. Do not rewrite Git history.

## Validation

Review the final diff side by side with the lossless checklist. Run the checks
that cover every changed format, generated file, link, CLI surface, and source
file. Repository drift checks can verify tokens and generated artifacts, but
they do not score vocabulary or prove that prose is unambiguous.
