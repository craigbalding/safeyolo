# Contributing to the SafeYolo repo

Load this when you are editing files in the SafeYolo checkout itself
(source under `cli/src/safeyolo/`, `guest/`, `scripts/`; user-facing
docs; CI configs). Do not load for unrelated project work — SafeYolo
being the sandbox boundary does not mean every task inside it is
SafeYolo development.

For the *why* behind these rules, read the "Documentation drift
protection" section of `docs/DEVELOPERS.md`. This file is the operational
counterpart: the exact commands and the anti-patterns that bite.

## One-time setup in a fresh checkout

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Without this, `git commit` does not gate on the hooks configured in
`.pre-commit-config.yaml` and you are relying on remembering to run them
manually. Do not skip.

## Before every push

```sh
pre-commit run --all-files
```

Not `pytest tests/... && python3 scripts/check_*.py`. That combination
exercises pytest and the drift checks but skips ruff, whitespace,
end-of-file, private-key detection, and the other pre-existing hooks.
Every gate CI runs is in `.pre-commit-config.yaml`; run the whole set.

If `uv` is missing on your machine two hooks (`blackbox-coverage-doc`,
`skill-graph-render`) will report "Executable `uv` not found". Install
`uv` or run those two under CI only — do not merge with them silently
skipped.

## Adding a new claim to a user-facing doc

The user-facing doc allowlist lives in `scripts/doc_allowlist.toml`.
Five drift checks guard every doc in that list; pick the one that fits
what you are documenting.

| You are documenting… | Add… |
|---|---|
| A CLI command or flag | Nothing — `check_doc_cli_flags.py` introspects the Typer surface automatically. Optionally add `# DOC: <doc>` on the `def cmd(` line for reverse binding. |
| A pinned value (version, size, IP, path) | An `[[assertion]]` in `scripts/doc_constants.toml`. Use `must_contain_any = [...]` when several phrasings are equivalent. |
| A security or behavioural invariant enforced by a specific expression | `# DOC: <doc>` marker on the enforcement expression. See DEVELOPERS.md for the per-kind placement table. |
| A claim about a mechanism that could be deleted later | A `[[rule]]` in `scripts/doc_forbidden.toml` blacklisting the phrases that must not remain if the mechanism is gone. |
| A repo-relative file reference | Nothing — the link check runs automatically once the path is in `[text](path)` or `[label]: path`. |

Then run `pre-commit run --all-files` (see above).

## Reading check failures

Each check names itself and points at the offending line. Read the
error verbatim; the message includes the fix path.

- `check_skill_markers`: a `# DOC:` or `# SKILL:` marker line changed
  without the referenced doc being in the same diff. Either touch the
  doc or drop the marker.
- `check_doc_cli_flags`: a doc references a `safeyolo <cmd>` command
  or flag that does not exist in the Typer surface. Update the doc; do
  not add the flag speculatively.
- `check_doc_constants`: a pinned value in source no longer matches
  what a doc quotes. Update the doc or update the `must_contain` /
  `must_contain_any` template.
- `check_doc_links`: a repo-relative link resolves to a missing file.
  Update the link or the target.
- `check_doc_forbidden`: a doc contains a blacklisted phrase. The
  `reason:` field in the error is the *why* — read it before assuming
  the check is wrong.

For visibility into what is covered where, run:

```sh
python3 scripts/audit_doc_coverage.py --brief   # per-doc counts
python3 scripts/audit_doc_coverage.py           # + keyword hits + orphans
```

Docs with zero bindings are marked `!` in the count report. Those are
the gaps to close next when the change lands near them.

## Anti-patterns that will bite you

- **Placing a `# DOC:` marker in a `tests/` file.** The checker excludes
  `tests/` on purpose so test fixtures that embed marker syntax as
  strings do not create false positives. Your marker there does nothing.
- **Adding a marker on a line that will not change when the enforced
  fact changes.** Put the marker on the specific expression, not the
  decorator or a comment above it. See DEVELOPERS.md's placement table.
- **Making a pure declarative marker addition and expecting the check to
  fire.** By design pure additions do not require a doc co-change — only
  edits and removals do. If you need to force a doc update, add the
  marker and touch the referenced doc in the same commit.
- **Editing `doc_constants.toml` with both `must_contain` and
  `must_contain_any` on the same assertion.** The checker rejects this;
  pick one.
- **Running individual scripts instead of `pre-commit run --all-files`
  before push.** Documented above; the failure mode is a CI red on lint
  after the drift checks all pass locally.
- **Adding a doc to the allowlist without any bindings.** The audit
  report will surface it with `!` on the next run — either add coverage
  or explain in `docs/DEVELOPERS.md` why the doc is scoped in but
  unbindable.
