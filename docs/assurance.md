# Rust proxy implementation assurance

Use the source-drift check to identify changes that need review. A clean result
means that the checker detected no drift against the selected trusted snapshot.
It does not establish complete security coverage or operator approval. Use the
[security testing design](security-testing-design.md) for containment procedures
and actual-platform evidence limits.

The [source map](assurance-map.toml) names critical decisions, their untrusted
inputs, authority, checks, effects, failure routes, test owners and source
symbols. After parsing source, the checker resolves those symbols. It qualifies
same-named Rust methods by their inherent implementation type and reports stale
or duplicate symbols instead of silently dropping them.

The [checked-in snapshot](../tools/assurance/accepted.json) binds the independently
accepted map, workflow and acceptance-tool lock listed below. Only those three
control hashes were corrected. The product source revision, extracted functions,
operations and dependency/build input baseline remain unchanged. The map still
contains symbols for removed Python runtime files. The snapshot's
`source_revision` identifies its extraction input; it does not track current
master. These limits prevent treating the retained snapshot as current product
acceptance. The checker continues to report source drift and stale symbols;
they must not be waived by generating another snapshot.

| Corrected control | Exact accepted input and independent acceptance |
| --- | --- |
| Map | [PR #1366 at ce6fbf06](https://github.com/craigbalding/safeyolo/pull/1366/commits/ce6fbf06bd47921b87f02637cd4c726937f7c851), [parser repair acceptance](https://github.com/craigbalding/safeyolo/issues/1365#issuecomment-6584281948); the preceding library inventory has [PR #1295 acceptance](https://github.com/craigbalding/safeyolo/issues/856#issuecomment-6497525151) |
| Workflow | [PR #1078 at 4b0a6a0a](https://github.com/craigbalding/safeyolo/pull/1078/commits/4b0a6a0a76af168cb7036f5c2abb2acbd7164eb2), [artifact action acceptance](https://github.com/craigbalding/safeyolo/issues/1077#issuecomment-6216983788) |
| Tool lock | [PR #1568 at b166fb27](https://github.com/craigbalding/safeyolo/pull/1568/commits/b166fb270e6457b4932c20266d5089a56954da6d), [OpenTelemetry repair acceptance](https://github.com/craigbalding/safeyolo/issues/1566#issuecomment-6863664596) |

Each corrected hash identifies the exact file bytes at its accepted commit.
This control-pin correction does not promote the product baseline. Wider
[#837](https://github.com/craigbalding/safeyolo/issues/837)
and [#838](https://github.com/craigbalding/safeyolo/issues/838) work remains deferred.

The following pointers identify current runtime owners, including Transport
Layer Security (TLS) and certificate authority (CA) setup. They do not establish
that the map or snapshot covers all current behavior.

The proxy requires `policy_file` in its [native configuration](../proxy/src/config.rs).
Policy decisions use the loaded native runtime.

| Decision | Entry points and effect boundary |
| --- | --- |
| Identity | [host listener lifecycle](../proxy/src/host_commands.rs), [native listener](../proxy/src/lib.rs), [HTTP caller](../proxy/src/http.rs) |
| Authorization | [policy decision](../proxy/src/policy.rs), [guard](../proxy/src/network_guard.rs), [DNS and dial](../proxy/src/http.rs) |
| Interception TLS | [CA creation and configuration](../proxy/src/bin/safeyolo.rs), [configuration loading](../proxy/src/native_config.rs), [CA load and leaf issuance](../proxy/src/tls.rs), [CONNECT handshake](../proxy/src/http.rs) |
| Credentials | [vault](../proxy/src/credentials.rs), [gateway injection](../proxy/src/credential_injection.rs), [grant check](../proxy/src/grants.rs) |
| Provider services | [gateway selection](../proxy/src/services.rs), [provider admission](../proxy/src/http.rs), [Rust stream](../proxy/src/provider_stream.rs), [guest port transport](../proxy/src/host_platform.rs) |
| Management and evidence | [Admin authentication](../proxy/src/admin_api.rs), [Agent API](../proxy/src/agent_api.rs), [flow store](../proxy/src/flow_store.rs), [export](../proxy/src/traffic_view.rs) |
| Policy publication | [load](../proxy/src/policy_runtime.rs), [durable writer](../proxy/src/approvals.rs), [runtime swap](../proxy/src/lib.rs) |
| External effects | [forwarding and response handoff](../proxy/src/http.rs), [tunnel](../proxy/src/tunnels.rs), [WebSocket](../proxy/src/websocket.rs) |
| Other sinks and launch | [native proxy launcher](../proxy/src/host_commands.rs), [desktop presenter](../proxy/src/desktop_present.rs), [coord client](../proxy/src/agent_api/coord.rs) |
| Foreign and embedded code | [descriptor ownership](../proxy/src/lib.rs), [WebSocket spill mapping](../proxy/src/websocket.rs), [traffic filter](../proxy/src/traffic_view/filter.rs) |

## What the drift check does

[The rule set](../tools/assurance/rules.yml) uses Semgrep's Rust and Python syntax
parsers to extract function spans, Rust implementation spans and selected
network, file, output, process and unsafe operations. [The checker](../tools/assurance/check.py)
compares those operations, mapped function bodies, source-file scope and
dependency/build inputs with the trusted snapshot. It identifies added, removed
and moved operations, changed mapped functions even when the sink is unchanged,
stale symbols, relevant input changes and proposed control changes. An error,
missing tool, unparsed file or reduced extraction scope cannot produce a clean
result. The output is JSON and a Markdown delta. A finding means review is
needed; it does not prove a vulnerability.

The checker selects Rust source in `proxy/src`, Python source under
`cli/src/safeyolo`, and `pdp` if present. Those Python directories are scanner
inputs, not evidence of a shipped Python CLI. See the
[dependency boundaries](security-verification.md#dependency-trust).
The checker also covers the Cargo manifest and lockfile, vendored patches,
embedded proxy data, Rust toolchain, Python lock, installer, Linux rootfs
builder, guest forwarder and Swift VM helper sources. Its `INPUT_FILES`,
`INPUT_DIRS` and `SOURCE_DIRS` define the exact scope. A new `proxy/build.rs`
is an input change. Changed vendored source and Swift helper source are
reported through file digests; those digests do not establish code correctness.
The scanner reads Rust `#[cfg]` source; it does not prove which branch a
particular build selects. Cargo input changes report dependency and feature
movement, including procedural-macro dependencies. Inline test modules may
appear in parser counts; test-only files are excluded.

The extraction is structural. It does not infer authorization semantics,
prove full source-to-sink data flow, or build a complete Rust/Python/Swift call
graph. The selected Rust calls include unqualified names, `fs`, `net` and
`process` module shorthand, and the relevant explicit `std` or `tokio` paths.
Those spellings are matched even when imports are grouped. Renamed module
aliases, re-exports, other APIs, and changes inside unmapped functions without
a selected operation can escape the automatic delta.

Maintainers must read the candidate's affected path and use focused behavior
checks for the claimed boundary. The drift check does not establish the deeper
data-flow, proof, sandbox or unsafe-code results in #837. Missing supplemental
scanner results remain unknown coverage. Admin route internals, flow export
and HTTP Archive (HAR) details, and NATS message persistence are not fully
traced by the map. Swift helper changes have no Swift syntax or call graph
analysis. Raw stored HTTP flows can contain credentials and are available to
authorized operator views and exports. Routine audit events use fingerprints
and selected metadata; the two evidence surfaces have different disclosure
properties.

## Local check

On a supported Ubuntu 24.04 host with Python 3.12 and `uv` 0.9.24, run from a
checkout of the operator-approved trusted controls. Set `candidate_root` to a
separate checkout of the exact candidate commit before running the command.
The command installs the locked acceptance environment, including the Semgrep
version required by the checker, and writes two reports to the chosen output
directory. It does not build or run candidate code.

```sh
uv python install 3.12
uv sync --frozen --group static --project tools/acceptance --python 3.12
candidate_root=/path/to/exact-candidate-checkout
tools/acceptance/.venv/bin/python -I tools/assurance/check.py check \
  --trusted-root . --candidate "$candidate_root" \
  --json /tmp/proxy-assurance.json \
  --markdown /tmp/proxy-assurance.md
```

Exit 0 means no detected drift against that checkout's snapshot. Exit 1 means
detected drift or an invalid trusted snapshot binding; the JSON `status` and
`errors` fields distinguish those results. Exit 2 means analysis failed before
comparison. If a trusted control differs from its accepted hash, comparison
reports a binding error. Corrected control pins do not clear source drift or
stale symbols. Read the actual report for those findings and analysis failures.
A local run with both arguments
pointing at one candidate is only a smoke check.

An operator can generate a proposed snapshot for source review without
accepting it. Use the same trusted checker checkout and environment. Set
`candidate_root` to the reviewed source checkout and replace the output path
below with a location outside the protected snapshot:

```sh
tools/acceptance/.venv/bin/python -I tools/assurance/check.py snapshot \
  --trusted-root . --candidate "$candidate_root" \
  --json /path/to/proposed-accepted.json
```

The command rejects stale mapped symbols and refuses to overwrite the trusted
snapshot. Craig must review the exact source and delta before promoting a
snapshot into the trusted base. A proposed file or successful local check does
not approve that change or establish a new baseline.

## Current enforcement boundary

[The PR workflow](../.github/workflows/proxy-assurance.yml) checks the exact
candidate head with base-revision controls and publishes both reports.
Candidate changes to the checker, rules, map, snapshot, Semgrep ignore file,
acceptance-tool inputs, workflow files or assurance tests are proposed control
changes. The job reads those controls from the base checkout. It never executes
candidate source, dependencies or build scripts. It requests only
`contents: read` and no approval or release credentials.

The workflow and [CODEOWNERS](../.github/CODEOWNERS) files alone do not enforce
an independently approved merge gate. Inspect effective repository rules and
the required-check principal before relying on approval separation. A workflow
can reuse another job's check name, and an author's own pull-request approval
does not establish independent approval. Operator authority selects and
promotes trusted controls. This documentation does not enable an assurance
gate or change release acceptance.

## Blackbox assurance change notices

The [blackbox change workflow](../.github/workflows/blackbox-changes.yml) reports
changes to what the [control catalogue](blackbox-coverage.md) proves or selects.
A material delta creates one new `github-actions[bot]` comment that mentions
Craig. Pull requests (PRs) receive the comment in their conversation, including
drafts, forks and Craig-authored PRs. Direct changes to `master` receive a
comment on [the assurance epic](https://github.com/craigbalding/safeyolo/issues/1557).
The notice identifies affected controls where mapped, changed definitions and
exact base, head and comparison links. It requests no human approval.

The read-only analyzer uses the accepted PR base, or the commit before a
default-branch push, for its code, catalogue, assurance map and locked parser
environment. For a PR, it compares the common ancestor with the exact head;
an unrelated update to the base does not become a candidate change. Candidate
files remain bounded Git blobs. The job does not check out, import, install
or execute candidate code. Candidate edits to the maps and filters cannot
change the rules used to analyze that same candidate.

[The analyzer](../tools/assurance/blackbox_changes.py) reads the catalogue's
witnesses and the assurance map's test references. It also discovers Python,
Rust and shell evidence under `tests/blackbox`, `tests/proxy_contracts` and
`proxy/tests`, test files under `proxy/src`, and fixtures in those test trees.
New Cargo integration targets at `proxy/tests/NAME.rs` or
`proxy/tests/NAME/main.rs` are discovered even before the catalogue names them.
It follows static local Python imports, parent `conftest.py` files and literal
test/script references. That includes shared helpers, origin observers,
positive controls, installed procedures and embedded guest probes. Mapped
native command-line interface (CLI) witnesses remain in scope outside the
blackbox directory. Workflows, test configuration, catalogue and guard code
are comparison inputs. Other changed paths remain visible as context or
unclassified inputs. Path membership selects analysis; a changed path alone
does not select a mention.
An unreferenced new helper or fixture that is not automatically collected, and
witnesses explicitly outside the trusted catalogue, remain unclassified. A
linked fixture's parsed data changes are part of the oracle comparison.

The comparison has these bounded rules:

| Input or change | Result |
|---|---|
| Python assertion, parameter, decorator, fixture, helper or executable statement changes in a catalogue witness or discovered BB evidence and its helpers | Material; report added, removed or changed definitions. |
| Python or shell script interpreter (`#!` line) changes | Material; a changed interpreter can change execution even when the body is identical. |
| Rust test/helper tokens or inline test module changes | Material; retain literals, attributes, oracle and failure-handling tokens. Production code outside an inline test module remains context. |
| Selected runner command, skip/filter, backend, user/root phase, dependency between jobs, required trigger or cadence changes | Material. Jobs that contain assurance commands and their prerequisite jobs are compared. |
| Catalogue witness mapping, effective pytest/Cargo test configuration, analyzer or notification decision changes | Material. Cargo selection inputs and notification scope are described below. Candidate-authored labels or impact claims cannot suppress the result. |
| Python comments, docstrings, formatting, parentheses or empty `pass` statements; Rust comments or token-preserving formatting | Quiet when the normalized executable definition is equal. Strings used by assertions remain executable input. |
| An identical Python file moves within its directory, keeps test discovery, has no recognized location introspection, and all known static references are updated | Quiet after reference comparison. Other executable moves remain material. |
| Daily or weekly cron time changes with the same frequency | Quiet for the supported single-time expressions. Other expressions are compared exactly. |
| Lockfiles, dependency versions, action revision pins, same-platform runner-image versions, product/guest artifact or result refreshes | Context; a dependency or artifact refresh alone does not establish an assurance change. Changes to action identity, runner platform or executable test configuration remain material. |
| Generated documentation, other prose and unclassified inputs | Visible in the check report; no automatic mention. |

A general CI pytest command does not establish that each named regression test
is a BB witness. For an unmapped test outside the discovered evidence trees,
the comparison retains the full executable definition, including straight-line
setup, assertions, exception expectations, skips, decorators, parameters,
control flow and shared helpers. Changing an assigned expected status from
403 to 200 remains material even when the assertion text is unchanged.

One bounded exception recognizes the inspected GitHub command-line interface
(CLI) fixture adaptation in `2ec26866..690549f1`. The adapter selects the `repos/`
argument after `--include` is added and emits fixed success headers before the
same JSON response. The analyzer pins the two complete normalized definitions
of `test_recurring_git_changes_through_both_clis`, including all setup,
assertions and selection. Only that exact pair compares equally and stays
visible as unclassified input. A different setup statement, expected value,
assertion, adapter operation or selection produces a different fingerprint and
remains material. This exception does not normalize arbitrary embedded strings
or establish general equivalence. Catalogue witnesses and discovered evidence
retain their full executable definitions without this exception.

For the publisher, static name references from module statements select the
notification decisions and their local helpers. The comparison retains event
and report validation, the materiality threshold, deduplication, notice content,
bot identity checks and top-level failure handling. The `api` adapter and its
reachable helpers retain their complete executable definitions. One finite
exception covers the inspected response-diagnostic adaptation at `2ec26866` and
`690549f1`. Its fingerprints include both complete adapter/helper definitions
and their order relative to module statements and selected functions. Only
those fingerprints use the exception; the changed definitions remain visible as
unclassified inputs. A changed payload filter, target, failure guard or helper falls outside
the exception and remains material. Other unused helpers remain unclassified,
but assertions retain a function even when it is otherwise unused. Decorators
and defaults also retain a function because they execute at definition time.
The exception does not establish general transport equivalence or delivery.
The analyzer does not exempt the publisher file or execute its candidate code.

Cargo comparison retains automatic target discovery (including
`package.autotests`) and explicit library, binary, example, test and benchmark
targets. The comparison also retains package and inherited workspace editions,
the member's workspace path, and workspace membership, default selection and
exclusions. These inputs can remove targets or packages from a required run.
Explicit discovery defaults for literal package editions and workspace selection
reordering stay quiet. Workspace dependency version and other package metadata
changes alone do not create a material delta. The rules retain inherited edition declarations without
resolving defaults across manifests.

These rules establish limited mechanical equivalence. They do not establish
arbitrary semantic equivalence or infer the effects of every dependency
release. A changed executable witness or required selection that the rules
cannot establish as mechanical remains material. Reviewers must inspect the
reported context when a dependency or other input changes actual assertion,
collection or coverage behavior. The rules use no language-model verdict.

[The publisher](../tools/assurance/notify_blackbox.py) runs in a separate job
with the trusted publisher checkout and this run's bounded, event-bound report.
Only that job has `issues: write` and `pull-requests: write`; its other permissions
are `contents: read` and `actions: read`. Pull-request conversation comments and
ordinary issue comments use the same
[issue-comment endpoint](https://docs.github.com/en/rest/issues/comments#create-an-issue-comment).
The publisher requests write access for both target types. The analyzer retains
read-only permissions. The publisher uses the job's `GITHUB_TOKEN`,
never a personal token or provider secret. It validates report shape, revisions,
control IDs and reasons before constructing the comment. It does not copy
candidate explanations into a mention.

The delta identity contains normalized assurance changes rather than commit
IDs, timestamps or explanatory prose. Bot-authored comment markers record the
delta, PR or push target, Actions run ID and exact commits. Publication of the
same normalized delta is serialized across PR, retry and merge events.

A PR compares its latest material notice. An ordinary commit or rebase with
the same delta does not repeat its mention. A later different delta creates a
new comment, including a return to an earlier delta after another notified
change. A direct push uses its Actions run ID: retrying that event stays quiet,
while a later occurrence receives a fresh mention even if its normalized delta
matches an older one. A merge checks the latest notice on each associated PR.
If the merge publisher finishes first, its exact merge commit binds the epic
notice to the delayed PR event. An unrelated historical PR or epic notice
cannot suppress a new occurrence. The publisher does not assume that editing
an old comment sends a notification. Nightly execution is not an event for
this workflow.

For diagnosis, open the exact **Blackbox assurance changes** Actions run. Read
its analysis summary and the `blackbox-changes-RUN_ID-ATTEMPT` artifact. A
material run also retains `blackbox-notice-RUN_ID-ATTEMPT`, including the comment
URL and ID or the explicit publication failure. Missing analysis, parse errors,
unavailable history and preparation failures mean unknown impact, never “no
change.” They fail the affected job without issuing a recurring change mention.

For a GitHub API failure, the publication receipt identifies the request method
and path. It retains the CLI exit code, HTTP status, GitHub request ID and bounded
response message when available. It excludes raw headers, stderr and request
bodies, and redacts `GH_TOKEN` and `GITHUB_TOKEN` values from the response message.
An unavailable diagnostic field does not establish the failure cause or whether
a comment was created.

After an uncertain comment response, inspect canonical bot comments for the
reported delta before retrying the run. The publisher performs that read before
another post. No source rebuild or nightly product replay is needed.

The workflow must first exist on the default branch with its trusted analyzer,
publisher and catalogue. Its introduction does not run the new privileged
path from an unaccepted PR head. Actual bot-comment receipts, fork/event
availability under the repository's Actions policy, and Craig's notification
settings require delivery observations. Source tests and a check summary do not
prove that Craig received a notification. GitHub routes notifications according
to the account's [configured settings](https://docs.github.com/en/subscriptions-and-notifications/concepts/about-notifications);
the feature does not promise email. Repository-level protection against
disabling or replacing the workflow remains unproved here and belongs to #838.
