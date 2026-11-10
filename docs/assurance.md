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
| Tool lock | [PR #1297 at cc534d1c](https://github.com/craigbalding/safeyolo/pull/1297/commits/cc534d1cfb69a9f67ee7b7d240e56235cddcb763), [filelock repair acceptance](https://github.com/craigbalding/safeyolo/issues/1173#issuecomment-6502998170) |

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
