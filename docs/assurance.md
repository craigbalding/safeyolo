# Rust proxy implementation assurance

The [source map](assurance-map.toml) is the maintained account of the first
Rust proxy release's critical decisions. Each row names the untrusted input,
authority, check, effect, failure route, existing tests, and concrete source
symbols. The checker resolves those symbols from parsed source on every run.
It qualifies same-named Rust methods by their inherent implementation type.
It reports a stale or duplicate symbol instead of silently dropping the row.

The map starts from [Lens's independent source reading at PR #830's pinned
head](https://github.com/craigbalding/safeyolo/issues/838#issuecomment-5876216643),
the [#621 native inventory](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5801132524),
and the [#636 accepted local-patch review](https://github.com/craigbalding/safeyolo/issues/636#issuecomment-5736479281).
It is refreshed for `feat/rust-proxy-620` at
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. At this head, the release
CLI requires native `policy_file`; an explicit temporary policy UDS remains a
development path in [config.rs](../proxy/src/config.rs) and
[decide](../proxy/src/http.rs). The production Python proxy still exists for
comparison and rollback. PR #830 remains a distinct deletion candidate.

| Map decision | Entry points and effect boundary |
| --- | --- |
| Identity | [CLI socket layout](../cli/src/safeyolo/sockets.py), [native listener](../proxy/src/lib.rs), [request reconciliation](../proxy/src/agent_discovery.rs) |
| Authorization | [policy decision](../proxy/src/policy.rs), [guard](../proxy/src/network_guard.rs), [DNS and dial](../proxy/src/http.rs) |
| Interception TLS | [CA selection](../cli/src/safeyolo/rust_proxy.py), [CA load and leaf issuance](../proxy/src/tls.rs), [CONNECT handshake](../proxy/src/http.rs) |
| Credentials | [vault](../proxy/src/credentials.rs), [gateway injection](../proxy/src/credential_injection.rs), [grant check](../proxy/src/grants.rs) |
| Management and evidence | [Admin authentication](../proxy/src/admin_api.rs), [Agent API](../proxy/src/agent_api.rs), [flow store](../proxy/src/flow_store.rs), [export](../proxy/src/traffic_view.rs) |
| Policy publication | [load](../proxy/src/policy_runtime.rs), [durable writer](../proxy/src/approvals.rs), [runtime swap](../proxy/src/lib.rs) |
| External effects | [forwarding and response handoff](../proxy/src/http.rs), [tunnel](../proxy/src/tunnels.rs), [WebSocket](../proxy/src/websocket.rs) |
| Other sinks and launch | [native launcher](../cli/src/safeyolo/rust_proxy.py), [desktop presenter](../proxy/src/desktop_present.rs), [coord client](../proxy/src/agent_api/coord.rs) |
| Foreign and embedded code | [descriptor ownership](../proxy/src/lib.rs), [WebSocket spill mapping](../proxy/src/websocket.rs), [traffic filter](../proxy/src/traffic_view/filter.rs) |

## What the drift check does

[The rule set](../tools/assurance/rules.yml) uses Semgrep's Rust and Python
syntax parsers to extract function spans, Rust implementation spans and selected
network, file, output, process and unsafe operations. [The checker](../tools/assurance/check.py)
compares those operations, mapped function bodies, source-file scope and
dependency/build inputs with the accepted snapshot. It identifies added,
removed and moved operations, changed mapped functions even when the sink is
unchanged, stale symbols, relevant input changes and proposed control changes.
An error, missing tool, unparsed file or reduced extraction scope cannot
produce a clean result. The result is JSON and a Markdown delta. A finding
means review is needed; it does not prove a vulnerability.

The scan covers production Rust source in `proxy/src`, Python source in
`cli/src/safeyolo` and `pdp`, the Cargo manifest and lockfile, local Hyper,
h2 and fancy-regex patches, embedded proxy data, Rust toolchain, Python lock,
installer, Linux rootfs builder, guest forwarder and Swift VM helper sources.
The scanner reads Rust `#[cfg]` source for all supported configurations; it
does not prove which branch a particular build selects. `Cargo.lock` and
`Cargo.toml` changes report dependency and feature movement, including
procedural-macro dependencies. A new `proxy/build.rs` is an input change.
Changed vendored source is reported through its file digest; the accepted
[#636 patch review](https://github.com/craigbalding/safeyolo/issues/636#issuecomment-5736479281)
remains the detailed patch map. Inline test modules may appear in parser
counts; test-only files are excluded.

The extraction is structural. It does not infer authorization semantics,
prove full source-to-sink data flow, or build a complete Rust/Python/Swift call
graph. The selected Rust calls include unqualified names, `fs`, `net` and
`process` module shorthand, and the relevant explicit `std` or `tokio` paths.
Those spellings are matched even when imports are grouped. Renamed module
aliases, re-exports, other APIs, and changes inside unmapped functions without
a selected operation can still escape the automatic delta.
Maintainers must read the candidate's affected path and use focused behavior
checks for the claimed boundary. The separate [CodeQL, Kani, capability and Miri assurance
issues](https://github.com/craigbalding/safeyolo/issues/837) can ask deeper
data-flow, proof, sandbox and unsafe-code questions; this check does not claim
their results. Admin route internals, flow export/HAR details and NATS message
persistence are not fully traced by the initial source reading. Swift helper
changes are reported by file digest, without a Swift syntax or call graph.
Raw stored HTTP flows can contain credentials and are available to
authorized operator views and exports; routine audit events use fingerprints
and selected metadata. The two evidence surfaces have different disclosure
properties.

## Local check and accepted revisions

On a supported Ubuntu 24.04 host with Python 3.12 and `uv` 0.9.24, run from a
checkout containing the accepted controls. The command installs Semgrep from
the locked acceptance environment and writes two reports to the chosen output
directory. It does not build or run candidate code.

```sh
uv python install 3.12
uv sync --frozen --group static --project tools/acceptance --python 3.12
tools/acceptance/.venv/bin/python -I tools/assurance/check.py check \
  --candidate . --json /tmp/proxy-assurance.json \
  --markdown /tmp/proxy-assurance.md
```

Exit 0 means no detected drift against that checkout's accepted snapshot.
Exit 1 means a detected change needs review. Exit 2 means analysis failed.
For a candidate PR, use an independent trusted base checkout with
`--trusted-root` and point `--candidate` at the exact head checkout. A local
run with both arguments pointing at a candidate is only a smoke check.

After reviewing a legitimate change, an operator can generate a proposed
snapshot from a trusted checker checkout without accepting it:

```sh
tools/acceptance/.venv/bin/python -I tools/assurance/check.py snapshot \
  --trusted-root /path/to/trusted-base \
  --candidate /path/to/reviewed-head \
  --json /path/to/proposed-accepted.json
```

Craig must review the exact source and delta before promoting that JSON into
the protected base revision. The candidate then incorporates the approved
base update and the PR check runs again. Candidate edits to the checker,
rules, map, snapshot, Semgrep ignore file, acceptance-tool lock, workflow files or assurance tests
are listed as proposed control changes. The PR job reads all those controls
from the base checkout. It never executes candidate source, dependencies or
build scripts. The job requests only `contents: read` and no approval or
release credentials.

## Current enforcement boundary

[The PR workflow](../.github/workflows/proxy-assurance.yml) checks the exact
head with base-revision controls and publishes both reports. The existing
`main-protection` ruleset currently targets only the default branch. It
requires `Test CLI`, `Lint` and `Test Addons (Python 3.12)`; it does not require
`Proxy assurance drift` or code-owner review. No active ruleset protects
`feat/rust-proxy-620`. The current repository credential can read rulesets but
GitHub rejects its branch-protection read request. The submitted
workflow and [CODEOWNERS](../.github/CODEOWNERS) changes are therefore a
reviewable control proposal, not an enforced merge gate yet.

Before treating this as protected acceptance, Craig must place these controls
on an operator-controlled base and configure an active branch ruleset for
`feat/rust-proxy-620` and the actual release branch. The rule must require a
pull request, at least one code-owner approval for control-file changes, and
the exact `Proxy assurance drift` check from GitHub Actions (integration ID
`15368`), with no agent bypass. Workflow files must be included in that
protected review set because a new workflow can otherwise imitate a required
job name. Once enforced, benign changes to mapped code, selected operations,
or build inputs also wait for an accepted snapshot update. Every workflow edit
needs code-owner review, including workflows outside the proxy release. These
costs follow from the shared GitHub Actions check identity and the required
baseline. The coding agent currently creates PRs as `craigbalding`; GitHub
does not count an author's own PR approval. Craig must use a distinct PR
author identity for future agent changes or select an independently controlled
required-check principal before claiming operator approval separation. The
release branch's base must also contain the trusted controls before its PR
check can run. No such setting is implied by this documentation, and this
assurance lane does not change #640 or #620 release acceptance.
