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
The initial map was reviewed at
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. This promotion proposes
master `8ba22365616d83b8b8b18b87781f0e9b9ad1e439` as the accepted
source revision. Since the previous proposal at `05e5e243afc0c959599618089825801dfb1b146e`,
master added sandbox provider routing and optional gateway credentials. The
map now records that route and its host Python transport. The released CLI
requires native `policy_file`; a temporary policy UDS remains an explicit
development path in [config.rs](../proxy/src/config.rs) and
[decide](../proxy/src/http.rs). Craig must review the source and snapshot delta
before this proposed baseline becomes trusted.

| Map decision | Entry points and effect boundary |
| --- | --- |
| Identity | [CLI socket layout](../cli/src/safeyolo/sockets.py), [native listener](../proxy/src/lib.rs), [request reconciliation](../proxy/src/agent_discovery.rs) |
| Authorization | [policy decision](../proxy/src/policy.rs), [guard](../proxy/src/network_guard.rs), [DNS and dial](../proxy/src/http.rs) |
| Interception TLS | [CA selection](../cli/src/safeyolo/rust_proxy.py), [CA load and leaf issuance](../proxy/src/tls.rs), [CONNECT handshake](../proxy/src/http.rs) |
| Credentials | [vault](../proxy/src/credentials.rs), [gateway injection](../proxy/src/credential_injection.rs), [grant check](../proxy/src/grants.rs) |
| Provider services | [gateway selection](../proxy/src/services.rs), [provider admission](../proxy/src/http.rs), [Rust stream](../proxy/src/provider_stream.rs), [host port forward](../cli/src/safeyolo/provider_stream.py) |
| Management and evidence | [Admin authentication](../proxy/src/admin_api.rs), [Agent API](../proxy/src/agent_api.rs), [flow store](../proxy/src/flow_store.rs), [export](../proxy/src/traffic_view.rs) |
| Policy publication | [load](../proxy/src/policy_runtime.rs), [durable writer](../proxy/src/approvals.rs), [runtime swap](../proxy/src/lib.rs) |
| External effects | [forwarding and response handoff](../proxy/src/http.rs), [tunnel](../proxy/src/tunnels.rs), [WebSocket](../proxy/src/websocket.rs) |
| Other sinks and launch | [native launcher](../cli/src/safeyolo/rust_proxy.py), [desktop presenter](../proxy/src/desktop_present.rs), [coord client](../proxy/src/agent_api/coord.rs) |
| Foreign and embedded code | [descriptor ownership](../proxy/src/lib.rs), [WebSocket spill mapping](../proxy/src/websocket.rs), [traffic filter](../proxy/src/traffic_view/filter.rs) |

## Proposed baseline refresh

[PR #885](https://github.com/craigbalding/safeyolo/pull/885) names the exact
proposed control commit in its review handoff. Its snapshot records source
revision `8ba22365616d83b8b8b18b87781f0e9b9ad1e439`. Neither revision is
approved by generating the snapshot or by passing a local check.

At that master commit, the installed snapshot still records source revision
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. It binds acceptance-tool lock
`ee045a54387a26c6cfe27c60422f2e56a64b73001f41d108e90f01e90415299f`,
but the trusted checkout contains lock
`d5e5be721172aad87c4d98b065f7ed3009ec086989fa64dd7b9b5b3fde764a20`.
The lock delta updates AnyIO from 4.12.1 to 4.14.2. The checker, rules and
Semgrep 1.176.0 selection are unchanged. This promotion retains the current
master lock and proposes a snapshot that binds it.

| Detected source delta | From the recorded `2ca598ce` source | From the previous `05e5e243` proposal |
| --- | --- | --- |
| Changed previously mapped function bodies | 14 | 4 |
| Added mapped symbols; removed mapped symbols | 8; 0 | 8; 0 |
| Added; removed; moved selected operations | 19; 50; 7 | 6; 1; 0 |
| Added; removed source files | 7; 55 | 2; 0 |
| Changed dependency or build inputs | 5 | 0 |
| Parsed functions | 5,528 to 4,523 | 4,512 to 4,523 |

The source reduction accounts for the released Python proxy and policy-decision
process deletions. The five changed inputs are `proxy/Cargo.toml`,
`pyproject.toml`, `uv.lock`, `install.sh`, and
`cli/src/safeyolo/guest-proxy-forwarder.sh`. The provider delta adds the Rust
stream and Python port-forward helper, optional service credentials, trusted
caller headers and provider routing before delivery. The eight added symbols
map service authorization, persistence, provider selection, configured caller
identity, launcher setup and both transport entry points. All 78 mapped symbols
resolve in the proposed source snapshot.

The proposal preserves every workflow from master, including the Rust release
workflow. It adds code-owner coverage for `.semgrepignore`, which is already a
detected control input. The proposal does not accept unmerged PR #895's native
host changes or removed Python helpers; those changes still need a map and
snapshot review after their product review. Drift counts require source review;
they do not establish that changed behavior is safe.

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
`cli/src/safeyolo`, and `pdp` if present. It also covers the Cargo manifest
and lockfile, local Hyper,
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
checkout of the approved trusted controls. Set `candidate_root` to a separate
checkout of the exact candidate commit before running the command. The command
installs Semgrep from the locked acceptance environment and writes two reports
to the chosen output directory. It does not build or run candidate code.

```sh
uv python install 3.12
uv sync --frozen --group static --project tools/acceptance --python 3.12
candidate_root=/path/to/exact-candidate-checkout
tools/acceptance/.venv/bin/python -I tools/assurance/check.py check \
  --trusted-root . --candidate "$candidate_root" \
  --json /tmp/proxy-assurance.json \
  --markdown /tmp/proxy-assurance.md
```

Exit 0 means no detected drift against that checkout's accepted snapshot.
Exit 1 means detected drift or an invalid trusted snapshot binding; the JSON
`status` and `errors` fields distinguish those results. Exit 2 means analysis
failed before comparison.
The proposed snapshot is for master `8ba22365616d83b8b8b18b87781f0e9b9ad1e439`.
That base still has an older snapshot and map. Until Craig approves and merges
this promotion, its PR check uses the older trusted snapshot and reports an
analysis error for the changed acceptance-tool lock. A candidate must include
approved control changes before its check can return clean. A local run with
both arguments pointing at one candidate is only a smoke check.

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
rules, map, snapshot, Semgrep ignore file, acceptance-tool lock, workflow files
or assurance tests are listed as proposed control changes. The PR job reads all those controls
from the base checkout. It never executes candidate source, dependencies or
build scripts. The job requests only `contents: read` and no approval or
release credentials.

## Current enforcement boundary

[The PR workflow](../.github/workflows/proxy-assurance.yml) checks the exact
head with base-revision controls and publishes both reports. The existing
`main-protection` ruleset currently targets only the default branch. It
requires `Test CLI`, `Lint` and `Test Addons (Python 3.12)`; it does not require
`Proxy assurance drift` or code-owner review. It also requires CodeQL code
scanning. Craig must preserve these existing requirements when adding the
assurance gate. The
[workflow](../.github/workflows/proxy-assurance.yml) and
[CODEOWNERS](../.github/CODEOWNERS) files alone do not enforce an independently
approved merge gate.

Before treating this as protected acceptance, Craig must place these controls
on the operator-controlled default branch and update `main-protection`. That
ruleset must require a pull request and at least one code-owner approval for
control-file changes. It must also require the exact `Proxy assurance drift`
check from GitHub Actions (integration ID `15368`), with no agent bypass.
Workflow files must be included in that
protected review set because a new workflow can otherwise imitate a required
job name. Once enforced, benign changes to mapped code, selected operations,
or build inputs also wait for an accepted snapshot update. Every workflow edit
needs code-owner review, including workflows outside the proxy release. These
costs follow from the shared GitHub Actions check identity and the required
baseline. The coding agent currently creates PRs as `craigbalding`; GitHub
does not count an author's own PR approval. Craig must use a distinct PR
author identity for future agent changes or select an independently controlled
required-check principal before claiming operator approval separation. If a
separate branch becomes a release merge target, its base also needs the trusted
controls and an equivalent gate. No such setting is implied by this
documentation, and this assurance lane does not change #640 or #620 release
acceptance.
