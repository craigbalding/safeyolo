# Native proxy contracts

`tests/proxy_contracts/` exercises the native proxy through owned processes,
per-agent Unix domain sockets (UDS), authenticated application programming
interfaces (APIs) and local origins. Each fixture owns its configuration,
policy, state, logs, certificate authority (CA), credentials and listeners.
Requests do not target an external origin or the operator's running instance.
The [blackbox guide](../blackbox/README.md) describes the separate installed
host and guest compositions.

## Run a focused selection

On Linux or macOS, start in a clean checkout of the candidate. Install the
locked test dependencies with `uv sync --frozen --group dev`. Build the native
binary with the repository Cargo wrapper. The factory uses one build job and
keeps a 20 GiB filesystem reserve.

```sh
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh build --locked --manifest-path proxy/Cargo.toml
uv run --frozen pytest -q tests/proxy_contracts/test_http_contract.py \
  --proxy-backend rust
```

The selected fixtures start and stop their own native processes. A missing or
unusable selected binary fails preparation; it does not select another runtime.
`SAFEYOLO_RUST_PROXY=/absolute/path/to/safeyolo-proxy` selects another built
binary. Preserve the proxy and CA environment when launching the test tools.
The default backend is native Rust; `--proxy-backend rust` is the sole explicit
selection. Historical Python and combined-backend selectors are retired.

The existing shell entry point records the selected binary's identity and a
JUnit result. From the repository root, supply the native binary and a focused
pytest expression after `--`:

```sh
./tests/blackbox/run-tests.sh --proxy --rust-bin "$PWD/proxy/target/debug/safeyolo-proxy" \
  -- -k test_readiness
```

Exit 0 means the selection passed. Exit 1 means an ordinary assertion failed.
Exit 2 means preparation, readiness, collection or runner infrastructure failed.
The runner does not boot a guest or claim installed-package or hardware evidence.

## Observation boundaries

The maintained tests retain their behavior-named modules and parameter cases.
Use the affected module or node first. The complete retained family runs once
per supported host platform overnight; full-suite success is not a normal
pull-request gate. Normal pull requests run quick checks and relevant platform
checks for platform changes. The [existing assurance map](../../docs/assurance-map.toml)
identifies current production and test owners.

The real native fixtures cover these distinct boundaries:

- Trusted listener attribution, owner-scoped flow/query/detail, test context,
  policy reload, operator approvals and revocation, and cross-agent denial.
- Owned HTTP delivery, exact headers and body bytes, request-ID/evidence
  correlation, HTTP/1.1 framing, HTTP/2 handoff, streaming inspection and capture
  limits. Complete small-body observations do not promise complete truncated
  capture or durability after an evidence write failure.
- Transport Layer Security (TLS) authority, upstream trust, chain validation,
  logical name/server name indication, client trust and no silent passthrough.
  Component trust is distinct from an installed guest's default trust store.
- Credential destination/header checks, service scope, redirects, risky-route
  approvals, vault/OAuth behavior and actual origin delivery or non-delivery.
  Synthetic credential bytes stay inside owned fixture state and origins.
- Server-Sent Events (SSE), WebSocket and opaque CONNECT admission, cancellation,
  exact wire bytes, compression, repeated bounded mixed-traffic batches,
  authenticated operator controls and same-state restart.
- Native circuit completion, bypass, reload, persistence and recovery; readiness,
  actual process identity, socket ownership, cleanup and bounded external process
  observations. Linux `/proc` measurements remain unavailable on other platforms;
  an unavailable measurement is not evidence of bounded memory.

Some tests explicitly skip unsupported platform facilities or historical source
controls. A collected or selected node is not a passing observation. Run the real
installed or hardware lane when the requirement depends on that boundary.

## Historical acceptance

The completed migration's [audited contract](https://github.com/craigbalding/safeyolo/blob/e91f69ef85df55341db530bab421f67c4afb83f5/tests/proxy_migration/CONTRACT.md)
and [baseline records](https://github.com/craigbalding/safeyolo/blob/e91f69ef85df55341db530bab421f67c4afb83f5/tests/proxy_migration/baseline.json)
preserve the original commands, source identities, measurements, normalization
rules, temporary adapters, full-production Python results and explicit gaps.
Those instructions describe their named historical revisions. The native harness
no longer launches that comparator or supplies capture/compare executors.
Do not restore the retired proxy to run a current feature check.

[Lens's replacement receipt for #320](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5951336164)
records the independently observed native provider/header, approval-body, TLS
chain and CA-import replacements and Linux installed continuity. Matching
historical observations were pruned only after that verification. Guest access,
guest lifecycle, actual preparation reuse/state separation, current macOS package
and actual KVM/physical VZ observations remain open before their matching pruning.
The accepted #620/#640 migration results remain in their issue comments.
