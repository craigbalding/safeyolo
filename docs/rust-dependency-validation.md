# Rust dependency validation

Run the command from the repository root with Rust 1.94.0 and CPython 3.12.
Cargo runs offline by default and requires the dependencies to be present in
the local cache. Use `--online` only when the operator intends Cargo to fetch
missing packages. The script uses a temporary `CARGO_TARGET_DIR` outside the
checkout and removes it after the run, so a successful run leaves no generated
Cargo artifacts in the worktree. The report is written outside the checkout
unless `--report` specifies another path.

```sh
SAFEYOLO_POLICY_PYTHON="$(command -v python3)" \
  ./scripts/validate_rust_dependencies.py \
  --report /tmp/safeyolo-rust-dependency-validation.json
```

The script exits nonzero when a command fails, a required target is absent, a
test command collects zero tests, a selected test fails, or a provenance hash
does not match the current vendored source. It prints command output and keeps
the command, exit code, elapsed time, test counts, output hash and output tail
in the JSON report. The report also records the Git revision, Rust and Cargo
versions, package manifests, actual resolved features from Cargo metadata,
lockfile hashes, and the cumulative source hashes from each `UPSTREAM.json`.
Product package selection follows the Cargo resolve graph's root dependency
IDs, so a same-version registry package cannot be mistaken for the selected
path package; the report retains those IDs beside each feature record.
Standalone metadata is filtered to the host target and uses each package's
committed lockfile. The vendored `fancy-regex` lockfile is committed beside
its manifest so its standalone dependency versions are reproducible.
The product and standalone package commands all pass `--locked`.

The coordinator's validation plan is: verify provenance; resolve the locked
product graph and each standalone feature set; run the selected package
regressions, including the intentional missing-oracle failure; check the
independent feature builds; then build all locked product targets and run the
focused inspection and parser-completion targets. Every Cargo invocation is
executed through `scripts/cargo_with_space.sh`, and the report records both the
requested Cargo command and the guarded command that actually ran.

Each run uses a fresh temporary target directory named
`safeyolo-rust-dependency-target-*` under the system temporary directory via
`CARGO_TARGET_DIR`; the path is recorded in every command entry and removed at
exit. The reviewable report path is
`/tmp/safeyolo-rust-dependency-validation.json` when using the command above.
The coordinator must run this plan with the repository checkout as its
working directory and leave the existing hosted CI matrix unchanged.

The first Python oracle command intentionally unsets
`SAFEYOLO_POLICY_PYTHON` and selects the real
`every_valid_scalar_lowercase_matches_actual_python_312` regression. That
command must fail because its required oracle is unavailable. The script then
runs the same package's complete Python-backreference target with CPython 3.12
and requires a clean result. This controlled failure checks the runner's
failure-to-nonzero path without changing product source or expected assertions.

## Change-to-test map

The map names the local change, the package and feature resolution, the
existing regression target, its complete requested Cargo invocation, and the
remaining limitation. The commands below are the default offline commands;
the runner adds `--offline --locked` in this order before `test`, `check`, or
`build`. The report's `requested_command` field is the authoritative generated
argv for every invocation, including metadata commands whose host filter comes
from `rustc -vV`.
`docs/proxy-parity.md` remains the capability and deletion inventory; this
document only describes dependency validation.

| Local change | Package and enabled features | Regression or build command | Remaining limitation |
| --- | --- | --- | --- |
| Fallible VM growth, scratch release and cancellation polling | `fancy-regex` 0.19.2, default `unicode,perf,std,variable-lookbehinds` | `cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test runtime_allocation -- --test-threads=1 --nocapture`<br>`cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test runtime_cancellation -- --include-ignored --test-threads=1 --nocapture` | Delegated-engine allocation and cancellation remain outside the patch. |
| Scoped ASCII references and Python scalar backreferences | `fancy-regex` 0.19.2, same default features; Python option is opt-in | `cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test ascii_backrefs -- --test-threads=1 --nocapture`<br>`cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test python_backrefs -- --include-ignored --exact every_valid_scalar_lowercase_matches_actual_python_312` (controlled missing-oracle failure)<br>`cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test python_backrefs -- --include-ignored --test-threads=1 --nocapture` (CPython 3.12 oracle) | The bounded tests do not establish complete Python regex parity. |
| Original regular-header fields | Patched `hyper` 1.11.1 and `h2` 0.4.19 selected by locked `safeyolo-proxy` | `cargo --offline --locked test --manifest-path proxy/Cargo.toml --test request_completion_h1 --test request_completion_h2 --test response_completion_h1 --test response_completion_h2 --test response_head_capture -- --test-threads=1 --nocapture` (includes `response_head_capture`) | Six bare-parser admission differences remain outside the metadata patch. |
| Request and response completion, unread payload and trailers | Patched `hyper`/`h2` selected by the product lock; H1 and H2 paths are separate targets | `cargo --offline --locked test --manifest-path proxy/Cargo.toml --test request_completion_h1 --test request_completion_h2 --test response_completion_h1 --test response_completion_h2 --test response_head_capture -- --test-threads=1 --nocapture` | The tests cover the selected parser/client paths, not all HTTP conformance. |
| Independent feature boundaries | Standalone `h2`: `none={}`, `stream={stream}`, `unstable={unstable}`, `all={stream,unstable}`; standalone Hyper: `client,http2`, with `http1` forbidden | `cargo --offline --locked check --manifest-path proxy/vendor/h2/Cargo.toml --no-default-features`<br>`cargo --offline --locked check --manifest-path proxy/vendor/h2/Cargo.toml --features stream`<br>`cargo --offline --locked check --manifest-path proxy/vendor/h2/Cargo.toml --features unstable`<br>`cargo --offline --locked check --manifest-path proxy/vendor/h2/Cargo.toml --features stream,unstable`<br>`cargo --offline --locked check --manifest-path proxy/vendor/hyper/Cargo.toml --no-default-features --features client,http2` | Standalone manifests resolve their own lockfiles; product behavior is proved by the locked product tests. |
| Locked product build | `safeyolo-proxy` 0.1.0 with the committed `proxy/Cargo.lock` and all product targets | `cargo --offline --locked build --manifest-path proxy/Cargo.toml --all-targets` | Build coverage is compile and link validation; shared #621 owns proxy startup and origin traffic. |
| Native inspection focused target | Locked `safeyolo-proxy` product features and patched dependencies | `cargo --offline --locked test --manifest-path proxy/Cargo.toml --test inspection -- --test-threads=1` | The seven ignored Python inspection oracles require the separately provisioned Python acceptance environment. |

The runner also records these inherited smoke commands:

| Package | Complete requested command |
| --- | --- |
| `fancy-regex` 0.19.2 | `cargo --offline --locked test --manifest-path proxy/vendor/fancy-regex/Cargo.toml --lib -- --test-threads=1` |
| Hyper 1.11.1 | `cargo --offline --locked test --manifest-path proxy/vendor/hyper/Cargo.toml --no-default-features --lib -- --test-threads=1` |
| h2 0.4.19 | `cargo --offline --locked test --manifest-path proxy/vendor/h2/Cargo.toml --no-default-features --lib -- hpack::huffman::test::decode_single_byte --exact --test-threads=1` |

The product command includes `inspection` without ignored tests. It executes
the native scanner's focused tests and records the seven ignored Python
inspection oracles as unexecuted. Those oracles import the checkout's optional
`mitmproxy` and `yarl` dependencies and belong to the shared acceptance lane
when that environment is provisioned.

The script labels inherited package tests separately from local patch
regressions and product acceptance. The Hyper inherited smoke runs two tests
with no default features. The h2 smoke runs one existing Huffman test and
filters the rest. h2's published vendored manifest excludes its upstream
fixture corpus, so the full fixture suite is not a valid local acceptance
command. No whole-library dependency conformance, proxy startup, real-origin
traffic, or Linux/macOS black-box result is claimed here; those scopes remain
with #621 and the release checkpoints.

## Provenance

`proxy/vendor/fancy-regex/SAFEYOLO.md` and `UPSTREAM.json` describe the pinned
crate commit, crates.io archive checksum, patch files, retained MIT and
CPython licenses, and generated lowercase-data source. Hyper and h2 retain
their MIT licenses, license checksums and cumulative source hashes in their
respective `UPSTREAM.json` files. The script checks every latest cumulative
candidate hash, the generated lowercase JSON and its CPython license, and
requires the recorded source, archive and patch checksums without replacing or
rewriting vendored source. The latest Hyper checkpoint also covers the
post-validation `src/ext/mod.rs` integration edit retained by current main.
