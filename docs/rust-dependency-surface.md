# Rust production dependency decisions

The dependency reduction keeps all 48 direct production dependencies. It
removes unused async-nats features and the unused Fernet timestamp-helper
feature. The selected Linux ARM64 production closure falls from 278 to 265
packages. The result reduces unused signing and transport branches while
leaving protocol, cryptography, parsing and platform implementations upstream.

The per-dependency API, feature, exposure and ownership decisions live in the
existing [`libraries` rows of the assurance map](assurance-map.toml). The graph
report joins those rows to measured removal closures. It does not create a
second maintained inventory.

## Reproduce the production graph

From a Linux or macOS repository checkout, use the pinned Rust 1.94.0 toolchain
and the frozen repository Python environment. The Cargo registry cache must
contain the locked packages for the selected target. The following command
resolves the current manifest and measures each direct dependency's removal.
It writes JSON to standard output and performs no compilation:

```sh
SAFEYOLO_CARGO_RESERVE_GIB=10 SAFEYOLO_CARGO_SPACE_POLL_SECONDS=1 \
  uv run --frozen --no-sync python tools/assurance/rust_dependencies.py \
  --target aarch64-unknown-linux-gnu --knockouts
```

Select `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` or
`x86_64-apple-darwin` for another supported host. Omitting `--knockouts` skips
only the repeated removal experiments. The report includes:

- direct and transitive packages, normal/build edges and target conditions;
- requested features, activated features and Cargo's feature-reason tree;
- each direct edge's actual removal closure, including feature deactivation
  on shared packages, rather than an exclusive-subtree estimate;
- build scripts, procedural macros, native `links` declarations and duplicate
  versions for the selected packages; and
- the API, feature-use, exposure and ownership decision from the maintained map.

The selected profile is the ordinary release profile used by the three native
binaries. Profiles change compiler settings, not this package's feature graph.
The root has no feature flags or direct build dependencies. Its `build.rs`
records build identity. Transitive build dependencies remain in the report.
Root dev dependencies, including the `toml` test oracle, are reported separately.

The script removes dev dependencies in a disposable manifest, reuses the real
source and local patches, and copies the committed lockfile. Cargo may prune
only that copy. Cargo tree supplies the selected normal/build packages and
features; Cargo metadata alone also contains feature unions and packages that
are absent from this build. Metadata supplies the package attributes and edge
kinds. A knockout re-resolves Cargo features; merely deleting a tree edge would
miss optional packages that disappear from a shared dependency. Generated code,
unsafe source and native compilation boundaries still need the explanations in
the map. These attributes are not a vulnerability score or an audit of every
upstream line.

## Measured result

The starting source is master
`2342843cb8694f71eb05cbbac57c7dea01921860`. Counts exclude SafeYolo's root
package and include normal/build packages selected by Cargo. They do not count
all lockfile records as production code. All four targets retain 48 direct
dependencies.

| Target | Before resolved | After resolved | Removed |
| --- | ---: | ---: | ---: |
| Linux ARM64 GNU | 278 | 265 | 13 |
| Linux AMD64 GNU | 282 | 268 | 14 |
| macOS ARM64 | 280 | 267 | 13 |
| macOS AMD64 | 284 | 270 | 14 |

The async-nats selection disables defaults and explicitly retains `jetstream`,
`ring`, `nuid`, `server_2_10`, `server_2_11` and `server_2_12`. SafeYolo starts
its own loopback TCP broker with password authentication and JetStream. The
callers use neither NKeys nor WebSocket broker connections, service discovery,
key/value stores or object stores. Retaining NUID preserves the current inbox
identifier generator. Retaining the server flags preserves stream/message
fields without adding packages.

Removing `nkeys`, `websockets`, `service`, `kv`, `object-store` and `crypto`
deactivates these packages on Linux ARM64:

```text
base64ct@1.8.3                 curve25519-dalek@4.1.3
ed25519-dalek@2.2.0            ed25519@2.2.3
nkeys@0.4.5                    pem-rfc7468@0.7.0
rustc_version@0.4.1            semver@1.0.28
signatory@0.27.1               signature@2.2.0
tokio-websockets@0.10.1        webpki-roots@0.26.11
webpki-roots@1.0.10
```

AMD64 also removes `curve25519-dalek-derive@0.1.1`. The shared DER, PKCS#8
and SPKI packages lose their PEM feature. The CA importer uses DER wrapping
and the separate Rustls PEM reader. The existing TLS import tests cover that
changed feature relationship. The Fernet timestamp feature exposes unused
`encrypt_at_time` and `decrypt_at_time` helpers. Ordinary vault encryption and
decryption retain their system-time implementation. Removing that feature
removes no package.

## Shortlist and stopped experiments

The shortlist follows measured graph saving and actual ownership cost. Each
removal count below is a re-resolved direct-edge knockout on Linux ARM64.
These hypothetical removals do not imply that the feature can be discarded.

| Priority | Opportunity | Measurement and decision |
| --- | --- | --- |
| 1 | async-nats defaults | The bounded feature experiment removes 13 packages. Keep the maintained client and apply the feature reduction. |
| 2 | OCI client | A direct knockout removes 36 packages before reduction. The required behavior includes registry authentication/challenges, redirects, media handling, streaming and errors. Replacing it with shared Hyper moves substantial protocol ownership to SafeYolo. Stop and retain. |
| 3 | UUID glue | One exclusive package; shared system randomness remains. Exercise the small formatter/validator prototype below, then retain upstream ownership. |
| 4 | Temporary files and mapping | Four exclusive packages for tempfile and one for memmap2. Race-resistant creation/cleanup and read-only mapping lifetime/platform rules outweigh the small call sites. Reading spill files into a Vec changes large-body memory behavior. Retain. |
| 5 | Shared primitives and defaults | Percent encoding, direct Base64 and rand have zero exclusive closure. Direct-default knockouts for Base64 and futures-util also remove no activated feature: pem/reqwest and OCI retain them. Stop without code changes. |

No direct dependency is unused. Existing disabled-default selections for
Rustls, Fernet, compression, OCI, SQLite, Markdown, the line editor and YAML
already avoid optional branches. The remaining parser, Unicode, protocol and
cryptographic decisions are recorded per dependency in the map.

The independent [`uuid_absorption.rs` prototype](../experiments/uuid_absorption.rs)
uses the already-present ring random source. It covers UUID version/variant
bits, simple and hyphenated formatting, and the canonical lowercase boot-ID
predicate consumed by `host_runs.rs`. Its 46 prototype lines and 48 control
lines include comments and blank lines. Integrating it would also require
changing the existing UUID callers and deciding entropy-failure handling;
the prototype's fallible generation API is not a complete drop-in replacement.
Three controls pass. Removing the bit masks or accepting every boot ID makes
the controls fail. This is a bounded ownership experiment, not shipped UUID
functionality. No upstream source was copied or absorbed.

To rerun that experiment after a guarded release Cargo build, use the `ring`
`.rlib` emitted by that build's `--message-format=json` output. Pass its exact
path as `RING_RLIB`, and put the executable on a disk-backed scratch path:

```sh
rustc --edition=2024 --test experiments/uuid_absorption.rs \
  -L dependency=proxy/target/release/deps --extern "ring=$RING_RLIB" \
  -o proxy/target/uuid-absorption
proxy/target/uuid-absorption
```

## Behavior and assurance boundaries

Focused Linux ARM64 proof uses the release binaries, one Cargo job and the
10 GiB build reserve. The existing native Coord tests exercise actual pinned
NATS authentication, durable room restart, targeted receipts, member scope,
MCP errors, substrate failure and independent proxy traffic. A refused-endpoint
sensitivity control makes the receipt test fail with coordination unavailable.
The TLS target exercises eight CA import, key match, validity and malformed-input
cases. The credential target covers real encrypted storage and rejection of
incorrect passwords, corruption and truncation.

The graph tool's local Cargo controls cover dev-feature exclusion, build edges,
macOS selection, shared-feature knockout and resolution failure. The existing
assurance feature/control tests check that dependency movement remains visible
and candidate control edits cannot accept themselves. Cargo manifest/lock changes
continue through `tools/assurance/check.py`; the expanded library rows retain
feature decisions in the same maintained map. The accepted snapshot and tool
pins are unchanged. The existing deferred map/control binding mismatch remains
an error, not accepted current-source assurance.

The macOS and AMD64 results above are target-specific source/feature resolution,
not new runtime or hardware proof. No release-size or security-score claim is
made. The local fancy-regex, Hyper and h2 sources and selected features are unchanged;
#636 provenance and regressions remain applicable. The rustyline patch is also
unchanged. The PKCS#8 feature relationship receives the focused TLS rerun.
