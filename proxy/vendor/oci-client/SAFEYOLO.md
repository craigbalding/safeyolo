# Optional typed image configuration

Source: the Apache-2.0-licensed crates.io `oci-client` 0.18.0 package,
upstream commit `129ee8fcd4408d6adb96f95eede414c16e2fd414`.
The published archive SHA-256 is
`ddc7848d781053285280fcd35aab24c9c0a677e26db4aa4209bd5db57467de0f`.
The upstream license, library, tests, examples and fixtures are retained.

The `image-config` feature enables the existing typed configuration module,
its `ConfigFile` conversions and its chrono dependency. It is enabled by
default. The enabled date types, parsing and serialization are unchanged.
Callers that disable default features can use the raw registry APIs and
`client::Config::oci_v1` without chrono through this dependency.
SafeYolo selects `rustls-tls-no-provider` without `image-config`; its existing
digest, platform and raw configuration validation remain in SafeYolo.

The source patch changes the two manifests, `src/lib.rs` and `src/client.rs`.
The added configuration tests exercise absent/null dates, precise timestamps,
offset normalization and typed conversions. The copied upstream manifests and
lockfile also describe optional and development dependencies. Their presence
does not establish that a native production build selects those dependencies.

The standalone `Cargo.lock` is locally refreshed from the published archive.
It selects rustix 1.1.6, ctutils 0.4.4, quinn-proto 0.11.19,
quinn-udp 0.5.16, rustls 0.23.46, rustls-webpki 0.103.16, tokio 1.53.3
and webpki-root-certs 1.0.10 to address the patchable advisories in those
selections, including the bundled emSign trust defect in RUSTSEC-2026-0383.
It also selects url 2.5.9 and form_urlencoded 1.2.3 to address the nested
`blob:` origin stack overflow in RUSTSEC-2026-0592.
The source and license remain those identified above. The standalone lock
still contains the chrono and astral-tokio-tar maintenance notices.
SafeYolo's product dependencies use `proxy/Cargo.lock`, separately from this
standalone lock.
