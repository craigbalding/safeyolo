# Optional typed image configuration

Source: the Apache-2.0-licensed crates.io `oci-client` 0.18.0 package,
upstream commit `129ee8fcd4408d6adb96f95eede414c16e2fd414`.
The published archive SHA-256 is
`ddc7848d781053285280fcd35aab24c9c0a677e26db4aa4209bd5db57467de0f`.
The upstream license, library, tests, examples and fixtures are retained.

The default-on `image-config` feature enables the typed configuration module
and its `ConfigFile` conversions. Its two date fields use a UTC `ImageTimestamp`
backed by maintained `time` calendar arithmetic. The adapter retains explicit
leap seconds, extended years, nanosecond precision and UTC normalization.
The parser also retains relaxed forms with unpadded components, whitespace,
`UTC` and offsets without a colon. Absent and null dates remain optional;
invalid dates are refused.
Callers that disable default features can use the raw registry APIs and
`client::Config::oci_v1` without the typed date dependency.
SafeYolo selects `rustls-tls-no-provider` without `image-config`; its existing
digest, platform and raw configuration validation remain in SafeYolo.

The source patch changes the two manifests, the typed configuration and its
conversions. Configuration tests exercise absent/null dates, precise timestamps,
offset normalization, leap seconds, extended years and typed conversions.
The copied upstream manifests and
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
uses the local `testcontainers` consumer patch in `../testcontainers` for
maintained streaming archives and the optional properties conversion.
The current date and archive consumers do not require chrono or
astral-tokio-tar.
SafeYolo's product dependencies use `proxy/Cargo.lock`, separately from this
standalone lock.
