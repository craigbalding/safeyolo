# Guest HTTP client dependency patch

Source: the crates.io reqwless 0.14.0 package, from
<https://static.crates.io/crates/reqwless/reqwless-0.14.0.crate>.
Its published archive SHA-256 is
`836acee7034acc981677b98cd9e6cf123c7d9174be376281c86d8248fe5169eb`.
The upstream Apache-2.0 license remains in `LICENSE`.

The manifest patch makes p256 optional and enables it with `embedded-tls`.
Upstream already gates its p256 source uses behind that feature. Both manifest
forms carry the patch; HTTP implementation code is unchanged. Repository hooks
may normalize trailing whitespace and final newlines.

Only the Core guest manifest selects this patch. The guest disables reqwless's
default features and uses its HTTP client over a rustls/ring stream. The patch
removes the unused p256/elliptic-curve/crypto-bigint dependency chain from that
build. It preserves p256 when `embedded-tls` is selected.

The upstream standalone Cargo.lock is omitted. The guest's controlling lockfile
selects its dependency versions, including fixed heapless 0.9.4.
Upstream integration tests, their certificate/key fixtures and their explicit
test targets are omitted from this library-only import. Development-only support
files are also omitted. The README remains because the library includes it in
its compiled documentation. The maintained guest client controls exercise the
selected HTTP/TLS arrangement.
