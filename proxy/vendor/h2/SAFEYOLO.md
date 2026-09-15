# SafeYolo HTTP/2 metadata

This is h2 0.4.19, copied from the pinned Cargo source cache. The upstream
MIT license is retained. `UPSTREAM.json` records the archive checksum and the
original and patched source hashes.

The local patch exposes regular request fields in arrival order through
`ext::OriginalHeaderFields::iter()`. It borrows field bytes from the existing
HTTP parser before HeaderMap normalization. Its Debug output contains only a
field count. It does not parse headers again or change request admission.

SafeYolo consumes the extension before header hygiene and credential inspection.
H1 capture requires `preserve_header_case(true)`. H2 captures decoded HPACK
fields and attaches them to accepted server requests; response/trailer decoding
also incurs temporary reference-vector storage. Pseudo-headers are excluded.

The implementation proof covered 36 source/socket observations, including 27
mutually admitted cases with exact bytes, order, first spelling and grouped
values. Six bare-parser admission differences remain outside this metadata
patch. This proof does not establish complete Python transport parity.

## Optional response completion

`ext::on_response_complete(&mut request)` returns a `ResponseCompletion` future.
Register it before sending the request. The future returns the final status when
this receiver validates response completion. `try_result()` reads the same
terminal state without registering or replacing a waker. `None` means pending;
`Some` is terminal and the application must apply its outcome only once.

A private request extension travels through Hyper's HTTP/2 client conversion to
h2. The receiver records completion after final HEADERS with END_STREAM, final
DATA, or trailers pass the existing framing, content-length and state checks.
The final payload can remain unread in the existing receive queue. Informational
responses do not complete the observer. The parser stores only status and an
atomic terminal latch; it does not invoke application callbacks, drain a body,
copy payloads or make circuit decisions.

Dropping an unsent request, canceling its response future or dropping its receive
body aborts a pending observation. Stream reset (including NO_ERROR), connection
failure and premature EOF also abort it. Normal request half-close does not
abort receiving. The first terminal latch wins: completed status survives later
cancellation, and cancellation that wins first cannot become a later success.
Request-extension clones share a registration; register separately for requests
that will be sent independently.

The external proof ran 11 focused tests using owned local HTTP/2 peers and actual
Hyper HTTP/2 client dispatch. It covers held/unread final payloads, informational
and partial responses, content-length/frame errors, remote/local resets,
connection and queued-request cancellation, once-only terminal wake, and the
non-registering result read. Independent h2 default-feature compilation and
Hyper client/http2 compilation require no HTTP/1 features or new dependencies.
This does not activate HTTP circuit behavior or establish all source hook races.

Two existing h2 admission limits remain: missing response `:status` selects 200,
and a pseudo `:status` in trailers is discarded. Both were witnessed against the
unchanged copy. The completion metadata follows those existing parser results;
it does not certify complete HTTP/2 specification conformance.

`UPSTREAM.json` retains the original archive checksum and header-metadata proof
hash. Its file list now records cumulative source changes. The separate
`response_completion` section records this patch's before/after source hashes
against commit `d089f99506d9342cfd853709de87d2a465312d4e` and its focused proof hash.
The upstream MIT license remains unchanged.
