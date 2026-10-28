# SafeYolo parsed request headers

This is hyper 1.11.1, copied from the pinned Cargo source cache. The upstream
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

SafeYolo also retains the native HTTP/2 stream ID in accepted request extensions.
HTTP/1 `ext::RequestByteRange` exposes parser-consumed stream offsets for the
request head, body framing and trailers. It contains counters only. Read-ahead
bytes stay outside the range until consumed. The existing completion producer
owns updates; these offsets do not change framing, completion or admission.
