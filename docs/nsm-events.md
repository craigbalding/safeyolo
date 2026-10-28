# Network Security Monitoring event contracts

The native audit writer accepts three Network Security Monitoring (NSM)
contracts: `network.connection`, `traffic.flow`, and `security.indicator`.
They describe transport sessions, application transactions, and sensor
indications respectively. Hypertext Transfer Protocol (HTTP) requests are not
transport connections.
Issue #582 defines these contracts. Issue #583 adds emission from actual
client and upstream transport owners. Issue #584 adds native Transport Layer
Security (TLS) client fingerprints and upstream certificate identity. Issue
#585 adds the first reusable indicator producer and a bounded prompt-injection
sensor.

## Version and reader compatibility

Existing events keep `schema_version: 1` and their existing wire representation.
The three NSM events use `schema_version: 2`. The new `network` kind is valid
only in version 2. Event prefixes must still match their kind. Version 2
currently accepts only the three NSM event names. A producer cannot label an
NSM payload as version 1 to avoid validation.

Producers use the existing `audit::Event` and `audit::Writer`. The writer selects
the version from the event name and kind, and validates the NSM fields before
queueing. Invalid input follows the existing audit validation failure path:
a diagnostic and an unversioned minimal fallback. The fallback is not a valid
NSM record and cannot establish a correlation relationship.

The native `audit::parse_record` reader accepts historical version 1 records
and validates version 2 records. The `safeyolo logs` command uses this reader.
Unknown schema versions and invalid version 2 contracts fail explicitly; the
raw log remains inspectable. Historical unversioned JSON, including writer
fallbacks, remains readable without being promoted to a validated schema.
Strict version 1 consumers reject version 2. Upgrade those consumers before
using NSM data; do not reinterpret `network.connection` as a traffic event.
The historical Python test reference is not the native product reader.

The #583 producer adds optional route, origin-peer, owning-client and Server
Name Indication (SNI) fields, plus `transport: stream`. A strict reader built against the earlier
version 2 field list must update before reading these producer records.
The current reader still accepts earlier version 2 payloads that omit the
new fields.

Issue #584 adds optional `tls_client_hello` and `tls_sessions` fields and the
`updated` connection state. Earlier strict version 2 readers need these additions.
The current reader continues to accept earlier records that omit TLS metadata.

All NSM payload fields below are in `details`, except `request_id`, which
uses the existing envelope field. Existing `ts`, `event_id`, `severity`,
`summary`, `agent`, and `addon`/`control` fields retain their envelope roles.
`ts` is the record time; it does not replace a connection's observed start/end
times. Version 2 accepts only the documented payload fields and existing
envelope fields.

## Correlation and trusted attribution

Every NSM payload requires nonempty `instance_id` and `runtime_id` strings.
For an installed native instance, use the durable `safeyolo_instance_id` from
`/admin/instance` as `instance_id`. Use the process identity from
`/admin/runtime-identity` as `runtime_id`; that older API currently names its
response field `instance_id`. The process token changes after a restart and
survives policy reloads. The lifecycle owner supplies these identities.
Request headers and sensor claims cannot supply them. This contract does not
add another identity authority.

The standalone development proxy has no installed instance identity. It uses
its process token for both namespace fields. If an installed instance identity
is unavailable or invalid, the proxy reports that diagnostic and omits NSM
records rather than claiming a different installed identity. Ordinary traffic
and audit behavior continue.

The connection key is `(instance_id, runtime_id, connection_id)`. Connection
IDs must identify real transport ownership and be unique across both legs
within that namespace. The transaction key is
`(instance_id, runtime_id, request_id)`. Local IDs may repeat in another
instance or runtime. Every reference in one record uses that record's namespace.
Never join records across instances or restarts using only a local ID.
Legacy version 1 records without this namespace need trusted source context
before a collector can join them to NSM records.

Reuse `audit::Attribution`. Its wire location remains `details.attribution`:
`evidence_owner`, `trusted_transport_identity`, `initiator`,
`attribution_status`, and `attribution_provenance`. The writer's attribution
argument takes precedence over compatibility fields in `details`.
Do not duplicate these fields in the NSM payload or obtain them from headers.
For an agent Unix domain socket (UDS), reuse the accepted listener identity.
For an upstream connection, reuse the owning client's trusted attribution
where meaningful. A shared transport must not invent a single agent owner
when its source cannot establish one.

`network.connection.details.ingress` identifies the ingress source, for example
`agent-uds` or a future `switchboard/mobile-test`. It is required on both legs
so the upstream record can retain its originating context. It does not imply
that an agent initiated external traffic. Preserve the trusted source's
`initiator`, including `external` or `unknown`, and its unavailable/conflict
status when appropriate. An ingress label does not establish agent identity.

## `network.connection`

Use `kind: network`. Each record describes one real connection/session, not
one HTTP request. A connection may carry zero, one, or many transactions.
Open, update and terminal records refer to the same connection key.

| Field | Contract |
| --- | --- |
| `connection_id` | Nonempty transport-owned local ID. |
| `leg` | `client_to_proxy` or `proxy_to_upstream`. The client may be external. |
| `transport` | `unix`, `tcp`, or `stream`. `stream` describes an owned provider session whose forwarding implementation does not expose socket endpoints. No inferred TCP, UDP or QUIC for such a session. |
| `started_at` | Observed start time in RFC 3339 format. |
| `ended_at` | Observed end time in RFC 3339 format; absent/null while open. Must not precede the start. |
| `state` | `open`, `updated`, `closed`, or `failed`. Open/update records have no end time. Terminal states require `ended_at`. |
| `local_endpoint`, `remote_endpoint` | Observed endpoints relative to the proxy; absent/null when unavailable. |
| `error` | Optional nonempty error category; no raw content or secret-bearing diagnostics. |
| `requested_target` | Optional requested authority, for example `example.com:443`. A hostname is not a peer IP. |
| `resolved_peer` | Optional actual dialed IP socket address, for example `203.0.113.10:443`. If the remote IP endpoint is present, they must agree. |
| `resolved_origin_peer` | Optional directly observed origin socket address. Present for a successful direct dial; absent for a parent or provider route. |
| `client_connection_id` | Optional owning ingress connection ID on the upstream leg, in this record's namespace. |
| `route` | Optional upstream route: `direct`, `parent`, or `provider`. |
| `tls_server_name` | Optional DNS name observed as Server Name Indication (SNI) in an established TLS session. Absent for IP verification names. An outer parent TLS name can be replaced by the origin TLS name when the inner handshake completes. |
| `tls_client_hello` | Optional agent-side ClientHello fingerprints and bounded offered metadata. See TLS identity below. |
| `tls_sessions` | Optional upstream TLS sessions, in establishment order. At most two entries distinguish `peer: parent` from `peer: origin` on a nested parent route. Physical endpoints and route ownership retain their existing meaning. |
| `ingress` | Nonempty originating ingress provenance. |

An IP endpoint is `{"type":"ip","address":"203.0.113.10:443"}` (bracketed
IPv6 is also valid). A Unix endpoint is
`{"type":"unix","path":"/run/alice.sock"}`. An unnamed Unix peer may use
`{"type":"unix","path":null}`. Unix endpoints require `transport: unix`;
IP endpoints and a resolved peer require `transport: tcp`.
Do not synthesize IP addresses for UDS peers. Failed dials can retain the
requested target with unknown local/remote endpoints and resolved peer.
When a parent proxy is used, the physical peer is that proxy, not an invented
origin connection. Record only facts observed by the connection owner.

The native producers emit one open record after transport establishment and
one terminal record when the final transport owner releases the connection.
`started_at` is the time the accepted transport or upstream dial owner began.
Failed or canceled dials emit a terminal `failed` record without an open record.
Errors are content-free categories, such as `connect_failed` or
`origin_tls_failed`. A half-close or an HTTP/2 stream completion does not end
the shared connection. Ingress ownership spans CONNECT upgrades and their
descendant tasks. Graceful proxy shutdown closes those transports before
emitting their terminal records. After an abrupt process exit, an unmatched
open record remains incomplete; no end time is inferred. If the wall clock
moves backward, the terminal time is bounded by the recorded start time.

For parent routes, `remote_endpoint` and `resolved_peer` identify the parent
socket. `requested_target` retains the logical authority, while
`resolved_origin_peer` remains absent. The native provider forwarding owner
exposes an opaque stream rather than a peer socket; its endpoint fields remain
absent and its transport is `stream`.

### TLS identity

The native CONNECT reader observes the first ClientHello before TLS termination
or SNI route selection. Observation also applies to configured passthrough
tunnels; it does not decrypt their upstream TLS. The reader reassembles a
ClientHello across TLS records and read boundaries. A complete parsed hello
emits one `state: updated` snapshot with the existing connection key. Each
successful upstream TLS establishment emits another update on its upstream key.
The terminal snapshot retains the observed TLS facts. HTTP requests do not
recompute fingerprints or create new TLS identities. Readers must treat updates
as snapshots, not new connections or counter increments.

`tls_client_hello` contains `ja3`, `ja4`, `sni`, `alpn_offers`, `legacy_version`,
`supported_versions`, `cipher_suites`, `cipher_suite_count`, `extension_types`,
`extension_count`, and `truncated`. Versions, ciphers and extension types are
unsigned wire values. The cipher and extension summaries retain observed order
and GREASE values; the fingerprint algorithms exclude GREASE where specified.
Each numeric list keeps at most 64 values. The SNI summary keeps at most 253
UTF-8 bytes. The Application-Layer Protocol Negotiation (ALPN) summary keeps the
first 16 offers, each at most 256 displayed bytes. Nonprinting and backslash
bytes are displayed as `\xNN`. `truncated` identifies a shortened summary.
Fingerprints always use the complete parsed values before summary truncation.

JA3 uses the ClientHello legacy version, ordered ciphers, ordered extension
types, supported groups and point formats. Its compatibility digest is MD5;
MD5 is not used for certificate identity or security decisions. JA4 uses TLS
over TCP (`t`), the highest non-GREASE supported version (or legacy version
when that extension is absent), SNI-extension presence, saturated two-digit
counts and the first ALPN offer. Its cipher hash sorts the non-GREASE ciphers.
Its extension hash sorts non-GREASE extension types excluding SNI and ALPN,
then appends signature algorithms in offered order. SHA-256 hash sections keep
12 lowercase hex digits. Empty sorted lists produce twelve zeroes. Unknown
versions use `00`. These values characterize client behavior; they are not
cryptographic process or executable identities. JA3S and JA4S are out of scope.

Each `tls_sessions` entry contains `peer`, `sni`, `version`, `cipher`, `alpn`,
`handshake_kind`, and `leaf_certificate`. The native rustls session supplies negotiated values;
absent values remain null. SNI is absent for IP verification names. DNS names
omit the trailing root dot, as rustls encodes them. A parent session and an
origin session remain separate entries, even though the
compatibility `tls_server_name` field names the latest completed session.
The leaf entry contains `cert_sha256` over the full certificate DER and
`spki_sha256` over the DER-encoded SubjectPublicKeyInfo (SPKI). A renewed
certificate can change the certificate hash while retaining the same SPKI hash.
Changing the public key changes the SPKI hash.
`handshake_kind` distinguishes `Full`, `FullWithHelloRetryRequest`, and
`Resumed`. On resumption, rustls can return the authenticated session's cached
certificate chain; that chain is not a fresh certificate observation on the wire.

Leaf identity includes bounded `subject`, `issuer`, `serial`, `not_before`,
`not_after`, `key_algorithm` (object identifier), `key_bits` where the parser
can determine it, `san`, `san_count`, and `truncated`. Subject, issuer and
serial keep at most 512 UTF-8 bytes each. Dates use RFC 3339. The Subject
Alternative Name (SAN) summary keeps at most 16 DNS/IP names, each at most
253 UTF-8 bytes; `san_count` counts all SAN entries. Unknown key sizes stay
null. A parsing failure retains only the observed certificate hash. An empty
certificate list has no leaf entry.

If a handshake fails after a complete ClientHello, the client fingerprint
update remains valid evidence and survives in the failed terminal snapshot.
Incomplete hellos or invalid field framing produce no fingerprint. Observation is bounded
in memory and does not change TLS admission. Failed upstream handshakes do not
produce an established-session entry: tokio-rustls does not return that TLS
session on failure. No negotiated values or certificates are fabricated.
If a preceding parent TLS handshake succeeded, its evidence remains when the
origin handshake fails. Raw ClientHello bytes, extension payloads, certificates,
TLS secrets and HTTP content are not stored in these sparse records.

The deterministic fixtures in `proxy/src/tls_identity/tests.rs` encode the two
published [Salesforce JA3 preimages and hashes](https://github.com/salesforce/ja3/blob/502cc6395811c54743b0561419d61900a6df3ff7/README.md#how-it-works)
and the ordered lists from the [FoxIO JA4 example](https://github.com/FoxIO-LLC/ja4/blob/c6469a7b0dbf8fe963810162429fbfd9d1acc4d5/technical_details/JA4.md#example).
The JA4 expected value is
`t13d1516h2_8daaf6152771_e5627efa2ab1`; synthetic extension payloads make this
an algorithm vector, not a captured browser identity. Tests insert GREASE into
ciphers, extensions, groups, versions and signatures, and fragment both TLS
records and reads. The JA3 expected value for that synthetic JA4 body is
`c000e2caf3a25423f9de6c8a4b12a975`, independently computed from the fixture's
decimal preimage with Python's `hashlib.md5`. The local MD5 implementation also
checks the [RFC 1321 test vectors](https://www.rfc-editor.org/rfc/rfc1321).
No reference implementation source or fingerprint dependency is imported.

The two public PEM fixtures in `proxy/tests/fixtures/tls-identity-*.pem` were
generated with OpenSSL using the same P-256 key and serials 58401 and 58402.
The test key was discarded. Known expected certificate hashes come from
`openssl x509 -outform DER | sha256sum`; the expected SPKI hash comes from
`openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`.
Those commands take the corresponding PEM file with `-in`. The tests also
cover a changed public key, missing/invalid certificate data, and real
connection correlation across concurrent HTTP/2 flows.

## `traffic.flow`

Use `kind: traffic` and a nonempty envelope `request_id`. The payload requires
`client_connection_id` and may carry `server_connection_id`. Both reference
real connections in the record's instance/runtime namespace. Leave the server
reference absent/null for a local response or when no upstream connection was
observed. Never allocate a connection ID merely to fill this field.

`traffic.flow` complements the existing `traffic.request`, `traffic.response`,
and outcome records with one metadata correlation record per transaction.
It does not copy their request/response facts or FlowStore content. Existing
human/watch output remains useful. For HTTP/2 multiplexing or connection reuse,
many flow keys can reference the same client and server connection keys:

```text
(instance-a, runtime-1): C1 client_to_proxy; S1 proxy_to_upstream
  F1: client_connection_id=C1, server_connection_id=S1
  F2: client_connection_id=C1, server_connection_id=S1
(instance-b, runtime-1): C1 and F1 are different keys
(instance-a, runtime-2): C1 and F1 are different keys after a restart
```

The native exchange owner emits correlation when its work finishes or is
canceled. CONNECT correlation follows any deferred route selection. A failed
upstream attempt retains its actual attempt ID even without an upstream HTTP
response. A local denial has no server reference. Existing HTTP/1.1 requests
reuse their ingress connection; the current upstream HTTP/1.1 implementation
opens an independent socket for each request. HTTP/2 streams within an admitted
TLS tunnel can share both connection references.

## `security.indicator`

Use `kind: security`. Required payload fields are nonempty `indicator_type`,
`sensor`, and `rule`, plus finite numeric `confidence` in the range 0–1.
Identify the sensor/rule version in those names when its meaning changes.
Confidence describes the sensor's signal; it is not a probability that an
agent is compromised.

Optional `connection_id` and envelope `request_id` refer to the affected
connection and transaction in the same namespace. A connection-level sensor
need not invent a request. Optional `direction` is the logical application
direction, `client_to_server` or `server_to_client`; it does not assert who
initiated a transport. Optional `evidence_hash` is `sha256:` followed by 64
hexadecimal digits. It may identify content-derived evidence without retaining
the content. It is not a promise that the original evidence is stored.

Indicators are indications/warnings for investigation. They are neither policy
decisions nor proof of compromise. Indicator records cannot carry `decision`
or `approval`. Emit any actual enforcement decision through its existing
separate event and correlate it by namespace/request/connection as applicable.

Issue #585 adds optional `content_type`, `inspected_bytes`, and
`prefix_truncated` metadata. `content_type` is a nonempty media type of at most
128 bytes. `inspected_bytes` is an unsigned byte count. `prefix_truncated` is a
Boolean that reports whether inspection omitted a suffix. The byte count and
truncation flag require `evidence_hash`. Earlier strict version 2 readers need
these optional fields and the optional `source` link below before reading the
new sensor records. The current
reader still accepts earlier records that omit them.

### Initial prompt-injection sensor

The native HTTP completion owners run `prompt-injection.v1` on request and
response content that they already hold transiently. The sensor uses the
shared `security_indicators::emit` producer. That producer reuses the existing
connection namespace, trusted attribution and audit writer. It does not select
policy, create connection IDs or enable recording.

The sensor recognizes four media types: `text/plain`, `text/html`,
`text/markdown`, and `application/json`. It accepts UTF-8 and US-ASCII charset
declarations, or no charset declaration. It skips missing, ambiguous, oversized
or unsupported content declarations, compression and non-chunked transfer
codings. Content-Type declarations are limited to 256 bytes; each content or
transfer coding declaration is limited to 64 bytes. The sensor performs no
decompression or encoded-instruction decoding.

The sensor inspects at most the first 65,536 bytes of each completed,
source-buffered body. Existing streaming selection and parser completion
barriers remain in force. Streamed, incomplete, upgraded and opaque tunnel
content is outside this sensor's coverage. The sensor performs no additional
body reads. Its normalized scratch buffer is bounded by that prefix and is
wiped on release. Exposure matching retains only the bounded hashes described
below; it retains no source or model body.

| Stable rule | Observable condition | Confidence |
| --- | --- | --- |
| `prompt.ignore_instructions.v1` | A word-bounded phrase asks to ignore or disregard previous instructions, optionally with `all`. | 0.5 |
| `prompt.system_role_delimiter.v1` | A ChatML, Llama header or `[INST] <<SYS>>` system-role delimiter appears in content. | 0.7 |
| `prompt.reveal_system_prompt.v1` | A word-bounded phrase asks to reveal, print or show `your system prompt`. | 0.5 |

Comparison folds ASCII case and collapses ASCII whitespace. Each content rule
emits at most once per body, so a body produces at most three lexical indicators.
A marked model request may also produce one exposure indicator. The fixed
substring checks have no regular-expression backtracking. The evidence hash is
SHA-256 of the entire normalized inspected prefix, with leading and trailing
ASCII whitespace removed. `inspected_bytes` counts source bytes before that
normalization. A prefix ends before an incomplete UTF-8 character.

All three rules use low severity. Confidence describes the lexical evidence,
independently of severity. Ordinary vocabulary such as “previous instructions”
does not match alone. Quoted examples, security documentation and test fixtures
can match the full phrases or delimiters. Those matches remain weak evidence;
the sensor does not determine author intent, content trust or successful model
control. It does not parse HTML visibility or distinguish quotation from an
instruction. Paraphrases, escaped text and instructions after the inspected
prefix can evade detection.

Indicators carry the trusted agent, request ID, actual ingress connection ID,
source host, direction, canonical media type and hash metadata. The request
key joins to `traffic.flow`, which supplies the real upstream connection when
available. The same request key can pivot to FlowStore evidence when existing
policy recorded that flow. The sensor does not copy matched text into an
event, summary or diagnostic. Quiet-host and quiet-path traffic settings do
not suppress indicators.

Unsupported or binary content is skipped. Invalid UTF-8 and caught classifier
failures produce a content-free `ops.sensor_error` through the ordinary audit
writer, with the same namespace and trusted attribution. The diagnostic has
`sensor`, `error`, `connection_id`, and `direction` details. Sensor and audit
submission failures do not change traffic, credentials, refusal controls or
policy decisions.

### Initial network-to-model exposure signal

The current service catalog identifies a narrow model operation reliably.
The shipped `claude` service defines the `inference` capability and separate
routes for `POST /v1/messages` and `POST /v1/messages/count_tokens` at
`api.anthropic.com`. The native gateway selects credentials under the trusted
request identity. After successful credential preparation and header application,
the HTTP owner carries a model-request marker to its existing content owner.
The marker requires the selected `claude`/`inference` binding, the same trusted
agent, HTTPS, the exact destination host, and the messages method/path.
A query string is permitted. Token counting, unrelated operations, unselected
requests and host-only matches do not receive that marker. No request header
can supply the marker. Existing route, credential and refusal controls still
run normally.

After a completed response produces a content indicator, the sensor may retain
hashed text shingles for that source. It compares them only with a later marked
model request from the same trusted agent. The cache belongs to the proxy
runtime, survives policy reloads and resets on restart. Each cached source
retains its actual request/connection IDs, host and normalized evidence hash.
Those references use the same instance/runtime namespace as the later indicator.

The first implementation uses these fixed bounds and false-positive controls:

- At most 64 source entries and 256 distinct SHA-256 fingerprints per source.
  Insertion evicts the oldest entry when necessary.
- Source matching expires after 300 seconds, measured with a monotonic clock.
  Source insertion and model matching purge expired entries. Idle entries remain
  bounded in memory until the next cache operation; there is no background cache
  task. Expired entries cannot match.
- Fingerprints use five consecutive ASCII alphanumeric words from the bounded
  normalized prefix. Words have 2–64 bytes. At most 260 words and 256 windows
  are considered. A window needs at least four distinct words and 24 word bytes.
- A source needs at least 160 normalized bytes, 16 distinct words and eight
  distinct fingerprints. Short or repetitive common text is not retained.
- A match needs at least four distinct fingerprints and at least half of the
  source fingerprints. Each model request emits at most one exposure indicator,
  using the source with the most matching fingerprints. A tie uses the newest
  source.

A match emits `indicator_type: prompt_injection_exposure` with stable rule
`prompt.source_text_overlap.v1`, confidence 0.85 and low severity. The optional
`details.source` link contains `request_id`, `connection_id`, `host`,
`evidence_hash`, `matched_fingerprints`, and `source_fingerprints`. Source IDs
and host are nonempty; the source hash uses the same SHA-256 representation.
Counts are positive, and the matched count cannot exceed the source count.
The envelope request ID identifies the model request. Its ordinary evidence
hash describes the normalized inspected model-request prefix. The source link
pivots to the earlier indicator, `traffic.flow`, and any policy-recorded
FlowStore evidence. It does not duplicate that content.

Exposure is stronger evidence of text reuse than a raw phrase match. It does
not prove that a model received the request, treated the matched text as an
instruction, or changed behavior. The request may still encounter a later
transport failure. Other model services, direct requests without a selected
binding, paraphrases, substantial transformations and content beyond the
bounded prefix are outside this first exposure signal. The sensor compares
request content without claiming universal model-field semantics. Full payload
capture and issue #858 are not prerequisites.

## Retention and quieting

[Native observation metadata](native-observations.md) preserves pre-reassembly
boundaries and explicit queue loss separately from these sparse audit events.
It does not enable payload retention.

Sparse NSM metadata may be emitted by default. Rich request/response content
continues to require FlowStore opt-in policy. A sensor may inspect transient
content already visible to the proxy; inspection does not authorize retention.
Do not add matched prompt text, bodies, headers, certificates, or other rich
content to payloads, summaries, errors, or attribution provenance because an
indicator fired. The NSM payload validator rejects additional content fields.
Separate content policy must permit any retained evidence.

`quiet_hosts` controls verbose request/response logging. Connection producers
must submit sparse connection records directly through the shared audit writer,
outside the request logger's quiet-host decision. Quieting cannot suppress that
underlying connection truth. Normal audit queue, sink-failure, and rotation
behavior still applies; this contract does not promise lossless storage.
