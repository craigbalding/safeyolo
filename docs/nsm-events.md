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
sensor. The connection history sensor adds destination, measured origin Internet
Protocol (IP) address, client-fingerprint and upstream TLS change clues under
issue #581.

## Current audit contract

All native audit families use `schema_version: 2`: security, gateway, traffic,
operations, admin, agent, plumb, Coord and network events. This number identifies
an audit format generation, not a SafeYolo product release. Event prefixes match
their kind. A current control event does not become scoped NSM evidence merely
because it uses the same envelope generation.

Producers use `audit::Event` and `audit::Writer`. Coord's transactional audit
outbox uses the same current envelope. Scoped connection, flow, indicator and
request-decision publications also validate their NSM fields before queueing.
An unscoped decision remains an ordinary audit record. A partial request scope
fails validation; missing namespace or run context is never invented.

If a producer cannot construct an event, the writer emits a current
`ops.audit_validation_failed` diagnostic. Its `details` contain only the failed
publication's event name, kind and summary. The diagnostic preserves the
publication's severity and records its own timestamp. It carries no request
scope, approval, attribution or original payload. It cannot establish an NSM
relationship. A file-write failure retains the existing categorical diagnostic
and stderr event output; it does not establish successful retained publication.

The native `audit::parse_record` reader and `safeyolo logs` validate the current
envelope and the applicable scoped contract. Earlier generations, unversioned
JSON and invalid current records fail explicitly. The selected-file bytes remain
unchanged. The reader does not migrate or reinterpret them.

All NSM payload fields below are in `details`, except `request_id`, which
uses the existing envelope field. Existing `ts`, `event_id`, `severity`,
`summary`, `agent`, and `addon`/`control` fields retain their envelope roles.
`ts` is the record time; it does not replace a connection's observed start/end
times. The three NSM contracts accept only their documented payload fields and
existing envelope fields. Scoped request decisions preserve their existing
decision-specific details in addition to the required binding below.

## Scoped request decisions

The connection owner binds the following existing publications to its actual
instance, runtime and ingress connection:

- `security.network_guard` and `security.network_guard.evaluated`;
- `security.credential_guard`, `security.credential_guard.evaluated` and
  `security.credential_guard.codex_refreshed`;
- `gateway.allow`, `gateway.deny`, `gateway.refresh_failed`,
  `gateway.https_redirect` and `gateway.http_injection_allowed`.

These version 2 events require nonempty envelope `request_id`, `event_id` and
`host`, plus `details.instance_id`, `details.runtime_id` and
`details.client_connection_id`. The binding is supplied by the same owner as
connection evidence and survives policy reload. Guard records also retain
`details.connection_id`, which must equal the bound ingress connection.
The original decision, approval fields and decision-specific details remain
available. Decision records require an existing `decision` value and the matching
`addon` label, or its native `control` label (`network`, `credentials` or
`services`). Guard evaluation records instead retain `outcome` and `pdp` or
`evaluations`; they do not acquire an invented envelope decision. An allowed
ordinary request may have an evaluation record without a separate
`security.network_guard` intent. Evaluations do not imply that a credential was
detected. The confirmed Codex response event describes an observed authorized
refresh, not an arbitrary upstream response.

Use `logs list` to find the bound request or connection, then use the ordinary
request/connection pivots. Both configured-file and explicit multi-file views
show the unchanged event and its physical source lines. Decision links resolve
only to a same-namespace, same-resolved-agent ingress connection and to that
request's `traffic.flow` with the same client owner. An upstream pivot includes
decisions for the requests whose flows actually name that upstream connection.
One level of recorded support is followed. Approval IDs, control IDs and
co-location in a file do not establish traffic relationships.

A denial may have no upstream flow or connection. The view retains the decision
and available ingress evidence; missing flow support is `unavailable`. Conflicting
event copies, request/client owners or attribution cannot establish a decision
link. Unscoped events never acquire scope from a matching ID.
Missing, filtered, outside-window, queued or lost events leave policy and
credential handling unknown. Schema validation does not authenticate the
producer or operator-selected inputs.

An indication, policy decision, credential handling event and observed traffic
are different evidence. An allow or injection event does not prove upstream
delivery, model receipt, malicious intent or compromise. This binding adds no
credential policy, content retention or enforcement decision.

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

When existing host-run authority is available at Unix domain socket (UDS)
accept, the connection owner retains `sandbox_run` with `agent`, `agent_id` and
`run_id`. These are the host-owned agent name, immutable agent identity and
sandbox generation bound to that ingress. The run ID has 32 hexadecimal
characters. The name must match the envelope agent; the agent identity must be
nonempty. The optional object accepts only those three fields. Absent or null
bindings mean run-unavailable, including standalone traffic and ingress without
host-run authority.
Schema checks establish representation and consistency, not producer identity.

The snapshot is carried through connection lifecycle, flow, indicator and
scoped request-decision publications. It is never read from HTTP headers or
reconstructed from mutable host files when displaying retained records.
Closing or late events keep their original ingress run after that generation
stops or is replaced. Historical provenance does not renew current authority;
the existing stale-run request check remains in force. A sandbox run is distinct
from the proxy runtime, host launch/terminal and coding task. It establishes
neither executable/process attribution nor current liveness.

The connection key is `(instance_id, runtime_id, connection_id)`. Connection
IDs must identify real transport ownership and be unique across both legs
within that namespace. The transaction key is
`(instance_id, runtime_id, request_id)`. Local IDs may repeat in another
instance or runtime. Every reference in one record uses that record's namespace.
Never join records across instances or restarts using only a local ID.

The live `safeyolo observations` view identifies the same observation-owner
namespace. Use `--instance ID --runtime ID` to check whether a retained
namespace is still the responding runtime. Its counters and histograms are
runtime aggregates; they cannot be attached to a particular historical agent,
request or connection. A restart mismatch fails instead of returning historical
totals. See the [live measurement workflow](operator-guide.md#read-current-observation-measurements).

The local operator can start with `logs list` to discover retained namespaces,
agent context and concrete connection/request/indicator references without
reading raw JSON. Optional `--instance`, `--runtime` and `--agent` filters narrow
that listing. Run groups expose the exact `sandbox_run` object and `run_context`:
`recorded`, `unavailable`, `unknown` or `conflicting`. Optional `--sandbox-run ID`
selects recorded run IDs in the listing and scoped pivots. It never matches an
absent binding. Run selection follows conflict detection, so selecting one claim
cannot hide an incompatible owner of the same local ID. Namespace counts still
describe the retained namespace before run selection. Entries preserve physical
source locations and distinguish recorded resolved agent context from unknown attribution and conflicting
records. A name alone does not establish trusted attribution. References name
retained keys, not verified relationships or live sessions. The listing
collapses equal parsed records in configured and selected-file modes, preserves
all retained locations, and reports retained distinct-record/copy counts.
Unscoped current records remain visible through ordinary logs without becoming
NSM choices.

The operator can use `logs connection ID` or `logs request ID` with
`--instance ID --runtime ID` to inspect these relationships. See the
[operator workflow](operator-guide.md#follow-local-nsm-evidence) for complete
commands. The read-only view uses the ordinary logs reader. By default it reads
the configured local file. Repeated `--file PATH` options instead select retained
files for offline inspection without installed config, proxy or Admin API.
The operator supplies those files through an existing trusted operational route;
the CLI neither acquires remote logs nor authenticates them through schema
validation. Provenance comes from source selection and the original trusted
producer, never from filenames or arbitrary identity claims.

A pivot keeps the last `--lines` selected-agent rows (default 100) per input,
then selects validated version 2 records within the requested namespace. Total
retention is at most input count times `--lines`, before duplicate removal.
Each selected input reports its supplied path, physical line range, rows read
and omitted rows. Total counts include input copies. File-mode line references
use `{"input":N,"line":L}`; `inputs` identifies the corresponding file and
`locations` preserves every retained copy of an original record. Equal parsed
records share evidence across repeated or overlapping inputs. Conflicting event
copies or transport owners cannot establish a join. Different lifecycle snapshots
with consistent owners remain distinct records. Input order and wall timestamps
do not establish a global chronological order.

Both ends of a cross-file join must agree on instance/runtime, agent and the
recorded reference fields. They must also have the same complete `sandbox_run`
binding, or both lack one. Missing context is never filled from a matching
agent, request or connection ID. Different run claims for one connection or
request owner are conflicts, even when a run selector excludes one claim.
Source and novelty references into another run remain visible but cannot
complete that run's supporting links or transport correlations. Run-unavailable
records retain their namespace and local-ID relationships and remain explicitly
unavailable for run selection. The reader validates every row
to end of file. If any selected file is malformed, unsupported or unreadable,
the command fails with an input-number diagnostic and no partial output.
Windows apply before namespace selection, and no additional output limit hides
related or supporting evidence. The view displays one level of recorded links
within those windows; unselected files, rotation, queues and loss can leave
support unavailable. It preserves input bytes and never fetches content.
Request pivots include their connections and those connections' indications;
connection indications can describe other requests on the same transport.
These are recorded relationships, not a verdict about an agent.

Each link reports `available` with matching file lines, or `unavailable`.
File-mode links with conflicting support identify `conflicting_record_lines`;
matching candidate records remain visible without establishing availability.
Novelty links match both connection ID and exact source event ID. Prompt source
links match the recorded request ID, connection ID and evidence hash of a
response indication. A coincident local ID or an unscoped record cannot
establish availability. Agent filtering also applies to supporting records.
The original records are returned unchanged inside `records[].record`.
Rotation, drops, queued writes, an unavailable file and the selected window
limit the evidence; missing evidence is not proof of absence. Unselected rotated files
and FlowStore bodies are not read by this view. The view makes no additional
retention or completeness guarantee.

For retained `prompt_injection_exposure` records, the view also derives
`correlations[]`. Each explanation names its exposure line/event ID and exact
source indication lines. The source must match the recorded request, client
connection, response direction, host and evidence hash. All participating records
must share the selected instance/runtime and resolved trusted agent attribution;
omitting `--agent` does not permit cross-agent joins.

`source_transport` and `model_transport` distinguish the fetched response's
transport from the authenticated model request's transport. Each uses that
request's retained `traffic.flow`, its client connection, and its upstream
connection with the matching client owner. Conflicting flow ownership cannot
establish a transport relationship. Connection lifecycle snapshots are listed
together rather than multiplied into combinations. Each companion novelty entry
names its client/server connection role, original indicator line/event ID,
exact current/previous/client observation links, availability and reason. Only a
current observation on that transport establishes the relationship; a previous
observation alone does not. The view consumes the recorded novelty indication
without running the detector again.

A correlation is `linked` when its source indication and both transports are
available, at least one companion novelty indication has complete support, and
all listed novelty support is available. It is `partial` when the recognized,
trusted exposure lacks part of that evidence. It is `unavailable` when the
exposure lacks resolved trusted attribution or the recognized exposure
sensor/rule/direction, or when selected copies of the exposure conflict. The original exposure remains visible in every case.
Per-source, transport and novelty statuses explain which evidence is missing.
No available novelty in the searched window means unavailable evidence, not a
clean verdict.

This is a read-only connection relationship, not request-level novelty. A
connection-wide indication can predate or serve multiple requests, including
both the source and model exchange. Quoted instructions and legitimate text
reuse can produce the underlying prompt indications. Even a `linked` result
does not prove malicious intent, model receipt, instruction following or causal
compromise. The exposure sensor's [bounded visibility](#initial-network-to-model-exposure-signal)
and the reader's window/loss limits still apply. No content is fetched or stored
by this explanation, and no new audit event is emitted.

Reuse `audit::Attribution`. Its wire location remains `details.attribution`:
`evidence_owner`, `trusted_transport_identity`, `initiator`,
`attribution_status`, and `attribution_provenance`. The writer's attribution
argument supplies these fields; payload claims in `details` are removed first.
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
cryptographic process or executable identities. JA4S remains out of scope pending
applicable implementation and distribution rights.

`tls_server_hello` records bytes read immediately below the origin TLS handshake,
after any parent CONNECT. It contains `status`, `hello`, and
`hello_retry_request`. Each hello contains the unsigned wire `legacy_version`,
selected `cipher_suite`, ordered `extension_types`, `extension_count`,
`truncated`, and `ja3s`. Extension summaries keep the first 64 types; the digest
uses the complete list. JA3S is the MD5 digest of the decimal
`legacy_version,cipher_suite,extension-types` tuple, with extension types joined
by hyphens. An absent extension vector leaves the third segment empty.
As in the [Salesforce JA3S implementation](https://github.com/salesforce/ja3/blob/502cc6395811c54743b0561419d61900a6df3ff7/python/ja3s.py),
all server extension types participate in their wire order, including GREASE
values. No upstream implementation source is imported.

The observer reassembles a ServerHello across records and read boundaries.
Under [RFC 8446 section 4.1.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3),
a TLS 1.3 ServerHello has wire `legacy_version: 771` (0x0303).
The independently negotiated session version remains `TLSv1_3` (0x0304).
The observer recognizes HelloRetryRequest by its specified random value, records
it separately, and waits for the final ServerHello. A retry fingerprint does
not substitute for the final server fingerprint. TLS 1.3 compatibility
ChangeCipherSpec records can separate these messages.

The observation status describes wire availability, separately from connection
success or certificate verification:

| Status | Meaning |
|---|---|
| `complete` | A complete final ServerHello was parsed. `hello` is present. |
| `incomplete` | The stream ended or the handshake was dropped before a complete final hello. A parsed retry can remain. |
| `invalid` | The observed record or handshake framing was malformed, or extension types were duplicated. |
| `unavailable` | Non-handshake bytes prevented observation, such as an alert or opaque/encrypted record. |
| `limit_exceeded` | A declared ServerHello exceeded its bounded observation size. |

For every status except `complete`, `hello` is null. An absent
`tls_server_hello` means no observation was recorded; it does not prove absence
of a handshake. The observer holds at most one bounded ServerHello message and
one record header transiently. It drops raw bytes after classification and
stores no extension payloads. Observation does not reject or change traffic.

The server responds to SafeYolo's upstream ClientHello. This fingerprint does
not describe the intercepted agent's original ClientHello. The outer parent's
TLS handshake cannot supply `tls_server_hello`; its negotiated evidence stays
in the separate parent session. A provider route can supply observed TLS bytes
over the named guest-port stream. Those bytes do not establish an independently
measured external origin or origin IP. The existing route, endpoint and trusted
attribution fields retain those distinctions.

A complete hello emits an update on the actual upstream connection key before
the negotiated-session update. An unavailable or incomplete observation also
emits an update when classification finishes. Terminal snapshots retain these
facts even if TLS verification subsequently fails. Existing `logs connection`
and `logs request` pivots expose these records in their instance/runtime
namespace through the recorded connection and flow IDs. Audit queue loss,
rotation and selected read windows can still make evidence unavailable.
Observation happens before optional, lossy payload retention and requires no
packet/content capture. Existing capture controls remain unchanged.

Each `tls_sessions` entry contains `peer`, `sni`, `version`, `cipher`, `alpn`,
`handshake_kind`, and `leaf_certificate`. The native rustls session supplies negotiated values;
absent values remain null. SNI is absent for IP verification names. DNS names
omit the trailing root dot, as rustls encodes them. A parent session and an
origin session remain separate entries, even though the
`tls_server_name` field names the latest completed session.
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
origin handshake fails. A complete observed ServerHello can survive that failure
without an established origin-session entry. Resumption observes a fresh
ServerHello, while rustls can still supply cached certificates in `tls_sessions`;
the new hello does not make those certificates fresh wire observations.
Raw ClientHello or ServerHello bytes, extension payloads, certificates,
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

The ServerHello tests in `proxy/src/tls_identity/server/tests.rs` cover ordered
tuples, fragmentation, coalescing, retries, summary limits and unavailable or
invalid evidence. Owned TLS 1.2/1.3 endpoints exercise the production handshake
path, including full and resumed sessions. A test-only endpoint tap supplies
the emitted wire bytes to an independent field reader and OpenSSL MD5 oracle.
The nested-parent fixture applies the same oracle to inner origin bytes,
including certificate-verification failure. These tests require OpenSSL in
the test host's command path.

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
truncation flag require `evidence_hash`. The optional `source` link below names
recorded supporting evidence.

### Destination and upstream TLS history

The native connection owners run `connection-history.v1`. The sensor emits eight
low-severity rules through the shared indicator producer:

| Stable rule | Observable condition |
| --- | --- |
| `destination.first_observation.v1` | The first native upstream record for an agent/destination/route absent from the bounded runtime cache. |
| `origin_ip.first_observation.v1` | An established native socket measures an origin IP absent from that trusted agent's bounded runtime history. |
| `tls.origin_identity_changed.v1` | A later full origin TLS handshake has a different certificate hash, or two available SPKI hashes differ. |
| `tls.origin_negotiation_changed.v1` | A later successful origin TLS handshake has a different measured TLS version or negotiated Application-Layer Protocol Negotiation (ALPN) result. |
| `tls.client_fingerprint_first_observation.v1` | The first complete supported ClientHello for a trusted agent absent from bounded runtime history. |
| `tls.client_fingerprint_changed.v1` | A later observed ClientHello for that agent has a different JA3 or JA4 fingerprint. |
| `tls.origin_spki_new_ip.v1` | A full origin handshake measures an already retained SPKI at an IP absent from that trusted agent/key's retained associations. |
| `tls.client_destination_first_observation.v1` | A measured client JA3/JA4 pair and logical destination/route combination for a trusted agent is absent from retained runtime history. |

These rules have confidence 1.0 in the stated metadata comparison. They do not
estimate the probability of compromise. Certificate renewal, key rotation,
load balancing, server protocol configuration, and operator configuration changes
can explain a TLS change. Negotiation changes use indicator type
`tls_negotiation_change`; certificate changes retain `tls_identity_change`.
When both change, the sensor emits separate records with their own comparable
baselines.
Client-fingerprint rules use indicator types `tls_client_fingerprint_novelty`
and `tls_client_fingerprint_change`. Client library updates, TLS settings and
randomized extension order can explain changes. Fingerprints describe observed
client TLS behavior; they do not identify an executable or prove compromise.
Origin key/IP reuse uses indicator type `tls_spki_new_origin_ip`. It describes
an observed public key at another measured IP. It does not establish address
ownership, hosting location, executable identity or compromise.
Client/destination pairing uses indicator type `tls_client_destination_novelty`.
It reports observed novelty, with no rarity threshold or score.
First origin-IP observation uses indicator type `origin_ip_novelty`. It makes
no claim about ownership, geography, executable identity, rarity or compromise.

On the operator host, with the native CLI installed, replace `AGENT` with an
existing configured agent name. This command reads recent audit records:

```sh
safeyolo logs --agent AGENT --lines 100 --json
```

Find `security.indicator` records whose `details.sensor` is
`connection-history.v1`. Each record's optional `novelty` object contains:

| Field | Meaning |
| --- | --- |
| `history_scope` | `runtime_fifo`: process-local history with first-in, first-out eviction. |
| `history_capacity` | At most 4096 entries shared by agent/destination/route history, client-agent history, agent/IP observations, agent/SPKI/IP associations and client/destination pairings across the runtime. Each client agent, agent/IP observation, key/IP association and distinct pairing use one entry. |
| `destination` | Logical requested host and explicit port, including the effective default port. DNS names use ASCII lowercase without the root dot. Parsed IP addresses use canonical spelling; IPv6 addresses have brackets. Absent for client-fingerprint and first origin-IP observations. |
| `route` | `direct`, `parent`, or `provider`. Each route has separate destination/TLS comparison state. Absent for client-fingerprint and first origin-IP observations. |
| `verification_name` | The normalized origin TLS verification name for an upstream TLS change; null for destination, first origin-IP and client-fingerprint observations. |
| `current` | Supporting `connection_id`, `event_id`, optional `cert_sha256`/`spki_sha256` hashes, optional `negotiation`, optional `client_fingerprint`, and optional `origin_ip`. |
| `previous` | The previous comparable observation for the same rule, with the same fields as `current`; null for a first destination, origin-IP or client-fingerprint observation. |
| `current.negotiation`, `previous.negotiation` | Measured `version` and `alpn` from the completed origin handshake. Present only for negotiation-change records; their certificate hashes are null. |
| `current.client_fingerprint`, `previous.client_fingerprint` | The observed `ja3` and `ja4` from the client ClientHello. Certificate hashes are null and negotiation evidence is absent. |
| `current.origin_ip`, `previous.origin_ip` | Canonical measured origin IPs. For first origin-IP observation, only `current` is present and its certificate hashes are null. For key/IP reuse, both observations have the same available SPKI hash, distinct IPs and their measured certificate hashes. |
| `client` | Present only for client/destination pairing. An observation with the measured ClientHello's `connection_id`, `event_id` and `client_fingerprint`. `current` links the associated upstream attempt; `previous` is null. |

Join each observation to its exact `network.connection` event by `event_id`
and connection key in the indicator's instance/runtime namespace. The outer
`details.connection_id` also identifies the current connection. TLS hashes
are lowercase SHA-256 hexadecimal values, as in `tls_sessions`. First destination
observations have null certificate hashes. The indicator does not invent an
application request or duplicate content evidence.

Within a `negotiation` object, `version` is the native rustls protocol-version
name, such as `TLSv1_3`. `alpn` uses the same escaped protocol bytes as
`tls_sessions`. A null `alpn` means the completed handshake negotiated no ALPN.
The absence of `negotiation` means the observation supplies no negotiation
evidence; it does not mean no ALPN. A missing version or incomplete handshake
cannot establish a negotiation comparison.

The destination key uses the accepted UDS agent identity, normalized requested
host and port, and route. Request headers cannot select the agent. A physical
parent/provider peer is not the logical destination. A first destination
observation refers to an upstream attempt: its first record follows transport
connection, or final failure if the attempt never connected. It does not prove
that a parent reached the destination, that an application exchange succeeded,
or that an agent initiated the traffic. Existing initiator attribution remains
explicit, including `unknown`. Unattributed connections retain their native
records and do not enter this agent comparison cache. External ingress is not
an input to this UDS-owned producer.

First origin-IP history keys only the trusted agent and canonical measured IP.
Stable retained IPs stay quiet across requested hostnames, ports and routes.
Another agent has separate history. IPv6 spelling is canonicalized;
IPv4-mapped IPv6 uses its IPv4 form. The current direct TCP owner supplies the
actual `resolved_origin_peer` from the established socket. A requested numeric
target, DNS result, synthetic capture address or immediate parent/provider
endpoint cannot establish an origin observation. Missing measurements and
failed connections that never establish a socket supply no IP baseline.

This transport observation occurs before origin TLS or application processing.
It qualifies for plaintext and TLS connections without a certificate or a
successful application response. If TLS verification, negotiation or later
application work fails, the earlier measurement remains a first origin-IP
observation. Follow `current.event_id` to the actual `proxy_to_upstream` open
record and its full measured endpoint, then use the connection ID to inspect
later updates and terminal failure. Closing a connection or updating its TLS
metadata does not compare that IP again after eviction.

Certificate comparison uses only `peer: origin` sessions from full native rustls
handshakes. Parent TLS, resumed sessions with potentially cached certificates,
failed handshakes, and missing certificates do not advance the certificate
baseline. Opaque passthrough tunnels supply no origin certificate observation.
SPKI comparison requires a hash in both observations; absence or newly available
metadata is not a measured change. Certificate changes can still be reported
when an SPKI hash is unavailable. A different verification name resets that
entry's single certificate baseline without comparing names. This matters when
a numeric CONNECT endpoint later acquires a logical SNI name.

Negotiation comparison also uses only `peer: origin` sessions. Successful full
and resumed handshakes measure the current version and ALPN result independently
of certificate availability. Failed handshakes, missing versions, parent TLS and
opaque passthrough tunnels do not advance this baseline. Unknown metadata is
not a change. A transition between a measured null ALPN and a measured protocol
is a change. Each agent/destination/route entry keeps one negotiation baseline
and one certificate baseline. A different verification name resets the affected
baseline without comparing names. Neither baseline mixes origin observations
with parent/provider transport TLS.

Client-fingerprint comparison uses the trusted UDS agent identity alone, across
destinations and routes. Request headers and claimed process/tool names cannot
select this identity. Each observation links to the `client_to_proxy` update
that records the actual ClientHello. The proxy's own upstream TLS never enters
this baseline. A complete supported ClientHello can establish an observation
even if the handshake later fails. Missing, malformed, incomplete or unsupported
hellos and unknown attribution supply no baseline or measured change. External
ingress does not enter this UDS-owned comparison. Stable fingerprint pairs
advance the prior-event link without another indication. A change to either
fingerprint emits one change indication containing both values.

Client/destination history keys the trusted agent, both JA3 and JA4 values,
normalized logical destination and route. Each first pairing emits an indication,
including the first pairing for an agent. A different fingerprint or destination
can establish another pairing. Returning to any retained pairing stays quiet,
even when other fingerprints or destinations were observed between requests.
The separate fingerprint and destination rules keep their existing meaning.

Pairing uses the actual ingress connection that owns each upstream attempt.
It never borrows the agent's most recently observed fingerprint from another
connection. One TLS client can own several application transactions and upstream
attempts. Each new attempt uses that client's measured hello, including after a
policy reload changes the route. Plaintext clients, unknown attribution and
missing, incomplete or unsupported hellos establish no pair. Upstream or parent
TLS cannot substitute for a client fingerprint.

A pair is observed when both a complete supported ClientHello and its owned
upstream attempt have native connection records. A CONNECT attempt can connect
before the hello arrives; observing the hello then compares the pair using
that attempt's existing connection record. Later attempts compare on connection
or final failure if they never connect. A complete hello followed by an aborted client
handshake can establish a pair. The indication proves an observed attempt,
not a successful TLS handshake, application exchange, origin reachability,
executable identity or compromise. Parent/provider routes retain the logical
destination; their physical endpoints are not the destination key.

Follow `client.event_id` to the exact `client_to_proxy` hello update and
`current.event_id` to the `proxy_to_upstream` record. That record's
`client_connection_id` identifies the same client. Both links use the indicator's
instance/runtime namespace and existing audit availability limits. Closing an
attempt does not compare that attempt's pair again after history eviction.

Origin key/IP comparison uses the trusted agent, measured SPKI and canonical IP,
across requested destinations, verification names, ports and routes. A new port
at a retained IP is stable. The first association for a key supplies a baseline;
a new IP for that key emits one indication. Returning to a retained association
updates its supporting event without another indication. For a new association,
`previous` is the latest observation at the most recently inserted retained IP
for that key. Stable repeats do not change that selection's FIFO age.
The top-level destination, route and verification name describe the current
connection. Follow each supporting event to inspect its own requested target,
verification name and full measured endpoint, including its port.

Only a successful full origin handshake with both certificate and SPKI hashes
and a measured `resolved_origin_peer` establishes a key/IP association. The
current native direct TCP owner supplies this peer from the connected socket.
Parent and provider routes do not measure an origin address, even when origin
TLS succeeds. Their immediate peer, a requested numeric target, DNS results and
synthetic capture addresses cannot substitute for measured origin evidence.
Resumed or failed handshakes, missing hashes and unknown attribution supply no
association. IPv6 spelling is canonicalized; IPv4-mapped IPv6 uses its IPv4 form.
No network location lookup or persistent history query is performed.

Cache operations serialize concurrent observations. For change comparisons,
identical observations advance the supporting baseline without another indicator.
Closing an older connection does not replay its TLS snapshot into the comparison. Reconnects
compare while their entry remains cached. Repetition does not refresh FIFO age.
Eviction discards the evicted entry's state; a later observation can produce
a new first observation. An evicted key/IP association can produce another
reuse indication if another IP for that key remains; loss of all associations
leaves a fresh baseline. Destination/TLS, client-agent, agent/IP, key/IP and pairing entries
compete for the same capacity. If a destination entry is evicted before an in-flight origin
TLS handshake completes, that handshake supplies no destination certificate or
negotiation comparison. Its measured key/IP association remains independent.
Policy reloads preserve the cache; process restart clears it, even when JSONL
files remain.
First observation therefore means first in this bounded runtime history, never
first over the agent's lifetime.

The audit writer retains sparse metadata, but it has no destination/TLS history
query or complete-history guarantee. The sensor does not scan rotated files or
enable FlowStore to reconstruct a baseline. Links identify submitted supporting
records; audit queue loss, sink failure, or rotation can make them unavailable.
This feature adds no payload retention, traffic restriction, approval, or change
to ordinary TLS trust and refusal.

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
