# Network Security Monitoring event contracts

The native audit writer accepts three Network Security Monitoring (NSM)
contracts: `network.connection`, `traffic.flow`, and `security.indicator`.
They describe transport sessions, application transactions, and sensor
indications respectively. Hypertext Transfer Protocol (HTTP) requests are not
transport connections.
Issue #582 defines these contracts. Issue #583 adds emission from actual
client and upstream transport owners. Transport Layer Security (TLS) identity
and sensor implementations remain separate work in #584 and #585.

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
Open and terminal records refer to the same connection key.

| Field | Contract |
| --- | --- |
| `connection_id` | Nonempty transport-owned local ID. |
| `leg` | `client_to_proxy` or `proxy_to_upstream`. The client may be external. |
| `transport` | `unix` or `tcp`, matching the current native transports. No inferred UDP or QUIC. |
| `started_at` | Observed start time in RFC 3339 format. |
| `ended_at` | Observed end time in RFC 3339 format; absent/null while open. Must not precede the start. |
| `state` | `open`, `closed`, or `failed`. Terminal states require `ended_at`. |
| `local_endpoint`, `remote_endpoint` | Observed endpoints relative to the proxy; absent/null when unavailable. |
| `error` | Optional nonempty error category; no raw content or secret-bearing diagnostics. |
| `requested_target` | Optional requested authority, for example `example.com:443`. A hostname is not a peer IP. |
| `resolved_peer` | Optional actual dialed IP socket address, for example `203.0.113.10:443`. If the remote IP endpoint is present, they must agree. |
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

## Retention and quieting

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
