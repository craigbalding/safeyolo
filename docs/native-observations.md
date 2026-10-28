# Native observation metadata

The native proxy records receiver-observed transport boundaries before Hypertext Transfer Protocol
(HTTP) reassembly. A canonical asynchronous queue supplies bounded consumer queues.
This foundation supplies metadata for later capture encoders and transport
metrics. It does not install an output adapter or retain payloads.

Metadata observation does not enable FlowStore. Default operation creates no
capture file or listener. The records contain no request headers, URLs, bodies,
Transport Layer Security (TLS) secrets or packet bytes. Existing sparse network security monitoring (NSM)
events and FlowStore eligibility keep their existing behavior.

## Configuration and operational state

In the installation's `config.toml`, the optional observation settings bound
the canonical queue:

```toml
[observations]
items = 4096
bytes = 4194304
```

These are the defaults. `items` limits queued records. `bytes` limits their
accounted memory: inline storage, owned identity strings and conservative
allocation/provenance charges. Queue allocation overhead is also bounded by
`items`. Session and active-connection metadata are separate, constant-size
state per owner. No payload allocation is included because no payload is stored.
Zero admits no observations and still reports sequence loss. A policy reload
preserves the process-owned queue, namespace and effective limits. Restart the
proxy to change these limits.

The existing authenticated operator stats report includes `observations`.
The runtime's existing Prometheus renderer includes the same operational
counters. No new HTTP endpoint is added. Layer labels identify transport
streams, TLS cleartext, protocol messages and application content. Consumer
labels are the fixed internal kinds `metrics` and `capture`; they contain no
request IDs, connection IDs, destinations or content.

`observations_total` and `observation_metadata_bytes_total` include attempted
observations before admission. `observation_bus_dropped_total` counts failed
canonical admissions by layer. `observation_gap_ranges_total` counts canonical
gap ranges dispatched to consumers. `observation_sequence_exhausted_total`
reports attempts after the runtime's unsigned 64-bit sequence is exhausted;
sequence allocation stops instead of wrapping, while traffic continues.

Consumer loss and disconnection counters describe the bounded consumer queues.
`observation_consumer_metadata_bytes_total` measures delivered metadata with the
same memory accounting. `sink_bytes_total`, `sink_errors_total` and
`observation_payload_bytes_total` remain zero: this foundation has no encoders,
output adapters or captured payload. Encoded output bytes must not be inferred
from the metadata memory counter. Behavioral distributions remain separate work
under [#863](https://github.com/craigbalding/safeyolo/issues/863).

## Identity, time and delivery

Each observation ID combines the existing installation `instance_id`, the
process `runtime_id` and a sequence starting at 1. Installed instances retain
their durable identity across restarts. A standalone proxy without an installed
identity uses its process namespace, as existing connection audit does.
Reloads preserve the namespace and sequence. A process restart changes the
runtime ID. Local connection and request IDs keep their native meanings within
that namespace.

Sequence allocation precedes queue admission. Producers use immediate admission
attempts and never wait for queue capacity or consumers. Item exhaustion, byte
exhaustion and concurrent queue access can refuse admission. Missing contiguous
sequence ranges become explicit `canonical_admission_unavailable` gap records
when the dispatcher resumes, including a loss tail with no later traffic.
Each gap carries the namespace, first/last sequence and exact count.

A stalled consumer does not block fan-out to other consumers. Its next receive
reports its missing range before later accepted records, including a terminal
loss tail. Consumer gaps identify consumer admission failure separately from
canonical admission loss. The queue bounds apply independently to each
consumer. The final bus owner flushes its bounded remainder before consumers
receive end of stream.

An internal consumer session identifies the instance, runtime, schema version,
new `sink_session_id`, timestamp resolutions and first eligible canonical
sequence. Subscriptions have no historical replay. A canonical gap that crosses
the subscription point is clipped to that session's starting sequence.
These are source/session contracts for later sinks, not a released capture
format or remote subscription API.

Records carry Unix wall time and monotonic time since the bus started. Ordering
and durations within one runtime use the sequence and monotonic clock. Wall
clock correction does not reorder records. Timestamp values use nanoseconds;
separate resolution fields report the kernel's clock resolutions. An unavailable
resolution is null, rather than an invented precision claim.

## Source boundaries and lineage

Transport records describe reads and successful writes on the actual agent
Unix-domain socket and upstream Transmission Control Protocol (TCP) or provider stream. Offsets advance by the
number of bytes actually read or written. A receiver read is not evidence of
one sender write. EOF, half-close, read/write error, owner drop and connection
lifecycle are distinct states. An incomplete request can therefore retain its
input and terminal metadata without a parsed application message.

The native TLS wrappers add cleartext observations at the client, parent and
origin TLS boundaries. These records do not replace transport records.
Parsed request heads retain native request IDs and HTTP/2 stream IDs when
present. Existing validated request-completion hooks add application-content
completion. Content lengths remain null when no decoded length was observed.
A confirmed content decoding operation sets the transform marker. Observation
does not force a decode, drain a body or change parser admission.

`input_span` names the source point, layer, direction and enclosing observation
IDs. Source observations are selected within that connection and source context;
stream offsets delimit the relevant bytes. For HTTP/1, `parser_consumed=true`
provides the parser's exact start/end offsets, including framing and trailers.
Read-ahead bytes for a later message are excluded. The enclosing source IDs can
cover read-ahead; their entire payload must not be assigned to this message.
Application-content records also reference their parsed-head observation ID.

When `parser_consumed=false`, the span identifies a source input prefix. TLS
and HTTP/2 parsers can buffer and read ahead, so this ancestry does not claim
exclusive byte ownership by a message or an exact ciphertext-to-cleartext map.
Plain HTTP inside CONNECT also uses prefix ancestry because the inner parser
starts a new offset space over replayed outer input. Outbound TLS cleartext is
observed before encryption; it does not claim already-written ciphertext as its
parent. If a source-prefix update cannot acquire its metadata lock, lineage
from that prefix stays absent until a successful update restores accurate bounds.
An exact parser range is attached only when the source observations enclose it.
If the first source-prefix update was missed, later lineage starts at the first
known source observation's offset. Missing lineage remains absent instead of
being reconstructed. Source chunk records and their queue loss accounting are
independent of prefix availability.

Count source transport bytes at the transport layer. Adding TLS or parsed
representation lengths would count the same logical bytes again. No synthetic
packet, TLS record, protocol frame or sender syscall boundary is manufactured.

## Remaining capture work

This is the canonical metadata and loss increment of
[#858](https://github.com/craigbalding/safeyolo/issues/858). Portable PCAP Next Generation
(PCAPNG) remains blocked on the operator-confirmed Internet Assigned Numbers
Authority (IANA) Private Enterprise Number in
[#862](https://github.com/craigbalding/safeyolo/issues/862). PCAPNG and classic PCAP
encoders, genuine packet capture, TLS-secret export, file, pipe, TCP and secure WebSocket (WSS) adapters
and their access controls remain unimplemented. All corresponding acceptance
criteria remain open. No placeholder enterprise number or substitute adapter is
provided by this foundation.
