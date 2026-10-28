# Native observations and classic capture

The native proxy records receiver-observed transport boundaries before Hypertext Transfer Protocol
(HTTP) reassembly. A canonical asynchronous queue supplies bounded consumer queues.
Metadata remains available without payload capture. Explicit capture settings
can retain source bytes and export a reconstructed classic PCAP stream through
file, stdout/pipe, TCP and secure WebSocket (WSS) adapters.

Metadata observation does not enable FlowStore. Default operation creates no
capture file or listener. With capture disabled, records retain no request headers, URLs, bodies,
Transport Layer Security (TLS) secrets or packet bytes. Metadata serialization
always excludes attached capture bytes. Existing sparse network security monitoring (NSM)
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
state per owner. If the operator enables payload capture, the queue charge also includes each
retained payload byte. An oversized source snapshot retains metadata with zero
captured length instead of allocating beyond the canonical byte bound.
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
same memory accounting. `observation_payload_bytes_total` counts attached source bytes by layer before
admission. `sink_bytes_total`, `sink_errors_total`,
`sink_dropped_observations_total` and `sink_disconnects_total` include fixed
`file`, `stdout`, `tcp` and `wss` labels for actual output adapters. Bytes count
complete batches written by the adapter. A failed partial write can therefore
leave fewer bytes counted than the operating system accepted. Encoded output bytes must not be inferred
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
Classic capture places the actual adapter session in its first UDP metadata
record after the PCAP global header. The session sequence is the first eligible
canonical sequence, even if that observation is later lost. Sink losses carry
the same session ID. A reconnect creates a new session and starting sequence.

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
representation lengths would count the same logical bytes again. Canonical observations contain no synthetic packet fields, TLS records,
protocol frames or inferred sender syscall boundaries. The separate classic
encoder projects source observations without publishing new observations or
updating source measurements.

## Enable explicit payload capture

On the operator host, edit the installation's `config.toml`. Keep the existing
listeners, policy and paths. Add only the desired capture settings, then restart
the native proxy. Capture settings and limits belong to the process. Policy
reloads preserve the effective capture configuration.

This example retains observed transport and TLS-cleartext chunks in a file.
A relative file path belongs to the `config.toml` directory. The parent directory
must exist. Starting a new file session truncates an existing file at that path.

```toml
[packet_capture]
profile = "pcap:compat"
payload_layers = ["transport_stream", "tls_cleartext"]
file = "logs/observations.pcap"

[packet_capture.queue]
items = 4096
bytes = 4194304
```

If `payload_layers` is absent or empty, capture exports metadata without retaining
source content. Current byte owners supply transport and TLS-cleartext chunks.
Protocol/application completion metadata remains available; the encoder does
not reconstruct missing application bytes or lineage. Capture does not change
FlowStore eligibility or force an application decode.

For stdout/pipe output, set `stdout = true` in `[packet_capture]`. The foreground
native proxy writes the capture bytes to stdout. Redirect stdout to a file or
pipe it to a reader that accepts classic PCAP. Operational errors use stderr.
When using the installed background service, stdout follows that service's
existing output destination; use the file or network adapter when appropriate.

For a raw TCP listener, add the following table. Its presence explicitly enables
the listener. The default bind is `127.0.0.1:46378` if `bind` is omitted.

```toml
[packet_capture.tcp]
bind = "127.0.0.1:46378"
```

A consumer receives a normal PCAP byte stream from each connection. There is no
HTTP preamble. If `bind` uses port zero, the existing readiness marker reports
the selected endpoint in `capture_tcp_address`. If the operator selects a non-loopback bind, the table must also
set `insecure_remote = true`. Changing the bind alone refuses configuration.
Raw TCP has no authentication or transport encryption. Use authenticated WSS
for remote consumers. The existing operator-port shield protects the actual
capture endpoint against agent requests through the proxy.

For WSS, set `wss = true` in `[packet_capture]` and configure the existing
Admin listener and operator token. Connect to `/admin/capture` with a WebSocket
upgrade and `Authorization: Bearer <operator-token>`. The existing Command Centre
Tailscale TLS publication exposes the same native operator listener remotely;
use its WSS endpoint with the `/admin/capture` path. The loopback backend uses
plain WebSocket, as the existing event stream does. Capture does not create a
second TLS listener or a new credential system.

The existing operator token grants capture read access when `wss` is explicitly
enabled. An unauthenticated client receives no capture bytes and creates no
capture session. Each binary WebSocket message contains part of the capture
stream. Concatenating binary payloads produces the exact PCAP byte stream.
WebSocket control frames are outside those bytes. These classic streams expose
no TLS-secret setting or secret grant. Observed plaintext in a compatibility
stream is not wire decryption.

No adapter is enabled by default. Network bind, file-open, permission, write and
bounded-session failures report content-free sink errors and counters. Sink
failures do not change the controlled agent traffic result. Files use mode
`0600` on supported Unix platforms before capture bytes are written.

## Classic `pcap:compat` representation

The savefile uses nanosecond timestamp units, PCAP version 2.4 and
`LINKTYPE_ETHERNET`. Source resolution is separately declared in session and
observation metadata; the timestamp unit does not claim a finer clock. Source
wall times outside classic PCAP's unsigned 32-bit seconds range cannot be
encoded and produce an explicit loss range. Canonical monotonic order remains
authoritative when wall time moves backwards.

All Ethernet/IP/TCP/UDP fields are reconstructed representation fields. The
locally administered synthetic MAC namespace is `02:53:59:xx:xx:xx`. Source IPv4
addresses use `192.0.2.0/24`, and destination addresses use `198.51.100.0/24`,
which are RFC 5737 TEST-NET ranges. The encoder derives endpoint suffixes and
ports deterministically from the flow context. A packet tool's synthetic
five-tuple is not a unique source identity; use `compat_flow_id` and metadata.

A flow ID is the lowercase SHA-256 digest of the bounded UTF-8 context record,
including the metadata magic prefix. The context identifies source instance,
runtime, connection, observation point, layer, original transport and direction.
Different source layers or directions produce separate compatibility flows.

Before each observation's data, a UDP record contains ASCII
`SAFEYOLO-PCAP-COMPAT/1`, a newline and at most 8192 bytes total of UTF-8 JSON
including that prefix. Observation records contain `compat_flow_id`, the
source context, canonical observation metadata and `payload_truncated`.
Session records contain profile/schema identity and the actual source session.
Gap records distinguish canonical/consumer loss from encoder/sink admission
loss. None of these metadata records contains captured payload or TLS secrets.

Context is repeated with each observation so a newly joined or recovering
consumer can interpret each accepted batch. This avoids an unbounded table of
previously seen flows and does not replay historical payloads. The source
observation retains its original state, offsets, IDs, monotonic time and
lineage, including absent lineage.

An observed chunk of at most 1200 captured bytes produces one synthetic TCP
payload segment. Larger observations split into consecutive segments of at most
1200 bytes. All segments carry the source observation's wall timestamp and
remain in source sequence order. TCP sequence numbers are the low 32 bits of
the source stream offset plus the segment offset. Only the final segment sets
synthetic PSH, which marks the captured source boundary. Metadata declares the
original and captured lengths so a reader can distinguish truncation from a
complete chunk. EOF/half-close may project FIN; read/write failure or owner drop
may project RST. These control fields are representation only.

Classic PCAP contains no PCAPNG Decryption Secrets Block (DSB). A reader can
inspect observed UDS or TLS plaintext through the synthetic TCP view, but must
not label these reconstructed frames as genuine wire packets.

## Delivery budgets and failures

The canonical and capture-consumer queues account retained metadata and payload
against their separate item/byte limits. The capture worker holds at most one
source record while encoding. Its output buffer is bounded by
`packet_capture.queue.bytes`; conversion into a shared byte array can briefly
hold a second buffer of that size. Metadata and packet/checksum scratch buffers
are bounded separately by the metadata/segment limits above.

Each configured sink or connected client has another queue with the same
`packet_capture.queue` limits. Shared encoded batches are conservatively charged
in full to every receiving queue. The charge remains held while an adapter
writes the batch, including a slow in-flight write. One item and 32 KiB are
reserved for a bounded loss record and output staging. File/stdout writes use
at most 16 KiB per staging copy and flush each batch. WebSocket framing uses
the existing bounded writer buffer. If the remaining budget cannot initialize a
session, that sink reports a session-budget error and emits no dependent bytes.

Each admitted batch contains complete metadata and data for one source record.
If a record cannot be encoded or a sink queue cannot admit it, the affected sink
emits a session-scoped sequence gap before subsequent bytes, including a final
loss tail. Healthy sinks preserve their own byte order. No capture producer
waits for a writer or queue capacity. A stalled write times out and disconnects
that sink. Errors contain fixed sink/reason labels, never captured content,
destinations or secrets.

## Remaining capture work

This increment of [#858](https://github.com/craigbalding/safeyolo/issues/858)
adds classic compatibility capture and the four adapters. Portable PCAP Next
Generation (PCAPNG) still requires the actual Internet Assigned Numbers
Authority (IANA) Private Enterprise Number owned by
[#862](https://github.com/craigbalding/safeyolo/issues/862), its encoder and
portable-extension proof. Genuine packet capture, `pcap:wire`, exporter
exclusion, TLS-secret export/authorization and DSB/decryption remain separate
unimplemented outcomes. Selecting an unavailable profile reports unavailable;
there is no placeholder PCAPNG format or reconstructed wire profile.
