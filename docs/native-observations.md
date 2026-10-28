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
`items`. Session and source metadata are separate, constant-size
state per owner. Transport metrics have separate fixed accounting bounds, described below.
If the operator enables payload capture, the queue charge also includes each
retained payload byte. An oversized source snapshot retains metadata with zero
captured length instead of allocating beyond the canonical byte bound.
Zero admits no observations and still reports sequence loss. A policy reload
preserves the process-owned queue, namespace and effective limits. Restart the
proxy to change these limits.

The existing authenticated operator stats report includes `observations`.
The runtime's existing Prometheus renderer includes the same operational
counters. Metadata statistics use the existing HTTP endpoints. Layer labels identify transport
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
from the metadata memory counter.

## Transport-behaviour metrics

The same operator stats report includes `observations.behaviour`. The existing
Prometheus renderer exposes these measurements with the `safeyolo_` prefix.
The canonical fan-out worker measures metadata once, before consumer admission
and capture encoding. Payload capture and FlowStore are not prerequisites.
Enabling `pcap:compat` does not add synthetic packets or control records to the
measurements.

| Metric | Measurement |
| --- | --- |
| `observation_chunks_total` | Canonical receiver-observed chunks |
| `observation_bytes_total` | Observed lengths of those chunks |
| `observation_chunk_bytes` | Histogram of observed chunk lengths |
| `observation_inter_chunk_interval_seconds` | Histogram of consecutive chunk intervals within one connection, point, layer, transport and direction |
| `application_messages_total` | Native request-completion records, including parsed CONNECT heads |
| `chunks_per_application_message` | Histogram of source chunks overlapping the completed message's exact parser-consumed byte range |
| `connections_started_total` | Canonical connected records for accepted or established connections |
| `connection_lifetime_seconds` | Histogram from a connected record to its closed or failed record |
| `partial_or_aborted_streams_total` | Incomplete parser input, unfinished application-body owner drops and stream read/write errors |
| `protocol_parse_failures_total` | Native parser errors, excluding generic HTTP failures and incomplete input |
| `observation_loss_total` | Canonical gap counts and records whose live accounting exceeds the fixed metrics capacity, separated by `reason` |

Series labels are the fixed enums `point`, `layer`, `transport` and `direction`.
No new metric uses agent names, request/connection IDs, destinations or content
as labels. Timing uses canonical monotonic nanoseconds converted to seconds;
wall-clock adjustments do not affect durations. Histograms expose cumulative
finite buckets, `+Inf`, count and sum through Prometheus. JSON reports finite
buckets, count and sum. Measurements do not assign anomaly thresholds or
security verdicts.

Application counts use completion rather than parsed-head admission. Incomplete
or failed input still contributes its observed chunks and bytes. Ordinary stream
owner drops after completed requests do not imply aborted messages. Partial
measurements describe the named layer: an application-body abort and a transport
error can each produce a measurement at their respective points.

Recoverable HTTP/2 parser rejections are counted at the native receiver,
including heads rejected before request admission. Distinct rejected streams
on one connection each contribute a failure. A peer reset is not a parser failure.

Chunks-per-message series use the source point/layer/direction from an exact
HTTP/1 `input_span`. A read-ahead chunk can overlap two messages and contribute
once to each. Framing and trailers are included; unrelated read-ahead bytes are
excluded. Prefix ancestry from HTTP/2, TLS or plain HTTP inside CONNECT cannot
establish an exact message relation. Missing lineage, missing source chunks or
accounting overflow omit that distribution sample and increment
`chunks_per_application_message_unavailable_total` at the application point.
The application-message count remains available.

Live accounting retains at most 4096 connections and 16384 inbound chunk ranges
across those connections. Completion retires consumed ranges; connection close
or failure retires the connection's state. These bounds limit measurement state
and do not limit traffic or parser admission. At capacity, raw chunk/byte and
message counts continue while `observation_loss_total{reason="metrics_accounting_capacity"}`
reports lost accounting input. A canonical gap adds its missing-record count
under `canonical_admission_unavailable` and clears uncertain live accounting
in that runtime. Neither timing adjacency nor complete message coverage is
inferred across the gap. Existing attempted-observation and per-consumer loss
counters retain their separate meanings.

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
Pipe writes are nonblocking. If the reader stops, the sink times out without
leaving a blocked stdout worker that prevents process exit.
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
For an Internet Protocol version 6 (IPv6) wildcard listener, the shield retains
the socket's effective IPv6-only setting. If the socket also accepts Internet
Protocol version 4 (IPv4), the shield protects its IPv4 loopback and unspecified
local aliases.

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

## Genuine `pcap:wire` acquisition

On the operator host, select a native capture interface and explicitly enable
packet payloads in `config.toml`. The host needs libpcap and permission to open
that interface. SafeYolo does not elevate the proxy or change host permissions.
Use the interface that carries the selected upstream connection. For example,
`lo0` captures loopback traffic on macOS; `en0` commonly carries external traffic.
Linux libpcap also supports `any` for the host's interfaces.

```toml
[packet_capture]
profile = "pcap:wire"
wire_interface = "lo0"
payload_layers = ["wire_packet"]
file = "logs/upstream-wire.pcap"
```

The existing file, stdout/pipe, TCP and authenticated WSS adapters consume the
same wire encoder. A wire file contains only genuine acquired packets under
one declared link type. It contains no synthetic session, gap or compatibility
packets. Packet bytes, original length, acquired length and source wall timestamp
pass through unchanged. The encoder selects nanosecond PCAP only when libpcap
reports nanosecond source precision; otherwise it uses microsecond PCAP.
The proxy reports each adapter's instance/runtime/session identity, starting
canonical sequence, link type and actual source precision on stderr. These
session records contain no packet content. Classic wire PCAP cannot carry that
rich metadata inside its packet-only byte stream.

Acquisition is disabled unless `pcap:wire`, `wire_interface` and the explicit
`wire_packet` payload layer are selected together with an adapter. Other payload
layers do not retain stream content under the wire profile. A missing library,
unsupported link type, denied interface or acquisition failure reports a fixed
unavailable reason. If acquisition fails after startup, existing wire sessions
end. Later TCP collectors receive no capture stream, and authenticated WebSocket
capture requests receive HTTP 503 until the proxy restarts.
Agent traffic, stream metadata and behavioural metrics
continue. Selecting `pcap:compat` continues to work without packet privileges.

The source uses libpcap without promiscuous mode. Its kernel filter selects TCP
on the configured interface. Before copying a packet into an observation, the
proxy requires an exact local/remote socket tuple from a native upstream owner.
Unrelated host connections and both legs of TCP/WSS export never register.
They cannot become packet observations or feed the export stream. Packet
observations carry the native connection ID and trusted source attribution.
They have no inferred stream offset or application lineage. Stream behavioural
metrics ignore packet records and continue to measure canonical stream reads
and writes. Packet monotonic time describes ingestion into SafeYolo; packet wall
time and its resolution come from libpcap.

The connection table is bounded by the capture queue's item limit and one entry
per 4096 bytes of its byte limit. Registration does not wait for table admission.
Closed entries remain for at most one second to correlate packets already
buffered by libpcap. Their source timestamp bounds exclude later tuple reuse.
The source polls at most 64 packets per acquisition turn. Kernel buffering is
bounded separately by libpcap; SafeYolo requests the configured capture byte
budget, with a minimum 64 KiB kernel buffer. The source supports Ethernet
(including two VLAN tags), native loopback, raw IP and Linux cooked link types.
It follows at most eight IPv6 extension headers. Packets without a readable TCP
tuple, including noninitial IP fragments, cannot be correlated and are omitted.
Connection registration follows successful connect. Packets timestamped before
registration or already drained before registration are unavailable. Capture does not claim a complete TCP
handshake or retransmission history.

The observation counters expose `wire_packets_received_total`,
`wire_kernel_dropped_total`, `wire_interface_dropped_total`,
`wire_correlation_missed_total` and `wire_source_errors_total`. Kernel receive
and drop counts describe the acquisition interface/filter, including traffic
later excluded by ownership. They are separate from observation-bus and sink
loss. A wire session with an observation or sink gap ends with a content-free
error and loss counters. The proxy cannot encode a gap as a genuine packet.
Other consumers and agent traffic continue. If acquisition is still active, a new
live consumer can subscribe after a session gap.

## Remaining capture work

This increment of [#858](https://github.com/craigbalding/safeyolo/issues/858)
adds genuine wire capture to the existing classic compatibility capture and four
adapters. Portable PCAP Next Generation (PCAPNG) still requires the actual
Internet Assigned Numbers Authority (IANA) Private Enterprise Number owned by
[#862](https://github.com/craigbalding/safeyolo/issues/862), its encoder and
portable-extension proof. The cross-format packet-subset comparison, TLS-secret
export/authorization and DSB/decryption remain unimplemented. Selecting PCAPNG
reports unavailable; no placeholder format is emitted.
