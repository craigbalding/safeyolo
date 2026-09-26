# Proxy migration contracts

These fixtures exercise the first HTTP slice of issue #620 and capture the
existing full production application programming interface (API) and approval
baseline. Each run starts its own proxy process, two per-agent Unix domain
sockets (UDS), and synthetic endpoints. Requests never target an external
origin or the running SafeYolo instance.

## Run the contracts

From the repository root on Linux or macOS, install the locked Python test
dependencies with `uv sync --frozen --group dev`. Build the Rust binary with
`cargo build --locked --manifest-path proxy/Cargo.toml`. The following command
starts and stops isolated Python and Rust fixtures:

```sh
uv run --frozen pytest -q tests/proxy_migration \
  --proxy-backend python --proxy-backend rust
```

The Python backend is the default for shared tests. The full-production tests
always use Python and currently skip platforms other than Linux. Set
`SAFEYOLO_RUST_PROXY` to select a built binary at another path. A missing
requested binary is an error. The fixture
does not select a different backend after a failure.

The shared assertions cover:

- Two simultaneously active agent listeners, alternating allowed and denied
  HTTP requests, forged agent/request identifiers, and evidence attribution.
- The origin-controlled request-ID cases join each HTTP response ID to its own
  trusted-agent runtime event, complete `/explain` audit result, and untruncated
  `/trace` decision. CONNECT admission IDs resolve to scoped audit and trace
  records; the Python fixture has no CONNECT runtime event. An allowed HTTP
  request with explicit test context must
  also resolve to a persisted, agent-owned flow. The other agent cannot read
  its trace, audit events, or flow detail. An early network denial and CONNECT
  admission have no applied test context and therefore no FlowStore row; the
  fixture checks that absence instead of claiming one. The CONNECT admission
  and inner request have different IDs and one shared connection ID. The owned
  origin records each socket accept and application request separately.
- With `addons.test_context.target_hosts` and declared injection enabled for
  one synthetic host, an unannotated request returns 428 before parent contact.
  Another host still reaches the parent. Alice's declaration is queryable and
  owned by her trusted UDS source even when its `agent` field says Bob; Bob
  cannot inherit it through forged identity fields. A malformed explicit
  header cannot borrow the declaration. Headerless inherited and valid explicit
  requests reach the parent without forwarding the reserved header, and their
  separate response IDs share one client connection ID. The case resolves those
  IDs to scoped trace, audit, runtime and persisted flow records. It requires
  complete traces and two persisted allowed flows with no capture truncation
  before interpreting empty denied-flow searches. Failure to persist either
  allowed flow fails the case. This small-body case makes no claim about
  truncated payload capture.
- Allowed HTTP/1.1 chunked uploads reach an owned origin with complete framing
  and exact body bytes. The fixture checks a buffered request and a request
  one byte above the configured 10 MiB streaming threshold. The origin waits
  for the final zero chunk or an exact Content-Length before it sends 200.
  A direct request controls the origin. This checks transport completion and
  hop-header removal; it does not establish body inspection or capture beyond
  the configured streaming window.
- A raw origin and one persistent client UDS connection check response transfer
  coding. The origin sends `gzip, chunked` or plain `chunked`, then an ordinary
  second response. The fixture checks the client's exact coded body, coding
  declaration, canary, and second response. It also checks that a client
  `TE: gzip` nominated by `Connection: TE` does not reach the origin. The
  gzip case runs with and without client `TE`; this fixture does not test
  HTTP/2 transfer-coding conversion.
- Persistent HTTP/1.1 requests on two trusted UDS connections, with repeated
  allowed/denied decisions, independent origin request targets, and stable
  per-agent connection identities across reuse.
- A framed HTTP/1.1 response sends its first chunk to the client, then holds
  the terminal chunk. The client closes deliberately. The origin observes the
  resulting socket close, while a completed response before cancellation and
  two later responses on one new client connection deliver exact body bytes.
  The other agent remains denied and creates no origin request. This finite
  handoff does not cover close-delimited Server-Sent Events (SSE) or repeated
  resource growth.
- A held close-delimited SSE response sends one event before the client closes
  both `HTTPResponse` and `HTTPConnection`. The origin observes socket EOF
  before the fixture releases the rest of the stream. A separate control
  request completes, then origin writes fail on both backends. The Python
  fixture records one `proxy.request` row for the completed control; Rust
  records rows for the stream and control. These are fixture events, not a
  production audit parity claim.
- One process handles three bounded batches of short HTTP, a partial canceled
  upload, a close-delimited SSE response, WS and WSS echoes, and an opaque
  CONNECT tunnel. The five long-lived legs overlap a permitted control request,
  an authenticated operator `/stats` read, and a denied other-agent request.
  The same operator endpoint rejects an unauthenticated read before and after
  restart. The upload origin records the exact partial body digest and an
  incomplete body; the WebSocket and tunnel origins record their exact bytes
  and end of connection. Both SSE origins observe cancellation
  after the fixture closes the response as well as the HTTP client. Closing only
  `HTTPConnection` left a close-delimited `HTTPResponse` holding the socket, so
  the earlier apparent Python cancellation difference was a client-fixture
  artifact. A separate raw-socket SSE case checks early disconnect, origin EOF,
  prompt shutdown and same-config restart. Its live-response control checks
  native graceful drain and records the Python comparator's SIGTERM EOF before
  the final event. Linux `/proc` samples check the live-to-quiet file-descriptor
  drop and resident-memory trends after each batch, allowing bounded allocator
  retention. The same process configuration then stops and starts on the same
  listener paths and operator port; a new readiness marker names the new
  process, and permitted and denied requests still follow the configured
  policy. On an isolated host, set `SAFEYOLO_LIFECYCLE_BATCHES` above three
  and run the same selected test under an external deadline for a longer check.
  The default finite fixture does not establish sustained churn, a global
  memory cap, or host cleanup.
- On Linux with `strace`, the shared outbound-effects case follows both real
  backends through their `connect` system calls. Two permitted parent requests
  establish that the observer sees IP `connect` attempts. Reserved API and
  probe requests, reserved CONNECT, malformed local requests, and denied
  ordinary HTTP and CONNECT create no additional IP `connect` attempt, parent
  accept, or parent application request. The Python case selects eager
  connections. A separate direct-route case binds a temporary authoritative
  DNS server to loopback port 53 without changing resolver configuration. It
  first requires a live `getaddrinfo` query from the test process, then live
  DNS queries and origin accepts from each proxy. Distinct denied and reserved
  names add no DNS query, IP network syscall destination, or origin accept;
  permitted names before and after those requests keep the observers live.
  The DNS case skips with a stated reason if the host cannot bind loopback
  port 53 or its resolver does not use that server. A skip is not DNS evidence.
  These Linux cases do not establish the remaining plain-HTTP decisions or
  platform coverage.
- Direct origin-form forwarding and absolute-form forwarding through an
  explicitly configured parent, preserving repeated/encoded query parameters.
- Raw absolute-form authority and Host controls through a Host-routing parent.
  The parent sends each request to a distinct physical origin and records the
  selected route. An allowed request keeps its signed-style encoded target,
  repeated query parameters, body bytes and synthetic credential. A forbidden
  absolute target opens no parent connection. For an allowed target with a
  forbidden Host, both backends forward the admitted Host to the parent. The
  forbidden origin has zero accepts and receives no credential. A direct parent
  request proves that the observer routes a conflicting Host to the forbidden
  origin.
- Raw service-gateway requests use an independent Host-routing parent and two
  origins. Duplicate Authorization and Host fields, plus encoded,
  doubled-slash, dot-segment, and trailing-slash spellings of an exact route,
  create no parent or origin connection. Python rejects raw fullwidth route
  letters during HTTP parsing; Rust rejects them at the service gateway.
  Both leave the parent and origin untouched. The exact canonical route
  succeeds. A service route with repeated encoded query values delivers the
  exact body and only the vaulted credential to the allowed origin. An ordinary
  signed target with an encoded path segment keeps its exact target and body
  without a gateway credential. When Content-Length conflicts with
  Transfer-Encoding,
  Python rejects the request locally.
  Rust forwards one chunked body with no Content-Length; the parent and origin
  both record the exact decoded bytes. A direct request proves that the parent
  routes a conflicting Host to the forbidden origin.
- A raw HTTP/1.1 client keeps one Alice listener connection open across allowed,
  denied, and approval-required requests to three independently observed ports.
  Each response has a distinct request ID, and the connection ID stays the same.
  Only allowed requests reach an origin. The allowed origin receives a synthetic
  credential on the two requests that supplied it and receives no credential on
  the intervening and later requests. Its first request retains an encoded path
  and repeated query parameters. A separate Bob listener denies a request with
  a forged Alice header and opens no origin connection. Both backends pass the
  same sequence; their raw framing and route-rejection differences remain above.
- Intercepted CONNECT authority, inner HTTP/1 Host, HTTP/2 `:authority` and
  Host, and client Server Name Indication (SNI) through the same controlled
  parent and two independent TLS origins. A forbidden CONNECT opens no parent
  connection.
  An allowed request and an ASCII case-equivalent inner Host complete with exact
  target, body and credential bytes. Both backends reject changed inner HTTP/1
  Host and HTTP/2 `:authority` before application delivery. An announced
  streaming HTTP/1 body receives a local denial from its request head before
  upload. Both proxies reject a conflicting HTTP/2 Host field before
  application delivery. A client SNI conflict cannot contact the forbidden
  origin. If the parent deliberately routes the allowed CONNECT to a wrong-name
  TLS origin, both proxies reject its certificate before sending application
  bytes. A direct client trusts that same certificate for its own name.
- An IDNA A-label destination remains the admitted authority through a Host
  routing parent, an HTTP/1 CONNECT request, and HTTP/2 conversion to an
  HTTP/1 origin request. The parent and TLS origin observe an ASCII A-label
  Host and the exact credential. Changed and malformed inner authorities are
  denied before origin application bytes. An absolute IPv6 target with a
  conflicting Host forwards the bracketed admitted authority to the parent.
- Configured `network:request` limits of one request per minute exhaust at
  the real proxy boundary. The shared fixture records the 429 response,
  agent and destination events, and exact parent accepts and application
  requests. A neighboring host remains allowed after per-host exhaustion but
  is denied after global exhaustion. An authenticated operator budget reset
  restores the limited host. The bounded sequence stays clear of the generic
  cell rate algorithm (GCRA) refill boundary. `network:connect` counters remain
  a separate case.
- A separate shared case exhausts 20 requests per minute at both global and
  per-host scope. Without an operator reset, the next request succeeds after
  the GCRA emission interval. The parent records no request for the denial and
  records the recovered request.
- A configured circuit opens after two complete 500 responses from an owned
  parent. While it is open, later requests for that host return local 503
  without another parent connection. A different permitted host remains usable.
  After the configured timeout, one successful half-open probe closes the
  circuit. The shared case checks wire IDs, parent counts, circuit state and
  scoped events on both backends; reset, persistence and other thresholds have
  separate tests.
- Local containment of unavailable Agent API handlers and the reserved probe,
  including mixed-case Agent API hostnames and synthetic bearer credentials.
- Readiness and graceful process shutdown.
- HTTPS through the real policy engine with verified client and origin TLS,
  including a configured private trust root, wrong-host and untrusted-origin
  failures, denied CONNECT, and exact repeated/encoded query bytes.
- A trusted-by-file origin certificate whose validity window starts tomorrow is
  rejected with HTTP 502; the independent origin records the TLS handshake
  failure and zero application bytes. mTLS, OCSP/CRL and protocol/cipher
  negotiation remain outside this case.
- A mutual-TLS origin control accepts a disposable client certificate directly,
  then rejects the proxy upstream connection without client-certificate
  configuration before any HTTP request. This records unsupported mTLS as a
  clear TLS failure; it does not add client-certificate configuration.
- A TLS 1.2-only origin restricted to `ECDHE-RSA-AES128-GCM-SHA256` accepts one
  direct control and one proxied request, with the independent origin recording
  the negotiated version and cipher for both. This is one bounded version/cipher
  witness; it does not claim TLS matrices, OCSP/CRL or renegotiation coverage.
- Authority-form CONNECT metadata with no HTTP path or scheme, including
  opposing path-conditioned allow and deny rules.
- Separate `network:connect` global and per-host limits on fresh tunnels.
  The fixture counts admitted origin connections and local HTTP 429 denials,
  checks a second destination, and sends a direct HTTP request to show its
  independent `network:request` counter. An unauthenticated reset cannot clear
  the exhausted limit; an authenticated reset permits another connection.
  A separate case shows that an exhausted limit denies another fresh tunnel
  without an origin connection, then admits one after the GCRA emission
  interval without an operator reset. It checks both scopes and the separate
  HTTP request counter.
  CONNECT creates no origin application request in this fixture. Both backends
  record CONNECT in the security audit; Rust also emits `proxy.request` rows.
- Concurrent HTTP/2 streams from two agents, independent request identities,
  exact encoded queries, protocol negotiation and rejected inner authorities.
  A mixed-outcome case sends allowed requests and a credential approval request
  on one Alice connection while Bob sends denied requests on another. The owned
  origin records HTTP/2 negotiation and distinct allowed response bodies. The
  operator API retains only Alice's credential approval. The origin sees only
  the two allowed application requests, with no credential header. A separate
  HTTP/1 request records HTTP/1 negotiation on both legs.
- An HTTP/2 upload one byte above the 10 MiB streaming threshold reaches the
  owned origin byte for byte. The origin observes END_STREAM before it replies.
  A separate header-detectable credential case announces 12 MiB, above that
  threshold, but sends only a 21-byte prefix without END_STREAM. It checks
  that the credential guard replies before the origin sees an application request.
  The allowed CONNECT can open the origin TLS connection first; the denied
  inner request creates no additional origin accept or outbound event. A
  sibling stream on the same client connection completes. The Python comparator
  opts into the production credential guard and early head-response hook for
  this case; other comparator scenarios keep their existing addon chain.
- Opaque CONNECT, server-first traffic and both TCP half-close directions.
  The old half-close defects remain two strict expected failures.
- A client EOF before the terminating CONNECT header line is a canceled request:
  the native fixture observes no origin accept for that incomplete request, then
  completes a separate valid CONNECT control. The Python comparator remains a
  strict expected failure because its existing CONNECT adapter drops the final
  response after the valid control's client half-close.
- Three sequential incomplete CONNECT cancellations repeat that request-side
  EOF control after a successful live-origin CONNECT. Each cancellation records
  the raw request, independent zero-origin-accept observation and process
  descriptor-settle result for Python and native Rust; the finite run does not
  claim an RSS/HWM ceiling, concurrency limit or long-duration bound.
- Three incomplete CONNECT cancellations can also remain open concurrently
  before their client write EOFs are sent together. The paired fixture records
  the external process RSS/HWM/thread/FD peak, then requires the FD set to
  return to baseline and the live origin to accept no new connection. This is
  a finite three-session observation, not a global resource cap.
- Configured opaque CONNECT uses a positive parent route control and a refused
  parent route control. The refused parent returns 502 while an independently
  listening direct-origin canary records zero accepts; the Python comparator's
  different ordering (its own 200 precedes opening the parent, so the
  parent server-first marker cannot precede client data) remains a named strict
  expected failure.
- The combined configured-parent case sends an absolute-form HTTP request and
  an opaque CONNECT to permitted logical hosts. The parent sends its CONNECT
  response and first tunnel bytes in one write; both backends deliver those
  bytes and the later client payload. Parent HTTP and CONNECT refusals leave a
  live direct-origin canary untouched. A request addressed to the parent's
  physical IP and two requests from the denied agent create no egress. An
  allowed direct request reaches the same origin when no parent is configured.
  On parent CONNECT refusal, Rust returns 502 before tunnel admission; the
  Python comparator has already sent 200 and then closes the tunnel.
- After one parent CONNECT refusal, a later independent CONNECT recovers through
  the same configured parent while the direct-origin canary remains untouched.
  This proves per-request recovery; the single-parent setting does not claim
  same-request retry or alternate-parent selection.
- The focused same-request control records the refusal and waits for a bounded
  second-connection window. It proves the current single-parent path makes no
  same-request retry and leaves the direct-origin canary untouched. This is a
  boundary control, not a retry feature: an explicit retry/replay contract or
  alternate-parent configuration is still required before either behavior can
  be accepted.
- Fragmented TLS prefixes retain the inner request decision. Two old short-prefix
  cases remain strict expected failures.
- SSH-prefixed HTTP methods retain inner policy. HTTP whitespace variants stay
  with the HTTP parser, which rejects malformed spelling before delivery.
  The source classifier bypasses remain strict expected failures.

The HTTPS fixture creates a fresh mitmproxy CA in private fixture state. Rust
receives that combined file through `tls_ca_file`. It never replaces an existing
operator CA. The shared upstream-trust case sends `allowed.invalid:443` through
a loopback parent to independent TLS origins. The
[`test_https_trust_continuity.py`](test_https_trust_continuity.py) controls check
SNI, extra-CA success and absence, wrong-name, untrusted and future-dated
failures with live-origin and client-trust observations, then run Python, Rust
and restarted Rust against one unchanged Python-generated CA. Chain-shape and
configured passthrough fixtures remain separate.

Native transport tests separately exercise inner authority/SNI
confusion, parent CONNECT, idle TLS shutdown and active HTTPS response drain
during shutdown. Native HTTP/2 tests also verify cancellation releases a paused
upstream response and shutdown drains its remaining bytes. The paired HTTP/2
fixture uses an independent Python protocol peer. Both backends reject changed
inner `:authority` host and port before origin delivery. Rust can
negotiate HTTP/2 with the client while using HTTP/1 at the origin. With Python's
eager connection strategy, the comparator negotiates HTTP/1 on both legs for
that origin. With Python's lazy strategy, it negotiates HTTP/2 with the client
and HTTP/1 at the origin. The controlled origin records its negotiated protocol
in each case. The stream-cancellation case resets one
partial response while a sibling waits. Rust forwards the reset to the owned
origin and completes the sibling. The Python comparator does not forward that
reset in this case, so the sibling times out; the test keeps a strict expected
failure. Native opaque CONNECT now shares the
authorized egress path with HTTP/TLS. Native passthrough tests preserve the
origin's certificate and restore interception after removing an exact entry.
WebSockets and the documented passthrough matching gaps remain unfinished.
The native WebSocket module is active after an HTTP/1 upgrade, including
intercepted HTTPS. Its codec tests use a Python wsproto oracle, but codec tests
alone do not establish WS/WSS proxy acceptance. The shared
`test_websocket_contract.py` fixture exercises both real proxies through their
listeners. Its storage-transition test compares direct and proxied peer bytes
at 65,536 and 65,537 decoded bytes in both directions over WS and WSS. Plain
fragmented messages carry an interleaved Ping; compressed fragmented messages
exercise blocking and logged delivery separately because Python's D32 defect
affects compression across control frames. Native events check the storage
spill and scanner outcome. This fixture does not impose a message-size limit or
resolve the scanner's documented Python-regex compatibility gaps.
The handshake cases observe each origin socket accept and upgrade request.
They check an allowed second offered subprotocol, post-upgrade messages in both
directions, blocked and logged inspection outcomes, and a denied agent with no
additional origin contact. An unoffered origin selection returns 502 before
application messages reach the origin; a later valid selection remains usable.

The earlier focused launcher keeps lazy connection setup by default. Tunnel
fixtures explicitly select the old production eager behavior; native CONNECT
now always uses that behavior. An allowed CONNECT may open one destination
connection even when a later inner request is denied. Assertions distinguish
that authorized contact from forbidden application bytes or a substituted
destination. A denied CONNECT still opens no connection.

For the real SSH contract on a prepared Linux host, install `ssh`, `ssh-keygen`
and `sshd`, then run from the repository root:

```sh
SAFEYOLO_RUN_SSH_CONTRACT=1 uv run --frozen pytest -q \
  tests/proxy_migration/test_tunnel_contract.py \
  --proxy-backend python --proxy-backend rust
```

The test starts an owned loopback SSH daemon with fresh keys and exact host-key
verification. It transfers 1 MiB of binary input while the server first writes
512 KiB of output. Both backends run with default classification and an exact
passthrough entry. Teardown removes private keys and stops the daemon. This
opt-in test passed on Linux aarch64; it does not establish macOS guest ingress.

The old launcher uses existing `RequestIdGenerator`, `AgentAPIRequestGuard`,
`NetworkGuard`, `SSEStreaming`, `ProbeSink`, and `TransportGuard` implementations
with the existing policy decision point (PDP). It deliberately omits the normal
Agent API handler. This focused chain is derived from the existing live tests;
it does not launch all production addons.

## Capture and compare independent runs

Use new, empty evidence directories outside the checkout. The commands below
use `/tmp/safeyolo-migration` as disposable local evidence. The second capture
reuses the first run's synthetic origin ports, so comparisons retain exact
ports. The proxy implementations run sequentially.
Each capture selects the Python source/interpreter or native executable
explicitly and writes schema 2 identity/resource observations beside the raw
event and process logs. Rust captures force the native policy path; they never
include the temporary Python policy adapter.

```sh
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend python --python-source "$PWD" --python-executable "$(command -v python)" \
  --extended-workloads \
  --evidence /tmp/safeyolo-migration/old \
  --output /tmp/safeyolo-migration/old.json
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/safeyolo/rust-620-target}"
SAFEYOLO_CARGO_RESERVE_GIB=20 scripts/cargo_with_space.sh \
  build --locked --release --manifest-path proxy/Cargo.toml
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend rust --rust-binary "$CARGO_TARGET_DIR/release/safeyolo-proxy" \
  --rust-build-profile release --fixture-from /tmp/safeyolo-migration/old.json \
  --evidence /tmp/safeyolo-migration/rust \
  --output /tmp/safeyolo-migration/rust.json
uv run --frozen python -m tests.proxy_migration.run compare \
  /tmp/safeyolo-migration/old.json /tmp/safeyolo-migration/rust.json
```

The comparator exits with status 1 when captured contract values differ. The
initial Rust slice has known differences: denial responses omit NetworkGuard's
reflection fields, and the reserved probe returns 503 instead of the existing
200. These differences remain visible in the report. Passing shared assertions
does not establish complete parity.

The capture replaces generated request IDs with sequence labels only after
checking their unique client/response/event relationships. It retains denial
JSON, decisions, destinations, ports, delivered allowed bodies, and upstream
effects. Python `proxy.request` entries are fixture observations; Rust entries
are transport events. They establish the explicitly asserted fields, not full
production audit/trace equivalence. Original audit and process logs remain in
the evidence directories. `proxy.egress` observes the old pre-DNS
`server_connect` hook or Rust's sole outbound entrypoint; neither event claims
that a socket connection succeeded.

Schema 2 also records the selected source checkout commits and dirty states,
interpreter/native executable hashes, native-policy provenance, each fixture's
JSON configuration hash and command line, externally sampled RSS/high-water RSS,
virtual memory, thread and open-FD counts, and the independent origin request
observations, including origin-received WebSocket frame sizes and SHA-256
payload digests. The resource samples are observations, not a newly invented
limit: repeated controls must establish any justified regression tolerance.
The output and evidence directory are raw result locations and must be retained
with the exact candidate identity. A debug or unspecified Rust profile remains
development evidence and must not be called release measurement.
The result also carries the integrated WebSocket cancellation witness at
`48761dbc` (owner candidate `afa279b1`): four sequential incomplete-fragment
WS/WSS cancellations reclaimed anonymous spools and produced no origin frames.
It keeps RSS/allocator retention, concurrent/compressed/completed workloads and
large-pattern scans open; this focused capture does not relabel that witness as
final resource evidence.

## Workload scope and limits

By default, each capture measures 100 sequential HTTP requests with fresh
connections. `--requests` changes that count. `--extended-workloads` also
measures a paced 1.56 MiB Server-Sent Events (SSE) stream, small WebSocket (WS)
echo messages, and unavailable-local-API responses. Repeated `--workload` flags
select individual workloads instead. Run WS against Python until the Rust
slice supports that protocol. Failure in a workload remains a command failure.

On the same development machine, from the repository root with the dependencies
and release binary prepared as described earlier, use fresh evidence directories
to capture 1,000 short connections and minute-long sessions:

```sh
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/safeyolo/rust-620-target}"
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend python --python-source "$PWD" --python-executable "$(command -v python)" \
  --workload short --workload sse --workload websocket \
  --requests 1000 --stream-seconds 60 \
  --websocket-seconds 60 --websocket-interval 0.005 \
  --evidence /tmp/safeyolo-migration/sustained-python \
  --output /tmp/safeyolo-migration/sustained-python.json
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend rust --rust-binary "$CARGO_TARGET_DIR/release/safeyolo-proxy" \
  --rust-build-profile release --workload short --workload sse \
  --requests 1000 --stream-seconds 60 \
  --fixture-from /tmp/safeyolo-migration/sustained-python.json \
  --evidence /tmp/safeyolo-migration/sustained-rust \
  --output /tmp/safeyolo-migration/sustained-rust.json
```

The SSE fixture sends 49,152,000 bytes for the requested 60-second pacing
schedule; scheduling overhead can extend wall time. It records first-chunk
arrival and samples memory about once per second. The `stream-control` workload
sends one SSE event, holds the origin until the capture releases it after a
second allowed request completes, then drains the finite response. It records
origin flush, client receipt, control completion, release and origin completion
in that order. The `stream-slow-admin` workload reads the first event, then
stops reading from a small receive buffer while the origin offers more event
bytes. Before the test releases the final event, a separate allowed request
and authenticated `/stats` request must each finish within five seconds. The
client then checks the exact complete SSE body. Both workloads use the real
agent Unix socket and an independently observed origin connection. They do not
establish sustained backpressure, repeated resource bounds or throughput.
The WS fixture sends five-byte echoes for the requested duration. These
sessions do not inspect fragmentation, compression or large messages.

On Linux, reports read resident set size (RSS), process high-water memory,
virtual memory, thread count and open-FD count from `/proc` for the proxy (and
any explicitly selected child process). The native capture requires no policy
adapter. The summed RSS counts shared pages more than once; it is not a unique
physical-memory measurement. Other platforms report unavailable memory values.
Latency/throughput values are observations, without a performance target.

Neither the original two-second smoke stream nor the later single-stream
minute-long session proves bounded memory under concurrent production load.
The Rust policy adapter still requires Python and does not reproduce all
NetworkGuard approval/audit side effects.

## Full production API and approval baseline

On Linux, from the repository root with the locked Python test dependencies
installed, run the following capture. The output directory must not exist.
The fixture creates isolated config, data, logs, coordination storage and
synthetic tokens. It uses private temporary UDS paths and owned ephemeral
loopback origin, web and admin ports. It preserves the standard proxy and
certificate-authority environment and removes its private token/key files at
shutdown.

```sh
uv run --frozen python -m tests.proxy_migration.full_production \
  --output /tmp/safeyolo-migration/full-production \
  --api-requests 400 --api-workers 4 --approvals 30
```

The fixture starts `safeyolo.traffic_master` through the production command
constructor and loads all 27 configured addons. It starts a private console
and web/admin listeners. A missing fixture vault disables the service gateway
as in the corresponding production configuration. Interactive console/web
workflows and credential injection are not exercised.

The workload checks healthy authenticated APIs, missing-token 401 responses,
a durable prompt approval, an exact Alice host/port grant and subsequent
delivery to the owned origin. Bob and another destination port remain prompt.
Four API workers then execute 400 requests each while 30 network approvals
complete. An approval transaction includes a CONNECT prompt, a grant through
the isolated admin API, Alice's allowed lookup and Bob's prompt lookup.
Synthetic `.invalid` endpoints are never dialed after grant. This measures
representative grant creation and use; expiry and one-shot service grants
remain unproven.

`result.json` records actual checks, source and fixture hashes, measurements,
shutdown and known failures. `completed_with_gaps` means the workload completed
and an explicit baseline failure remains. The current old process exits zero
after SIGTERM and removes readiness, but leaves dead UDS pathnames. Connection
checks return `ECONNREFUSED`; no listener remains. The smoke suite records
`test_full_production_shutdown_removes_socket_files` as a strict expected
failure. Fixture-directory teardown removes the dead files without converting
that production cleanup assertion into a pass.

## Recorded evidence and remaining requirements

The checked-in [baseline manifest](baseline.json) records the old commit,
environment, executed tests, measured workloads, and observed migration gaps.
The original fields retain the initial 45-test live suite, six shared scenarios
and smoke captures. `followup_captures` adds full production and sustained
measurements with artifact hashes. Historical gaps in the original fields
describe that initial run; they do not erase the follow-up results.

All recorded runs used Linux aarch64. Full production and sustained Python
ran at checkout `4586a127`, with production source unchanged from `4116c7ee`.
The sustained Rust binary was the transport repair at `5b661dc9`, before the
temporary adapter concurrency repair. Dirty fixture worktrees are recorded;
the captures are not measurements of a later integrated binary.

The [inventory discrepancies](../../docs/proxy-parity.md#discrepancies-and-unproven-claims)
retain D10's framing normalization difference and D11's concurrent adapter
failure. Independent review observed 18 unexpected 502 responses in 160
requests at eight workers before D11's repair. Repair `ffb189ca` serializes
decision roundtrips across reload snapshots without retrying decisions. The
paired regression passes, and independent review verified 480 concurrent
requests plus requests queued across reload. The subsequent adapter peer-disconnect
repair also passed independent cancellation checks. The older sequential
measurements do not establish concurrent health.

The recorded workload categories now include full-production authenticated
API/approval activity and sustained focused SSE/WS sessions. Independent review
accepted M1 and the smallest M2 slice at `c2afb9cfcb42107920aeaf9d687e2da6be74dc8c`,
including artifact hashes and an independent production smoke run. This does not establish Rust
API/approval parity, full evidence parity, bounded production stream memory,
approval expiry/one-shot semantics or supported macOS guest ingress. These
remain replacement acceptance requirements in later milestones.
