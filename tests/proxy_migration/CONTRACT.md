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
- Allowed HTTP/1.1 chunked uploads reach an owned origin with complete framing
  and exact body bytes. The fixture checks a buffered request and a request
  one byte above the configured 10 MiB streaming threshold. The origin waits
  for the final zero chunk or an exact Content-Length before it sends 200.
  A direct request controls the origin. This checks transport completion and
  hop-header removal; it does not establish body inspection or capture beyond
  the configured streaming window.
- Persistent HTTP/1.1 requests on two trusted UDS connections, with repeated
  allowed/denied decisions, independent origin request targets, and stable
  per-agent connection identities across reuse.
- No pre-DNS outbound attempt or synthetic upstream connection after denial.
- Direct origin-form forwarding and absolute-form forwarding through an
  explicitly configured parent, preserving repeated/encoded query parameters.
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
  CONNECT creates no origin application request in this fixture. Both backends
  record CONNECT in the security audit; Rust also emits `proxy.request` rows.
- Concurrent HTTP/2 streams from two agents, independent request identities,
  exact encoded queries, protocol negotiation and rejected inner authorities.
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
operator CA. Native transport tests separately exercise inner authority/SNI
confusion, parent CONNECT, idle TLS shutdown and active HTTPS response drain
during shutdown. Native HTTP/2 tests also verify cancellation releases a paused
upstream response and shutdown drains its remaining bytes. The paired HTTP/2
fixture uses an independent Python protocol peer. Two strict expected failures
retain the old inner-authority bypass; Rust rejects both cases. Rust can
negotiate HTTP/2 with the client while using HTTP/1 at the origin, where the old
proxy negotiates HTTP/1 on both sides. Native opaque CONNECT now shares the
authorized egress path with HTTP/TLS. Native passthrough tests preserve the
origin's certificate and restore interception after removing an exact entry.
WebSockets and the documented passthrough matching gaps remain unfinished.

The separate native WebSocket module has codec and handshake tests, including
an actual Python wsproto oracle, complete-message scanner calls, compression
context after message drops, UTF-8 fragments and private spooling. It remains
inactive in the HTTP transport. The scanner's documented Python-regex gaps
also block activation; passing codec tests are not WS/WSS proxy acceptance.

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
the release ordering and control latency; it does not exercise a slow consumer
or an authenticated admin operation. The WS fixture sends
five-byte echoes for the requested duration. These sessions do not inspect
fragmentation, compression, large messages, cancellation or slow readers.

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
