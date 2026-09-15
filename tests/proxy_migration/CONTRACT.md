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
- No pre-DNS outbound attempt or synthetic upstream connection after denial.
- Direct origin-form forwarding and absolute-form forwarding through an
  explicitly configured parent, preserving repeated/encoded query parameters.
- Local containment of unavailable Agent API handlers and the reserved probe,
  including mixed-case Agent API hostnames and synthetic bearer credentials.
- Readiness and graceful process shutdown.
- HTTPS through the real policy engine with verified client and origin TLS,
  including a configured private trust root, wrong-host and untrusted-origin
  failures, denied CONNECT, and exact repeated/encoded query bytes.
- Authority-form CONNECT metadata with no HTTP path or scheme, including
  opposing path-conditioned allow and deny rules.

The HTTPS fixture creates a fresh mitmproxy CA in private fixture state. Rust
receives that combined file through `tls_ca_file`. It never replaces an existing
operator CA. Native transport tests separately exercise inner authority/SNI
confusion, parent CONNECT, idle TLS shutdown and active HTTPS response drain
during shutdown. HTTP/2, opaque CONNECT, TLS
passthrough and WebSockets remain outside this development HTTPS path.

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

```sh
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend python --extended-workloads \
  --evidence /tmp/safeyolo-migration/old \
  --output /tmp/safeyolo-migration/old.json
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend rust --fixture-from /tmp/safeyolo-migration/old.json \
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

## Workload scope and limits

By default, each capture measures 100 sequential HTTP requests with fresh
connections. `--requests` changes that count. `--extended-workloads` also
measures a paced 1.56 MiB Server-Sent Events (SSE) stream, small WebSocket (WS)
echo messages, and unavailable-local-API responses. Repeated `--workload` flags
select individual workloads instead. Run WS against Python until the Rust
slice supports that protocol. Failure in a workload remains a command failure.

On the same development machine, from the repository root with the dependencies
and binary prepared as described earlier, use fresh evidence directories to
capture 1,000 short connections and minute-long sessions:

```sh
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend python --workload short --workload sse --workload websocket \
  --requests 1000 --stream-seconds 60 \
  --websocket-seconds 60 --websocket-interval 0.005 \
  --evidence /tmp/safeyolo-migration/sustained-python \
  --output /tmp/safeyolo-migration/sustained-python.json
uv run --frozen python -m tests.proxy_migration.run capture \
  --backend rust --workload short --workload sse \
  --requests 1000 --stream-seconds 60 \
  --fixture-from /tmp/safeyolo-migration/sustained-python.json \
  --evidence /tmp/safeyolo-migration/sustained-rust \
  --output /tmp/safeyolo-migration/sustained-rust.json
```

The SSE fixture sends 49,152,000 bytes for the requested 60-second pacing
schedule; scheduling overhead can extend wall time. It records first-chunk
arrival and samples memory about once per second. The WS fixture sends
five-byte echoes for the requested duration. These sessions do not inspect
fragmentation, compression, large messages, cancellation or slow readers.

On Linux, reports read resident set size (RSS) and process high-water memory from
`/proc`. Measurements include the temporary policy adapter as a separate role
when present. The summed RSS counts shared pages more than once; it is not a
unique physical-memory measurement. Other platforms report unavailable memory
values. Latency/throughput values are observations, without a performance target.

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
