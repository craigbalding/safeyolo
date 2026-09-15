# Proxy migration contracts

These fixtures exercise the first HTTP slice of issue #620. Each run starts
one selected proxy process, two per-agent Unix domain sockets (UDS), and local
synthetic upstreams. Requests never target an external origin or the running
SafeYolo instance.

## Run the contracts

From the repository root on Linux or macOS, install the locked Python test
dependencies with `uv sync --frozen --group dev`. Build the Rust binary with
`cargo build --manifest-path proxy/Cargo.toml`. The following command starts
and stops isolated Python and Rust fixtures:

```sh
uv run --frozen pytest -q tests/proxy_migration \
  --proxy-backend python --proxy-backend rust
```

The Python backend is the default. Set `SAFEYOLO_RUST_PROXY` to select a built
binary at another path. A missing requested binary is an error. The fixture
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

Every capture measures 100 sequential HTTP requests with fresh connections.
`--requests` changes that count. `--extended-workloads` also measures a paced
1.56 MiB event stream, small WebSocket echo messages, and unavailable-local-API
responses. Run extended workloads against Python until the Rust slice supports
WebSockets. Failure in a workload remains a command failure.

On Linux, reports read resident memory (RSS) and process high-water memory from
`/proc`. Measurements include the temporary policy adapter as a separate role
when present. The summed RSS counts shared pages more than once; it is not a
unique physical-memory measurement. Other platforms report unavailable memory
values. Latency/throughput values are observations, without a performance target.

The two-second stream and five-byte WebSocket workload are smoke measurements.
They do not prove bounded memory over long durations or inspect fragmentation,
compression, large messages, or cancellation. Normal authenticated APIs,
approval creation/consumption, concurrent API responsiveness, and real macOS
guest ingress remain unmeasured here. The Rust policy adapter still requires
Python and does not reproduce all NetworkGuard approval/audit side effects.

The checked-in [baseline manifest](baseline.json) records the old commit,
environment, executed tests, measured workloads, and observed migration gaps.
