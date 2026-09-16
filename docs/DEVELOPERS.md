# SafeYolo Developer Guide

This guide is for developers who want to contribute to SafeYolo, build integrations, or extend it with custom addons.

Before changing agent attribution or sandbox lifecycle, read the
[agent identity and run-lifecycle implementation plan](agent-lifecycle-identity-plan.md).
It separates operator-facing names from durable agent identity, records the
current restart behavior, and defines the proposed minimal runtime incarnation.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     HOST (trusted)                            │
│                                                              │
│  ┌──────────────┐        ┌──────────────────────────────┐   │
│  │ safeyolo CLI │───────▶│ mitmproxy (host process)     │   │
│  │  (Typer)     │  admin │   + addons (credential-guard,│   │
│  │  init/start/ │  :9090 │     policy_engine, agent_api,│   │
│  │  watch/logs  │◀───────│     network_guard, ...)      │   │
│  └──────┬───────┘  JSONL └──────────────┬───────────────┘   │
│         │                               │ per-agent UDS      │
│         ▼                               ▼                    │
│  ┌───────────────┐          ┌───────────────────────────┐   │
│  │ ~/.safeyolo/  │          │ Agent sandbox VMs         │   │
│  │  config.yaml  │          │  macOS: Virtualization.fw │   │
│  │  policy.toml  │          │  Linux: rootless gVisor   │   │
│  │  addons.yaml  │          │  (no external network —   │   │
│  │  logs/        │          │   UDS is the only egress) │   │
│  └───────────────┘          └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key design principles:**
- Addons are sensors: detect credentials/patterns, build HttpEvents, call PolicyClient
- PDP package (~2500 lines) handles policy evaluation (can run in-process or as service)
- Detection module (~350 lines) is pure Python for easy testing/fuzzing
- CLI handles user interaction, approval workflow, notifications
- Communication via Admin API (HTTP) and JSONL logs (file)
- Policy files are the source of truth for approvals

## Repository Structure

```
safeyolo/
├── addons/                   # mitmproxy addons (sensors, run in host proxy)
│   ├── detection/            # Pure detection logic (no mitmproxy deps)
│   │   ├── patterns.py       # PatternRule, compile_rules, scan_text
│   │   ├── credentials.py    # CredentialRule, analyze_headers, entropy
│   │   └── matching.py       # Host/resource matching, HMAC fingerprinting
│   ├── admin_api.py          # REST API for runtime control
│   ├── admin_shield.py       # Protects admin API endpoints
│   ├── agent_api.py          # Read-only PDP agent API for agent self-service
│   ├── base.py               # Base addon class with shared functionality
│   ├── budget_tracker.py     # GCRA-based rate limiting
│   ├── circuit_breaker.py    # Fail-fast for unhealthy upstreams
│   ├── credential_guard.py   # Core credential detection and protection
│   ├── file_logging.py       # Structured JSONL file logging setup
│   ├── flow_pruner.py        # TUI-only: prune old flows for memory
│   ├── loop_guard.py         # Proxy loop detection (Via header)
│   ├── memory_monitor.py     # Process memory + connection tracking
│   ├── metrics.py            # Statistics collection
│   ├── network_guard.py      # Network-level security policies
│   ├── pattern_scanner.py    # Regex pattern matching for secrets
│   ├── policy_engine.py      # PolicyEngineAddon, mitmproxy integration
│   ├── policy_loader.py      # Policy file loading and caching
│   ├── request_id.py         # Request ID generation
│   ├── request_logger.py     # JSONL audit logging
│   ├── sensor_utils.py       # HttpEvent builders for sensors
│   ├── service_discovery.py  # Client IP to project mapping
│   ├── sse_streaming.py      # Server-sent events handling
│   ├── test_context.py       # X-SafeYolo-Test-Context header enforcement
│   └── utils.py              # Shared utilities (logging, blocking)
├── pdp/                      # Policy Decision Point (library + service)
│   ├── schemas.py            # HttpEvent, PolicyDecision, Effect enums
│   ├── core.py               # PDPCore - policy evaluation engine
│   ├── client.py             # PolicyClient interface (local/HTTP modes, incl. admin)
│   ├── tokens.py             # HMAC-signed readonly tokens for agent API
│   └── app.py                # FastAPI service (optional deployment)
├── cli/                      # safeyolo CLI (runs on host)
│   ├── src/safeyolo/
│   │   ├── cli.py            # Typer app entry point
│   │   ├── config.py         # Configuration loading
│   │   ├── api.py            # Admin API client
│   │   ├── proxy.py          # Host mitmproxy lifecycle
│   │   ├── vm.py             # Sandbox VM lifecycle (macOS / Linux)
│   │   └── commands/         # CLI command modules
│   │       ├── admin.py      # check, mode, policies
│   │       ├── agent.py      # agent subcommands
│   │       ├── cert.py       # certificate management
│   │       ├── doctor.py     # 11-check diagnostic cascade
│   │       ├── init.py       # init command
│   │       ├── lifecycle.py  # start, stop, status
│   │       ├── logs.py       # log viewing
│   │       ├── sandbox.py    # sandbox subcommands
│   │       ├── setup.py      # setup subcommands
│   │       ├── token.py      # token create/list/revoke
│   │       └── watch.py      # real-time log watching
│   └── pyproject.toml
├── fuzz/                     # Atheris fuzz targets (ClusterFuzzLite)
├── contrib/                  # Example integrations
├── config/                   # Default configurations
├── tests/                    # Test suite (unit + integration)
└── docs/                     # Documentation
```

## Coord trust boundary

Envelope attribution is authoritative; message bodies are untrusted data, and
any SafeYolo-owned UI that presents provenance must keep the two separate when
rendering. Both spoofing bugs found in the Stage-1 dogfood were in the display
layer with a correct envelope. See [coord-trust-boundary.md](coord-trust-boundary.md)
for the contract and the per-sink obligations (terminal, web, log export).

## Building Integrations

### Option 1: Consume JSONL Events

The simplest integration is tailing the JSONL log file. Every security decision is logged with structured data.

**Event format:**
```json
{
  "timestamp": "2024-01-15T14:32:15.123Z",
  "event": "security.credential",
  "request_id": "req-abc123",
  "data": {
    "addon": "credential-guard",
    "decision": "block",
    "rule": "openai",
    "host": "api.example.com",
    "fingerprint": "hmac:a1b2c3d4e5f6",
    "reason": "destination_mismatch",
    "expected_hosts": ["api.openai.com"],
    "confidence": "high",
    "project_id": "default"
  }
}
```

**Event types:**
| Event | Description |
|-------|-------------|
| `security.credential` | Credential detected, decision made |
| `security.ratelimit` | Rate limit hit |
| `security.circuit` | Circuit breaker state change |
| `traffic.request` | Request logged |
| `traffic.response` | Response logged |
| `gateway.allow` | Service gateway allowed a request (capability match) |
| `gateway.deny` | Service gateway denied a request (no matching capability) |
| `gateway.risky_route` | Request matched a risky route, PDP evaluated |
| `gateway.grant_added` | Operator approved a grant for a risky route |
| `gateway.grant_consumed` | Once-grant consumed after successful (2xx) response |
| `gateway.grant_expired` | Grant expired (TTL exceeded) |
| `gateway.grant_revoked` | Grant revoked by operator |
| `admin.policy_write` | Policy file updated |
| `admin.approval_added` | Approval rule added |
| `admin.mode_change` | Addon mode changed |

**Python example:**
```python
import json
import os
import time
from pathlib import Path


def tail_events(log_path: Path):
    """Tail JSONL log for events."""
    with open(log_path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)

logs_dir = os.environ.get("SAFEYOLO_LOGS_DIR")
if not logs_dir:
    state_home = Path(
        os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")
    )
    logs_dir = state_home / "safeyolo"
log_path = Path(logs_dir) / "safeyolo.jsonl"

# React to blocked credentials
for event in tail_events(log_path):
    if event.get("event") == "security.credential":
        data = event.get("data", {})
        if data.get("decision") == "block":
            # Send notification, update dashboard, etc.
            print(f"Blocked: {data.get('fingerprint')} -> {data.get('host')}")
```

### Option 2: Use the Admin API

The Admin API provides runtime control and status.

**Base URL:** `http://localhost:9090`

**Authentication:** Bearer token
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/stats
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth required) |
| GET | `/stats` | Aggregated addon stats |
| GET | `/modes` | Current addon modes |
| PUT | `/modes` | Set all addon modes |
| GET | `/plugins/{addon}/mode` | Get specific addon mode |
| PUT | `/plugins/{addon}/mode` | Set specific addon mode |
| GET | `/admin/policy/baseline` | Get baseline policy |
| PUT | `/admin/policy/baseline` | Update baseline policy (see note below) |
| POST | `/admin/policy/baseline/approve` | Add credential approval |
| GET | `/admin/policy/task/{task_id}` | Get task-specific policy |
| PUT | `/admin/policy/task/{task_id}` | Create/update task policy |
| GET | `/admin/budgets` | Get budget usage stats |
| POST | `/admin/budgets/reset` | Reset budget counters |
| POST | `/admin/policy/validate` | Validate YAML policy content |

> **Note on `PUT /admin/policy/baseline`:** Full baseline replacement is intended
> for machine-to-machine automation. This operation may not preserve comments,
> layout, or human-authored formatting in the policy file. Operators who use inline
> comments as guidance should prefer incremental local updates or regenerate from
> a canonical source.

**Add an approval via API:**
```bash
curl -X POST "http://localhost:9090/admin/policy/baseline/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "api.openai.com",
    "credential": "sk-proj-abc123",
    "tier": "explicit"
  }'
```

**Python client:**
```python
from safeyolo.api import AdminAPI

api = AdminAPI(base_url="http://localhost:9090", token="...")

# Get stats
stats = api.stats()
print(stats["credential-guard"]["violations_total"])

# Get current modes
modes = api.get_modes()
print(modes)

# Change mode
api.set_mode("credential-guard", "warn")
```

### Option 3: Write a Custom Addon

Create a new mitmproxy addon for custom logic.

**Basic addon structure:**
```python
# addons/my_addon.py
from mitmproxy import ctx, http

try:
    from .utils import write_event
except ImportError:
    from utils import write_event

class MyAddon:
    name = "my-addon"

    def load(self, loader):
        """Register options."""
        loader.add_option(
            name="myaddon_enabled",
            typespec=bool,
            default=True,
            help="Enable my addon",
        )

    def request(self, flow: http.HTTPFlow):
        """Called for each request."""
        if not ctx.options.myaddon_enabled:
            return

        # Your logic here
        host = flow.request.host

        if self.should_block(flow):
            flow.response = http.Response.make(
                403,
                b'{"error": "Blocked by my-addon"}',
                {"Content-Type": "application/json", "X-Blocked-By": self.name}
            )
            flow.metadata["blocked_by"] = self.name

            # Log the event
            write_event("security.custom",
                addon=self.name,
                decision="block",
                host=host,
                request_id=flow.metadata.get("request_id")
            )

    def should_block(self, flow: http.HTTPFlow) -> bool:
        # Your detection logic
        return False

    def get_stats(self) -> dict:
        """Return stats for admin API."""
        return {"blocks": 0}

# TrafficMaster registers this list directly
addons = [MyAddon()]
```

**Add to startup:**
```python
# In cli/src/safeyolo/mitm_addons/__init__.py, add the filename to
# ADDON_CHAIN at the required security hook position:
"my_addon.py",
```

Production addons are package imports, not mitmproxy `-s` scripts. The traffic
process loads each addon and its imported `safeyolo.*` dependencies once; source
edits take effect together on the next proxy restart rather than through an
implicit partial hot reload.

**Key patterns:**
- Use `flow.metadata["blocked_by"]` when blocking (logger picks it up)
- Use `write_event()` for structured logging
- Implement `get_stats()` for admin API integration
- Check `flow.metadata.get("policy")` for per-domain config

## Development Setup

For host installation and retrying an individual bootstrap phase, use the
[installation reference](../cli/README.md#installation).

**Running the default Python backend with live source editing:**
```bash
# `--dev` runs the proxy from your local checkout so edits to addons/pdp
# source pick up on the next start (no container image, no rebuild step).
safeyolo start --dev

# Edit mitm_addons/*.py, safeyolo/*.py, or pdp/*.py, then restart the traffic
# process to pick up one consistent code generation:
safeyolo stop && safeyolo start --dev
```

### Rust proxy development backend

The CLI defaults to `proxy.backend: python`. Rust selection is an explicit
development setting, not a completed migration or production cutover. HTTP
credential inspection and injection, WebMITM, and complete agent management
remain incomplete. Native listeners include the supplied JSON entries and
the CLI's agent-map sockets. See [proxy parity](proxy-parity.md) for current scope.

Run the following on the host from the checkout root, with the Rust toolchain,
tmux, and an initialized CLI configuration. Stop the current backend before
changing selection. These commands change the currently selected CLI instance
and stop its proxy. This example copies the default policy into development
state because native loads can remove expired TOML entries from disk. If your
policy is elsewhere, use that path as the copy source.

```sh
safeyolo stop
cargo build --manifest-path proxy/Cargo.toml
export SAFEYOLO_RUST_PROXY="$PWD/proxy/target/debug/safeyolo-proxy"
mkdir -p .native-dev
cp ~/.safeyolo/policy.toml .native-dev/policy.toml
```

Create `.native-dev/proxy.json` with a listener identity and paths for this
development instance. This example supplies a local Unix socket; it does not
provision or attach a sandbox:

```json
{
  "listeners": [{"agent_id": "development", "socket_path": ".native-dev/agent.sock"}],
  "policy_file": ".native-dev/policy.toml",
  "readiness_file": ".native-dev/ready.json",
  "event_log": ".native-dev/diagnostics.jsonl",
  "audit_log_path": ".native-dev/audit.jsonl",
  "flow_store_db_path": ".native-dev/flows.sqlite3"
}
```

The [native configuration](../proxy/src/config.rs) defines additional fields,
including TLS and an optional authenticated operator listener. Relative paths
inside the JSON resolve from the directory where the CLI is launched. Keep that
working directory consistent across starts; JSON paths do not expand `~`.

In your existing CLI `config.yaml` (normally `~/.safeyolo/config.yaml`), set these
fields under `proxy`, retaining other configuration. Set `rust_config` to the
absolute path of the JSON you created:

```yaml
proxy:
  backend: rust
  rust_config: /absolute/path/to/checkout/.native-dev/proxy.json
```

The export selects this build for the current shell, including an installed CLI.
Without it, a CLI running from the checkout uses
`proxy/target/debug/safeyolo-proxy`. Missing binaries or invalid configuration
fail without falling back to Python. Selection persists for subsequent starts,
including automatic starts. Rust rejects `--dev`, `--test`, `--flow-cache` and
`--flow-cache-bytes`; set native values in its JSON instead. It does not change
the Python `test.enabled` setting.

```sh
safeyolo start
```

The success panel identifies the Rust development backend and its listener
configuration. Startup requires native readiness. The default `--wait` also
checks the running native operator endpoint when configured; otherwise it uses
readiness. This establishes process availability, not full policy parity or a
working sandbox. `--no-wait` skips that extra health check, not startup readiness.

`safeyolo status` reports the running Rust process's PID, readiness file and
native admin port, even if `proxy.backend` has since changed. A live process
without its readiness marker is shown as running but not ready. Status does not
query the Python management APIs for a Rust process.

The shared CLI admin client uses the running Rust process record's admin port
and token file, including an automatically assigned port. An explicit client
URL keeps its existing behavior. For the default Rust target, token precedence
is an explicit client token, `SAFEYOLO_ADMIN_TOKEN`, then the recorded token file.
Long-lived clients can follow a verified Rust restart and refresh the port and
default token. Once a client selects Rust, missing or stale process ownership
prevents the request; it does not select a Python endpoint. Established admin
listeners remain usable for
diagnostics while the process is alive even if its readiness marker is absent.
The native listener loads its token at startup, so token-file changes require
a proxy restart. This client integration reaches the native APIs already
implemented, including budget and circuit resets used by `safeyolo watch`.
Agent service authorization remains an unimplemented native route.

For a running Rust development proxy with its admin listener enabled, run
`safeyolo traffic` on the host to open the terminal inspector. The inspector
reads the proxy's shared live HTTP and WebSocket view. It includes ordinary
requests without TestContext, pending requests, and terminal responses or errors.
The existing scope options, such as `--agent alice --test CASE-1`, update the
shared view before attaching. `--no-attach` changes only the scope.
Scope and user-filter changes affect all inspectors and do not change forwarding
policy.
Detaching leaves the proxy and its retained view running.
Use Up/Down to select a flow, Tab to change panes, and Page Up/Page Down to
scroll. `r` and `s` fetch request and response body snapshots. `a` and `t`
change the shared agent and test scope; `c` clears only that scope. `f` edits
the shared user filter. Enter applies the expression, Escape cancels, and an
empty expression clears only the user filter. `q` detaches.
For an upgraded WebSocket, `w` opens its retained message transcript and returns
to HTTP. Up/Down selects a message; `[` and `]` navigate its 64 KiB body pages.
Every retained byte is reachable through these pages. The inspector fetches a
page when selected or requested, rather than fetching the payload on every poll.
Message rows show direction, type, size, time and the reached inspection drop
decision. That decision does not establish delivery to the peer.

To export a selected flow, press `x`, enter `raw`, `raw_request`, `raw_response`,
`curl`, `httpie`, `har` or `zhar`, then enter a local file path. Escape cancels either prompt.
The selection is fixed when the format prompt opens. Export also works while
viewing that flow's WebSocket transcript. The destination belongs to the host
running the inspector; the proxy receives only the flow ID and format.
The inspector saves the completed download before replacing the destination.
A failed or canceled download leaves an existing destination unchanged.
Replacement preserves an existing destination's permissions and follows a final
symbolic link to its target. It creates a new file inode, so other hard links
to the previous file keep their previous content.

Raw export reconstructs HTTP messages from retained observations and available
body content. It does not reproduce original wire bytes. Combined `raw` output can
append retained WebSocket payloads with direction prefixes, including dropped
messages. That format does not record message type or drop status. Use the
inspector for those facts. `curl` and `httpie` produce command text; export does
not execute it. If a format requires unavailable content or protocol facts,
the export reports a failure.
HAR writes a JSON archive for the selected flow. ZHAR compresses that archive
with zlib. The selected format determines the output; the file suffix does not.
The shared text decoder supports the codec families listed under
[selected-flow file export](proxy-parity.md#selected-flow-file-export).
Registered codecs without a native implementation report an unsupported
representation. Unknown charset labels follow the selected format's decoding
error behavior. Broader codec compatibility remains migration work.
HTTP decoding and command formatting materialize complete decoded HTTP bodies
in memory. WebSocket export reads retained payloads in bounded chunks.

For example, enter `~m GET`, `~u example.com`, or `~b base_instruction` in the
filter prompt. Combine predicates with explicit `&`, `|`, `!` and parentheses,
such as `~m POST & ~b base_instruction`. A bare regular expression searches the
URL. The filter combines with the pinned scope; changing either preserves the
other. Invalid expressions and unsupported predicates leave the previous filter
active. If an accepted filter fails during evaluation, the inspector reports
the failure and retains its previous rows. Use `f` to edit or clear the active
expression and recover.

The shared editor preserves the source parser's spacing rules. For a standalone
predicate without an operand, use a spaced group such as `(~q )` for flows
without a response or `(~websocket )` for WebSockets. The source wrapper rejects
bare `~q` and `~websocket`. An explicit combination such as `~q & ~m GET` works.

The native filter supports URL, method, status, request/response presence,
headers, content type, assets, metadata, HTTP/WebSocket body, HTTP/WebSocket type,
`~all` and error predicates. Body searches use complete retained HTTP content
after decoding and each retained WebSocket message separately, including dropped
messages. Searches are independent of terminal preview and page sizes. Body
predicates search only retained bytes. Header and body expressions search bytes;
URL and metadata expressions search text. Matching ignores case unless
`MITMPROXY_CASE_SENSITIVE_FILTERS=1` when the view is created; the asset predicate
keeps its source case-sensitive behavior.

Domain, peer-address, replay, mark, comment and non-HTTP protocol predicates
remain unimplemented. The private filter API reports unsupported predicates or
known regex incompatibilities with HTTP 501. Invalid expressions return 400;
evaluation failures return 500. Compilation and evaluation errors contain a
category, without the expression or captured content. Native regex matching
has finite Python compatibility. Unavailable byte-pattern cases include
case-insensitive backreferences and advanced patterns containing non-ASCII byte
literals. This interface does not establish complete mitmproxy filter parity.

The live view is separate from the durable TestContext evidence store.
Native JSON settings `flow_pruner_max` (default 5000 flows) and
`flow_pruner_max_body_bytes` (default 1 GiB) set positive retention targets.
The proxy evicts the oldest finished flows across all scopes. Open WebSockets
and active HTTP exchanges remain retained even above these targets. If retained
bodies still exceed the byte target, the proxy removes older nonempty messages
from open WebSockets in global timestamp order. It preserves each session's
latest message, even when that message alone exceeds the target. The inspector
shows how many messages have been trimmed from each session. Closed sessions
keep their remaining transcript until the whole flow is evicted. These targets
do not limit forwarded message size. Large messages share the relay's anonymous
file storage; inspecting a page does not load the whole message into memory.
Accepted reloads keep the view, scope and user filter, and apply updated targets.
Failed reloads leave the targets unchanged. Native pruning occurs on observation,
exchange release or settings changes. Python uses its hook and interval schedule.

For HTTP, the inspector shows retained encoded body bytes, including a distinct
empty body. Streamed bodies, unavailable local response bodies, and bodies whose
capture failed are labelled unavailable. The view does not drain a stream to
make a body inspectable. A completed row and its end time describe the observed
response; a slower request body can remain pending until its parser completes.

HTTP flow JSON includes `request_completed`, `response_head_observed` and
`response_completed` as Unix timestamps in seconds. Each field stays `null`
until its boundary is observed. Later response metadata updates preserve the
first observed response-head time. A successful response transport can have a
completion timestamp even when its body is unavailable for inspection. The
exchange's `ended` field does not supply missing phase timestamps.

The optional `upstream` record identifies the opened upstream connection
separately from the ingress connection. It retains the direct peer's IP address
and port and the observed connection phases. Parent routes leave the origin
peer and TCP phases unavailable; parent connection facts do not stand in for
origin facts. Target TLS completion is retained only after its handshake succeeds.

WebSocket transcripts retain complete decompressed and unmasked text or binary
messages, including messages dropped by inspection. Ping, pong and close frames
are not transcript messages. The flow remains open until the session ends.
The inspector shows the session end time, direction, code and reason when
available. A code can describe a peer close or the native relay's local close
decision. Native transport failures have categorical errors; they do not invent
a peer reason. Cancellation marks the session incomplete. A message page can
report a storage error independently of forwarding. Terminal control bytes in
payloads and close reasons are escaped for display.
If native validation rejects an upstream 101 upgrade response, the HTTP view
keeps that observed response and shows the rejection error. No WebSocket
session is created for that response.

Remaining filter compatibility, flow editing, replay, interception, all-flow
HAR archives and lifecycle behavior, flow-dump export, import and a web inspector
remain migration work.

The native view excludes CONNECT, reserved internal hosts, and requests whose
destination cannot be parsed. URLs use the admitted scheme and authority with
the original path and query; headers retain the observed Host field. This is
not the Python view's `pretty_url` projection. Native scope matching uses
case-insensitive literal metadata text with multiline anchors. The Python
filter lexer can change escaped punctuation and reject newlines; its optional
case-sensitive mode and Unicode regex folding also differ. Native scope
updates validate before publication. Python can publish scope fields before
its generated filter fails. Native pins also remain a separate AND condition
when a user expression closes the source's generated parentheses early. The
Python expression can widen the pinned selection in that case. These are
display-selection differences; scope is not an authorization boundary.

Request headers reflect the last reached hygiene/context stage; an earlier
local reply can retain the ingress headers. Upstream response headers come
from the parser before downstream header rewriting. Known local replies show
their returned headers. The inspector preserves repeated fields and available
original order, but does not claim the Python view's final mutable header state.
Trailer capture uses normalized header pairs. Original trailer field casing
and interleaving of different fields are unavailable.

At startup and after agent-map changes, the CLI derives managed listener paths
with the existing `<ip>_<agent>/proxy.sock` convention under its data directory.
It preserves custom JSON listeners outside that convention. A missing map leaves
explicit listeners in place; a valid empty map removes managed listeners. An
unreadable or malformed map cannot become an empty replacement.

For a running Rust process, listener synchronization updates the JSON recorded
at launch, preserving other fields and file permissions, then sends SIGHUP.
Native SIGHUP reloads the full configuration, including policy and catalog
inputs. It is not a listener-only operation. The CLI confirms success only
after the same process publishes the requested `reload_id`. A timeout means
the result is unconfirmed; the requested JSON remains for the next reload or
start. It does not imply that the live configuration was rolled back. Processes
launched before configuration-path recording need one restart to use live sync.

To return to Python, run `safeyolo stop`, change `proxy.backend` to `python` in
`config.yaml`, then run `safeyolo start`. A requested/live backend mismatch is an
error; changing the setting does not replace a running backend. The development
files remain available for inspection after rollback. Native stop waits for the
process to exit. An interrupted stop retains its process ownership state so that
the stop can be retried. The exited console remains in the private tmux session
for diagnostics; the next start reaps that dead pane.

### Runtime and build identity

The Python traffic process captures one immutable runtime-identity snapshot at
startup. Operators can inspect it with `safeyolo doctor`; the underlying
authenticated host-admin route is `GET /admin/runtime-identity`. It is not
exposed through the sandbox Agent API, and the public `/health` response
remains only `{"status": "ok"}`.

The Rust lifecycle receipt records process ownership and readiness. Rust does
not yet implement this build-identity endpoint or the corresponding doctor check.

Production wheels include `safeyolo/_build_identity.json`, generated by the
Hatch wheel-build hook rather than at runtime. Release automation should set
`SAFEYOLO_BUILD_REVISION` to the immutable source revision and may set
`SAFEYOLO_BUILD_ID` to a CI or release identifier before running `uv build
--wheel`. A local wheel build falls back to a clean build checkout's Git
revision; a dirty checkout or missing Git evidence produces an explicit
`unknown` stamp. The checkout's resolved Git top-level must also be the build
project root, so a source archive nested under an unrelated repository cannot
inherit that repository's revision.
An installed production runtime only reads this package resource: it does not
invoke Git or scan a checkout.

An explicit `safeyolo start --dev` also records the selected `safeyolo` and
`pdp` package roots, their Git revision and relevant working-tree state, and a
deterministic SHA-256 fingerprint. The fingerprint hashes sorted, root-relative
file names plus contents for Python, YAML, TOML, Jinja, and `py.typed` files.
It excludes documentation, shell helpers, VCS data, virtual environments,
build output, caches, and dependency trees; roots are limited to the selected
code packages, so operator configuration, user data, logs, and secrets are
never scanned.
Symlinked, missing, or unreadable source produces explicit `unknown` evidence.
The traffic Python process runs in safe-path/no-user-site mode, ensuring its
imports come from those selected roots rather than a package in the launch
directory or a user-site shadow.

On a later `safeyolo doctor` run, production mode reports only the immutable
wheel stamp. Dev mode recomputes the recorded roots and distinguishes a clean
match, an unchanged dirty generation, dirty same-commit drift, committed
revision drift, and missing or unreadable evidence. Drift means the running
traffic generation is still the startup snapshot; converge with:

```bash
safeyolo stop && safeyolo start --dev
```

The snapshot includes the traffic PID, capture time, and an OS process-start
token. Doctor compares all three against the live proxy so a stale pidfile,
mid-check restart, or reused PID cannot be reported as the running generation.

Guest VM artifacts (kernel, initramfs, rootfs) are rebuilt separately via
`safeyolo build` — see the top-level README for the full guest-build flow.

**Install dev dependencies and pre-commit hooks:**
```bash
# Install dev dependencies (using uv)
uv sync --group dev

# Install fast commit hooks and the deeper CodeQL pre-push hook
uv run pre-commit install --hook-type pre-commit --hook-type pre-push

# Run the fast hooks manually on all files
uv run pre-commit run --all-files

# Run the Python security-and-quality CodeQL suite used in CI when available
uv run python scripts/check_codeql.py
```

Lens's broader, operator-bound analysis toolbox is a separate locked tool
project:

```bash
uv sync --project tools/acceptance --frozen --only-group static
```

This creates an isolated tool environment and does not change the product
runtime lock. The acceptance graph selects bounded uses of mypy, Semgrep,
pip-audit, Radon, pytest-xdist, and pytest-repeat; its stress-test invocation
layers the small hash-locked pytest plugin set over the exact root project
environment. These tools contribute different evidence, and their findings are
not automatic merge vetoes. In particular, compare static and complexity
findings with the trusted base, and treat parallel or repeated tests as stress
signals rather than proof that a race cannot exist. See `accept-safeyolo.yaml`
in the bundled SafeYolo skill graphs for the trusted sources, invocations, and
evidence to retain.

The commit hooks mirror CI's fast static checks:
- **ruff** - linting and import sorting
- **py_compile** - Python syntax validation
- **blackbox schema/docs** - validate test documentation and generated coverage
- **check-yaml/json/toml** - config file validation
- **detect-private-key** - prevent accidental key commits

The pre-push hook additionally runs the same CodeQL Python
`security-and-quality` suite as `.github/workflows/codeql.yml` on supported
local platforms. Its first run downloads the checksum-pinned official stable
bundle used by the workflow action (about 600–850 MB on Linux, depending on
whether `zstd` is available) and caches it under
`~/.cache/safeyolo/codeql`. Set `SAFEYOLO_CODEQL_CACHE` to relocate the cache
or `SAFEYOLO_CODEQL_BIN` to use an already-installed matching CLI. An explicit
binary is validated and used on every architecture; an invalid path is a
pre-push failure. Temporary databases and SARIF files are deleted after each
analysis.

GitHub does not yet publish a pinned official stable native CodeQL bundle for
Linux ARM64 ([upstream tracking PR](https://github.com/github/codeql-action/pull/4072)).
On `aarch64` and `arm64`, the default pre-push hook therefore reports that
local CodeQL is unavailable and skipped, and exits successfully without a
download or analysis. GitHub CI CodeQL remains the required analysis gate; the
skip message does not mean that the commit was analyzed locally. Set
`SAFEYOLO_CODEQL_BIN` to an executable matching CLI to opt into real local
analysis on Linux ARM64. `--install-only` fails if neither that override nor a
supported pinned bundle is available, while `--verify-version` and
`--update-bundle` remain platform-independent. When an official stable native
asset becomes available, adding its platform layout and pinned digest to the
manifest enables it without a separate architecture bypass.

Treat CodeQL findings as defects by default. When a finding is a verified
false positive, put a rationale and a query-specific `# codeql[query-id]`
comment immediately before the reported line. The local runner includes
CodeQL's alert-suppression query, so the annotation behaves the same locally
and in GitHub; broad or unexplained suppressions are not appropriate.

`.github/codeql/local-bundle.json` is the single source of truth for the
CodeQL version. CI compares the version selected from GitHub's hosted tool
cache with that manifest and fails clearly on drift. Refresh the manifest and
official release digests with:

```bash
uv run python scripts/check_codeql.py --update-bundle VERSION_FROM_CI
```

Local analysis uses `--no-download`, so after the initial bundle installation
a missing query pack fails instead of contacting a package registry.

## CLI Development

The CLI is part of the root SafeYolo package and uses Typer.

**Setup:**
```bash
uv sync --group dev
```

**Add a new command:**
```python
# cli/src/safeyolo/commands/mycommand.py
import typer
from rich.console import Console

console = Console()

def mycommand(
    arg: str = typer.Argument(..., help="Required argument"),
    flag: bool = typer.Option(False, "--flag", "-f", help="Optional flag"),
) -> None:
    """Description shown in --help."""
    console.print(f"Running with {arg}, flag={flag}")
```

**Register in cli.py:**
```python
from .commands.mycommand import mycommand
app.command()(mycommand)
```

## macOS VM helper development

On an Apple Silicon Mac with Command Line Tools and Python 3.11 or later,
run these commands from the repository root. The production build retains
hardened runtime and the virtualization entitlement. It does not carry
`com.apple.security.get-task-allow`.

```sh
make -C vm build
vm/.build/release/safeyolo-vm --version --json
```

To install a development helper, run:

```sh
make -C vm debug-install
safeyolo doctor
```

This replaces the helper at `~/.safeyolo/bin/safeyolo-vm`. It installs a matching
`safeyolo-vm.dSYM` bundle and `safeyolo-vm.build-info.json` beside the helper.
It does not rebuild the Linux guest tools. Development uses release optimisation
with symbols and adds `com.apple.security.get-task-allow`. Authorised local
debuggers can inspect or modify the helper's memory and execution. Hardened
runtime remains enabled; no library-injection or executable-memory exceptions
are added. Use this profile only where that local debugger authority is acceptable.

`doctor` and `agent diag` report the installed helper's build identity and warn
when debugger access is enabled. The helper's `version` and `--version` commands
accept `--json`. Output includes the SafeYolo and helper versions, Git revision
and dirty state, profile, architecture, compiler, optimisation, symbol profile
and running debug/hardened-runtime flags. Each VM startup also logs its identity.
An older or unmanaged helper produces an explicit identity warning.

On macOS, `safeyolo agent diag AGENT` also checks the shell UDS and reads an
SSH identification within one three-second deadline. A successful UDS connect
alone does not prove shell health. The banner check traverses the helper, vsock
and guest shell bridge to sshd, then disconnects without authentication. Failure
leaves those downstream hops unproven and does not skip the separate egress
checks. Slow or excessive pre-banner data remains bounded within the diagnostic.

Start a disposable agent after installing the development helper. Replace
`AGENT` below with that agent's name. From the Mac operator account, attach LLDB:

```sh
lldb -p "$(cat ~/.safeyolo/agents/AGENT/vm.pid)"
```

The Mac must permit developer-tool attachment. Re-signing an executable does
not change the debugger authority of an already-running process. Restart the
disposable agent to test a newly signed helper. Verify a symbol bundle's UUID
against the executable with `dwarfdump --uuid` before using it for an incident.

For an isolated helper selection, build with `make -C vm debug` and set
`SAFEYOLO_VM_HELPER` to the absolute path of
`vm/.build/development/release/safeyolo-vm` for the disposable agent's run.
To restore the production installation, run `make -C vm install-helper` and
restart the affected agents.

The build and install targets verify the actual signature and reject an
unexpected entitlement set, a missing hardened runtime or a profile mismatch.
Run `make -C vm verify` when packaging an existing production artifact. To test
both profiles and rejection of a production artifact re-signed with debugger
access, build both profiles and run `python3 vm/test/build-profiles.py` on the Mac.

Inside the confined SSH account, pass `SWIFT_BUILD_FLAGS=--disable-sandbox`
to `make`. This suppresses SwiftPM's additional sandbox while the inherited
Seatbelt profile remains active. The build uses SwiftPM's native backend;
Swift 6.4's default backend currently tries to use `/tmp` during linking under
this profile. Stage dependencies through the approved SSH connection.

For an exported source tree without Git metadata, the build can take a full
`SAFEYOLO_BUILD_REVISION` and `SAFEYOLO_BUILD_DIRTY=yes|no|unknown` from the
exporting build process. Without source evidence, identity reports `unknown`.

The proxy and shell relays each use a dedicated thread with nonblocking socket
I/O. Each direction buffers at most 64 KiB and stops reading while that buffer
is full. Relay establishment has a ten-second deadline from acceptance,
including waiting for a vsock callback. A late callback closes its connection.
Cancellation shuts down both endpoints and releases their owners on the next
relay turn; no relay waits for child work on a shared GCD pool.

A half-close propagates only after its buffered bytes drain. The other direction
can continue sending a response without a lifetime or idle limit. Once both
readers reach EOF, any remaining buffer must make progress within ten seconds
or teardown closes the flow. Completion logs use a separate thread so stderr
backpressure cannot block pumps. Its bounded queue holds 1,024 pending messages;
overflow is counted and reported when logging resumes.

Run `make -C vm test-relays` on macOS for real Unix-socket regression tests.
They exercise 300 held proxy flows alongside shell traffic, backpressure and
byte integrity, half-close responses, establishment/drain timeouts, cancellation,
late callbacks, closed idle shell clients, blocked logging and return to the original open-FD count. This
suite tests the native relay implementation; real VZ/guest acceptance is still
needed for framework integration and guest services.

Run `make -C vm test-admission` for connection-limit tests. They check rejection
before VZ connection creation, concurrent callers, pending attempts, slot reuse,
and terminal callbacks arriving after a timeout. The guest forwarder tests in
`cli/tests/test_guest_proxy_admission.py` use real socat with a local Unix-socket
substitute for VZ. They verify queueing, continued traffic on an existing flow,
slot reuse, and unchanged Linux UDS admission. They do not establish the native
framework's resource ceiling. See [connection admission](microvm-architecture.md#connection-admission-on-macos)
for the shipped limits and their scope.

Run `make -C vm test-control` for native control-channel tests. They deliberately
leave relay executors unscheduled, hold a partial control request open, and
verify status/dump responsiveness, process-instance checks, private auditing,
cancellation acknowledgement versus observed closure, and listener cleanup.
The [host VM diagnostics](agent-debugging.md#inspect-a-macos-vm-helper-from-the-host)
describe the supported operator commands and the evidence each one provides.

## Testing

**Run tests:**
```bash
uv sync --group dev
uv run pytest tests/ -v          # unit + integration; integration needs running proxy
uv run pytest tests/test_http_integration.py -v   # integration only
```

**Run CLI tests:**
```bash
uv run pytest cli/tests/ -v
```

**Test credential detection:**
```bash
# Start SafeYolo and add a test agent
safeyolo start
safeyolo agent add scratch --host-script @claude

# Shell into the agent and issue requests through its per-agent socket
safeyolo agent shell scratch
$ curl -H "Authorization: Bearer sk-test123..." https://api.openai.com/v1/models
# Should return 403 (blocked) with X-Blocked-By header

$ curl https://httpbin.org/get
# Should return 200 (allowed)
```

## README skill discovery

The repository ships one [readme-usability skill](../cli/src/safeyolo/agent_context/skills/readme-usability/SKILL.md)
with a conditional SafeYolo reference. Edit that source. The checked-in
`.agents/skills/readme-usability` and `.claude/skills/readme-usability` directory
symlinks expose it to Codex and Claude Code in this checkout. `AGENTS.md`, also
imported by `CLAUDE.md`, routes README and onboarding work to it.

The bundled Codex and Claude host setup scripts also stage discovery links in
agent homes. SafeYolo copies the skill into the read-only `/safeyolo/skills/`
share on each run. New agents receive the links through normal host setup.
Existing agent homes outside this checkout need the bundled host setup reapplied
once after upgrade: stop the agent, then use the run command’s `--host-script`
option with its **existing** alias or path (for example, `@codex`, `@codex-coord`
or `@claude`). Preserve any coordinated or custom variant. Ordinary restarts refresh
skill contents but do not rerun host setup to add missing discovery links.
No skill-specific wiring is required. Unrelated
user-owned skills at the same discovery path are preserved and reported as a
setup conflict.

Both harnesses can select the skill from its description. Explicit invocation
is `$readme-usability` in Codex or `/readme-usability` in Claude Code. If a running
harness does not show the newly added skill, restart that harness. Discovery
makes a skill available; it does not prove a particular model used it.
Custom launchers that do not run the bundled setup still get repository discovery
when working in this checkout. This does not install a skill into Claude's web
application. See the supported discovery rules for
[Codex](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)
and [Claude Code](https://code.claude.com/docs/en/skills#choose-where-skills-load).

## Documentation drift protection

All authoritative prose changes must follow the project
[technical-writing rule and lossless review checklist](technical-writing.md).
The rule uses Simplified Technical English principles for clarity without
claiming formal ASD-STE100 compliance. Automated drift checks support that
review, but they do not judge whether a rewrite is clear or lossless.

User-facing docs listed in `scripts/doc_allowlist.toml` are guarded by
six pre-commit hooks that fail CI when a claim in a doc no longer matches
the code. Each mechanism addresses one drift class; together they cover
the five drift classes we've actually observed in this repo.

### The six checks

| Check | Script | Catches |
|---|---|---|
| Marker co-change | `check_skill_markers.py` | Source lines with `# DOC:` markers edited/removed without a matching doc update |
| CLI-flag drift | `check_doc_cli_flags.py` | Docs referencing `safeyolo <cmd>` commands or flags that don't exist |
| Constants-in-prose | `check_doc_constants.py` + `doc_constants.toml` | Pinned values in code no longer matching what docs quote |
| Repo-relative links | `check_doc_links.py` | `[text](path)` / `[label]: path` references to moved or renamed files |
| Forbidden phrases | `check_doc_forbidden.py` + `doc_forbidden.toml` | Stale mechanism claims after the enforcing code was deleted (no anchor left to mark against) |
| Agent token argv | `check_agent_token_argv.py` | Agent API curl examples that expand the bearer into `-H` / `--header` process arguments |

An additional soft check, `audit_doc_coverage.py`, reports which docs
carry how many bindings and which curated security keywords appear in
any doc without a binding. Run it manually — it's a visibility tool,
not a gate.

### Where the allowlist lives

The shipped-docs allowlist is `scripts/doc_allowlist.toml`, with two
tiers reflecting the two audiences:

- `user_facing_docs` — human-operator docs (`README.md`, `SECURITY.md`,
  `docs/*`, `guest/README.md`, `cli/README.md`, `contrib/*.md`). Explicit
  list, no globs.
- `skill_files` — agent-facing docs shipped INTO agent sandboxes as part
  of the safeyolo skill (`SKILL.md` + `references/*.md`). Glob patterns
  allowed — new reference files get automatic coverage.

Both tiers are exposed via `scripts/_doc_config.py` as
`USER_FACING_DOCS`, `SKILL_FILES`, and their union `ALL_SHIPPED_DOCS`.
The link and CLI-flag checks scan the union. The marker check accepts
DOC refs pointing at either tier. The audit tool reports per-tier
binding counts. Design/planning docs (`docs/*-design.md`,
`docs/FUTURE.md`, etc.) are deliberately out of scope — they describe
intent, not runtime behaviour.

`doc_forbidden.toml` and `doc_constants.toml` rules each declare their
own `docs = [...]` list independent of the allowlist, so a rule can
target any file in the repo (used, for example, by the
`skill-must-use-uv-run-pre-commit` rule that scans the skill reference
file directly).

### Where to place a `# DOC:` marker

**Rule of thumb: place the marker on the specific expression that, if
changed, would invalidate the doc claim.** Check semantics are "edits
and removals fire; pure declarative additions do not" — so the marker
line needs to actually change when the enforced fact changes.

Concrete choices used in this repo:

| Kind of claim | Marker location | Example |
|---|---|---|
| Typer command exists | The `def cmdname(` line | `def start(  # DOC: README.md` |
| Typer flag exists (specific flag) | The `"--flag"` string line, not the `def` | `"--dev",  # DOC: docs/DEVELOPERS.md` |
| Pinned constant (shell) | The assignment line | `ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"  # DOC: guest/README.md` |
| Security invariant (specific expression) | The enforcement expression | `HTTPServer(("127.0.0.1", port), ...)  # DOC: SECURITY.md` |
| Class-level property (whole class defends the claim) | The `class Foo:` line | `class AdminShield:  # DOC: SECURITY.md` |
| Function-level property (whole function defends the claim) | The `def foo(` line | `def hmac_fingerprint(...):  # DOC: SECURITY.md` |

A marker can list multiple docs: `# DOC: SECURITY.md, README.md`.
Anchors (`# DOC: docs/AGENTS.md#agents-section`) are advisory in v1.

### Adding a new claim to a user-facing doc

1. **CLI reference** (a `safeyolo` command or option) → no action needed; the
   CLI-flag check catches broken references automatically. If you want
   the reverse binding ("changing this flag reminds me to update the
   doc"), add a `# DOC:` marker per the table above.
2. **Pinned value** (version, size, IP, path) → add an `[[assertion]]`
   to `scripts/doc_constants.toml`. Use `must_contain_any = [...]` when
   several phrasings are equivalent (e.g. `["127.0.0.1", "loopback only"]`).
3. **Security or behavioural invariant** → place a `# DOC:` marker on
   the specific enforcement expression per the table above.
4. **Claim about a mechanism that could be removed later** → add a
   `[[rule]]` to `scripts/doc_forbidden.toml` listing the phrases that
   should never appear if the mechanism is gone. This is the check that
   catches "the code that used to defend the claim was deleted" — no
   marker helps there because there's nothing left to mark.
5. **Referenced file path** → the link check handles it automatically
   once the path is in a `[text](path)` or `[label]: path`.

Run `uv run pre-commit run --all-files` locally to verify all six checks pass.
Run `uv run python scripts/audit_doc_coverage.py` to see current coverage per
doc and per security keyword — useful for planning what to mark next.

### When *not* to add a marker

- **Design or planning doc** — out of scope; those describe intent.
- **Prose that describes a behaviour enforced by absence of code**
  (e.g. "no external network interface" is defended by the absence of
  bridge configuration — no line to mark). Cover it with a
  forbidden-phrase rule for the stale-mechanism variant, or a
  constants-in-prose assertion for a specific verifiable value.
- **The same claim already has a marker at a stronger enforcement site.**
  One marker per claim is fine; N markers on the same claim add churn
  without extra coverage.

## Contributing

### Contribution Process

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix
3. **Write tests** for new functionality
4. **Run tests** to ensure nothing breaks
5. **Submit a PR** with a clear description

### Coding Standards

All contributions must:

- **Pass syntax checks** - CI runs `python -m py_compile` on all Python files
- **Pass tests** - All existing tests must pass, new features need tests
- **Support Python 3.12 and 3.13** - CI tests both versions
- **Use type hints** - For function signatures (not enforced by CI yet, but preferred)
- **Follow existing patterns** - Match the style of surrounding code

**Code style:**
- Use descriptive variable names (no single letters except loop counters)
- Keep functions focused and single-purpose
- Add docstrings for public functions
- Follow the Python defect-prevention rules below for exception handling.

#### Python defect prevention

Apply these rules to changed code during implementation and independent review.
They address recurring findings; they do not require unrelated cleanup in every
pull request.

- **Reuse the existing implementation.** Before adding a parser, configuration
  writer, subprocess wrapper, or state helper, find the repository's existing
  entrypoint and its tests. Use the established helper when it fits. For
  structured formats such as TOML, use the existing parser/writer rather than
  a regular expression that guesses at the format.
- **Catch only failures the code can handle.** Keep the `try` block focused on
  the operation that can raise the expected exception. Do not turn an
  unexpected failure into an empty result or a success return. A handler must
  recover, propagate, or report the failure through the existing error path;
  logging alone does not make the failed operation successful.
- **Explain deliberate exception suppression.** An expected race can be
  harmless: for example, another process created a directory that the next
  operation will open and validate. Catch the specific exception and state why
  continuing is correct at that handler. Do not add a generic comment, switch
  to `contextlib.suppress`, or log and continue merely to silence a finding.
  Test material recovery paths and ensure unexpected errors remain visible.
- **Preserve cancellation and shutdown.** Do not use bare `except:` or
  `BaseException` as ordinary application error handling. Prefer `finally` or
  a context manager for cleanup. If a worker boundary genuinely must catch
  `BaseException`, explain and test how cancellation, `KeyboardInterrupt`, and
  `SystemExit` reach the caller or terminate the worker. Do not silently convert
  them into normal task success.
- **Remove dead code, not required work.** Delete unused imports, variables,
  constants, and expressions when they have no purpose. If a call is needed
  for its effect, keep the call without an unused assignment. Use `_` for a
  deliberately unused unpacked value. Do not rename a value to `_value` just
  to hide a missing check or discard error information the caller needs.
- **Keep imports consistent and dependencies one-way.** Reuse the file's
  existing import style for a module instead of importing it both directly
  and through `from`. Put genuinely shared behaviour in an existing common
  module when possible, rather than making two command modules import each
  other. A local import can be appropriate for optional or deferred loading;
  explain that need instead of using it to conceal a new cycle. Preserve
  intentional public re-exports and document their consumers.
- **Distinguish valid Python from scanner mistakes.** An ellipsis in a
  `typing.Protocol` method declares an interface; it is not an unfinished
  implementation. Check the reported symbol and its callers before changing
  behaviour or removing an apparent unused export. For a verified false
  positive, use the existing query-specific CodeQL suppression with a concrete
  rationale. Do not suppress the rule across a file or repository.

Run the configured Ruff checks on changed Python paths during development and
the existing pre-commit hooks before publication. A clean Ruff result is not
equivalent to a clean CodeQL analysis: their coverage differs. If local CodeQL
is unavailable, retain that limitation and inspect the GitHub analysis findings
for the candidate; a successful analysis/upload job does not mean no findings.

### Acceptance tooling

For SafeYolo, tracked lockfiles, package manifests, pre-commit and CI
configuration, and build/rootfs/install scripts form the dependency inventory
until a unified software bill of materials (SBOM) manifest exists. An
operator-bound acceptance graph supplies the separate validation-tool
inventory. Use both from the trusted base revision; a candidate's changes to
these inventories remain review subject matter, not standing approval to
install new tools. The factory reviewer contract defines installation authority
and how to request a tool outside those inventories.

For changed production Python, the trusted-base Ruff installation supports the
configured lint pass and this focused structural-complexity check:

```sh
uv run ruff check --select C901,PLR0911,PLR0912,PLR0913,PLR0915 <changed-production-python-paths>
```

Replace the placeholder with the changed production Python paths. Inspect
flagged symbols and compare with the base when attribution is unclear. A tool
finding is evidence, not an automatic veto: report new material complexity and
code smells; keep pre-existing findings, minor cleanup, and preferences
non-blocking. The command supplements the configured lint and static checks;
it does not replace independent acceptance of the behaviour being changed.

### Testing Requirements

Before submitting a PR:

```bash
# Run addon tests
pytest tests/ -v

# Run CLI tests
uv run pytest cli/tests/ -v

# Check syntax (what CI does)
find cli/src -name "*.py" -exec uv run python -m py_compile {} \;
```

### Pull Request Guidelines

- PRs should address a single concern (bug fix, feature, refactor)
- Include tests for new functionality
- Update documentation if adding user-facing changes
- Keep commits atomic and well-described
- CI must pass before merge

### Areas for Contribution

- New credential patterns for additional providers
- Notification backends (Slack, Discord, email)
- CLI improvements
- Documentation
- Test coverage

## Example Integrations

The `contrib/` directory contains example integrations you can use as templates:

| Integration | Description |
|-------------|-------------|
| `contrib/claude-code-chokepoint/` | **Recommended**: Claude Code in enforced chokepoint mode |
| `contrib/monitors/` | Log monitoring and visualization tools |
| `contrib/notifiers/` | Push notifications via ntfy with optional approval buttons |

See [contrib/README.md](../contrib/README.md) for the integration pattern and how to build your own.

**Ideas for new integrations:**
- **Slack/Discord bot** - Post blocked credentials to a channel
- **Dashboard** - Real-time visualization of proxy traffic
- **Metrics exporter** - Push to Prometheus/Grafana
- **CI integration** - Block builds if credentials leak in tests
- **IDE plugin** - Show SafeYolo status in VS Code

## Questions?

Open an issue on GitHub or reach out to the maintainers.
