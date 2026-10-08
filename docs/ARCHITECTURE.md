# SafeYolo architecture and historical Python proxy

This document describes the software architecture of SafeYolo, an egress control proxy for AI coding agents.

The current agent identity/lifecycle sources of truth and the staged plan for
durable `agent_id` plus runtime `run_id` are documented in the
[agent identity and run-lifecycle implementation plan](agent-lifecycle-identity-plan.md).

## Overview

The current host CLI launches the packaged Rust proxy. The native process
handles network policy, credential and pattern inspection, local Agent and
Admin APIs, flow evidence, and the read-only terminal inspector. The CLI owns
host setup and sandbox lifecycle. See [developer architecture](DEVELOPERS.md#architecture-overview)
for current source locations and [configuration](CONFIGURATION.md) for operator
settings.

The policy, Policy Decision Point (PDP), and addon sections below document the
former Python implementation. They explain the source behavior used for migration
comparison; their module paths and custom-addon instructions do not apply to
the current package. The [capability inventory](proxy-parity.md) records
accepted differences and first-release traffic scope.

## Sandbox runtime and networking

Each agent runs in an isolated Linux sandbox without an external network
interface. Requests go through the guest forwarder and a host-owned,
per-agent Unix domain socket (UDS) to the native Rust proxy:

```text
Agent sandbox -> guest forwarder -> per-agent UDS -> Rust proxy -> upstream
```

The host-controlled listener and agent map establish request identity. A
request header cannot select another agent. The proxy applies the configured
network, credential, and inspection controls at their respective request
stages; streamed bodies and TLS passthrough have narrower inspection and
capture coverage. The [networking reference](networking-vsock-uds.md)
describes the platform bridges and their limits.

On macOS, the sandbox is a hardware-backed microVM using Apple
Virtualization.framework and virtual sockets. On Linux, it is a rootless
gVisor sandbox using `runsc` in an unprivileged user namespace. The guest has
no direct external interface; removing proxy environment variables does not
create an external network route. See [security verification](security-verification.md)
for tests of the isolation boundary.

Agents have full pseudo-terminals (PTYs): a virtual-socket PTY bridge on macOS
and `runsc exec` on Linux. Guest init is served from a writable status share
and a read-only configuration share.

### Linux runtime and storage

- **Rootless host operation**: runsc runs in an unprivileged user namespace (`unshare -Un` + `newuidmap`/`newgidmap`) and launching agents requires no host sudo. Agents start as uid 1000; in-guest `sudo` may enter sandbox uid 0 for ephemeral package installs. That identity maps to subordinate host uid 100000, while container uid 1000 maps to the operator.
- **Rootfs**: a single shared directory tree at
  `~/.safeyolo/share/rootfs-tree/` is the gVisor OCI `root.path`; Linux does
  not package it as an image. By default, writes
  go to a per-agent file-backed overlay and persist across stop and run.
  `--ephemeral` selects a memory-backed overlay whose rootfs writes are
  discarded on stop. Per-agent package-cache bind mounts keep reinstalls cheap.
- **Isolation platform**: KVM (hardware-enforced) if available; systrap (seccomp-BPF) fallback otherwise. Auto-detected by the native host prerequisites in `docs/native-policy.md` and surfaced in `safeyolo doctor`.
- **One-time setup**: AppArmor profile to allow unprivileged user namespaces on Ubuntu 24.04+, and a udev rule granting the subordinate uid access to `/dev/kvm` — both applied idempotently by the native host prerequisites in `docs/native-policy.md`.


See the [macOS microVM architecture](microvm-architecture.md) and
[historical Linux port design](linux-port-design.md) for platform design context.

## Historical Python policy model

All sections below, including policy, PDP, sensors,
reload, gateway, and file structure, describe the former Python
implementation unless a section explicitly says otherwise. They are migration
reference, not current configuration or extension instructions. Use
[configuration](CONFIGURATION.md) and the [Rust source](../proxy/src/) for the
current implementation.


### UnifiedPolicy

Security configuration is split across two sibling files that are loaded into a single Pydantic-validated model (`UnifiedPolicy`):

- `policy.toml` -- human-owned host-centric policy (TOML-first; `.yaml` also supported), including agent config in `[agents]`
- `addons.yaml` -- addon tuning (merged as defaults)

Both are merged by PolicyLoader before compilation.

```toml
# policy.toml — host-centric policy
version = "2.0"
budget = 12_000

required = ["credential_guard", "network_guard", "circuit_breaker"]
scan_patterns = []

[lists]
package_registries = "lists/package-registries.txt"
known_bad          = "lists/stevenblack-hosts.txt"

[hosts]
"api.openai.com"      = { allow = ["openai:*"],    rate = 3_000 }
"api.anthropic.com"   = { allow = ["anthropic:*"],  rate = 3_000 }
"api.github.com"      = { allow = ["github:*"],     rate = 300 }
"$package_registries" = { rate = 1_200 }
"$known_bad"          = { egress = "deny" }
"*"                   = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]

[agents.boris]
egress = "prompt"
[agents.boris.hosts]
"api.stripe.com" = { rate = 600 }
```

The `[lists]` section defines named lists -- files containing one host per line. Reference them in `[hosts]` with a `$name` prefix; the loader expands each list entry into a host permission with the same settings.

Agent configuration lives in `[agents]` within `policy.toml`. Each agent can have its own `egress` posture (default egress decision for hosts not explicitly listed) and a `[agents.<name>.hosts]` table that works identically to the top-level `[hosts]` but scopes permissions to that agent. Agent-scoped permissions are evaluated first; if no match is found, evaluation falls through to the proxy-wide `[hosts]` rules.

```yaml
# addons.yaml — addon tuning (sibling to policy.toml)
addons:
  credential_guard:
    enabled: true
    detection_level: standard
    entropy: { min_length: 20, min_charset_diversity: 0.5, min_shannon_entropy: 3.5 }
  circuit_breaker:
    enabled: true
    failure_threshold: 5
  pattern_scanner:
    enabled: true
    builtin_sets: []
```

The host-centric format in `policy.toml` compiles to IAM-style rules at load time. TOML field names are normalized during loading (`allow` → `credentials`, `rate` → `rate_limit`, `unknown_creds` → `unknown_credentials`, etc.). Each host entry can include `allow`, `egress`, `unknown_creds`, `rate`, `bypass`, and a `rules` escape hatch for full IAM expressiveness. `allowed_hosts` for credential rules are auto-derived from the `[hosts]` section.

### Policy Layers

Policies are layered (baseline + task):

1. **Baseline Policy**: Default rules loaded from `policy.toml` (or `policy.yaml`)
2. **Task Policy**: Optional per-task overrides (additive)

The PolicyEngine merges these, with task policy extending baseline.

### Key Policy Sections

| File | Section | Purpose |
|------|---------|---------|
| `policy.toml` | `[hosts]` | Per-host credentials (`allow`), egress posture, rate limits (`rate`), bypass, rules |
| `policy.toml` | `budget` | Global rate limit cap across all hosts |
| `policy.toml` | `[lists]` | Named host lists (file paths), referenced with `$name` in `[hosts]` |
| `policy.toml` | `[credential.*]` | Credential detection patterns (`match`) and header names |
| `policy.toml` | `[agents.*]` | Per-agent egress posture and host overrides |
| `policy.toml` | `required` | Addons that must be active |
| `policy.toml` | `scan_patterns` | Content scanning rules (URL, headers, body) |
| `addons.yaml` | `addons` | Per-addon configuration, enablement, tuning |

## PDP Architecture

### Components

```
PolicyClient (interface)
    │
    ├── LocalPolicyClient ──► PDPCore ──► PolicyEngine ──► PolicyLoader
    │                                                            │
    └── HttpPolicyClient ──► FastAPI (/v1/evaluate)              ▼
                                    │                      UnifiedPolicy
                                    └──► PDPCore ──► ...    (toml/yaml)
```

### PolicyClient

Abstract interface that sensors use to query policy:

```python
class PolicyClient(ABC):
    @abstractmethod
    def evaluate(self, event: HttpEvent) -> PolicyDecision:
        """Main policy query - returns allow/deny/prompt decision."""

    @abstractmethod
    def get_sensor_config(self) -> dict:
        """Get credential_rules, scan_patterns, policy_hash."""

    @abstractmethod
    def is_addon_enabled(self, addon_name: str, domain: str = None) -> bool:
        """Check if addon should process this request."""
```

Two implementations:
- **LocalPolicyClient**: In-process, calls PDPCore directly (default, fastest)
- **HttpPolicyClient**: HTTP calls to PDP service (for split-process deployments)

### PDPCore

Wraps PolicyEngine with operational concerns:

- Budget tracking (sliding window counters)
- Approval management
- Statistics collection
- Policy hash for cache invalidation

### PolicyEngine

Pure policy evaluation logic:

- Loads and validates policy via PolicyLoader
- Evaluates permissions against events
- Merges baseline + task policies
- Provides accessors for sensor config:
  - `get_credential_rules()` - merged credential detection rules
  - `get_scan_patterns()` - merged content scan patterns

Compiled permissions are stored in a three-tier permission index for fast lookup:

1. **Simple sets** -- `{(action, effect): set(resource)}` -- O(1) set membership for unconditional deny/allow/prompt rules (the bulk of host entries)
2. **Exact dict** -- `{(action, resource): [Permission]}` -- O(1) dict lookup for entries that carry conditions or budgets and need full Permission evaluation
3. **Pattern list** -- `[Permission]` -- linear scan reserved for wildcard/glob patterns only

This avoids a linear scan over all permissions on every request; most lookups resolve in tier 1 or 2.

### PolicyLoader

Handles policy file loading and validation:

- Loads policy.toml (or .yaml) at startup
- Validates against UnifiedPolicy Pydantic model
- Supports task policy upsert/delete
- Computes policy hash for change detection

## Sensor Architecture

### Base Classes

All security addons extend `SecurityAddon`:

```python
class SecurityAddon:
    name: str  # e.g., "credential-guard"

    def log_decision(self, flow, decision, **kwargs):
        """Structured logging to JSONL."""

    def is_bypassed(self, flow) -> bool:
        """Check if client should bypass this addon."""
```

### Addon Chain

Addons process requests in the order defined by
`cli/src/safeyolo/mitm_addons/__init__.py`. `safeyolo.traffic_master`
registers that production chain directly for one process generation; it does
not use mitmproxy's watched script loader.

**Layer 0 - Infrastructure:**
1. `file_logging` - Structured JSONL file logging setup
2. `memory_monitor` - Process memory and connection tracking
3. `admin_shield` - Blocks proxy access to admin API
4. `agent_api` - Read-only PDP agent API for agent self-service
5. `loop_guard` - Detects and breaks proxy loops (Via header)
6. `request_id` - Assigns unique ID to each request
7. `sse_streaming` - SSE/streaming support for LLM responses
8. `policy_engine` - Unified policy evaluation and budgets

**Layer 1 - Network Policy:**
9. `network_guard` - Access control + rate limiting + homoglyph detection
10. `circuit_breaker` - Fail-fast for unhealthy upstreams

**Layer 2 - Security Inspection:**
11. `credential_guard` - Credential routing validation
12. `pattern_scanner` - Content pattern detection
13. `test_context` - X-SafeYolo-Test-Context header enforcement for target hosts

**Layer 3 - Observability:**
14. `request_logger` - JSONL audit logging
15. `metrics` - Per-domain statistics
16. `admin_api` - REST control plane on :9090

**TUI-only:**
17. `flow_pruner` - Prune old flows to prevent memory growth (loaded when `SAFEYOLO_TUI=true`)

First addon to block wins; subsequent addons see `flow.response` is set.

### credential_guard

Detects credentials in HTTP requests and validates they're going to authorized destinations.

**Data Flow:**
```
request() called
    │
    ├── _maybe_reload_rules()  ← Check policy_hash, reload if changed
    │         │
    │         └── PolicyClient.get_sensor_config()
    │                    │
    │                    └── {credential_rules, policy_hash}
    │
    ├── analyze_headers() ← Detect credentials using rules
    │
    └── evaluate_credential_with_pdp() ← Get allow/deny decision
              │
              └── PolicyClient.evaluate(HttpEvent)
                           │
                           └── PolicyDecision (allow/deny/prompt)
```

**Key Features:**
- Pattern-based credential detection (regex)
- Destination validation (credential X can only go to host Y)
- HMAC fingerprinting (never logs raw credentials)
- Tiered detection: known patterns (tier 1), entropy heuristics (tier 2)

### pattern_scanner

Scans HTTP and WebSocket content for user-defined patterns.

**Data Flow:**
```
request()/response()/websocket_message() called
    │
    ├── _maybe_reload_patterns()  ← Check policy_hash, reload if changed
    │         │
    │         └── PolicyClient.get_sensor_config()
    │                    │
    │                    └── {scan_patterns, addons.pattern_scanner.builtin_sets}
    │
    └── _scan_request_content() / _scan_response_content()
        / _scan_websocket_message()
              │
              └── Check URL, headers, body based on rule scope
```

**Key Features:**
- Configurable scope: URL, headers, body
- Direction filtering: request, response, or both
- Action modes: block or log
- Builtin pattern sets: `secrets`, `pii`
- Complete WebSocket text and binary messages use body rules
- Client messages use request rules; server messages use response rules
- WebSocket blocking drops the matching message and keeps the connection open
- WebSocket block mode has independent per-direction options; HTTP block
  options do not change WebSocket behavior

## Hot Reload

Both credential_guard and pattern_scanner support hot reload via policy hash polling:

```python
def _maybe_reload_rules(self):
    """Reload if policy changed."""
    client = get_policy_client()
    config = client.get_sensor_config()

    if config["policy_hash"] != self._last_policy_hash:
        self._load_from_config(config)
        self._last_policy_hash = config["policy_hash"]
```

This is called at the start of each `request()` hook, ensuring rules stay in sync with policy changes without requiring proxy restart.

## HTTP API (when running PDP as service)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/evaluate` | POST | Evaluate HttpEvent, return PolicyDecision |
| `/v1/sensor_config` | GET | Get credential_rules, scan_patterns, policy_hash |
| `/v1/baseline` | GET/PUT | Read/update baseline policy |
| `/v1/tasks/{id}/policy` | PUT/GET/DELETE | Manage task policies |
| `/v1/approvals/credentials` | POST | Add credential approval |
| `/v1/budgets` | GET | Get budget usage stats |
| `/health` | GET | Health check |

## Service Gateway

The service gateway enables agents to access external APIs without seeing real credentials:

```
Agent Container                    SafeYolo Proxy                    External API
    |                                  |                                 |
    |-- Authorization: sgw_xxx ------->|                                 |
    |                                  |-- strip sgw_ token             |
    |                                  |-- vault lookup -> real cred     |
    |                                  |-- inject Authorization: Bearer real_cred -->|
    |                                  |<-- response --------------------|
    |<-- response (cred redacted) ----|                                 |
```

Key components:
- `service_gateway.py` -- mitmproxy addon, credential injection
- `service_loader.py` -- loads service YAML definitions, hot-reload watcher
- `vault.py` -- encrypted credential store (Fernet encryption)
- `policy_compiler.py` -- compiles `agents:` section into gateway token map

## File Structure

```
safeyolo/
├── addons/
│   ├── base.py              # SecurityAddon base class
│   ├── utils.py             # Shared utilities (logging, blocking)
│   ├── sensor_utils.py      # HttpEvent builders for sensors
│   ├── detection/
│   │   ├── credentials.py   # Credential detection logic
│   │   ├── patterns.py      # Pattern compilation, builtin sets
│   │   └── matching.py      # Host/resource matching, HMAC
│   ├── file_logging.py      # Structured JSONL file logging setup
│   ├── memory_monitor.py    # Process memory + connection tracking
│   ├── admin_shield.py      # Protects admin API endpoints
│   ├── agent_api.py         # Read-only PDP agent API for agents
│   ├── loop_guard.py        # Proxy loop detection (Via header)
│   ├── request_id.py        # Request ID generation
│   ├── sse_streaming.py     # SSE/streaming for LLM responses
│   ├── policy_engine.py     # PolicyEngine + PolicyClientConfigurator
│   ├── policy_loader.py     # TOML/YAML loading, hot reload
│   ├── budget_tracker.py    # GCRA-based rate limiting
│   ├── network_guard.py     # Access control + rate limiting
│   ├── circuit_breaker.py   # Upstream failure protection
│   ├── credential_guard.py  # Credential routing protection
│   ├── pattern_scanner.py   # Content pattern detection
│   ├── test_context.py      # X-SafeYolo-Test-Context header enforcement
│   ├── request_logger.py    # JSONL audit logging
│   ├── metrics.py           # Per-domain statistics
│   ├── admin_api.py         # REST control plane
│   ├── flow_pruner.py       # TUI-only: prune old flows
│   └── service_discovery.py # Client IP to project mapping
├── pdp/
│   ├── __init__.py          # Public API exports
│   ├── core.py              # PDPCore - main PDP implementation
│   ├── client.py            # PolicyClient interface + implementations
│   ├── schemas.py           # HttpEvent, PolicyDecision Pydantic models
│   ├── tokens.py            # HMAC-signed readonly tokens
│   └── app.py               # FastAPI HTTP adapter
├── config/
│   ├── policy.toml          # Host-centric policy (TOML preferred; .yaml fallback)
│   ├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
│   └── safe_headers.yaml    # Headers to skip in credential scanning
└── tests/
    ├── test_credential_guard.py
    ├── test_pattern_scanner.py
    ├── test_test_context.py
    ├── test_memory_monitor.py
    ├── test_agent_api.py
    └── test_integration.py
```

## Design Principles

1. **Single Source of Truth**: All security configuration in UnifiedPolicy
2. **Fail Closed**: PDP unavailable = DENY (never fail open by default)
3. **Separation of Concerns**: Sensors detect, PDP decides, policy defines
4. **No Raw Credentials**: HMAC fingerprints only, never log actual secrets
5. **Hot Reload**: Policy changes apply without restart
6. **Testable**: All components work with mitmproxy test fixtures
