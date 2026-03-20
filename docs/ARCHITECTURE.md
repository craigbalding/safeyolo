# SafeYolo Architecture

This document describes the software architecture of SafeYolo, an egress control proxy for AI coding agents.

## Overview

SafeYolo is built as a mitmproxy addon stack with a centralized Policy Decision Point (PDP). The architecture separates concerns into:

- **Sensors (Addons)**: Observe HTTP traffic, detect security-relevant events, request policy decisions
- **PDP**: Evaluates events against policy, returns allow/deny decisions
- **Policy**: Single source of truth for all security configuration

```
┌─────────────────────────────────────────────────────────────────┐
│                        mitmproxy                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ request_id   │  │network_guard │  │credential_   │  ...     │
│  │              │  │              │  │guard         │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                 │                   │
│         └─────────────────┼─────────────────┘                   │
│                           ▼                                     │
│                   ┌───────────────┐                             │
│                   │ PolicyClient  │                             │
│                   └───────────────┘                             │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            ▼
                   ┌───────────────┐
                   │   PDPCore     │
                   │  (in-process  │
                   │   or HTTP)    │
                   └───────────────┘
                            │
                            ▼
                   ┌───────────────┐
                   │ PolicyEngine  │
                   │               │
                   │ UnifiedPolicy │
                   └───────────────┘
```

## Policy Model

### UnifiedPolicy

Security configuration is split across three sibling files that are loaded into a single Pydantic-validated model (`UnifiedPolicy`):

- `policy.yaml` -- human-owned host-centric policy
- `addons.yaml` -- addon tuning (merged as defaults)
- `agents.yaml` -- machine-managed agent-to-service bindings (merged at load time)

All three are merged by PolicyLoader before compilation.

```yaml
# policy.yaml — host-centric policy
hosts:
  api.openai.com:      { credentials: [openai:*],    rate_limit: 3000 }
  api.anthropic.com:   { credentials: [anthropic:*],  rate_limit: 3000 }
  api.github.com:      { credentials: [github:*],     rate_limit: 300 }
  "*":                 { unknown_credentials: prompt,  rate_limit: 600 }

global_budget: 12000

credentials:
  openai:
    patterns: ["sk-proj-[a-zA-Z0-9_-]{80,}"]
    headers: [authorization, x-api-key]

required: [credential_guard, network_guard, circuit_breaker]
scan_patterns: []
```

```yaml
# addons.yaml — addon tuning (sibling to policy.yaml)
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

The host-centric format in `policy.yaml` compiles to IAM-style rules at load time. Each host entry can include `credentials`, `rate_limit`, `bypass`, and a `rules` escape hatch for full IAM expressiveness. `allowed_hosts` for credential rules are auto-derived from the `hosts` section.

### Policy Layers

Policies are layered (baseline + task):

1. **Baseline Policy**: Default rules loaded from `policy.yaml`
2. **Task Policy**: Optional per-task overrides (additive)

The PolicyEngine merges these, with task policy extending baseline.

### Key Policy Sections

| File | Section | Purpose |
|------|---------|---------|
| `policy.yaml` | `hosts` | Per-host credentials, rate limits, bypass, rules |
| `policy.yaml` | `global_budget` | Global rate limit cap across all hosts |
| `policy.yaml` | `credentials` | Credential detection patterns and header names |
| `policy.yaml` | `required` | Addons that must be active |
| `policy.yaml` | `scan_patterns` | Content scanning rules (URL, headers, body) |
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
                                    └──► PDPCore ──► ...        (yaml)
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

### PolicyLoader

Handles YAML loading and validation:

- Loads policy.yaml at startup
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

Addons process requests in order (defined in `scripts/start-safeyolo.sh`):

**Layer 0 - Infrastructure:**
1. `file_logging` - Structured JSONL file logging setup
2. `memory_monitor` - Process memory and connection tracking
3. `admin_shield` - Blocks proxy access to admin API
4. `agent_relay` - Read-only PDP relay for agent self-service
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
13. `test_context` - X-Test-Context header enforcement for target hosts

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

Scans request/response content for user-defined patterns.

**Data Flow:**
```
request()/response() called
    │
    ├── _maybe_reload_patterns()  ← Check policy_hash, reload if changed
    │         │
    │         └── PolicyClient.get_sensor_config()
    │                    │
    │                    └── {scan_patterns, addons.pattern_scanner.builtin_sets}
    │
    └── _scan_request_content() / _scan_response_content()
              │
              └── Check URL, headers, body based on rule scope
```

**Key Features:**
- Configurable scope: URL, headers, body
- Direction filtering: request, response, or both
- Action modes: block or log
- Builtin pattern sets: `secrets`, `pii`

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
│   ├── agent_relay.py       # Read-only PDP relay for agents
│   ├── loop_guard.py        # Proxy loop detection (Via header)
│   ├── request_id.py        # Request ID generation
│   ├── sse_streaming.py     # SSE/streaming for LLM responses
│   ├── policy_engine.py     # PolicyEngine + PolicyClientConfigurator
│   ├── policy_loader.py     # YAML loading, hot reload
│   ├── budget_tracker.py    # GCRA-based rate limiting
│   ├── network_guard.py     # Access control + rate limiting
│   ├── circuit_breaker.py   # Upstream failure protection
│   ├── credential_guard.py  # Credential routing protection
│   ├── pattern_scanner.py   # Content pattern detection
│   ├── test_context.py      # X-Test-Context header enforcement
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
│   ├── policy.yaml          # Host-centric policy (hosts, credentials, rate limits)
│   ├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
│   └── safe_headers.yaml    # Headers to skip in credential scanning
└── tests/
    ├── test_credential_guard.py
    ├── test_pattern_scanner.py
    ├── test_test_context.py
    ├── test_memory_monitor.py
    ├── test_agent_relay.py
    └── test_integration.py
```

## Design Principles

1. **Single Source of Truth**: All security configuration in UnifiedPolicy
2. **Fail Closed**: PDP unavailable = DENY (never fail open by default)
3. **Separation of Concerns**: Sensors detect, PDP decides, policy defines
4. **No Raw Credentials**: HMAC fingerprints only, never log actual secrets
5. **Hot Reload**: Policy changes apply without restart
6. **Testable**: All components work with mitmproxy test fixtures
