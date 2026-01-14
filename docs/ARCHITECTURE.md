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

All security configuration lives in a single Pydantic-validated model (`UnifiedPolicy`):

```yaml
# baseline.yaml
metadata:
  version: "1.0"
  description: "Baseline security policy"

permissions:
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]

budgets:
  openai-requests:
    resource: "api.openai.com/*"
    limit: 1000
    window: 3600

credential_rules:
  - name: openai
    patterns:
      - "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"
      - "sk-proj-[a-zA-Z0-9_-]{80,}"
    allowed_hosts:
      - api.openai.com
    header_names:
      - authorization
      - x-api-key

scan_patterns:
  - name: internal-ids
    pattern: "PROJ-[0-9]{5}"
    target: request
    scope: [body, url]
    action: block

addons:
  credential_guard:
    enabled: true
  pattern_scanner:
    builtin_sets: [secrets]

clients:
  "admin-*":
    bypass: [pattern-scanner]
```

### Policy Layers

Policies are layered (baseline + task):

1. **Baseline Policy**: Default rules loaded from `baseline.yaml`
2. **Task Policy**: Optional per-task overrides (additive)

The PolicyEngine merges these, with task policy extending baseline.

### Key Policy Sections

| Section | Purpose |
|---------|---------|
| `permissions` | Allow/deny rules for actions on resources |
| `budgets` | Rate limits with sliding windows |
| `credential_rules` | Credential detection patterns + allowed destinations |
| `scan_patterns` | Content scanning rules (URL, headers, body) |
| `addons` | Per-addon configuration and enablement |
| `clients` | Client-specific bypasses based on IP/identity |
| `domains` | Domain-specific overrides |

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

- Loads baseline.yaml at startup
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

Addons process requests in order (defined in `main.py`):

1. `request_id` - Assigns unique ID to each request
2. `network_guard` - Domain allowlist enforcement
3. `credential_guard` - Credential routing validation
4. `pattern_scanner` - Content pattern detection
5. `circuit_breaker` - Upstream failure protection
6. `metrics` - Prometheus metrics collection

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

## File Structure

```
safeyolo/
├── addons/
│   ├── base.py              # SecurityAddon base class
│   ├── credential_guard.py  # Credential routing protection
│   ├── pattern_scanner.py   # Content pattern detection
│   ├── network_guard.py     # Domain allowlist
│   ├── circuit_breaker.py   # Upstream failure protection
│   ├── policy_engine.py     # UnifiedPolicy model, PolicyEngine
│   ├── policy_loader.py     # YAML loading, PolicyLoader
│   ├── detection/
│   │   ├── credentials.py   # Credential detection logic
│   │   └── patterns.py      # Pattern compilation, builtin sets
│   └── utils.py             # Shared utilities
├── pdp/
│   ├── __init__.py          # Public API exports
│   ├── core.py              # PDPCore - main PDP implementation
│   ├── client.py            # PolicyClient interface + implementations
│   ├── schemas.py           # HttpEvent, PolicyDecision Pydantic models
│   └── app.py               # FastAPI HTTP adapter
├── config/
│   ├── baseline.yaml        # Default policy
│   └── safe_headers.yaml    # Headers to skip in credential scanning
└── tests/
    ├── test_credential_guard.py
    ├── test_pattern_scanner.py
    └── test_integration.py
```

## Design Principles

1. **Single Source of Truth**: All security configuration in UnifiedPolicy
2. **Fail Closed**: PDP unavailable = DENY (never fail open by default)
3. **Separation of Concerns**: Sensors detect, PDP decides, policy defines
4. **No Raw Credentials**: HMAC fingerprints only, never log actual secrets
5. **Hot Reload**: Policy changes apply without restart
6. **Testable**: All components work with mitmproxy test fixtures
