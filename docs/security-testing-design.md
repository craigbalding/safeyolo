# SafeYolo Security Testing Design

## Overview

Tests are organized into two suites using Docker Compose overlays:
- **Proxy tests (base compose):** Credential guard, network guard via sinkhole inspection (~0.25s)
- **Isolation tests (overlay):** Container hardening, network isolation, key isolation

## Quick Start

```bash
cd tests/blackbox

# Run all tests (recommended)
./run-tests.sh

# Proxy tests only
./run-tests.sh --proxy

# Isolation tests only
./run-tests.sh --isolation
```

### Manual compose commands

```bash
# Proxy tests only
docker compose up --build --exit-code-from test-runner

# Isolation tests only
docker compose -f docker-compose.yml -f docker-compose.security.yml up --build --exit-code-from test-runner
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ security-       │     │ isolation-      │     │ key-isolation-  │
│ verifier (CDK)  │     │ verifier        │     │ verifier        │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │ JSON results
                                 ▼
                    ┌─────────────────────────┐
                    │  security-results vol   │
                    │  /cdk-evaluate.json     │
                    │  /isolation.json        │
                    │  /key-isolation.json    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      test-runner        │
                    │  Reads JSON, asserts    │
                    └─────────────────────────┘
```

## Design Principles

1. **Verifiers write, test-runner reads** - All verifiers write structured JSON
2. **No Docker CLI from test containers** - Use volume mounts and compose deps only
3. **Compose orchestrates, pytest asserts** - Let compose handle container lifecycle
4. **Graceful skipping** - Proxy tests skip when sinkhole unavailable; isolation tests skip when JSON files don't exist

## Test Categories

### 1. Proxy Tests (base compose)
- **Files:** `test_credential_guard.py`, `test_network_guard.py`
- **Method:** HTTP through proxy, inspect via sinkhole
- **Runtime:** ~0.25 seconds

### 2. Container Hardening Tests (overlay)
- **File:** `test_runtime_security.py`
- **Verifier:** `security-verifier` runs CDK v1.5.5
- **JSON:** `/security-results/cdk-evaluate.json`
- **Tests:** Non-root UID/GID, no dangerous capabilities, seccomp enabled, not privileged

### 3. Network Isolation Tests (overlay)
- **File:** `test_sandbox_isolation.py`
- **Verifier:** `isolation-verifier` on internal-only network
- **JSON:** `/security-results/isolation.json`
- **Tests:** Direct HTTP/HTTPS blocked, DNS blocked, proxy reachable

### 4. Key Isolation Tests (overlay)
- **File:** `test_key_isolation.py`
- **Verifier:** `key-isolation-verifier` mounts public CA volume
- **JSON:** `/security-results/key-isolation.json`
- **Tests:** Public cert exists, private key NOT in public volume

## JSON Output Formats

### cdk-evaluate.json
```json
{
  "uid": 1000,
  "gid": 1000,
  "capabilities": {
    "has_sys_admin": false,
    "has_sys_module": false,
    "has_dac_read_search": false
  },
  "seccomp_disabled": false,
  "privileged": false,
  "docker_socket_mounted": false,
  "critical_findings_count": 0,
  "all_passed": true
}
```

### isolation.json
```json
{
  "direct_http_blocked": true,
  "direct_https_blocked": true,
  "dns_blocked": true,
  "proxy_reachable": true,
  "all_passed": true
}
```

### key-isolation.json
```json
{
  "public_cert_exists": true,
  "private_key_in_public_volume": false,
  "public_cert_readable": true,
  "private_key_in_cert_content": false,
  "all_passed": true
}
```

## Files

| File | Purpose |
|------|---------|
| `run-tests.sh` | Test runner script (runs both suites) |
| `docker-compose.yml` | Base: safeyolo, sinkhole, test-runner (proxy tests) |
| `docker-compose.security.yml` | Overlay: verifiers, isolation-net (isolation tests) |
| `test_credential_guard.py` | Proxy: credential routing/blocking |
| `test_network_guard.py` | Proxy: access control, rate limiting |
| `test_runtime_security.py` | Isolation: CDK security posture |
| `test_sandbox_isolation.py` | Isolation: network isolation |
| `test_key_isolation.py` | Isolation: private key isolation |
| `conftest.py` | Fixtures (sinkhole, proxy_client, etc.) |

## Why This Design

### Problem with original approach
Tests used `subprocess.run(["docker", ...])` but test-runner has no Docker CLI.

### Solution
- Verifiers run as separate containers with compose dependencies
- Each verifier writes structured JSON results
- Test-runner reads JSON and makes assertions
- No Docker CLI, no Docker socket mount needed

### Benefits
- **Fast proxy tests** - No verifier overhead when not needed
- **GHA compatible** - Works in CI with same commands
- **Transparent** - Verifier output visible in compose logs
- **Maintainable** - JSON format is stable, easy to extend
- **Graceful skipping** - Each suite skips cleanly when run alone

## CDK (Container Development Kit)

**Repo:** https://github.com/cdk-team/CDK
**Version:** v1.5.5 (Feb 2025)
**Hash verification:** `202f3fc5babfcb64b3c1d99bf24563f1bbce31cbbf4216a83116c8f6149efe80`

CDK `evaluate` command reports:
- Container runtime, user namespaces
- Available capabilities (flags dangerous ones as "Critical")
- Seccomp status
- Privileged mode detection
- Docker socket detection
