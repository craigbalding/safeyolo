# SafeYolo Addon Tests

Unit and integration tests for native mitmproxy addons.

## Test Files

- `conftest.py` - Pytest fixtures using `mitmproxy.test.tflow`
- `test_credential_guard.py` - Credential detection, host authorization, blocking, allowlist
- `test_rate_limiter.py` - GCRA algorithm, per-domain limits, 429 responses
- `test_circuit_breaker.py` - State transitions, failure detection, recovery
- `test_admin_api.py` - REST endpoints, mode switching, stats, allowlist API
- `test_pattern_scanner.py` - Regex patterns, secret detection, jailbreak detection
- `test_policy.py` - Policy engine, domain/client rules, hot reload
- `test_prompt_injection.py` - ML classifiers (DeBERTa/Ollama), blocking, async verification
- `test_integration.py` - Addon chain behavior, metadata sharing

## Running Tests

### Option 1: Docker (recommended)

mitmproxy has complex native dependencies (aioquic, bpf-linker for eBPF).
Easiest to run tests in the mitmproxy Docker image:

```bash
# From safeyolo/ directory
docker run --rm -v $(pwd):/app -w /app \
  mitmproxy/mitmproxy \
  pip install pytest && pytest tests/ -v
```

### Option 2: Local Install

Requires:
- C compiler (for aioquic crypto)
- Rust + bpf-linker (for mitmproxy-linux eBPF)

```bash
pip install mitmproxy pytest
pytest tests/ -v
```

## Test Coverage

| Addon | Tests | Coverage |
|-------|-------|----------|
| credential_guard | 16 | Pattern matching, host auth, blocking, allowlist, temp allowlist, stats |
| rate_limiter | 21 | GCRA algorithm, config, hot reload, blocking, 429 response, wildcard domains |
| circuit_breaker | 18 | State machine, blocking, exponential backoff, manual control, recovery |
| admin_api | 17 | REST endpoints, mode switching, stats aggregation, allowlist management |
| pattern_scanner | 32 | Regex patterns, secret detection, jailbreak detection, redaction |
| policy | 28 | Policy engine, domain/client rules, hot reload, bypass lists, wildcards |
| prompt_injection | 21 | DeBERTa/Ollama classifiers, blocking, confidence thresholds, async verification |
| integration | 15 | Addon chain behavior, metadata sharing, realistic multi-addon scenarios |

**Total: 168 tests** across 8 test suites

## Adding Tests

Tests use mitmproxy's test utilities:
- `mitmproxy.test.tflow` - Create test HTTP flows
- `mitmproxy.test.taddons` - Test addon context

Example:
```python
def test_blocks_credential(credential_guard, make_flow):
    flow = make_flow(
        method="POST",
        url="https://evil.com/api",
        content='{"key": "sk-abc123xyz456def789ghijklmno"}',
        headers={"Content-Type": "application/json"},
    )

    credential_guard.request(flow)

    assert flow.response.status_code == 403
    assert flow.metadata["blocked_by"] == "credential-guard"
```
