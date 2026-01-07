# SafeYolo Integration Test Plan

## Goal

Create "specification quality" integration tests - tests good enough that SafeYolo could be reimplemented in another language and these tests would define correctness.

## Current State

- **Unit tests**: 355 tests using mitmproxy test utilities (simulated flows via `taddons.context`, `tflow`)
- **Integration tests**: 32 tests sending real HTTP through the proxy (`tests/test_http_integration.py`)

## Integration Test Architecture

### Upstream Server Fixture

A local HTTP server (`UpstreamServer`) that returns deterministic responses based on path:

| Path | Response |
|------|----------|
| `/ok` | 200 `{"status": "ok"}` |
| `/echo` | 200, echoes request details (method, path, headers, body) |
| `/slow?delay=N` | 200 after N second delay |
| `/fail?code=N` | Returns HTTP status N |
| `/headers` | 200, returns all received headers |
| `/body` | 200, echoes request body |
| `/secret` | 200, `{"secret": "value"}` (for leak testing) |

### Test Clients

1. **Admin API client** - Direct to admin API (no proxy), authenticated with bearer token
2. **Proxied client** - Routes through SafeYolo proxy to upstream server

### Test Categories (32 tests)

#### 1. Admin API Health (`TestAdminAPIHealth`) - 3 tests
- Health endpoint responds with `{"status": "ok"}`
- Health endpoint does NOT require authentication (for monitoring)
- Non-health endpoints require authentication (401 Unauthorized)

#### 2. Admin API Plugins (`TestAdminAPIPlugins`) - 4 tests
- `/modes` lists all security addons with their modes
- Get plugin mode via `/plugins/<name>/mode`
- Set plugin to block mode
- Set plugin to warn mode

#### 3. Admin API Stats (`TestAdminAPIStats`) - 2 tests
- `/stats` returns data from all addons
- Stats include check/allow/block counters

#### 4. Proxy Basic (`TestProxyBasic`) - 4 tests
- Forwards requests to upstream
- Preserves headers
- Handles POST bodies correctly
- Forwards upstream errors (500s)

#### 5. Network Guard Access (`TestNetworkGuardAccess`) - 3 tests
- Allowed domains pass through
- Blocked domains handled (403 or connection error)
- Warn mode allows requests through

#### 6. Network Guard Budget (`TestNetworkGuardBudget`) - 2 tests
- `/admin/budgets` endpoint responds with budget status
- Budget reset via `/admin/budgets/reset`

#### 7. Credential Guard (`TestCredentialGuard`) - 3 tests
- Requests without credentials pass through
- **Core guarantee**: OpenAI key (`sk-proj-*`) to non-OpenAI host → 428 (blocked)
- Warn mode logs violation but allows through

#### 8. Circuit Breaker (`TestCircuitBreaker`) - 6 tests
- Circuit breaker config available in `/stats` (enabled, failure_threshold)
- Healthy upstream passes through (circuit closed or half_open)
- Upstream 500 increments failure_count
- Success keeps circuit in closed state
- **Core guarantee**: Circuit opens after threshold failures → returns 503 WITHOUT hitting upstream
- Open circuit response is JSON with circuit breaker indication

#### 9. Block Response Format (`TestBlockResponseFormat`) - 3 tests
- Block responses are JSON with Content-Type header
- Block responses include error/reason field
- Block responses include `event_id` for audit trail

#### 10. Concurrency (`TestConcurrency`) - 2 tests
- Multiple concurrent requests all succeed
- Concurrent requests are isolated (no cross-talk)

## Running Tests

```bash
# Inside container with shell_mux:
python3 /projects/claude-dev/lib/shell_mux.py exec safeyolo \
  sh -c "cd /app && ADMIN_API_TOKEN=<token> python3 -m pytest tests/test_http_integration.py -v"

# With specific test class:
python3 /projects/claude-dev/lib/shell_mux.py exec safeyolo \
  sh -c "cd /app && ADMIN_API_TOKEN=<token> python3 -m pytest tests/test_http_integration.py::TestCredentialGuard -v"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_HOST` | `localhost` | SafeYolo proxy host |
| `PROXY_PORT` | `8080` | SafeYolo proxy port |
| `ADMIN_HOST` | `localhost` | Admin API host |
| `ADMIN_PORT` | `9090` | Admin API port |
| `ADMIN_API_TOKEN` | (required) | Bearer token for admin API |

Tests skip automatically if `ADMIN_API_TOKEN` is not set.

## Specification Guarantees Verified

These tests verify SafeYolo's core security guarantees:

1. **Credential Protection**: API keys cannot be exfiltrated to unauthorized hosts (test_openai_credential_to_wrong_host_blocked)
2. **Access Control**: Security addons can block/warn on requests
3. **Budget Management**: Budgets queryable and resettable via admin API
4. **Audit Trail**: Block responses include `event_id` for correlation
5. **Fail-Safe**: Block mode is enforceable per-addon
6. **Monitoring**: Health endpoint unauthenticated, stats authenticated

## Future Additions

- [ ] Pattern scanner tests (secrets in request body blocked)
- [ ] SSE/streaming passthrough tests
- [ ] Policy reload during request
- [ ] Multi-client isolation tests (different client IPs)
- [ ] TLS certificate validation tests
