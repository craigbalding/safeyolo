"""Agent API scope tests — verify the token grants read-only access
and that auth enforcement has no bypasses.

Runs from inside the sandbox (same as test_vm_isolation.py). The
agent API is reached via `http://_safeyolo.proxy.internal/` — a
virtual hostname intercepted by the mitmproxy-based proxy. The
token lives at /app/agent_token.
"""

import os
import subprocess

import pytest


def _agent_token() -> str:
    """Read agent API token from the expected location."""
    path = "/app/agent_token"
    if not os.path.isfile(path):
        pytest.skip("Agent token not present at /app/agent_token")
    with open(path) as f:
        return f.read().strip()


def _curl_agent_api(path: str, method: str = "GET",
                    token: str | None = None,
                    extra_flags: list[str] | None = None) -> tuple[int, str]:
    """Hit the agent API and return (http_status_code, body)."""
    cmd = [
        "curl", "-s",
        "-X", method,
        "-o", "/dev/stderr",   # body → stderr so we can capture it
        "-w", "%{http_code}",  # status → stdout
        "--max-time", "5",
    ]
    if token is not None:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.append(f"http://_safeyolo.proxy.internal{path}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
    body = result.stderr
    return status, body


class TestAgentAPIAuth:
    """Verify auth enforcement on the agent API."""

    def test_health_with_valid_token(self):
        """Positive case: valid token → 200."""
        status, body = _curl_agent_api("/health", token=_agent_token())
        assert status == 200, f"Expected 200, got {status}: {body}"

    def test_health_without_token(self):
        """Missing Authorization header → must reject."""
        status, _ = _curl_agent_api("/health")
        assert status in (401, 403), f"Expected 401/403 without token, got {status}"

    def test_health_with_wrong_token(self):
        """Incorrect bearer token → must reject (no partial match)."""
        status, _ = _curl_agent_api("/health", token="wrong-token-value")
        assert status in (401, 403), f"Expected 401/403 with wrong token, got {status}"

    def test_health_with_empty_bearer(self):
        """Empty bearer → must reject."""
        status, _ = _curl_agent_api("/health", token="")
        assert status in (401, 403), f"Expected 401/403 with empty bearer, got {status}"

    def test_every_get_route_requires_auth(self):
        """Spot-check all GET routes: without a token, every one rejects."""
        routes = [
            "/health", "/status", "/policy", "/budgets",
            "/config", "/memory", "/agents", "/circuits",
        ]
        for route in routes:
            status, _ = _curl_agent_api(route)
            assert status in (401, 403), (
                f"GET {route} returned {status} without token — auth bypass"
            )


class TestAgentAPIMethodRestriction:
    """Verify only expected HTTP methods are accepted."""

    def test_put_rejected(self):
        """PUT on a read route → 405."""
        status, _ = _curl_agent_api("/health", method="PUT",
                                    token=_agent_token())
        assert status == 405, f"PUT /health returned {status}, expected 405"

    def test_patch_rejected(self):
        """PATCH on a read route → 405."""
        status, _ = _curl_agent_api("/health", method="PATCH",
                                    token=_agent_token())
        assert status == 405, f"PATCH /health returned {status}, expected 405"

    def test_delete_on_nonexistent_route(self):
        """DELETE on an arbitrary path → 404 or 405, not 200."""
        status, _ = _curl_agent_api("/nonexistent", method="DELETE",
                                    token=_agent_token())
        assert status in (404, 405), (
            f"DELETE /nonexistent returned {status}, expected 404/405"
        )
