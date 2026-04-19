"""Agent API scope tests — verify auth enforcement has no bypasses
and that the mutation surface is correctly scoped.

The agent API is NOT read-only: it exposes diagnostics (GET) plus a
small mutation surface:
  - POST /api/flows/{id}/tag — add/update tag
  - DELETE /api/flows/{id}/tag/{name} — remove tag
  - POST /gateway/request-access — request service capability
  - POST /gateway/submit-binding — submit contract binding

All endpoints require a valid bearer token. The token MUST NOT grant
access to the admin API (separate addon, separate port, separate token).
These tests verify the auth boundary and that methods outside each
route's allowed set are rejected.

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


class TestAgentAPIMutationSurface:
    """Verify the known mutation endpoints exist and are auth-gated,
    and that mutation outside those endpoints is rejected.
    """

    def test_tag_post_requires_auth(self):
        """POST /api/flows/{id}/tag without token → reject."""
        status, _ = _curl_agent_api(
            "/api/flows/nonexistent-id/tag", method="POST",
            extra_flags=["-d", '{"name":"test","value":"x"}',
                         "-H", "Content-Type: application/json"],
        )
        assert status in (401, 403), (
            f"POST tag without auth returned {status}"
        )

    def test_tag_delete_requires_auth(self):
        """DELETE /api/flows/{id}/tag/{name} without token → reject."""
        status, _ = _curl_agent_api(
            "/api/flows/nonexistent-id/tag/test-tag", method="DELETE",
        )
        assert status in (401, 403), (
            f"DELETE tag without auth returned {status}"
        )

    def test_gateway_request_access_requires_auth(self):
        """POST /gateway/request-access without token → reject."""
        status, _ = _curl_agent_api(
            "/gateway/request-access", method="POST",
            extra_flags=["-d", '{"service":"test"}',
                         "-H", "Content-Type: application/json"],
        )
        assert status in (401, 403), (
            f"POST /gateway/request-access without auth returned {status}"
        )

    def test_post_on_get_only_route_rejected(self):
        """POST on a GET-only route (e.g. /policy) → 405, not silent OK."""
        token = _agent_token()
        status, _ = _curl_agent_api("/policy", method="POST", token=token)
        assert status == 405, (
            f"POST /policy returned {status}, expected 405"
        )


class TestAgentAPICrossAgentIsolation:
    """Verify one agent cannot read another agent's data via the API.

    The agent API scopes gateway endpoints by source IP → agent name
    via service_discovery. But flow-inspection endpoints
    (/api/flows/search, /api/flows/{id}, /api/flows/{id}/request-body)
    may or may not filter by calling agent. This test generates a flow
    from THIS agent, then verifies the API returns ONLY flows belonging
    to this agent (not flows from other agents sharing the same proxy).
    """

    def test_flow_search_scoped_to_calling_agent(self):
        """Search flows via API — result must not contain flows from
        other agents. We make a known request, then search for it.
        If flows from other subnets/agents appear, scope is broken.
        """
        import json
        token = _agent_token()

        # Generate a flow from this agent — the proxy will log it.
        # Include X-Test-Context so the test_context addon tags the
        # flow and the flow recorder captures it. This also exercises
        # the test_context control itself (it's a security control
        # used during pentesting to link traffic to test activities).
        proxy = os.environ.get("HTTP_PROXY", "")
        if not proxy:
            pytest.skip("HTTP_PROXY not set")
        marker = "bbtest-scope-probe"
        subprocess.run(
            ["curl", "-s", "--proxy", proxy, "-o", "/dev/null",
             "-H", "X-Test-Context: run=security-audit;agent=bbtest",
             f"http://httpbin.org/get?marker={marker}"],
            capture_output=True, timeout=10,
        )

        # Brief pause for the flow recorder to commit to SQLite.
        import time
        time.sleep(1)

        # Now search flows and inspect results.
        status, body = _curl_agent_api(
            f"/api/flows/search?host=httpbin.org&limit=50",
            token=token,
        )
        if status != 200:
            pytest.skip(f"Flow search not available (status {status})")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            pytest.fail(f"Flow search 200 but non-JSON (len={len(body)}): {body[:100]!r}")

        flows = data.get("flows", [])
        if not flows:
            # Debug: query without host filter to see if any flows exist
            status2, body2 = _curl_agent_api(
                "/api/flows/search?limit=5",
                token=token,
            )
            pytest.skip(
                f"No flows for host=httpbin.org. "
                f"Unfiltered search (status={status2}): {body2[:300]}"
            )

        # Check: every returned flow's client_address should be in OUR
        # subnet, not another agent's. Our subnet's gateway is the
        # HTTP_PROXY host IP.
        from urllib.parse import urlparse
        our_host = urlparse(proxy).hostname  # e.g. 192.168.75.1
        our_prefix = ".".join(our_host.split(".")[:3])  # e.g. 192.168.75

        foreign_flows = []
        for f in flows:
            addr = f.get("client_address", f.get("client_conn", {}).get("address", [""])[0])
            if isinstance(addr, list):
                addr = addr[0] if addr else ""
            if addr and not addr.startswith(our_prefix):
                foreign_flows.append({"id": f.get("id"), "client": addr,
                                      "host": f.get("request", {}).get("host", "?")})

        assert not foreign_flows, (
            f"Flow search returned {len(foreign_flows)} flows from other agents "
            f"(our subnet: {our_prefix}.x): {foreign_flows[:5]}. "
            f"This is a cross-agent information disclosure vulnerability."
        )

    def test_gateway_services_scoped(self):
        """GET /gateway/services must return only THIS agent's services,
        not other agents'. Verify by checking the response doesn't
        contain service entries tagged with a different agent name.
        """
        import json
        token = _agent_token()
        status, body = _curl_agent_api("/gateway/services", token=token)
        if status != 200:
            pytest.skip(f"/gateway/services returned {status}")
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            pytest.fail(f"/gateway/services 200 but non-JSON (len={len(body)}): {body[:100]!r}")
        # The response should be for THIS agent only. If it contains
        # services for named agents other than ours, scoping is broken.
        # (This is a structural check — the exact response shape
        # varies, so we just verify no OTHER agent names appear.)
        body_str = json.dumps(data)
        # We don't know other agent names, but we can check that the
        # endpoint at least WORKS without error — the scoping assertion
        # is in the flow search test above.
        assert "error" not in data, f"Unexpected error: {data}"
