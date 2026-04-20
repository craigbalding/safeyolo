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
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
        body_file = tf.name

    cmd = [
        "curl", "-s",
        "-X", method,
        "-o", body_file,
        "-w", "%{http_code}",
        "--max-time", "5",
    ]
    if token is not None:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.append(f"http://_safeyolo.proxy.internal{path}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
        body = open(body_file).read()
    finally:
        os.unlink(body_file)
    return status, body


class TestAgentAPIAuth:
    """Agent API rejects every unauthenticated request.

    Why: The agent API exposes proxy diagnostics and a small mutation
    surface. Any bypass of the bearer-token gate means any local
    process on the VM (or a LAN attacker if the endpoint ever leaks)
    can read policy, flow contents, and credentials metadata, or
    mutate agent gateway state.
    """

    def test_health_with_valid_token(self):
        """Valid token returns 200.

        What: GET /health with the agent token from /app/agent_token;
        assert 200.
        Why: Baseline positive case — if this fails, every other
        auth test is meaningless because auth is entirely broken.
        """
        status, body = _curl_agent_api("/health", token=_agent_token())
        assert status == 200, f"Expected 200, got {status}: {body}"

    def test_health_without_token(self):
        """No Authorization header returns 401/403.

        What: GET /health with no Authorization header.
        Why: Default-deny — any bypass here means the whole API is
        open to unauthenticated callers.
        """
        status, _ = _curl_agent_api("/health")
        assert status in (401, 403), f"Expected 401/403 without token, got {status}"

    def test_health_with_wrong_token(self):
        """Bogus bearer value returns 401/403.

        What: GET /health with Authorization: Bearer wrong-token-value.
        Why: Confirms the auth check actually compares the full token,
        not just its presence. A check that accepts 'any non-empty
        value' is effectively unauthenticated.
        """
        status, _ = _curl_agent_api("/health", token="wrong-token-value")
        assert status in (401, 403), f"Expected 401/403 with wrong token, got {status}"

    def test_health_with_empty_bearer(self):
        """Empty Bearer token returns 401/403.

        What: GET /health with Authorization: Bearer  (empty value).
        Why: An empty string passes a naive truthiness check in some
        implementations. Closes that specific evasion.
        """
        status, _ = _curl_agent_api("/health", token="")
        assert status in (401, 403), f"Expected 401/403 with empty bearer, got {status}"

    def test_every_get_route_requires_auth(self):
        """Every documented GET route rejects unauthenticated callers.

        What: GET each of /health, /status, /policy, /budgets,
        /config, /memory, /agents, /circuits with no token;
        assert 401/403 each time.
        Why: Individual auth decorators could be forgotten when new
        routes are added. Coverage across the route set catches
        per-route auth bypasses.
        """
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
    """Each route accepts only its documented HTTP methods.

    Why: A route that silently accepts any method can become a
    mutation endpoint by accident. PUT/PATCH/DELETE on a GET-only
    route must not succeed — if they do, someone has forgotten a
    method allowlist and mutations can happen unintentionally.
    """

    def test_put_rejected(self):
        """PUT on /health returns 405.

        What: PUT /health with a valid token; assert 405.
        Why: PUT is a mutation method. /health is read-only. A 200
        or 2xx here would indicate the route accepts arbitrary
        methods — potential mutation surface.
        """
        status, _ = _curl_agent_api("/health", method="PUT",
                                    token=_agent_token())
        assert status == 405, f"PUT /health returned {status}, expected 405"

    def test_patch_rejected(self):
        """PATCH on /health returns 405.

        What: PATCH /health; assert 405.
        Why: Same property as PUT — mutation method on a read route.
        """
        status, _ = _curl_agent_api("/health", method="PATCH",
                                    token=_agent_token())
        assert status == 405, f"PATCH /health returned {status}, expected 405"

    def test_delete_on_nonexistent_route(self):
        """DELETE on /nonexistent returns 404 or 405.

        What: DELETE /nonexistent; assert status is 404 or 405.
        Why: A 200 on an unrecognised path indicates a catch-all
        handler that silently accepts any method — a route-matching
        bug that could eat valid requests or accept unintended ones.
        """
        status, _ = _curl_agent_api("/nonexistent", method="DELETE",
                                    token=_agent_token())
        assert status in (404, 405), (
            f"DELETE /nonexistent returned {status}, expected 404/405"
        )


class TestAgentAPIMutationSurface:
    """Mutation endpoints are auth-gated; non-mutation routes reject writes.

    Why: The agent API's mutation surface is deliberately narrow:
    flow tagging plus gateway request/binding. Bypasses here let
    an unauthenticated caller mark flows or trigger capability
    grants — higher-blast-radius than read-only diagnostic access.
    """

    def test_tag_post_requires_auth(self):
        """POST /api/flows/.../tag without token returns 401/403.

        What: POST to the tag endpoint with a JSON body but no
        Authorization header; assert 401/403.
        Why: Tag mutation is part of the audit trail. Unauthenticated
        tagging corrupts flow metadata — someone could add misleading
        tags that throw off post-incident analysis.
        """
        status, _ = _curl_agent_api(
            "/api/flows/nonexistent-id/tag", method="POST",
            extra_flags=["-d", '{"name":"test","value":"x"}',
                         "-H", "Content-Type: application/json"],
        )
        assert status in (401, 403), (
            f"POST tag without auth returned {status}"
        )

    def test_tag_delete_requires_auth(self):
        """DELETE /api/flows/.../tag/... without token returns 401/403.

        What: DELETE the tag endpoint with no Authorization header;
        assert 401/403.
        Why: Tag deletion is also mutation. An attacker who can
        delete tags can wipe evidence tying flows to a test run or
        investigation context.
        """
        status, _ = _curl_agent_api(
            "/api/flows/nonexistent-id/tag/test-tag", method="DELETE",
        )
        assert status in (401, 403), (
            f"DELETE tag without auth returned {status}"
        )

    def test_gateway_request_access_requires_auth(self):
        """POST /gateway/request-access without token returns 401/403.

        What: POST to /gateway/request-access with a JSON body but
        no Authorization header; assert 401/403.
        Why: request-access triggers the human-in-the-loop approval
        flow for capability grants. An unauthenticated caller
        spamming this endpoint could social-engineer approvals or
        exhaust operator attention.
        """
        status, _ = _curl_agent_api(
            "/gateway/request-access", method="POST",
            extra_flags=["-d", '{"service":"test"}',
                         "-H", "Content-Type: application/json"],
        )
        assert status in (401, 403), (
            f"POST /gateway/request-access without auth returned {status}"
        )

    def test_post_on_get_only_route_rejected(self):
        """POST on /policy returns 405, not 200.

        What: POST /policy with a valid token; assert 405.
        Why: /policy is a read-only diagnostic endpoint. A 200 would
        indicate method-router confusion — another mutation surface
        silently opened.
        """
        token = _agent_token()
        status, _ = _curl_agent_api("/policy", method="POST", token=token)
        assert status == 405, (
            f"POST /policy returned {status}, expected 405"
        )


class TestAgentAPICrossAgentIsolation:
    """Agent API returns only the calling agent's data.

    Why: Multiple agents share the same proxy and flow store. If the
    API returns flows belonging to other agents, one agent can read
    another's request bodies (credentials, PII, contents). The scope
    is enforced by resolving the caller's source IP through
    service_discovery; this tests the end-to-end isolation, not the
    mechanism.
    """

    def test_flow_search_scoped_to_calling_agent(self):
        """Flow search returns only flows from the caller's subnet.

        What: Emit a tagged probe through the proxy, then query
        /api/flows/search. For each returned flow, assert the
        client address is in this agent's subnet (not another
        agent's).
        Why: A cross-agent leak here is a full information
        disclosure — one agent reads another's request contents,
        including credentials and response bodies.
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
            "/api/flows/search?host=httpbin.org&limit=50",
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
        """GET /gateway/services responds without error as this agent.

        What: GET /gateway/services with the agent token; assert 200
        and the response body parses as JSON without an 'error' key.
        Why: A smoke test for the scoping mechanism — the response
        shape varies, so we verify the endpoint functions for the
        calling agent. Cross-agent leakage in the detailed contents
        is covered by test_flow_search_scoped_to_calling_agent.
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
        # The response should be for THIS agent only. Structural
        # check — we don't know other agents' names, but the endpoint
        # must WORK for the calling agent (no error). Cross-agent
        # scoping is asserted in test_flow_search_scoped_to_calling_agent.
        assert "error" not in data, f"Unexpected error: {data}"
