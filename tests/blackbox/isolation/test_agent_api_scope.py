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
    header_input = None
    if token is not None:
        cmd.extend(["--header", "@-"])
        header_input = f"Authorization: Bearer {token}\n"
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.append(f"http://_safeyolo.proxy.internal{path}")
    try:
        result = subprocess.run(
            cmd,
            input=header_input,
            capture_output=True,
            text=True,
            timeout=10,
        )
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
