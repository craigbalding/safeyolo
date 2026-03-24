"""Tests for addons/service_gateway.py — Service Gateway addon (v2)."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from service_gateway import (
    SGW_TOKEN_PREFIX,
    GrantEntry,
    ServiceGateway,
    _mint_grant_id,
    mint_gateway_token,
)
from service_loader import (
    Capability,
    CapabilityRoute,
    RiskyRoute,
    init_service_registry,
)
from vault import Vault, VaultCredential

# --- Fixtures ---


@pytest.fixture
def gateway():
    return ServiceGateway()


@pytest.fixture
def services_dir(tmp_path):
    """Create temp services dir with v2 minifuse and gmail definitions."""
    svc_dir = tmp_path / "services"
    svc_dir.mkdir()
    (svc_dir / "minifuse.yaml").write_text("""
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-API-Key
capabilities:
  reader:
    description: "Read-only access"
    routes:
      - methods: [GET]
        path: "/v1/**"
risky_routes:
  - path: "/v1/feeds"
    methods: [DELETE]
    description: "Delete feed"
    tactics: [impact]
    irreversible: true
""")
    (svc_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
default_host: gmail.googleapis.com
auth:
  type: bearer
  scheme: Bearer
  refresh_on_401: true
capabilities:
  search_headers:
    description: "Search message metadata"
    routes:
      - methods: [GET]
        path: "/gmail/v1/users/me/messages"
  read_and_send:
    description: "Full read/write access"
    routes:
      - methods: [GET, POST]
        path: "/gmail/v1/users/me/messages/**"
      - methods: [GET]
        path: "/gmail/v1/users/me/threads/**"
risky_routes:
  - group: "Mail routing"
    description: "Controls where email goes"
    tactics: [exfiltration, persistence]
    routes:
      - path: "/gmail/v1/users/me/settings/filters/**"
        enables: [defense_evasion]
      - path: "/gmail/v1/users/me/settings/forwardingAddresses/**"
        methods: [POST, PUT]
""")
    return svc_dir


@pytest.fixture
def registry(services_dir):
    return init_service_registry(services_dir)


@pytest.fixture
def vault_obj(tmp_path):
    vault_path = tmp_path / "vault.yaml.enc"
    v = Vault(vault_path)
    v.unlock("test-pass")
    v.store(VaultCredential(name="minifuse-test", type="api_key", value="real-api-key-123"))
    v.store(VaultCredential(name="gmail-oauth2", type="oauth2", value="ya29.real-token"))
    return v


@pytest.fixture
def configured_gateway(gateway, registry, vault_obj):
    """Gateway with tokens minted for test agent."""
    gateway._host_map = {
        "api.minifuse.io": "minifuse",
        "gmail.googleapis.com": "gmail",
    }
    env = gateway.mint_tokens(
        {
            "test-agent": {
                "minifuse": {"capability": "reader", "token": "minifuse-test"},
                "gmail": {"capability": "read_and_send", "token": "gmail-oauth2", "account": "operator"},
            },
        }
    )
    return gateway, env, registry, vault_obj


def _mock_ctx():
    """Create a mock ctx with gateway_enabled=True."""
    mock = MagicMock()
    mock.options.gateway_enabled = True
    return mock


# --- Token Extraction Tests ---


class TestTokenExtraction:
    def test_bearer_sgw_token(self, make_flow, gateway):
        token = f"{SGW_TOKEN_PREFIX}{'a' * 64}"
        flow = make_flow(headers={"authorization": f"Bearer {token}"})
        result = gateway._extract_sgw_token(flow)
        assert result == token

    def test_raw_sgw_token(self, make_flow, gateway):
        token = f"{SGW_TOKEN_PREFIX}{'b' * 64}"
        flow = make_flow(headers={"authorization": token})
        result = gateway._extract_sgw_token(flow)
        assert result == token

    def test_non_sgw_ignored(self, make_flow, gateway):
        flow = make_flow(headers={"authorization": "Bearer sk-openai-key"})
        result = gateway._extract_sgw_token(flow)
        assert result is None

    def test_no_auth_header(self, make_flow, gateway):
        flow = make_flow()
        result = gateway._extract_sgw_token(flow)
        assert result is None

    def test_case_insensitive_bearer(self, make_flow, gateway):
        token = f"{SGW_TOKEN_PREFIX}{'c' * 64}"
        flow = make_flow(headers={"authorization": f"bearer {token}"})
        result = gateway._extract_sgw_token(flow)
        assert result == token


# --- Capability Route Matching Tests ---


class TestCapabilityRouteMatching:
    def test_allow_get(self, gateway):
        cap = Capability(
            name="reader",
            routes=[
                CapabilityRoute(methods=["GET"], path="/v1/**"),
            ],
        )
        assert gateway._evaluate_capability_routes("GET", "/v1/data", cap) is True

    def test_route_not_in_capability(self, gateway):
        cap = Capability(
            name="reader",
            routes=[
                CapabilityRoute(methods=["GET"], path="/v1/**"),
            ],
        )
        assert gateway._evaluate_capability_routes("POST", "/v1/data", cap) is False
        assert gateway._evaluate_capability_routes("GET", "/v2/data", cap) is False

    def test_method_wildcard(self, gateway):
        cap = Capability(
            name="full",
            routes=[
                CapabilityRoute(methods=["*"], path="/api/**"),
            ],
        )
        assert gateway._evaluate_capability_routes("GET", "/api/test", cap) is True
        assert gateway._evaluate_capability_routes("POST", "/api/test", cap) is True
        assert gateway._evaluate_capability_routes("DELETE", "/api/test", cap) is True

    def test_empty_routes_denies(self, gateway):
        cap = Capability(name="empty", routes=[])
        assert gateway._evaluate_capability_routes("GET", "/anything", cap) is False

    def test_multiple_routes(self, gateway):
        cap = Capability(
            name="mixed",
            routes=[
                CapabilityRoute(methods=["GET"], path="/v1/messages/**"),
                CapabilityRoute(methods=["POST"], path="/v1/messages/**"),
                CapabilityRoute(methods=["GET"], path="/v1/threads/**"),
            ],
        )
        assert gateway._evaluate_capability_routes("GET", "/v1/messages/123", cap) is True
        assert gateway._evaluate_capability_routes("POST", "/v1/messages/send", cap) is True
        assert gateway._evaluate_capability_routes("GET", "/v1/threads/456", cap) is True
        assert gateway._evaluate_capability_routes("DELETE", "/v1/messages/123", cap) is False


# --- Risky Route Matching Tests ---


class TestRiskyRouteMatching:
    def test_match_found(self, gateway):
        routes = [
            RiskyRoute(path="/api/delete/**", methods=["DELETE"], tactics=["impact"]),
        ]
        match = gateway._match_risky_route("DELETE", "/api/delete/123", routes)
        assert match is not None
        assert match.tactics == ["impact"]

    def test_no_match(self, gateway):
        routes = [
            RiskyRoute(path="/api/delete/**", methods=["DELETE"], tactics=["impact"]),
        ]
        match = gateway._match_risky_route("GET", "/api/read/123", routes)
        assert match is None

    def test_method_mismatch(self, gateway):
        routes = [
            RiskyRoute(path="/api/**", methods=["DELETE"], tactics=["impact"]),
        ]
        match = gateway._match_risky_route("GET", "/api/test", routes)
        assert match is None

    def test_wildcard_method_matches(self, gateway):
        routes = [
            RiskyRoute(path="/settings/**", methods=["*"], tactics=["persistence"]),
        ]
        match = gateway._match_risky_route("POST", "/settings/filters", routes)
        assert match is not None


# --- Credential Injection Tests ---


class TestCredentialInjection:
    def test_bearer_injection(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["gmail"]
        flow = make_flow(
            url="http://gmail.googleapis.com/gmail/v1/users/me/messages/123",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ya29.real-token"
        assert flow.metadata["gateway_service"] == "gmail"
        assert flow.metadata["gateway_capability"] == "read_and_send"
        assert flow.metadata["gateway_account"] == "operator"

    def test_api_key_injection(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://api.minifuse.io/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["X-API-Key"] == "real-api-key-123"
        assert flow.metadata["gateway_service"] == "minifuse"
        assert flow.metadata["gateway_capability"] == "reader"

    def test_agent_mismatch_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://api.minifuse.io/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "other-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "AGENT_MISMATCH" in body["reason_codes"]
        assert body["type"] == "agent_mismatch"
        assert body["action"] == "self_correct"
        assert "reflection" in body

    def test_host_mismatch_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://evil.example.com/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "HOST_MISMATCH" in body["reason_codes"]
        assert body["type"] == "host_mismatch"
        assert body["action"] == "self_correct"
        assert "reflection" in body

    def test_invalid_token_denied(self, make_flow, gateway):
        flow = make_flow(
            url="http://api.minifuse.io/v1/feeds",
            headers={"authorization": f"Bearer sgw_{'x' * 64}"},
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "INVALID_TOKEN" in body["reason_codes"]
        assert body["type"] == "invalid_token"
        assert body["action"] == "self_correct"
        assert "reflection" in body

    def test_route_not_in_capability_denied(self, make_flow, configured_gateway):
        """POST to a path not in the reader capability is denied."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            method="POST",
            url="http://api.minifuse.io/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "ROUTE_DENIED" in body["reason_codes"]
        assert body["type"] == "route_denied"
        assert body["action"] == "self_correct"
        assert "reflection" in body

    def test_capability_not_found_denied(self, make_flow, gateway, registry, vault_obj):
        """Token bound to nonexistent capability is denied."""
        gateway._host_map = {"api.minifuse.io": "minifuse"}
        env = gateway.mint_tokens(
            {
                "test-agent": {
                    "minifuse": {"capability": "nonexistent", "token": "minifuse-test"},
                },
            }
        )
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://api.minifuse.io/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "CAPABILITY_NOT_FOUND" in body["reason_codes"]
        assert body["type"] == "capability_not_found"
        assert body["action"] == "self_correct"
        assert "reflection" in body


# --- Risky Route PDP Integration Tests ---


class TestRiskyRoutePDP:
    def test_risky_route_pdp_allow(self, make_flow, configured_gateway):
        """Risky route that PDP allows → credential injected."""
        gw, env, registry, vault_obj = configured_gateway

        from pdp.schemas import Effect

        mock_decision = MagicMock()
        mock_decision.effect = Effect.ALLOW

        mock_client = MagicMock()
        mock_client.evaluate.return_value = mock_decision

        # Create a service where risky routes overlap with capabilities
        svc_dir = registry._user_dir
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_risky
auth:
  type: bearer
capabilities:
  full:
    description: "Full access"
    routes:
      - methods: [GET, POST, DELETE]
        path: "/api/**"
risky_routes:
  - path: "/api/admin/**"
    methods: [POST]
    tactics: [privilege_escalation]
    description: "Admin endpoint"
""")
        registry.load()

        gw._host_map["api.testrisky.com"] = "test_risky"
        new_env = gw.mint_tokens(
            {
                "test-agent": {
                    "test_risky": {"capability": "full", "token": "minifuse-test", "account": "agent"},
                },
            }
        )
        token = new_env["test-agent"]["test_risky"]

        flow = make_flow(
            method="POST",
            url="http://api.testrisky.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault_obj):
                    # Patch inside the _check_risky_route method's import scope
                    with patch("pdp.is_policy_client_configured", return_value=True):
                        with patch("pdp.get_policy_client", return_value=mock_client):
                            gw.request(flow)

        assert flow.response is None  # Allowed through
        assert gw.stats.injected > 0

    def test_risky_route_pdp_require_approval(self, make_flow, gateway, tmp_path):
        """Risky route that PDP blocks with 428 → flow.response set."""
        from pdp.schemas import DecisionEventBlock, Effect, ImmediateResponseBlock
        from pdp.schemas import PolicyDecision as SchemaDecision

        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_risky
auth:
  type: bearer
capabilities:
  full:
    description: "Full"
    routes:
      - methods: ["*"]
        path: "/api/**"
risky_routes:
  - path: "/api/admin/**"
    methods: [POST]
    tactics: [privilege_escalation]
""")
        registry = init_service_registry(svc_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="test-cred",
            type="bearer",
            value="real-token",
        )

        gateway._host_map = {"api.test.com": "test_risky"}
        env = gateway.mint_tokens(
            {
                "agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}},
            }
        )
        token = env["agent-1"]["test_risky"]

        mock_decision = SchemaDecision(
            version=1,
            event=DecisionEventBlock(
                event_id="evt-test",
                policy_hash="sha256:abc",
                engine_version="pdp-0.1.0",
            ),
            effect=Effect.REQUIRE_APPROVAL,
            reason="Risky route requires approval",
            reason_codes=["REQUIRE_APPROVAL", "GATEWAY_RISKY_ROUTE"],
            immediate_response=ImmediateResponseBlock(
                status_code=428,
                headers={"content-type": "application/json"},
                body_json={
                    "error": "Require Approval",
                    "reason": "Risky route",
                    "reason_codes": ["GATEWAY_RISKY_ROUTE"],
                    "reflection": {"service": "test_risky", "question": "Check signals"},
                },
            ),
        )

        mock_client = MagicMock()
        mock_client.evaluate.return_value = mock_decision

        flow = make_flow(
            method="POST",
            url="http://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "agent-1"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    with patch("pdp.is_policy_client_configured", return_value=True):
                        with patch("pdp.get_policy_client", return_value=mock_client):
                            gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert "GATEWAY_RISKY_ROUTE" in body["reason_codes"]
        assert body["type"] == "gateway_risky_route"
        assert body["action"] == "wait_for_approval"
        assert "reflection" in body


# --- Token Minting Tests ---


class TestTokenMinting:
    def test_mint_gateway_token_format(self):
        token = mint_gateway_token()
        assert token.startswith("sgw_")
        assert len(token) == 4 + 64

    def test_mint_tokens_creates_bindings(self, gateway):
        env = gateway.mint_tokens(
            {
                "agent-1": {
                    "gmail": {"capability": "search_headers", "token": "gmail-cred"},
                    "slack": {"capability": "poster", "token": "slack-cred"},
                },
                "agent-2": {
                    "minifuse": {"capability": "reader", "token": "mf-cred"},
                },
            }
        )
        assert "agent-1" in env
        assert "gmail" in env["agent-1"]
        assert "slack" in env["agent-1"]
        assert "agent-2" in env
        assert "minifuse" in env["agent-2"]
        assert gateway.stats.tokens_registered == 3

    def test_minted_tokens_are_unique(self, gateway):
        env = gateway.mint_tokens(
            {
                "a": {"s1": {"capability": "r", "token": "t1"}},
                "b": {"s1": {"capability": "r", "token": "t2"}},
            }
        )
        token_a = env["a"]["s1"]
        token_b = env["b"]["s1"]
        assert token_a != token_b

    def test_mint_tokens_with_account(self, gateway):
        env = gateway.mint_tokens(
            {
                "agent-1": {
                    "gmail": {"capability": "read_and_send", "token": "g", "account": "operator"},
                },
            }
        )
        token = env["agent-1"]["gmail"]
        binding = gateway._token_map[token]
        assert binding.account == "operator"
        assert binding.capability_name == "read_and_send"

    def test_mint_tokens_default_account(self, gateway):
        env = gateway.mint_tokens(
            {
                "agent-1": {
                    "gmail": {"capability": "reader", "token": "g"},
                },
            }
        )
        token = env["agent-1"]["gmail"]
        binding = gateway._token_map[token]
        assert binding.account == "agent"

    def test_mint_tokens_role_compat(self, gateway):
        """Legacy role field still works."""
        env = gateway.mint_tokens(
            {
                "agent-1": {
                    "gmail": {"role": "readonly", "token": "g"},
                },
            }
        )
        token = env["agent-1"]["gmail"]
        binding = gateway._token_map[token]
        assert binding.capability_name == "readonly"


# --- Stats Tests ---


class TestGatewayStats:
    def test_initial_stats(self, gateway):
        stats = gateway.get_stats()
        assert stats["requests"] == 0
        assert stats["injected"] == 0
        assert stats["denied_route"] == 0
        assert stats["denied_token"] == 0
        assert stats["tokens_registered"] == 0

    def test_stats_show_bindings_not_tokens(self, gateway):
        gateway.mint_tokens(
            {
                "agent": {"minifuse": {"capability": "reader", "token": "cred"}},
            }
        )
        stats = gateway.get_stats()
        assert len(stats["bindings"]) == 1
        assert stats["bindings"][0]["capability"] == "reader"
        assert stats["bindings"][0]["account"] == "agent"
        # Tokens must NOT appear in stats
        stats_str = json.dumps(stats)
        assert "sgw_" not in stats_str


# --- Agent Services Tests ---


class TestAgentServices:
    def test_get_agent_services_includes_capability(self, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        services = gw.get_agent_services()
        assert "test-agent" in services
        gmail = services["test-agent"]["gmail"]
        assert "capability" in gmail
        assert gmail["capability"] == "read_and_send"
        assert gmail["account"] == "operator"
        assert "host" in gmail
        assert "token" in gmail


# --- Full Flow Integration Test ---


class TestFullFlow:
    def test_minifuse_get_flow(self, make_flow, services_dir):
        """Full flow: mint token -> request -> credential injected -> metadata stamped."""
        registry = init_service_registry(services_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="minifuse-test",
            type="api_key",
            value="real-key-456",
        )

        gw = ServiceGateway()
        gw._host_map = {"api.minifuse.io": "minifuse"}
        env = gw.mint_tokens(
            {
                "my-agent": {"minifuse": {"capability": "reader", "token": "minifuse-test"}},
            }
        )
        token = env["my-agent"]["minifuse"]

        flow = make_flow(
            url="http://api.minifuse.io/v1/resources",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "my-agent"

        # minifuse reader capability has /v1/** GET
        # /v1/resources should match /v1/**
        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["X-API-Key"] == "real-key-456"
        assert flow.metadata["gateway_service"] == "minifuse"
        assert flow.metadata["gateway_capability"] == "reader"
        assert flow.metadata["gateway_agent"] == "my-agent"
        assert gw.stats.injected == 1

    def test_host_validated_via_host_map(self, make_flow, services_dir):
        """Request to unmapped host gets HOST_MISMATCH even if service exists."""
        registry = init_service_registry(services_dir)

        gw = ServiceGateway()
        # host_map does NOT include unmapped.example.com
        gw._host_map = {"api.minifuse.io": "minifuse"}
        env = gw.mint_tokens(
            {
                "my-agent": {"minifuse": {"capability": "reader", "token": "minifuse-test"}},
            }
        )
        token = env["my-agent"]["minifuse"]

        flow = make_flow(
            url="http://unmapped.example.com/v1/data",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "my-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "HOST_MISMATCH" in body["reason_codes"]
        assert body["type"] == "host_mismatch"
        assert body["action"] == "self_correct"
        assert "reflection" in body


# --- Grant Management Tests ---


class TestGrantEntry:
    def test_matches_exact(self):
        grant = GrantEntry(
            grant_id="grt_test1",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/658",
        )
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/658") is True

    def test_matches_glob_pattern(self):
        grant = GrantEntry(
            grant_id="grt_test1b",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
        )
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/658") is True
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/999") is True
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/entries/1") is False

    def test_matches_case_insensitive_method(self):
        grant = GrantEntry(
            grant_id="grt_test2",
            agent="claude",
            service="minifuse",
            method="delete",
            path="/v1/feeds/*",
        )
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/658") is True

    def test_no_match_wrong_agent(self):
        grant = GrantEntry(
            grant_id="grt_test3",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
        )
        assert grant.matches("other-agent", "minifuse", "DELETE", "/v1/feeds/658") is False

    def test_no_match_wrong_service(self):
        grant = GrantEntry(
            grant_id="grt_test4",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
        )
        assert grant.matches("claude", "gmail", "DELETE", "/v1/feeds/658") is False

    def test_no_match_wrong_method(self):
        grant = GrantEntry(
            grant_id="grt_test5",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
        )
        assert grant.matches("claude", "minifuse", "GET", "/v1/feeds/658") is False


class TestGrantManagement:
    def test_add_grant(self, gateway):
        grant = gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        assert grant.grant_id.startswith("grt_")
        assert grant.agent == "claude"
        assert grant.scope == "once"

    def test_list_grants(self, gateway):
        gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        gateway.add_grant("claude", "gmail", "POST", "/v1/filters")

        grants = gateway.list_grants()
        assert len(grants) == 2
        services = {g["service"] for g in grants}
        assert services == {"minifuse", "gmail"}

    def test_revoke_grant(self, gateway):
        grant = gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        assert gateway.revoke_grant(grant.grant_id) is True
        assert gateway.list_grants() == []

    def test_revoke_nonexistent(self, gateway):
        assert gateway.revoke_grant("grt_nonexistent") is False

    def test_check_grant_found(self, gateway):
        gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        found = gateway._check_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        assert found is not None
        assert found.service == "minifuse"

    def test_check_grant_not_found(self, gateway):
        gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        found = gateway._check_grant("claude", "minifuse", "GET", "/v1/feeds")
        assert found is None

    def test_grant_id_format(self):
        gid = _mint_grant_id()
        assert gid.startswith("grt_")
        assert len(gid) == 4 + 24  # "grt_" + 24 hex chars

    def test_stats_include_grant_count(self, gateway):
        gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/658")
        stats = gateway.get_stats()
        assert stats["active_grants"] == 1


class TestGrantBypassPDP:
    """Test that grants bypass PDP for risky routes."""

    def test_grant_bypasses_pdp(self, make_flow, tmp_path):
        """With a matching grant, risky route skips PDP and injects credential."""
        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_risky
auth:
  type: bearer
capabilities:
  full:
    description: "Full"
    routes:
      - methods: ["*"]
        path: "/api/**"
risky_routes:
  - path: "/api/admin/**"
    methods: [DELETE]
    tactics: [impact]
    irreversible: true
""")
        registry = init_service_registry(svc_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="test-cred",
            type="bearer",
            value="real-token",
        )

        gw = ServiceGateway()
        gw._host_map = {"api.test.com": "test_risky"}
        env = gw.mint_tokens(
            {
                "agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}},
            }
        )
        token = env["agent-1"]["test_risky"]

        # Add grant using risky route pattern (as watch would send it)
        grant = gw.add_grant("agent-1", "test_risky", "DELETE", "/api/admin/**")

        flow = make_flow(
            method="DELETE",
            url="http://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "agent-1"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    gw.request(flow)

        # Should pass through (grant bypassed PDP)
        assert flow.response is None
        assert flow.metadata.get("gateway_grant_id") == grant.grant_id
        assert gw.stats.injected == 1

    def test_no_grant_hits_pdp(self, make_flow, tmp_path):
        """Without a grant, risky route still goes through PDP → 428."""
        from pdp.schemas import DecisionEventBlock, Effect, ImmediateResponseBlock
        from pdp.schemas import PolicyDecision as SchemaDecision

        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_risky
auth:
  type: bearer
capabilities:
  full:
    description: "Full"
    routes:
      - methods: ["*"]
        path: "/api/**"
risky_routes:
  - path: "/api/admin/**"
    methods: [DELETE]
    tactics: [impact]
""")
        registry = init_service_registry(svc_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="test-cred",
            type="bearer",
            value="real-token",
        )

        gw = ServiceGateway()
        gw._host_map = {"api.test.com": "test_risky"}
        env = gw.mint_tokens(
            {
                "agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}},
            }
        )
        token = env["agent-1"]["test_risky"]

        # No grant — PDP blocks
        mock_decision = SchemaDecision(
            version=1,
            event=DecisionEventBlock(
                event_id="evt-test",
                policy_hash="sha256:abc",
                engine_version="pdp-0.1.0",
            ),
            effect=Effect.REQUIRE_APPROVAL,
            reason="Risky route requires approval",
            reason_codes=["REQUIRE_APPROVAL"],
            immediate_response=ImmediateResponseBlock(
                status_code=428,
                headers={"content-type": "application/json"},
                body_json={"error": "Require Approval", "reason_codes": ["GATEWAY_RISKY_ROUTE"]},
            ),
        )
        mock_client = MagicMock()
        mock_client.evaluate.return_value = mock_decision

        flow = make_flow(
            method="DELETE",
            url="http://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "agent-1"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    with patch("pdp.is_policy_client_configured", return_value=True):
                        with patch("pdp.get_policy_client", return_value=mock_client):
                            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428


class TestGrantConsumption:
    """Test once-grant consumption via response() hook."""

    def test_once_grant_consumed_on_2xx(self, gateway):
        """Once-scope grant is removed after successful response."""
        from mitmproxy.test import tflow

        grant = gateway.add_grant("agent-1", "svc", "DELETE", "/api/item")
        assert len(gateway.list_grants()) == 1

        # Simulate response flow
        flow = tflow.tflow()
        flow.metadata["gateway_grant_id"] = grant.grant_id
        flow.response = MagicMock()
        flow.response.status_code = 200

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 0

    def test_once_grant_not_consumed_on_4xx(self, gateway):
        """Once-scope grant survives non-2xx response."""
        from mitmproxy.test import tflow

        grant = gateway.add_grant("agent-1", "svc", "DELETE", "/api/item")

        flow = tflow.tflow()
        flow.metadata["gateway_grant_id"] = grant.grant_id
        flow.response = MagicMock()
        flow.response.status_code = 404

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 1

    def test_session_grant_not_consumed(self, gateway):
        """Session-scope grant survives 2xx response."""
        from mitmproxy.test import tflow

        grant = gateway.add_grant("agent-1", "svc", "DELETE", "/api/item", scope="session")

        flow = tflow.tflow()
        flow.metadata["gateway_grant_id"] = grant.grant_id
        flow.response = MagicMock()
        flow.response.status_code = 200

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 1

    def test_response_no_grant_id_ignored(self, gateway):
        """Flows without gateway_grant_id are ignored by response()."""
        from mitmproxy.test import tflow

        gateway.add_grant("agent-1", "svc", "DELETE", "/api/item")

        flow = tflow.tflow()
        # No gateway_grant_id in metadata
        flow.response = MagicMock()
        flow.response.status_code = 200

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 1


class TestGrantTTL:
    """Test grant expiry via TTL."""

    def test_expired_grant_does_not_match(self):
        """A grant past its TTL does not match."""
        from datetime import timedelta

        past = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        grant = GrantEntry(
            grant_id="grt_expired",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
            created=past,
            expires=past,  # already expired
        )
        assert grant.is_expired() is True
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/1") is False

    def test_fresh_grant_matches(self):
        """A grant within TTL matches normally."""
        from datetime import timedelta

        future = (datetime.now(UTC) + timedelta(seconds=3600)).isoformat()
        grant = GrantEntry(
            grant_id="grt_fresh",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
            expires=future,
        )
        assert grant.is_expired() is False
        assert grant.matches("claude", "minifuse", "DELETE", "/v1/feeds/1") is True

    def test_check_grant_cleans_expired(self, gateway):
        """_check_grant removes expired grants from storage."""
        from datetime import timedelta

        past = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        expired_grant = GrantEntry(
            grant_id="grt_old",
            agent="claude",
            service="minifuse",
            method="DELETE",
            path="/v1/feeds/*",
            created=past,
            expires=past,
        )
        with gateway._lock:
            gateway._grants["grt_old"] = expired_grant

        assert len(gateway.list_grants()) == 1

        # _check_grant should clean it up
        result = gateway._check_grant("claude", "minifuse", "DELETE", "/v1/feeds/1")
        assert result is None
        assert len(gateway.list_grants()) == 0

    def test_list_grants_shows_expired_flag(self, gateway):
        """list_grants includes expired field."""
        gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/1")
        grants = gateway.list_grants()
        assert len(grants) == 1
        assert "expires" in grants[0]
        assert grants[0]["expired"] is False

    def test_custom_ttl_on_gateway(self, gateway):
        """Gateway uses configured TTL for new grants."""

        gateway._grant_ttl = 120  # 2 minutes
        grant = gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/1")

        created_dt = datetime.fromisoformat(grant.created)
        expires_dt = datetime.fromisoformat(grant.expires)
        delta = expires_dt - created_dt
        assert 119 <= delta.total_seconds() <= 121


class TestRiskyRouteApprovalField:
    """Verify risky route events include the approval field."""

    def test_risky_route_event_has_approval(self, make_flow, gateway, tmp_path):
        """gateway.risky_route events must include approval with correct type/key/target."""
        from pdp.schemas import DecisionEventBlock, Effect, ImmediateResponseBlock
        from pdp.schemas import PolicyDecision as SchemaDecision

        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_risky
auth:
  type: bearer
capabilities:
  full:
    description: "Full"
    routes:
      - methods: ["*"]
        path: "/api/**"
risky_routes:
  - path: "/api/admin/**"
    methods: [POST]
    tactics: [privilege_escalation]
    description: "Admin endpoint"
""")
        registry = init_service_registry(svc_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="test-cred",
            type="bearer",
            value="real-token",
        )

        gateway._host_map = {"api.test.com": "test_risky"}
        env = gateway.mint_tokens(
            {
                "agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}},
            }
        )
        token = env["agent-1"]["test_risky"]

        mock_decision = SchemaDecision(
            version=1,
            event=DecisionEventBlock(
                event_id="evt-test",
                policy_hash="sha256:abc",
                engine_version="pdp-0.1.0",
            ),
            effect=Effect.REQUIRE_APPROVAL,
            reason="Risky route requires approval",
            reason_codes=["REQUIRE_APPROVAL", "GATEWAY_RISKY_ROUTE"],
            immediate_response=ImmediateResponseBlock(
                status_code=428,
                headers={"content-type": "application/json"},
                body_json={
                    "error": "Require Approval",
                    "reason_codes": ["GATEWAY_RISKY_ROUTE"],
                    "reflection": {"service": "test_risky", "question": "Check signals"},
                },
            ),
        )
        mock_client = MagicMock()
        mock_client.evaluate.return_value = mock_decision

        flow = make_flow(
            method="POST",
            url="http://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "agent-1"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    with patch("pdp.is_policy_client_configured", return_value=True):
                        with patch("pdp.get_policy_client", return_value=mock_client):
                            with patch("service_gateway.write_event") as mock_write:
                                gateway.request(flow)

        # Verify write_event was called with approval kwarg
        mock_write.assert_called()
        call_kwargs = mock_write.call_args
        # write_event uses keyword-only args after the first positional
        assert call_kwargs[0][0] == "gateway.risky_route"
        approval = call_kwargs[1]["approval"]
        assert approval is not None
        assert approval.required is True
        assert approval.approval_type == "gateway_route"
        assert approval.key == "gw:agent-1:test_risky:POST:/api/admin/users"
        assert approval.target == "test_risky"
        assert approval.scope_hint == {"method": "POST", "path": "/api/admin/users"}


# --- Grant persistence tests ---


class TestGrantPersistence:
    """Tests for _persist_grants and _load_grants_from_agents_yaml."""

    @pytest.fixture
    def agents_yaml(self, tmp_path):
        """Create an empty agents.yaml."""
        path = tmp_path / "agents.yaml"
        path.write_text("claude:\n  template: claude-code\n")
        return path

    @pytest.fixture
    def mock_pdp(self, agents_yaml):
        """Mock PDP with correct client._pdp._engine._loader chain."""
        mock_loader = MagicMock()
        mock_loader._agents_path.return_value = agents_yaml

        mock_engine = MagicMock()
        mock_engine._loader = mock_loader

        mock_pdp = MagicMock()
        mock_pdp._engine = mock_engine

        mock_client = MagicMock()
        mock_client._pdp = mock_pdp

        with (
            patch("pdp.get_policy_client", return_value=mock_client),
            patch("pdp.is_policy_client_configured", return_value=True),
        ):
            yield

    def test_persist_writes_grants(self, gateway, mock_pdp, agents_yaml):
        """Grants are written to agents.yaml."""
        import yaml

        grant = GrantEntry(
            grant_id="g1",
            agent="claude",
            service="gmail",
            method="POST",
            path="/messages/send",
            scope="remembered",
        )
        gateway._grants["g1"] = grant
        gateway._persist_grants()

        raw = yaml.safe_load(agents_yaml.read_text())
        grants = raw["claude"]["grants"]
        assert len(grants) == 1
        assert grants[0]["grant_id"] == "g1"
        assert grants[0]["service"] == "gmail"

    def test_load_reads_remembered_grants(self, gateway, mock_pdp, agents_yaml):
        """Remembered grants are loaded from agents.yaml."""
        from datetime import timedelta

        import yaml

        # Use a recent timestamp so the grant isn't expired
        now = datetime.now(UTC)
        created = now.isoformat()
        expires = (now + timedelta(hours=1)).isoformat()

        raw = yaml.safe_load(agents_yaml.read_text())
        raw["claude"]["grants"] = [
            {
                "grant_id": "g2",
                "service": "gmail",
                "method": "DELETE",
                "path": "/messages/*",
                "scope": "remembered",
                "created": created,
                "expires": expires,
            },
        ]
        agents_yaml.write_text(yaml.dump(raw, default_flow_style=False))

        gateway._load_grants_from_agents_yaml()
        assert "g2" in gateway._grants
        assert gateway._grants["g2"].service == "gmail"
        assert gateway._grants["g2"].scope == "remembered"

    def test_persist_then_load_roundtrip(self, gateway, mock_pdp, agents_yaml):
        """Grants survive a persist → load cycle."""
        grant = GrantEntry(
            grant_id="g3",
            agent="claude",
            service="slack",
            method="POST",
            path="/chat.postMessage",
            scope="remembered",
        )
        gateway._grants["g3"] = grant
        gateway._persist_grants()

        # Fresh gateway loads from disk
        gw2 = ServiceGateway()
        gw2._load_grants_from_agents_yaml()
        assert "g3" in gw2._grants
        assert gw2._grants["g3"].service == "slack"
        assert gw2._grants["g3"].method == "POST"
