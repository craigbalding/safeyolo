"""Tests for addons/service_gateway.py — Service Gateway addon."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from service_gateway import SGW_TOKEN_PREFIX, ServiceGateway, TokenBinding, mint_gateway_token
from service_loader import (
    AuthConfig,
    RouteRule,
    ServiceDefinition,
    ServiceRole,
    ServiceRegistry,
    init_service_registry,
)
from vault import Vault, VaultCredential


# --- Fixtures ---

@pytest.fixture
def gateway():
    return ServiceGateway()


@pytest.fixture
def services_dir(tmp_path):
    """Create temp services dir with minifuse and gmail definitions."""
    svc_dir = tmp_path / "services"
    svc_dir.mkdir()
    (svc_dir / "minifuse.yaml").write_text("""
name: minifuse
roles:
  reader:
    auth:
      type: api_key
      header: X-API-Key
    routes:
      - effect: deny
        methods: [POST, PUT, DELETE, PATCH]
        path: "/v1/**"
      - effect: allow
        methods: [GET]
        path: "/v1/**"
""")
    (svc_dir / "gmail.yaml").write_text("""
name: gmail
roles:
  readonly:
    auth:
      type: bearer
      scheme: Bearer
      refresh_on_401: true
    routes:
      - effect: deny
        methods: ["*"]
        path: "/gmail/v1/users/me/settings/**"
      - effect: allow
        methods: [GET]
        path: "/gmail/v1/users/me/**"
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
    env = gateway.mint_tokens({
        "test-agent": {
            "minifuse": {"role": "reader", "token": "minifuse-test"},
            "gmail": {"role": "readonly", "token": "gmail-oauth2"},
        },
    })
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


# --- Route Matching Tests ---

class TestRouteMatching:
    def test_allow_get(self, gateway):
        routes = [RouteRule(effect="allow", methods=["GET"], path="/v1/**")]
        assert gateway._evaluate_routes("GET", "/v1/data", routes) is True

    def test_deny_overrides_allow(self, gateway):
        routes = [
            RouteRule(effect="deny", methods=["POST"], path="/v1/**"),
            RouteRule(effect="allow", methods=["*"], path="/v1/**"),
        ]
        assert gateway._evaluate_routes("POST", "/v1/data", routes) is False
        assert gateway._evaluate_routes("GET", "/v1/data", routes) is True

    def test_method_wildcard(self, gateway):
        routes = [RouteRule(effect="allow", methods=["*"], path="/api/**")]
        assert gateway._evaluate_routes("GET", "/api/test", routes) is True
        assert gateway._evaluate_routes("POST", "/api/test", routes) is True
        assert gateway._evaluate_routes("DELETE", "/api/test", routes) is True

    def test_no_match_denies(self, gateway):
        routes = [RouteRule(effect="allow", methods=["GET"], path="/v1/**")]
        assert gateway._evaluate_routes("GET", "/v2/data", routes) is False

    def test_path_glob(self, gateway):
        routes = [RouteRule(effect="allow", methods=["GET"], path="/gmail/v1/users/me/**")]
        assert gateway._evaluate_routes("GET", "/gmail/v1/users/me/messages", routes) is True
        assert gateway._evaluate_routes("GET", "/gmail/v1/users/me/labels/123", routes) is True

    def test_deny_settings_path(self, gateway):
        routes = [
            RouteRule(effect="deny", methods=["*"], path="/gmail/v1/users/me/settings/**"),
            RouteRule(effect="allow", methods=["GET"], path="/gmail/v1/users/me/**"),
        ]
        assert gateway._evaluate_routes("GET", "/gmail/v1/users/me/settings/filters", routes) is False
        assert gateway._evaluate_routes("GET", "/gmail/v1/users/me/messages", routes) is True

    def test_empty_routes_denies(self, gateway):
        assert gateway._evaluate_routes("GET", "/anything", []) is False


# --- Credential Injection Tests ---

class TestCredentialInjection:
    def test_bearer_injection(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["gmail"]
        flow = make_flow(
            url="http://gmail.googleapis.com/gmail/v1/users/me/messages",
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
        assert flow.metadata["gateway_role"] == "readonly"

    def test_api_key_injection(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://api.minifuse.io/v1/data",
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

    def test_agent_mismatch_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://api.minifuse.io/v1/data",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "other-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "AGENT_MISMATCH" in body["reason_codes"]

    def test_host_mismatch_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="http://evil.example.com/v1/data",
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

    def test_invalid_token_denied(self, make_flow, gateway):
        flow = make_flow(
            url="http://api.minifuse.io/v1/data",
            headers={"authorization": f"Bearer sgw_{'x' * 64}"},
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "INVALID_TOKEN" in body["reason_codes"]

    def test_route_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            method="POST",
            url="http://api.minifuse.io/v1/data",
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


# --- Token Minting Tests ---

class TestTokenMinting:
    def test_mint_gateway_token_format(self):
        token = mint_gateway_token()
        assert token.startswith("sgw_")
        assert len(token) == 4 + 64

    def test_mint_tokens_creates_bindings(self, gateway):
        env = gateway.mint_tokens({
            "agent-1": {
                "gmail": {"role": "readonly", "token": "gmail-cred"},
                "slack": {"role": "poster", "token": "slack-cred"},
            },
            "agent-2": {
                "minifuse": {"role": "reader", "token": "mf-cred"},
            },
        })
        assert "agent-1" in env
        assert "gmail" in env["agent-1"]
        assert "slack" in env["agent-1"]
        assert "agent-2" in env
        assert "minifuse" in env["agent-2"]
        assert gateway.stats.tokens_registered == 3

    def test_minted_tokens_are_unique(self, gateway):
        env = gateway.mint_tokens({
            "a": {"s1": {"role": "r", "token": "t1"}},
            "b": {"s1": {"role": "r", "token": "t2"}},
        })
        token_a = env["a"]["s1"]
        token_b = env["b"]["s1"]
        assert token_a != token_b


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
        gateway.mint_tokens({
            "agent": {"minifuse": {"role": "reader", "token": "cred"}},
        })
        stats = gateway.get_stats()
        assert len(stats["bindings"]) == 1
        assert stats["bindings"][0]["role"] == "reader"
        # Tokens must NOT appear in stats
        stats_str = json.dumps(stats)
        assert "sgw_" not in stats_str


# --- Full Flow Integration Test ---

class TestFullFlow:
    def test_minifuse_get_flow(self, make_flow, services_dir):
        """Full flow: mint token -> request -> credential injected -> metadata stamped."""
        registry = init_service_registry(services_dir)

        vault = MagicMock()
        vault.get.return_value = VaultCredential(
            name="minifuse-test", type="api_key", value="real-key-456",
        )

        gw = ServiceGateway()
        gw._host_map = {"api.minifuse.io": "minifuse"}
        env = gw.mint_tokens({
            "my-agent": {"minifuse": {"role": "reader", "token": "minifuse-test"}},
        })
        token = env["my-agent"]["minifuse"]

        flow = make_flow(
            url="http://api.minifuse.io/v1/resources",
            headers={"authorization": f"Bearer {token}"},
        )
        flow.metadata["agent"] = "my-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", return_value=registry):
                with patch("service_gateway.get_vault", return_value=vault):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["X-API-Key"] == "real-key-456"
        assert flow.metadata["gateway_service"] == "minifuse"
        assert flow.metadata["gateway_role"] == "reader"
        assert flow.metadata["gateway_agent"] == "my-agent"
        assert gw.stats.injected == 1

    def test_host_validated_via_host_map(self, make_flow, services_dir):
        """Request to unmapped host gets HOST_MISMATCH even if service exists."""
        registry = init_service_registry(services_dir)

        gw = ServiceGateway()
        # host_map does NOT include unmapped.example.com
        gw._host_map = {"api.minifuse.io": "minifuse"}
        env = gw.mint_tokens({
            "my-agent": {"minifuse": {"role": "reader", "token": "minifuse-test"}},
        })
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
