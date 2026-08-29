"""Tests for addons/service_gateway.py — Service Gateway addon (v2)."""

import json
import threading
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy import http
from service_gateway import (
    SGW_TOKEN_PREFIX,
    GrantEntry,
    ServiceGateway,
    _mint_grant_id,
    mint_gateway_token,
)

from pdp.client import LocalPolicyClient, PolicyClient, PolicyClientConfig
from pdp.schemas import DecisionEventBlock, Effect, PolicyDecision
from safeyolo.core.service_loader import (
    Capability,
    CapabilityRoute,
    RiskyRoute,
    ServiceRegistry,
    init_service_registry,
)
from safeyolo.core.service_paths import builtin_services_dir
from safeyolo.core.trace import get_store, reset_store_for_tests
from safeyolo.core.vault import Vault, VaultCredential
from safeyolo.proxy_modes.unix_listener import UnixMode

pytestmark = pytest.mark.assurance_boundary

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
    """Create the minimal concrete context state read by request hooks."""
    return SimpleNamespace(options=SimpleNamespace(gateway_enabled=True))


def _set_agent(flow, agent: str) -> None:
    """Give a flow a real trusted connection identity for gateway tests."""
    flow.client_conn.proxy_mode = UnixMode.parse(
        f"unix:/tmp/10.0.0.5_{agent}/proxy.sock"
    )
    flow.metadata["agent"] = agent


def _decision(effect: Effect) -> PolicyDecision:
    """Build a schema-valid PDP decision, never an attribute-only fake."""
    return PolicyDecision(
        event=DecisionEventBlock(
            event_id="evt-gateway-test",
            policy_hash="sha256:test",
            engine_version="test",
        ),
        effect=effect,
        reason=f"test {effect.value}",
    )


def _policy_client(**method_results):
    """Autospec the external PDP boundary and configure selected methods."""
    client = create_autospec(PolicyClient, instance=True, spec_set=True)
    for method, result in method_results.items():
        getattr(client, method).return_value = result
    return client


def _vault_with(tmp_path, credential: VaultCredential | None = None) -> Vault:
    """Create a real unlocked vault, optionally containing one credential."""
    vault = Vault(tmp_path / "test-vault.enc")
    vault.unlock("test-pass")
    if credential is not None:
        vault.store(credential)
    return vault


class TestServiceSourceConfiguration:
    def test_addon_default_builtin_is_the_packaged_source(self, gateway):
        class Loader:
            def __init__(self):
                self.options = {}

            def add_option(self, **option):
                self.options[option["name"]] = option

        loader = Loader()
        gateway.load(loader)

        assert loader.options["gateway_builtin_services_dir"]["default"] == str(
            builtin_services_dir()
        )
        assert loader.options["gateway_services_dir"]["default"] == "/safeyolo/services"

    def test_malformed_runtime_source_fails_with_actionable_options_error(
        self, gateway, tmp_path
    ):
        from mitmproxy.exceptions import OptionsError

        builtin = tmp_path / "builtin"
        user = tmp_path / "user"
        builtin.mkdir()
        user.mkdir()
        (builtin / "valid.yaml").write_text(
            "schema_version: 1\nname: valid\n"
        )
        (user / "broken.yaml").write_text("not: valid: yaml: [")
        options = SimpleNamespace(
            gateway_services_dir=str(user),
            gateway_builtin_services_dir=str(builtin),
        )

        with patch("service_gateway.ctx", SimpleNamespace(options=options)):
            with pytest.raises(OptionsError, match="broken.yaml"):
                gateway._init_services()

    def test_policy_activation_failure_restores_previous_live_registry(
        self, gateway, tmp_path
    ):
        from mitmproxy.exceptions import OptionsError

        from safeyolo.core.service_loader import (
            _swap_service_registry,
            get_service_registry,
        )

        def registry_for(label):
            directory = tmp_path / label
            directory.mkdir()
            (directory / "service.yaml").write_text(
                f"schema_version: 1\nname: {label}\n"
            )
            result = ServiceRegistry(
                directory,
                builtin_dir=tmp_path / f"no-{label}-builtins",
            )
            result.load(strict=True)
            return result

        previous = registry_for("previous")
        candidate = registry_for("candidate")
        original = _swap_service_registry(previous, stop_previous=False)
        observed = []

        def synchronize_policy():
            live = get_service_registry()
            names = [service.name for service in live.list_services()]
            observed.append(names)
            if names == ["candidate"]:
                raise RuntimeError("candidate policy compile failed")

        gateway._trigger_policy_reload = synchronize_policy
        try:
            with pytest.raises(OptionsError, match="candidate policy compile failed"):
                gateway._activate_service_registry(candidate)

            assert get_service_registry() is previous
            assert observed == [["candidate"], ["previous"]]
        finally:
            _swap_service_registry(original, stop_previous=False)

    def test_policy_activation_blocks_registry_readers_until_commit(
        self, gateway, tmp_path
    ):
        from safeyolo.core.service_loader import (
            _swap_service_registry,
            get_service_registry,
        )

        def registry_for(label):
            directory = tmp_path / label
            directory.mkdir()
            (directory / "service.yaml").write_text(
                f"schema_version: 1\nname: {label}\n"
            )
            result = ServiceRegistry(
                directory,
                builtin_dir=tmp_path / f"no-{label}-builtins",
            )
            result.load(strict=True)
            return result

        previous = registry_for("previous")
        candidate = registry_for("candidate")
        original = _swap_service_registry(previous, stop_previous=False)
        callback_started = threading.Event()
        allow_commit = threading.Event()
        reader_finished = threading.Event()
        activation_errors = []
        observed = []

        def synchronize_policy():
            if get_service_registry() is candidate:
                callback_started.set()
                assert allow_commit.wait(timeout=2)

        def activate():
            try:
                gateway._activate_service_registry(candidate)
            except Exception as error:
                activation_errors.append(error)

        def read_live_registry():
            observed.append(
                [service.name for service in get_service_registry().list_services()]
            )
            reader_finished.set()

        gateway._trigger_policy_reload = synchronize_policy
        activation_thread = threading.Thread(target=activate)
        reader_thread = threading.Thread(target=read_live_registry)
        try:
            activation_thread.start()
            assert callback_started.wait(timeout=2)
            reader_thread.start()
            assert not reader_finished.wait(timeout=0.05)

            allow_commit.set()
            activation_thread.join(timeout=2)
            reader_thread.join(timeout=2)
            assert not activation_thread.is_alive()
            assert not reader_thread.is_alive()
            assert activation_errors == []
            assert observed == [["candidate"]]
        finally:
            allow_commit.set()
            activation_thread.join(timeout=2)
            reader_thread.join(timeout=2)
            candidate.stop_watcher()
            _swap_service_registry(original, stop_previous=False)


# --- Token Extraction Tests ---


class TestTokenExtraction:
    """Token extraction uses host → service → auth.header to find the sgw_ token."""

    def test_bearer_service_token(self, make_flow, gateway, registry):
        """Bearer service: sgw_ token in Authorization header with Bearer prefix."""
        gateway._host_map = {"gmail.googleapis.com": "gmail"}
        token = f"{SGW_TOKEN_PREFIX}{'a' * 64}"
        flow = make_flow(
            url="https://gmail.googleapis.com/test",
            headers={"authorization": f"Bearer {token}"},
        )
        result = gateway._extract_sgw_token(flow)
        assert result == token

    def test_api_key_service_token(self, make_flow, gateway, registry):
        """API key service: sgw_ token in service-specific header."""
        gateway._host_map = {"api.minifuse.io": "minifuse"}
        token = f"{SGW_TOKEN_PREFIX}{'b' * 64}"
        flow = make_flow(
            url="https://api.minifuse.io/test",
            headers={"x-api-key": token},
        )
        result = gateway._extract_sgw_token(flow)
        assert result == token

    def test_non_sgw_value_ignored(self, make_flow, gateway, registry):
        gateway._host_map = {"api.minifuse.io": "minifuse"}
        flow = make_flow(
            url="https://api.minifuse.io/test",
            headers={"x-api-key": "not-a-gateway-token"},
        )
        result = gateway._extract_sgw_token(flow)
        assert result is None

    def test_unknown_host_ignored(self, make_flow, gateway):
        token = f"{SGW_TOKEN_PREFIX}{'c' * 64}"
        flow = make_flow(
            url="https://unknown.example.com/test",
            headers={"authorization": f"Bearer {token}"},
        )
        result = gateway._extract_sgw_token(flow)
        assert result is None

    def test_no_auth_header(self, make_flow, gateway, registry):
        gateway._host_map = {"gmail.googleapis.com": "gmail"}
        flow = make_flow(url="https://gmail.googleapis.com/test")
        result = gateway._extract_sgw_token(flow)
        assert result is None


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
    def test_packaged_builtin_authorization_swaps_real_credential_and_traces(
        self,
        make_flow,
        gateway,
        tmp_path,
    ):
        user_dir = tmp_path / "services"
        user_dir.mkdir()
        registry = ServiceRegistry(
            user_dir,
            builtin_dir=builtin_services_dir(),
            require_builtin=True,
        )
        registry.load(strict=True)
        vault = _vault_with(
            tmp_path,
            VaultCredential(
                name="minifuse-live",
                type="api_key",
                value="real-upstream-api-key",
            ),
        )
        gateway._host_map = {"api.minifuse.example": "minifuse"}
        token = gateway.mint_tokens(
            {
                "test-agent": {
                    "minifuse": {
                        "capability": "reader",
                        "token": "minifuse-live",
                    }
                }
            }
        )["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.example/v1/feeds",
            headers={"x-auth-token": token},
        )
        _set_agent(flow, "test-agent")
        flow.metadata.update(
            {
                "trace": True,
                "request_id": "req-packaged-builtin",
            }
        )
        reset_store_for_tests()

        with (
            patch("service_gateway.ctx", _mock_ctx()),
            patch(
                "service_gateway.get_service_registry",
                autospec=True,
                return_value=registry,
            ),
            patch("service_gateway.get_vault", autospec=True, return_value=vault),
            patch("pdp.is_policy_client_configured", autospec=True, return_value=False),
        ):
            gateway.request(flow)

        assert flow.response is None
        assert flow.request.headers["x-auth-token"] == "real-upstream-api-key"
        assert token not in str(flow.request.headers)
        record = get_store().get("req-packaged-builtin", "test-agent")
        assert record is not None
        step = next(item for item in record.steps if item.addon == "service-gateway")
        assert step.outcome == "injected"
        assert step.details == {
            "service": "minifuse",
            "capability": "reader",
        }

    def test_bearer_injection(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["gmail"]
        flow = make_flow(
            url="https://gmail.googleapis.com/gmail/v1/users/me/messages/123",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
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
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["X-API-Key"] == "real-api-key-123"
        assert flow.metadata["gateway_service"] == "minifuse"
        assert flow.metadata["gateway_capability"] == "reader"

    def test_http_redirects_to_https(self, make_flow, configured_gateway):
        """Gateway refuses to inject credentials over HTTP — returns 301 to HTTPS."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["gmail"]
        flow = make_flow(
            url="http://gmail.googleapis.com/gmail/v1/users/me/messages/123",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 301
        location = flow.response.headers["Location"]
        assert location == "https://gmail.googleapis.com/gmail/v1/users/me/messages/123"
        # Credential must NOT have been injected
        assert "ya29.real-token" not in str(flow.request.headers)

    def test_agent_mismatch_denied(self, make_flow, configured_gateway):
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "other-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "AGENT_MISMATCH" in body["reason_codes"]
        assert body["type"] == "agent_mismatch"
        assert body["action"] == "self_correct"
        assert "other-agent" in body["reflection"]

    def test_missing_trusted_identity_denied(self, make_flow, configured_gateway):
        gw, env, _registry, _vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        # A caller-controlled metadata value is not an identity source.
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            gw.request(flow)

        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["AGENT_IDENTITY_REQUIRED"]
        assert "agent" not in flow.metadata

    def test_conflicting_trusted_identity_denied(self, make_flow, configured_gateway):
        gw, env, _registry, _vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")
        flow.metadata["agent"] = "other-agent"

        with patch("service_gateway.ctx", _mock_ctx()):
            gw.request(flow)

        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["AGENT_IDENTITY_CONFLICT"]
        assert flow.metadata["agent_identity_status"] == "conflict"

    def test_unknown_host_gateway_token_fails_closed(self, make_flow, configured_gateway):
        """An sgw_ token never passes upstream because host metadata is missing."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://evil.example.com/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["GATEWAY_CONFIGURATION_ERROR"]
        assert token not in str(flow.request.headers)

    def test_unknown_host_ordinary_credential_still_passes_through(
        self, make_flow, configured_gateway
    ):
        gw, _env, registry, _vault_obj = configured_gateway
        flow = make_flow(
            url="https://evil.example.com/v1/feeds",
            headers={"authorization": "Bearer ordinary-upstream-token"},
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["authorization"] == "Bearer ordinary-upstream-token"

    def test_missing_registry_gateway_token_fails_closed_and_is_stripped(
        self, make_flow, gateway
    ):
        gateway._host_map = {"api.example.com": "missing-service"}
        token = f"sgw_{'d' * 64}"
        flow = make_flow(
            url="https://api.example.com/v1/data",
            headers={"authorization": f"Bearer {token}"},
        )

        with (
            patch("service_gateway.ctx", _mock_ctx()),
            patch(
                "service_gateway.get_service_registry",
                autospec=True,
                return_value=None,
            ),
        ):
            gateway.request(flow)

        assert flow.response.status_code == 503
        assert token not in str(flow.request.headers)
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["GATEWAY_CONFIGURATION_ERROR"]

    def test_invalid_token_denied(self, make_flow, gateway, registry):
        gateway._host_map = {"api.minifuse.io": "minifuse"}
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": f"sgw_{'x' * 64}"},
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "INVALID_TOKEN" in body["reason_codes"]
        assert body["type"] == "invalid_token"
        assert body["action"] == "self_correct"
        assert "not recognized" in body["reflection"]

    def test_route_not_in_capability_denied(self, make_flow, configured_gateway):
        """POST to a path not in the reader capability is denied."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            method="POST",
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "ROUTE_DENIED" in body["reason_codes"]
        assert body["type"] == "route_denied"
        assert body["action"] == "self_correct"
        assert "reader" in body["reflection"]

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
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "CAPABILITY_NOT_FOUND" in body["reason_codes"]
        assert body["type"] == "capability_not_found"
        assert body["action"] == "self_correct"
        assert "nonexistent" in body["reflection"]
        assert "minifuse" in body["reflection"]

    def test_host_mismatch_denied(self, make_flow, configured_gateway):
        """G5: Token bound to service A used against host mapped to service B is denied."""
        gw, env, registry, vault_obj = configured_gateway
        # Token is for minifuse, but we send it to gmail.googleapis.com
        minifuse_token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"authorization": f"Bearer {minifuse_token}"},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "HOST_MISMATCH" in body["reason_codes"]
        assert body["type"] == "host_mismatch"
        assert body["action"] == "self_correct"

    def test_vault_unavailable_returns_503(self, make_flow, configured_gateway):
        """G3: When vault is unavailable, gateway returns 503 not a silent pass-through."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=None):
                    gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert "VAULT_UNAVAILABLE" in body["reason_codes"]
        assert "vault" in body["reflection"].lower()

    def test_credential_not_found_returns_503(self, make_flow, configured_gateway):
        """G4: When credential is not in vault, gateway returns 503."""
        gw, env, registry, vault_obj = configured_gateway
        token = env["test-agent"]["minifuse"]
        flow = make_flow(
            url="https://api.minifuse.io/v1/feeds",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "test-agent")

        vault_obj.remove("minifuse-test")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert "CREDENTIAL_NOT_FOUND" in body["reason_codes"]
        assert "safeyolo agent authorize" in body["reflection"]


# --- Risky Route PDP Integration Tests ---


class TestRiskyRoutePDP:
    def test_risky_route_pdp_allow(self, make_flow, configured_gateway):
        """Risky route that PDP allows → credential injected."""
        gw, env, registry, vault_obj = configured_gateway

        mock_client = _policy_client(
            evaluate=_decision(Effect.ALLOW),
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )

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
            url="https://api.testrisky.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    # Patch inside the _check_risky_route method's import scope
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
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

        # Route check must pass (ALLOW) so we reach the risky route check
        mock_client = _policy_client(
            evaluate=mock_decision,
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )

        flow = make_flow(
            method="POST",
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
                            gateway.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert "GATEWAY_RISKY_ROUTE" in body["reason_codes"]
        assert body["type"] == "gateway_risky_route"
        assert body["action"] == "wait_for_approval"
        assert body["reflection"] == {"service": "test_risky", "question": "Check signals"}


class TestRiskyRouteFailClosed:
    """Fail-closed tests: risky routes must deny when PDP is unavailable."""

    def test_risky_route_no_pdp_denies(self, make_flow, tmp_path):
        """B1: When PDP not configured, risky route must NOT allow through — returns non-None to block."""
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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
        )

        gw = ServiceGateway()
        gw._host_map = {"api.test.com": "test_risky"}
        env = gw.mint_tokens(
            {"agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}}},
        )
        token = env["agent-1"]["test_risky"]

        flow = make_flow(
            method="DELETE",
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    # PDP not configured — risky route must fail closed
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=False):
                        gw.request(flow)

        # Critical: credential must NOT have been injected
        assert "real-token" not in str(flow.request.headers)
        assert gw.stats.injected == 0

    def test_risky_route_pdp_exception_denies(self, make_flow, tmp_path):
        """PDP raising an exception on risky route check fails closed with 503."""
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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
        )

        gw = ServiceGateway()
        gw._host_map = {"api.test.com": "test_risky"}
        env = gw.mint_tokens(
            {"agent-1": {"test_risky": {"capability": "full", "token": "test-cred"}}},
        )
        token = env["agent-1"]["test_risky"]

        mock_client = _policy_client(
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )
        mock_client.evaluate.side_effect = RuntimeError("PDP connection failed")

        flow = make_flow(
            method="DELETE",
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
                            gw.request(flow)

        # Fail closed: must block, credential must not be injected
        assert flow.response is not None
        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert "PDP_ERROR" in body["reason_codes"]
        assert "real-token" not in str(flow.request.headers)


class TestPDPRouteCheck:
    """Tests for PDP-delegated route check in the gateway."""

    def test_route_check_calls_pdp(self, make_flow, gateway, tmp_path):
        """Gateway delegates route check to PDP evaluate_gateway_request."""
        from pdp.schemas import Effect

        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_svc
auth:
  type: bearer
capabilities:
  reader:
    description: "Read-only"
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
        registry = init_service_registry(svc_dir)

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
        )

        gateway._host_map = {"api.test.com": "test_svc"}
        env = gateway.mint_tokens(
            {"agent-1": {"test_svc": {"capability": "reader", "token": "test-cred"}}},
        )
        token = env["agent-1"]["test_svc"]

        # PDP allows the route
        mock_client = _policy_client(
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )

        flow = make_flow(
            url="https://api.test.com/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
                            gateway.request(flow)

        # Route allowed → credential injected
        assert flow.response is None
        mock_client.evaluate_gateway_request.assert_called_once_with(
            service="test_svc", capability="reader",
            agent="agent-1", method="GET", path="/v1/feeds",
        )

    def test_route_check_deny_blocks_request(self, make_flow, gateway, tmp_path):
        """PDP denying a route → 403 ROUTE_DENIED."""
        from pdp.schemas import Effect

        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "test_svc.yaml").write_text("""
schema_version: 1
name: test_svc
auth:
  type: bearer
capabilities:
  reader:
    description: "Read-only"
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
        registry = init_service_registry(svc_dir)

        gateway._host_map = {"api.test.com": "test_svc"}
        env = gateway.mint_tokens(
            {"agent-1": {"test_svc": {"capability": "reader", "token": "test-cred"}}},
        )
        token = env["agent-1"]["test_svc"]

        # PDP denies the route
        mock_client = _policy_client(
            evaluate_gateway_request=_decision(Effect.DENY),
        )

        flow = make_flow(
            method="DELETE",
            url="https://api.test.com/v1/feeds",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                    with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
                        gateway.request(flow)

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

        vault = _vault_with(
            services_dir,
            VaultCredential(name="minifuse-test", type="api_key", value="real-key-456"),
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
            url="https://api.minifuse.io/v1/resources",
            headers={"x-api-key": token},
        )
        _set_agent(flow, "my-agent")

        # minifuse reader capability has /v1/** GET
        # /v1/resources should match /v1/**
        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    gw.request(flow)

        assert flow.response is None
        assert flow.request.headers["X-API-Key"] == "real-key-456"
        assert flow.metadata["gateway_service"] == "minifuse"
        assert flow.metadata["gateway_capability"] == "reader"
        assert flow.metadata["gateway_agent"] == "my-agent"
        assert gw.stats.injected == 1



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

    def test_add_grant_invalid_scope_raises(self, gateway):
        """B7: Invalid scope raises ValueError with descriptive message."""
        with pytest.raises(ValueError, match="Invalid grant scope 'forever'"):
            gateway.add_grant("claude", "minifuse", "DELETE", "/v1/feeds/1", scope="forever")

    def test_add_grant_valid_scopes_accepted(self, gateway):
        """All three valid scopes are accepted without error."""
        g1 = gateway.add_grant("claude", "svc", "DELETE", "/a", scope="once")
        assert g1.scope == "once"
        g2 = gateway.add_grant("claude", "svc", "DELETE", "/b", scope="session")
        assert g2.scope == "session"
        g3 = gateway.add_grant("claude", "svc", "DELETE", "/c", scope="remembered")
        assert g3.scope == "remembered"

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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
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
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
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
        # Route check must pass (ALLOW) so we reach the risky route check
        mock_client = _policy_client(
            evaluate=mock_decision,
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )

        flow = make_flow(
            method="DELETE",
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
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
        flow.response = http.Response.make(200)

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 0

    def test_once_grant_not_consumed_on_4xx(self, gateway):
        """Once-scope grant survives non-2xx response."""
        from mitmproxy.test import tflow

        grant = gateway.add_grant("agent-1", "svc", "DELETE", "/api/item")

        flow = tflow.tflow()
        flow.metadata["gateway_grant_id"] = grant.grant_id
        flow.response = http.Response.make(404)

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 1

    def test_session_grant_not_consumed(self, gateway):
        """Session-scope grant survives 2xx response."""
        from mitmproxy.test import tflow

        grant = gateway.add_grant("agent-1", "svc", "DELETE", "/api/item", scope="session")

        flow = tflow.tflow()
        flow.metadata["gateway_grant_id"] = grant.grant_id
        flow.response = http.Response.make(200)

        with patch("service_gateway.ctx", _mock_ctx()):
            gateway.response(flow)

        assert len(gateway.list_grants()) == 1

    def test_response_no_grant_id_ignored(self, gateway):
        """Flows without gateway_grant_id are ignored by response()."""
        from mitmproxy.test import tflow

        gateway.add_grant("agent-1", "svc", "DELETE", "/api/item")

        flow = tflow.tflow()
        # No gateway_grant_id in metadata
        flow.response = http.Response.make(200)

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

        vault = _vault_with(
            tmp_path,
            VaultCredential(name="test-cred", type="bearer", value="real-token"),
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
        # Route check must pass (ALLOW) so we reach the risky route check
        mock_client = _policy_client(
            evaluate=mock_decision,
            evaluate_gateway_request=_decision(Effect.ALLOW),
        )

        flow = make_flow(
            method="POST",
            url="https://api.test.com/api/admin/users",
            headers={"authorization": f"Bearer {token}"},
        )
        _set_agent(flow, "agent-1")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault):
                    with patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
                        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client):
                            with patch("service_gateway.write_event", autospec=True) as mock_write:
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
    """Tests for _persist_grants and _load_grants_from_policy."""

    @pytest.fixture
    def policy_toml(self, tmp_path):
        """Create a policy.toml with an agent entry."""
        import tomlkit

        doc = tomlkit.document()
        doc.add("version", "2.0")
        agents = tomlkit.table()
        claude = tomlkit.table()
        claude.add("template", "claude-code")
        agents.add("claude", claude)
        doc.add("agents", agents)
        path = tmp_path / "policy.toml"
        path.write_text(tomlkit.dumps(doc))
        return path

    @pytest.fixture
    def mock_pdp(self, policy_toml):
        """Run persistence against a real local PDP and policy loader."""
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=policy_toml))

        with (
            patch("pdp.get_policy_client", autospec=True, return_value=client),
            patch("pdp.is_policy_client_configured", autospec=True, return_value=True),
        ):
            yield
        client.shutdown()

    def test_persist_writes_grants(self, gateway, mock_pdp, policy_toml):
        """Grants are written to policy.toml."""
        import tomlkit

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

        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        grants = agents["claude"]["grants"]
        assert len(grants) == 1
        assert grants[0]["grant_id"] == "g1"
        assert grants[0]["service"] == "gmail"

    def test_load_reads_remembered_grants(self, gateway, mock_pdp, policy_toml):
        """Remembered grants are loaded from policy.toml."""
        from datetime import timedelta

        import tomlkit

        now = datetime.now(UTC)
        created = now.isoformat()
        expires = (now + timedelta(hours=1)).isoformat()

        doc = tomlkit.parse(policy_toml.read_text())
        grants = tomlkit.aot()
        grant = tomlkit.table()
        grant.add("grant_id", "g2")
        grant.add("service", "gmail")
        grant.add("method", "DELETE")
        grant.add("path", "/messages/*")
        grant.add("scope", "remembered")
        grant.add("created", created)
        grant.add("expires", expires)
        grants.append(grant)
        doc["agents"]["claude"].add("grants", grants)
        policy_toml.write_text(tomlkit.dumps(doc))

        gateway._load_grants_from_policy()
        assert "g2" in gateway._grants
        assert gateway._grants["g2"].service == "gmail"
        assert gateway._grants["g2"].scope == "remembered"

    def test_persist_then_load_roundtrip(self, gateway, mock_pdp, policy_toml):
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
        gw2._load_grants_from_policy()
        assert "g3" in gw2._grants
        assert gw2._grants["g3"].service == "slack"
        assert gw2._grants["g3"].method == "POST"

    def test_session_grants_skipped_during_load(self, gateway, mock_pdp, policy_toml):
        """G8: Session-scope grants are not loaded from policy.toml (they don't survive restart)."""
        from datetime import timedelta

        import tomlkit

        now = datetime.now(UTC)
        created = now.isoformat()
        expires = (now + timedelta(hours=1)).isoformat()

        doc = tomlkit.parse(policy_toml.read_text())
        grants = tomlkit.aot()

        # Session grant — should be skipped
        session_grant = tomlkit.table()
        session_grant.add("grant_id", "g_session")
        session_grant.add("service", "gmail")
        session_grant.add("method", "POST")
        session_grant.add("path", "/messages/send")
        session_grant.add("scope", "session")
        session_grant.add("created", created)
        session_grant.add("expires", expires)
        grants.append(session_grant)

        # Remembered grant — should be loaded
        remembered_grant = tomlkit.table()
        remembered_grant.add("grant_id", "g_remembered")
        remembered_grant.add("service", "slack")
        remembered_grant.add("method", "POST")
        remembered_grant.add("path", "/chat.postMessage")
        remembered_grant.add("scope", "remembered")
        remembered_grant.add("created", created)
        remembered_grant.add("expires", expires)
        grants.append(remembered_grant)

        doc["agents"]["claude"].add("grants", grants)
        policy_toml.write_text(tomlkit.dumps(doc))

        gateway._load_grants_from_policy()

        assert "g_session" not in gateway._grants
        assert "g_remembered" in gateway._grants
        assert gateway._grants["g_remembered"].service == "slack"

    def test_malformed_grant_does_not_break_other_grants(self, gateway, mock_pdp, policy_toml):
        """B8: One malformed grant dict does not prevent loading valid grants."""
        from datetime import timedelta

        import tomlkit

        now = datetime.now(UTC)
        created = now.isoformat()
        expires = (now + timedelta(hours=1)).isoformat()

        doc = tomlkit.parse(policy_toml.read_text())
        grants = tomlkit.aot()

        # Malformed grant — missing required "service" key
        bad_grant = tomlkit.table()
        bad_grant.add("grant_id", "g_bad")
        bad_grant.add("method", "DELETE")
        bad_grant.add("path", "/v1/feeds/1")
        bad_grant.add("scope", "remembered")
        bad_grant.add("created", created)
        bad_grant.add("expires", expires)
        grants.append(bad_grant)

        # Valid grant
        good_grant = tomlkit.table()
        good_grant.add("grant_id", "g_good")
        good_grant.add("service", "minifuse")
        good_grant.add("method", "DELETE")
        good_grant.add("path", "/v1/feeds/*")
        good_grant.add("scope", "remembered")
        good_grant.add("created", created)
        good_grant.add("expires", expires)
        grants.append(good_grant)

        doc["agents"]["claude"].add("grants", grants)
        policy_toml.write_text(tomlkit.dumps(doc))

        gateway._load_grants_from_policy()

        # Bad grant skipped, good grant loaded
        assert "g_bad" not in gateway._grants
        assert "g_good" in gateway._grants
        assert gateway._grants["g_good"].service == "minifuse"

    def test_persist_grants_for_unknown_agent_silently_dropped(self, gateway, mock_pdp, policy_toml):
        """B2: Grants for agents not in policy.toml [agents] are silently dropped on persist."""
        grant = GrantEntry(
            grant_id="g_orphan",
            agent="unknown-agent",
            service="gmail",
            method="POST",
            path="/messages/send",
            scope="remembered",
        )
        gateway._grants["g_orphan"] = grant
        gateway._persist_grants()

        # The grant is in memory but not persisted (agent not in policy.toml)
        import tomlkit
        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        # unknown-agent doesn't exist in policy, so no grants written for it
        assert "unknown-agent" not in agents

        # But the in-memory grant is still there
        assert "g_orphan" in gateway._grants


# =========================================================================
# Contract Binding State
# =========================================================================


class TestContractBindingState:
    def test_add_and_get(self):
        gw = ServiceGateway()
        binding = gw.add_contract_binding(
            agent="claude",
            service="gmail",
            capability="read_messages",
            template="gmail.read_messages.v1",
            bound_values={"approved_category": "CATEGORY_PROMOTIONS"},
            grantable_operations=["list_messages"],
        )
        assert binding.binding_id.startswith("cbs_")
        assert binding.agent == "claude"
        assert binding.bound_values["approved_category"] == "CATEGORY_PROMOTIONS"

        # Retrieve
        result = gw.get_contract_binding("claude", "gmail", "read_messages")
        assert result is not None
        assert result.binding_id == binding.binding_id

    def test_get_missing_returns_none(self):
        gw = ServiceGateway()
        assert gw.get_contract_binding("claude", "gmail", "read_messages") is None

    def test_replace_existing(self):
        gw = ServiceGateway()
        b1 = gw.add_contract_binding(
            agent="claude", service="gmail", capability="read_messages",
            template="v1", bound_values={"cat": "A"}, grantable_operations=["op1"],
        )
        b2 = gw.add_contract_binding(
            agent="claude", service="gmail", capability="read_messages",
            template="v1", bound_values={"cat": "B"}, grantable_operations=["op1"],
        )
        assert b1.binding_id != b2.binding_id
        result = gw.get_contract_binding("claude", "gmail", "read_messages")
        assert result.binding_id == b2.binding_id
        assert result.bound_values["cat"] == "B"

    def test_revoke(self):
        gw = ServiceGateway()
        binding = gw.add_contract_binding(
            agent="claude", service="gmail", capability="read_messages",
            template="v1", bound_values={}, grantable_operations=[],
        )
        assert gw.revoke_contract_binding(binding.binding_id) is True
        assert gw.get_contract_binding("claude", "gmail", "read_messages") is None

    def test_revoke_missing(self):
        gw = ServiceGateway()
        assert gw.revoke_contract_binding("cbs_nonexistent") is False

    def test_different_agents_independent(self):
        gw = ServiceGateway()
        gw.add_contract_binding(
            agent="claude", service="gmail", capability="read_messages",
            template="v1", bound_values={"cat": "A"}, grantable_operations=[],
        )
        gw.add_contract_binding(
            agent="boris", service="gmail", capability="read_messages",
            template="v1", bound_values={"cat": "B"}, grantable_operations=[],
        )
        c = gw.get_contract_binding("claude", "gmail", "read_messages")
        b = gw.get_contract_binding("boris", "gmail", "read_messages")
        assert c.bound_values["cat"] == "A"
        assert b.bound_values["cat"] == "B"


# =========================================================================
# End-to-end contract enforcement via request()
# =========================================================================


class TestContractEnforcementE2E:
    """End-to-end tests exercising the gateway request() path with contracts."""

    @pytest.fixture
    def contract_services_dir(self, tmp_path):
        """Create temp services dir with a contract-enabled service."""
        svc_dir = tmp_path / "contract_services"
        svc_dir.mkdir()
        (svc_dir / "contractsvc.yaml").write_text("""
schema_version: 1
name: contractsvc
default_host: api.contractsvc.com
auth:
  type: bearer
capabilities:
  read_items:
    description: "Read items filtered by category"
    routes:
      - methods: [GET]
        path: "/api/v1/items"
      - methods: [GET]
        path: "/api/v1/items/*"
    contract:
      template: contractsvc.read_items.v1
      bindings:
        approved_category:
          source: agent
          type: enum
          options: [ELECTRONICS, BOOKS, CLOTHING]
          visible_to_operator: true
      operations:
        - name: list_items
          request:
            method: GET
            path: /api/v1/items
            transport:
              require_no_body: true
              allow_headers: [Accept]
              deny_ambiguous_encoding: true
            query:
              allow:
                category:
                  equals_var: approved_category
                limit:
                  integer_range: [1, 50]
              deny_unknown: true
        - name: get_item
          requires_enforcement: state_enforcement
          request:
            method: GET
            path: "/api/v1/items/{id}"
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
""")
        return svc_dir

    @pytest.fixture
    def contract_registry(self, contract_services_dir):
        return init_service_registry(contract_services_dir)

    @pytest.fixture
    def contract_vault(self, tmp_path):
        vault_path = tmp_path / "contract_vault.yaml.enc"
        v = Vault(vault_path)
        v.unlock("test-pass")
        v.store(VaultCredential(name="test-cred", type="oauth2", value="real-bearer-token"))
        return v

    @pytest.fixture
    def gw_with_contract(self, contract_registry, contract_vault):
        from service_gateway import TokenBinding
        gw = ServiceGateway()
        token = mint_gateway_token()
        gw._token_map[token] = TokenBinding(
            agent="testbot",
            service_name="contractsvc",
            capability_name="read_items",
            vault_token="test-cred",
        )
        gw._host_map = {"api.contractsvc.com": "contractsvc"}
        return gw, token, contract_registry, contract_vault

    def _clean_flow(self, make_flow, token, url, **kwargs):
        """Create a flow with only contract-compatible headers."""
        flow = make_flow(url=url, headers={"authorization": f"Bearer {token}"}, **kwargs)
        # Remove default tflow headers not in our contract allowlist
        for h in list(flow.request.headers.keys()):
            if h.lower() not in ("authorization", "accept", "host", "content-length"):
                del flow.request.headers[h]
        _set_agent(flow, "testbot")
        return flow

    def test_bound_contract_allows_matching_request(self, make_flow, gw_with_contract):
        gw, token, registry, vault_obj = gw_with_contract

        gw.add_contract_binding(
            agent="testbot", service="contractsvc", capability="read_items",
            template="contractsvc.read_items.v1",
            bound_values={"approved_category": "ELECTRONICS"},
            grantable_operations=["list_items"],
        )

        flow = self._clean_flow(
            make_flow, token,
            url="https://api.contractsvc.com/api/v1/items?category=ELECTRONICS&limit=10",
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        if flow.response is not None:
            body = json.loads(flow.response.content)
            pytest.fail(f"Expected no response but got {flow.response.status_code}: {body}")
        assert flow.metadata.get("gateway_service") == "contractsvc"

    def test_no_binding_denied(self, make_flow, gw_with_contract):
        gw, token, registry, vault_obj = gw_with_contract

        flow = self._clean_flow(
            make_flow, token,
            url="https://api.contractsvc.com/api/v1/items?category=ELECTRONICS",
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "CONTRACT_NOT_BOUND" in body["reason_codes"]

    def test_wrong_binding_value_denied(self, make_flow, gw_with_contract):
        gw, token, registry, vault_obj = gw_with_contract

        gw.add_contract_binding(
            agent="testbot", service="contractsvc", capability="read_items",
            template="v1", bound_values={"approved_category": "ELECTRONICS"},
            grantable_operations=["list_items"],
        )

        flow = self._clean_flow(
            make_flow, token,
            url="https://api.contractsvc.com/api/v1/items?category=BOOKS",
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "CONTRACT_VIOLATION" in body["reason_codes"]
        assert body.get("field") == "category"

    def test_unknown_query_param_denied(self, make_flow, gw_with_contract):
        gw, token, registry, vault_obj = gw_with_contract

        gw.add_contract_binding(
            agent="testbot", service="contractsvc", capability="read_items",
            template="v1", bound_values={"approved_category": "ELECTRONICS"},
            grantable_operations=["list_items"],
        )

        flow = self._clean_flow(
            make_flow, token,
            url="https://api.contractsvc.com/api/v1/items?category=ELECTRONICS&q=secret",
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "CONTRACT_VIOLATION" in body["reason_codes"]
        assert body.get("field") == "q"

    def test_non_grantable_operation_denied(self, make_flow, gw_with_contract):
        gw, token, registry, vault_obj = gw_with_contract

        gw.add_contract_binding(
            agent="testbot", service="contractsvc", capability="read_items",
            template="v1", bound_values={"approved_category": "ELECTRONICS"},
            grantable_operations=["list_items"],
        )

        # get_item requires state_enforcement (declared) — not grantable
        flow = self._clean_flow(
            make_flow, token,
            url="https://api.contractsvc.com/api/v1/items/123",
        )

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)

        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "OPERATION_NOT_GRANTABLE" in body["reason_codes"]


class TestPrebindingDiscoveryWithRealPDP:
    """Policy compilation and gateway enforcement transition together."""

    def test_discovery_before_binding_then_only_resolved_bound_route(
        self, make_flow, tmp_path
    ):
        services = tmp_path / "services"
        services.mkdir()
        (services / "contractsvc.yaml").write_text(
            """
schema_version: 1
name: contractsvc
default_host: api.contractsvc.com
auth: {type: bearer}
capabilities:
  explorer:
    routes:
      - methods: [GET]
        path: /api/v1/**
    contract:
      template: explorer.v1
      bindings:
        category: {source: operator, type: string}
      operations:
        - name: discover_categories
          request:
            method: GET
            path: /api/v1/categories
            transport: {require_no_body: true}
        - name: list_items
          request:
            method: GET
            path: /api/v1/categories/{id}/items
            path_params:
              id: {equals_var: category}
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
"""
        )
        registry = init_service_registry(services)
        policy_path = tmp_path / "policy.yaml"

        def write_policy(*, bound: bool) -> None:
            binding = ""
            if bound:
                binding = """
    contract_bindings:
      - service: contractsvc
        capability: explorer
        template: explorer.v1
        bound_values: {category: books}
        grantable_operations: [list_items]
"""
            policy_path.write_text(
                """
version: "2.0"
hosts:
  api.contractsvc.com: {service: contractsvc}
agents:
  testbot:
    services:
      contractsvc: {capability: explorer, token: test-cred}
"""
                + binding
            )

        write_policy(bound=False)
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=policy_path))
        vault = _vault_with(
            tmp_path,
            VaultCredential(
                name="test-cred",
                type="bearer",
                value="real-upstream-token",
            ),
        )
        gateway = ServiceGateway()
        gateway._host_map = {"api.contractsvc.com": "contractsvc"}
        token = gateway.mint_tokens(
            {
                "testbot": {
                    "contractsvc": {
                        "capability": "explorer",
                        "token": "test-cred",
                    }
                }
            }
        )["testbot"]["contractsvc"]

        def request(path: str):
            flow = make_flow(
                url=f"https://api.contractsvc.com{path}",
                headers={"authorization": f"Bearer {token}"},
            )
            for header in list(flow.request.headers):
                if header.lower() not in (
                    "authorization",
                    "host",
                    "content-length",
                ):
                    del flow.request.headers[header]
            _set_agent(flow, "testbot")
            with (
                patch("service_gateway.ctx", _mock_ctx()),
                patch(
                    "service_gateway.get_service_registry",
                    autospec=True,
                    return_value=registry,
                ),
                patch(
                    "service_gateway.get_vault",
                    autospec=True,
                    return_value=vault,
                ),
                patch(
                    "pdp.is_policy_client_configured",
                    autospec=True,
                    return_value=True,
                ),
                patch(
                    "pdp.get_policy_client",
                    autospec=True,
                    return_value=client,
                ),
            ):
                gateway.request(flow)
            return flow

        try:
            discovery = request("/api/v1/categories")
            assert discovery.response is None
            assert discovery.request.headers["authorization"] == (
                "Bearer real-upstream-token"
            )

            broadened_discovery = request("/api/v1/categories?secret=value")
            assert broadened_discovery.response.status_code == 403
            assert json.loads(broadened_discovery.response.content)[
                "reason_codes"
            ] == ["CONTRACT_VIOLATION"]

            before_binding = request("/api/v1/categories/books/items")
            assert before_binding.response.status_code == 403
            assert json.loads(before_binding.response.content)["reason_codes"] == [
                "ROUTE_DENIED"
            ]

            write_policy(bound=True)
            assert client._pdp._engine._loader.reload()
            with patch.object(
                gateway,
                "_persist_contract_binding_delta",
                autospec=True,
            ):
                gateway.add_contract_binding(
                    agent="testbot",
                    service="contractsvc",
                    capability="explorer",
                    template="explorer.v1",
                    bound_values={"category": "books"},
                    grantable_operations=["list_items"],
                )

            resolved = request("/api/v1/categories/books/items")
            assert resolved.response is None
            assert resolved.request.headers["authorization"] == (
                "Bearer real-upstream-token"
            )

            wrong_value = request("/api/v1/categories/music/items")
            assert wrong_value.response.status_code == 403
            assert json.loads(wrong_value.response.content)["reason_codes"] == [
                "ROUTE_DENIED"
            ]

            stale_discovery = request("/api/v1/categories")
            assert stale_discovery.response.status_code == 403
            assert json.loads(stale_discovery.response.content)["reason_codes"] == [
                "ROUTE_DENIED"
            ]
        finally:
            client.shutdown()


# =========================================================================
# Transport Hygiene E2E Tests
# =========================================================================


class TestTransportHygieneE2E:
    """End-to-end tests for transport hygiene tightening via request()."""

    @pytest.fixture
    def contract_services_dir(self, tmp_path):
        svc_dir = tmp_path / "hygiene_services"
        svc_dir.mkdir()
        (svc_dir / "hygienesvc.yaml").write_text("""
schema_version: 1
name: hygienesvc
default_host: api.hygienesvc.com
auth:
  type: bearer
capabilities:
  reader:
    description: "Read items"
    routes:
      - methods: [GET]
        path: "/api/v1/items"
      - methods: [GET]
        path: "/api/v1/items/*"
      - methods: [POST]
        path: "/api/v1/items"
    contract:
      template: hygienesvc.reader.v1
      bindings:
        approved_category:
          source: agent
          type: enum
          options: [A, B]
      operations:
        - name: list_items
          request:
            method: GET
            path: /api/v1/items
            transport:
              require_no_body: true
              allow_headers: [Accept]
              deny_ambiguous_encoding: true
            query:
              allow:
                category:
                  equals_var: approved_category
              deny_unknown: true
        - name: create_item
          request:
            method: POST
            path: /api/v1/items
            body:
              allow:
                name:
                  type: string
              deny_unknown: true
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
""")
        return svc_dir

    @pytest.fixture
    def contract_registry(self, contract_services_dir):
        return init_service_registry(contract_services_dir)

    @pytest.fixture
    def contract_vault(self, tmp_path):
        vault_path = tmp_path / "hygiene_vault.yaml.enc"
        v = Vault(vault_path)
        v.unlock("test-pass")
        v.store(VaultCredential(name="test-cred", type="oauth2", value="real-bearer-token"))
        return v

    @pytest.fixture
    def gw_with_contract(self, contract_registry, contract_vault):
        from service_gateway import TokenBinding
        gw = ServiceGateway()
        token = mint_gateway_token()
        gw._token_map[token] = TokenBinding(
            agent="testbot",
            service_name="hygienesvc",
            capability_name="reader",
            vault_token="test-cred",
        )
        gw._host_map = {"api.hygienesvc.com": "hygienesvc"}
        gw.add_contract_binding(
            agent="testbot", service="hygienesvc", capability="reader",
            template="hygienesvc.reader.v1",
            bound_values={"approved_category": "A"},
            grantable_operations=["list_items", "create_item"],
        )
        return gw, token, contract_registry, contract_vault

    def _clean_flow(self, make_flow, token, url, **kwargs):
        flow = make_flow(url=url, headers={"authorization": f"Bearer {token}"}, **kwargs)
        for h in list(flow.request.headers.keys()):
            if h.lower() not in ("authorization", "accept", "host", "content-length", "content-type"):
                del flow.request.headers[h]
        _set_agent(flow, "testbot")
        return flow

    def test_path_traversal_denied(self, make_flow, gw_with_contract):
        """Request with /../ in path → denied at contract enforcement."""
        gw, token, registry, vault_obj = gw_with_contract
        # Use a path that resolves to a valid route after normalisation
        # but contains dot segments that must be rejected before evaluation.
        # /api/v1/items/../items resolves to /api/v1/items which matches.
        flow = self._clean_flow(
            make_flow, token,
            url="https://api.hygienesvc.com/api/v1/items/../items?category=A",
        )
        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)
        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "TRANSPORT_PATH_TRICK" in body["reason_codes"]

    def test_duplicate_header_denied(self, make_flow, gw_with_contract):
        """Request with duplicate Accept header → denied."""
        gw, token, registry, vault_obj = gw_with_contract
        flow = make_flow(url="https://api.hygienesvc.com/api/v1/items?category=A")
        # Manually set raw headers with duplicates
        from mitmproxy.http import Headers
        flow.request.headers = Headers(fields=[
            (b"authorization", f"Bearer {token}".encode()),
            (b"host", b"api.hygienesvc.com"),
            (b"accept", b"text/html"),
            (b"accept", b"application/json"),
        ])
        _set_agent(flow, "testbot")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                gw.request(flow)
        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "TRANSPORT_DUPLICATE_HEADER" in body["reason_codes"]

    def test_post_text_plain_denied(self, make_flow, gw_with_contract):
        """POST with text/plain → denied."""
        gw, token, registry, vault_obj = gw_with_contract
        flow = self._clean_flow(
            make_flow, token,
            url="https://api.hygienesvc.com/api/v1/items",
            method="POST",
            content='{"name": "test"}',
        )
        flow.request.headers["content-type"] = "text/plain"
        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)
        assert flow.response is not None
        body = json.loads(flow.response.content)
        assert "TRANSPORT_CONTENT_TYPE" in body["reason_codes"]

    def test_clean_request_passes(self, make_flow, gw_with_contract):
        """Clean GET request with proper contract values → passes."""
        gw, token, registry, vault_obj = gw_with_contract
        flow = self._clean_flow(
            make_flow, token,
            url="https://api.hygienesvc.com/api/v1/items?category=A",
        )
        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)
        if flow.response is not None:
            body = json.loads(flow.response.content)
            pytest.fail(f"Expected pass but got {flow.response.status_code}: {body}")
        assert flow.metadata.get("gateway_service") == "hygienesvc"


# --- allow_http opt-in tests (#346) ---


class TestAllowHttpOptIn:
    """`auth.allow_http` bypasses the HTTP→HTTPS redirect for services on
    operator-vouched trusted transports (tailnet / WireGuard / private VLAN).

    Default is False — existing services keep the redirect. Opt-in is per
    service YAML and emits a MEDIUM `gateway.http_injection_allowed` event
    every time it fires so the operator sees the HTTP injection happen.
    """

    def test_yaml_round_trips_through_authconfig(self):
        from safeyolo.core.service_loader import AuthConfig

        cfg = AuthConfig.from_dict(
            {"type": "api_key", "header": "X-Auth-Token", "allow_http": True}
        )
        assert cfg.allow_http is True

        default_cfg = AuthConfig.from_dict({"type": "api_key", "header": "X-Auth-Token"})
        assert default_cfg.allow_http is False

    @pytest.fixture
    def _trusted_transport_env(self, tmp_path):
        """Two v1 services identical except for auth.allow_http."""
        svc_dir = tmp_path / "allow_http_services"
        svc_dir.mkdir()
        (svc_dir / "denysvc.yaml").write_text("""
schema_version: 1
name: denysvc
default_host: api.denysvc.internal
auth:
  type: api_key
  header: X-Auth-Token
  allow_http: false
capabilities:
  reader:
    description: "Read"
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
        (svc_dir / "allowsvc.yaml").write_text("""
schema_version: 1
name: allowsvc
default_host: api.allowsvc.internal
auth:
  type: api_key
  header: X-Auth-Token
  allow_http: true
capabilities:
  reader:
    description: "Read"
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
        registry = init_service_registry(svc_dir)

        vault_path = tmp_path / "trusted_vault.yaml.enc"
        v = Vault(vault_path)
        v.unlock("test-pass")
        v.store(VaultCredential(name="deny-cred", type="api_key", value="real-deny-key"))
        v.store(VaultCredential(name="allow-cred", type="api_key", value="real-allow-key"))

        gw = ServiceGateway()
        gw._host_map = {
            "api.denysvc.internal": "denysvc",
            "api.allowsvc.internal": "allowsvc",
        }
        env = gw.mint_tokens(
            {
                "test-agent": {
                    "denysvc": {"capability": "reader", "token": "deny-cred"},
                    "allowsvc": {"capability": "reader", "token": "allow-cred"},
                },
            }
        )
        return gw, env, registry, v

    def test_http_still_redirects_when_flag_false(self, make_flow, _trusted_transport_env):
        gw, env, registry, vault_obj = _trusted_transport_env
        token = env["test-agent"]["denysvc"]

        flow = make_flow(url="http://api.denysvc.internal/v1/things", headers={"X-Auth-Token": token})
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 301
        assert flow.response.headers["Location"] == "https://api.denysvc.internal/v1/things"
        assert flow.response.headers["X-SafeYolo-Reason"] == "credential-injection-requires-https"
        assert "real-deny-key" not in str(flow.request.headers)

    def test_http_injects_when_flag_true(self, make_flow, _trusted_transport_env):
        gw, env, registry, vault_obj = _trusted_transport_env
        token = env["test-agent"]["allowsvc"]

        flow = make_flow(url="http://api.allowsvc.internal/v1/things", headers={"X-Auth-Token": token})
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    gw.request(flow)

        assert flow.response is None, "expected credential swap to proceed, not a redirect"
        assert flow.request.headers["X-Auth-Token"] == "real-allow-key"
        assert flow.request.url == "http://api.allowsvc.internal/v1/things"

    def test_gateway_http_injection_allowed_event_fires(self, make_flow, _trusted_transport_env):
        gw, env, registry, vault_obj = _trusted_transport_env
        token = env["test-agent"]["allowsvc"]

        flow = make_flow(url="http://api.allowsvc.internal/v1/things", headers={"X-Auth-Token": token})
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    with patch("service_gateway.write_event", autospec=True) as mock_write:
                        gw.request(flow)

        events = [c[0][0] for c in mock_write.call_args_list]
        assert "gateway.http_injection_allowed" in events
        assert "gateway.https_redirect" not in events

    def test_no_http_injection_event_when_flag_false(self, make_flow, _trusted_transport_env):
        gw, env, registry, vault_obj = _trusted_transport_env
        token = env["test-agent"]["denysvc"]

        flow = make_flow(url="http://api.denysvc.internal/v1/things", headers={"X-Auth-Token": token})
        _set_agent(flow, "test-agent")

        with patch("service_gateway.ctx", _mock_ctx()):
            with patch("service_gateway.get_service_registry", autospec=True, return_value=registry):
                with patch("service_gateway.get_vault", autospec=True, return_value=vault_obj):
                    with patch("service_gateway.write_event", autospec=True) as mock_write:
                        gw.request(flow)

        events = [c[0][0] for c in mock_write.call_args_list]
        assert "gateway.https_redirect" in events
        assert "gateway.http_injection_allowed" not in events
