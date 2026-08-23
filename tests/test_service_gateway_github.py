"""Github service definition + smart-HTTP routing at the Service Gateway.

Covers:

  * fetch/clone (POST git-upload-pack, GET info/refs) — normal capability route,
    NOT gated by risky-route approval.
  * push (POST git-receive-pack) — matches a risky route, emits an approval
    request with structured `operation`/`repository` details, blocks with 428.
  * approve → grant → retry succeeds.
  * deny → retry still blocked.
  * The resolved PAT is only ever placed in the Authorization: Basic header
    and never leaks into any other request field.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from service_gateway import SGW_TOKEN_PREFIX, ServiceGateway, _parse_git_smart_http

from safeyolo.core.service_loader import init_service_registry
from safeyolo.core.vault import Vault, VaultCredential


REPO_ROOT_SERVICES = Path("/workspace/safeyolo/config/services")


# --- Fixtures --------------------------------------------------------------


@pytest.fixture
def github_registry(tmp_path):
    """Load the real github.yaml + a user services dir."""
    user_dir = tmp_path / "services"
    user_dir.mkdir()
    return init_service_registry(user_dir, builtin_dir=REPO_ROOT_SERVICES)


@pytest.fixture
def pat_vault(tmp_path):
    v = Vault(tmp_path / "vault.yaml.enc")
    v.unlock("pw")
    v.store(VaultCredential(name="github-pat", type="bearer", value="ghp_realpat_abcdef123456"))
    return v


@pytest.fixture
def github_gateway(github_registry, pat_vault):
    gw = ServiceGateway()
    gw._host_map = {"github.com": "github"}
    env = gw.mint_tokens(
        {
            "test-agent": {
                "github": {"capability": "git_push", "credential": "github-pat"},
            }
        }
    )
    return gw, env, github_registry, pat_vault


def _mock_ctx():
    m = MagicMock()
    m.options.gateway_enabled = True
    return m


def _mock_pdp_allow():
    """PDP mock that allows both capability route + risky route evaluation."""
    from pdp.schemas import Effect

    decision = MagicMock()
    decision.effect = Effect.ALLOW
    client = MagicMock()
    client.evaluate.return_value = decision
    client.evaluate_gateway_request.return_value = decision
    return client


def _mock_pdp_require_approval():
    """PDP mock: capability check allows, risky route requires approval (no immediate response)."""
    from pdp.schemas import Effect

    allow = MagicMock()
    allow.effect = Effect.ALLOW

    require_approval = MagicMock()
    require_approval.effect = Effect.REQUIRE_APPROVAL
    require_approval.immediate_response = None

    client = MagicMock()
    client.evaluate.return_value = require_approval  # risky-route eval
    client.evaluate_gateway_request.return_value = allow  # capability check
    return client


# --- Path parsing ----------------------------------------------------------


class TestParseGitSmartHttp:
    def test_receive_pack_is_push(self):
        assert _parse_git_smart_http("/craigbalding/safeyolo/git-receive-pack") == {
            "operation": "push",
            "repository": "craigbalding/safeyolo",
        }

    def test_dot_git_suffix_stripped(self):
        assert _parse_git_smart_http("/craigbalding/safeyolo.git/git-receive-pack") == {
            "operation": "push",
            "repository": "craigbalding/safeyolo",
        }

    def test_upload_pack_is_fetch(self):
        assert _parse_git_smart_http("/owner/repo/git-upload-pack") == {
            "operation": "fetch",
            "repository": "owner/repo",
        }

    def test_info_refs_is_fetch(self):
        assert _parse_git_smart_http("/owner/repo.git/info/refs") == {
            "operation": "fetch",
            "repository": "owner/repo",
        }

    def test_non_git_path_returns_none(self):
        assert _parse_git_smart_http("/owner/repo/pulls") is None
        assert _parse_git_smart_http("/") is None
        assert _parse_git_smart_http("") is None


# --- Fetch is NOT risky ----------------------------------------------------


class TestGithubFetchAllowed:
    def test_fetch_upload_pack_injects_basic_auth(self, make_flow, github_gateway):
        gw, env, registry, vault = github_gateway
        token = env["test-agent"]["github"]

        flow = make_flow(
            method="POST",
            url="https://github.com/craigbalding/safeyolo.git/git-upload-pack",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("pdp.get_policy_client", return_value=_mock_pdp_allow()):
            gw.request(flow)

        assert flow.response is None  # No block.
        expected = "Basic " + base64.b64encode(b"safeyolo:ghp_realpat_abcdef123456").decode("ascii")
        assert flow.request.headers["Authorization"] == expected


# --- Push triggers approval ------------------------------------------------


class TestGithubPushRequiresApproval:
    def test_push_blocked_428_with_operation_and_repository_in_details(
        self, make_flow, github_gateway
    ):
        gw, env, registry, vault = github_gateway
        token = env["test-agent"]["github"]

        flow = make_flow(
            method="POST",
            url="https://github.com/craigbalding/safeyolo.git/git-receive-pack",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        events: list[dict] = []

        def _capture(_name, **kwargs):
            events.append(kwargs)

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("pdp.get_policy_client", return_value=_mock_pdp_require_approval()), \
             patch("service_gateway.write_event", side_effect=_capture):
            gw.request(flow)

        # 428 is emitted on the flow response for the operator to approve.
        assert flow.response is not None
        assert flow.response.status_code == 428

        # Real PAT must not have been injected on the (blocked) request.
        auth = flow.request.headers.get("Authorization", "")
        assert "ghp_realpat_abcdef123456" not in auth
        assert "ghp_realpat_abcdef123456" not in flow.request.url

        # The risky_route audit event carries semantic operation + repository.
        assert any(
            e.get("details", {}).get("operation") == "push"
            and e.get("details", {}).get("repository") == "craigbalding/safeyolo"
            for e in events
        )


# --- Approve → retry succeeds ---------------------------------------------


class TestGithubPushGrantMakesRetrySucceed:
    def test_grant_bypasses_risky_route_check(self, make_flow, github_gateway):
        gw, env, registry, vault = github_gateway
        token = env["test-agent"]["github"]

        # Operator approval materialises as a gateway grant on the concrete route.
        grant = gw.add_grant(
            agent="test-agent",
            service="github",
            method="POST",
            path="/craigbalding/safeyolo.git/git-receive-pack",
            scope="once",
        )
        assert grant is not None

        flow = make_flow(
            method="POST",
            url="https://github.com/craigbalding/safeyolo.git/git-receive-pack",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("pdp.get_policy_client", return_value=_mock_pdp_allow()):
            gw.request(flow)

        assert flow.response is None  # Grant covered the risky route.
        expected = "Basic " + base64.b64encode(b"safeyolo:ghp_realpat_abcdef123456").decode("ascii")
        assert flow.request.headers["Authorization"] == expected


# --- Deny → still blocked --------------------------------------------------


class TestGithubPushDenyLeavesBlocked:
    def test_no_grant_present_means_retry_still_blocked(self, make_flow, github_gateway):
        gw, env, registry, vault = github_gateway
        token = env["test-agent"]["github"]

        flow = make_flow(
            method="POST",
            url="https://github.com/craigbalding/safeyolo.git/git-receive-pack",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("pdp.get_policy_client", return_value=_mock_pdp_require_approval()):
            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        # And nothing was injected.
        assert "ghp_realpat" not in flow.request.headers.get("Authorization", "")


# --- Provider errors surface as 503 ---------------------------------------


class TestProviderErrorSurfaces:
    def test_missing_credential_denies_with_provider_not_found(self, make_flow, github_gateway):
        gw, env, registry, _vault = github_gateway
        token = env["test-agent"]["github"]

        empty_vault = Vault(Path("/tmp/_empty_vault_test.enc"))  # never unlocked
        # Provide an unlocked-but-empty vault so the local provider returns
        # CredentialNotFound rather than ResolveFailed.
        empty_vault._credentials = {}
        empty_vault._fernet = object()  # any truthy value
        empty_vault._salt = b"x" * 16

        flow = make_flow(
            method="POST",
            url="https://github.com/craigbalding/safeyolo.git/git-upload-pack",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=empty_vault), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("pdp.get_policy_client", return_value=_mock_pdp_allow()):
            gw.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert "CREDENTIAL_NOT_FOUND" in body["reason_codes"]
