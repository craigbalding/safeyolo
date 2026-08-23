"""Basic-auth injection at the Service Gateway credential swap point.

Validates that a service declared with `auth.type: basic` gets its sgw_ token
substituted for `Authorization: Basic base64(username:password)` — the
credential value is used as the password and never appears elsewhere on the
request.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
from service_gateway import SGW_TOKEN_PREFIX, ServiceGateway

from safeyolo.core.service_loader import init_service_registry
from safeyolo.core.vault import Vault, VaultCredential


@pytest.fixture
def basic_registry(tmp_path):
    svc_dir = tmp_path / "services"
    svc_dir.mkdir()
    (svc_dir / "basic_svc.yaml").write_text("""
schema_version: 1
name: basic_svc
default_host: basic.example.com
auth:
  type: basic
  username: safeyolo
capabilities:
  reader:
    description: "Read routes"
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
    return init_service_registry(svc_dir)


@pytest.fixture
def basic_vault(tmp_path):
    v = Vault(tmp_path / "vault.yaml.enc")
    v.unlock("pw")
    v.store(VaultCredential(name="basic-secret", type="bearer", value="s3cret-password-42"))
    return v


@pytest.fixture
def basic_gateway(basic_registry, basic_vault):
    gw = ServiceGateway()
    gw._host_map = {"basic.example.com": "basic_svc"}
    env = gw.mint_tokens(
        {
            "test-agent": {
                "basic_svc": {"capability": "reader", "credential": "basic-secret"},
            }
        }
    )
    return gw, env, basic_registry, basic_vault


def _mock_ctx():
    m = MagicMock()
    m.options.gateway_enabled = True
    return m


class TestBasicAuthInjection:
    def test_basic_auth_header_uses_service_username(self, make_flow, basic_gateway):
        gw, env, registry, vault = basic_gateway
        token = env["test-agent"]["basic_svc"]

        flow = make_flow(
            url="https://basic.example.com/v1/items",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault):
            gw.request(flow)

        assert flow.response is None
        expected = "Basic " + base64.b64encode(b"safeyolo:s3cret-password-42").decode("ascii")
        assert flow.request.headers["Authorization"] == expected

    def test_secret_never_appears_in_plaintext_on_request(self, make_flow, basic_gateway):
        """The bare password must NOT show up outside the Authorization header."""
        gw, env, registry, vault = basic_gateway
        token = env["test-agent"]["basic_svc"]

        flow = make_flow(
            url="https://basic.example.com/v1/items",
            headers={"authorization": "Basic " + base64.b64encode(
                f"safeyolo:{token}".encode()
            ).decode("ascii")},
        )
        flow.metadata["agent"] = "test-agent"

        with patch("service_gateway.ctx", _mock_ctx()), \
             patch("service_gateway.get_service_registry", return_value=registry), \
             patch("safeyolo.core.providers.local.get_vault", return_value=vault):
            gw.request(flow)

        # Nothing in URL, non-auth headers, or body carries the raw value.
        assert "s3cret-password-42" not in flow.request.url
        for name, value in flow.request.headers.items():
            if name == "Authorization":
                continue
            assert "s3cret-password-42" not in value
        assert b"s3cret-password-42" not in (flow.request.content or b"")

    def test_service_loader_rejects_basic_without_username(self, tmp_path):
        """auth.type=basic requires a username to be meaningful."""
        svc_dir = tmp_path / "services"
        svc_dir.mkdir()
        # No username field — loader must reject.
        (svc_dir / "bad.yaml").write_text("""
schema_version: 1
name: bad_svc
auth:
  type: basic
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: "/v1/**"
""")
        registry = init_service_registry(svc_dir)
        # The load path swallows individual-service failures and logs them, so
        # the service should simply be absent from the registry.
        assert registry.get_service("bad_svc") is None
