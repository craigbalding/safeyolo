"""Tests for addons/service_loader.py — Service definition loader."""

import pytest
from service_loader import (
    AuthConfig,
    RouteRule,
    ServiceDefinition,
    ServiceRegistry,
)


@pytest.fixture
def services_dir(tmp_path):
    """Create a temp directory with test service definitions."""
    svc_dir = tmp_path / "services"
    svc_dir.mkdir()

    # Gmail service
    (svc_dir / "gmail.yaml").write_text("""
name: gmail
description: "Gmail API"
roles:
  readonly:
    auth:
      type: bearer
      refresh_on_401: true
    routes:
      - effect: deny
        methods: ["*"]
        path: "/gmail/v1/users/me/settings/**"
      - effect: allow
        methods: [GET]
        path: "/gmail/v1/users/me/**"
  sender:
    auth:
      type: bearer
    routes:
      - effect: deny
        methods: ["*"]
        path: "/gmail/v1/users/me/settings/**"
      - effect: allow
        methods: [GET, POST]
        path: "/gmail/v1/users/me/**"
""")

    # MiniFuse service
    (svc_dir / "minifuse.yaml").write_text("""
name: minifuse
description: "MiniFuse API"
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

    return svc_dir


@pytest.fixture
def registry(services_dir):
    reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
    reg.load()
    return reg


class TestRouteRule:
    def test_from_dict_defaults(self):
        rule = RouteRule.from_dict({"effect": "allow"})
        assert rule.effect == "allow"
        assert rule.methods == ["*"]
        assert rule.path == "/*"

    def test_from_dict_full(self):
        rule = RouteRule.from_dict({
            "effect": "deny",
            "methods": ["get", "post"],
            "path": "/api/v1/**",
        })
        assert rule.effect == "deny"
        assert rule.methods == ["GET", "POST"]
        assert rule.path == "/api/v1/**"

    def test_from_dict_string_method(self):
        rule = RouteRule.from_dict({"effect": "allow", "methods": "GET"})
        assert rule.methods == ["GET"]


class TestAuthConfig:
    def test_from_dict_defaults(self):
        auth = AuthConfig.from_dict({"type": "bearer"})
        assert auth.type == "bearer"
        assert auth.header == "Authorization"
        assert auth.scheme == "Bearer"
        assert auth.refresh_on_401 is False

    def test_from_dict_custom(self):
        auth = AuthConfig.from_dict({
            "type": "api_key",
            "header": "X-API-Key",
            "scheme": "",
        })
        assert auth.type == "api_key"
        assert auth.header == "X-API-Key"


class TestServiceDefinition:
    def test_from_dict(self):
        svc = ServiceDefinition.from_dict({
            "name": "test",
            "description": "Test service",
            "roles": {
                "reader": {
                    "auth": {"type": "bearer"},
                    "routes": [{"effect": "allow", "methods": ["GET"], "path": "/v1/**"}],
                },
            },
        })
        assert svc.name == "test"
        assert "reader" in svc.roles
        assert len(svc.roles["reader"].routes) == 1


class TestServiceRegistry:
    def test_load_gmail_service(self, registry):
        svc = registry.get_service("gmail")
        assert svc is not None
        assert "readonly" in svc.roles
        assert "sender" in svc.roles

    def test_multiple_roles(self, registry):
        svc = registry.get_service("gmail")
        assert len(svc.roles) == 2
        readonly = svc.roles["readonly"]
        assert readonly.auth.refresh_on_401 is True
        sender = svc.roles["sender"]
        assert "POST" in sender.routes[-1].methods

    def test_list_services(self, registry):
        services = registry.list_services()
        names = [s.name for s in services]
        assert "gmail" in names
        assert "minifuse" in names

    def test_invalid_yaml_skipped(self, services_dir):
        (services_dir / "bad.yaml").write_text("not: a: valid: yaml: [")
        reg = ServiceRegistry(services_dir)
        reg.load()
        assert reg.get_service("gmail") is not None

    def test_empty_file_skipped(self, services_dir):
        (services_dir / "empty.yaml").write_text("")
        reg = ServiceRegistry(services_dir)
        reg.load()
        assert reg.get_service("gmail") is not None

    def test_nonexistent_directory(self, tmp_path):
        reg = ServiceRegistry(tmp_path / "nope")
        reg.load()
        assert reg.list_services() == []

    def test_minifuse_api_key_auth(self, registry):
        svc = registry.get_service("minifuse")
        assert svc is not None
        reader = svc.roles["reader"]
        assert reader.auth.type == "api_key"
        assert reader.auth.header == "X-API-Key"

    def test_hot_reload_detects_modified_file(self, registry, services_dir):
        """Modifying a YAML file triggers _has_changes()."""
        assert not registry._has_changes()

        # Modify existing service file
        (services_dir / "minifuse.yaml").write_text("""
name: minifuse
description: "MiniFuse API — updated"
roles:
  reader:
    auth:
      type: api_key
      header: X-API-Key
    routes:
      - effect: allow
        methods: [GET]
        path: "/v2/**"
""")

        assert registry._has_changes()

        # Reload and verify the change was picked up
        registry.load()
        svc = registry.get_service("minifuse")
        assert svc.description == "MiniFuse API — updated"
        assert svc.roles["reader"].routes[0].path == "/v2/**"
        assert not registry._has_changes()

    def test_hot_reload_detects_new_file(self, registry, services_dir):
        """Adding a new YAML file triggers _has_changes()."""
        assert not registry._has_changes()

        (services_dir / "slack.yaml").write_text("""
name: slack
roles:
  bot:
    auth:
      type: bearer
    routes:
      - effect: allow
        methods: [POST]
        path: "/api/**"
""")

        assert registry._has_changes()
        registry.load()
        assert registry.get_service("slack") is not None
        assert not registry._has_changes()

    def test_hot_reload_detects_deleted_file(self, registry, services_dir):
        """Deleting a YAML file triggers _has_changes()."""
        assert not registry._has_changes()

        (services_dir / "minifuse.yaml").unlink()

        assert registry._has_changes()
        registry.load()
        assert registry.get_service("minifuse") is None
        assert not registry._has_changes()
