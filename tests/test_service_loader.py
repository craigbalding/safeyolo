"""Tests for addons/service_loader.py — Service definition loader (v2 schema)."""

import pytest
from service_loader import (
    AuthConfig,
    Capability,
    CapabilityRoute,
    RiskyRoute,
    RiskyRouteGroup,
    ServiceDefinition,
    ServiceRegistry,
)


@pytest.fixture
def services_dir(tmp_path):
    """Create a temp directory with v2 test service definitions."""
    svc_dir = tmp_path / "services"
    svc_dir.mkdir()

    (svc_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
description: "Gmail API"
default_host: gmail.googleapis.com
auth:
  type: bearer
  refresh_on_401: true

risky_routes:
  - group: "Mail routing"
    description: "Controls where email goes"
    tactics: [exfiltration, persistence]
    routes:
      - path: "/gmail/v1/users/me/settings/filters/**"
        description: "Mail filters"
        enables: [defense_evasion]
      - path: "/gmail/v1/users/me/settings/forwardingAddresses/**"
        methods: [POST, PUT]

  - path: "/gmail/v1/users/me/messages/*/delete"
    methods: [DELETE]
    description: "Permanent delete"
    tactics: [impact, defense_evasion]
    irreversible: true

capabilities:
  search_headers:
    description: "Search message metadata"
    scopes: ["gmail.metadata"]
    routes:
      - methods: [GET]
        path: "/gmail/v1/users/me/messages"
  read_and_send:
    description: "Full read/write access"
    scopes: ["gmail.modify"]
    routes:
      - methods: [GET, POST]
        path: "/gmail/v1/users/me/messages/**"
      - methods: [GET]
        path: "/gmail/v1/users/me/threads/**"
""")

    (svc_dir / "minifuse.yaml").write_text("""
schema_version: 1
name: minifuse
description: "MiniFuse API"
auth:
  type: api_key
  header: X-API-Key

capabilities:
  reader:
    description: "Read-only access"
    routes:
      - methods: [GET]
        path: "/v1/feeds"
      - methods: [GET]
        path: "/v1/feeds/*"
      - methods: [GET]
        path: "/v1/entries"
""")

    return svc_dir


@pytest.fixture
def registry(services_dir):
    reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
    reg.load()
    return reg


class TestCapabilityRoute:
    def test_from_dict(self):
        route = CapabilityRoute.from_dict({"methods": ["GET", "POST"], "path": "/api/v1/**"})
        assert route.methods == ["GET", "POST"]
        assert route.path == "/api/v1/**"

    def test_from_dict_string_method(self):
        route = CapabilityRoute.from_dict({"methods": "GET", "path": "/v1/**"})
        assert route.methods == ["GET"]

    def test_methods_uppercased(self):
        route = CapabilityRoute.from_dict({"methods": ["get", "post"], "path": "/v1/**"})
        assert route.methods == ["GET", "POST"]


class TestCapability:
    def test_from_dict_minimal(self):
        cap = Capability.from_dict("reader", {
            "description": "Read-only",
            "routes": [{"methods": ["GET"], "path": "/v1/**"}],
        })
        assert cap.name == "reader"
        assert cap.description == "Read-only"
        assert len(cap.routes) == 1
        assert cap.scopes == []

    def test_from_dict_with_scopes(self):
        cap = Capability.from_dict("writer", {
            "description": "Write access",
            "scopes": ["write", "admin"],
            "routes": [{"methods": ["GET", "POST"], "path": "/v1/**"}],
        })
        assert cap.scopes == ["write", "admin"]

    def test_from_dict_no_routes(self):
        cap = Capability.from_dict("empty", {"description": "Empty"})
        assert cap.routes == []


class TestRiskyRoute:
    def test_from_dict_standalone(self):
        route = RiskyRoute.from_dict({
            "path": "/api/delete/**",
            "methods": ["DELETE"],
            "description": "Delete endpoint",
            "tactics": ["impact"],
            "enables": ["defense_evasion"],
            "irreversible": True,
        })
        assert route.path == "/api/delete/**"
        assert route.methods == ["DELETE"]
        assert route.tactics == ["impact"]
        assert route.enables == ["defense_evasion"]
        assert route.irreversible is True
        assert route.group is None

    def test_from_dict_defaults(self):
        route = RiskyRoute.from_dict({"path": "/api/test"})
        assert route.methods == ["*"]
        assert route.description == ""
        assert route.tactics == []
        assert route.enables == []
        assert route.irreversible is False

    def test_from_dict_with_group_defaults(self):
        group_defaults = {
            "group": "Admin",
            "description": "Admin actions",
            "tactics": ["privilege_escalation"],
            "enables": ["lateral_movement"],
            "irreversible": True,
        }
        route = RiskyRoute.from_dict({"path": "/admin/**"}, group_defaults)
        assert route.group == "Admin"
        assert route.description == "Admin actions"
        assert route.tactics == ["privilege_escalation"]
        assert route.enables == ["lateral_movement"]
        assert route.irreversible is True

    def test_group_defaults_tactics_union(self):
        group_defaults = {
            "group": "G",
            "tactics": ["exfiltration", "persistence"],
            "enables": ["credential_access"],
        }
        route = RiskyRoute.from_dict({
            "path": "/api/test",
            "tactics": ["impact"],
            "enables": ["defense_evasion"],
        }, group_defaults)
        # Union: group first, then route
        assert route.tactics == ["exfiltration", "persistence", "impact"]
        assert route.enables == ["credential_access", "defense_evasion"]

    def test_group_defaults_tactics_dedup(self):
        group_defaults = {"group": "G", "tactics": ["impact"]}
        route = RiskyRoute.from_dict({
            "path": "/api/test",
            "tactics": ["impact", "collection"],
        }, group_defaults)
        assert route.tactics == ["impact", "collection"]

    def test_route_overrides_group_irreversible(self):
        group_defaults = {"group": "G", "irreversible": True}
        route = RiskyRoute.from_dict({
            "path": "/api/trash",
            "irreversible": False,
        }, group_defaults)
        assert route.irreversible is False

    def test_route_inherits_group_irreversible_when_not_set(self):
        group_defaults = {"group": "G", "irreversible": True}
        route = RiskyRoute.from_dict({"path": "/api/delete"}, group_defaults)
        assert route.irreversible is True

    def test_route_overrides_group_description(self):
        group_defaults = {"group": "G", "description": "Group desc"}
        route = RiskyRoute.from_dict({
            "path": "/api/test",
            "description": "Route desc",
        }, group_defaults)
        assert route.description == "Route desc"

    def test_route_inherits_group_description(self):
        group_defaults = {"group": "G", "description": "Group desc"}
        route = RiskyRoute.from_dict({"path": "/api/test"}, group_defaults)
        assert route.description == "Group desc"

    def test_methods_uppercased(self):
        route = RiskyRoute.from_dict({"path": "/api", "methods": ["get", "post"]})
        assert route.methods == ["GET", "POST"]


class TestRiskyRouteGroup:
    def test_from_dict(self):
        grp = RiskyRouteGroup.from_dict({
            "group": "Mail routing",
            "description": "Controls email routing",
            "tactics": ["exfiltration", "persistence"],
            "enables": ["defense_evasion"],
            "irreversible": False,
            "routes": [
                {"path": "/settings/filters/**", "description": "Filters"},
                {"path": "/settings/forwarding/**", "methods": ["POST"]},
            ],
        })
        assert grp.group == "Mail routing"
        assert grp.tactics == ["exfiltration", "persistence"]
        assert len(grp.routes) == 2
        # Routes should inherit group signals
        assert grp.routes[0].tactics == ["exfiltration", "persistence"]
        assert grp.routes[0].group == "Mail routing"
        assert grp.routes[0].description == "Filters"  # route overrides
        assert grp.routes[1].description == "Controls email routing"  # inherits

    def test_from_dict_minimal(self):
        grp = RiskyRouteGroup.from_dict({
            "group": "test",
            "routes": [{"path": "/test"}],
        })
        assert grp.group == "test"
        assert grp.description == ""
        assert grp.tactics == []
        assert grp.enables == []
        assert grp.irreversible is False
        assert len(grp.routes) == 1


class TestServiceDefinition:
    def test_from_dict_v2(self):
        svc = ServiceDefinition.from_dict({
            "schema_version": 1,
            "name": "test",
            "description": "Test service",
            "default_host": "api.test.com",
            "auth": {"type": "bearer"},
            "capabilities": {
                "reader": {
                    "description": "Read-only",
                    "routes": [{"methods": ["GET"], "path": "/v1/**"}],
                },
            },
        })
        assert svc.name == "test"
        assert svc.schema_version == 1
        assert svc.auth is not None
        assert svc.auth.type == "bearer"
        assert "reader" in svc.capabilities
        assert svc.risky_routes == []
        assert svc.risky_route_groups == []

    def test_rejects_missing_schema_version(self):
        with pytest.raises(ValueError, match="schema_version"):
            ServiceDefinition.from_dict({
                "name": "test",
                "auth": {"type": "bearer"},
            })

    def test_rejects_unknown_schema_version(self):
        with pytest.raises(ValueError, match="schema_version"):
            ServiceDefinition.from_dict({
                "schema_version": 99,
                "name": "test",
            })

    def test_from_dict_with_risky_routes(self):
        svc = ServiceDefinition.from_dict({
            "schema_version": 1,
            "name": "test",
            "auth": {"type": "bearer"},
            "risky_routes": [
                {
                    "group": "Admin",
                    "tactics": ["privilege_escalation"],
                    "routes": [
                        {"path": "/admin/**"},
                        {"path": "/admin/delete", "methods": ["DELETE"]},
                    ],
                },
                {
                    "path": "/api/delete",
                    "methods": ["DELETE"],
                    "tactics": ["impact"],
                    "irreversible": True,
                },
            ],
        })
        # Flat routes: 2 from group + 1 ungrouped
        assert len(svc.risky_routes) == 3
        assert len(svc.risky_route_groups) == 1
        assert svc.risky_route_groups[0].group == "Admin"

    def test_from_dict_minimal(self):
        svc = ServiceDefinition.from_dict({
            "schema_version": 1,
            "name": "minimal",
        })
        assert svc.name == "minimal"
        assert svc.auth is None
        assert svc.capabilities == {}
        assert svc.risky_routes == []


class TestServiceRegistry:
    def test_load_gmail_service(self, registry):
        svc = registry.get_service("gmail")
        assert svc is not None
        assert svc.schema_version == 1
        assert "search_headers" in svc.capabilities
        assert "read_and_send" in svc.capabilities

    def test_gmail_risky_routes(self, registry):
        svc = registry.get_service("gmail")
        # 2 grouped routes + 1 ungrouped
        assert len(svc.risky_routes) == 3
        assert len(svc.risky_route_groups) == 1
        assert svc.risky_route_groups[0].group == "Mail routing"

    def test_gmail_auth(self, registry):
        svc = registry.get_service("gmail")
        assert svc.auth is not None
        assert svc.auth.type == "bearer"
        assert svc.auth.refresh_on_401 is True

    def test_minifuse_api_key_auth(self, registry):
        svc = registry.get_service("minifuse")
        assert svc is not None
        assert svc.auth.type == "api_key"
        assert svc.auth.header == "X-API-Key"

    def test_minifuse_capabilities(self, registry):
        svc = registry.get_service("minifuse")
        assert "reader" in svc.capabilities
        reader = svc.capabilities["reader"]
        assert len(reader.routes) == 3
        assert reader.routes[0].methods == ["GET"]

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

    def test_v1_schema_skipped(self, services_dir):
        """Files without schema_version are skipped."""
        (services_dir / "legacy.yaml").write_text("""
name: legacy
roles:
  reader:
    auth:
      type: bearer
    routes:
      - effect: allow
        methods: [GET]
        path: "/v1/**"
""")
        reg = ServiceRegistry(services_dir)
        reg.load()
        assert reg.get_service("legacy") is None
        assert reg.get_service("gmail") is not None

    def test_nonexistent_directory(self, tmp_path):
        reg = ServiceRegistry(tmp_path / "nope")
        reg.load()
        assert reg.list_services() == []

    def test_hot_reload_detects_modified_file(self, registry, services_dir):
        assert not registry._has_changes()

        (services_dir / "minifuse.yaml").write_text("""
schema_version: 1
name: minifuse
description: "MiniFuse API — updated"
auth:
  type: api_key
  header: X-API-Key
capabilities:
  reader:
    description: "Read-only"
    routes:
      - methods: [GET]
        path: "/v2/**"
""")

        assert registry._has_changes()
        registry.load()
        svc = registry.get_service("minifuse")
        assert svc.description == "MiniFuse API — updated"
        assert svc.capabilities["reader"].routes[0].path == "/v2/**"
        assert not registry._has_changes()

    def test_hot_reload_detects_new_file(self, registry, services_dir):
        assert not registry._has_changes()

        (services_dir / "slack.yaml").write_text("""
schema_version: 1
name: slack
auth:
  type: bearer
capabilities:
  bot:
    description: "Bot access"
    routes:
      - methods: [POST]
        path: "/api/**"
""")

        assert registry._has_changes()
        registry.load()
        assert registry.get_service("slack") is not None
        assert not registry._has_changes()

    def test_hot_reload_detects_deleted_file(self, registry, services_dir):
        assert not registry._has_changes()
        (services_dir / "minifuse.yaml").unlink()
        assert registry._has_changes()
        registry.load()
        assert registry.get_service("minifuse") is None
        assert not registry._has_changes()
