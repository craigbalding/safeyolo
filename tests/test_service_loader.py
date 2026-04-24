"""Tests for addons/service_loader.py — Service definition loader (v2 schema)."""

import copy
from unittest.mock import patch

import pytest

from safeyolo.core.service_loader import (
    AuthConfig,
    Capability,
    CapabilityRoute,
    ContractBinding,
    ContractOperation,
    ContractTemplate,
    EnforcementStatus,
    RiskyRoute,
    RiskyRouteGroup,
    ServiceDefinition,
    ServiceRegistry,
    _path_match_specificity,
    get_service_registry,
    init_service_registry,
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
        cap = Capability.from_dict(
            "reader",
            {
                "description": "Read-only",
                "routes": [{"methods": ["GET"], "path": "/v1/**"}],
            },
        )
        assert cap.name == "reader"
        assert cap.description == "Read-only"
        assert len(cap.routes) == 1
        assert cap.scopes == []

    def test_from_dict_with_scopes(self):
        cap = Capability.from_dict(
            "writer",
            {
                "description": "Write access",
                "scopes": ["write", "admin"],
                "routes": [{"methods": ["GET", "POST"], "path": "/v1/**"}],
            },
        )
        assert cap.scopes == ["write", "admin"]

    def test_from_dict_no_routes(self):
        cap = Capability.from_dict("empty", {"description": "Empty"})
        assert cap.routes == []


class TestRiskyRoute:
    def test_from_dict_standalone(self):
        route = RiskyRoute.from_dict(
            {
                "path": "/api/delete/**",
                "methods": ["DELETE"],
                "description": "Delete endpoint",
                "tactics": ["impact"],
                "enables": ["defense_evasion"],
                "irreversible": True,
            }
        )
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
        route = RiskyRoute.from_dict(
            {
                "path": "/api/test",
                "tactics": ["impact"],
                "enables": ["defense_evasion"],
            },
            group_defaults,
        )
        # Union: group first, then route
        assert route.tactics == ["exfiltration", "persistence", "impact"]
        assert route.enables == ["credential_access", "defense_evasion"]

    def test_group_defaults_tactics_dedup(self):
        group_defaults = {"group": "G", "tactics": ["impact"]}
        route = RiskyRoute.from_dict(
            {
                "path": "/api/test",
                "tactics": ["impact", "collection"],
            },
            group_defaults,
        )
        assert route.tactics == ["impact", "collection"]

    def test_route_overrides_group_irreversible(self):
        group_defaults = {"group": "G", "irreversible": True}
        route = RiskyRoute.from_dict(
            {
                "path": "/api/trash",
                "irreversible": False,
            },
            group_defaults,
        )
        assert route.irreversible is False

    def test_route_inherits_group_irreversible_when_not_set(self):
        group_defaults = {"group": "G", "irreversible": True}
        route = RiskyRoute.from_dict({"path": "/api/delete"}, group_defaults)
        assert route.irreversible is True

    def test_route_overrides_group_description(self):
        group_defaults = {"group": "G", "description": "Group desc"}
        route = RiskyRoute.from_dict(
            {
                "path": "/api/test",
                "description": "Route desc",
            },
            group_defaults,
        )
        assert route.description == "Route desc"

    def test_route_inherits_group_description(self):
        group_defaults = {"group": "G", "description": "Group desc"}
        route = RiskyRoute.from_dict({"path": "/api/test"}, group_defaults)
        assert route.description == "Group desc"

    def test_methods_uppercased(self):
        route = RiskyRoute.from_dict({"path": "/api", "methods": ["get", "post"]})
        assert route.methods == ["GET", "POST"]

    def test_string_methods_wrapped_to_list(self):
        route = RiskyRoute.from_dict({"path": "/api/test", "methods": "delete"})
        assert route.methods == ["DELETE"]


class TestRiskyRouteGroup:
    def test_from_dict(self):
        grp = RiskyRouteGroup.from_dict(
            {
                "group": "Mail routing",
                "description": "Controls email routing",
                "tactics": ["exfiltration", "persistence"],
                "enables": ["defense_evasion"],
                "irreversible": False,
                "routes": [
                    {"path": "/settings/filters/**", "description": "Filters"},
                    {"path": "/settings/forwarding/**", "methods": ["POST"]},
                ],
            }
        )
        assert grp.group == "Mail routing"
        assert grp.tactics == ["exfiltration", "persistence"]
        assert len(grp.routes) == 2
        # Routes should inherit group signals
        assert grp.routes[0].tactics == ["exfiltration", "persistence"]
        assert grp.routes[0].group == "Mail routing"
        assert grp.routes[0].description == "Filters"  # route overrides
        assert grp.routes[1].description == "Controls email routing"  # inherits

    def test_from_dict_minimal(self):
        grp = RiskyRouteGroup.from_dict(
            {
                "group": "test",
                "routes": [{"path": "/test"}],
            }
        )
        assert grp.group == "test"
        assert grp.description == ""
        assert grp.tactics == []
        assert grp.enables == []
        assert grp.irreversible is False
        assert len(grp.routes) == 1


class TestServiceDefinition:
    def test_from_dict_v2(self):
        svc = ServiceDefinition.from_dict(
            {
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
            }
        )
        assert svc.name == "test"
        assert svc.schema_version == 1
        assert svc.auth is not None
        assert svc.auth.type == "bearer"
        assert "reader" in svc.capabilities
        assert svc.risky_routes == []
        assert svc.risky_route_groups == []

    def test_rejects_missing_schema_version(self):
        with pytest.raises(ValueError, match="schema_version"):
            ServiceDefinition.from_dict(
                {
                    "name": "test",
                    "auth": {"type": "bearer"},
                }
            )

    def test_rejects_unknown_schema_version(self):
        with pytest.raises(ValueError, match="schema_version"):
            ServiceDefinition.from_dict(
                {
                    "schema_version": 99,
                    "name": "test",
                }
            )

    def test_from_dict_with_risky_routes(self):
        svc = ServiceDefinition.from_dict(
            {
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
            }
        )
        # Flat routes: 2 from group + 1 ungrouped
        assert len(svc.risky_routes) == 3
        assert len(svc.risky_route_groups) == 1
        assert svc.risky_route_groups[0].group == "Admin"

    def test_from_dict_minimal(self):
        svc = ServiceDefinition.from_dict(
            {
                "schema_version": 1,
                "name": "minimal",
            }
        )
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


class TestServiceRegistryErrorHandling:
    """Tests for B1 fix: malformed service YAML emits ops.config_error audit event."""

    def test_invalid_yaml_emits_audit_event_and_skips_service(self, services_dir):
        """Invalid YAML should be skipped AND emit ops.config_error audit event."""
        (services_dir / "bad.yaml").write_text("not: a: valid: yaml: [")
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        with patch("safeyolo.core.utils.write_event") as mock_write_event:
            reg.load()

        # Service is skipped (fail-closed: absent from registry)
        assert reg.get_service("gmail") is not None
        assert reg.get_service("bad") is None

        # Audit event was emitted for the bad file
        mock_write_event.assert_called_once()
        call_kwargs = mock_write_event.call_args
        assert call_kwargs[0][0] == "ops.config_error"
        assert call_kwargs[1]["details"]["file"] == "bad.yaml"
        assert call_kwargs[1]["details"]["error_type"] == "ScannerError"

    def test_v1_schema_emits_audit_event_and_skips_service(self, services_dir):
        """Files without schema_version=1 should be skipped AND emit ops.config_error."""
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
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        with patch("safeyolo.core.utils.write_event") as mock_write_event:
            reg.load()

        # Service is absent from registry
        assert reg.get_service("legacy") is None
        assert reg.get_service("gmail") is not None

        # Audit event emitted — ValueError for unsupported schema_version
        calls = [c for c in mock_write_event.call_args_list
                 if c[1]["details"]["file"] == "legacy.yaml"]
        assert len(calls) == 1
        assert calls[0][0][0] == "ops.config_error"
        assert calls[0][1]["details"]["error_type"] == "ValueError"

    def test_empty_file_skipped_without_audit_event(self, services_dir):
        """Empty files are skipped via continue (not an error), no audit event emitted."""
        (services_dir / "empty.yaml").write_text("")
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        with patch("safeyolo.core.utils.write_event") as mock_write_event:
            reg.load()

        # Valid services still load
        assert reg.get_service("gmail") is not None
        # No audit event: empty file hits the `not raw` continue path, not the except block
        mock_write_event.assert_not_called()

    def test_missing_name_field_emits_audit_event(self, services_dir):
        """Service YAML missing required 'name' field emits audit event."""
        (services_dir / "noname.yaml").write_text("""
schema_version: 1
description: "Missing the name field"
""")
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        with patch("safeyolo.core.utils.write_event") as mock_write_event:
            reg.load()

        assert reg.get_service("gmail") is not None
        calls = [c for c in mock_write_event.call_args_list
                 if c[1]["details"]["file"] == "noname.yaml"]
        assert len(calls) == 1
        assert calls[0][1]["details"]["error_type"] == "KeyError"

    def test_audit_event_failure_does_not_break_registry_load(self, services_dir):
        """If write_event itself fails, the registry still loads valid services."""
        (services_dir / "bad.yaml").write_text("not: a: valid: yaml: [")
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        with patch("safeyolo.core.utils.write_event", side_effect=RuntimeError("audit broken")):
            reg.load()

        # Valid services still loaded despite audit failure
        assert reg.get_service("gmail") is not None
        assert reg.get_service("minifuse") is not None


class TestUserOverridesBuiltin:
    """C15: User services override builtin services with the same name."""

    def test_user_service_overrides_builtin_service(self, tmp_path):
        builtin_dir = tmp_path / "builtin"
        builtin_dir.mkdir()
        user_dir = tmp_path / "user"
        user_dir.mkdir()

        (builtin_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
description: "Builtin Gmail"
""")
        (user_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
description: "User Gmail Override"
""")

        reg = ServiceRegistry(user_dir, builtin_dir=builtin_dir)
        reg.load()

        svc = reg.get_service("gmail")
        assert svc is not None
        assert svc.description == "User Gmail Override"

    def test_builtin_service_loads_when_no_user_override(self, tmp_path):
        builtin_dir = tmp_path / "builtin"
        builtin_dir.mkdir()
        user_dir = tmp_path / "user"
        user_dir.mkdir()

        (builtin_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
description: "Builtin Gmail"
""")

        reg = ServiceRegistry(user_dir, builtin_dir=builtin_dir)
        reg.load()

        svc = reg.get_service("gmail")
        assert svc is not None
        assert svc.description == "Builtin Gmail"

    def test_builtin_dir_loads_when_present(self, tmp_path):
        builtin_dir = tmp_path / "builtin"
        builtin_dir.mkdir()
        user_dir = tmp_path / "user"
        user_dir.mkdir()

        (builtin_dir / "slack.yaml").write_text("""
schema_version: 1
name: slack
description: "Builtin Slack"
""")
        (user_dir / "gmail.yaml").write_text("""
schema_version: 1
name: gmail
description: "User Gmail"
""")

        reg = ServiceRegistry(user_dir, builtin_dir=builtin_dir)
        reg.load()

        # Both directories contribute to the registry
        assert reg.get_service("slack") is not None
        assert reg.get_service("gmail") is not None
        services = reg.list_services()
        names = sorted(s.name for s in services)
        assert names == ["gmail", "slack"]


# =========================================================================
# Contract dataclass tests
# =========================================================================


class TestContractBinding:
    def test_from_dict_enum(self):
        b = ContractBinding.from_dict("category", {
            "source": "agent",
            "type": "enum",
            "options": ["A", "B", "C"],
            "visible_to_operator": True,
        })
        assert b.name == "category"
        assert b.type == "enum"
        assert b.options == ["A", "B", "C"]

    def test_from_dict_string(self):
        b = ContractBinding.from_dict("query", {
            "type": "string",
            "pattern": "^[A-Z]+$",
        })
        assert b.type == "string"
        assert b.pattern == "^[A-Z]+$"

    def test_from_dict_integer(self):
        b = ContractBinding.from_dict("count", {"type": "integer"})
        assert b.type == "integer"

    def test_from_dict_boolean(self):
        b = ContractBinding.from_dict("flag", {"type": "boolean"})
        assert b.type == "boolean"

    def test_from_dict_string_list(self):
        b = ContractBinding.from_dict("tags", {"type": "string_list"})
        assert b.type == "string_list"

    def test_enum_requires_options(self):
        with pytest.raises(ValueError, match="non-empty 'options'"):
            ContractBinding.from_dict("bad", {"type": "enum"})

    def test_invalid_type_rejected(self):
        with pytest.raises(ValueError, match="Invalid binding type"):
            ContractBinding.from_dict("bad", {"type": "float"})

    def test_defaults(self):
        b = ContractBinding.from_dict("x", {})
        assert b.source == "agent"
        assert b.type == "string"
        assert b.visible_to_operator is True
        assert b.required_if == {}

    def test_required_if(self):
        b = ContractBinding.from_dict("detail", {
            "type": "string",
            "required_if": {"mode": "advanced"},
        })
        assert b.required_if == {"mode": "advanced"}


class TestContractOperation:
    def test_from_dict_full(self):
        op = ContractOperation.from_dict({
            "name": "list_messages",
            "request": {
                "method": "GET",
                "path": "/api/messages",
                "transport": {
                    "require_no_body": True,
                    "allow_headers": ["Accept"],
                    "deny_ambiguous_encoding": True,
                },
                "query": {
                    "allow": {
                        "label": {"equals_var": "category"},
                        "limit": {"integer_range": [1, 100]},
                    },
                    "deny_unknown": True,
                },
            },
        })
        assert op.name == "list_messages"
        assert op.method == "GET"
        assert op.path == "/api/messages"
        assert op.transport is not None
        assert op.transport.require_no_body is True
        assert "label" in op.query_allow
        assert op.query_allow["label"].equals_var == "category"
        assert op.query_deny_unknown is True

    def test_from_dict_minimal(self):
        op = ContractOperation.from_dict({"name": "simple"})
        assert op.name == "simple"
        assert op.method == "GET"
        assert op.transport is None
        assert op.query_allow == {}
        assert op.requires_enforcement == ""

    def test_requires_enforcement_valid(self):
        op = ContractOperation.from_dict({
            "name": "guarded",
            "requires_enforcement": "state_enforcement",
        })
        assert op.requires_enforcement == "state_enforcement"

    def test_requires_enforcement_invalid(self):
        with pytest.raises(ValueError, match="not a valid tier"):
            ContractOperation.from_dict({
                "name": "bad",
                "requires_enforcement": "magic_tier",
            })

    def test_body_constraints(self):
        op = ContractOperation.from_dict({
            "name": "create",
            "request": {
                "method": "POST",
                "path": "/api/items",
                "body": {
                    "allow": {
                        "name": {"type": "string"},
                        "category": {"equals_var": "cat_var"},
                    },
                    "deny_unknown": True,
                },
            },
        })
        assert "name" in op.body_allow
        assert op.body_allow["category"].equals_var == "cat_var"
        assert op.body_deny_unknown is True

    def test_path_params(self):
        op = ContractOperation.from_dict({
            "name": "get_item",
            "request": {
                "method": "GET",
                "path": "/api/items/{id}",
                "path_params": {
                    "id": {"in_state_set": "discovered_ids", "type": "string"},
                },
            },
        })
        assert "id" in op.path_params
        assert op.path_params["id"].in_state_set == "discovered_ids"


class TestEnforcementStatus:
    def test_from_dict(self):
        es = EnforcementStatus.from_dict({
            "request_shape": "enforced",
            "transport_hygiene": "enforced",
            "state_capture": "declared",
            "state_enforcement": "declared",
            "response_validators": "declared",
        })
        assert es.request_shape == "enforced"
        assert es.state_capture == "declared"

    def test_defaults_to_declared(self):
        es = EnforcementStatus.from_dict({})
        assert es.request_shape == "declared"
        assert es.transport_hygiene == "declared"

    def test_invalid_value_rejected(self):
        with pytest.raises(ValueError, match="must be 'enforced' or 'declared'"):
            EnforcementStatus.from_dict({"request_shape": "active"})

    def test_get_tier_status(self):
        es = EnforcementStatus.from_dict({"request_shape": "enforced"})
        assert es.get_tier_status("request_shape") == "enforced"
        assert es.get_tier_status("state_capture") == "declared"


class TestContractTemplate:
    @pytest.fixture
    def gmail_contract_dict(self):
        return {
            "template": "gmail.read_messages.v1",
            "bindings": {
                "approved_category": {
                    "source": "agent",
                    "type": "enum",
                    "options": ["CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"],
                    "visible_to_operator": True,
                },
            },
            "operations": [
                {
                    "name": "list_messages",
                    "request": {
                        "method": "GET",
                        "path": "/gmail/v1/users/me/messages",
                        "query": {
                            "allow": {
                                "labelIds": {"equals_var": "approved_category"},
                            },
                            "deny_unknown": True,
                        },
                    },
                },
                {
                    "name": "get_message",
                    "requires_enforcement": "state_enforcement",
                    "request": {
                        "method": "GET",
                        "path": "/gmail/v1/users/me/messages/{id}",
                    },
                },
            ],
            "enforcement": {
                "request_shape": "enforced",
                "transport_hygiene": "enforced",
                "state_capture": "declared",
                "state_enforcement": "declared",
                "response_validators": "declared",
            },
        }

    def test_from_dict(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        assert ct.template == "gmail.read_messages.v1"
        assert len(ct.bindings) == 1
        assert "approved_category" in ct.bindings
        assert len(ct.operations) == 2

    def test_grantable_operations_excludes_state_enforcement(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        grantable = ct.grantable_operations()
        assert len(grantable) == 1
        assert grantable[0].name == "list_messages"

    def test_is_grantable(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        assert ct.is_grantable is True

    def test_is_not_grantable_when_all_ops_need_declared_tier(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "op1",
                    "requires_enforcement": "state_enforcement",
                    "request": {"method": "GET", "path": "/test"},
                },
            ],
            "enforcement": {
                "request_shape": "enforced",
                "state_enforcement": "declared",
            },
        })
        assert ct.is_grantable is False
        assert ct.grantable_operations() == []

    def test_ungrantable_tiers(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        tiers = ct.ungrantable_tiers()
        assert "state_enforcement" in tiers

    def test_match_operation_exact(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        op = ct.match_operation("GET", "/gmail/v1/users/me/messages")
        assert op is not None
        assert op.name == "list_messages"

    def test_match_operation_no_match(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        op = ct.match_operation("POST", "/gmail/v1/users/me/messages")
        assert op is None

    def test_match_operation_non_grantable_excluded(self, gmail_contract_dict):
        ct = ContractTemplate.from_dict(gmail_contract_dict)
        # get_message requires state_enforcement (declared), so not grantable
        op = ct.match_operation("GET", "/gmail/v1/users/me/messages/msg123")
        assert op is None


class TestMatchOperationSpecificity:
    """Test that match_operation picks most specific route: exact > param > glob."""

    def test_exact_preferred_over_parameterized(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "get_by_id",
                    "request": {"method": "GET", "path": "/api/items/{id}"},
                },
                {
                    "name": "get_special",
                    "request": {"method": "GET", "path": "/api/items/special"},
                },
            ],
            "enforcement": {"request_shape": "enforced"},
        })
        op = ct.match_operation("GET", "/api/items/special")
        assert op is not None
        assert op.name == "get_special"

    def test_parameterized_preferred_over_glob(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "catch_all",
                    "request": {"method": "GET", "path": "/api/*"},
                },
                {
                    "name": "get_item",
                    "request": {"method": "GET", "path": "/api/{id}"},
                },
            ],
            "enforcement": {"request_shape": "enforced"},
        })
        op = ct.match_operation("GET", "/api/123")
        assert op is not None
        assert op.name == "get_item"

    def test_exact_preferred_over_glob(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "catch_all",
                    "request": {"method": "GET", "path": "/api/**"},
                },
                {
                    "name": "list_items",
                    "request": {"method": "GET", "path": "/api/items"},
                },
            ],
            "enforcement": {"request_shape": "enforced"},
        })
        op = ct.match_operation("GET", "/api/items")
        assert op is not None
        assert op.name == "list_items"

    def test_method_mismatch_returns_none(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "list_items",
                    "request": {"method": "GET", "path": "/api/items"},
                },
            ],
            "enforcement": {"request_shape": "enforced"},
        })
        op = ct.match_operation("POST", "/api/items")
        assert op is None

    def test_method_matching_is_case_insensitive(self):
        ct = ContractTemplate.from_dict({
            "template": "test.v1",
            "operations": [
                {
                    "name": "list_items",
                    "request": {"method": "GET", "path": "/api/items"},
                },
            ],
            "enforcement": {"request_shape": "enforced"},
        })
        op = ct.match_operation("get", "/api/items")
        assert op is not None
        assert op.name == "list_items"


class TestPathMatchSpecificity:
    def test_exact_match(self):
        assert _path_match_specificity("/api/v1/items", "/api/v1/items") == 2

    def test_parameterized_match(self):
        assert _path_match_specificity("/api/v1/items/123", "/api/v1/items/{id}") == 1

    def test_no_match(self):
        assert _path_match_specificity("/api/v1/items", "/api/v2/items") == -1

    def test_length_mismatch(self):
        assert _path_match_specificity("/api/v1", "/api/v1/items") == -1

    def test_glob_match(self):
        assert _path_match_specificity("/api/v1/items/123", "/api/v1/*") == 0

    def test_double_glob_match(self):
        assert _path_match_specificity("/api/v1/items/123/sub", "/api/v1/**") == 0

    def test_root_to_root(self):
        assert _path_match_specificity("/", "/") == 2

    def test_empty_to_empty(self):
        assert _path_match_specificity("", "") == 2

    def test_trailing_slash_ignored(self):
        assert _path_match_specificity("/api/v1/items/", "/api/v1/items") == 2

    def test_both_trailing_slashes_ignored(self):
        assert _path_match_specificity("/api/v1/items/", "/api/v1/items/") == 2

    def test_actual_longer_than_template(self):
        assert _path_match_specificity("/api/v1/items/123", "/api/v1/items") == -1

    def test_template_longer_than_actual(self):
        assert _path_match_specificity("/api/v1", "/api/v1/items/{id}") == -1

    def test_glob_at_start(self):
        assert _path_match_specificity("/anything/here", "*") == 0

    def test_mixed_param_and_literal(self):
        assert _path_match_specificity("/api/v1/items/123", "/api/{version}/items/{id}") == 1

    def test_param_only_path(self):
        assert _path_match_specificity("/123", "/{id}") == 1

    def test_mid_path_glob_matches(self):
        """Glob at a middle position matches the path from that point."""
        assert _path_match_specificity("/api/v1/items/123/details", "/api/v1/*") == 0

    def test_single_segment(self):
        assert _path_match_specificity("/api", "/api") == 2

    def test_single_segment_mismatch(self):
        assert _path_match_specificity("/api", "/rpc") == -1


class TestCapabilityWithContract:
    def test_without_contract(self):
        cap = Capability.from_dict("reader", {
            "description": "Read-only",
            "routes": [{"methods": ["GET"], "path": "/v1/**"}],
        })
        assert cap.contract is None

    def test_with_contract(self):
        cap = Capability.from_dict("reader", {
            "description": "Read-only",
            "routes": [{"methods": ["GET"], "path": "/v1/**"}],
            "contract": {
                "template": "test.v1",
                "bindings": {
                    "scope": {
                        "type": "enum",
                        "options": ["A", "B"],
                    },
                },
                "operations": [
                    {"name": "list", "request": {"method": "GET", "path": "/v1/items"}},
                ],
                "enforcement": {
                    "request_shape": "enforced",
                },
            },
        })
        assert cap.contract is not None
        assert cap.contract.template == "test.v1"
        assert cap.contract.is_grantable is True


class TestAuthConfig:
    """Direct unit tests for AuthConfig defaults and from_dict."""

    def test_bearer_defaults(self):
        auth = AuthConfig.from_dict({"type": "bearer"})
        assert auth.type == "bearer"
        assert auth.header == "Authorization"
        assert auth.scheme == "Bearer"
        assert auth.refresh_on_401 is False

    def test_api_key_with_custom_header(self):
        auth = AuthConfig.from_dict({"type": "api_key", "header": "X-API-Key"})
        assert auth.type == "api_key"
        assert auth.header == "X-API-Key"
        assert auth.scheme == "Bearer"
        assert auth.refresh_on_401 is False

    def test_bearer_with_refresh(self):
        auth = AuthConfig.from_dict({
            "type": "bearer",
            "refresh_on_401": True,
        })
        assert auth.refresh_on_401 is True

    def test_custom_scheme(self):
        auth = AuthConfig.from_dict({
            "type": "bearer",
            "scheme": "Token",
        })
        assert auth.scheme == "Token"

    def test_all_fields_explicit(self):
        auth = AuthConfig.from_dict({
            "type": "bearer",
            "header": "X-Custom-Auth",
            "scheme": "Custom",
            "refresh_on_401": True,
        })
        assert auth.type == "bearer"
        assert auth.header == "X-Custom-Auth"
        assert auth.scheme == "Custom"
        assert auth.refresh_on_401 is True


class TestModuleSingleton:
    """Tests for init_service_registry / get_service_registry module singleton."""

    def test_init_creates_and_loads_registry(self, services_dir):
        import safeyolo.core.service_loader as service_loader
        old_registry = service_loader._registry

        try:
            reg = init_service_registry(
                services_dir,
                builtin_dir=services_dir.parent / "nonexistent",
            )
            assert reg is not None
            assert reg.get_service("gmail") is not None
            assert get_service_registry() is reg
        finally:
            service_loader._registry = old_registry

    def test_get_returns_none_before_init(self):
        import safeyolo.core.service_loader as service_loader
        old_registry = service_loader._registry

        try:
            service_loader._registry = None
            assert get_service_registry() is None
        finally:
            service_loader._registry = old_registry

    def test_init_replaces_previous_registry(self, tmp_path):
        import safeyolo.core.service_loader as service_loader
        old_registry = service_loader._registry

        try:
            dir1 = tmp_path / "dir1"
            dir1.mkdir()
            (dir1 / "svc1.yaml").write_text("""
schema_version: 1
name: svc1
""")
            dir2 = tmp_path / "dir2"
            dir2.mkdir()
            (dir2 / "svc2.yaml").write_text("""
schema_version: 1
name: svc2
""")

            reg1 = init_service_registry(dir1, builtin_dir=tmp_path / "no")
            assert reg1.get_service("svc1") is not None

            reg2 = init_service_registry(dir2, builtin_dir=tmp_path / "no")
            assert reg2.get_service("svc2") is not None
            assert reg2.get_service("svc1") is None
            assert get_service_registry() is reg2
        finally:
            service_loader._registry = old_registry


class TestWatcherIdempotency:
    """Watcher start is idempotent: calling start_watcher twice does not create two threads."""

    def test_start_watcher_twice_creates_one_thread(self, services_dir):
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        reg.load()

        reg.start_watcher()
        first_thread = reg._watcher_thread
        assert first_thread is not None
        assert first_thread.is_alive()

        reg.start_watcher()
        assert reg._watcher_thread is first_thread

        reg.stop_watcher()
        assert reg._watcher_thread is None

    def test_stop_then_start_creates_new_thread(self, services_dir):
        reg = ServiceRegistry(services_dir, builtin_dir=services_dir.parent / "nonexistent")
        reg.load()

        reg.start_watcher()
        first_thread = reg._watcher_thread

        reg.stop_watcher()
        assert reg._watcher_thread is None

        reg.start_watcher()
        second_thread = reg._watcher_thread
        assert second_thread is not None
        assert second_thread is not first_thread
        assert second_thread.is_alive()

        reg.stop_watcher()


class TestSharedReferenceSafety:
    """B3: Verify from_dict methods handle mutable references safely where they do."""

    def test_capability_route_from_dict_does_not_share_methods_list(self):
        """CapabilityRoute uppercases methods into a new list, so input mutation is safe."""
        input_dict = {"methods": ["GET", "POST"], "path": "/v1/**"}
        route = CapabilityRoute.from_dict(input_dict)
        input_dict["methods"].append("DELETE")
        assert route.methods == ["GET", "POST"]

    def test_risky_route_from_dict_does_not_share_tactics_list(self):
        """RiskyRoute builds new lists via dict.fromkeys, so input mutation is safe."""
        input_dict = {
            "path": "/api/test",
            "tactics": ["impact"],
            "enables": ["defense_evasion"],
        }
        route = RiskyRoute.from_dict(input_dict)
        input_dict["tactics"].append("exfiltration")
        input_dict["enables"].append("lateral_movement")
        assert route.tactics == ["impact"]
        assert route.enables == ["defense_evasion"]

    def test_contract_binding_options_shares_reference_with_input(self):
        """ContractBinding.from_dict uses d.get("options", []) which shares the list.

        This is a known footgun (B3). Mutating the input dict's options after
        parsing will affect the binding. Documenting actual behaviour.
        """
        input_dict = {
            "type": "enum",
            "options": ["A", "B"],
        }
        binding = ContractBinding.from_dict("test", input_dict)
        input_dict["options"].append("C")
        # Shared reference: mutation propagates (B3 footgun, not yet fixed)
        assert binding.options == ["A", "B", "C"]

    def test_auth_config_from_dict_is_independent_of_input(self):
        """AuthConfig stores scalar values, so input dict mutation is safe."""
        input_dict = {"type": "bearer", "header": "Authorization"}
        auth = AuthConfig.from_dict(input_dict)
        input_dict["type"] = "api_key"
        assert auth.type == "bearer"

    def test_enforcement_status_from_dict_is_independent_of_input(self):
        """EnforcementStatus stores scalar values, so input dict mutation is safe."""
        input_dict = {"request_shape": "enforced"}
        es = EnforcementStatus.from_dict(input_dict)
        input_dict["request_shape"] = "declared"
        assert es.request_shape == "enforced"

    def test_service_definition_from_dict_capabilities_independent(self):
        """ServiceDefinition.from_dict creates new Capability instances, safe from input mutation."""
        input_dict = {
            "schema_version": 1,
            "name": "test",
            "capabilities": {
                "reader": {
                    "description": "Read-only",
                    "routes": [{"methods": ["GET"], "path": "/v1/**"}],
                },
            },
        }
        input_copy = copy.deepcopy(input_dict)
        svc = ServiceDefinition.from_dict(input_copy)
        input_copy["capabilities"]["reader"]["description"] = "CHANGED"
        assert svc.capabilities["reader"].description == "Read-only"
