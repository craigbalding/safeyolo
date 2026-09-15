"""Record actual LocalPolicyClient baseline projections from synthetic files.

The Rust historical baseline test runs this from the repository with its
configured Python executable and PYTHONPATH=cli/src:. .
The fixture disables watchers and audit output, supplies a temporary service
registry, and replaces token minting with deterministic noncredential labels.
No service requests are sent. All baseline and list paths belong to this run.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import logging
import platform
import socket
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pydantic
import yaml

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.core.service_loader import ServiceRegistry
from safeyolo.policy.compiler import compile_policy
from safeyolo.policy.loader import PolicyLoader, _extract_simple_permissions
from safeyolo.policy.models import UnifiedPolicy

ROOT = Path.cwd()
ROWS = []
EVENTS = []


def reject_network(*_args, **_kwargs):
    raise AssertionError("the projection fixture must remain local")


def client_for(path):
    return LocalPolicyClient(PolicyClientConfig(baseline_path=path))


def add_case(directory, name, source, *, suffix="json", siblings=None, registry=None):
    case_dir = directory / name
    case_dir.mkdir()
    text = source if isinstance(source, str) else json.dumps(source, ensure_ascii=False)
    baseline_path = case_dir / f"policy.{suffix}"
    baseline_path.write_text(text)
    for filename, contents in (siblings or {}).items():
        (case_dir / filename).write_text(contents)
    old_events = len(EVENTS)
    with patch("safeyolo.policy.compiler._get_service_registry", return_value=registry):
        client = client_for(baseline_path)
        try:
            baseline = client.get_baseline()
            row = {
                "case": name,
                "input": {"filename": baseline_path.name, "source": text, "siblings": siblings or {}},
                "health": client.health_check(),
                "baseline": baseline,
                "serialized": json.dumps({"policy": baseline}),
                "events": EVENTS[old_events:],
            }
            ROWS.append(row)
            return copy.deepcopy(row)
        finally:
            client.shutdown()


def main():
    logging.disable(logging.CRITICAL)
    token_counter = itertools.count(1)
    with tempfile.TemporaryDirectory(prefix="policy-projection-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        stack.enter_context(patch.object(PolicyLoader, "start_watcher", return_value=None))
        stack.enter_context(patch("safeyolo.policy.loader.write_event", side_effect=lambda event, **fields: EVENTS.append({"event": event, **fields})))
        stack.enter_context(patch("safeyolo.policy.compiler.mint_gateway_token", side_effect=lambda: f"synthetic-projection-label-{next(token_counter)}"))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=reject_network))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=reject_network))
        stack.enter_context(patch.object(socket.socket, "connect", side_effect=reject_network))
        stack.enter_context(patch.object(socket.socket, "connect_ex", side_effect=reject_network))
        with patch("safeyolo.policy.compiler._get_service_registry", return_value=None):
            absent = client_for(None)
            ROWS.append({"case": "no_configured_path", "health": absent.health_check(), "baseline": absent.get_baseline()})
            absent.shutdown()

        add_case(directory, "empty_iam", {})
        add_case(directory, "empty_hosts", {"hosts": {}})
        add_case(directory, "iam_exact_visible", {"permissions": [
            {"action": "network:request", "resource": "exact.invalid/*", "budget": 9},
            {"action": "network:request", "resource": "exact.invalid/*", "condition": {}},
            {"action": "file:read", "resource": "/workspace/*", "effect": "deny"},
            {"action": "file:write", "resource": "/workspace/out", "condition": {"method": "put", "credential": ["x:*"], "account": "agent", "ignored": "drop"}},
            {"action": "subprocess:exec", "resource": "program:*", "tier": "inferred"},
        ], "simple_permissions": {"authored:count": 17}})
        add_case(directory, "host_simple_extraction", {"hosts": {
            "first.invalid": {"egress": "allow", "rules": [
                {"action": "network:request", "resource": "first.invalid/*", "condition": {}},
                {"action": "network:request", "resource": "first.invalid/*", "effect": "deny"},
                {"action": "file:read", "resource": "other.invalid/*"},
            ]},
            "*:8443": {"egress": "deny"},
            "*.wild.invalid": {"egress": "prompt"},
            "*": {"egress": "deny"},
        }, "simple_permissions": {"ignored": 99}})
        add_case(directory, "all_schema_fields", {
            "metadata": {"version": "2.0", "task_id": "fixture-task", "description": "Synthetic baseline", "created": "text-date", "extra": "drop"},
            "budgets": {"file:read": "7", "network:request": 30}, "required": ["other_addon", "network_guard"],
            "credential_rules": [{"name": "fixture", "patterns": ["not-a-real-secret"], "allowed_hosts": ["EXAMPLE.invalid"], "extra": "drop"}],
            "scan_patterns": [{"name": "fixture", "pattern": "abc", "case_sensitive": "false", "extra": "drop"}],
            "addons": {"fixture": {"enabled": "false", "settings": {"nested": {"arbitrary": [1, True, None]}}, "custom": "retain"}},
            "domains": {"EXAMPLE.invalid": {"bypass": ["fixture"], "addons": {"fixture": {"custom": 3}}, "extra": "drop"}},
            "clients": {"alice": {"addons": {"fixture": {"enabled": False}}}},
            "gateway": {"arbitrary": {"preserve": True}}, "unknown_top_level": "drop",
        })
        add_case(directory, "sibling_defaults", {
            "hosts": {"one.invalid": {"egress": "allow", "bypass": ["credential_guard"], "addons": {"custom": {"color": "host"}}}},
            "addons": {"custom": {"enabled": False}},
            "domains": {"one.invalid": {"bypass": ["other"], "addons": {"lost": {}}}},
        }, siblings={"addons.yaml": "addons:\n  custom: {enabled: true, settings: {lost: true}, color: default}\n  other: {enabled: false, trace: true}\nrequired: [other]\nscan_patterns:\n  - {name: from-sibling, pattern: x}\n"})
        add_case(directory, "host_credentials_and_risk", {
            "hosts": {"bind.invalid": {"credentials": "fixture:*", "service": "slack", "egress": "allow"}},
            "credentials": {"fixture": {"patterns": ["abc"], "headers": ["X-Token"], "suggested_url": "https://synthetic.invalid"}},
            "credential_rules": [{"name": "ignored", "patterns": ["ignored"], "allowed_hosts": []}],
            "budgets": {"file:read": 8}, "global_budget": 50,
            "gateway": {"risk_appetite": [{"decision": "allow", "agent": "alice"}], "grant_ttl_seconds": 31, "arbitrary": "drop"},
        })
        add_case(directory, "toml_normalization", '''version = "3.0"
description = "TOML top metadata"
budget = 50
[metadata]
description = "ignored nested metadata"
[credential.fixture]
match = ["abc"]
headers = ["X-Synthetic"]
[hosts."api.invalid"]
allow = ["fixture:*"]
egress = "allow"
[[risk]]
decision = "deny"
agent = "alice"
''', suffix="toml")
        add_case(directory, "lists_and_expiry", {
            "hosts": {"$blocked": {"egress": "deny"}, "$expired": {"egress": "allow", "expires": "2001-01-01T00:00:00Z"}, "explicit.invalid": {"egress": "allow"}},
            "lists": {"blocked": "blocked.txt", "expired": "never-open.txt"},
        }, siblings={"blocked.txt": "# synthetic list\nfirst.invalid\nfirst.invalid\n0.0.0.0 second.invalid\nexplicit.invalid\n"})
        add_case(directory, "sort_and_agent_order", {
            "hosts": {"x.invalid": {"credentials": ["fixture:*"], "egress": "allow", "rate_limit": 5}, "x.invalid:443": {"egress": "deny"}},
            "agents": {"alice": {"hosts": {"x.invalid": {"credentials": ["fixture:*"], "egress": "allow", "rate_limit": 5}}, "egress": "prompt"}},
        })
        service_input = {
            "hosts": {"slack.com": {"service": "slack"}},
            "agents": {"alice": {"services": {"slack": {"capability": "reader", "token": "synthetic-vault-reference"}}}, "bob": {"services": {"slack": "poster"}}},
        }
        add_case(directory, "gateway_registry_absent", service_input)
        service_user = directory / "user-services"
        service_user.mkdir()
        registry = ServiceRegistry(service_user, ROOT / "cli/src/safeyolo/services", require_builtin=True)
        registry.load(strict=True)
        add_case(directory, "gateway_registry_present", service_input, registry=registry)
        add_case(directory, "invalid_initial_load", {"permissions": [{"action": "made:up", "resource": "*"}]})
        add_case(directory, "invalid_sibling_ignored", {"hosts": {"still.invalid": {"egress": "allow"}}}, siblings={"addons.yaml": "addons: [\n"})
        add_case(directory, "extraction_before_validation", {"hosts": {"x.invalid": {"rules": [
            {"action": "made:up", "resource": "x.invalid/*", "effect": "unknown", "budget": "not-an-integer"},
        ]}}})
        add_case(directory, "wide_integers_and_authored_object", {
            "budgets": {"file:read": 2**64 + 1},
            "permissions": [{"action": "file:read", "resource": "*", "budget": 2**64 + 1}],
            "gateway": {"authored_object": {"$serde_json::private::Number": "123"}},
        })

        path = directory / "reload.json"
        path.write_text(json.dumps({"permissions": [{"action": "network:request", "resource": "*", "effect": "deny"}]}))
        with patch("safeyolo.policy.compiler._get_service_registry", return_value=None):
            client = client_for(path)
            loader = client._pdp._engine._loader
            before = client.get_baseline()
            task = directory / "task.json"
            task.write_text(json.dumps({"metadata": {"task_id": "fixture-task"}, "permissions": [{"action": "network:request", "resource": "*", "effect": "allow"}]}))
            task_loaded = client._pdp._engine.load_task_policy(task)
            after_task = client.get_baseline()
            path.write_text(json.dumps({"permissions": [{"action": "network:request", "resource": "*", "effect": "prompt"}]}))
            before_reload = client.get_baseline()
            successful_reload = loader._load_baseline()
            after_reload = client.get_baseline()
            path.write_text("{")
            failed_reload = loader._load_baseline()
            after_failure = client.get_baseline()
            ROWS.append({"case": "task_and_reload", "before": before, "task_loaded": task_loaded, "after_task": after_task, "before_reload": before_reload, "successful_reload": successful_reload, "after_reload": after_reload, "failed_reload": failed_reload, "after_failure": after_failure})
            client.shutdown()

    checks = verify_rows()
    files = ["pdp/client.py", "pdp/core.py", "cli/src/safeyolo/policy/engine.py", "cli/src/safeyolo/policy/loader.py", "cli/src/safeyolo/policy/compiler.py", "cli/src/safeyolo/policy/models.py", "cli/src/safeyolo/policy/toml_normalize.py", "cli/src/safeyolo/policy/list_loader.py", "proxy/src/policy.rs", "proxy/src/services.rs"]
    result = {
        "python": platform.python_version(),
        "pydantic": pydantic.__version__,
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
        "row_count": len(ROWS), "checks": checks, "rows": ROWS,
        "supplemental": supplemental(),
        "timestamps": timestamp_rows(),
    }
    print(json.dumps(result, ensure_ascii=True))


TIMESTAMP_TEMPLATES = {
    "metadata_string": "metadata: {created: VALUE}",
    "metadata_unknown": "metadata: {ignored: VALUE}",
    "required_string": "required: [VALUE]",
    "budget_integer": "budgets: {file: VALUE}",
    "addon_enabled_bool": "addons: {synthetic: {enabled: VALUE}}",
    "addon_setting_any": "addons: {synthetic: {settings: {observed: VALUE}}}",
    "addon_extra_any": "addons: {synthetic: {observed: VALUE}}",
    "addon_settings_key": "addons: {synthetic: {settings: {VALUE: observed}}}",
    "addon_nested_any_key": "addons: {synthetic: {settings: {nested: {VALUE: observed}}}}",
    "domain_unknown": "domains: {example.test: {ignored: VALUE}}",
    "domain_addon_any": "domains: {example.test: {addons: {synthetic: {observed: VALUE}}}}",
    "permission_unknown": "permissions: [{action: 'network:request', resource: '*', ignored: VALUE}]",
    "condition_unknown": "permissions: [{action: 'network:request', resource: '*', condition: {ignored: VALUE}}]",
    "condition_string": "permissions: [{action: 'network:request', resource: '*', condition: {agent: VALUE}}]",
    "scan_string": "scan_patterns: [{name: synthetic, pattern: VALUE}]",
    "gateway_any": "gateway: {observed: VALUE}",
    "host_unknown": "hosts: {example.test: {ignored: VALUE}}",
    "host_egress": "hosts: {example.test: {egress: VALUE}}",
    "host_service": "hosts: {example.test: {service: VALUE}}",
    "host_credentials": "hosts: {example.test: {credentials: [VALUE]}}",
    "host_extracted_action": "hosts: {example.test: {rules: [{action: VALUE, resource: 'example.test/*'}]}}",
    "host_extracted_effect": "hosts: {example.test: {rules: [{action: 'network:request', effect: VALUE, resource: 'example.test/*'}]}}",
    "host_permission_resource": "hosts: {example.test: {rules: [{action: 'network:request', resource: VALUE}]}}",
    "host_key": "hosts: {VALUE: {egress: allow}}",
    "agent_capability": "hosts: {}\nagents: {alice: {services: {synthetic: {capability: VALUE}}}}",
    "agent_account": "hosts: {}\nagents: {alice: {services: {synthetic: {capability: reader, account: VALUE}}}}",
    "agent_vault_ref": "hosts: {}\nagents: {alice: {services: {synthetic: {capability: reader, token: VALUE}}}}",
    "agent_service_key": "hosts: {}\nagents: {alice: {services: {VALUE: reader}}}",
    "agent_binding_dropped": "hosts: {}\nagents: {alice: {contract_bindings: [{service: synthetic, bound_values: {observed: VALUE}}]}}",
}


def timestamp_rows():
    rows = []
    for name, template in TIMESTAMP_TEMPLATES.items():
        for label, spelling in [("date", "2001-02-03"), ("datetime", "2001-02-03T04:05:06Z"), ("quoted", '"2001-02-03T04:05:06Z"')]:
            text = template.replace("VALUE", spelling)
            row = {"case": name, "scalar": label, "source": text}
            try:
                raw = yaml.safe_load(text)
                if "hosts" in raw:
                    with patch("safeyolo.policy.compiler.mint_gateway_token", return_value="opaque-token-label"), patch("safeyolo.policy.compiler._get_service_registry", return_value=None):
                        raw = compile_policy(raw)
                    raw["permissions"], simple = _extract_simple_permissions(raw["permissions"])
                    raw["simple_permissions"] = {f"{action}:{effect}": len(resources) for (action, effect), resources in simple.items()}
                expected = UnifiedPolicy.model_validate(raw).model_dump()
                row["loaded"] = True
                try:
                    json.dumps(expected)
                except TypeError:
                    row["serializable"] = False
                else:
                    row["serializable"] = True
                    row["expected"] = expected
            except Exception as exc:
                row["loaded"] = False
                row["error"] = type(exc).__name__
            rows.append(row)
    return rows


def supplemental():
    groups = []
    for values in [
        [True, 1, 1.0], [1, True, 1.0], [1.0, 1, True],
        [-0.0, 0, False], [2**53 + 1, float(2**53 + 1)],
        [True, True, "True"], ["a:b", "a", "a:b"],
    ]:
        rules = [{"action": action, "effect": None, "resource": f"r{index}.invalid/*"} for index, action in enumerate(values)]
        if values == ["a:b", "a", "a:b"]:
            for rule, effect in zip(rules, ["c", "b:c", "c"]):
                rule["effect"] = effect
        remaining, simple = _extract_simple_permissions(rules)
        assert not remaining
        groups.append({"source": {"hosts": {"x.invalid": {"rules": rules}}}, "expected": {f"{action}:{effect}": len(resources) for (action, effect), resources in simple.items()}})
    integers = []
    for value in [True, False, 0, -1, 2**64 + 1, 1.0, 1.5, "1.00", "+1.000", "1_0.00", "1.0_0", "1_.0", "1e0", "01", "١٢", " 1\x1c", "\u20031\u00a0", "_1", "00_1", ".0", "1.", None, [], {}]:
        try:
            expected = UnifiedPolicy(budgets={"file:read": value}).budgets["file:read"]
        except ValueError:
            integers.append({"value": value, "accepted": False})
        else:
            integers.append({"value": value, "accepted": True, "expected": expected})
    return {"scalar_groups": groups, "integers": integers}


def verify_rows():
    rows = {row["case"]: row for row in ROWS}
    def baseline(name):
        return rows[name]["baseline"]

    transition = rows["task_and_reload"]
    checks = {
        "absent_baseline_is_null": baseline("no_configured_path") is None,
        "empty_and_failed_initial_models_have_same_defaults": baseline("empty_iam") == baseline("empty_hosts") == baseline("invalid_initial_load"),
        "all_eleven_baseline_fields_present": len(baseline("empty_iam")) == 11,
        "iam_retains_all_actions_and_exact_rules": len(baseline("iam_exact_visible")["permissions"]) == 5,
        "host_simple_counts_deduplicate_and_include_nonproxy_actions": baseline("host_simple_extraction")["simple_permissions"] == {"network:request:allow": 1, "network:request:deny": 1, "file:read:allow": 1},
        "sibling_addon_replacement_is_not_settings_deep_merge": baseline("sibling_defaults")["addons"]["custom"] == {"enabled": False, "settings": {}},
        "toml_top_metadata_wins_nested_metadata": baseline("toml_normalization")["metadata"]["description"] == "TOML top metadata",
        "toml_credential_and_risk_compile": len(baseline("toml_normalization")["credential_rules"]) == 1 and any(rule["action"] == "gateway:risky_route" for rule in baseline("toml_normalization")["permissions"]),
        "expired_list_not_opened_and_list_values_deduplicated": baseline("lists_and_expiry")["simple_permissions"] == {"network:request:allow": 1, "network:request:deny": 2},
        "gateway_mints_bindings_without_registry": len(baseline("gateway_registry_absent")["gateway"]["token_map"]) == 2 and not baseline("gateway_registry_absent")["permissions"],
        "same_registry_compiles_seven_slack_routes": len(baseline("gateway_registry_present")["permissions"]) == 7,
        "failed_sibling_does_not_discard_baseline": baseline("invalid_sibling_ignored")["simple_permissions"] == {"network:request:allow": 1},
        "source_extracts_before_permission_validation": baseline("extraction_before_validation")["simple_permissions"] == {"made:up:unknown": 1},
        "wide_integer_preserved_exactly": baseline("wide_integers_and_authored_object")["budgets"]["file:read"] == 2**64 + 1,
        "authored_number_marker_is_an_object": baseline("wide_integers_and_authored_object")["gateway"]["authored_object"] == {"$serde_json::private::Number": "123"},
        "task_does_not_replace_baseline": transition["task_loaded"] and transition["before"] == transition["after_task"],
        "reads_do_not_reload_source": transition["before"] == transition["before_reload"],
        "reload_publishes_new_baseline": transition["successful_reload"] and transition["before"] != transition["after_reload"],
        "failed_reload_retains_prior_baseline": not transition["failed_reload"] and transition["after_reload"] == transition["after_failure"],
    }
    assert all(checks.values()), checks
    return checks


if __name__ == "__main__":
    main()
