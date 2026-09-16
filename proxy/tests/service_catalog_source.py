"""Selected real service loader, gateway catalog and AgentAPI source contracts.

All files, bindings and authentication material are synthetic and owned. No
gateway request/injection hook, watcher, vault read, socket or production startup
runs. Lifecycle inputs use a disclosed compiled-policy client seam; the real
configure, token refresh, registry transaction and catalog methods still run.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import logging
import os
import socket
import sys
import tempfile
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
TOKEN = "owned-service-catalog-api-token"
HOST = "_safeyolo.proxy.internal"
SOURCE_PATHS = [
    "cli/src/safeyolo/core/service_loader.py",
    "cli/src/safeyolo/core/service_paths.py",
    "cli/src/safeyolo/mitm_addons/service_gateway.py",
    "cli/src/safeyolo/mitm_addons/agent_api.py",
    "cli/src/safeyolo/core/identity.py",
    "cli/src/safeyolo/core/flow_cache.py",
    "cli/src/safeyolo/core/utils.py",
    "cli/src/safeyolo/core/audit_schema.py",
    "cli/src/safeyolo/proxy_modes/unix_listener.py",
    "cli/src/safeyolo/policy/toml_roundtrip.py",
    "pdp/tokens.py",
]


def service(name, description="", capabilities=None):
    return {"schema_version": 1, "name": name, "description": description, "capabilities": capabilities or {}}


def catalog_files():
    return {
        "builtin/10-z.yaml": service(
            "zeta", "Builtin Z", {"write": {"description": "Write"}, "read": {"description": "Read"}}
        ),
        "builtin/20-a.yaml": service(
            "alpha", "Alpha", {"second": {"description": "Second"}, "first": {"description": "First"}}
        ),
        "user/10-z.yaml": service(
            "zeta", "Owned override", {"late": {"description": "Late"}, "early": {"description": "Early"}}
        ),
        "user/20-m.yaml": service("middle", "Middle"),
    }


def loader_cases():
    return [
        {"name": "missing_required_builtin", "steps": [{}]},
        {"name": "empty_builtin_optional_user_missing", "steps": [{"dirs": ["builtin"]}]},
        {"name": "both_sources_are_files", "steps": [{"files": {"builtin": "owned", "user": "owned"}}]},
        {
            "name": "yaml_selection_and_filename_order",
            "steps": [
                {
                    "files": {
                        "builtin/.hidden.yaml": service("z-hidden"),
                        "builtin/20-a.yaml": service("a-last"),
                        "builtin/ignored.yml": "[invalid",
                        "builtin/ignored.YAML": "[invalid",
                        "builtin/nested/ignored.yaml": "[invalid",
                    }
                }
            ],
        },
        {"name": "user_override_retains_position", "steps": [{"files": catalog_files()}]},
        {
            "name": "duplicate_rejects_prefix_then_recovery",
            "steps": [
                {"files": {"builtin/10.yaml": service("old")}},
                {"files": {"builtin/10.yaml": service("new"), "builtin/20.yaml": service("new")}},
                {"remove": ["builtin/20.yaml"], "files": {"builtin/10.yaml": service("recovered")}},
            ],
        },
        {
            "name": "malformed_candidate_retains_previous",
            "steps": [
                {"files": {"builtin/00.yaml": service("old")}},
                {
                    "files": {
                        "builtin/00.yaml": service("candidate"),
                        "user/10-empty.yaml": "",
                        "user/20-scalar.yaml": "42\n",
                        "user/30-version.yaml": {"name": "bad"},
                        "user/40-parse.yaml": "[invalid",
                    },
                    "dirs": ["user/50-directory.yaml"],
                },
            ],
        },
        {
            "name": "consumer_rollback_and_no_unchanged_retry",
            "steps": [
                {"files": {"builtin/00.yaml": service("old")}},
                {"op": "reload", "files": {"builtin/00.yaml": service("rejected-long-name")}, "consumer_error": True},
                {"op": "reload"},
                {"op": "reload", "files": {"builtin/00.yaml": service("recovered")}},
            ],
        },
    ]


def bindings():
    return [
        {"token": "owned-alice-z-first", "agent": "alice", "service": "zeta", "capability": "early"},
        {"token": "owned-bob-middle", "agent": "bob", "service": "middle", "capability": "reader"},
        {"token": "owned-alice-alpha", "agent": "alice", "service": "alpha", "capability": "first"},
        {"token": "owned-alice-z-last", "agent": "alice", "service": "zeta", "capability": "late", "account": "team"},
    ]


def api_defaults():
    return {
        "method": "GET",
        "path": "/gateway/services",
        "agent": "alice",
        "auth": "valid",
        "gateway": True,
        "registry": "normal",
        "query": "",
        "payload": "",
        "hosts": {"first.owned.invalid": "zeta", "alpha.owned.invalid": "alpha", "last.owned.invalid": "zeta"},
        "bindings": bindings(),
        "registries": {
            "normal": {"files": catalog_files(), "dirs": ["builtin"]},
            "empty": {"files": {}, "dirs": ["builtin"]},
            "typed": {
                "files": {
                    "builtin/typed.yaml": service(
                        "typed", None, {"boolean": {"description": False}, "object": {"description": {"owned": 2}}}
                    )
                },
                "dirs": ["builtin"],
            },
        },
    }


def api_cases():
    return [
        {"name": "alice_last_host_and_binding", "agent": "alice"},
        {"name": "bob_scope_available_order", "agent": "bob"},
        {"name": "unbound_agent_available_order", "agent": "carol"},
        {
            "name": "query_and_header_cannot_select_bob",
            "agent": "alice",
            "query": "agent=bob&agent=carol&unused=%FF",
            "header_agent": "bob",
        },
        {"name": "post_body_ignored", "method": "POST", "payload": "not JSON", "encoding": "gzip"},
        {"name": "delete_and_trailing_slashes", "method": "DELETE", "path": "/gateway/services///"},
        {"name": "method_before_auth", "method": "PUT", "auth": "missing", "agent": None},
        {"name": "missing_auth_before_identity", "auth": "missing", "agent": None, "gateway": False},
        {"name": "bad_auth_before_identity", "auth": "wrong", "agent": None},
        {"name": "identity_before_owner", "agent": None, "gateway": False, "header_agent": "alice"},
        {"name": "trusted_metadata_conflict", "metadata_agent": "bob"},
        {"name": "missing_gateway_owner", "gateway": False},
        {"name": "absent_registry_retains_authorized", "registry": "absent"},
        {"name": "empty_registry_retains_authorized", "registry": "empty"},
        {"name": "no_bindings_and_no_registry", "bindings": [], "registry": "absent"},
        {"name": "missing_host_defaults_empty", "hosts": {}},
        {
            "name": "malformed_sibling_service_unhashable",
            "extra_binding": {"token": "owned-bad", "agent": "bob", "service": ["zeta"], "capability": "reader"},
        },
        {"name": "typed_available_descriptions", "agent": "carol", "registry": "typed"},
        {
            "name": "caller_timestamp_account_serialization",
            "extra_binding": {
                "token": "owned-time",
                "agent": "alice",
                "service": "zeta",
                "capability": "reader",
                "account_datetime": "2026-01-02T03:04:05",
            },
        },
        {
            "name": "overwritten_timestamp_binding_not_serialized",
            "bindings": [
                {
                    **bindings()[0],
                    "account_datetime": "2026-01-02T03:04:05",
                    "capability_datetime": "2026-01-02T03:04:05",
                },
                *bindings()[1:],
            ],
        },
    ]


def write_recipe(directory, spec, yaml):
    for relative in spec.get("remove", []):
        (directory / relative).unlink()
    for relative in spec.get("dirs", []):
        (directory / relative).mkdir(parents=True, exist_ok=True)
    for relative, content in spec.get("files", {}).items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            content if isinstance(content, str) else yaml.safe_dump(content, sort_keys=False), encoding="utf-8"
        )
    for relative, content in spec.get("bytes_hex", {}).items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes.fromhex(content))
    for relative, target in spec.get("symlinks", {}).items():
        (directory / relative).symlink_to(target)


def normalized(value, directory):
    if isinstance(value, str):
        return value.replace(str(directory), "<owned>")
    if isinstance(value, list):
        return [normalized(item, directory) for item in value]
    if isinstance(value, dict):
        return {key: normalized(item, directory) for key, item in value.items()}
    return value


def registry_view(registry):
    return None if registry is None else [svc.to_dict() for svc in registry.list_services()]


def observe_loader(spec, directory, modules, events):
    loader, yaml = modules.loader, modules.yaml
    directory.mkdir()
    registry = loader.ServiceRegistry(directory / "user", builtin_dir=directory / "builtin", require_builtin=True)
    outputs, callbacks = [], []
    active = {}

    def synchronize():
        names = [svc.name for svc in registry.list_services()]
        callbacks.append(names)
        if active.get("consumer_error") and names == ["rejected-long-name"]:
            raise RuntimeError("owned consumer rejected candidate")

    registry.add_reload_callback(synchronize)
    for index, step in enumerate(spec["steps"]):
        active = step
        write_recipe(directory, step, yaml)
        error, changed = None, None
        event_start, callback_start = len(events), len(callbacks)
        try:
            if step.get("op", "load") == "reload":
                changed = registry.reload_if_changed()
            else:
                registry.load(strict=True)
        except (loader.ServiceRegistryError, RuntimeError) as exception:
            error = {"class": type(exception).__name__, "message": str(exception)}
        outputs.append(
            normalized(
                {
                    "step": index,
                    "error": error,
                    "changed": changed,
                    "services": registry_view(registry),
                    "last_errors": [
                        {"path": str(p.path), "error_type": p.error_type, "message": p.message}
                        for p in registry.last_errors
                    ],
                    "callbacks": callbacks[callback_start:],
                    "audit": events[event_start:],
                },
                directory,
            )
        )
    return {"input": spec, "steps": outputs}


def diagnostic_cases():
    files = {
        "builtin/00.yaml": service("candidate"),
        "builtin/10-empty.yaml": "",
        "builtin/40-missing-name.yaml": {"schema_version": 1},
        "builtin/50-null-capabilities.yaml": {"schema_version": 1, "name": "null", "capabilities": None},
        "builtin/60-schema.yaml": {"schema_version": 2, "name": "unsupported"},
        "builtin/70-duplicate.yaml": service("candidate"),
        "user/00-parser.yaml": "[invalid",
        "user/10-nonmapping.yaml": "42\n",
    }
    return [
        {
            "name": name,
            "audit_raises": raises,
            "initial_files": {"builtin/00.yaml": service("previous")},
            "files": files,
            "dirs": ["builtin/30-directory.yaml"],
            "bytes_hex": {"builtin/20-utf8.yaml": "ff"},
            "symlinks": {"builtin/35-missing.yaml": "owned-missing-target"},
        }
        for name, raises in [("ordered_file_diagnostics", False), ("audit_failure_does_not_interrupt_load", True)]
    ]


def observe_diagnostics(spec, directory, modules):
    directory.mkdir()
    write_recipe(directory, {"files": spec["initial_files"]}, modules.yaml)
    registry = modules.loader.ServiceRegistry(
        directory / "user", builtin_dir=directory / "builtin", require_builtin=True
    )
    registry.load(strict=True)
    previous = registry_view(registry)
    write_recipe(directory, spec, modules.yaml)
    attempts, timeline = [], []
    real_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        assert path.is_relative_to(directory), "loader must read only owned definitions"
        timeline.append({"kind": "read", "path": str(path.relative_to(directory))})
        return real_read_text(path, *args, **kwargs)

    def submit(entry):
        event = copy.deepcopy(entry)
        event["ts"] = "<canonical timestamp>"
        attempt = {
            "event": event,
            "accepted": not spec["audit_raises"],
            "exception_class": "RuntimeError" if spec["audit_raises"] else None,
            "services_at_submit": registry_view(registry),
            "last_errors_at_submit": len(registry.last_errors),
        }
        attempts.append(attempt)
        timeline.append({"kind": "audit", "file": event["details"]["file"], "accepted": attempt["accepted"]})
        if spec["audit_raises"]:
            raise RuntimeError("owned audit submission failure")

    error = None
    with (
        patch.object(Path, "read_text", new=read_text),
        patch.object(modules.audit_writer, "put_event", side_effect=submit),
    ):
        try:
            registry.load(strict=True)
        except modules.loader.ServiceRegistryError as exception:
            error = {"class": type(exception).__name__, "message": str(exception)}
    return {
        "input": spec,
        **normalized(
            {
                "error": error,
                "previous_services": previous,
                "services": registry_view(registry),
                "last_errors": [
                    {"path": str(p.path), "error_type": p.error_type, "message": p.message}
                    for p in registry.last_errors
                ],
                "attempts": attempts,
                "timeline": timeline,
                "file_state_paths": [str(Path(path).relative_to(directory)) for path in registry._last_file_state],
                "has_changes_after_failure": registry._has_changes(),
            },
            directory,
        ),
    }


def gateway_from(spec, modules):
    gateway = modules.gateway.ServiceGateway()
    gateway._host_map = spec["hosts"].copy()
    rows = copy.deepcopy(spec["bindings"])
    if "extra_binding" in spec:
        rows.append(copy.deepcopy(spec["extra_binding"]))
    for binding in rows:
        account = binding.get("account", "agent")
        if "account_datetime" in binding:
            account = datetime.fromisoformat(binding["account_datetime"])
        capability = binding["capability"]
        if "capability_datetime" in binding:
            capability = datetime.fromisoformat(binding["capability_datetime"])
        gateway._token_map[binding["token"]] = modules.gateway.TokenBinding(
            agent=binding["agent"],
            service_name=binding["service"],
            capability_name=capability,
            account=account,
            vault_token="owned-vault-reference",
        )
    return gateway


def response(flow, api):
    return {
        "status": flow.response.status_code,
        "body_text": flow.response.content.decode(),
        "headers": [list(pair) for pair in flow.response.headers.items(multi=True)],
        "api_response": flow.metadata.get(api.AGENT_API_RESPONSE_METADATA),
        "blocked_by": flow.metadata.get("blocked_by"),
    }


def call_api(spec, gateway, registry, modules):
    api = modules.api.AgentAPI()
    flow = modules.tflow.tflow(resp=False)
    flow.client_conn.id = "owned-catalog-connection"
    flow.metadata.clear()
    flow.request = modules.http.Request.make(
        spec.get("method", "GET"),
        "http://" + HOST + spec.get("path", "/gateway/services") + ("?" + spec["query"] if spec.get("query") else ""),
        spec.get("payload", "").encode(),
    )
    auth = spec.get("auth", "valid")
    if auth != "missing":
        flow.request.headers["Authorization"] = "Bearer " + (TOKEN if auth == "valid" else "owned-wrong")
    if "encoding" in spec:
        flow.request.headers["Content-Encoding"] = spec["encoding"]
    if "header_agent" in spec:
        flow.request.headers["X-SafeYolo-Agent"] = spec["header_agent"]
    agent = spec.get("agent", "alice")
    flow.client_conn.peername = ("192.0.2.10", 1234)
    if agent:
        flow.client_conn.proxy_mode = modules.UnixMode.parse(f"unix:/tmp/192.0.2.10_{agent}/proxy.sock")
    if "metadata_agent" in spec:
        flow.metadata["agent"] = spec["metadata_agent"]
    timeline = []

    def lookup(name):
        timeline.append("lookup:" + name)
        return gateway if name == "service-gateway" else None

    real_project = gateway.get_agent_services if gateway else None
    real_list = registry.list_services if registry else None

    def project():
        timeline.append("get_agent_services")
        return real_project()

    def list_services():
        timeline.append("list_services")
        return real_list()

    context = SimpleNamespace(
        options=SimpleNamespace(agent_api_enabled=True), master=SimpleNamespace(addons=SimpleNamespace(get=lookup))
    )
    with ExitStack() as stack:
        stack.enter_context(patch.object(modules.api, "ctx", context))
        stack.enter_context(patch.object(modules.loader, "_registry", registry))
        if gateway:
            stack.enter_context(patch.object(gateway, "get_agent_services", side_effect=project))
        if registry:
            stack.enter_context(patch.object(registry, "list_services", side_effect=list_services))
        asyncio.run(api.request(flow))
    assert flow.response is not None
    result = response(flow, modules.api)
    assert result["api_response"] is True and result["blocked_by"] == "agent-api"
    assert flow.response.headers["content-length"] == str(len(flow.response.content))
    return {"result": result, "timeline": timeline}


def make_registry(directory, kind, modules):
    if kind == "absent":
        return None
    write_recipe(directory, api_defaults()["registries"][kind], modules.yaml)
    registry = modules.loader.ServiceRegistry(
        directory / "user", builtin_dir=directory / "builtin", require_builtin=True
    )
    registry.load(strict=True)
    return registry


def observe_api(spec, directory, modules, events):
    directory.mkdir()
    effective = {**api_defaults(), **spec}
    gateway = gateway_from(effective, modules) if effective["gateway"] else None
    registry = make_registry(directory, effective["registry"], modules)
    event_start = len(events)
    observed = call_api(effective, gateway, registry, modules)
    return {"input": spec, **observed, "audit": copy.deepcopy(events[event_start:])}


def observe_lifecycle(directory, modules):
    directory.mkdir()
    write_recipe(directory, {"files": catalog_files()}, modules.yaml)
    policy_path = directory / "owned-policy.toml"
    policy_path.write_text("[agents]\n", encoding="utf-8")
    gateway = modules.gateway.ServiceGateway()
    timeline, callbacks, steps = [], [], []
    config = {"token_map": {}, "host_map": {}}

    def reload_policy():
        timeline.append("policy.reload")
        return True

    def gateway_config():
        timeline.append("policy.get_gateway_config")
        return copy.deepcopy(config)

    def register(callback):
        timeline.append("policy.add_reload_callback")
        callbacks.append(callback)

    policy_loader = SimpleNamespace(
        _baseline_path=policy_path, baseline=SimpleNamespace(permissions=[]), reload=reload_policy
    )
    client = SimpleNamespace(
        _pdp=SimpleNamespace(_engine=SimpleNamespace(_loader=policy_loader)),
        get_gateway_config=gateway_config,
        add_reload_callback=register,
    )
    options = SimpleNamespace(
        gateway_enabled=False,
        gateway_services_dir=str(directory / "user"),
        gateway_builtin_services_dir=str(directory / "builtin"),
        gateway_vault_key=str(directory / "absent-vault-key"),
        gateway_vault_path=str(directory / "absent-vault"),
    )

    def snapshot(name, start):
        registry = modules.loader.get_service_registry()
        steps.append(
            {
                "name": name,
                "enabled": options.gateway_enabled,
                "configure_timeline": timeline[start:],
                "registered_callbacks": len(callbacks),
                "services": registry_view(registry),
                "projection": gateway.get_agent_services(),
                "tokens_registered": gateway.stats.tokens_registered,
                **call_api({}, gateway, registry, modules),
            }
        )

    with ExitStack() as stack:
        stack.enter_context(patch.object(modules.loader, "_registry", None))
        stack.enter_context(patch.object(modules.gateway, "ctx", SimpleNamespace(options=options)))
        stack.enter_context(patch.object(modules.pdp, "is_policy_client_configured", return_value=True))
        stack.enter_context(patch.object(modules.pdp, "get_policy_client", return_value=client))
        stack.enter_context(
            patch.object(
                modules.loader.ServiceRegistry,
                "start_watcher",
                side_effect=lambda: timeline.append("watcher.start.suppressed"),
            )
        )
        gateway.configure({"gateway_enabled"})
        snapshot("initial_disabled", 0)
        config = {
            "host_map": {"first.owned.invalid": "zeta"},
            "token_map": {
                "owned-before": {"agent": "alice", "service": "zeta", "capability": "early", "token": "owned-reference"}
            },
        }
        start = len(timeline)
        options.gateway_enabled = True
        gateway.configure({"gateway_enabled"})
        snapshot("loaded_enabled", start)
        start = len(timeline)
        options.gateway_enabled = False
        gateway.configure({"gateway_enabled"})
        snapshot("loaded_then_disabled", start)
        start = len(timeline)
        config = {
            "host_map": {"new.owned.invalid": "alpha"},
            "token_map": {
                "owned-after": {"agent": "alice", "service": "alpha", "role": "first", "token": "owned-reference"}
            },
        }
        for callback in callbacks:
            callback()
        snapshot("callback_refresh_while_disabled", start)
        start = len(timeline)
        config = {"host_map": {}, "token_map": {}}
        for callback in callbacks:
            callback()
        snapshot("empty_token_source_retention_D43", start)
    return {"input": {"name": "selected_configure_disable_and_callback", "files": catalog_files()}, "steps": steps}


def check_contract(result):
    api = {row["input"]["name"]: row for row in result["api_rows"]}
    alice = json.loads(api["alice_last_host_and_binding"]["result"]["body_text"])
    assert list(alice) == ["agent", "authorized", "available"]
    assert list(alice["authorized"]) == ["zeta", "alpha"]
    assert alice["authorized"]["zeta"] == {
        "host": "last.owned.invalid",
        "token": "owned-alice-z-last",
        "capability": "late",
        "account": "team",
    }
    bob = json.loads(api["bob_scope_available_order"]["result"]["body_text"])
    assert list(bob["authorized"]) == ["middle"]
    assert [item["name"] for item in bob["available"]] == ["zeta", "alpha"]
    assert [item["name"] for item in bob["available"][0]["capabilities"]] == ["late", "early"]
    for name in [
        "query_and_header_cannot_select_bob",
        "post_body_ignored",
        "delete_and_trailing_slashes",
        "overwritten_timestamp_binding_not_serialized",
    ]:
        assert api[name]["result"] == api["alice_last_host_and_binding"]["result"]
    for name, status in {
        "method_before_auth": 405,
        "missing_auth_before_identity": 401,
        "bad_auth_before_identity": 401,
        "identity_before_owner": 403,
        "trusted_metadata_conflict": 403,
        "missing_gateway_owner": 503,
        "malformed_sibling_service_unhashable": 500,
        "caller_timestamp_account_serialization": 500,
    }.items():
        assert api[name]["result"]["status"] == status
    assert api["method_before_auth"]["timeline"] == []
    assert api["identity_before_owner"]["timeline"] == ["lookup:service-discovery"]
    assert api["malformed_sibling_service_unhashable"]["timeline"][-1] == "get_agent_services"
    assert api["caller_timestamp_account_serialization"]["timeline"][-1] == "list_services"
    loader = {row["input"]["name"]: row for row in result["loader_rows"]}
    assert [svc["name"] for svc in loader["yaml_selection_and_filename_order"]["steps"][0]["services"]] == [
        "z-hidden",
        "a-last",
    ]
    for name in ["duplicate_rejects_prefix_then_recovery", "malformed_candidate_retains_previous"]:
        assert loader[name]["steps"][1]["error"]["class"] == "ServiceRegistryError"
        assert loader[name]["steps"][1]["services"] == loader[name]["steps"][0]["services"]
    rollback = loader["consumer_rollback_and_no_unchanged_retry"]["steps"]
    assert rollback[1]["callbacks"] == [["rejected-long-name"], ["old"]]
    assert rollback[2]["changed"] is False and rollback[2]["callbacks"] == []
    for name in ["missing_required_builtin", "both_sources_are_files"]:
        assert loader[name]["steps"][0]["audit"] == []
    lifecycle = result["lifecycle_rows"][0]["steps"]
    assert lifecycle[0]["projection"] == {} and lifecycle[0]["services"] is None
    assert lifecycle[0]["result"]["status"] == 200
    assert lifecycle[2]["projection"] == lifecycle[1]["projection"]
    assert list(lifecycle[3]["projection"]["alice"]) == ["alpha"]
    assert lifecycle[4]["projection"]["alice"]["alpha"]["token"] == "owned-after"
    assert lifecycle[4]["projection"]["alice"]["alpha"]["host"] == ""
    expected_types = [
        "ValueError",
        "UnicodeDecodeError",
        "IsADirectoryError",
        "FileNotFoundError",
        "KeyError",
        "AttributeError",
        "ValueError",
        "ValueError",
        "ParserError",
        "TypeError",
    ]
    first, rejected = result["diagnostic_rows"]
    assert first["last_errors"] == rejected["last_errors"]
    assert first["error"] == rejected["error"]
    assert [attempt["event"] for attempt in first["attempts"]] == [attempt["event"] for attempt in rejected["attempts"]]
    for row in result["diagnostic_rows"]:
        assert row["error"]["class"] == "ServiceRegistryError"
        assert row["services"] == row["previous_services"]
        assert [problem["error_type"] for problem in row["last_errors"]] == expected_types
        assert len(row["attempts"]) == 10
        assert row["has_changes_after_failure"] is False
        assert "builtin/35-missing.yaml" not in row["file_state_paths"]
        reads = [entry["path"] for entry in row["timeline"] if entry["kind"] == "read"]
        assert reads == ["builtin/00.yaml"] + [
            problem["path"].removeprefix("<owned>/") for problem in row["last_errors"]
        ]
        for problem, attempt in zip(row["last_errors"], row["attempts"]):
            event = attempt["event"]
            basename = Path(problem["path"]).name
            assert event["event"] == "ops.config_error" and event["kind"] == "ops"
            assert event["severity"] == "medium" and event["addon"] == "service-loader"
            assert event["summary"] == f"Service definition {basename} failed to load"
            assert list(event["details"]) == ["file", "error_type", "error"]
            assert event["details"]["file"] == basename and event["details"]["error_type"] == problem["error_type"]
            assert not any(key in event for key in ["agent", "request_id", "host", "decision", "approval"])
            assert "attribution" not in event["details"]
            assert attempt["services_at_submit"] == row["previous_services"]
            assert attempt["last_errors_at_submit"] == 0
            assert attempt["accepted"] is not row["input"]["audit_raises"]


def run():
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT), str(ROOT / "cli/src/safeyolo/mitm_addons")]
    logging.disable(logging.CRITICAL)
    events = []

    def deny_network(*_args, **_kwargs):
        raise AssertionError("network is outside this selected-source oracle")

    def capture(entry):
        entry = copy.deepcopy(entry)
        entry["ts"] = "<canonical timestamp>"
        events.append(entry)

    with tempfile.TemporaryDirectory(prefix="owned-service-catalog-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        (directory / "agent_token").write_text(TOKEN, encoding="utf-8")
        stack.enter_context(
            patch.dict(
                os.environ, {"SAFEYOLO_DATA_DIR": temporary, "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl")}
            )
        )
        stack.enter_context(patch.object(socket, "create_connection", side_effect=deny_network))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=deny_network))
        import yaml
        from mitmproxy import http
        from mitmproxy.test import tflow

        import pdp
        from safeyolo.core import audit_writer, service_loader
        from safeyolo.mitm_addons import agent_api, service_gateway
        from safeyolo.proxy_modes.unix_listener import UnixMode

        modules = SimpleNamespace(
            pdp=pdp,
            yaml=yaml,
            http=http,
            tflow=tflow,
            loader=service_loader,
            api=agent_api,
            gateway=service_gateway,
            audit_writer=audit_writer,
            UnixMode=UnixMode,
        )
        stack.enter_context(patch.object(audit_writer, "put_event", side_effect=capture))
        result = {
            "api_defaults": api_defaults(),
            "loader_rows": [
                observe_loader(spec, directory / ("loader-" + str(i)), modules, events)
                for i, spec in enumerate(loader_cases())
            ],
            "api_rows": [
                observe_api(spec, directory / ("api-" + str(i)), modules, events) for i, spec in enumerate(api_cases())
            ],
            "lifecycle_rows": [observe_lifecycle(directory / "lifecycle", modules)],
            "diagnostic_rows": [
                observe_diagnostics(spec, directory / ("diagnostics-" + str(i)), modules)
                for i, spec in enumerate(diagnostic_cases())
            ],
            "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS},
        }
        assert not (directory / "unused-audit.jsonl").exists()
        check_contract(result)
    assert not directory.exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = args.output or Path(__file__).with_suffix(".json")
    rendered = json.dumps(run(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert output.read_text(encoding="utf-8") == rendered, "source fixture drift"
    else:
        output.write_text(rendered, encoding="utf-8")
    print(
        "service catalog: 8 strict-loader workflows, 20 actual API requests, 1 configure workflow, 2 diagnostic workflows passed"
    )


if __name__ == "__main__":
    main()
