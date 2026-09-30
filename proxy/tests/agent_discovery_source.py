"""Actual ServiceDiscovery and authenticated AgentAPI with owned map inputs.

Only temporary JSON files, supplied clocks, synthetic tokens and the final
canonical put_event seam are used. No proxy, socket traffic or operational map
is accessed. Discovery groups are explicitly unordered because source uses set
iteration. Stats, response bytes and map insertion order remain exact.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import tempfile
from contextlib import ExitStack, chdir
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
ALICE = {"alice": {"ip": "192.0.2.10", "started": "synthetic-start"}}
BOTH = {**ALICE, "bob": {"ip": "192.0.2.11"}}


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def op(hook, **values):
    return {"hook": hook, "now": 100.0, **values}


def write(data, mtime=1, **values):
    return op("write", data=data, mtime=mtime, **values)


def case(name, *steps, dependency=True):
    return {"name": name, "dependency": dependency, "steps": list(steps)}


def cases():
    configure = op("configure", path="map.json")
    load = [write(ALICE), configure]
    return [
        case("unconfigured_and_missing", op("get_agents"), op("get_stats"), configure,
             op("get_agents"), op("get_stats")),
        case("zero_mtime_and_empty_map", write(ALICE, 0), configure, op("get_agents"),
             write(ALICE), op("get_agents"), write({}, 2), op("get_stats")),
        case("mtime_is_only_cache_key", *load, write(BOTH, 1), op("get_agents"),
             write(BOTH, 2), op("get_agents"), write(ALICE, 1), op("get_stats")),
        case("duplicate_ip_and_no_ip_entries", write({
            "first": {"ip": "192.0.2.20"}, "last": {"ip": "192.0.2.20"},
            "absent": {"started": "ignored"}, "null": {"ip": None}, "empty": {"ip": ""}}),
             configure, op("lookup", ip="192.0.2.20"), op("lookup", ip="192.0.2.99"), op("get_stats")),
        case("last_seen_survives_removal_and_readdition", op("request", agent="alice", now=90.0), *load,
             op("get_agents", now=91.0),
             op("request", agent="alice", now=100.25), op("get_agents", now=99.0),
             write({}, 2), op("get_stats", now=200.0), write(ALICE, 3), op("get_agents", now=300.0)),
        case("missing_file_retains_and_empty_config_retains", *load, op("delete_file"),
             op("get_agents"), op("configure", path=""), op("get_stats")),
        case("path_switch_same_mtime_retains", *load, write(BOTH, 1, path="other.json"),
             op("configure", path="other.json"), op("get_stats"),
             write(BOTH, 2, path="other.json"), op("get_stats")),
        case("malformed_json_retried_without_publication", *load,
             op("write", text="{", mtime=2), op("get_agents"), op("get_stats"),
             write(BOTH, 2), op("get_agents")),
        case("shape_errors_precede_publication", *load, write([], 2), op("get_agents"),
             write({"bad": 42}, 3), op("get_stats"), write({"bad": {"ip": [1]}}, 4),
             op("get_agents"), write(BOTH, 5), op("get_agents")),
        case("read_errors_retain_old_snapshot", *load, write(BOTH, 2),
             op("get_agents", read_error=True), op("write", hex="ff", mtime=3),
             op("get_agents"), write(BOTH, 4), op("get_agents")),
        case("audit_oserror_swallowed_after_publication", *load, write(BOTH, 2),
             op("get_agents", audit_error="OSError"), op("get_stats")),
        case("audit_runtimeerror_escapes_after_publication", *load, write(BOTH, 2),
             op("get_agents", audit_error="RuntimeError"), op("get_agents")),
        case("uds_identity_swallows_reload_audit_error", write(ALICE), configure,
             write(BOTH, 2), op("request", agent="bob", ip="192.0.2.11", audit_error="RuntimeError"),
             op("get_agents", now=110.0)),
        case("falsy_typed_ips_and_numeric_key_collision", write({
            "list": {"ip": []}, "object": {"ip": {}}, "false": {"ip": False},
            "zero": {"ip": 0}, "integer": {"ip": 1}, "boolean": {"ip": True}}),
             configure, op("get_stats")),
        case("nonfinite_and_large_scalar_ip", write({"nan": {"ip": float("nan")},
             "infinite": {"ip": float("inf")}, "large": {"ip": 2**80}}), configure, op("get_agents"), op("api")),
        case("global_api_ignores_caller_filter", *load, write(BOTH, 2), op("get_agents"),
             op("api", agent="alice"), op("api", agent="bob", ip="192.0.2.11", path="/agents/?agent=alice"),
             op("api", agent=None, ip="192.0.2.99", path="/agents?agent=bob", forged_agent="alice")),
        case("api_before_discovery_reports_previous_seen", *load,
             op("request", agent="alice", now=100.25),
             op("api_then_request", agent="alice", now=120.0), op("get_agents", now=121.0)),
        case("api_missing_dependency", op("api"), dependency=False),
        case("api_auth_and_method_order", *load, op("api", auth="missing"), op("api", auth="wrong"),
             op("api", auth="missing", method="POST"), op("api", auth="missing", method="PUT")),
        case("api_maps_reached_source_errors", *load, write([], 2), op("api"),
             op("write", hex="ff", mtime=3), op("api"), write(BOTH, 4),
             op("api", audit_error="RuntimeError"), op("api")),
    ]


def state(discovery):
    return {"map_path": discovery._map_path, "map_mtime": discovery._map_mtime,
            "agent_map": discovery._agent_map,
            "ip_to_name": [[ip, name] for ip, name in discovery._ip_to_name.items()],
            "last_seen": discovery._last_seen.copy()}


def normalize_timeline(timeline):
    """Only adjacent discovery events form an unordered source set group."""
    output = []
    for item in timeline:
        if isinstance(item, dict) and "discovered" in item:
            if not output or not isinstance(output[-1], dict) or "discovered_unordered" not in output[-1]:
                output.append({"discovered_unordered": []})
            output[-1]["discovered_unordered"].append(item["discovered"])
            output[-1]["discovered_unordered"].sort()
        else:
            output.append(item)
    return output


def make_flow(spec, token, modules):
    agent_api, _, _, _, _, _, tflow, unix_mode = modules
    flow = tflow.tflow(resp=False)
    flow.client_conn.peername = (spec.get("ip", "192.0.2.10"), 12345)
    agent = spec.get("agent", "alice")
    if agent is not None:
        flow.client_conn.proxy_mode = unix_mode.parse(f"unix:/tmp/{flow.client_conn.peername[0]}_{agent}/proxy.sock")
    flow.request.url = "http://" + agent_api.AGENT_API_HOST + spec.get("path", "/agents")
    flow.request.method = spec.get("method", "GET")
    auth = spec.get("auth", "valid")
    if auth != "missing":
        flow.request.headers["authorization"] = "Bearer " + (token if auth == "valid" else "synthetic-wrong")
    if spec.get("forged_agent"):
        flow.metadata["agent"] = spec["forged_agent"]
        flow.request.headers["X-SafeYolo-Agent"] = spec["forged_agent"]
    return flow


def observe(spec, directory, token, modules):
    agent_api, discovery_module, audit_writer, audit_schema, utils, taddons, _, _ = modules
    directory.mkdir()
    discovery, api = discovery_module.ServiceDiscovery(), agent_api.AgentAPI()
    steps, attempts = [], []
    addons = (api, discovery) if spec["dependency"] else (api,)
    with chdir(directory), taddons.context(*addons) as context:
        for index, operation in enumerate(spec["steps"]):
            timeline = []
            hook = operation["hook"]
            result = {"hook": hook, "error_class": None}

            def clock(operation=operation, timeline=timeline):
                timeline.append({"time": operation["now"]})
                return operation["now"]

            def put_event(entry, operation=operation, index=index, timeline=timeline):
                if entry["event"] == "agent.discovered":
                    timeline.append({"discovered": entry.get("agent")})
                else:
                    timeline.append("put_event:" + entry["event"])
                error = operation.get("audit_error")
                attempts.append({"step": index, "event": entry, "accepted": error is None,
                                 "state_at_submit": state(discovery)})
                if error:
                    raise {"RuntimeError": RuntimeError, "OSError": OSError}[error]("owned submission failure")

            read_text = Path.read_text

            def owned_read(path, *args, operation=operation, timeline=timeline, read_text=read_text, **kwargs):
                assert path.resolve().is_relative_to(directory.parent), "only owned temporary reads"
                if str(path) == discovery._map_path:
                    timeline.append("read_map")
                    if operation.get("read_error"):
                        raise OSError("owned map read failure")
                return read_text(path, *args, **kwargs)

            with ExitStack() as stack:
                stack.enter_context(patch.object(discovery_module, "time", SimpleNamespace(time=clock)))
                stack.enter_context(patch.object(audit_writer, "put_event", side_effect=put_event))
                stack.enter_context(patch.object(audit_schema, "datetime", FixedDatetime))
                stack.enter_context(patch.object(utils, "datetime", FixedDatetime))
                stack.enter_context(patch.object(Path, "read_text", owned_read))
                try:
                    if hook == "write":
                        path = Path(operation.get("path", "map.json"))
                        assert path.parent == Path(".")
                        content = bytes.fromhex(operation["hex"]) if "hex" in operation else operation.get(
                            "text", json.dumps(operation.get("data"))).encode()
                        path.write_bytes(content)
                        os.utime(path, (operation["mtime"], operation["mtime"]))
                    elif hook == "delete_file":
                        Path("map.json").unlink()
                    elif hook == "configure":
                        # Actual configured option and configure hook, using the
                        # standard source addon context; no replacement loader.
                        context.configure(discovery, agent_map_file=operation["path"])
                    elif hook in {"get_agents", "get_stats"}:
                        result["result_json"] = json.dumps(getattr(discovery, hook)())
                    elif hook == "lookup":
                        result["lookup"] = discovery.get_client_for_ip(operation["ip"])
                    elif hook in {"request", "api", "api_then_request"}:
                        flow = make_flow(operation, token, modules)
                        if hook != "request":
                            asyncio.run(api.request(flow))
                            result["api"] = {"status": flow.response.status_code,
                                "body_text": flow.response.content.decode(),
                                "headers": [list(pair) for pair in flow.response.headers.items(multi=True)],
                                "blocked_by": flow.metadata.get("blocked_by"),
                                "api_response": flow.metadata.get(agent_api.AGENT_API_RESPONSE_METADATA)}
                            if hook == "api_then_request":
                                timeline.append("api_response_ready")
                        if hook != "api":
                            discovery.request(flow)
                            result["identity"] = {"agent": flow.metadata.get("agent"),
                                "snapshot": list(flow.metadata.get("_safeyolo_identity_snapshot", []))}
                    else:
                        raise AssertionError("unknown operation")
                except (AttributeError, TypeError, UnicodeDecodeError, RuntimeError, OSError, ValueError) as error:
                    result["error_class"] = type(error).__name__
            result["timeline"] = normalize_timeline(timeline)
            result["state_after"] = state(discovery)
            # Freeze referenced dicts before the next source mutation.
            steps.append(json.loads(json.dumps(result)))
    # Set iteration is not a native compatibility ordering requirement. The
    # source event contents and state-at-submit remain exact within each group.
    attempts.sort(key=lambda item: (item["step"], item["event"].get("agent", "")))
    return {"input": spec, "steps": steps, "attempts": attempts}


def check_contract(rows):
    rows = {row["input"]["name"]: row for row in rows}
    assert len(rows) == 20
    def final(name):
        return rows[name]["steps"][-1]
    assert json.loads(final("unconfigured_and_missing")["result_json"])["agents_seen"] == 0
    assert final("mtime_is_only_cache_key")["state_after"]["agent_map"] == ALICE
    duplicate = json.loads(final("duplicate_ip_and_no_ip_entries")["result_json"])
    assert duplicate["known_ips"] == 1 and duplicate["agents_seen"] == 5
    assert rows["duplicate_ip_and_no_ip_entries"]["steps"][2]["lookup"] == "last"
    assert json.loads(rows["zero_mtime_and_empty_map"]["steps"][2]["result_json"]) == {"agents": {}, "count": 0}
    assert rows["mtime_is_only_cache_key"]["steps"][3]["state_after"]["agent_map"] == ALICE
    assert final("missing_file_retains_and_empty_config_retains")["state_after"]["agent_map"] == ALICE
    assert rows["path_switch_same_mtime_retains"]["steps"][4]["state_after"]["agent_map"] == ALICE
    for index in (3, 4):
        step = rows["malformed_json_retried_without_publication"]["steps"][index]
        assert step["timeline"] == [{"time": 100.0}, "read_map"]
        assert step["state_after"]["map_mtime"] == 1.0
    shape = rows["shape_errors_precede_publication"]["steps"]
    assert [shape[i]["error_class"] for i in (3, 5, 7)] == ["AttributeError", "AttributeError", "TypeError"]
    assert all(shape[i]["state_after"]["agent_map"] == ALICE for i in (3, 5, 7))
    collision = rows["falsy_typed_ips_and_numeric_key_collision"]
    assert collision["steps"][-1]["state_after"]["ip_to_name"] == [[1, "boolean"]]
    assert collision["attempts"][0]["event"]["details"] == {"ip": 1}
    for attempt in rows["nonfinite_and_large_scalar_ip"]["attempts"]:
        if attempt["event"]["agent"] in {"nan", "infinite"}:
            assert attempt["event"]["details"] == {"ip": None}
    stale = json.loads(final("last_seen_survives_removal_and_readdition")["result_json"])
    assert rows["last_seen_survives_removal_and_readdition"]["steps"][0]["state_after"]["last_seen"] == {"alice": 90.0}
    assert stale["agents"]["alice"] == {"ip": "192.0.2.10", "last_seen": 100.25, "idle_seconds": 199.8}
    for name, expected_error in [("audit_oserror_swallowed_after_publication", None),
                                  ("audit_runtimeerror_escapes_after_publication", "RuntimeError")]:
        row = rows[name]
        assert row["steps"][3]["error_class"] == expected_error
        assert row["steps"][3]["state_after"]["agent_map"] == BOTH
        assert row["steps"][4]["timeline"] == [{"time": 100.0}]
    swallowed = rows["uds_identity_swallows_reload_audit_error"]["steps"][3]
    assert swallowed["error_class"] is None and swallowed["state_after"]["last_seen"] == {"bob": 100.0}
    reports = [step["api"]["body_text"] for step in rows["global_api_ignores_caller_filter"]["steps"] if "api" in step]
    assert len(reports) == 3 and len(set(reports)) == 1
    ordered = rows["api_before_discovery_reports_previous_seen"]["steps"][3]
    assert json.loads(ordered["api"]["body_text"])["agents"]["alice"]["last_seen"] == 100.25
    assert ordered["state_after"]["last_seen"] == {"alice": 120.0}
    assert final("api_missing_dependency")["api"]["status"] == 503
    auth = [step["api"]["status"] for step in rows["api_auth_and_method_order"]["steps"] if "api" in step]
    assert auth == [401, 401, 405, 405]
    failed = [step["api"]["status"] for step in rows["api_maps_reached_source_errors"]["steps"] if "api" in step]
    assert failed == [500, 500, 500, 200]


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="agent-discovery-source-") as temporary:
        directory = Path(temporary)
        token = secrets.token_hex(32)
        (directory / "agent_token").write_text(token)
        with patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": str(directory),
                "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl"),
                "MITMPROXY_LOG_PATH": str(directory / "unused-diagnostic.log")}):
            from mitmproxy.test import taddons, tflow

            from safeyolo.core import audit_schema, audit_writer, utils
            from safeyolo.mitm_addons import agent_api, service_discovery
            from safeyolo.proxy_modes.unix_listener import UnixMode

            modules = agent_api, service_discovery, audit_writer, audit_schema, utils, taddons, tflow, UnixMode
            network_attempts = []
            def no_network(*_args, **_kwargs):
                network_attempts.append(True)
                raise AssertionError("no network in source discovery oracle")
            with (patch.object(socket, "getaddrinfo", side_effect=no_network),
                  patch.object(socket, "create_connection", side_effect=no_network)):
                rows = [observe(spec, directory / str(index), token, modules) for index, spec in enumerate(cases())]
            assert not network_attempts
            check_contract(rows)
            encoded = json.dumps(rows)
            assert token not in encoded
    paths = ["cli/src/safeyolo/mitm_addons/service_discovery.py", "cli/src/safeyolo/mitm_addons/agent_api.py",
             "cli/src/safeyolo/core/identity.py", "cli/src/safeyolo/core/audit_schema.py", "cli/src/safeyolo/core/utils.py",
             "cli/src/safeyolo/proxy_modes/unix_listener.py", "cli/src/safeyolo/core/flow_cache.py",
             "pdp/tokens.py", "tests/test_service_discovery_file.py", "tests/test_agent_api.py"]
    return {"discovery_events": "unordered within each step (source set iteration)",
            "rows": rows, "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = json.dumps(run(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert result == args.check.read_text(), "source oracle changed"
    if args.output:
        args.output.write_text(result)
    print(json.dumps({"source_discovery_rows": 20}))
