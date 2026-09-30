"""Actual decorated CircuitBreaker/TestContext hooks with owned source state.

No transport or full addon chain. Only measured trace duration is normalized;
wall/monotonic and canonical audit clocks are explicit deterministic inputs.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import logging
import os
import socket
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
RID = "req-" + "a" * 32
HOST = "owned.invalid"
CONTEXT = {"run": "owned", "agent": "alice", "test": "T1"}
HEADER = "run=owned;agent=alice;test=T1"
CLOCK = {"now": 100.0}
TRACE_ENV = {
    "SAFEYOLO_TRACE_TTL_S": "300",
    "SAFEYOLO_TRACE_GLOBAL_MAX": "1000",
    "SAFEYOLO_TRACE_PER_AGENT_MAX": "200",
    "SAFEYOLO_TRACE_STEPS_MAX": "128",
    "SAFEYOLO_TRACE_DETAILS_MAX_BYTES": "4096",
}
CIRCUIT_SETTINGS = {
    "failure_threshold": 2,
    "success_threshold": 2,
    "timeout_seconds": 10,
    "half_open_max_requests": 3,
    "use_exponential_backoff": False,
}


def clock():
    return CLOCK["now"]


class FixedDate(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2000, 1, 2, 3, 4, 5, tzinfo=UTC)


def hook(name="request", **values):
    return {"hook": name, "now": 100.0 if name == "request" else 101.0, **values}


def circuit(name, *hooks, state=None, sensor=None, flow=None, **options):
    return {
        "component": "circuit",
        "name": name,
        "sensor": {
            "policy_hash": "owned",
            "addons": {"circuit_breaker": CIRCUIT_SETTINGS if sensor is None else sensor},
        },
        "options": {"enabled": True, "policy_enabled": True, **options},
        "initial_state": state or {},
        "flow": flow or {},
        "hooks": list(hooks),
    }


def context(name, *hooks, target=True, flow=None, **options):
    return {
        "component": "context",
        "name": name,
        "sensor": {
            "policy_hash": "owned",
            "addons": {
                "test_context": {
                    "target_hosts": [HOST] if target else [],
                    "inject_declared": options.get("declared", False),
                }
            },
        },
        "options": {"block": True, **options},
        "initial_state": {},
        "flow": flow or {},
        "hooks": list(hooks),
    }


def cases():
    closed_failure = {"state": "closed", "failure_count": 1, "failure_streak": 0}
    opened = {"state": "open", "failure_count": 2, "opened_at": 95.0, "failure_streak": 0}
    half = {"state": "half_open", "failure_count": 2, "success_count": 1, "failure_streak": 1}
    rows = [
        circuit(
            "request_disabled_first",
            hook(),
            hook("response"),
            enabled=False,
            policy_enabled=False,
            flow={"response_status": 418},
        ),
        circuit("request_prior_response", hook(), policy_enabled=False, flow={"response_status": 418}),
        circuit("request_policy_disabled", hook(), policy_enabled=False),
        circuit("request_excluded", hook(), hook("response", response_status=500), flow={"host": "localhost"}),
        circuit("request_closed_then_status_no_action", hook(), hook("response", response_status=404)),
        circuit("request_half_open_allowed", hook(), state=half),
        circuit("request_open_block_then_prior_response", hook(), hook("response"), state=opened),
        circuit("request_deny_submission_error", hook(audit_error=True), state=opened),
        circuit("request_half_open_transition_error", hook(audit_error=True), state={**opened, "opened_at": 0.0}),
        circuit("request_record_failure_is_observational", hook(record_error=True)),
        circuit(
            "response_reload_error_precedes_prior_block",
            hook("response"),
            sensor=42,
            flow={"response_status": 403, "blocked_by": "network-guard"},
        ),
        circuit("response_absent", hook("response")),
        circuit("response_failure_429_below_threshold", hook("response", response_status=429)),
        circuit("response_failure_500_opens", hook("response", response_status=500), state=closed_failure),
        circuit(
            "response_open_submission_error",
            hook("response", response_status=500, audit_error=True),
            state=closed_failure,
        ),
        circuit("response_success_closes", hook("response", response_status=200), state=half),
        circuit("response_close_submission_error", hook("response", response_status=200, audit_error=True), state=half),
        circuit(
            "response_failure_numeric_error",
            hook("response", response_status=500),
            sensor={**CIRCUIT_SETTINGS, "failure_threshold": "invalid"},
        ),
        context("request_prior_response", hook(), flow={"response_status": 418, "context_header": HEADER}),
        context("request_nontarget", hook(), target=False),
        context(
            "request_header_then_response",
            hook(),
            hook("response", response_status=200),
            flow={"context_header": HEADER},
        ),
        context("request_declared_then_response_absent", hook(), hook("response", response_status=None), declared=True),
        context("request_missing_block_then_not_applicable", hook(), hook("response")),
        context("request_malformed_warn", hook(), block=False, flow={"context_header": "invalid"}),
        context("request_optional_malformed_warn", hook(), target=False, flow={"context_header": "invalid"}),
        context(
            "request_warn_submission_error", hook(audit_error=True), hook("response", response_status=200), block=False
        ),
        context(
            "request_apply_submission_error_then_response",
            hook(audit_error=True),
            hook("response", response_status=200),
            flow={"context_header": HEADER},
        ),
        context(
            "request_decode_error_then_response",
            hook(),
            hook("response", response_status=200),
            flow={"context_header": HEADER, "request_body": "invalid_gzip"},
        ),
        context("request_config_type_error", hook(sensor_targets=42)),
        context(
            "response_applied_gzip",
            hook("response", response_status=200, response_body="gzip"),
            flow={"applied_context": True},
        ),
        context(
            "response_decode_error",
            hook("response", response_status=200, response_body="invalid_gzip"),
            flow={"applied_context": True},
        ),
        context(
            "response_submission_error",
            hook("response", response_status=200, audit_error=True),
            flow={"applied_context": True},
        ),
        context(
            "request_record_failure_is_observational",
            hook(record_error=True),
            hook("response", response_status=200),
            flow={"context_header": HEADER},
        ),
        context("request_untraced_still_runs", hook(), flow={"context_header": HEADER, "traced": False}),
        context("request_malformed_block", hook(), flow={"context_header": "invalid"}),
        context("request_optional_valid", hook(), target=False, flow={"context_header": HEADER}),
    ]
    return rows


def body(recipe, message):
    value = b"owned body"
    if recipe == "gzip":
        value = gzip.compress(value, mtime=0)
        message.headers["Content-Encoding"] = "gzip"
    elif recipe == "invalid_gzip":
        value = b"owned invalid gzip"
        message.headers["Content-Encoding"] = "gzip"
    message.raw_content = value
    message.headers["Content-Length"] = str(len(value))


def flow_snapshot(flow):
    # The decorator's private nanosecond timer is deliberately not a product
    # effect. Its presence/cleanup is asserted separately from elapsed value.
    metadata = {key: value for key, value in flow.metadata.items() if not key.startswith("_trace_hook_start:")}
    response = (
        None
        if flow.response is None
        else {
            "status": flow.response.status_code,
            "headers": list(flow.response.headers.items(multi=True)),
            "raw_body_hex": (flow.response.raw_content or b"").hex(),
        }
    )
    return copy.deepcopy(
        {
            "metadata": metadata,
            "request_headers": list(flow.request.headers.items(multi=True)),
            "request_raw_body_hex": (flow.request.raw_content or b"").hex(),
            "response": response,
        }
    )


def state_snapshot(addon, component):
    if component == "circuit":
        value = {
            "counters": {
                "checks": addon.checks_total,
                "opens": addon.opens_total,
                "half_opens": addon.half_opens_total,
                "recoveries": addon.recoveries_total,
            },
            "states": addon._state._states,
            "last_policy_hash": addon._last_policy_hash,
            "settings": {name: getattr(addon, name) for name in CIRCUIT_SETTINGS},
        }
    else:
        value = {
            "counters": asdict(addon.stats),
            "declared_injections": addon._declared_injections_total,
            "declarations": addon._declarations,
            "target_hosts": addon._target_hosts,
            "last_policy_hash": addon._last_policy_hash,
        }
    return copy.deepcopy(value)


def trace_step(step):
    result = asdict(step)
    if result["duration_us"] is not None:
        assert type(result["duration_us"]) is int and result["duration_us"] >= 0
        result["duration_us"] = "<measured>"
    return result


def trace_snapshot(store):
    return [
        {
            "request_id": rid,
            "agent_id": record.agent_id,
            "created_at": record.created_at,
            "truncated": record.truncated,
            "steps": [trace_step(step) for step in record.steps],
        }
        for rid, record in store._records.items()
    ]


def observe(spec, modules):
    (
        trace,
        base,
        audit_writer,
        audit_schema,
        utils,
        config_cache,
        circuit_module,
        context_module,
        taddons,
        tflow,
        http,
        ctx,
        unix_mode,
    ) = modules
    spec = copy.deepcopy(spec)
    component = spec["component"]
    addon = circuit_module.CircuitBreaker() if component == "circuit" else context_module.TestContext()
    store = trace.TraceStore()
    sensor = copy.deepcopy(spec["sensor"])
    flow = tflow.tflow(resp=False)
    flow.client_conn.id = "owned-connection"
    flow.client_conn.peername = ("192.0.2.10", 12345)
    flow.client_conn.proxy_mode = unix_mode.parse("unix:/owned/192.0.2.10_alice/proxy.sock")
    flow.request = http.Request.make("POST", "http://" + spec["flow"].get("host", HOST) + ":8123/path?owned=1", b"")
    body(spec["flow"].get("request_body", "plain"), flow.request)
    flow.metadata.clear()
    flow.metadata.update(trace=spec["flow"].get("traced", True), request_id=RID, agent="alice", start_time=99.0)
    if "context_header" in spec["flow"]:
        flow.request.headers[context_module.TEST_CONTEXT_HEADER] = spec["flow"]["context_header"]
    if spec["flow"].get("applied_context"):
        flow.metadata.update(test_context=copy.deepcopy(CONTEXT), test_context_source="header", test_agent_match=True)
    if spec["flow"].get("blocked_by"):
        flow.metadata["blocked_by"] = spec["flow"]["blocked_by"]
    if spec["flow"].get("response_status") is not None:
        flow.response = http.Response.make(spec["flow"]["response_status"], b"owned prior")
    timeline, outputs = [], []
    current = {"operation": {}}
    real_append = store.append_step
    real_config_read = config_cache.get_or_raise

    def effect():
        return {"flow": flow_snapshot(flow), "state": state_snapshot(addon, component)}

    def submit(entry):
        failed = current["operation"].get("audit_error", False)
        timeline.append({"kind": "audit", "event": copy.deepcopy(entry), "accepted": not failed, **effect()})
        if failed:
            raise RuntimeError("owned synchronous audit submission failure")

    def append_observed(rid, agent, step):
        failed = current["operation"].get("record_error", False)
        timeline.append(
            {
                "kind": "trace",
                "request_id": rid,
                "agent": agent,
                "step": trace_step(step),
                "accepted": not failed,
                **effect(),
            }
        )
        if failed:
            raise RuntimeError("owned ordinary trace append failure")
        return real_append(rid, agent, step)

    def config_read():
        timeline.append({"kind": "config_read", **effect()})
        return real_config_read()

    def policy_enabled(name, domain, agent):
        result = spec["options"].get("policy_enabled", True)
        timeline.append(
            {"kind": "policy_enabled", "addon": name, "domain": domain, "agent": agent, "enabled": result, **effect()}
        )
        return result

    fake_time = SimpleNamespace(time=clock, monotonic=clock, perf_counter_ns=time.perf_counter_ns)
    with (
        taddons.context(addon),
        patch.object(trace, "_store", store),
        patch.object(trace, "time", fake_time),
        patch.object(circuit_module, "time", fake_time),
        patch.object(context_module, "time", fake_time),
        patch.object(audit_schema, "datetime", FixedDate),
        patch.object(utils, "datetime", FixedDate),
        patch.object(audit_writer, "put_event", side_effect=submit),
        patch.object(store, "append_step", side_effect=append_observed),
        patch.object(config_cache._cache, "_config", sensor),
        patch.object(config_cache._cache, "_ttl_s", None),
        patch.object(config_cache, "get_or_raise", side_effect=config_read),
        patch.object(base, "get_policy_client", return_value=SimpleNamespace(is_addon_enabled=policy_enabled)),
    ):
        CLOCK["now"] = 100.0
        if component == "circuit":
            ctx.options.add_option("circuit_breaker_enabled", bool, True, "owned source option")
            ctx.options.update(circuit_state_file="", circuit_breaker_enabled=spec["options"]["enabled"])
            if spec["initial_state"]:
                addon._state.set(HOST, copy.deepcopy(spec["initial_state"]))
        else:
            ctx.options.update(test_context_block=spec["options"]["block"])
            if spec["options"].get("declared"):
                addon.set_declaration("192.0.2.10", "alice", CONTEXT, 20)
        initial = effect()
        timeline.clear()
        for operation in spec["hooks"]:
            current["operation"] = operation
            CLOCK["now"] = operation["now"]
            if "sensor_targets" in operation:
                sensor["addons"]["test_context"]["target_hosts"] = operation["sensor_targets"]
            if "response_status" in operation:
                status = operation["response_status"]
                flow.response = None if status is None else http.Response.make(status, b"")
                if flow.response:
                    body(operation.get("response_body", "plain"), flow.response)
            timeline.clear()
            error = None
            try:
                getattr(addon, operation["hook"])(flow)
            except (RuntimeError, ValueError, TypeError, AttributeError, OverflowError, ZeroDivisionError) as exception:
                error = type(exception).__name__
            assert not any(key.startswith("_trace_hook_start:") for key in flow.metadata)
            outputs.append(
                {
                    "hook": operation["hook"],
                    "error_class": error,
                    "trace": trace_snapshot(store),
                    **effect(),
                    "timeline": copy.deepcopy(timeline),
                }
            )
        assert not getattr(getattr(addon, "_state", None), "_worker", None)
    return {"input": spec, "initial": initial, "hooks": outputs}


def check_contract(rows):
    by_name = {(row["input"]["component"], row["input"]["name"]): row for row in rows}

    def output(component, name, index=0):
        return by_name[component, name]["hooks"][index]

    def steps(value):
        return [entry["step"] for entry in value["timeline"] if entry["kind"] == "trace"]

    def kinds(value):
        return [entry["kind"] for entry in value["timeline"] if entry["kind"] in {"audit", "trace"}]

    for name, reason in [
        ("request_disabled_first", "addon_disabled"),
        ("request_prior_response", "prior_response"),
        ("request_policy_disabled", "policy_disabled"),
    ]:
        result = output("circuit", name)
        assert steps(result)[0]["reason"] == reason and steps(result)[0]["duration_us"] is None
        assert result["state"]["counters"]["checks"] == 0
    blocked = output("circuit", "request_open_block_then_prior_response")
    assert kinds(blocked) == ["audit", "trace"] and blocked["flow"]["response"]["status"] == 503
    assert steps(blocked)[0]["details"] == {"status": 503}
    assert steps(output("circuit", "request_open_block_then_prior_response", 1))[-1]["outcome"] == "prior_block"
    for name in [
        "request_deny_submission_error",
        "request_half_open_transition_error",
        "response_open_submission_error",
        "response_close_submission_error",
    ]:
        result = output("circuit", name)
        assert result["error_class"] == "RuntimeError" and kinds(result) == ["audit", "trace"]
        assert steps(result)[0]["state"] == "error" and steps(result)[0]["outcome"] is None
    assert output("circuit", "request_deny_submission_error")["flow"]["response"] is None
    assert output("circuit", "request_half_open_transition_error")["state"]["states"][HOST]["state"] == "half_open"
    opening = output("circuit", "response_open_submission_error")
    assert opening["state"]["counters"]["opens"] == 1 and opening["state"]["states"][HOST]["state"] == "closed"
    assert output("circuit", "response_absent")["trace"] == []
    assert output("circuit", "response_reload_error_precedes_prior_block")["error_class"] == "AttributeError"
    assert output("circuit", "response_failure_numeric_error")["error_class"] == "TypeError"
    for component in ("circuit", "context"):
        result = output(component, "request_record_failure_is_observational")
        assert result["error_class"] is None and result["trace"] == []
        assert [entry["accepted"] for entry in result["timeline"] if entry["kind"] == "trace"] == [False]
    for name in ["request_nontarget"]:
        result = output("context", name)
        assert result["state"]["counters"]["checks"] == 0 and steps(result)[0]["outcome"] == "not_target_host"
        assert not any(key.lower() == "x-safeyolo-test-context" for key, _ in result["flow"]["request_headers"])
    for name in ["request_header_then_response", "request_declared_then_response_absent"]:
        result = output("context", name)
        assert result["state"]["counters"]["allowed"] == 1 and kinds(result) == ["audit", "trace"]
        assert steps(result)[0]["outcome"] == "allowed"
    for name, error in [
        ("request_apply_submission_error_then_response", "RuntimeError"),
        ("request_decode_error_then_response", "ValueError"),
    ]:
        result = output("context", name)
        assert result["error_class"] == error and result["state"]["counters"]["allowed"] == 0
        assert result["flow"]["metadata"]["test_context"] == CONTEXT
        assert steps(result)[0]["state"] == "error"
        later = output("context", name, 1)
        assert later["error_class"] is None and steps(later)[0]["outcome"] == "response_recorded"
    blocked = output("context", "request_missing_block_then_not_applicable")
    assert blocked["state"]["counters"]["blocked"] == 1 and blocked["flow"]["response"]["status"] == 428
    assert kinds(blocked) == ["audit", "trace"]
    assert steps(output("context", "request_missing_block_then_not_applicable", 1))[0]["outcome"] == "not_applicable"
    assert output("context", "request_untraced_still_runs")["trace"] == []
    assert kinds(output("context", "request_untraced_still_runs")) == ["audit"]
    for name, error in [("response_decode_error", "ValueError"), ("response_submission_error", "RuntimeError")]:
        result = output("context", name)
        assert result["error_class"] == error and steps(result)[0]["state"] == "error"
    assert output("context", "request_config_type_error")["error_class"] == "TypeError"


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    attempts = []

    def no_network(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("source selected hooks must not access network")

    with tempfile.TemporaryDirectory(prefix="security-trace-source-") as temporary:
        directory = Path(temporary)
        with (
            patch.dict(
                os.environ,
                {
                    **TRACE_ENV,
                    "SAFEYOLO_DATA_DIR": temporary,
                    "SAFEYOLO_LOG_PATH": str(directory / "unused-audit"),
                    "MITMPROXY_LOG_PATH": str(directory / "unused-log"),
                },
            ),
            patch.object(socket, "getaddrinfo", side_effect=no_network),
            patch.object(socket, "create_connection", side_effect=no_network),
        ):
            assert "safeyolo.core.trace" not in sys.modules
            with patch.object(time, "time", clock):
                from safeyolo.core import trace
            from mitmproxy import ctx, http
            from mitmproxy.test import taddons, tflow

            from safeyolo.core import audit_schema, audit_writer, base, config_cache, utils
            from safeyolo.mitm_addons import circuit_breaker, test_context
            from safeyolo.proxy_modes.unix_listener import UnixMode

            modules = (
                trace,
                base,
                audit_writer,
                audit_schema,
                utils,
                config_cache,
                circuit_breaker,
                test_context,
                taddons,
                tflow,
                http,
                ctx,
                UnixMode,
            )
            rows = [observe(spec, modules) for spec in cases()]
            check_contract(rows)
            assert list(directory.iterdir()) == []
    assert not attempts and not directory.exists()
    paths = [
        "cli/src/safeyolo/core/trace.py",
        "cli/src/safeyolo/core/base.py",
        "cli/src/safeyolo/core/utils.py",
        "cli/src/safeyolo/core/identity.py",
        "cli/src/safeyolo/core/audit_schema.py",
        "cli/src/safeyolo/core/config_cache.py",
        "cli/src/safeyolo/mitm_addons/circuit_breaker.py",
        "cli/src/safeyolo/mitm_addons/test_context.py",
        "cli/src/safeyolo/test_context_contract.py",
        "cli/src/safeyolo/proxy_modes/unix_listener.py",
    ]
    return {
        "rows": rows,
        "duration_normalization": "non-null duration_us -> <measured>; presence retained",
        "scope": "selected actual decorated source hooks; no production dispatch or transport claim",
        "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = json.dumps(run(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert args.check.read_text() == result, "source security trace changed"
    if args.output:
        args.output.write_text(result)
    print(json.dumps({"source_security_trace_rows": 36}))
