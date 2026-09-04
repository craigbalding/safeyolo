"""Assurance-boundary tests for structured traffic evidence."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy import http
from mitmproxy.test import tflow
from request_logger import RequestLogger

from pdp.client import PolicyClient
from safeyolo.core import utils
from safeyolo.proxy_modes.unix_listener import UnixMode

pytestmark = pytest.mark.assurance_boundary


def _flow(
    url: str = "https://api.example.com/v1/data",
    *,
    method: str = "GET",
    request_content: bytes = b"",
    status: int | None = 200,
    response_content: bytes = b"",
    agent: str | None = "agent-a",
):
    flow = tflow.tflow(resp=False)
    flow.request.method = method
    flow.request.url = url
    flow.request.content = request_content
    flow.client_conn.peername = ("192.0.2.10", 32100)
    if agent:
        flow.client_conn.proxy_mode = UnixMode.parse(
            f"unix:/tmp/192.0.2.10_{agent}/proxy.sock"
        )
    if status is not None:
        flow.response = http.Response.make(status, response_content)
    return flow


@pytest.fixture
def logger_with_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with patch.object(utils, "AUDIT_LOG_PATH", new=log_path):
        yield RequestLogger(), log_path


def _events(path: Path) -> list[dict]:
    from safeyolo.core.audit_writer import get_writer

    assert get_writer().wait_for_drain(timeout_s=3.0)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _policy(config: dict) -> PolicyClient:
    client = create_autospec(PolicyClient, instance=True, spec_set=True)
    client.get_sensor_config.return_value = config
    return client


def test_quiet_rule_parsing_and_matching_are_canonical_and_case_insensitive():
    addon = RequestLogger()
    addon._load_quiet_hosts_from_pdp(
        {
            "addons": {
                "request_logger": {
                    "quiet_hosts": {
                        "hosts": ["Exact.Example", "*.Telemetry.Example"],
                        "paths": {"API.Example": ["/health", "/metrics/*"]},
                    }
                }
            }
        }
    )

    assert addon._should_quiet("exact.example", "/anything") is True
    assert addon._should_quiet("APP.TELEMETRY.EXAMPLE", "/") is True
    assert addon._should_quiet("api.example", "/metrics/cpu") is True
    assert addon._should_quiet("telemetry.example.evil", "/") is False
    assert addon._should_quiet("api.example", "/v1/data") is False


@pytest.mark.parametrize(
    "config, message",
    [
        ({"addons": {"request_logger": {"quiet_hosts": {"hosts": "bad"}}}}, "hosts must be a list"),
        ({"addons": {"request_logger": {"quiet_hosts": {"paths": []}}}}, "paths must be a dict"),
        (
            {"addons": {"request_logger": {"quiet_hosts": {"paths": {"x": "bad"}}}}},
            "must be a list of path patterns",
        ),
    ],
)
def test_malformed_quiet_rules_fail_loudly(config: dict, message: str):
    with pytest.raises(ValueError, match=message):
        RequestLogger()._load_quiet_hosts_from_pdp(config)


def test_quiet_path_lists_are_copied_from_policy_input():
    addon = RequestLogger()
    paths = ["/health"]
    addon._load_quiet_hosts_from_pdp(
        {"addons": {"request_logger": {"quiet_hosts": {"paths": {"x": paths}}}}}
    )
    paths.append("/*")
    assert addon._should_quiet("x", "/private") is False


def test_request_writes_schema_valid_event_with_trusted_identity(logger_with_log):
    addon, path = logger_with_log
    flow = _flow(method="POST", request_content=b"hello")
    flow.metadata["request_id"] = "req-1"

    addon.request(flow)

    assert _events(path) == [
        {
            "schema_version": 1,
            "ts": _events(path)[0]["ts"],
            "event": "traffic.request",
            "kind": "traffic",
            "severity": "low",
            "summary": "POST api.example.com/v1/data",
            "request_id": "req-1",
            "agent": "agent-a",
            "evidence_owner": "agent-a",
            "trusted_transport_identity": "agent-a",
            "initiator": "unknown",
            "attribution_status": "resolved",
            "attribution_provenance": {
                "transport_source": "uds",
                "uds_agent": "agent-a",
            },
            "host": "api.example.com",
            "addon": "request-logger",
            "details": {
                "method": "POST",
                "path": "/v1/data",
                "size": 5,
                "client": "192.0.2.10",
            },
        }
    ]


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@api.example.com/v1/data",
        "https://api.example.com:8443/v1/data",
    ],
)
def test_canonical_host_excludes_userinfo_and_port(logger_with_log, url: str):
    addon, path = logger_with_log
    addon.request(_flow(url))
    event = _events(path)[0]
    assert event["host"] == "api.example.com"
    assert "secret" not in json.dumps(event)
    assert ":8443" not in json.dumps(event)


def test_untrusted_metadata_is_removed_from_audit_attribution(logger_with_log):
    addon, path = logger_with_log
    flow = _flow(agent=None)
    flow.metadata["agent"] = "spoofed-agent"
    addon.request(flow)
    event = _events(path)[0]
    assert "agent" not in event
    assert event["attribution_status"] == "unavailable"
    assert event["initiator"] == "unknown"
    assert event["attribution_provenance"] == {"reason": "no_trusted_identity"}
    assert "agent" not in flow.metadata
    assert flow.metadata["agent_identity_status"] == "unavailable"


def test_delegated_operator_traffic_keeps_transport_owner_but_not_agent_initiator(
    logger_with_log,
):
    addon, path = logger_with_log
    flow = _flow()
    flow.metadata["origin"] = "operator"

    addon.request(flow)

    event = _events(path)[0]
    assert event["agent"] == "agent-a"
    assert event["evidence_owner"] == "agent-a"
    assert event["trusted_transport_identity"] == "agent-a"
    assert event["initiator"] == "operator"
    assert event["attribution_status"] == "delegated"
    assert event["attribution_provenance"]["delegation"] == "operator-provenance"


def test_conflicting_trusted_sources_are_operator_only(logger_with_log):
    from service_discovery import ServiceDiscovery

    addon, path = logger_with_log
    discovery = ServiceDiscovery()
    discovery._ip_to_name = {"192.0.2.10": "agent-b"}
    flow = _flow()

    with patch(
        "request_logger.find_addon", autospec=True, return_value=discovery
    ):
        addon.request(flow)

    event = _events(path)[0]
    assert "agent" not in event
    assert event["attribution_status"] == "conflict"
    assert "evidence_owner" not in event
    assert "trusted_transport_identity" not in event
    assert event["attribution_provenance"] == {
        "uds_agent": "agent-a",
        "ip_map_agent": "agent-b",
        "reason": "uds_ip_map_mismatch",
    }


def test_missing_response_emits_ops_event_without_response_counter(logger_with_log):
    addon, path = logger_with_log
    flow = _flow(status=None)
    flow.metadata["request_id"] = "req-missing"
    addon.response(flow)
    event = _events(path)[0]
    assert event["event"] == "ops.response_missing"
    assert event["kind"] == "ops"
    assert event["severity"] == "medium"
    assert event["agent"] == "agent-a"
    assert addon.responses_total == 0
    assert addon.blocks_total == 0


def test_request_response_share_snapshot_when_ip_map_changes(logger_with_log):
    """A late trusted-source change is linked and quarantines storage scope."""
    from service_discovery import ServiceDiscovery

    addon, path = logger_with_log
    discovery = ServiceDiscovery()
    discovery._ip_to_name = {"192.0.2.10": "agent-a"}
    flow = _flow()
    flow.metadata["request_id"] = "req-late-change"

    with patch("request_logger.find_addon", autospec=True, return_value=discovery):
        addon.request(flow)
        discovery._ip_to_name["192.0.2.10"] = "agent-b"
        addon.response(flow)

    traffic = [event for event in _events(path) if event["event"].startswith("traffic.")]
    assert traffic[0]["evidence_owner"] == traffic[1]["evidence_owner"] == "agent-a"
    assert traffic[0]["trusted_transport_identity"] == traffic[1]["trusted_transport_identity"] == "agent-a"
    assert traffic[0]["attribution_status"] == traffic[1]["attribution_status"] == "resolved"
    assert traffic[1]["details"]["attribution_quarantined"] is True

    late = next(event for event in _events(path) if event["event"] == "security.agent_identity_late_change")
    assert "agent" not in late
    assert "evidence_owner" not in late
    assert late["request_id"] == "req-late-change"
    assert late["decision"] == "log"
    assert late["details"]["quarantined"] is True
    assert late["attribution_provenance"]["snapshot_agent"] == "agent-a"
    assert late["attribution_provenance"]["current_status"] == "conflict"


def test_response_duration_and_counter_are_exact(logger_with_log):
    addon, path = logger_with_log
    flow = _flow(response_content=b"abc")
    flow.metadata.update(request_id="req-2", start_time=1000.0)
    with patch("request_logger.time.time", autospec=True, return_value=1000.075):
        addon.response(flow)
    event = _events(path)[0]
    assert event["details"] == {
        "path": "/v1/data",
        "status": 200,
        "size": 3,
        "ms": 75.0,
    }
    assert event["agent"] == "agent-a"
    assert addon.responses_total == 1


def test_quiet_request_and_response_emit_nothing_but_count_request(logger_with_log):
    addon, path = logger_with_log
    addon._quiet_hosts.add("api.example.com")
    flow = _flow()
    addon.request(flow)
    addon.response(flow)
    assert _events(path) == []
    assert flow.metadata["quieted"] is True
    assert addon.get_stats() == {
        "requests_total": 1,
        "requests_quieted": 1,
        "responses_total": 0,
        "blocks_total": 0,
    }


def test_block_overrides_quiet_and_preserves_reason_and_fingerprint(logger_with_log):
    addon, path = logger_with_log
    addon._quiet_hosts.add("api.example.com")
    flow = _flow(status=403)
    addon.request(flow)
    flow.metadata.update(
        blocked_by="credential-guard",
        block_reason="credential destination denied",
        credential_fingerprint="hmac:abc123",
    )
    addon.response(flow)
    event = _events(path)[0]
    assert event["event"] == "traffic.response"
    assert event["severity"] == "high"
    assert event["agent"] == "agent-a"
    assert event["details"]["blocked_by"] == "credential-guard"
    assert event["details"]["block_reason"] == "credential destination denied"
    assert event["details"]["credential_fingerprint"] == "hmac:abc123"
    assert addon.responses_total == 0
    assert addon.blocks_total == 1


def test_changed_policy_hash_reloads_once_and_preserves_last_good_rules(logger_with_log):
    addon, path = logger_with_log
    good = _policy(
        {
            "policy_hash": "one",
            "addons": {"request_logger": {"quiet_hosts": {"hosts": ["quiet.example"]}}},
        }
    )
    with patch("request_logger.get_policy_client", new=lambda: good):
        addon._maybe_reload_config()
        addon._maybe_reload_config()
    assert good.get_sensor_config.call_count == 2
    assert addon._should_quiet("quiet.example", "/") is True

    malformed = _policy(
        {
            "policy_hash": "two",
            "addons": {"request_logger": {"quiet_hosts": {"hosts": "bad"}}},
        }
    )
    with patch("request_logger.get_policy_client", new=lambda: malformed):
        addon._maybe_reload_config()
    assert addon._should_quiet("quiet.example", "/") is True
    assert _events(path)[0]["event"] == "ops.config_error"


def test_unconfigured_policy_is_silent_and_keeps_logging(logger_with_log):
    addon, path = logger_with_log

    def unavailable() -> PolicyClient:
        raise RuntimeError("not ready")

    with patch("request_logger.get_policy_client", new=unavailable):
        addon.request(_flow())
    assert _events(path)[0]["event"] == "traffic.request"


def test_stats_returns_an_independent_snapshot():
    addon = RequestLogger()
    addon.requests_total = 3
    snapshot = addon.get_stats()
    snapshot["requests_total"] = 999
    assert addon.get_stats()["requests_total"] == 3
