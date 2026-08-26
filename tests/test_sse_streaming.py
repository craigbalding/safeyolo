"""Assurance-boundary tests for response streaming decisions."""

from __future__ import annotations

from unittest.mock import create_autospec, patch

import pytest
from mitmproxy import http
from mitmproxy.test import taddons, tflow
from sse_streaming import SSE_CONTENT_TYPES, SSEStreaming

from pdp.client import PolicyClient

pytestmark = pytest.mark.assurance_boundary


def _flow(content_type: str, host: str = "api.example.com") -> http.HTTPFlow:
    flow = tflow.tflow(resp=False)
    flow.request.host = host
    flow.response = http.Response.make(200, b"payload", {"Content-Type": content_type})
    return flow


def _policy(enabled: bool = True) -> PolicyClient:
    client = create_autospec(PolicyClient, instance=True, spec_set=True)
    client.is_addon_enabled.return_value = enabled
    return client


def _run(addon: SSEStreaming, flow: http.HTTPFlow, client: PolicyClient, **options):
    with taddons.context(addon) as context, patch(
        "pdp.get_policy_client", new=lambda: client
    ):
        context.options.update(**options)
        addon.responseheaders(flow)


def test_streaming_content_types_are_an_explicit_contract():
    assert SSE_CONTENT_TYPES == ["text/event-stream", "application/x-ndjson"]


@pytest.mark.parametrize(
    "content_type, reason",
    [
        ("text/event-stream", "text/event-stream"),
        ("text/event-stream; charset=utf-8", "text/event-stream"),
        ("application/x-ndjson", "application/x-ndjson"),
    ],
)
def test_matching_content_type_mutates_real_response_and_counts_exactly(
    content_type: str, reason: str
):
    addon = SSEStreaming()
    flow = _flow(content_type)
    client = _policy()

    _run(addon, flow, client)

    assert flow.response.stream is True
    assert addon.get_stats()["streams_enabled_total"] == 1
    assert addon.streams_by_domain == {"api.example.com": 1}
    assert addon.streams_by_content_type == {reason: 1}
    client.is_addon_enabled.assert_called_once_with(
        "sse_streaming", domain="api.example.com"
    )


@pytest.mark.parametrize("content_type", ["text/plain", "application/json", "text/eventful"])
def test_non_matching_content_type_is_not_streamed(content_type: str):
    addon = SSEStreaming()
    flow = _flow(content_type)
    _run(addon, flow, _policy())
    assert flow.response.stream is False
    assert addon.streams_enabled == 0


def test_global_disablement_prevents_policy_lookup_and_mutation():
    addon = SSEStreaming()
    flow = _flow("text/event-stream")
    client = _policy()
    _run(addon, flow, client, sse_streaming_enabled=False)
    assert flow.response.stream is False
    assert addon.streams_enabled == 0
    client.is_addon_enabled.assert_not_called()


def test_policy_disablement_prevents_response_mutation_and_counting():
    addon = SSEStreaming()
    flow = _flow("text/event-stream")
    client = _policy(enabled=False)
    _run(addon, flow, client)
    assert flow.response.stream is False
    assert addon.streams_enabled == 0
    client.is_addon_enabled.assert_called_once_with(
        "sse_streaming", domain="api.example.com"
    )


def test_unconfigured_policy_defaults_to_streaming():
    addon = SSEStreaming()
    flow = _flow("text/event-stream")

    def unavailable() -> PolicyClient:
        raise RuntimeError("not configured")

    with taddons.context(addon), patch("pdp.get_policy_client", new=unavailable):
        addon.responseheaders(flow)
    assert flow.response.stream is True
    assert addon.streams_enabled == 1


def test_json_streaming_requires_explicit_option():
    addon = SSEStreaming()
    ordinary = _flow("application/json; charset=utf-8", "ntfy.example.com")
    _run(addon, ordinary, _policy())
    assert ordinary.response.stream is False

    opted_in = _flow("application/json; charset=utf-8", "ntfy.example.com")
    _run(addon, opted_in, _policy(), sse_stream_json=True)
    assert opted_in.response.stream is True
    assert addon.streams_by_content_type == {"application/json (option)": 1}


def test_stats_snapshot_is_independent_and_preserves_exact_totals():
    addon = SSEStreaming()
    addon._record_stream("api.example.com", "text/event-stream")
    addon._record_stream("api.example.com", "text/event-stream")
    addon._record_stream("other.example", "application/x-ndjson")

    with taddons.context(addon):
        stats = addon.get_stats()
    stats["streams_by_domain"]["api.example.com"] = 999

    assert stats["enabled"] is True
    assert stats["streams_enabled_total"] == 3
    assert addon.streams_by_domain == {"api.example.com": 2, "other.example": 1}
    assert addon.streams_by_content_type == {
        "text/event-stream": 2,
        "application/x-ndjson": 1,
    }
