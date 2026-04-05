"""Tests for the request_id addon.

Contract: assign a correlation ID and start_time to every flow, strip RFC 7230
hop-by-hop headers, preserve WebSocket handshake headers when applicable.

These tests are organised by contract area (ID + start_time, hop-by-hop
stripping, WebSocket classification, logging hygiene, cross-module contract)
and include a dedicated error/non-promise section.
"""

import logging
import re
import time

import pytest
from mitmproxy.test import tflow


@pytest.fixture
def addon():
    """Fresh RequestIdGenerator for each test."""
    from request_id import RequestIdGenerator
    return RequestIdGenerator()


# =========================================================================
# Request ID format and cross-module contract
# =========================================================================


class TestRequestIdFormat:
    def test_request_id_matches_pattern(self, addon):
        """The generated ID matches REQUEST_ID_PATTERN byte-for-byte."""
        from request_id import REQUEST_ID_PATTERN

        flow = tflow.tflow()
        addon.request(flow)

        assert REQUEST_ID_PATTERN.match(flow.metadata["request_id"]) is not None

    def test_request_id_uses_prefix_constant(self, addon):
        """The ID starts with the REQUEST_ID_PREFIX constant, not a hardcoded string."""
        from request_id import REQUEST_ID_PREFIX

        flow = tflow.tflow()
        addon.request(flow)

        assert flow.metadata["request_id"].startswith(REQUEST_ID_PREFIX)

    def test_request_id_hex_part_is_128_bits(self, addon):
        """The hex portion is 32 lowercase hex chars (128 bits of uuid4 entropy)."""
        flow = tflow.tflow()
        addon.request(flow)

        hex_part = flow.metadata["request_id"][len("req-"):]
        assert len(hex_part) == 32
        assert re.fullmatch(r"[0-9a-f]{32}", hex_part) is not None

    def test_request_id_matches_agent_api_explain_pattern(self, addon):
        """Cross-module contract: /explain's validator pattern accepts our IDs.

        agent_api imports REQUEST_ID_PATTERN from request_id; this test locks
        the generator/validator pair so a future rename or format drift on
        either side fails this test.
        """
        from agent_api import _REQUEST_ID_PATTERN as explain_pattern

        flow = tflow.tflow()
        addon.request(flow)

        assert explain_pattern.match(flow.metadata["request_id"]) is not None


class TestRequestIdUniqueness:
    def test_100_flows_have_100_distinct_ids(self, addon):
        flows = [tflow.tflow() for _ in range(100)]
        for f in flows:
            addon.request(f)

        ids = [f.metadata["request_id"] for f in flows]
        assert len(set(ids)) == 100

    def test_request_id_overwrites_preexisting_value(self, addon):
        """Contract: the addon owns request_id and unconditionally overwrites."""
        from request_id import REQUEST_ID_PATTERN

        flow = tflow.tflow()
        flow.metadata["request_id"] = "req-legacy000000000000000000000000000"

        addon.request(flow)

        assert flow.metadata["request_id"] != "req-legacy000000000000000000000000000"
        assert REQUEST_ID_PATTERN.match(flow.metadata["request_id"]) is not None

    def test_second_invocation_assigns_fresh_id(self, addon):
        """Calling request() twice on the same flow produces two distinct IDs."""
        flow = tflow.tflow()
        addon.request(flow)
        first = flow.metadata["request_id"]

        addon.request(flow)
        second = flow.metadata["request_id"]

        assert first != second


# =========================================================================
# start_time
# =========================================================================


class TestStartTime:
    def test_start_time_is_float(self, addon):
        flow = tflow.tflow()
        addon.request(flow)

        assert isinstance(flow.metadata["start_time"], float)

    def test_start_time_is_wall_clock_seconds(self, addon):
        flow = tflow.tflow()
        before = time.time()
        addon.request(flow)
        after = time.time()

        assert before <= flow.metadata["start_time"] <= after

    def test_start_time_overwrites_preexisting_value(self, addon):
        flow = tflow.tflow()
        flow.metadata["start_time"] = 0.0

        addon.request(flow)

        assert flow.metadata["start_time"] > 0.0

    def test_second_invocation_advances_start_time(self, addon):
        """Successive invocations re-stamp start_time."""
        flow = tflow.tflow()
        addon.request(flow)
        first = flow.metadata["start_time"]

        time.sleep(0.001)
        addon.request(flow)
        second = flow.metadata["start_time"]

        assert second > first


# =========================================================================
# Hop-by-hop header stripping (RFC 7230 §6.1)
# =========================================================================


HOP_BY_HOP = [
    ("Connection", "keep-alive"),
    ("Keep-Alive", "timeout=5"),
    ("Proxy-Authenticate", "Basic"),
    ("Proxy-Authorization", "Basic c2VjcmV0"),
    ("TE", "trailers"),
    ("Trailer", "Expires"),
    ("Transfer-Encoding", "chunked"),
    ("Upgrade", "h2c"),
]


class TestHopByHopStripping:
    @pytest.mark.parametrize("header,value", HOP_BY_HOP)
    def test_canonical_hop_by_hop_header_stripped(self, addon, header, value):
        """Every RFC 7230 §6.1 hop-by-hop header is individually stripped."""
        flow = tflow.tflow()
        flow.request.headers[header] = value

        addon.request(flow)

        assert header not in flow.request.headers
        assert header.lower() not in {k.lower() for k in flow.request.headers.keys()}

    def test_end_to_end_headers_preserved(self, addon):
        """Headers that are NOT hop-by-hop must survive stripping."""
        flow = tflow.tflow()
        preserved = {
            "Authorization": "Bearer keep-me",
            "Host": "api.example.com",
            "User-Agent": "pytest/1.0",
            "Cookie": "session=abc",
            "Content-Type": "application/json",
            "Content-Length": "42",
            "X-Custom": "value",
        }
        for k, v in preserved.items():
            flow.request.headers[k] = v

        addon.request(flow)

        for k, v in preserved.items():
            assert flow.request.headers.get(k) == v, f"{k} did not survive"

    def test_stripping_is_case_insensitive(self, addon):
        """Both upper- and lower-case variants of a hop-by-hop header are stripped."""
        flow = tflow.tflow()
        flow.request.headers["PROXY-AUTHORIZATION"] = "Basic aaa"

        addon.request(flow)

        assert "proxy-authorization" not in {k.lower() for k in flow.request.headers.keys()}


class TestConnectionHeaderNominatedHopHeaders:
    def test_connection_listed_header_stripped(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Connection"] = "X-Custom-Hop, close"
        flow.request.headers["X-Custom-Hop"] = "stripped"
        flow.request.headers["X-Regular"] = "kept"

        addon.request(flow)

        assert "Connection" not in flow.request.headers
        assert "X-Custom-Hop" not in flow.request.headers
        assert flow.request.headers.get("X-Regular") == "kept"

    def test_connection_tokens_are_whitespace_tolerant(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Connection"] = "  x-foo  ,x-bar,  x-baz  "
        flow.request.headers["X-Foo"] = "a"
        flow.request.headers["X-Bar"] = "b"
        flow.request.headers["X-Baz"] = "c"

        addon.request(flow)

        assert "X-Foo" not in flow.request.headers
        assert "X-Bar" not in flow.request.headers
        assert "X-Baz" not in flow.request.headers

    def test_connection_tokens_are_case_insensitive(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Connection"] = "X-UPPER"
        flow.request.headers["X-Upper"] = "stripped"

        addon.request(flow)

        assert "X-Upper" not in flow.request.headers

    def test_empty_connection_header_is_noop(self, addon):
        """Empty Connection header does not crash and does not strip anything extra."""
        flow = tflow.tflow()
        flow.request.headers["Connection"] = ""
        flow.request.headers["X-Keep"] = "value"

        addon.request(flow)

        assert flow.request.headers.get("X-Keep") == "value"

    def test_comma_only_connection_header_is_noop(self, addon):
        """Whitespace/comma-only Connection values do not strip empty-name headers."""
        flow = tflow.tflow()
        flow.request.headers["Connection"] = ", , "
        flow.request.headers["X-Keep"] = "value"

        addon.request(flow)

        assert flow.request.headers.get("X-Keep") == "value"


# =========================================================================
# WebSocket handshake classification (RFC 6455 §4.1)
# =========================================================================


class TestWebSocketDetection:
    def _ws(self):
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        flow.request.headers["Connection"] = "Upgrade"
        return flow

    def test_websocket_upgrade_sets_metadata_flag(self, addon):
        flow = self._ws()
        addon.request(flow)
        assert flow.metadata["is_websocket"] is True

    def test_websocket_upgrade_preserves_upgrade_and_connection(self, addon):
        flow = self._ws()
        addon.request(flow)
        assert flow.request.headers.get("Upgrade") == "websocket"
        assert flow.request.headers.get("Connection") == "Upgrade"

    def test_websocket_still_assigns_request_id_and_start_time(self, addon):
        from request_id import REQUEST_ID_PATTERN
        flow = self._ws()
        addon.request(flow)
        assert REQUEST_ID_PATTERN.match(flow.metadata["request_id"])
        assert isinstance(flow.metadata["start_time"], float)

    def test_websocket_still_strips_other_hop_by_hop_headers(self, addon):
        """Security-critical: Proxy-Authorization and Keep-Alive must still be stripped
        on a websocket flow."""
        flow = self._ws()
        flow.request.headers["Proxy-Authorization"] = "Basic secret"
        flow.request.headers["Keep-Alive"] = "timeout=5"

        addon.request(flow)

        assert "Proxy-Authorization" not in flow.request.headers
        assert "Keep-Alive" not in flow.request.headers

    def test_non_websocket_flow_has_no_is_websocket_key(self, addon):
        """Contract: is_websocket is absent (not False) on non-websocket flows."""
        flow = tflow.tflow()
        addon.request(flow)
        assert "is_websocket" not in flow.metadata

    def test_upgrade_h2c_is_not_a_websocket(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "h2c"
        flow.request.headers["Connection"] = "Upgrade"

        addon.request(flow)

        assert "is_websocket" not in flow.metadata
        # Both headers stripped because this is not a websocket
        assert "Upgrade" not in flow.request.headers
        assert "Connection" not in flow.request.headers

    def test_upgrade_websocket_without_connection_is_not_a_websocket(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        # no Connection header

        addon.request(flow)

        assert "is_websocket" not in flow.metadata
        assert "Upgrade" not in flow.request.headers

    def test_upgrade_websocket_with_connection_close_is_not_a_websocket(self, addon):
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        flow.request.headers["Connection"] = "close"

        addon.request(flow)

        assert "is_websocket" not in flow.metadata

    def test_connection_upgrade_insecure_requests_is_not_a_websocket(self, addon):
        """Pins B6 fix: substring matching would false-positive this header value.

        `Connection: upgrade-insecure-requests` contains the substring 'upgrade'
        but NOT the token 'upgrade'. Tokenised comparison is required.
        """
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        flow.request.headers["Connection"] = "upgrade-insecure-requests"

        addon.request(flow)

        assert "is_websocket" not in flow.metadata

    def test_connection_keep_alive_upgrade_is_websocket(self, addon):
        """Order-invariant: `Connection: keep-alive, Upgrade` is still a valid websocket."""
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        flow.request.headers["Connection"] = "keep-alive, Upgrade"

        addon.request(flow)

        assert flow.metadata.get("is_websocket") is True


# =========================================================================
# Log-injection hygiene (B3)
# =========================================================================


class TestWebSocketLogSanitisation:
    def test_websocket_log_sanitises_malicious_host(self, addon, caplog):
        """A malicious Host header must not inject fake log lines."""
        flow = tflow.tflow()
        flow.request.headers["Upgrade"] = "websocket"
        flow.request.headers["Connection"] = "Upgrade"
        # mitmproxy's test flow exposes .host via the request; inject a
        # control-character-laden value to trigger sanitisation.
        flow.request.host = "evil.com\nfake log line"
        flow.request.path = "/ws\r\ninjected"

        with caplog.at_level(logging.INFO, logger="safeyolo.request_id"):
            addon.request(flow)

        logged = " ".join(rec.getMessage() for rec in caplog.records)
        # sanitize_for_log replaces control chars with "?" (collapsed)
        assert "\n" not in logged
        assert "\r" not in logged
        assert "fake log line" not in logged or "?" in logged


# =========================================================================
# Non-promises and fail-closed
# =========================================================================


class TestNonPromises:
    def test_addon_has_no_response_hook(self, addon):
        """The addon does not touch response headers — scope-limiting assertion."""
        assert not hasattr(addon, "response")

    def test_addon_name_is_request_id(self, addon):
        """The `name` attribute leaks into audit-log fields via blocked_by-style writes
        elsewhere; it is part of the external contract."""
        assert addon.name == "request-id"
