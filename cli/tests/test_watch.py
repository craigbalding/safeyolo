"""Tests for watch command — batch approval UX."""

import io
import json
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from rich.panel import Panel

from safeyolo.commands.watch import (
    DISPATCH,
    FALLBACK_DISPATCH,
    RollingStats,
    _contract_binding_format_row,
    _credential_format_row,
    _dedup_key_from_approval,
    _fallback_format_row,
    _format_batch_table,
    _gateway_format_row,
    _host_to_domain,
    _network_egress_format_row,
    _parse_duration,
    _resolved_key_from_admin_event,
    _risky_route_dedup_key,
    _service_format_row,
    build_batch_items,
    handle_batch,
    parse_selection,
    scan_pending_approvals,
)

# ---------------------------------------------------------------------------
# Sample events
# ---------------------------------------------------------------------------

def _credential_event(key="hmac:abc123", target="api.openai.com", rule="openai", ts="2026-03-24T10:00:00Z"):
    return {
        "event": "security.credential_guard",
        "kind": "security",
        "decision": "require_approval",
        "host": target,
        "agent": "boris",
        "ts": ts,
        "summary": f"{rule} credential → {target}",
        "approval": {
            "required": True,
            "approval_type": "credential",
            "key": key,
            "target": target,
        },
        "details": {
            "fingerprint": key,
            "rule": rule,
            "reason": "credential sent to unexpected host",
        },
    }


def _gateway_event(
    agent="boris",
    service="gmail",
    method="POST",
    path="/messages/send",
    tactics=None,
    irreversible=False,
    description="",
    ts="2026-03-24T10:00:01Z",
):
    tactics = tactics or ["impact"]
    return {
        "event": "gateway.risky_route",
        "kind": "gateway",
        "decision": "require_approval",
        "host": "gmail.googleapis.com",
        "agent": agent,
        "ts": ts,
        "summary": f"Risky route {method} {service}{path}",
        "approval": {
            "required": True,
            "approval_type": "gateway_route",
            "key": f"gw:{agent}:{service}:{method}:{path}",
            "target": service,
        },
        "details": {
            "service": service,
            "capability": "mail",
            "method": method,
            "path": path,
            "risky_route": path,
            "tactics": tactics,
            "enables": [],
            "irreversible": irreversible,
            "description": description,
            "group": "",
            "effect": "require_approval",
        },
    }


# ---------------------------------------------------------------------------
# parse_selection tests
# ---------------------------------------------------------------------------

class TestParseSelection:
    def test_approve_aliases(self):
        for raw in ("a", "approve", "y", "yes", "A", "APPROVE", "Y", "YES"):
            assert parse_selection(raw, 5) == "a"

    def test_deny_aliases(self):
        for raw in ("d", "deny", "n", "no", "D", "DENY"):
            assert parse_selection(raw, 5) == "d"

    def test_later_aliases(self):
        for raw in ("l", "later", "", "L", "LATER"):
            assert parse_selection(raw, 5) == "l"

    def test_review_syntax(self):
        assert parse_selection("r3", 5) == ("review", 3)
        assert parse_selection("r1", 1) == ("review", 1)

    def test_review_out_of_range(self):
        with pytest.raises(ValueError, match="out of range"):
            parse_selection("r6", 5)
        with pytest.raises(ValueError, match="out of range"):
            parse_selection("r0", 5)

    def test_single_number(self):
        assert parse_selection("3", 5) == [3]

    def test_comma_list(self):
        assert parse_selection("1,3,5", 5) == [1, 3, 5]

    def test_range(self):
        assert parse_selection("1-3", 5) == [1, 2, 3]

    def test_mixed_ranges(self):
        assert parse_selection("1-2,4", 5) == [1, 2, 4]

    def test_dedup(self):
        assert parse_selection("1,1,2", 5) == [1, 2]

    def test_out_of_range_index(self):
        with pytest.raises(ValueError, match="out of range"):
            parse_selection("6", 5)
        with pytest.raises(ValueError, match="out of range"):
            parse_selection("0", 5)

    def test_invalid_input(self):
        with pytest.raises(ValueError, match="Invalid"):
            parse_selection("xyz", 5)

    def test_invalid_range(self):
        with pytest.raises(ValueError, match="Invalid range"):
            parse_selection("3-1", 5)


# ---------------------------------------------------------------------------
# build_batch_items tests
# ---------------------------------------------------------------------------

class TestBuildBatchItems:
    def test_credential_event(self):
        events = [_credential_event()]
        items = build_batch_items(events)
        assert len(items) == 1
        assert items[0].index == 1
        assert items[0].approval_type == "credential"
        assert items[0].dedup_key == "hmac:abc123:api.openai.com"
        assert items[0].irreversible is False

    def test_gateway_event(self):
        events = [_gateway_event(irreversible=True)]
        items = build_batch_items(events)
        assert len(items) == 1
        assert items[0].approval_type == "gateway_route"
        assert items[0].irreversible is True

    def test_mixed_events(self):
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)
        assert len(items) == 2
        assert items[0].index == 1
        assert items[0].approval_type == "credential"
        assert items[1].index == 2
        assert items[1].approval_type == "gateway_route"

    def test_index_assignment(self):
        events = [_credential_event(key=f"hmac:{i}", target=f"host{i}.com") for i in range(5)]
        items = build_batch_items(events)
        assert [it.index for it in items] == [1, 2, 3, 4, 5]

    def test_unknown_approval_type(self):
        event = _credential_event()
        event["approval"]["approval_type"] = "new_type"
        items = build_batch_items([event])
        assert items[0].approval_type == "new_type"

    def test_irreversible_flag_from_details(self):
        event = _gateway_event(irreversible=False)
        items = build_batch_items([event])
        assert items[0].irreversible is False

        event = _gateway_event(irreversible=True)
        items = build_batch_items([event])
        assert items[0].irreversible is True


# ---------------------------------------------------------------------------
# Dispatch registry tests
# ---------------------------------------------------------------------------

class TestDispatchFormatRow:
    def test_credential_format_row(self):
        event = _credential_event()
        agent, action, risk, desc = _credential_format_row(event)
        assert agent == "boris"
        assert "openai" in action
        assert "api.openai.com" in action
        assert risk == "credential routing"

    def test_gateway_format_row(self):
        event = _gateway_event(tactics=["impact", "exfiltration"])
        agent, action, risk, desc = _gateway_format_row(event)
        assert agent == "boris"
        assert "gmail" in action
        assert "POST" in action
        assert "destructive action" in risk  # TACTIC_LABELS["impact"]
        assert "data theft" in risk  # TACTIC_LABELS["exfiltration"]

    def test_gateway_format_row_with_description(self):
        event = _gateway_event(description="Send email as operator")
        _, _, _, desc = _gateway_format_row(event)
        assert desc == "Send email as operator"

    def test_fallback_format_row(self):
        event = _credential_event()
        event["approval"]["approval_type"] = "new_type"
        agent, action, risk, desc = _fallback_format_row(event)
        assert "new_type" in action


class TestDispatchApprove:
    def test_credential_approve(self):
        api = MagicMock()
        api.add_approval.return_value = {"status": "added"}
        event = _credential_event()
        dispatch = DISPATCH["credential"]
        result = dispatch.approve(event, api)
        assert result == "added"
        api.add_approval.assert_called_once_with(
            destination="api.openai.com", cred_id="hmac:abc123"
        )

    def test_gateway_approve(self):
        api = MagicMock()
        api.add_gateway_grant.return_value = {"grant_id": "g123"}
        event = _gateway_event()
        dispatch = DISPATCH["gateway_route"]
        result = dispatch.approve(event, api)
        assert result == "g123"
        api.add_gateway_grant.assert_called_once_with(
            agent="boris", service="gmail", method="POST",
            path="/messages/send", lifetime="once",
        )

    def test_credential_deny(self):
        api = MagicMock()
        event = _credential_event()
        dispatch = DISPATCH["credential"]
        dispatch.deny(event, api)
        api.log_denial.assert_called_once_with(
            destination="api.openai.com", cred_id="hmac:abc123",
            reason="user_denied",
        )

    def test_gateway_deny(self):
        api = MagicMock()
        event = _gateway_event()
        dispatch = DISPATCH["gateway_route"]
        dispatch.deny(event, api)
        api.log_gateway_denial.assert_called_once_with(
            agent="boris", service="gmail", method="POST",
            path="/messages/send",
        )

    def test_unknown_approve_raises(self):
        api = MagicMock()
        event = _credential_event()
        event["approval"]["approval_type"] = "new_type"
        with pytest.raises(NotImplementedError, match="unknown approval_type"):
            FALLBACK_DISPATCH.approve(event, api)

    def test_unknown_deny_raises(self):
        api = MagicMock()
        event = _credential_event()
        event["approval"]["approval_type"] = "new_type"
        with pytest.raises(NotImplementedError, match="unknown approval_type"):
            FALLBACK_DISPATCH.deny(event, api)


# ---------------------------------------------------------------------------
# handle_batch tests
# ---------------------------------------------------------------------------

class TestHandleBatch:
    def _make_api(self):
        api = MagicMock()
        api.add_approval.return_value = {"status": "added"}
        api.add_gateway_grant.return_value = {"grant_id": "g1"}
        return api

    def test_single_item_delegates(self):
        """Single item should delegate to existing handler, not show batch table."""
        api = self._make_api()
        stats = RollingStats()
        event = _credential_event()
        items = build_batch_items([event])

        with patch("safeyolo.commands.watch.console"):
            with patch("safeyolo.commands.watch.handle_approval", return_value=True) as mock_handler:
                handle_batch(items, api, stats)

        mock_handler.assert_called_once_with(event, api)

    def test_approve_all_no_irreversible(self):
        """Approve-all with no irreversible items approves everything."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(irreversible=False, ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            mock_console.input.return_value = "a"
            handle_batch(items, api, stats)

        api.add_approval.assert_called_once()
        api.add_gateway_grant.assert_called_once()

    def test_approve_all_with_irreversible(self):
        """Approve-all: safe items approved, irreversible get individual prompt."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(irreversible=True, ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            # First prompt: approve all. Second: confirm irreversible
            mock_console.input.side_effect = ["a", "yes"]
            handle_batch(items, api, stats)

        api.add_approval.assert_called_once()
        api.add_gateway_grant.assert_called_once()

    def test_approve_all_deny_irreversible(self):
        """Approve-all: safe approved, irreversible denied."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(irreversible=True, ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            mock_console.input.side_effect = ["a", "d"]
            handle_batch(items, api, stats)

        api.add_approval.assert_called_once()
        api.add_gateway_grant.assert_not_called()
        api.log_gateway_denial.assert_called_once()

    def test_deny_all(self):
        """Deny all calls all denial APIs."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            mock_console.input.return_value = "d"
            handle_batch(items, api, stats)

        api.log_denial.assert_called_once()
        api.log_gateway_denial.assert_called_once()

    def test_later_no_api_calls(self):
        """Later defers everything — no API calls."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            mock_console.input.return_value = "l"
            handle_batch(items, api, stats)

        api.add_approval.assert_not_called()
        api.add_gateway_grant.assert_not_called()
        api.log_denial.assert_not_called()
        api.log_gateway_denial.assert_not_called()

    def test_select_indices(self):
        """Select specific indices prompts only those, then defer remaining."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
            _credential_event(key="hmac:xyz", target="api.other.com", ts="2026-03-24T10:00:02Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            with patch("safeyolo.commands.watch.handle_approval", return_value=True) as mock_cred:
                with patch("safeyolo.commands.watch.handle_risky_route_approval", return_value=False) as mock_gw:
                    # Select items 1 and 2, then defer remaining item 3
                    mock_console.input.side_effect = ["1,2", "l"]
                    handle_batch(items, api, stats)

        # Item 1 (credential) and item 2 (gateway) prompted
        mock_cred.assert_called_once()
        mock_gw.assert_called_once()

    def test_review_prompts_action_on_item(self):
        """Review opens item for action, then returns to remaining batch."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            with patch("safeyolo.commands.watch.handle_approval", return_value=True) as mock_handler:
                # Review item 1 (credential) → handled by handle_approval, then later for rest
                mock_console.input.side_effect = ["r1", "l"]
                handle_batch(items, api, stats)

        mock_handler.assert_called_once_with(events[0], api)

    def test_review_removes_acted_item_from_batch(self):
        """After review+action, the item is removed from the batch."""
        api = self._make_api()
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
            _credential_event(key="hmac:other", target="other.com", ts="2026-03-24T10:00:02Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            with patch("safeyolo.commands.watch.handle_approval", return_value=False):
                # Review item 1 (denied/deferred), then approve all remaining
                mock_console.input.side_effect = ["r1", "a"]
                handle_batch(items, api, stats)

        # Item 1 was handled via review, items 2+3 via approve-all
        api.add_gateway_grant.assert_called_once()  # item 2
        api.add_approval.assert_called_once()  # item 3

    def test_api_error_continues(self):
        """API error on one item doesn't abort the batch."""
        from safeyolo.api import APIError

        api = self._make_api()
        api.add_approval.side_effect = APIError("connection failed")
        stats = RollingStats()
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(irreversible=False, ts="2026-03-24T10:00:01Z"),
        ]
        items = build_batch_items(events)

        with patch("safeyolo.commands.watch.console") as mock_console:
            mock_console.input.return_value = "a"
            handle_batch(items, api, stats)

        # Credential failed but gateway still called
        api.add_approval.assert_called_once()
        api.add_gateway_grant.assert_called_once()


# ---------------------------------------------------------------------------
# scan_pending_approvals tests
# ---------------------------------------------------------------------------

class TestScanPendingApprovals:
    def test_empty_file(self, tmp_path):
        log = tmp_path / "test.jsonl"
        log.write_text("")
        pending, resolved = scan_pending_approvals(log)
        assert pending == []
        assert resolved == set()

    def test_missing_file(self, tmp_path):
        pending, resolved = scan_pending_approvals(tmp_path / "nope.jsonl")
        assert pending == []
        assert resolved == set()

    def test_collects_approval_events(self, tmp_path):
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(ts="2026-03-24T10:00:00Z"),
            _gateway_event(ts="2026-03-24T10:00:01Z"),
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert len(pending) == 2
        # Sorted by timestamp
        assert pending[0]["ts"] == "2026-03-24T10:00:00Z"
        assert pending[1]["ts"] == "2026-03-24T10:00:01Z"

    def test_resolved_items_excluded(self, tmp_path):
        """Operator actions resolve specific items, not everything."""
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:old", target="httpbin.org", ts="2026-03-24T09:00:00Z"),
            _credential_event(key="hmac:new", target="api.example.com", ts="2026-03-24T09:01:00Z"),
            # Denial resolves hmac:old → httpbin.org
            {"event": "admin.denial", "ts": "2026-03-24T09:30:00Z",
             "details": {"destination": "httpbin.org", "cred_id": "hmac:old", "reason": "user_denied"}},
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        # hmac:old was denied, hmac:new is still pending
        assert len(pending) == 1
        assert pending[0]["approval"]["key"] == "hmac:new"

    def test_unresolved_items_survive_other_actions(self, tmp_path):
        """Items not specifically resolved remain pending after other operator actions."""
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:aaa", target="host1.com", ts="2026-03-24T09:00:00Z"),
            _credential_event(key="hmac:bbb", target="host2.com", ts="2026-03-24T09:01:00Z"),
            _credential_event(key="hmac:ccc", target="host3.com", ts="2026-03-24T09:02:00Z"),
            # Only hmac:aaa is denied
            {"event": "admin.denial", "ts": "2026-03-24T09:30:00Z",
             "details": {"destination": "host1.com", "cred_id": "hmac:aaa", "reason": "user_denied"}},
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert len(pending) == 2
        keys = {p["approval"]["key"] for p in pending}
        assert keys == {"hmac:bbb", "hmac:ccc"}

    def test_dedup_by_approval_key(self, tmp_path):
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:abc", ts="2026-03-24T10:00:00Z"),
            _credential_event(key="hmac:abc", ts="2026-03-24T10:00:05Z"),  # duplicate
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert len(pending) == 1

    def test_denied_then_retried_not_reprompted(self, tmp_path):
        """Denial followed by a retry of the same credential must not re-prompt.

        Regression: the single-pass reverse scan added the retry event to
        pending_blocks before encountering the denial, so the denial never
        filtered it out.
        """
        log = tmp_path / "test.jsonl"
        events = [
            # 1) Original approval request
            _credential_event(key="hmac:xyz", target="api.openai.com", ts="2026-03-24T09:00:00Z"),
            # 2) Operator denies
            {"event": "admin.denial", "ts": "2026-03-24T09:05:00Z",
             "details": {"destination": "api.openai.com", "cred_id": "hmac:xyz", "reason": "user_denied"}},
            # 3) Agent retries — same credential, same host
            _credential_event(key="hmac:xyz", target="api.openai.com", ts="2026-03-24T09:06:00Z"),
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, resolved = scan_pending_approvals(log)
        assert pending == [], "denied credential should not re-appear after retry"
        assert "hmac:xyz:api.openai.com" in resolved

    def test_denied_one_does_not_suppress_different_key(self, tmp_path):
        """Denying one credential must not suppress an unrelated pending request."""
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:aaa", target="host1.com", ts="2026-03-24T09:00:00Z"),
            _credential_event(key="hmac:bbb", target="host2.com", ts="2026-03-24T09:01:00Z"),
            # Deny only aaa
            {"event": "admin.denial", "ts": "2026-03-24T09:05:00Z",
             "details": {"destination": "host1.com", "cred_id": "hmac:aaa", "reason": "user_denied"}},
            # aaa retries
            _credential_event(key="hmac:aaa", target="host1.com", ts="2026-03-24T09:06:00Z"),
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert len(pending) == 1
        assert pending[0]["approval"]["key"] == "hmac:bbb"

    def test_approved_then_retried_not_reprompted(self, tmp_path):
        """Same pattern but with approval instead of denial."""
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:xyz", target="api.openai.com", ts="2026-03-24T09:00:00Z"),
            {"event": "admin.approval_added", "ts": "2026-03-24T09:05:00Z",
             "details": {"destination": "api.openai.com", "cred_id": "hmac:xyz"}},
            # Retry after approval
            _credential_event(key="hmac:xyz", target="api.openai.com", ts="2026-03-24T09:06:00Z"),
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert pending == [], "approved credential should not re-appear after retry"

    def test_resolved_keys_returned_for_live_dedup(self, tmp_path):
        """Resolved keys are returned so callers can seed live-event dedup sets.

        Regression: the watch loop's seen_fingerprints was never seeded with
        resolved keys, so live retries of denied credentials were re-prompted.
        """
        log = tmp_path / "test.jsonl"
        events = [
            _credential_event(key="hmac:aaa", target="host1.com", ts="2026-03-24T09:00:00Z"),
            _credential_event(key="hmac:bbb", target="host2.com", ts="2026-03-24T09:01:00Z"),
            {"event": "admin.denial", "ts": "2026-03-24T09:05:00Z",
             "details": {"destination": "host1.com", "cred_id": "hmac:aaa", "reason": "user_denied"}},
            {"event": "admin.approval_added", "ts": "2026-03-24T09:06:00Z",
             "details": {"destination": "host2.com", "cred_id": "hmac:bbb"}},
        ]
        log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        pending, resolved = scan_pending_approvals(log)
        assert pending == []
        assert "hmac:aaa:host1.com" in resolved
        assert "hmac:bbb:host2.com" in resolved

    def test_unified_path_for_gateway_events(self, tmp_path):
        """Gateway events with approval field are collected via approval.required."""
        log = tmp_path / "test.jsonl"
        event = _gateway_event()
        log.write_text(json.dumps(event) + "\n")
        pending, _ = scan_pending_approvals(log)
        assert len(pending) == 1
        assert pending[0]["approval"]["approval_type"] == "gateway_route"


# ---------------------------------------------------------------------------
# _dedup_key_from_approval tests
# ---------------------------------------------------------------------------

class TestDedupKey:
    def test_credential(self):
        event = _credential_event(key="hmac:abc", target="api.openai.com")
        assert _dedup_key_from_approval(event) == "hmac:abc:api.openai.com"

    def test_gateway(self):
        event = _gateway_event(agent="a", service="s", method="GET", path="/x")
        assert _dedup_key_from_approval(event) == "gw:a:s:GET:/x:s"


# ---------------------------------------------------------------------------
# Batch table rendering (smoke test)
# ---------------------------------------------------------------------------

class TestBatchTableRendering:
    def test_renders_without_error(self):
        events = [
            _credential_event(),
            _gateway_event(irreversible=True, description="Delete all data"),
        ]
        items = build_batch_items(events)
        panel = _format_batch_table(items)
        assert panel is not None
        assert isinstance(panel, Panel)

        # Verify it can be rendered by a Console without error
        test_console = Console(file=io.StringIO(), width=120)
        test_console.print(panel)


# ---------------------------------------------------------------------------
# Sample events: network_egress, contract_binding, service
# ---------------------------------------------------------------------------

def _network_egress_event(host="cdn.example.com", agent="boris", ts="2026-04-04T12:00:00Z"):
    return {
        "event": "security.network_guard",
        "kind": "security",
        "decision": "require_approval",
        "host": host,
        "agent": agent,
        "ts": ts,
        "summary": f"Egress approval needed for {host}",
        "approval": {
            "required": True,
            "approval_type": "network_egress",
            "key": host,
            "target": host,
        },
        "details": {},
    }


def _contract_binding_event(
    agent="boris",
    service="gmail",
    capability="mail",
    template="send-only",
    bindings=None,
    grantable_ops=None,
    ts="2026-04-04T12:00:00Z",
):
    bindings = bindings or {"project": "acme"}
    grantable_ops = grantable_ops or ["send", "list"]
    return {
        "event": "gateway.contract_binding",
        "kind": "gateway",
        "decision": "require_approval",
        "host": "gmail.googleapis.com",
        "agent": agent,
        "ts": ts,
        "summary": f"Contract binding {service}/{capability}",
        "approval": {
            "required": True,
            "approval_type": "contract_binding",
            "key": f"{agent}:{service}:{capability}",
            "target": service,
            "scope_hint": {
                "capability": capability,
                "template": template,
                "bindings": bindings,
                "grantable_operations": grantable_ops,
            },
        },
        "details": {},
    }


def _service_event(agent="boris", service="gmail", capability="mail", ts="2026-04-04T12:00:00Z"):
    return {
        "event": "gateway.service_access",
        "kind": "gateway",
        "decision": "require_approval",
        "host": "gmail.googleapis.com",
        "agent": agent,
        "ts": ts,
        "summary": f"{agent} requests access to {service}",
        "approval": {
            "required": True,
            "approval_type": "service",
            "key": f"{agent}:{service}",
            "target": service,
            "scope_hint": {
                "capability": capability,
                "reason": "Agent needs mail access",
            },
        },
        "details": {},
    }


# ---------------------------------------------------------------------------
# TestRollingStats
# ---------------------------------------------------------------------------

class TestRollingStats:
    def test_initial_counts_are_zero(self):
        stats = RollingStats()
        assert stats.total_requests == 0
        assert stats.total_blocks == 0
        assert stats.total_warnings == 0
        assert stats.pending_approvals == 0

    def test_add_event_increments_request_count(self):
        stats = RollingStats()
        stats.add_event({"kind": "security", "decision": "allow"})
        assert stats.total_requests == 1
        assert stats.total_blocks == 0

    def test_add_deny_event_increments_block_count(self):
        stats = RollingStats()
        stats.add_event({"kind": "security", "decision": "deny"})
        assert stats.total_requests == 1
        assert stats.total_blocks == 1

    def test_add_approval_event_increments_pending(self):
        stats = RollingStats()
        stats.add_event({
            "kind": "security",
            "decision": "require_approval",
            "approval": {"required": True, "key": "hmac:abc", "target": "host.com"},
        })
        assert stats.pending_approvals == 1

    def test_dedup_by_fingerprint(self):
        stats = RollingStats()
        event = {
            "kind": "security",
            "decision": "require_approval",
            "approval": {"required": True, "key": "hmac:abc", "target": "host.com"},
        }
        stats.add_event(event)
        stats.add_event(event)  # same fingerprint
        assert stats.pending_approvals == 1

    def test_mark_resolved_decrements_pending(self):
        stats = RollingStats()
        stats.add_event({
            "kind": "security",
            "decision": "require_approval",
            "approval": {"required": True, "key": "hmac:abc", "target": "host.com"},
        })
        assert stats.pending_approvals == 1
        stats.mark_resolved("hmac:abc:host.com")
        assert stats.pending_approvals == 0

    def test_mark_resolved_does_not_go_negative(self):
        stats = RollingStats()
        stats.mark_resolved("nonexistent:key")
        assert stats.pending_approvals == 0

    def test_warn_event_increments_warnings(self):
        stats = RollingStats()
        stats.add_event({"kind": "security", "decision": "warn"})
        assert stats.total_warnings == 1
        assert stats.total_blocks == 0

    def test_non_security_event_ignored(self):
        stats = RollingStats()
        stats.add_event({"kind": "traffic", "decision": "allow"})
        assert stats.total_requests == 0


# ---------------------------------------------------------------------------
# TestResolvedKeyFromAdminEvent
# ---------------------------------------------------------------------------

class TestResolvedKeyFromAdminEvent:
    def test_credential_approval(self):
        event = {
            "event": "admin.approval_added",
            "details": {"destination": "api.openai.com", "cred_id": "hmac:abc"},
        }
        assert _resolved_key_from_admin_event(event) == "hmac:abc:api.openai.com"

    def test_credential_denial(self):
        event = {
            "event": "admin.denial",
            "details": {"destination": "api.openai.com", "cred_id": "hmac:abc", "reason": "user_denied"},
        }
        assert _resolved_key_from_admin_event(event) == "hmac:abc:api.openai.com"

    def test_gateway_grant(self):
        event = {
            "event": "admin.gateway_grant",
            "details": {"agent": "boris", "service": "gmail", "method": "POST", "path": "/send"},
        }
        assert _resolved_key_from_admin_event(event) == "gw:boris:gmail:POST:/send:gmail"

    def test_service_authorized(self):
        event = {
            "event": "admin.agent_service_authorized",
            "details": {"agent": "boris", "service": "gmail"},
        }
        assert _resolved_key_from_admin_event(event) == "boris:gmail:gmail"

    def test_service_revoked(self):
        event = {
            "event": "admin.agent_service_revoked",
            "details": {"agent": "boris", "service": "gmail"},
        }
        assert _resolved_key_from_admin_event(event) == "boris:gmail:gmail"

    def test_contract_binding_approved(self):
        event = {
            "event": "admin.contract_binding_approved",
            "details": {"agent": "boris", "service": "gmail", "capability": "mail"},
        }
        assert _resolved_key_from_admin_event(event) == "boris:gmail:mail:gmail"

    def test_host_allowed(self):
        event = {
            "event": "admin.host_allowed",
            "details": {"host": "cdn.example.com"},
        }
        assert _resolved_key_from_admin_event(event) == "cdn.example.com:cdn.example.com"

    def test_host_denied(self):
        event = {
            "event": "admin.host_denied",
            "details": {"host": "evil.com"},
        }
        assert _resolved_key_from_admin_event(event) == "evil.com:evil.com"

    def test_unknown_event_returns_none(self):
        event = {"event": "traffic.request", "details": {}}
        assert _resolved_key_from_admin_event(event) is None

    def test_missing_details_returns_none(self):
        event = {"event": "admin.approval_added", "details": {}}
        assert _resolved_key_from_admin_event(event) is None

    def test_gateway_denial_via_credential_path(self):
        """Gateway denial uses destination=gateway:service, cred_id=agent:method:path."""
        event = {
            "event": "admin.denial",
            "details": {
                "destination": "gateway:gmail",
                "cred_id": "boris:POST:/send",
                "reason": "user_denied",
            },
        }
        assert _resolved_key_from_admin_event(event) == "gw:boris:gmail:POST:/send:gmail"


# ---------------------------------------------------------------------------
# TestHostToDomain
# ---------------------------------------------------------------------------

class TestHostToDomain:
    def test_three_part_host(self):
        assert _host_to_domain("api.stripe.com") == "*.stripe.com"

    def test_two_part_host(self):
        assert _host_to_domain("example.com") == "*.example.com"

    def test_deeply_nested_host(self):
        assert _host_to_domain("a.b.c.d.example.com") == "*.b.c.d.example.com"


# ---------------------------------------------------------------------------
# TestParseDuration
# ---------------------------------------------------------------------------

class TestParseDuration:
    def test_valid_1h(self):
        result = _parse_duration("1h")
        assert result is not None
        # Should be a valid ISO datetime string
        assert "T" in result

    def test_valid_7d(self):
        result = _parse_duration("7d")
        assert result is not None
        assert "T" in result

    def test_unknown_code_returns_none(self):
        assert _parse_duration("2h") is None
        assert _parse_duration("3d") is None

    def test_permanent_returns_none(self):
        assert _parse_duration("permanent") is None


# ---------------------------------------------------------------------------
# TestRiskyRouteDedup
# ---------------------------------------------------------------------------

class TestRiskyRouteDedupKey:
    def test_key_format(self):
        event = _gateway_event(agent="boris", service="gmail", method="POST", path="/messages/send")
        key = _risky_route_dedup_key(event)
        assert key == "gw:boris:gmail:POST:/messages/send"

    def test_missing_fields_produce_empty_segments(self):
        event = {"details": {}, "agent": ""}
        key = _risky_route_dedup_key(event)
        assert key == "gw::::"


# ---------------------------------------------------------------------------
# New dispatch format_row tests for egress, contract_binding, service
# ---------------------------------------------------------------------------

class TestNetworkEgressFormatRow:
    def test_format_row_fields(self):
        event = _network_egress_event(host="cdn.example.com")
        agent, action, risk, desc = _network_egress_format_row(event)
        assert agent == "boris"
        assert "cdn.example.com" in action
        assert risk == "network access"

    def test_format_row_fallback_agent(self):
        event = _network_egress_event()
        del event["agent"]
        agent, _, _, _ = _network_egress_format_row(event)
        assert agent == "\u2014"


class TestContractBindingFormatRow:
    def test_format_row_with_bindings(self):
        event = _contract_binding_event(
            service="gmail", capability="mail", bindings={"project": "acme"}
        )
        agent, action, risk, desc = _contract_binding_format_row(event)
        assert agent == "boris"
        assert "gmail/mail" in action
        assert "acme" in action
        assert risk == "contract binding"

    def test_format_row_no_capability(self):
        event = _contract_binding_event(capability="")
        agent, action, risk, _ = _contract_binding_format_row(event)
        assert "gmail" in action


class TestServiceFormatRow:
    def test_format_row_with_capability(self):
        event = _service_event(service="gmail", capability="mail")
        agent, action, risk, desc = _service_format_row(event)
        assert agent == "boris"
        assert "gmail/mail" in action
        assert risk == "service access"

    def test_format_row_without_capability(self):
        event = _service_event(capability="")
        event["approval"]["scope_hint"]["capability"] = ""
        agent, action, _, _ = _service_format_row(event)
        assert action == "gmail"


# ---------------------------------------------------------------------------
# Dispatch approve/deny tests for egress, contract_binding, service
# ---------------------------------------------------------------------------

class TestNetworkEgressDispatch:
    def test_approve_calls_allow_host(self):
        api = MagicMock()
        api.allow_host.return_value = {"status": "ok"}
        event = _network_egress_event(host="cdn.example.com")
        dispatch = DISPATCH["network_egress"]
        result = dispatch.approve(event, api)
        assert result == "ok"
        api.allow_host.assert_called_once_with(host="cdn.example.com", rate=600)

    def test_deny_calls_deny_host(self):
        api = MagicMock()
        event = _network_egress_event(host="cdn.example.com")
        dispatch = DISPATCH["network_egress"]
        dispatch.deny(event, api)
        api.deny_host.assert_called_once()
        call_kwargs = api.deny_host.call_args[1]
        assert call_kwargs["host"] == "cdn.example.com"
        assert call_kwargs["expires"] is not None


class TestContractBindingDispatch:
    def test_approve_calls_api(self):
        api = MagicMock()
        api.approve_contract_binding.return_value = {"status": "bound"}
        event = _contract_binding_event(
            agent="boris", service="gmail", capability="mail",
            template="send-only", bindings={"project": "acme"},
            grantable_ops=["send"],
        )
        dispatch = DISPATCH["contract_binding"]
        result = dispatch.approve(event, api)
        assert result == "bound"
        api.approve_contract_binding.assert_called_once_with(
            agent="boris",
            service="gmail",
            capability="mail",
            template="send-only",
            bindings={"project": "acme"},
            grantable_operations=["send"],
        )

    def test_approve_missing_agent_raises(self):
        api = MagicMock()
        event = _contract_binding_event()
        event["agent"] = ""
        dispatch = DISPATCH["contract_binding"]
        with pytest.raises(NotImplementedError, match="missing"):
            dispatch.approve(event, api)

    def test_deny_calls_log_denial(self):
        api = MagicMock()
        event = _contract_binding_event(agent="boris", service="gmail")
        dispatch = DISPATCH["contract_binding"]
        dispatch.deny(event, api)
        api.log_denial.assert_called_once_with(
            destination="gateway:gmail",
            cred_id="boris:contract_binding",
            reason="user_denied",
        )


class TestServiceDispatch:
    def test_deny_calls_log_denial(self):
        api = MagicMock()
        event = _service_event(agent="boris", service="gmail")
        dispatch = DISPATCH["service"]
        dispatch.deny(event, api)
        api.log_denial.assert_called_once_with(
            destination="gateway:gmail",
            cred_id="boris:service_access",
            reason="user_denied",
        )


# ---------------------------------------------------------------------------
# Batch table rendering: additional checks
# ---------------------------------------------------------------------------

class TestBatchTableRenderingExtended:
    def test_irreversible_marker_in_output(self):
        events = [_gateway_event(irreversible=True)]
        items = build_batch_items(events)
        test_console = Console(file=io.StringIO(), width=120)
        panel = _format_batch_table(items)
        test_console.print(panel)
        output = test_console.file.getvalue()
        assert "IRREVERSIBLE" in output

    def test_service_item_rendered_differently(self):
        events = [_service_event()]
        items = build_batch_items(events)
        test_console = Console(file=io.StringIO(), width=120)
        panel = _format_batch_table(items)
        test_console.print(panel)
        output = test_console.file.getvalue()
        assert "authenticated access" in output

    def test_network_egress_in_batch(self):
        events = [_network_egress_event()]
        items = build_batch_items(events)
        test_console = Console(file=io.StringIO(), width=120)
        panel = _format_batch_table(items)
        test_console.print(panel)
        output = test_console.file.getvalue()
        assert "cdn.example.com" in output
