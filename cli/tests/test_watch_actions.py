"""Tests for watch command — ActionDispatch, action hints, and micro-prompts."""

from unittest.mock import MagicMock, patch

import pytest

from safeyolo.commands.watch import (
    ACTION_DISPATCH,
    ActionDispatch,
    _contract_binding_approve,
    _contract_binding_deny,
    _default_bump_rate,
    _hint_access_denied,
    _hint_budget_exceeded,
    _hint_circuit_open,
    _hint_pattern_block,
    _match_access_denied,
    _match_budget_exceeded,
    _match_circuit_open,
    _match_pattern_block,
    _network_egress_approve,
    _network_egress_deny,
    _print_event_summary,
    _service_deny,
    build_action_map,
    find_action_dispatch,
    format_action_help,
    handle_action_key,
)
from safeyolo.commands.watch import (
    DISPATCH as APPROVAL_DISPATCH,
)

# ---------------------------------------------------------------------------
# Sample events
# ---------------------------------------------------------------------------

def _budget_exceeded_event(host="api.openai.com", rate=3000):
    return {
        "event": "security.network_guard",
        "kind": "security",
        "decision": "budget_exceeded",
        "host": host,
        "severity": "high",
        "ts": "2026-04-03T10:23:16Z",
        "summary": f"Rate limit exceeded for {host} ({rate}/min)",
        "details": {"budget": rate, "host": host},
    }


def _access_denied_event(host="cdn.example.com"):
    return {
        "event": "security.network_guard",
        "kind": "security",
        "decision": "deny",
        "host": host,
        "severity": "high",
        "ts": "2026-04-03T10:24:00Z",
        "summary": f"Access denied for {host}",
        "details": {"host": host, "reason": "not in policy"},
    }


def _circuit_open_event(host="api.slack.com"):
    return {
        "event": "ops.circuit_breaker.open",
        "kind": "ops",
        "host": host,
        "ts": "2026-04-03T10:25:00Z",
        "summary": f"Circuit opened for {host}",
        "details": {"host": host},
    }


def _pattern_block_event(host="api.internal.com"):
    return {
        "event": "security.pattern_scanner",
        "kind": "security",
        "decision": "deny",
        "host": host,
        "severity": "high",
        "ts": "2026-04-03T10:26:00Z",
        "summary": f"Pattern blocked for {host}",
        "details": {"host": host, "pattern": "SSN"},
    }


def _allow_event(host="api.openai.com"):
    return {
        "event": "security.network_guard",
        "kind": "security",
        "decision": "allow",
        "host": host,
        "ts": "2026-04-03T10:27:00Z",
        "summary": f"Allowed {host}",
    }


# ---------------------------------------------------------------------------
# Event matching tests
# ---------------------------------------------------------------------------


class TestEventMatching:
    """Test ActionDispatch event matchers."""

    def test_match_budget_exceeded(self):
        assert _match_budget_exceeded(_budget_exceeded_event())
        assert not _match_budget_exceeded(_access_denied_event())
        assert not _match_budget_exceeded(_allow_event())

    def test_match_access_denied(self):
        assert _match_access_denied(_access_denied_event())
        assert not _match_access_denied(_budget_exceeded_event())

    def test_match_circuit_open(self):
        assert _match_circuit_open(_circuit_open_event())
        assert not _match_circuit_open(_budget_exceeded_event())

    def test_match_pattern_block(self):
        assert _match_pattern_block(_pattern_block_event())
        assert not _match_pattern_block(_access_denied_event())

    def test_no_match_for_allow(self):
        assert find_action_dispatch(_allow_event()) is None


class TestFindActionDispatch:
    """Test find_action_dispatch returns correct dispatch."""

    def test_budget_exceeded_dispatch(self):
        dispatch = find_action_dispatch(_budget_exceeded_event())
        assert dispatch is not None
        assert len(dispatch.actions) == 2
        keys = {a.key for a in dispatch.actions}
        assert keys == {"b", "r"}

    def test_access_denied_dispatch(self):
        dispatch = find_action_dispatch(_access_denied_event())
        assert dispatch is not None
        assert len(dispatch.actions) == 1
        assert dispatch.actions[0].key == "h"

    def test_circuit_open_dispatch(self):
        dispatch = find_action_dispatch(_circuit_open_event())
        assert dispatch is not None
        assert len(dispatch.actions) == 1
        assert dispatch.actions[0].key == "x"

    def test_pattern_block_dispatch(self):
        dispatch = find_action_dispatch(_pattern_block_event())
        assert dispatch is not None
        assert len(dispatch.actions) == 1
        assert dispatch.actions[0].key == "s"


class TestBuildActionMap:
    """Test build_action_map creates correct key mapping."""

    def test_budget_exceeded_map(self):
        event = _budget_exceeded_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)
        assert "b" in action_map
        assert "r" in action_map
        assert action_map["b"][0] is event
        assert action_map["r"][0] is event


# ---------------------------------------------------------------------------
# Hint formatting tests
# ---------------------------------------------------------------------------


class TestHintFormatting:
    """Test action hint strings."""

    def test_budget_exceeded_hint(self):
        hint = _hint_budget_exceeded(_budget_exceeded_event())
        assert "bump rate" in hint
        assert "reset" in hint

    def test_access_denied_hint(self):
        hint = _hint_access_denied(_access_denied_event())
        assert "allow host" in hint

    def test_circuit_open_hint(self):
        hint = _hint_circuit_open(_circuit_open_event())
        assert "reset circuit" in hint

    def test_pattern_block_hint(self):
        hint = _hint_pattern_block(_pattern_block_event())
        assert "suppress pattern" in hint


class TestDefaultBumpRate:
    """Test default value calculation for rate bump."""

    def test_doubles_current_rate(self):
        event = _budget_exceeded_event(rate=3000)
        assert _default_bump_rate(event) == "6000"

    def test_fallback_when_no_rate(self):
        event = {"details": {}}
        assert _default_bump_rate(event) == "6000"


# ---------------------------------------------------------------------------
# Event summary with hints
# ---------------------------------------------------------------------------


class TestPrintEventSummaryWithHints:
    """Test _print_event_summary returns ActionDispatch when show_hints=True."""

    def test_returns_dispatch_for_actionable(self):
        result = _print_event_summary(_budget_exceeded_event(), show_hints=True)
        assert result is not None
        assert isinstance(result, ActionDispatch)

    def test_returns_none_for_non_actionable(self):
        result = _print_event_summary(_allow_event(), show_hints=True)
        assert result is None

    def test_returns_none_when_hints_disabled(self):
        result = _print_event_summary(_budget_exceeded_event(), show_hints=False)
        assert result is None


# ---------------------------------------------------------------------------
# Action key handling
# ---------------------------------------------------------------------------


class TestHandleActionKey:
    """Test handle_action_key dispatches correctly."""

    def test_help_key(self):
        """? key shows help and returns True."""
        result = handle_action_key("?", {}, MagicMock())
        assert result is True

    def test_unknown_key_returns_false(self):
        result = handle_action_key("z", {}, MagicMock())
        assert result is False

    def test_instant_action(self):
        """Instant actions execute immediately."""
        api = MagicMock()
        api.reset_budget.return_value = {"status": "reset"}

        event = _budget_exceeded_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("r", action_map, api)
        assert result is True
        api.reset_budget.assert_called_once()

    def test_instant_circuit_reset(self):
        """Circuit reset executes immediately."""
        api = MagicMock()
        api.reset_circuit.return_value = {"status": "reset"}

        event = _circuit_open_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("x", action_map, api)
        assert result is True
        api.reset_circuit.assert_called_once_with(host="api.slack.com")

    @patch("safeyolo.commands.watch.console")
    def test_explicit_action_confirmed(self, mock_console):
        """Explicit actions prompt and execute on 'y'."""
        api = MagicMock()
        api.allow_host.return_value = {"status": "added", "host": "cdn.example.com", "rate": 600}
        mock_console.input.return_value = "y"

        event = _access_denied_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("h", action_map, api)
        assert result is True
        api.allow_host.assert_called_once()

    @patch("safeyolo.commands.watch.console")
    def test_explicit_action_declined(self, mock_console):
        """Explicit actions don't execute when declined."""
        api = MagicMock()
        mock_console.input.return_value = "n"

        event = _access_denied_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("h", action_map, api)
        assert result is True
        api.allow_host.assert_not_called()

    @patch("safeyolo.commands.watch.console")
    def test_value_action_with_input(self, mock_console):
        """Value actions prompt for input and execute."""
        api = MagicMock()
        api.update_host_rate.return_value = {"status": "updated", "old_rate": 3000, "new_rate": 6000}
        mock_console.input.return_value = "6000"

        event = _budget_exceeded_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("b", action_map, api)
        assert result is True
        api.update_host_rate.assert_called_once_with(host="api.openai.com", rate=6000)

    @patch("safeyolo.commands.watch.console")
    def test_value_action_uses_default(self, mock_console):
        """Value actions use default when input is empty."""
        api = MagicMock()
        api.update_host_rate.return_value = {"status": "updated", "old_rate": 3000, "new_rate": 6000}
        mock_console.input.return_value = ""  # empty -> use default

        event = _budget_exceeded_event(rate=3000)
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("b", action_map, api)
        assert result is True
        api.update_host_rate.assert_called_once_with(host="api.openai.com", rate=6000)

    @patch("safeyolo.commands.watch.console")
    def test_suppress_pattern_confirmed(self, mock_console):
        """Pattern suppress prompts and executes on 'y'."""
        api = MagicMock()
        api.add_host_bypass.return_value = {"status": "updated", "host": "api.internal.com", "bypass": ["pattern-scanner"]}
        mock_console.input.return_value = "y"

        event = _pattern_block_event()
        dispatch = find_action_dispatch(event)
        action_map = build_action_map(event, dispatch)

        result = handle_action_key("s", action_map, api)
        assert result is True
        api.add_host_bypass.assert_called_once_with(host="api.internal.com", addon="pattern-scanner")


class TestFormatActionHelp:
    """Test help overlay formatting."""

    def test_contains_all_action_keys(self):
        help_text = format_action_help()
        for dispatch in ACTION_DISPATCH:
            for action in dispatch.actions:
                assert action.key in help_text
                assert action.label in help_text

    def test_contains_help_key(self):
        help_text = format_action_help()
        assert "?" in help_text


# ---------------------------------------------------------------------------
# Registry completeness
# ---------------------------------------------------------------------------


class TestActionDispatchRegistry:
    """Test ACTION_DISPATCH registry is well-formed."""

    def test_no_duplicate_keys(self):
        """All action keys across all dispatches are unique."""
        all_keys = []
        for dispatch in ACTION_DISPATCH:
            for action in dispatch.actions:
                all_keys.append(action.key)
        assert len(all_keys) == len(set(all_keys)), f"Duplicate keys: {all_keys}"

    def test_all_dispatches_have_actions(self):
        for dispatch in ACTION_DISPATCH:
            assert len(dispatch.actions) >= 1

    def test_all_confirm_types_valid(self):
        valid = {"instant", "value", "explicit"}
        for dispatch in ACTION_DISPATCH:
            for action in dispatch.actions:
                assert action.confirm in valid, f"Invalid confirm type: {action.confirm}"


# ---------------------------------------------------------------------------
# Approval dispatch tests: network_egress, contract_binding, service
# (These test the ApprovalDispatch registry in DISPATCH, separate from
# ActionDispatch above which handles non-approval event actions.)
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


class TestNetworkEgressApprovalDispatch:
    """Tests for network_egress approve/deny in the DISPATCH registry."""

    def test_approve_calls_allow_host(self):
        api = MagicMock()
        api.allow_host.return_value = {"status": "ok"}
        event = _network_egress_event(host="cdn.example.com")
        result = _network_egress_approve(event, api)
        assert result == "ok"
        api.allow_host.assert_called_once_with(host="cdn.example.com", rate=600)

    def test_deny_calls_deny_host_with_expires(self):
        api = MagicMock()
        event = _network_egress_event(host="cdn.example.com")
        _network_egress_deny(event, api)
        api.deny_host.assert_called_once()
        call_kwargs = api.deny_host.call_args[1]
        assert call_kwargs["host"] == "cdn.example.com"
        # Expires should be an ISO timestamp string (not None)
        assert "T" in call_kwargs["expires"]

    def test_dispatch_registry_has_network_egress(self):
        assert "network_egress" in APPROVAL_DISPATCH


class TestContractBindingApprovalDispatch:
    """Tests for contract_binding approve/deny in the DISPATCH registry."""

    def test_approve_calls_approve_contract_binding(self):
        api = MagicMock()
        api.approve_contract_binding.return_value = {"status": "bound"}
        event = _contract_binding_event(
            agent="boris", service="gmail", capability="mail",
            template="send-only", bindings={"project": "acme"},
            grantable_ops=["send"],
        )
        result = _contract_binding_approve(event, api)
        assert result == "bound"
        api.approve_contract_binding.assert_called_once_with(
            agent="boris",
            service="gmail",
            capability="mail",
            template="send-only",
            bindings={"project": "acme"},
            grantable_operations=["send"],
        )

    def test_approve_missing_capability_raises(self):
        api = MagicMock()
        event = _contract_binding_event(capability="")
        event["approval"]["scope_hint"]["capability"] = ""
        with pytest.raises(NotImplementedError, match="missing"):
            _contract_binding_approve(event, api)

    def test_deny_calls_log_denial(self):
        api = MagicMock()
        event = _contract_binding_event(agent="boris", service="gmail")
        _contract_binding_deny(event, api)
        api.log_denial.assert_called_once_with(
            destination="gateway:gmail",
            cred_id="boris:contract_binding",
            reason="user_denied",
        )


class TestServiceApprovalDispatch:
    """Tests for service approve/deny in the DISPATCH registry."""

    def test_deny_calls_log_denial(self):
        api = MagicMock()
        event = _service_event(agent="boris", service="gmail")
        _service_deny(event, api)
        api.log_denial.assert_called_once_with(
            destination="gateway:gmail",
            cred_id="boris:service_access",
            reason="user_denied",
        )

    def test_dispatch_registry_has_service(self):
        assert "service" in APPROVAL_DISPATCH

    def test_dispatch_registry_has_contract_binding(self):
        assert "contract_binding" in APPROVAL_DISPATCH
