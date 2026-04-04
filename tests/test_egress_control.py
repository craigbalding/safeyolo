"""Tests for egress control feature — egress field, 428 responses, expires pruning."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# =========================================================================
# Policy compiler — egress field
# =========================================================================


class TestEgressCompilation:
    """Test that the egress field compiles to correct permissions."""

    def _compile(self, egress_value=None, **extra):
        from policy_compiler import compile_policy

        wildcard = {"unknown_credentials": "prompt", "rate_limit": 600}
        if egress_value is not None:
            wildcard["egress"] = egress_value
        wildcard.update(extra)
        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
                "*": wildcard,
            },
            "required": [],
            "addons": {},
            "scan_patterns": [],
        }
        return compile_policy(raw)

    def _network_wildcard_perms(self, result):
        return [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p["resource"] == "*"
        ]

    def test_egress_prompt_compiles_to_prompt_permission(self):
        result = self._compile("prompt")
        perms = self._network_wildcard_perms(result)
        effects = {p["effect"] for p in perms}
        assert "prompt" in effects

    def test_egress_deny_compiles_to_deny_permission(self):
        result = self._compile("deny")
        perms = self._network_wildcard_perms(result)
        effects = {p["effect"] for p in perms}
        assert "deny" in effects

    def test_egress_allow_no_prompt_or_deny(self):
        result = self._compile("allow")
        perms = self._network_wildcard_perms(result)
        effects = {p["effect"] for p in perms}
        assert "prompt" not in effects
        assert "deny" not in effects

    def test_egress_absent_no_prompt_or_deny(self):
        result = self._compile()
        perms = self._network_wildcard_perms(result)
        effects = {p["effect"] for p in perms}
        assert "prompt" not in effects
        assert "deny" not in effects

    def test_egress_independent_of_credential_prompt(self):
        """egress and on_unknown produce separate permissions."""
        result = self._compile("prompt")
        cred_prompts = [
            p for p in result["permissions"]
            if p["action"] == "credential:use" and p["effect"] == "prompt"
        ]
        net_prompts = [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p["effect"] == "prompt"
        ]
        assert len(cred_prompts) == 1
        assert len(net_prompts) == 1

    def test_named_hosts_still_compile_with_egress(self):
        """Named hosts get their own permissions regardless of egress."""
        result = self._compile("prompt")
        openai_perms = [
            p for p in result["permissions"]
            if "api.openai.com" in p["resource"]
        ]
        assert len(openai_perms) > 0


# =========================================================================
# Network guard — 428 on REQUIRE_APPROVAL
# =========================================================================


class TestNetworkGuardEgressApproval:
    """Test that network_guard returns 428 for egress approval."""

    @pytest.fixture
    def network_guard(self):
        from network_guard import NetworkGuard
        ng = NetworkGuard()
        return ng

    def test_require_approval_blocks_with_428(self, network_guard, make_flow):
        """REQUIRE_APPROVAL from PDP triggers 428 block."""
        from pdp.schemas import Effect

        flow = make_flow("http://unknown-host.com/api")

        mock_decision = MagicMock()
        mock_decision.effect = Effect.REQUIRE_APPROVAL
        mock_decision.reason = "egress prompt"
        mock_decision.budget = None

        with (
            patch("network_guard.get_policy_client") as mock_client,
            patch("base.write_event"),
        ):
            mock_client.return_value.evaluate.return_value = mock_decision
            network_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        assert b"egress_approval_required" in flow.response.content

    def test_require_approval_emits_approval_event(self, network_guard, make_flow):
        """REQUIRE_APPROVAL emits an audit event with approval metadata."""
        from pdp.schemas import Effect

        flow = make_flow("http://unknown-host.com/api")

        mock_decision = MagicMock()
        mock_decision.effect = Effect.REQUIRE_APPROVAL
        mock_decision.reason = "egress prompt"
        mock_decision.budget = None

        with (
            patch("network_guard.get_policy_client") as mock_client,
            patch("base.write_event") as mock_write,
        ):
            mock_client.return_value.evaluate.return_value = mock_decision
            network_guard.request(flow)

        # Find the security event
        calls = [c for c in mock_write.call_args_list if c[0][0] == "security.network_guard"]
        assert len(calls) >= 1
        call_kwargs = calls[-1][1]
        assert call_kwargs["decision"] == "require_approval"
        assert call_kwargs["approval"] is not None
        assert call_kwargs["approval"].approval_type == "network_egress"


# =========================================================================
# Expires pruning
# =========================================================================


class TestExpiresPruning:
    """Test that expired host entries get pruned on policy reload."""

    def test_expired_host_removed_from_raw(self, tmp_path):
        from policy_loader import PolicyLoader

        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        baseline = tmp_path / "policy.yaml"
        baseline.write_text(f"""
hosts:
  api.openai.com: {{rate_limit: 3000}}
  expired-host.com: {{egress: deny, expires: "{past}"}}
  future-host.com: {{egress: deny, expires: "{future}"}}
  "*": {{unknown_credentials: prompt, rate_limit: 600}}
required: []
addons:
  credential_guard: {{enabled: true}}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)

        # expired-host.com should be gone, future-host.com should remain
        # Simple deny permissions live in the index sets, not Permission objects
        simple_sets, _, _ = loader.get_merged_index()
        deny_resources = simple_sets.get(("network:request", "deny"), set())
        all_perm_resources = {p.resource for p in loader.baseline.permissions}
        assert "expired-host.com/*" not in deny_resources
        assert "expired-host.com/*" not in all_perm_resources
        assert "future-host.com/*" in deny_resources

    def test_host_without_expires_unaffected(self, tmp_path):
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com: {rate_limit: 3000}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        resources = {p.resource for p in policy.permissions}
        assert "api.openai.com/*" in resources
