"""Tests for agent-level egress posture — per-agent default deny/prompt."""

import tempfile
import threading
from pathlib import Path

import yaml


class TestAgentEgressCompilation:
    """Test that agents.<name>.egress compiles to catch-all permission."""

    def _compile(self, agents, hosts=None):
        from policy_compiler import compile_policy

        raw = {
            "hosts": hosts or {"*": {"unknown_credentials": "prompt", "rate_limit": 600}},
            "agents": agents,
            "required": [],
            "addons": {},
            "scan_patterns": [],
        }
        return compile_policy(raw)

    def test_agent_egress_deny(self):
        result = self._compile({"boris": {"egress": "deny"}})
        perms = [
            p for p in result["permissions"]
            if p["resource"] == "*" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["effect"] == "deny"

    def test_agent_egress_prompt(self):
        result = self._compile({"boris": {"egress": "prompt"}})
        perms = [
            p for p in result["permissions"]
            if p["resource"] == "*" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["effect"] == "prompt"

    def test_agent_egress_allow_no_permission(self):
        """egress = allow doesn't emit a catch-all permission."""
        result = self._compile({"boris": {"egress": "allow"}})
        perms = [
            p for p in result["permissions"]
            if p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 0

    def test_agent_egress_absent_no_permission(self):
        """No egress field doesn't emit a catch-all permission."""
        result = self._compile({"boris": {"hosts": {"x.com": {"rate_limit": 100}}}})
        catch_all = [
            p for p in result["permissions"]
            if p["resource"] == "*" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(catch_all) == 0

    def test_agent_egress_with_hosts(self):
        """Agent egress + hosts: both catch-all and per-host permissions emitted."""
        result = self._compile({
            "boris": {
                "egress": "deny",
                "hosts": {"api.stripe.com": {"rate_limit": 600}},
            },
        })
        boris_perms = [
            p for p in result["permissions"]
            if p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(boris_perms) == 2  # catch-all deny + stripe budget


class TestAgentEgressEvaluation:
    """Test evaluation with agent-level egress posture."""

    def _make_engine(self, hosts, agents):
        from budget_tracker import GCRABudgetTracker
        from policy_engine import PolicyEngine
        from policy_loader import PolicyLoader

        raw = {
            "hosts": hosts,
            "agents": agents,
            "required": [],
            "addons": {"credential_guard": {"enabled": True}},
            "scan_patterns": [],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(raw, f, sort_keys=False)
            path = Path(f.name)

        loader = PolicyLoader(baseline_path=path)
        engine = PolicyEngine.__new__(PolicyEngine)
        engine._loader = loader
        engine._evaluations = 0
        engine._lock = threading.RLock()
        engine._budget_tracker = GCRABudgetTracker()
        return engine

    def test_locked_agent_allowed_host(self):
        """Agent with egress=deny can reach its own allowed hosts."""
        engine = self._make_engine(
            hosts={"*": {"unknown_credentials": "prompt", "rate_limit": 600}},
            agents={"boris": {"egress": "deny", "hosts": {"api.stripe.com": {"rate_limit": 600}}}},
        )
        d = engine.evaluate_request("api.stripe.com", agent="boris")
        assert d.effect == "allow"

    def test_locked_agent_unknown_host_denied(self):
        """Agent with egress=deny can't reach unlisted hosts."""
        engine = self._make_engine(
            hosts={"*": {"egress": "allow", "unknown_credentials": "prompt", "rate_limit": 600}},
            agents={"boris": {"egress": "deny"}},
        )
        d = engine.evaluate_request("random-site.com", agent="boris")
        assert d.effect == "deny"

    def test_locked_agent_proxy_wide_explicit_still_works(self):
        """Proxy-wide explicit host entries still accessible (higher specificity)."""
        engine = self._make_engine(
            hosts={
                "api.openai.com": {"rate_limit": 3000},
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            },
            agents={"boris": {"egress": "deny"}},
        )
        d = engine.evaluate_request("api.openai.com", agent="boris")
        assert d.effect == "allow"

    def test_open_agent_unaffected(self):
        """Agent without egress restriction uses proxy-wide policy."""
        engine = self._make_engine(
            hosts={"*": {"egress": "allow", "unknown_credentials": "prompt", "rate_limit": 600}},
            agents={"boris": {"egress": "deny"}},
        )
        # Alice has no agent config — proxy-wide allows
        d = engine.evaluate_request("random-site.com", agent="alice")
        assert d.effect == "allow"
