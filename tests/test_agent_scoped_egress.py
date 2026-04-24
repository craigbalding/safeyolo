"""Tests for agent-scoped egress — per-agent host entries in policy."""




class TestAgentHostsCompilation:
    """Test that agents.<name>.hosts compiles to permissions with agent condition."""

    def _compile(self, agents, hosts=None):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": hosts or {"*": {"unknown_credentials": "prompt", "rate_limit": 600}},
            "agents": agents,
            "required": [],
            "addons": {},
            "scan_patterns": [],
        }
        return compile_policy(raw)

    def test_agent_host_rate_limit(self):
        result = self._compile({"boris": {"hosts": {"api.stripe.com": {"rate_limit": 600}}}})
        perms = [
            p for p in result["permissions"]
            if p["resource"] == "api.stripe.com/*" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["effect"] == "budget"
        assert perms[0]["budget"] == 600

    def test_agent_host_egress_deny(self):
        result = self._compile({"boris": {"hosts": {"sketchy.io": {"egress": "deny"}}}})
        perms = [
            p for p in result["permissions"]
            if p["resource"] == "sketchy.io/*" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["effect"] == "deny"

    def test_agent_host_credentials(self):
        result = self._compile({
            "boris": {"hosts": {"api.stripe.com": {"credentials": ["stripe:*"]}}},
        })
        perms = [
            p for p in result["permissions"]
            if p["action"] == "credential:use" and p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["condition"]["credential"] == ["stripe:*"]

    def test_multiple_agents(self):
        result = self._compile({
            "boris": {"hosts": {"api.stripe.com": {"rate_limit": 600}}},
            "alice": {"hosts": {"api.github.com": {"rate_limit": 300}}},
        })
        boris_perms = [p for p in result["permissions"] if p.get("condition", {}).get("agent") == "boris"]
        alice_perms = [p for p in result["permissions"] if p.get("condition", {}).get("agent") == "alice"]
        assert len(boris_perms) == 1
        assert len(alice_perms) == 1

    def test_agent_without_hosts_section(self):
        """Agents with services but no hosts don't produce host permissions."""
        result = self._compile({
            "boris": {"template": "claude-code", "folder": "/tmp/proj"},
        })
        agent_perms = [p for p in result["permissions"] if p.get("condition", {}).get("agent") == "boris"]
        assert len(agent_perms) == 0


class TestAgentScopedEvaluation:
    """Test that agent-scoped permissions are evaluated correctly."""

    def _make_engine(self, hosts, agents):
        import tempfile
        from pathlib import Path

        import yaml

        from safeyolo.policy.loader import PolicyLoader

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
        return loader._baseline, loader

    def test_boris_matches_agent_entry(self):
        """Boris gets allowed for his agent-scoped host."""
        policy, loader = self._make_engine(
            hosts={"*": {"unknown_credentials": "prompt", "rate_limit": 600, "egress": "prompt"}},
            agents={"boris": {"hosts": {"api.stripe.com": {"rate_limit": 600}}}},
        )
        from safeyolo.policy.engine import PolicyEngine

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._loader = loader
        engine._evaluations = 0
        engine._lock = __import__("threading").RLock()
        from safeyolo.policy.budget_tracker import GCRABudgetTracker
        engine._budget_tracker = GCRABudgetTracker()

        decision = engine.evaluate_request("api.stripe.com", agent="boris")
        assert decision.effect == "allow"

    def test_alice_falls_through_to_wildcard(self):
        """Alice has no agent entry for stripe — falls through to proxy-wide prompt."""
        policy, loader = self._make_engine(
            hosts={"*": {"unknown_credentials": "prompt", "rate_limit": 600, "egress": "prompt"}},
            agents={"boris": {"hosts": {"api.stripe.com": {"rate_limit": 600}}}},
        )
        from safeyolo.policy.engine import PolicyEngine

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._loader = loader
        engine._evaluations = 0
        engine._lock = __import__("threading").RLock()
        from safeyolo.policy.budget_tracker import GCRABudgetTracker
        engine._budget_tracker = GCRABudgetTracker()

        decision = engine.evaluate_request("api.stripe.com", agent="alice")
        # Alice has no agent entry — falls through to wildcard egress=prompt
        assert decision.effect == "prompt"

    def test_agent_deny_overrides_proxy_wide(self):
        """Agent deny beats proxy-wide allow for the same host."""
        policy, loader = self._make_engine(
            hosts={
                "api.stripe.com": {"rate_limit": 600},
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            },
            agents={"boris": {"hosts": {"api.stripe.com": {"egress": "deny"}}}},
        )
        from safeyolo.policy.engine import PolicyEngine

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._loader = loader
        engine._evaluations = 0
        engine._lock = __import__("threading").RLock()
        from safeyolo.policy.budget_tracker import GCRABudgetTracker
        engine._budget_tracker = GCRABudgetTracker()

        # Boris: agent deny wins
        decision = engine.evaluate_request("api.stripe.com", agent="boris")
        assert decision.effect == "deny"

        # Alice: no agent entry, proxy-wide allows
        decision = engine.evaluate_request("api.stripe.com", agent="alice")
        assert decision.effect == "allow"


class TestTomlNormalizeAgentHosts:
    """Test that agents.<name>.hosts fields get normalized."""

    def test_normalize_agent_hosts(self):
        from safeyolo.policy.toml_normalize import normalize

        doc = {
            "version": "2.0",
            "hosts": {"api.openai.com": {"allow": ["openai:*"], "rate": 3000}},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.stripe.com": {"allow": ["stripe:*"], "rate": 600},
                    }
                }
            },
        }
        result = normalize(doc)
        # Top-level hosts normalized
        assert "credentials" in result["hosts"]["api.openai.com"]
        assert "rate_limit" in result["hosts"]["api.openai.com"]
        # Agent hosts also normalized
        agent_host = result["agents"]["boris"]["hosts"]["api.stripe.com"]
        assert "credentials" in agent_host
        assert "rate_limit" in agent_host

    def test_denormalize_agent_hosts(self):
        from safeyolo.policy.toml_normalize import denormalize

        doc = {
            "metadata": {"version": "2.0"},
            "hosts": {"api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000}},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.stripe.com": {"credentials": ["stripe:*"], "rate_limit": 600},
                    }
                }
            },
        }
        result = denormalize(doc)
        agent_host = result["agents"]["boris"]["hosts"]["api.stripe.com"]
        assert "allow" in agent_host
        assert "rate" in agent_host
