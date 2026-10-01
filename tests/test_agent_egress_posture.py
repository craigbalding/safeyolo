"""Tests for agent-level egress posture — per-agent default deny/prompt."""

class TestAgentEgressCompilation:
    """Test that agents.<name>.egress compiles to catch-all permission."""

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

    def test_agent_egress_allow_emits_catch_all_permission(self):
        """egress = allow emits the explicit catch-all required by default-deny."""
        result = self._compile({"boris": {"egress": "allow"}})
        perms = [
            p for p in result["permissions"]
            if p.get("condition", {}).get("agent") == "boris"
        ]
        assert len(perms) == 1
        assert perms[0]["effect"] == "allow"

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
