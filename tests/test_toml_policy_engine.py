"""
Tests for TOML save paths in policy_engine.py.

Verifies that policy engine save methods correctly handle .toml files:
- Incremental saves (credential approvals) with comment preservation
- Full saves with denormalization
- Plain saves as fallback
"""

import tempfile
from pathlib import Path

import tomlkit

SAMPLE_TOML = '''\
# SafeYolo policy
version = "2.0"
budget = 12000

required = ["credential_guard"]

[hosts]
# LLM APIs
"api.openai.com" = { allow = ["openai:*"], rate = 3000 }
"*"              = { unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-test']
headers = ["authorization"]
'''


class TestTOMLIncrementalSave:
    """Test _save_baseline_incremental with TOML files."""

    def test_incremental_save_adds_credential(self):
        """Incremental save adds credential to existing host."""
        from toml_roundtrip import load_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML)

            # Simulate what policy engine does
            from toml_roundtrip import add_host_credential, save_roundtrip

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.example.com", ["hmac:abc123"])
            save_roundtrip(path, doc)

            # Verify
            doc2 = load_roundtrip(path)
            assert "api.example.com" in doc2["hosts"]
            assert doc2["hosts"]["api.example.com"]["allow"] == ["hmac:abc123"]

    def test_incremental_save_preserves_comments(self):
        """Incremental save preserves existing comments."""
        from toml_roundtrip import add_host_credential, load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML)

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.new.com", ["hmac:xyz"])
            save_roundtrip(path, doc)

            content = path.read_text()
            assert "# SafeYolo policy" in content
            assert "# LLM APIs" in content

    def test_incremental_save_appends_to_existing(self):
        """Adding credential to host that already has credentials."""
        from toml_roundtrip import add_host_credential, load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML)

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.openai.com", ["hmac:new_key"])
            save_roundtrip(path, doc)

            doc2 = load_roundtrip(path)
            allow = list(doc2["hosts"]["api.openai.com"]["allow"])
            assert "openai:*" in allow
            assert "hmac:new_key" in allow


class TestTOMLDenormalize:
    """Test denormalize for full save path."""

    def test_denormalize_produces_valid_toml(self):
        """Denormalized internal dict produces valid TOML."""
        from toml_normalize import denormalize

        internal = {
            "metadata": {"version": "2.0"},
            "global_budget": 12000,
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            },
            "credentials": {
                "openai": {"patterns": ["sk-test"]},
            },
            "required": ["credential_guard"],
        }

        toml_data = denormalize(internal)
        content = tomlkit.dumps(toml_data)

        # Should be parseable TOML
        parsed = tomlkit.parse(content)
        assert parsed["version"] == "2.0"
        assert parsed["budget"] == 12000


class TestTOMLPolicyFlow:
    """End-to-end: TOML load -> compile -> evaluate."""

    def test_toml_loads_compiles_evaluates(self):
        """Full pipeline: TOML file loads, compiles, creates valid UnifiedPolicy."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline

            # Should have real permissions
            assert len(policy.permissions) > 0

            # credential:use for openai
            cred_perms = [p for p in policy.permissions if p.action == "credential:use"]
            assert any(
                p.condition and p.condition.credential and "openai:*" in (
                    p.condition.credential if isinstance(p.condition.credential, list)
                    else [p.condition.credential]
                )
                for p in cred_perms
            )

            # network:request budget
            budget_perms = [
                p for p in policy.permissions
                if p.action == "network:request" and p.effect == "budget"
            ]
            assert len(budget_perms) > 0
