"""
Tests for TOML policy loading through PolicyLoader.

Verifies that .toml policy files load, normalize, and compile correctly
through the same pipeline as .yaml files.
"""

import tempfile
from pathlib import Path

SAMPLE_TOML_POLICY = '''\
version = "2.0"

budget = 12000

required = ["credential_guard"]

[hosts]
"api.openai.com"    = { allow = ["openai:*"], rate = 3000 }
"api.anthropic.com" = { allow = ["anthropic:*"], rate = 3000 }
"*"                 = { unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']
headers = ["authorization", "x-api-key"]
'''


class TestTOMLLoading:
    """Test PolicyLoader with TOML policy files."""

    def test_loads_toml_policy(self):
        """Test loading a .toml policy file."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML_POLICY)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline

            # Should have compiled permissions from host-centric format
            assert len(policy.permissions) > 0
            assert any(p.action == "credential:use" for p in policy.permissions)
            assert any(p.action == "network:request" for p in policy.permissions)

    def test_toml_host_centric_compiles(self):
        """TOML host-centric format compiles to correct IAM permissions."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML_POLICY)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline

            # Check credential:use for openai
            cred_perms = [
                p for p in policy.permissions
                if p.action == "credential:use" and "openai" in p.resource
            ]
            assert len(cred_perms) == 1
            assert cred_perms[0].condition is not None
            assert "openai:*" in (
                cred_perms[0].condition.credential
                if isinstance(cred_perms[0].condition.credential, list)
                else [cred_perms[0].condition.credential]
            )

    def test_toml_global_budget(self):
        """TOML budget field maps to budgets."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML_POLICY)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline
            assert policy.budgets.get("network:request") == 12000

    def test_toml_required_addons(self):
        """TOML required field passes through."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML_POLICY)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline
            assert "credential_guard" in policy.required

    def test_toml_credential_rules(self):
        """TOML credential section normalizes to credential_rules."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(SAMPLE_TOML_POLICY)

            loader = PolicyLoader(baseline_path=path)
            policy = loader.baseline

            # Should have compiled credential rules
            openai_rules = [r for r in policy.credential_rules if r.name == "openai"]
            assert len(openai_rules) == 1
            assert len(openai_rules[0].patterns) > 0

    def test_toml_merges_with_addons_yaml(self):
        """TOML policy merges with sibling addons.yaml."""
        from policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.toml"
            policy_path.write_text(SAMPLE_TOML_POLICY)

            addons_path = Path(tmpdir) / "addons.yaml"
            addons_path.write_text("addons:\n  entropy_scanner:\n    threshold: 4.5\n")

            PolicyLoader(baseline_path=policy_path)
            # Should not crash — addons merge is format-agnostic

    def test_toml_iam_format(self):
        """TOML file in IAM format (no hosts section) loads directly."""
        from policy_loader import PolicyLoader

        iam_toml = '''\
[[permissions]]
action = "network:request"
resource = "api.example.com/*"
effect = "allow"
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(iam_toml)

            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].action == "network:request"


class TestTOMLEquivalence:
    """Verify TOML and YAML policies produce equivalent compiled output."""

    def test_yaml_toml_equivalence(self):
        """Same policy in YAML and TOML produces same compiled permissions."""
        from policy_loader import PolicyLoader

        yaml_content = """\
metadata:
  version: "2.0"
global_budget: 12000
hosts:
  api.openai.com: { credentials: [openai:*], rate_limit: 3000 }
  "*": { unknown_credentials: prompt, rate_limit: 600 }
credentials:
  openai:
    patterns: ['sk-test']
    headers: [authorization]
required: [credential_guard]
"""
        toml_content = '''\
version = "2.0"
budget = 12000

required = ["credential_guard"]

[hosts]
"api.openai.com" = { allow = ["openai:*"], rate = 3000 }
"*"              = { unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ["sk-test"]
headers = ["authorization"]
'''

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "yaml" / "policy.yaml"
            toml_path = Path(tmpdir) / "toml" / "policy.toml"
            yaml_path.parent.mkdir()
            toml_path.parent.mkdir()
            yaml_path.write_text(yaml_content)
            toml_path.write_text(toml_content)

            yaml_loader = PolicyLoader(baseline_path=yaml_path)
            toml_loader = PolicyLoader(baseline_path=toml_path)

            yaml_policy = yaml_loader.baseline
            toml_policy = toml_loader.baseline

            # Same number of permissions
            assert len(yaml_policy.permissions) == len(toml_policy.permissions)

            # Same actions
            yaml_actions = sorted(p.action for p in yaml_policy.permissions)
            toml_actions = sorted(p.action for p in toml_policy.permissions)
            assert yaml_actions == toml_actions

            # Same budgets
            assert yaml_policy.budgets == toml_policy.budgets

            # Same required
            assert yaml_policy.required == toml_policy.required
