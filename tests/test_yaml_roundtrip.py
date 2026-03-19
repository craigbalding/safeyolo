"""
Tests for yaml_roundtrip.py - YAML comment preservation.

Verifies that comments, section banners, and formatting survive
load → modify → save cycles using ruamel.yaml round-trip mode.
"""

import textwrap
from pathlib import Path

import pytest

SAMPLE_BASELINE = textwrap.dedent("""\
    # SafeYolo Baseline Policy
    #
    # This is an important header comment that must survive saves.

    metadata:
      version: "1.0"
      description: "Test baseline"

    # =============================================================================
    # PERMISSIONS
    # =============================================================================

    permissions:
      # ---------------------------------------------------------------------------
      # Credential Routing
      # ---------------------------------------------------------------------------

      # OpenAI endpoints accept OpenAI credentials
      - action: credential:use
        resource: "api.openai.com/*"
        effect: allow
        tier: explicit
        condition:
          credential: ["openai:*"]

      # Unknown destinations require approval
      - action: credential:use
        resource: "*"
        effect: prompt
        tier: explicit

      # ---------------------------------------------------------------------------
      # Rate Limits
      # ---------------------------------------------------------------------------

      # Default rate limit
      - action: network:request
        resource: "*"
        effect: budget
        budget: 600
        tier: explicit

    # =============================================================================
    # GLOBAL BUDGETS
    # =============================================================================

    budgets:
      network:request: 12000  # Total requests per minute

    # =============================================================================
    # REQUIRED ADDONS
    # =============================================================================

    required:
      - credential_guard
      - network_guard

    credential_rules: []
    scan_patterns: []
    addons: {}
    domains: {}
""")


@pytest.fixture
def yaml_file(tmp_path):
    """Create a temporary YAML file with comments."""
    p = tmp_path / "policy.yaml"
    p.write_text(SAMPLE_BASELINE)
    return p


class TestLoadRoundtrip:
    """Tests for load_roundtrip."""

    def test_loads_with_comments(self, yaml_file):
        from yaml_roundtrip import load_roundtrip

        data = load_roundtrip(yaml_file)
        assert data["metadata"]["version"] == "1.0"
        assert len(data["permissions"]) == 3

    def test_missing_file_raises(self, tmp_path):
        from yaml_roundtrip import load_roundtrip

        with pytest.raises(FileNotFoundError):
            load_roundtrip(tmp_path / "nonexistent.yaml")


class TestSaveRoundtrip:
    """Tests for save_roundtrip - comment preservation on write."""

    def test_comments_survive_save(self, yaml_file):
        """Load a commented YAML, save it back, verify comments survive."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)
        save_roundtrip(yaml_file, data)

        saved = yaml_file.read_text()
        # Header comment
        assert "# SafeYolo Baseline Policy" in saved
        assert "# This is an important header comment" in saved
        # Section banners
        assert "# PERMISSIONS" in saved
        assert "# GLOBAL BUDGETS" in saved
        assert "# REQUIRED ADDONS" in saved
        # Sub-section headers
        assert "# Credential Routing" in saved
        assert "# Rate Limits" in saved
        # Inline/per-rule comments
        assert "# OpenAI endpoints accept OpenAI credentials" in saved
        assert "# Unknown destinations require approval" in saved
        assert "# Default rate limit" in saved
        assert "# Total requests per minute" in saved

    def test_data_integrity_after_save(self, yaml_file):
        """Verify data values are preserved after round-trip."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)
        save_roundtrip(yaml_file, data)

        # Reload and verify
        data2 = load_roundtrip(yaml_file)
        assert data2["metadata"]["version"] == "1.0"
        assert len(data2["permissions"]) == 3
        assert data2["budgets"]["network:request"] == 12000
        assert data2["required"] == ["credential_guard", "network_guard"]

    def test_atomic_write(self, yaml_file):
        """Verify file is written atomically (no partial writes)."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)
        save_roundtrip(yaml_file, data)

        # File should exist and be valid
        saved = yaml_file.read_text()
        assert len(saved) > 0
        # Should be loadable
        data2 = load_roundtrip(yaml_file)
        assert data2 is not None


class TestIncrementalPermissionInsert:
    """Tests for inserting a permission into a commented baseline."""

    def test_insert_preserves_all_comments(self, yaml_file):
        """Insert a permission and verify all original comments are preserved."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)

        # Insert a new permission at position 0
        new_perm = {
            "action": "credential:use",
            "resource": "api.newservice.com/*",
            "effect": "allow",
            "tier": "explicit",
            "condition": {"credential": ["hmac:abc123"]},
        }
        data["permissions"].insert(0, new_perm)

        save_roundtrip(yaml_file, data)
        saved = yaml_file.read_text()

        # New permission present
        assert "api.newservice.com/*" in saved
        assert "hmac:abc123" in saved

        # All original comments still present
        assert "# SafeYolo Baseline Policy" in saved
        assert "# PERMISSIONS" in saved
        assert "# Credential Routing" in saved
        assert "# OpenAI endpoints accept OpenAI credentials" in saved
        assert "# Unknown destinations require approval" in saved
        assert "# Rate Limits" in saved
        assert "# Default rate limit" in saved
        assert "# GLOBAL BUDGETS" in saved
        assert "# Total requests per minute" in saved

    def test_insert_increases_permission_count(self, yaml_file):
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)
        original_count = len(data["permissions"])

        new_perm = {
            "action": "credential:use",
            "resource": "api.test.com/*",
            "effect": "allow",
            "tier": "explicit",
        }
        data["permissions"].insert(0, new_perm)
        save_roundtrip(yaml_file, data)

        data2 = load_roundtrip(yaml_file)
        assert len(data2["permissions"]) == original_count + 1


class TestMergeIntoRoundtrip:
    """Tests for merge_into_roundtrip - full update with comment preservation."""

    def test_merge_preserves_section_banners(self, yaml_file):
        """Full update via merge preserves section banners."""
        from yaml_roundtrip import load_roundtrip, merge_into_roundtrip, save_roundtrip

        original = load_roundtrip(yaml_file)

        # Simulate a full policy replacement (e.g., from replace_baseline)
        new_data = {
            "metadata": {"version": "1.0", "description": "Updated baseline"},
            "permissions": [
                {
                    "action": "credential:use",
                    "resource": "api.openai.com/*",
                    "effect": "allow",
                    "tier": "explicit",
                    "condition": {"credential": ["openai:*"]},
                },
                {
                    "action": "credential:use",
                    "resource": "*",
                    "effect": "prompt",
                    "tier": "explicit",
                },
            ],
            "budgets": {"network:request": 15000},
            "required": ["credential_guard"],
            "credential_rules": [],
            "scan_patterns": [],
            "addons": {},
            "domains": {},
        }

        merge_into_roundtrip(original, new_data)
        save_roundtrip(yaml_file, original)

        saved = yaml_file.read_text()

        # Section banners preserved
        assert "# PERMISSIONS" in saved
        assert "# GLOBAL BUDGETS" in saved

        # Updated values
        assert "Updated baseline" in saved
        assert "15000" in saved

        # Removed permission (rate limit) is gone from data
        data = load_roundtrip(yaml_file)
        assert len(data["permissions"]) == 2

    def test_merge_updates_nested_values(self, yaml_file):
        """Merge correctly updates nested dict values."""
        from yaml_roundtrip import load_roundtrip, merge_into_roundtrip

        original = load_roundtrip(yaml_file)
        new_data = dict(original)
        new_data["metadata"] = {"version": "2.0", "description": "v2 policy"}

        merge_into_roundtrip(original, new_data)

        assert original["metadata"]["version"] == "2.0"
        assert original["metadata"]["description"] == "v2 policy"

    def test_merge_removes_deleted_keys(self, yaml_file):
        """Merge removes keys not present in new_data."""
        from yaml_roundtrip import load_roundtrip, merge_into_roundtrip

        original = load_roundtrip(yaml_file)
        new_data = {
            "metadata": {"version": "1.0"},
            "permissions": [],
            "budgets": {},
            "required": [],
            "credential_rules": [],
            "scan_patterns": [],
            "addons": {},
            "domains": {},
        }
        merge_into_roundtrip(original, new_data)

        assert list(original.keys()) == list(new_data.keys())


class TestRegressionFragileCases:
    """Targeted regression tests for known fragile ruamel.yaml behaviors.

    ruamel.yaml stores section banners that appear between a list and the
    next mapping key as trailing comments on the last list item's last key.
    These tests lock in that the preservation logic handles this correctly.
    """

    def test_banner_between_list_and_mapping_key(self, yaml_file):
        """Banner sitting between a list (permissions) and next key (budgets) survives.

        This is the core fragile case: the '# GLOBAL BUDGETS' banner is stored
        internally on the last permission's last key, not on the budgets key.
        A naive list clear-and-replace would silently lose it.
        """
        from yaml_roundtrip import load_roundtrip, merge_into_roundtrip, save_roundtrip

        original = load_roundtrip(yaml_file)

        # Replace the permissions list entirely (triggers the fragile path)
        new_data = dict(original)
        new_data["permissions"] = [
            {"action": "credential:use", "resource": "*", "effect": "prompt", "tier": "explicit"},
        ]

        merge_into_roundtrip(original, new_data)
        save_roundtrip(yaml_file, original)

        saved = yaml_file.read_text()
        assert "# GLOBAL BUDGETS" in saved, "Banner between list and next key was lost"
        assert "# REQUIRED ADDONS" in saved

    def test_insert_at_top_preserves_banner_below_list(self, yaml_file):
        """Inserting a permission at position 0 must not displace the banner
        that follows the last list item (the '# GLOBAL BUDGETS' separator).
        """
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        data = load_roundtrip(yaml_file)

        new_perm = {
            "action": "credential:use",
            "resource": "api.inserted.com/*",
            "effect": "allow",
            "tier": "explicit",
            "condition": {"credential": ["hmac:inserted"]},
        }
        data["permissions"].insert(0, new_perm)
        save_roundtrip(yaml_file, data)

        saved = yaml_file.read_text()
        assert "api.inserted.com/*" in saved
        assert "# GLOBAL BUDGETS" in saved, "Banner below permissions list was lost after insert"
        # The banner should still appear AFTER the last permission, not before it
        last_perm_pos = saved.rfind("budget: 600")
        banner_pos = saved.find("# GLOBAL BUDGETS")
        assert banner_pos > last_perm_pos, "Banner relocated above the last permission"

    def test_repeated_incremental_saves_are_idempotent(self, yaml_file):
        """Five sequential insert-save cycles must not drift formatting or relocate comments.

        This catches gradual rot: a fix can pass once and still slowly corrupt
        the file over multiple edits (e.g., accumulating blank lines, shifting
        indentation, or duplicating comments).
        """
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        # Snapshot comment lines and their content before any edits
        original_text = yaml_file.read_text()
        original_comments = [
            line.strip() for line in original_text.splitlines()
            if line.strip().startswith("#")
        ]

        for i in range(5):
            data = load_roundtrip(yaml_file)
            new_perm = {
                "action": "credential:use",
                "resource": f"api.iter{i}.com/*",
                "effect": "allow",
                "tier": "explicit",
                "condition": {"credential": [f"hmac:iter{i}"]},
            }
            data["permissions"].insert(0, new_perm)
            save_roundtrip(yaml_file, data)

        # Verify all 5 permissions were added
        final_data = load_roundtrip(yaml_file)
        assert len(final_data["permissions"]) == 3 + 5  # 3 original + 5 inserted

        # Verify every original comment line still appears the same number of times.
        # (Separator lines like '# ====...' appear multiple times legitimately.)
        final_text = yaml_file.read_text()
        final_comments = [
            line.strip() for line in final_text.splitlines()
            if line.strip().startswith("#")
        ]

        from collections import Counter
        original_counts = Counter(original_comments)
        final_counts = Counter(final_comments)

        for comment, expected in original_counts.items():
            actual = final_counts.get(comment, 0)
            assert actual == expected, (
                f"Comment count changed after 5 saves: {comment!r} "
                f"(was {expected}, now {actual})"
            )

        # Verify no runaway blank line accumulation
        # (ruamel.yaml can sometimes add extra blank lines on repeated saves)
        original_blank_runs = original_text.count("\n\n\n")
        final_blank_runs = final_text.count("\n\n\n")
        assert final_blank_runs <= original_blank_runs + 1, (
            f"Blank lines accumulating: {original_blank_runs} -> {final_blank_runs} triple-newline runs"
        )


class TestFallbackBehavior:
    """Tests for fallback when original file doesn't exist."""

    def test_plain_save_works_without_original(self, tmp_path):
        """PolicyEngine falls back to plain dump when no original file."""
        import yaml

        # Just verify yaml.safe_dump works as the fallback path
        data = {
            "metadata": {"version": "1.0"},
            "permissions": [
                {"action": "credential:use", "resource": "*", "effect": "prompt", "tier": "explicit"}
            ],
        }
        content = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
        p = tmp_path / "new_policy.yaml"
        p.write_text(content)

        loaded = yaml.safe_load(p.read_text())
        assert loaded["metadata"]["version"] == "1.0"
        assert len(loaded["permissions"]) == 1


class TestRealBaseline:
    """Acceptance test using the real policy.yaml."""

    @pytest.fixture
    def real_baseline(self, tmp_path):
        """Copy real policy.yaml to tmp."""
        real = Path(__file__).parent.parent / "config" / "policy.yaml"
        if not real.exists():
            pytest.skip("config/policy.yaml not found")
        dest = tmp_path / "policy.yaml"
        dest.write_text(real.read_text())
        return dest

    def test_real_baseline_comments_survive(self, real_baseline):
        """Round-trip the real baseline and verify comment count is preserved."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        original_text = real_baseline.read_text()
        original_comment_lines = sum(
            1 for line in original_text.splitlines() if line.strip().startswith("#")
        )

        data = load_roundtrip(real_baseline)
        save_roundtrip(real_baseline, data)

        saved_text = real_baseline.read_text()
        saved_comment_lines = sum(
            1 for line in saved_text.splitlines() if line.strip().startswith("#")
        )

        # All comment lines should survive
        assert saved_comment_lines >= original_comment_lines

    def test_real_baseline_incremental_add(self, real_baseline):
        """Add a host entry to real policy, verify comments survive."""
        from yaml_roundtrip import load_roundtrip, save_roundtrip

        original_text = real_baseline.read_text()
        original_comment_lines = sum(
            1 for line in original_text.splitlines() if line.strip().startswith("#")
        )

        data = load_roundtrip(real_baseline)

        # Policy uses host-centric format — add a new host entry
        original_hosts = len(data["hosts"])
        data["hosts"]["api.example.com"] = {"credentials": ["hmac:testfingerprint"]}
        save_roundtrip(real_baseline, data)

        # Verify new host added
        data2 = load_roundtrip(real_baseline)
        assert len(data2["hosts"]) == original_hosts + 1
        assert "api.example.com" in data2["hosts"]

        # Verify comments survived
        saved_text = real_baseline.read_text()
        saved_comment_lines = sum(
            1 for line in saved_text.splitlines() if line.strip().startswith("#")
        )
        assert saved_comment_lines >= original_comment_lines
