"""
Tests for policy_loader.py - Policy file loading and hot reload.

Tests YAML/JSON loading, file watching, and thread-safe policy access.
"""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock


class TestSpecificityScore:
    """Tests for specificity score calculation."""

    def test_wildcard_only_scores_zero(self):
        """Test that '*' pattern scores 0."""
        from addons.policy_loader import _specificity_score

        assert _specificity_score("*") == 0

    def test_longer_patterns_score_higher(self):
        """Test longer patterns score higher."""
        from addons.policy_loader import _specificity_score

        assert _specificity_score("api.example.com") > _specificity_score("api.com")

    def test_wildcards_reduce_score(self):
        """Test wildcards reduce score."""
        from addons.policy_loader import _specificity_score

        assert _specificity_score("api.example.com") > _specificity_score("*.example.com")
        assert _specificity_score("*.example.com") > _specificity_score("*.*")


class TestPolicyLoaderBasics:
    """Basic PolicyLoader tests."""

    def test_creates_empty_baseline(self):
        """Test loader creates empty baseline when no path given."""
        from addons.policy_loader import PolicyLoader

        loader = PolicyLoader()
        assert loader.baseline is not None
        assert len(loader.baseline.permissions) == 0

    def test_baseline_path_property(self):
        """Test baseline_path property returns correct value."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            assert loader.baseline_path == path


class TestPolicyLoaderFileLoading:
    """Tests for policy file loading."""

    def test_loads_yaml_policy(self):
        """Test loading YAML policy file."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")

            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1

    def test_loads_json_policy(self):
        """Test loading JSON policy file."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.json"
            path.write_text(json.dumps({
                "permissions": [
                    {"action": "network:request", "resource": "api.example.com/*", "effect": "allow"}
                ]
            }))

            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1

    def test_handles_missing_file(self):
        """Test handling of missing policy file."""
        from addons.policy_loader import PolicyLoader

        loader = PolicyLoader(baseline_path=Path("/nonexistent/policy.yaml"))
        # Should create empty policy, not fail
        assert len(loader.baseline.permissions) == 0

    def test_handles_invalid_yaml(self):
        """Test handling of invalid YAML."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("not: valid: yaml: {{{")

            loader = PolicyLoader(baseline_path=path)
            # Should create empty policy
            assert len(loader.baseline.permissions) == 0

    def test_handles_invalid_policy_structure(self):
        """Test handling of invalid policy structure."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("""
permissions:
  - invalid_field: "should fail validation"
""")

            loader = PolicyLoader(baseline_path=path)
            # Should keep empty baseline on validation error
            assert len(loader.baseline.permissions) == 0


class TestPolicyLoaderTaskPolicy:
    """Tests for task policy loading."""

    def test_loads_task_policy(self):
        """Test loading task policy."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "baseline.yaml"
            baseline.write_text("permissions: []")

            task = Path(tmpdir) / "task.yaml"
            task.write_text("""
permissions:
  - action: "credential:use"
    resource: "openai:*"
    effect: allow
""")

            loader = PolicyLoader(baseline_path=baseline)
            result = loader.load_task_policy(task)

            assert result is True
            assert loader.task_policy is not None
            assert len(loader.task_policy.permissions) == 1

    def test_clear_task_policy(self):
        """Test clearing task policy."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "baseline.yaml"
            baseline.write_text("permissions: []")

            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            loader.load_task_policy(task)
            assert loader.task_policy is not None

            loader.clear_task_policy()
            assert loader.task_policy is None


class TestPolicyLoaderSpecificity:
    """Tests for permission ordering by specificity."""

    def test_sorts_permissions_by_specificity(self):
        """Test permissions are sorted by specificity (most specific first)."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "*"
    effect: deny
  - action: "network:request"
    resource: "*.example.com/*"
    effect: allow
  - action: "network:request"
    resource: "api.example.com/v1/*"
    effect: allow
""")

            loader = PolicyLoader(baseline_path=path)

            # Most specific should be first
            assert "api.example.com" in loader.baseline.permissions[0].resource
            # Wildcard only should be last
            assert loader.baseline.permissions[-1].resource == "*"


class TestPolicyLoaderDirectSet:
    """Tests for direct policy setting via API."""

    def test_set_baseline_directly(self):
        """Test setting baseline policy directly."""
        from addons.policy_loader import PolicyLoader
        from addons.policy_engine import UnifiedPolicy, Permission

        loader = PolicyLoader()

        new_policy = UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="api.example.com/*", effect="allow")
        ])
        loader.set_baseline(new_policy)

        assert len(loader.baseline.permissions) == 1

    def test_set_task_policy_directly(self):
        """Test setting task policy directly."""
        from addons.policy_loader import PolicyLoader
        from addons.policy_engine import UnifiedPolicy, Permission

        loader = PolicyLoader()

        task_policy = UnifiedPolicy(permissions=[
            Permission(action="credential:use", resource="openai:*", effect="allow")
        ])
        loader.set_task_policy(task_policy)

        assert loader.task_policy is not None
        assert len(loader.task_policy.permissions) == 1


class TestPolicyLoaderReload:
    """Tests for policy reload functionality."""

    def test_reload_reloads_all(self):
        """Test reload() reloads all policies."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "baseline.yaml"
            baseline.write_text("permissions: []")

            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            loader.load_task_policy(task)

            # Modify files
            baseline.write_text("""
permissions:
  - action: "network:request"
    resource: "new.example.com/*"
    effect: allow
""")

            result = loader.reload()
            assert result is True
            assert len(loader.baseline.permissions) == 1

    def test_on_reload_callback_called(self):
        """Test on_reload callback is called."""
        from addons.policy_loader import PolicyLoader

        callback = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("permissions: []")

            # Loader created to trigger callback
            _ = PolicyLoader(baseline_path=path, on_reload=callback)

            # Callback should have been called on initial load
            assert callback.called


class TestPolicyLoaderWatcher:
    """Tests for file watcher."""

    def test_start_stop_watcher(self):
        """Test starting and stopping file watcher."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)

            loader.start_watcher()
            assert loader._watcher_thread is not None
            assert loader._watcher_thread.is_alive()

            loader.stop_watcher()
            # After stop, thread should be None
            assert loader._watcher_thread is None

    def test_watcher_detects_changes(self):
        """Test watcher detects file changes."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            loader.start_watcher()

            # Initial state
            assert len(loader.baseline.permissions) == 0

            # Modify file
            time.sleep(0.1)  # Ensure mtime changes
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")

            # Wait for watcher to detect change (poll interval is 2s)
            time.sleep(2.5)

            loader.stop_watcher()

            # Should have loaded the new permission
            assert len(loader.baseline.permissions) == 1


class TestPolicyLoaderProperties:
    """Tests for loader properties."""

    def test_baseline_property_thread_safe(self):
        """Test baseline property is thread-safe."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)

            # Multiple reads should be safe
            for _ in range(10):
                _ = loader.baseline

    def test_task_policy_property_initially_none(self):
        """Test task_policy is None initially."""
        from addons.policy_loader import PolicyLoader

        loader = PolicyLoader()
        assert loader.task_policy is None

    def test_task_policy_path_property(self):
        """Test task_policy_path property."""
        from addons.policy_loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "baseline.yaml"
            baseline.write_text("permissions: []")

            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            assert loader.task_policy_path is None

            loader.load_task_policy(task)
            assert loader.task_policy_path == task
