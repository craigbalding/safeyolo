"""Import-boundary tests for shared policy models."""

import subprocess
import sys


def test_loader_import_does_not_import_engine():
    """The loader must remain usable without creating an engine import cycle."""
    code = """
import sys
import safeyolo.policy.loader

assert "safeyolo.policy.engine" not in sys.modules
"""

    subprocess.run([sys.executable, "-c", code], check=True)


def test_engine_reexports_shared_model_objects():
    """Existing imports from policy.engine retain identical model objects."""
    from safeyolo.policy import engine, models

    model_names = (
        "AddonConfig",
        "Condition",
        "CredentialRule",
        "DomainOverride",
        "Permission",
        "PolicyDecision",
        "PolicyMetadata",
        "ScanPattern",
        "UnifiedPolicy",
    )

    for name in model_names:
        assert getattr(engine, name) is getattr(models, name)


def test_loader_constructs_shared_policy_model():
    """The loader and public engine API operate on the same policy type."""
    from safeyolo.policy.loader import PolicyLoader
    from safeyolo.policy.models import UnifiedPolicy

    loader = PolicyLoader()

    assert isinstance(loader.baseline, UnifiedPolicy)
