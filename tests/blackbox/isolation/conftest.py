"""Minimal conftest for VM-side isolation tests.

These tests run inside the microVM. No sinkhole, no admin API,
no host-side fixtures. Only stdlib + pytest.
"""
import sys
from pathlib import Path

# Import the shared docstring linter from the parent blackbox dir.
# Inside the VM, /workspace is the repo root; parent dir is reachable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _docstring_lint import validate_items  # noqa: E402


def pytest_collection_modifyitems(config, items):
    """Reject collection if any test's docstring is missing structure.

    Schema lives in tests/blackbox/_docstring_lint.py and is shared
    with the host suite and docs/blackbox-coverage.md generator.
    """
    validate_items(items)
