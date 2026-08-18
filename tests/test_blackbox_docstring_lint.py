"""Tests for blackbox docstring collection scoping."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

BLACKBOX_ROOT = Path(__file__).parent / "blackbox"
sys.path.insert(0, str(BLACKBOX_ROOT))
from _docstring_lint import validate_items  # noqa: E402


def _item(path: Path, docstring: str | None):
    """Build the subset of a pytest Function item used by the validator."""

    def test_example():
        pass

    test_example.__doc__ = docstring
    module = SimpleNamespace(__name__="test_example")
    return SimpleNamespace(path=path, function=test_example, module=module, cls=None)


def test_validate_items_ignores_tests_outside_suite(tmp_path):
    """An unrelated test without blackbox sections is not validated."""
    suite_root = tmp_path / "blackbox" / "isolation"
    suite_root.mkdir(parents=True)
    unrelated = tmp_path / "test_unit.py"

    validate_items([_item(unrelated, None)], suite_root)


def test_validate_items_rejects_invalid_test_inside_suite(tmp_path):
    """A test inside the selected blackbox suite still requires the schema."""
    suite_root = tmp_path / "blackbox" / "isolation"
    suite_root.mkdir(parents=True)
    blackbox_test = suite_root / "test_isolation.py"

    with pytest.raises(RuntimeError, match="missing docstring"):
        validate_items([_item(blackbox_test, None)], suite_root)


def test_validate_items_accepts_valid_test_inside_suite(tmp_path):
    """A conforming test inside the selected blackbox suite is accepted."""
    suite_root = tmp_path / "blackbox" / "isolation"
    suite_root.mkdir(parents=True)
    blackbox_test = suite_root / "test_isolation.py"
    docstring = """Isolation property.

    What: Exercises the property.
    Why: Demonstrates that validation remains enabled.
    """

    validate_items([_item(blackbox_test, docstring)], suite_root)
