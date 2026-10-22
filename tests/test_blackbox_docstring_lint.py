"""Tests for blackbox docstring collection scoping."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

BLACKBOX_ROOT = Path(__file__).parent / "blackbox"
sys.path.insert(0, str(BLACKBOX_ROOT))
import _docstring_lint as lint  # noqa: E402


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

    lint.validate_items([_item(unrelated, None)], suite_root)


def test_validate_items_rejects_invalid_test_inside_suite(tmp_path):
    """A test inside the selected blackbox suite still requires the schema."""
    suite_root = tmp_path / "blackbox" / "isolation"
    suite_root.mkdir(parents=True)
    blackbox_test = suite_root / "test_isolation.py"

    with pytest.raises(RuntimeError, match="missing docstring"):
        lint.validate_items([_item(blackbox_test, None)], suite_root)


def test_validate_items_accepts_valid_test_inside_suite(tmp_path):
    """A conforming test inside the selected blackbox suite is accepted."""
    suite_root = tmp_path / "blackbox" / "isolation"
    suite_root.mkdir(parents=True)
    blackbox_test = suite_root / "test_isolation.py"
    docstring = """Isolation property.

    What: Exercises the property.
    Why: Demonstrates that validation remains enabled.
    """

    lint.validate_items([_item(blackbox_test, docstring)], suite_root)


@pytest.mark.parametrize("suite", ["host", "isolation"])
@pytest.mark.parametrize("why", ["", "Why: Listener ownership determines request identity."])
def test_standalone_and_collection_validate_nested_classes(tmp_path, monkeypatch, suite, why):
    """Both entrypoints reject a nested class without its Why section."""
    root = tmp_path / "tests" / "blackbox"
    nested = root / suite / "identity" / "test_listener.py"
    nested.parent.mkdir(parents=True)
    source = f'''class TestListener:
    """Host listener identity.

    {why}
    """

    def test_identity(self):
        """Each listener belongs to one agent.

        What: Inspect the configured identity.
        Why: Policy needs the correct agent.
        """
'''
    nested.write_text(source)
    monkeypatch.setattr(lint, "__file__", str(root / "_docstring_lint.py"))
    violations = lint._validate_via_ast()
    namespace = {}
    exec(compile(source, str(nested), "exec"), namespace)
    cls = namespace["TestListener"]
    item = _item(nested, cls.test_identity.__doc__)
    item.cls = cls
    if why:
        assert violations == []
        lint.validate_items([item], root / suite)
    else:
        assert violations == [f"tests/blackbox/{suite}/identity/test_listener.py::TestListener: missing 'Why:' section"]
        with pytest.raises(RuntimeError, match="TestListener: missing 'Why:' section"):
            lint.validate_items([item], root / suite)
