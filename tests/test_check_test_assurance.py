"""Tests for the assurance-policy ratchet."""

import tomllib
from pathlib import Path

from scripts.check_test_assurance import (
    audit_boundary_file,
    audit_factory_acceptance,
    audit_manifest,
    audit_test_file,
    changed_factory_acceptance_ids,
    update_factory_acceptance,
)


def _audit_source(tmp_path: Path, source: str) -> list[str]:
    path = tmp_path / "test_example.py"
    path.write_text(source)
    return audit_boundary_file(path, {"Subject"})


def test_current_assurance_manifest_passes():
    assert audit_manifest() == []


def test_boundary_policy_rejects_bare_magicmock(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import MagicMock
pytestmark = pytest.mark.assurance_boundary
value = MagicMock()
""",
    )

    assert any("bare MagicMock" in issue for issue in issues)


def test_global_policy_rejects_asyncmock(tmp_path):
    path = tmp_path / "test_example.py"
    path.write_text("from unittest.mock import AsyncMock\nvalue = AsyncMock()\n")

    assert any("bare AsyncMock" in issue for issue in audit_test_file(path))


def test_boundary_policy_rejects_unspecced_patch(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import patch
pytestmark = pytest.mark.assurance_boundary
value = patch("package.collaborator")
""",
    )

    assert any("requires autospec=True" in issue for issue in issues)


def test_boundary_policy_rejects_unspecced_patch_object(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import patch
pytestmark = pytest.mark.assurance_boundary
value = patch.object(Collaborator, "method", return_value=True)
""",
    )

    assert any("requires autospec=True" in issue for issue in issues)


def test_boundary_policy_accepts_explicit_patch_replacement(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import patch
pytestmark = pytest.mark.assurance_boundary
value = patch.object(Collaborator, "method", lambda self: True)
other = patch("package.value", new=object())
""",
    )

    assert issues == []


def test_boundary_policy_rejects_mock_new_callable(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import MagicMock, patch
pytestmark = pytest.mark.assurance_boundary
value = patch("package.collaborator", new_callable=MagicMock)
""",
    )

    assert any("requires autospec=True" in issue for issue in issues)


def test_boundary_policy_rejects_subject_patch(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import patch
pytestmark = pytest.mark.assurance_boundary
value = patch.object(Subject, "method", autospec=True)
""",
    )

    assert any("Subject may not be patched" in issue for issue in issues)


def test_boundary_policy_rejects_unittest_mock_module_forms(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest import mock
pytestmark = pytest.mark.assurance_boundary
client = mock.create_autospec(Client, instance=True)
value = mock.patch("package.collaborator")
subject = mock.patch.object(Subject, "method", autospec=True)
""",
    )

    assert any("create_autospec requires spec_set=True" in issue for issue in issues)
    assert any("mock-producing patch requires autospec=True" in issue for issue in issues)
    assert any("Subject may not be patched" in issue for issue in issues)


def test_boundary_policy_accepts_autospecced_collaborator(tmp_path):
    issues = _audit_source(
        tmp_path,
        """
import pytest
from unittest.mock import create_autospec, patch
pytestmark = pytest.mark.assurance_boundary
client = create_autospec(Client, instance=True, spec_set=True)
value = patch("package.collaborator", autospec=True, return_value=client)
""",
    )

    assert issues == []


def _factory_manifest(tmp_path: Path) -> tuple[Path, Path]:
    test_file = tmp_path / "cli/tests/test_factory_example.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "import pytest\n\n"
        "@pytest.mark.parametrize('value', [1])\n"
        "def test_factory_example(value):\n"
        "    assert value == 1\n"
    )
    manifest = tmp_path / "assurance.toml"
    manifest.write_text(
        "[[factory_acceptance]]\n"
        'id = "FACTORY-EXAMPLE"\n'
        'description = "The factory example passes."\n'
        'node = "cli/tests/test_factory_example.py::test_factory_example"\n'
        f'sha256 = "{"0" * 64}"\n'
    )
    return manifest, test_file


def test_factory_acceptance_digest_detects_an_edit_and_updates_explicitly(tmp_path):
    manifest, test_file = _factory_manifest(tmp_path)

    assert any("test changed" in issue for issue in audit_factory_acceptance(manifest, root=tmp_path))
    assert update_factory_acceptance(manifest, root=tmp_path) == []
    assert audit_factory_acceptance(manifest, root=tmp_path) == []

    test_file.write_text(test_file.read_text().replace("value == 1", "value > 0"))
    assert any("test changed" in issue for issue in audit_factory_acceptance(manifest, root=tmp_path))


def test_factory_acceptance_update_replaces_a_new_entry_placeholder(tmp_path):
    manifest, _ = _factory_manifest(tmp_path)
    manifest.write_text(manifest.read_text().replace("0" * 64, "pending"))

    assert update_factory_acceptance(manifest, root=tmp_path) == []
    assert audit_factory_acceptance(manifest, root=tmp_path) == []


def test_factory_acceptance_reports_a_missing_named_test(tmp_path):
    manifest, test_file = _factory_manifest(tmp_path)
    assert update_factory_acceptance(manifest, root=tmp_path) == []
    test_file.unlink()

    issues = audit_factory_acceptance(manifest, root=tmp_path)

    assert any("test file does not exist" in issue for issue in issues)


def test_factory_acceptance_change_report_names_only_changed_ids():
    before = {
        "factory_acceptance": [
            {"id": "FACTORY-ONE", "node": "old", "description": "one", "sha256": "a" * 64},
            {"id": "FACTORY-TWO", "node": "same", "description": "two", "sha256": "b" * 64},
        ]
    }
    after = tomllib.loads(
        '[[factory_acceptance]]\nid = "FACTORY-ONE"\nnode = "new"\n'
        'description = "one"\nsha256 = "' + "c" * 64 + '"\n'
        '[[factory_acceptance]]\nid = "FACTORY-TWO"\nnode = "same"\n'
        'description = "two"\nsha256 = "' + "b" * 64 + '"\n'
    )

    assert changed_factory_acceptance_ids(before, after) == ["FACTORY-ONE"]
