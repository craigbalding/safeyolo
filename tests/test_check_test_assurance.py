"""Tests for the assurance-policy ratchet."""

from pathlib import Path

from scripts.check_test_assurance import audit_boundary_file, audit_manifest, audit_test_file


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
