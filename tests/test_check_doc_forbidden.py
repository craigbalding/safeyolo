"""Tests for scripts/check_doc_forbidden.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_doc_forbidden.py"


def _load_module():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("check_doc_forbidden", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


@pytest.fixture
def make_repo(tmp_path: Path, monkeypatch):
    """Point the module at a temp repo layout for the duration of the test."""
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    return tmp_path


class TestCheckRule:
    def test_absent_phrase_passes(self, make_repo):
        (make_repo / "doc.md").write_text("This is fine prose.\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["doc.md"],
            "forbidden": ["banned phrase"],
        })
        assert problems == []

    def test_present_phrase_fails(self, make_repo):
        (make_repo / "doc.md").write_text("This mentions a banned phrase.\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["doc.md"],
            "forbidden": ["banned phrase"],
        })
        assert len(problems) == 1
        assert "banned phrase" in problems[0]

    def test_reason_appears_in_error(self, make_repo):
        (make_repo / "doc.md").write_text("A stale claim here.\n")
        problems = mod._check_rule({
            "name": "test-rule",
            "docs": ["doc.md"],
            "forbidden": ["stale claim"],
            "reason": "See PR #123.",
        })
        assert len(problems) == 1
        assert "See PR #123." in problems[0]

    def test_multiple_docs_each_scanned(self, make_repo):
        (make_repo / "a.md").write_text("bad thing\n")
        (make_repo / "b.md").write_text("nothing wrong\n")
        (make_repo / "c.md").write_text("bad thing also here\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["a.md", "b.md", "c.md"],
            "forbidden": ["bad thing"],
        })
        assert len(problems) == 2
        assert any("a.md" in p for p in problems)
        assert any("c.md" in p for p in problems)
        assert not any("b.md" in p for p in problems)

    def test_multiple_forbidden_all_checked(self, make_repo):
        (make_repo / "doc.md").write_text("first bad, and second bad too.\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["doc.md"],
            "forbidden": ["first bad", "second bad"],
        })
        assert len(problems) == 2

    def test_missing_doc_reported(self, make_repo):
        problems = mod._check_rule({
            "name": "n",
            "docs": ["does-not-exist.md"],
            "forbidden": ["anything"],
        })
        assert len(problems) == 1
        assert "not found" in problems[0]

    def test_empty_docs_list_reports(self, make_repo):
        problems = mod._check_rule({
            "name": "n",
            "docs": [],
            "forbidden": ["x"],
        })
        assert len(problems) == 1
        assert "no docs list" in problems[0]

    def test_empty_forbidden_list_reports(self, make_repo):
        (make_repo / "doc.md").write_text("x\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["doc.md"],
            "forbidden": [],
        })
        assert len(problems) == 1
        assert "no forbidden list" in problems[0]

    def test_phrase_boundary_is_substring_match(self, make_repo):
        """Deliberately substring-based: catches 'no Docker socket' inside
        larger sentences without requiring word-boundary regex complexity."""
        (make_repo / "doc.md").write_text("The container runs as the user.\n")
        problems = mod._check_rule({
            "name": "n",
            "docs": ["doc.md"],
            "forbidden": ["container runs as"],
        })
        assert len(problems) == 1
