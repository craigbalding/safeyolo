"""Tests for scripts/audit_doc_coverage.py — the coverage reporter."""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_doc_coverage.py"


def _load_module():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("audit_doc_coverage", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


@pytest.fixture
def make_repo(tmp_path: Path, monkeypatch):
    """Point the module at a temp repo with a minimal source/doc layout."""
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    # Ensure the module's allowlist reflects the temp docs we create,
    # so per-doc counts include them in the report.
    (tmp_path / "docs").mkdir()
    monkeypatch.setattr(
        mod, "USER_FACING_DOCS",
        frozenset({"README.md", "docs/AGENTS.md"}),
    )
    monkeypatch.setattr(
        mod, "CONSTANTS_PATH", tmp_path / "scripts" / "doc_constants.toml",
    )
    monkeypatch.setattr(
        mod, "FORBIDDEN_PATH", tmp_path / "scripts" / "doc_forbidden.toml",
    )
    (tmp_path / "scripts").mkdir()
    return tmp_path


class TestMarkerBindings:
    def test_finds_markers_across_source(self, make_repo):
        (make_repo / "a.py").write_text('x = 1  # DOC: README.md\n')
        (make_repo / "b.sh").write_text('X=1  # DOC: docs/AGENTS.md\n')
        b = mod._marker_bindings()
        assert Path("README.md") not in b  # keyed by ref string not Path
        assert "README.md" in b
        assert "docs/AGENTS.md" in b
        assert len(b["README.md"]) == 1
        assert len(b["docs/AGENTS.md"]) == 1

    def test_comma_separated_refs_split(self, make_repo):
        (make_repo / "a.py").write_text("z = 1  # DOC: README.md, docs/AGENTS.md\n")
        b = mod._marker_bindings()
        assert "README.md" in b
        assert "docs/AGENTS.md" in b

    def test_tests_dir_excluded(self, make_repo):
        (make_repo / "tests").mkdir()
        (make_repo / "tests" / "t.py").write_text('x = 1  # DOC: README.md\n')
        b = mod._marker_bindings()
        assert not b.get("README.md")

    def test_anchor_stripped(self, make_repo):
        (make_repo / "a.py").write_text("y = 1  # DOC: README.md#section-x\n")
        b = mod._marker_bindings()
        assert "README.md" in b
        assert "README.md#section-x" not in b


class TestConfigBindings:
    def test_constants_toml_indexed_by_doc(self, make_repo):
        (make_repo / "scripts" / "doc_constants.toml").write_text(
            '[[assertion]]\nname = "x"\nsource = "s"\npattern = "p"\n'
            'docs = ["README.md", "docs/AGENTS.md"]\nmust_contain = "y"\n',
        )
        b = mod._constants_bindings()
        assert b["README.md"] == ["x"]
        assert b["docs/AGENTS.md"] == ["x"]

    def test_forbidden_toml_indexed_by_doc(self, make_repo):
        (make_repo / "scripts" / "doc_forbidden.toml").write_text(
            '[[rule]]\nname = "r"\ndocs = ["README.md"]\nforbidden = ["bad"]\n',
        )
        b = mod._forbidden_bindings()
        assert b["README.md"] == ["r"]


class TestReportOutput:
    def test_per_doc_counts_include_all_allowlisted(self, make_repo):
        (make_repo / "a.py").write_text('x = 1  # DOC: README.md\n')
        (make_repo / "README.md").write_text("# R\n")
        (make_repo / "docs" / "AGENTS.md").write_text("# A\n")
        buf = io.StringIO()
        mod._print_per_doc_counts(
            mod._marker_bindings(), mod._constants_bindings(),
            mod._forbidden_bindings(), out=buf,
        )
        report = buf.getvalue()
        assert "README.md" in report
        assert "docs/AGENTS.md" in report
        # Total line reflects the single marker
        assert "TOTAL" in report

    def test_orphan_markers_reported(self, make_repo):
        (make_repo / "a.py").write_text(
            'x = 1  # DOC: docs/not-allowlisted.md\n',
        )
        buf = io.StringIO()
        mod._print_orphan_markers(
            mod._marker_bindings(), mod._constants_bindings(),
            mod._forbidden_bindings(), out=buf,
        )
        report = buf.getvalue()
        assert "docs/not-allowlisted.md" in report

    def test_no_orphans_produces_no_output(self, make_repo):
        (make_repo / "a.py").write_text('x = 1  # DOC: README.md\n')
        buf = io.StringIO()
        mod._print_orphan_markers(
            mod._marker_bindings(), mod._constants_bindings(),
            mod._forbidden_bindings(), out=buf,
        )
        assert buf.getvalue() == ""


class TestKeywordHits:
    def test_finds_curated_keywords(self, make_repo):
        (make_repo / "d.md").write_text(
            "The admin API binds to 127.0.0.1 only.\n"
            "Rate limiting uses GCRA.\n"
            "Nothing to see here.\n",
        )
        hits = mod._keyword_hits(make_repo / "d.md")
        assert 1 in hits.get("127.0.0.1", [])
        assert 2 in hits.get("GCRA", [])
