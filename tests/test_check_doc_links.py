"""Tests for scripts/check_doc_links.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_doc_links.py"


def _load_module():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("check_doc_links", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


class TestIsExternal:
    @pytest.mark.parametrize("url", [
        "https://example.com",
        "http://example.com",
        "mailto:x@y.z",
        "ftp://f.example",
        "#anchor",
    ])
    def test_external_or_fragment(self, url):
        assert mod._is_external(url)

    @pytest.mark.parametrize("url", [
        "path/to/file.md",
        "../other/file.py",
        "/absolute/repo/path",
        "file.md#anchor",
    ])
    def test_internal(self, url):
        assert not mod._is_external(url)


class TestExtractTargets:
    def test_inline_link(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("See [the guide](docs/GUIDE.md).\n")
        targets = mod._extract_targets(doc)
        assert targets == [(1, "docs/GUIDE.md")]

    def test_inline_link_with_anchor(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("[X](path/to/x.md#section)\n")
        assert mod._extract_targets(doc) == [(1, "path/to/x.md#section")]

    def test_inline_link_with_title(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text('[X](path/x.md "the title")\n')
        assert mod._extract_targets(doc) == [(1, "path/x.md")]

    def test_reference_definition(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("[label]: path/to/thing.md\n")
        assert mod._extract_targets(doc) == [(1, "path/to/thing.md")]

    def test_external_urls_excluded(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("[G](https://google.com) [L](local.md)\n")
        assert mod._extract_targets(doc) == [(1, "local.md")]

    def test_multiple_per_line(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("[A](a.md) and [B](b.md)\n")
        targets = mod._extract_targets(doc)
        assert (1, "a.md") in targets
        assert (1, "b.md") in targets

    def test_link_syntax_in_backticks_is_ignored(self, tmp_path: Path):
        """Illustrative link syntax inside inline code spans must not be
        parsed as a real link — otherwise docs explaining the link
        format would trigger false positives."""
        doc = tmp_path / "d.md"
        doc.write_text(
            "The link check verifies every `[text](path)` in the docs.\n"
            "Real link: [Real](real.md)\n",
        )
        targets = mod._extract_targets(doc)
        assert targets == [(2, "real.md")]


class TestResolve:
    def test_relative_from_doc_dir(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
        (tmp_path / "docs").mkdir()
        doc = tmp_path / "docs" / "a.md"
        doc.write_text("")
        (tmp_path / "docs" / "b.md").write_text("")
        assert mod._resolve("b.md", doc) == tmp_path.resolve() / "docs" / "b.md"

    def test_relative_with_parent(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
        (tmp_path / "docs").mkdir()
        doc = tmp_path / "docs" / "a.md"
        doc.write_text("")
        (tmp_path / "src.py").write_text("")
        assert mod._resolve("../src.py", doc) == tmp_path.resolve() / "src.py"

    def test_absolute_from_repo_root(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
        (tmp_path / "docs").mkdir()
        doc = tmp_path / "docs" / "a.md"
        doc.write_text("")
        assert mod._resolve("/README.md", doc) == tmp_path.resolve() / "README.md"

    def test_fragment_stripped(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
        (tmp_path / "docs").mkdir()
        doc = tmp_path / "docs" / "a.md"
        doc.write_text("")
        (tmp_path / "docs" / "b.md").write_text("")
        assert mod._resolve("b.md#section", doc) == tmp_path.resolve() / "docs" / "b.md"
