"""Tests for scripts/check_doc_constants.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_doc_constants.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_doc_constants", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


@pytest.fixture
def make_repo(tmp_path: Path, monkeypatch):
    """Point the module at a temp repo layout for the duration of the test."""
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    return tmp_path


class TestCheckOne:
    def test_capture_and_must_contain_pass(self, make_repo):
        (make_repo / "src.sh").write_text('SIZE="${SIZE:-2048}"\n')
        (make_repo / "doc.md").write_text("The default is 2048 MiB.\n")
        problems = mod._check_one({
            "name": "test",
            "source": "src.sh",
            "pattern": r'SIZE="\$\{SIZE:-(?P<size>\d+)\}"',
            "docs": ["doc.md"],
            "must_contain": "{size} MiB",
        })
        assert problems == []

    def test_must_contain_absent_fails(self, make_repo):
        (make_repo / "src.sh").write_text('SIZE="${SIZE:-2048}"\n')
        (make_repo / "doc.md").write_text("The default is 4096 MiB.\n")
        problems = mod._check_one({
            "name": "size",
            "source": "src.sh",
            "pattern": r'SIZE="\$\{SIZE:-(?P<size>\d+)\}"',
            "docs": ["doc.md"],
            "must_contain": "{size} MiB",
        })
        assert len(problems) == 1
        assert "2048 MiB" in problems[0]

    def test_forbidden_phrase_fails(self, make_repo):
        (make_repo / "src.sh").write_text('SIZE="${SIZE:-2048}"\n')
        (make_repo / "doc.md").write_text(
            "The default is 2048 MiB with 20% headroom.\n",
        )
        problems = mod._check_one({
            "name": "size",
            "source": "src.sh",
            "pattern": r'SIZE="\$\{SIZE:-(?P<size>\d+)\}"',
            "docs": ["doc.md"],
            "must_contain": "{size} MiB",
            "forbidden": ["20% headroom"],
        })
        assert len(problems) == 1
        assert "20% headroom" in problems[0]

    def test_source_pattern_no_match_fails(self, make_repo):
        (make_repo / "src.sh").write_text("nothing here\n")
        (make_repo / "doc.md").write_text("2048\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'SIZE="\$\{SIZE:-(?P<size>\d+)\}"',
            "docs": ["doc.md"],
            "must_contain": "{size}",
        })
        assert len(problems) == 1
        assert "pattern did not match" in problems[0]

    def test_source_file_missing_fails(self, make_repo):
        (make_repo / "doc.md").write_text("x\n")
        problems = mod._check_one({
            "name": "n",
            "source": "does-not-exist.sh",
            "pattern": r'x',
            "docs": ["doc.md"],
            "must_contain": "x",
        })
        assert len(problems) == 1
        assert "source file not found" in problems[0]

    def test_multiple_docs_all_checked(self, make_repo):
        (make_repo / "src.sh").write_text('SIZE="${SIZE:-2048}"\n')
        (make_repo / "a.md").write_text("2048 MiB\n")
        (make_repo / "b.md").write_text("nothing\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'SIZE="\$\{SIZE:-(?P<size>\d+)\}"',
            "docs": ["a.md", "b.md"],
            "must_contain": "{size} MiB",
        })
        assert len(problems) == 1
        assert "b.md" in problems[0]

    def test_no_must_contain_only_forbidden(self, make_repo):
        (make_repo / "src.sh").write_text("marker\n")
        (make_repo / "doc.md").write_text("bad thing here\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r"marker",
            "docs": ["doc.md"],
            "forbidden": ["bad thing"],
        })
        assert len(problems) == 1
        assert "bad thing" in problems[0]


class TestMustContainAny:
    def test_first_alternative_present_passes(self, make_repo):
        (make_repo / "src.sh").write_text('IP="127.0.0.1"\n')
        (make_repo / "doc.md").write_text("Binds to 127.0.0.1 only.\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'IP="(?P<ip>[0-9.]+)"',
            "docs": ["doc.md"],
            "must_contain_any": ["{ip}", "loopback only"],
        })
        assert problems == []

    def test_second_alternative_present_passes(self, make_repo):
        (make_repo / "src.sh").write_text('IP="127.0.0.1"\n')
        (make_repo / "doc.md").write_text("Binds loopback only.\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'IP="(?P<ip>[0-9.]+)"',
            "docs": ["doc.md"],
            "must_contain_any": ["{ip}", "loopback only"],
        })
        assert problems == []

    def test_no_alternative_present_fails(self, make_repo):
        (make_repo / "src.sh").write_text('IP="127.0.0.1"\n')
        (make_repo / "doc.md").write_text("Binds to something unrelated.\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'IP="(?P<ip>[0-9.]+)"',
            "docs": ["doc.md"],
            "must_contain_any": ["{ip}", "loopback only"],
        })
        assert len(problems) == 1
        assert "127.0.0.1" in problems[0]
        assert "loopback only" in problems[0]

    def test_both_must_contain_and_must_contain_any_is_error(self, make_repo):
        (make_repo / "src.sh").write_text("marker\n")
        (make_repo / "doc.md").write_text("x\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r"marker",
            "docs": ["doc.md"],
            "must_contain": "x",
            "must_contain_any": ["y", "z"],
        })
        assert len(problems) == 1
        assert "either" in problems[0].lower()

    def test_alternatives_template_with_captures(self, make_repo):
        (make_repo / "src.sh").write_text('VER="2048"\n')
        (make_repo / "doc.md").write_text("Default 2048 MiB image size.\n")
        problems = mod._check_one({
            "name": "n",
            "source": "src.sh",
            "pattern": r'VER="(?P<v>\d+)"',
            "docs": ["doc.md"],
            "must_contain_any": ["{v} MiB", "{v}MiB"],
        })
        assert problems == []
