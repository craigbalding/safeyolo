"""Tests for scripts/check_website_claims.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_website_claims.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_website_claims", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()

CONTROLS = """
[[controls]]
id = "BB-01"
[[controls]]
id = "BB-02"
[[witnesses]]
controls = ["BB-01"]
"""


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    (tmp_path / "tests/blackbox").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests/blackbox/controls.toml").write_text(CONTROLS)
    (tmp_path / "docs/assurance-map.toml").write_text('[[decisions]]\nid = "identity"\n')
    (tmp_path / "tests/assurance.toml").write_text('[[factory_acceptance]]\nid = "FACTORY-X"\n')
    return tmp_path


def page(repo: Path, front: str) -> None:
    path = repo / "website/how-it-works/index.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\ntitle: T\n{front}---\n<p>Prose.</p>\n")


def test_committed_website_names_existing_witnessed_claims() -> None:
    assert mod.main() == 0


def test_each_claim_source_is_accepted(repo: Path) -> None:
    page(repo, "claims:\n- BB-01  # comment\n- decision:identity\n- factory:FACTORY-X\n")
    assert mod.check() == []


@pytest.mark.parametrize(("front", "problem"), [
    ("", "needs a non-empty claims list"),
    ("claims:\n", "needs a non-empty claims list"),
    ("claims:\n- BB-99\n", "unknown claim BB-99"),
    ("claims:\n- decision:missing\n", "unknown claim decision:missing"),
    ("claims:\n- BB-02\n", "BB-02 has no witness"),
    ("claims:\n- BB-01\n- BB-01\n", "BB-01 is listed twice"),
])
def test_ungrounded_pages_fail(repo: Path, front: str, problem: str) -> None:
    page(repo, front)
    assert any(problem in found for found in mod.check())


def test_unreadable_claim_source_exits_2(repo: Path) -> None:
    (repo / "docs/assurance-map.toml").write_text("not [toml")
    page(repo, "claims:\n- BB-01\n")
    assert mod.main() == 2
