"""Tests for scripts/check_skill_markers.py.

Covers:
- SKILL and DOC marker regex parsing (both in-line comment forms).
- Path resolution for SKILL refs (skill tree) and DOC refs (allowlist).
- End-to-end diff-driven behavior via a temp git repo.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_skill_markers.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_skill_markers", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


# ---------------------------------------------------------------------------
# Regex parsing
# ---------------------------------------------------------------------------

class TestSkillMarkerRegex:
    def test_matches_bare_ref(self):
        assert mod.SKILL_MARKER_RE.search("foo  # SKILL: agent-api.md").group(1) == "agent-api.md"

    def test_matches_ref_with_anchor(self):
        assert (
            mod.SKILL_MARKER_RE.search("x = 1  # SKILL: agent-api.md#flow-inspection").group(1)
            == "agent-api.md#flow-inspection"
        )

    def test_no_match_when_absent(self):
        assert mod.SKILL_MARKER_RE.search("plain line") is None


class TestDocMarkerRegex:
    def test_matches_single_ref(self):
        m = mod.DOC_MARKER_RE.search("def foo():  # DOC: README.md")
        assert m is not None
        refs = [r.strip() for r in m.group(1).split(",")]
        assert refs == ["README.md"]

    def test_matches_comma_separated(self):
        m = mod.DOC_MARKER_RE.search("x = 1  # DOC: README.md, docs/AGENTS.md")
        assert m is not None
        refs = [r.strip() for r in m.group(1).split(",")]
        assert refs == ["README.md", "docs/AGENTS.md"]

    def test_matches_anchor(self):
        m = mod.DOC_MARKER_RE.search("y = 2  # DOC: docs/DEVELOPERS.md#development-setup")
        assert m is not None
        refs = [r.strip() for r in m.group(1).split(",")]
        assert refs == ["docs/DEVELOPERS.md#development-setup"]

    def test_no_match_when_absent(self):
        assert mod.DOC_MARKER_RE.search("plain line") is None


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

class TestSkillRelpath:
    def test_valid_ref_resolves_under_repo(self):
        # Any file that exists under the skill tree works; use the SKILL_REF_DIR itself's parent
        # to check the resolution logic even if we don't reference a real file.
        rel = mod._skill_relpath("agent-api.md")
        assert rel is not None
        assert str(rel).startswith("cli/src/safeyolo/agent_context/skills/safeyolo/references/")

    def test_escaping_ref_returns_none(self):
        # SKILL_REF_DIR is 7 levels deep; use an absolute path to guarantee escape.
        assert mod._skill_relpath("/etc/passwd") is None


class TestDocRelpath:
    def test_allowlisted_ref_resolves(self):
        assert mod._doc_relpath("README.md") == Path("README.md")
        assert mod._doc_relpath("docs/AGENTS.md") == Path("docs/AGENTS.md")

    def test_anchor_stripped(self):
        assert mod._doc_relpath("docs/DEVELOPERS.md#development-setup") == Path(
            "docs/DEVELOPERS.md",
        )

    def test_non_allowlisted_returns_none(self):
        assert mod._doc_relpath("docs/FUTURE.md") is None  # design doc, not in allowlist
        assert mod._doc_relpath("secret/notes.md") is None
        assert mod._doc_relpath("../../etc/passwd") is None


# ---------------------------------------------------------------------------
# End-to-end via temp git repo
# ---------------------------------------------------------------------------

def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=cwd, text=True, stderr=subprocess.STDOUT,
    )


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Build a minimal repo mirroring the real layout so the script can run."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "master")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")

    # Layout: scripts/check_skill_markers.py (copy of the real script) +
    # its config dependencies (_doc_config.py + doc_allowlist.toml),
    # skill ref dir, plus the docs we want to reference.
    (repo / "scripts").mkdir()
    (repo / "scripts" / "check_skill_markers.py").write_bytes(SCRIPT_PATH.read_bytes())
    (repo / "scripts" / "_doc_config.py").write_bytes(
        (REPO_ROOT / "scripts" / "_doc_config.py").read_bytes(),
    )
    (repo / "scripts" / "doc_allowlist.toml").write_bytes(
        (REPO_ROOT / "scripts" / "doc_allowlist.toml").read_bytes(),
    )

    skill_dir = repo / "cli/src/safeyolo/agent_context/skills/safeyolo/references"
    skill_dir.mkdir(parents=True)
    (skill_dir / "agent-api.md").write_text("# Agent API\n")

    (repo / "README.md").write_text("# README\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "AGENTS.md").write_text("# Agents\n")
    (repo / "docs" / "DEVELOPERS.md").write_text("# Developers\n")

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _run_script(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/check_skill_markers.py"],
        cwd=repo,
        capture_output=True,
        text=True,
    )


class TestEndToEnd:
    def test_no_change_passes(self, fake_repo: Path):
        r = _run_script(fake_repo)
        assert r.returncode == 0, r.stderr

    def test_unmarked_source_change_passes(self, fake_repo: Path):
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("x = 1\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 0, r.stderr

    def test_doc_marker_added_with_matching_doc_passes(self, fake_repo: Path):
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("def foo():  # DOC: README.md\n    pass\n")
        (fake_repo / "README.md").write_text("# README updated\n")
        _git(fake_repo, "add", str(f), "README.md")
        r = _run_script(fake_repo)
        assert r.returncode == 0, r.stderr

    def test_pure_add_of_marker_does_not_require_doc_update(self, fake_repo: Path):
        """Adding a brand-new marker is declarative (binding claim → doc);
        it must NOT force a doc update. Only edits/removals require co-change."""
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("def foo():  # DOC: README.md\n    pass\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 0, r.stderr

    def test_editing_marker_line_content_requires_doc_update(self, fake_repo: Path):
        """Editing the code that carries an existing marker fires the check —
        the referent claim may no longer be accurate."""
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("x = 1  # DOC: README.md\n")
        (fake_repo / "README.md").write_text("# README v1\n")
        _git(fake_repo, "add", str(f), "README.md")
        _git(fake_repo, "commit", "-q", "-m", "add marker v1")

        # Edit the line (marker stays but body changed) without touching README
        f.write_text("x = 2  # DOC: README.md\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "DOC: README.md" in r.stderr

    def test_doc_marker_with_non_allowlisted_ref_fails_even_on_pure_add(
        self, fake_repo: Path,
    ):
        """Structural validation applies to every marker on any + line,
        including pure declarative adds. Typos and design-doc refs must fail."""
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("def foo():  # DOC: docs/FUTURE.md\n    pass\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "shipped-docs allowlist" in r.stderr

    def test_doc_marker_can_target_skill_file(self, fake_repo: Path):
        """DOC markers may point at agent-facing skill files (SKILL_FILES),
        not only user-facing docs. The allowlist is the union of both tiers."""
        # Materialise the skill file the allowlist glob would resolve to.
        skill_ref = (
            fake_repo
            / "cli/src/safeyolo/agent_context/skills/safeyolo/references/"
            / "contributing-to-safeyolo.md"
        )
        skill_ref.write_text("# contributing\n")
        f = fake_repo / "scripts" / "worker.py"
        f.write_text(
            "def foo():  # DOC: cli/src/safeyolo/agent_context/skills/safeyolo/"
            "references/contributing-to-safeyolo.md\n    pass\n",
        )
        _git(fake_repo, "add", str(f), str(skill_ref))
        r = _run_script(fake_repo)
        # Pure add — structural validation passes since the ref resolves.
        assert r.returncode == 0, r.stderr

    def test_doc_marker_multiple_refs_all_required_on_edit(self, fake_repo: Path):
        """On edit of a marked line, every listed ref must be co-changed."""
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("x = 1  # DOC: README.md, docs/AGENTS.md\n")
        (fake_repo / "README.md").write_text("# README v1\n")
        (fake_repo / "docs" / "AGENTS.md").write_text("# Agents v1\n")
        _git(fake_repo, "add", str(f), "README.md", "docs/AGENTS.md")
        _git(fake_repo, "commit", "-q", "-m", "add marker + docs v1")

        # Edit the marked line; only update one of the two required docs
        f.write_text("x = 2  # DOC: README.md, docs/AGENTS.md\n")
        (fake_repo / "README.md").write_text("# README v2\n")
        _git(fake_repo, "add", str(f), "README.md")
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "docs/AGENTS.md" in r.stderr

    def test_skill_marker_still_works_on_edit(self, fake_repo: Path):
        """SKILL markers use the same edit-triggers-drift semantics as DOC."""
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("x = 1  # SKILL: agent-api.md\n")
        _git(fake_repo, "add", str(f))
        _git(fake_repo, "commit", "-q", "-m", "add skill marker")

        f.write_text("x = 2  # SKILL: agent-api.md\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "SKILL: agent-api.md" in r.stderr

    def test_shell_script_marker_works_on_edit(self, fake_repo: Path):
        """Shell sources are scanned identically to Python sources."""
        f = fake_repo / "scripts" / "build.sh"
        f.write_text("#!/bin/sh\nSIZE_MB=2048  # DOC: README.md\n")
        (fake_repo / "README.md").write_text("# README v1\n")
        _git(fake_repo, "add", str(f), "README.md")
        _git(fake_repo, "commit", "-q", "-m", "add shell marker")

        f.write_text("#!/bin/sh\nSIZE_MB=4096  # DOC: README.md\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "DOC: README.md" in r.stderr

    def test_tests_directory_is_excluded(self, fake_repo: Path):
        """Test files legitimately embed marker syntax as fixtures; the checker
        must not treat those as real markers."""
        (fake_repo / "tests").mkdir()
        f = fake_repo / "tests" / "test_marker_check.py"
        f.write_text('assert "# ' + 'DOC: README.md" in fixture\n')
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 0, r.stderr

    def test_removing_marker_line_also_fails_without_doc_update(self, fake_repo: Path):
        f = fake_repo / "scripts" / "worker.py"
        f.write_text("def foo():  # DOC: README.md\n    pass\n")
        (fake_repo / "README.md").write_text("# README v1\n")
        _git(fake_repo, "add", str(f), "README.md")
        _git(fake_repo, "commit", "-q", "-m", "add marker")

        # Remove the marker; do not touch the doc.
        f.write_text("def foo():\n    pass\n")
        _git(fake_repo, "add", str(f))
        r = _run_script(fake_repo)
        assert r.returncode == 1
        assert "not modified" in r.stderr
