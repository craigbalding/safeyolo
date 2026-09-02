"""Tests for the bundled SafeYolo teaching skill and its helpers."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SKILL = REPO_ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo-demo-lab"


def test_demo_skill_is_codex_scoped_and_uses_bundled_paths() -> None:
    content = (DEMO_SKILL / "SKILL.md").read_text()
    _, frontmatter, body = content.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert set(metadata) == {"name", "description"}
    assert metadata["name"] == "safeyolo-demo-lab"
    assert "SafeYolo Codex tmux lab" in metadata["description"]
    assert "safeyolo-lab-controller" in body
    assert "scripts/request-story.sh" in body
    assert "references/structured-lessons.md" in body

    all_text = "\n".join(
        path.read_text()
        for path in DEMO_SKILL.rglob("*")
        if path.is_file()
    )
    assert "$HOME/.codex/skills" not in all_text
    assert "/home/agent/.codex/skills" not in all_text
    assert "/safeyolo/skills/safeyolo-demo-lab" in all_text


def test_demo_helpers_pass_self_test() -> None:
    if shutil.which("jq") is None:
        pytest.skip("jq is not installed")

    script = DEMO_SKILL / "scripts/self-test.sh"
    assert script.stat().st_mode & 0o111
    result = subprocess.run(
        [str(script)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "PASS: safeyolo-demo-lab helper self-test" in result.stdout
