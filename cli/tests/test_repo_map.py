"""Tests for the compact repository map."""

import subprocess
from pathlib import Path

from safeyolo.repo_map import build_repo_map, main


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)


def _repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/app.py").write_text(
        "class Service:\n"
        "    async def run(self, target, *, force=False):\n"
        "        return target\n\n"
        "def create(name):\n"
        "    return Service()\n"
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/start.sh").write_text("start_service() {\n  true\n}\n")
    (tmp_path / "ignored.py").write_text("def ignored():\n    pass\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    _git(tmp_path, "add", ".")
    return tmp_path


def test_map_contains_compact_python_symbols(tmp_path):
    repository = _repository(tmp_path)

    result = build_repo_map(repository / "pkg")

    assert "pkg/app.py\n  class Service @1" in result.text
    assert "    async def run(target, *, force) @2" in result.text
    assert "  def create(name) @5" in result.text
    assert result.files == 1
    assert result.symbols == 3


def test_map_contains_shell_functions(tmp_path):
    repository = _repository(tmp_path)
    with (repository / "scripts/start.sh").open("a") as script:
        script.write("if { true; }; then\n  true\nfi\n")

    result = build_repo_map(repository / "scripts")

    assert "scripts/start.sh\n  function start_service() @1" in result.text
    assert "function if" not in result.text
    assert result.symbols == 1


def test_overview_omits_methods_private_symbols_and_tests(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/test_app.py").write_text("def test_service():\n    pass\n")

    result = build_repo_map(repository)

    assert "class Service @1" in result.text
    assert "async def run" not in result.text
    assert "def create @5" in result.text
    assert "test_app.py" not in result.text
    assert "ignored.py" not in result.text
    assert "function start_service() @1" in result.text


def test_map_scope_limits_files(tmp_path):
    repository = _repository(tmp_path)

    result = build_repo_map(repository / "pkg")

    assert result.scope == Path("pkg")
    assert "pkg/app.py" in result.text
    assert "scripts/start.sh" not in result.text


def test_map_reads_uncommitted_and_untracked_source(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/app.py").write_text("def changed():\n    pass\n")
    (repository / "pkg/new.py").write_text("def untracked():\n    pass\n")

    result = build_repo_map(repository)

    assert "def changed @1" in result.text
    assert "def create" not in result.text
    assert "pkg/new.py\n  def untracked @1" in result.text


def test_command_reports_scope_and_observability(tmp_path, capsys):
    repository = _repository(tmp_path)

    exit_code = main([str(repository / "pkg")])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert output.startswith(
        "# repo-map scope=pkg mode=detail files=1 symbols=3 elapsed_ms="
    )
    assert "pkg/app.py" in output


def test_command_rejects_non_repository(tmp_path, capsys):
    exit_code = main([str(tmp_path)])

    assert exit_code == 2
    assert "not inside a Git working tree" in capsys.readouterr().err
