"""Tests for the compact repository map."""

import subprocess
from pathlib import Path

from safeyolo.repo_map import build_repo_map, build_repo_query, main


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

    result = build_repo_map(repository / "pkg/app.py")

    assert "pkg/app.py\n  class Service @1-3" in result.text
    assert "    async def run(target, *, force) @2-3" in result.text
    assert "  def create(name) @5-6" in result.text
    assert result.files == 1
    assert result.symbols == 3


def test_detailed_map_shows_python_type_and_internal_module_relationships(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/app.py").write_text(
        "from dataclasses import dataclass\n"
        "from pathlib import Path\n"
        "from safeyolo.coord import api\n"
        "from .models import Result, WorkTarget\n\n"
        "@dataclass(frozen=True)\n"
        "class Service(BaseService):\n"
        "    current: WorkTarget | None\n"
        "    @property\n"
        "    def ready(self) -> bool:\n"
        "        return self.current is not None\n"
        "    async def run(self: 'Service', target: WorkTarget, *, force: bool = False) -> Result:\n"
        "        return Result()\n"
    )

    result = build_repo_map(repository / "pkg/app.py")

    assert "uses from safeyolo.coord import api" in result.text
    assert "uses from .models import Result, WorkTarget" in result.text
    assert "pathlib" not in result.text
    assert "@dataclass(frozen=True)" in result.text
    assert "class Service(BaseService) @7-13" in result.text
    assert "current: WorkTarget | None @8" in result.text
    assert "@property\n    def ready() -> bool @10-11" in result.text
    assert "async def run(target: WorkTarget, *, force: bool) -> Result @12-13" in result.text


def test_detailed_map_bounds_internal_import_statements(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/app.py").write_text("".join(f"import safeyolo.module_{index}\n" for index in range(10)))

    result = build_repo_map(repository / "pkg/app.py")

    assert result.text.count("  uses import safeyolo.module_") == 8
    assert "  uses +2 internal imports" in result.text


def test_map_contains_shell_functions(tmp_path):
    repository = _repository(tmp_path)
    with (repository / "scripts/start.sh").open("a") as script:
        script.write("if { true; }; then\n  true\nfi\n")

    result = build_repo_map(repository / "scripts/start.sh")

    assert "scripts/start.sh\n  function start_service() @1" in result.text
    assert "function if" not in result.text
    assert result.symbols == 1


def test_overview_omits_methods_private_symbols_and_tests(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/test_app.py").write_text("def test_service():\n    pass\n")

    result = build_repo_map(repository)

    assert "class Service @1-3" in result.text
    assert "async def run" not in result.text
    assert "def create @5-6" in result.text
    assert "test_app.py" not in result.text
    assert "ignored.py" not in result.text
    assert "function start_service() @1" in result.text


def test_map_scope_limits_files(tmp_path):
    repository = _repository(tmp_path)

    result = build_repo_map(repository / "pkg")

    assert result.scope == Path("pkg")
    assert "pkg/app.py" in result.text
    assert "scripts/start.sh" not in result.text


def test_directory_map_uses_one_bounded_line_per_file(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/many.py").write_text("".join(f"def symbol_{index}():\n    pass\n" for index in range(9)))

    result = build_repo_map(repository / "pkg")

    lines = result.text.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("pkg/app.py | class Service @1-3; def create @5-6")
    assert lines[1].endswith("+5 symbols")
    assert "async def run" not in result.text


def test_directory_map_lists_test_files_without_every_test_symbol(tmp_path):
    repository = _repository(tmp_path)
    (repository / "tests").mkdir()
    (repository / "tests/test_many.py").write_text(
        "".join(f"def test_case_{index}():\n    pass\n" for index in range(20))
    )

    result = build_repo_map(repository / "tests")

    assert result.text == "tests/test_many.py"
    assert result.symbols == 20


def test_map_reads_uncommitted_and_untracked_source(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/app.py").write_text("def changed():\n    pass\n")
    (repository / "pkg/new.py").write_text("def untracked():\n    pass\n")

    result = build_repo_map(repository)

    assert "def changed @1-2" in result.text
    assert "def create" not in result.text
    assert "pkg/new.py | def untracked @1-2" in result.text


def test_command_reports_scope_and_observability(tmp_path, capsys):
    repository = _repository(tmp_path)

    exit_code = main([str(repository / "pkg")])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert output.startswith("# repo-map scope=pkg mode=overview files=1 symbols=2 elapsed_ms=")
    assert "pkg/app.py" in output


def test_command_accepts_multiple_scopes(tmp_path, capsys):
    repository = _repository(tmp_path)

    exit_code = main([str(repository / "pkg"), str(repository / "scripts")])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "# repo-map scope=pkg mode=overview" in output
    assert "# repo-map scope=scripts mode=overview" in output
    assert "pkg/app.py" in output
    assert "scripts/start.sh" in output


def test_command_compacts_overlapping_scopes(tmp_path, capsys):
    repository = _repository(tmp_path)

    exit_code = main([str(repository / "pkg"), str(repository)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "# repo-map scope=pkg mode=overview" in output
    assert "scope=." not in output
    assert output.count("pkg/app.py") == 1


def test_command_rejects_non_repository(tmp_path, capsys):
    exit_code = main([str(tmp_path)])

    assert exit_code == 2
    assert "not inside a Git working tree" in capsys.readouterr().err


def test_task_query_combines_locations_and_repository_guidance(tmp_path):
    repository = _repository(tmp_path)
    (repository / "repo-map.toml").write_text(
        "version = 1\n"
        "[[hints]]\n"
        'id = "service-lifecycle"\n'
        'triggers = ["service lifecycle", "async service"]\n'
        'advice = "Inspect the service entrypoint before changing callers."\n'
        'paths = ["scripts/start.sh", "pkg/app.py"]\n'
        'source = "docs/service.md"\n'
    )

    result = build_repo_query(
        repository,
        "Repair the async service lifecycle and its run target.",
    )

    assert "GUIDANCE (repository-authored, not syntax-derived)" in result.text
    assert "[service-lifecycle]" in result.text
    assert "source: docs/service.md" in result.text
    assert "LIKELY IMPLEMENTATION (lexical + repository guidance; returned-file symbols)" in result.text
    assert result.text.index("scripts/start.sh") < result.text.index("pkg/app.py")
    assert "function run @2-3" in result.text


def test_task_query_reads_the_current_working_tree(tmp_path):
    repository = _repository(tmp_path)
    cache = tmp_path / "query-cache.json"
    first = build_repo_query(repository, "quasar routing", cache_path=cache)
    assert "pkg/app.py" not in first.text
    assert first.indexed_files == 3
    assert first.cached_files == 0

    (repository / "pkg/app.py").write_text("def route_quasar_signal():\n    pass\n")
    refreshed = build_repo_query(repository, "quasar routing", cache_path=cache)

    assert "pkg/app.py" in refreshed.text
    assert "function route_quasar_signal @1-2" in refreshed.text
    assert refreshed.indexed_files == 1
    assert refreshed.cached_files == 2


def test_command_exposes_task_query_observability(tmp_path, capsys):
    repository = _repository(tmp_path)

    exit_code = main(["--query", "create service", "--limit", "4", str(repository)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert output.startswith("# repo-map mode=query head=")
    assert "files=" in output
    assert "elapsed_ms=" in output
    assert "pkg/app.py" in output
