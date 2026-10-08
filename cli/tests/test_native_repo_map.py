"""Drive the native command against the retained repository-map behavior fixtures."""

import json
import os
import subprocess
import tempfile
import unicodedata
from pathlib import Path

import pytest
import repo_map_reference as reference
from hypothesis import example, given, settings
from hypothesis import strategies as st
from test_repo_map import _repository

BINARY = Path(__file__).resolve().parents[2] / "proxy/target/debug/safeyolo-coord"


def _run(repository, *args, check=True):
    return subprocess.run([str(BINARY), "repo-map", *map(str, args)], cwd=repository,
                          env=os.environ.copy(), capture_output=True, text=True, check=check, timeout=10)


@pytest.mark.parametrize("scope", ["pkg/app.py", "pkg", "scripts/start.sh", "scripts", "tests"])
def test_native_structural_map_retains_python_and_shell_views(tmp_path, scope):
    repository = _repository(tmp_path)
    (repository / "tests").mkdir()
    (repository / "tests/test_app.py").write_text("def test_service():\n    pass\n")
    path = repository / scope
    expected = reference.build_repo_map(path)
    result = _run(repository, path)
    for line in expected.text.splitlines():
        assert line in result.stdout
    assert f"scope={scope}" in result.stdout
    assert f"files={expected.files} symbols={expected.symbols}" in result.stdout


def test_native_detailed_signatures_preserve_decorators_annotations_and_imports(tmp_path):
    repository = _repository(tmp_path)
    path = repository / "pkg/app.py"
    path.write_text(
        "from dataclasses import dataclass\nfrom pathlib import Path\n"
        "from safeyolo.coord import api\nfrom .models import Result, WorkTarget\n\n"
        "@dataclass(frozen=True)\nclass Service(BaseService):\n"
        "    current: WorkTarget | None\n    @property\n"
        "    def ready(self) -> bool:\n        return self.current is not None\n"
        "    async def run(self: 'Service', target: WorkTarget, *, force: bool = False) -> Result:\n"
        "        return Result()\n"
    )
    expected = reference.build_repo_map(path)
    result = _run(repository, path)
    for line in expected.text.splitlines():
        assert line in result.stdout
    assert "pathlib" not in result.stdout


def test_native_map_reads_current_sources_and_compacts_scopes(tmp_path):
    repository = _repository(tmp_path)
    (repository / "pkg/app.py").write_text("def changed():\n    pass\n")
    (repository / "pkg/new.py").write_text("def untracked():\n    pass\n")
    result = _run(repository, repository / "pkg", repository)
    assert "def changed @1-2" in result.stdout
    assert "def untracked @1-2" in result.stdout
    assert "def create" not in result.stdout
    assert "scope=." not in result.stdout
    assert result.stdout.count("pkg/app.py") == 1


def test_native_map_bounds_overview_and_internal_imports(tmp_path):
    repository = _repository(tmp_path)
    path = repository / "pkg/app.py"
    path.write_text("".join(f"import safeyolo.module_{i}\n" for i in range(10))
                    + "".join(f"def public_{i}():\n    pass\n" for i in range(9))
                    + "def _private():\n    pass\n")
    detail = _run(repository, path).stdout
    assert detail.count("  uses import safeyolo.module_") == 8
    assert "uses +2 internal imports" in detail
    assert "def _private()" in detail
    overview = _run(repository, path.parent).stdout
    assert "+5 symbols" in overview
    assert "_private" not in overview


@pytest.mark.parametrize("query", ["api.send", "api.send()", "pkg.api.send"])
def test_native_exact_symbol_preview_preserves_definition_and_lexical_use(tmp_path, query):
    repository = _repository(tmp_path)
    (repository / "pkg/api.py").write_text(
        "def send(body: str, *, notify=None):\n"
        '    """Send without attention unless notify is supplied."""\n'
        "    return body, notify\n")
    (repository / "pkg/admin_api.py").write_text("def send(body):\n    return body\n")
    (repository / "tests").mkdir()
    (repository / "tests/test_api.py").write_text(
        'from pkg import api\n\ndef test_send():\n    assert api.send("hello", notify=["worker"])\n')
    result = _run(repository, repository, "--query", query)
    assert "DEFINITION pkg/api.py:1-3" in result.stdout
    assert "1: def send(body: str, *, notify=None):" in result.stdout
    assert '2:     """Send without attention unless notify is supplied."""' in result.stdout
    assert "admin_api.py" not in result.stdout
    # The lexical usage example follows the exact query, as in the retained tool.
    if query.startswith("api.send"):
        assert "EXAMPLE USE (text match; binding not verified) tests/test_api.py:4" in result.stdout


def test_native_qualified_method_preview_keeps_decorator_and_bounded_tail(tmp_path):
    repository = _repository(tmp_path)
    path = repository / "pkg/app.py"
    path.write_text("class Service:\n    @staticmethod\n    def create(name='default'):\n        return name\n"
                    "class Other:\n    def create(self):\n        pass\n")
    result = _run(repository, repository, "--query", "Service.create")
    assert "DEFINITION pkg/app.py:2-4" in result.stdout
    assert "2:     @staticmethod" in result.stdout
    assert "Other" not in result.stdout
    path.write_text("def lengthy():\n" + "    # implementation\n" * 100 + "    return 'end'\n")
    result = _run(repository, repository, "--query", "lengthy")
    assert "DEFINITION pkg/app.py:1-102" in result.stdout
    assert "42 lines omitted; full range 1-102" in result.stdout
    assert "102:     return 'end'" in result.stdout


def test_native_query_cache_follows_edits_and_renames(tmp_path):
    repository = _repository(tmp_path)
    path = repository / "pkg/app.py"
    assert "DEFINITION pkg/app.py:5-6" in _run(repository, repository, "--query", "app.create").stdout
    repeated = _run(repository, repository, "--query", "app.create").stdout
    assert "indexed=0" in repeated
    path.write_text("def replacement():\n    return 42\n")
    assert "DEFINITION" not in _run(repository, repository, "--query", "app.create").stdout
    assert "return 42" in _run(repository, repository, "--query", "app.replacement").stdout
    path.rename(repository / "pkg/renamed.py")
    assert "DEFINITION" not in _run(repository, repository, "--query", "app.replacement").stdout
    assert "DEFINITION pkg/renamed.py:1-2" in _run(repository, repository, "--query", "renamed.replacement").stdout


def test_native_guidance_keeps_tests_and_documents_visible(tmp_path):
    repository = _repository(tmp_path)
    (repository / "tests").mkdir()
    (repository / "tests/test_service.py").write_text("def test_service():\n    assert True\n")
    for number in range(3):
        (repository / f"guide{number}.md").write_text("Service lifecycle guidance\n")
    (repository / "repo-map.toml").write_text(
        'version = 1\n[[hints]]\nid = "service"\ntriggers = ["service lifecycle"]\n'
        'advice = "Use existing service."\nsource = "guide0.md"\n'
        'paths = ["scripts/start.sh", "pkg/app.py", "guide0.md", "guide1.md", "guide2.md"]\n')
    result = _run(repository, repository, "--query", "Repair lifecycle of the service", "--limit", 6)
    assert "GUIDANCE (repository-authored, not syntax-derived)" in result.stdout
    assert "[service]" in result.stdout
    assert "source: guide0.md" in result.stdout
    assert result.stdout.index("- scripts/start.sh") < result.stdout.index("- pkg/app.py")
    assert "RELATED TESTS" in result.stdout and "tests/test_service.py" in result.stdout
    assert "RELATED DOCUMENTATION" in result.stdout


def test_native_query_excludes_outside_broken_and_looping_links(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    repository = _repository(checkout)
    outside = tmp_path / "outside.py"
    outside.write_text("def outside_helper():\n    return 'outside-only-sentinel'\n")
    (repository / "escape.py").symlink_to(outside)
    (repository / "local_alias.py").symlink_to("pkg/app.py")
    (repository / "broken.py").symlink_to("missing.py")
    (repository / "loop.py").symlink_to("loop.py")
    mapped = _run(repository, repository).stdout
    assert "local_alias.py" in mapped
    assert all(name not in mapped for name in ("escape.py", "broken.py", "loop.py"))
    result = _run(repository, repository, "--query", "outside_helper").stdout
    assert "outside-only-sentinel" not in result and "escape.py" not in result


def test_native_repository_and_file_paths_keep_unix_bytes(tmp_path):
    repository = tmp_path / os.fsdecode(b"checkout-\xff")
    repository.mkdir()
    _repository(repository)
    path = repository / os.fsdecode(b"source-\x80.py")
    path.write_text("def byte_filename():\n    return 42\n")
    result = _run(repository, path)
    assert "def byte_filename() @1-2" in result.stdout
    result = _run(repository, repository, "--query", "byte_filename")
    assert "return 42" in result.stdout


def test_native_installed_guidance_is_project_bound_and_local_guidance_wins(tmp_path):
    repository = _repository(tmp_path)
    installed = tmp_path / "installed"
    installed.mkdir()
    binary = installed / "safeyolo-coord"
    os.link(BINARY.resolve(), binary)
    guidance = installed / "repo-map.toml"
    guidance.write_text('version = 1\nproject = "example"\n[[hints]]\nid = "installed"\n'
                        'triggers = ["service"]\nadvice = "Reuse the service."\nsource = "README.md"\n')

    def query():
        return subprocess.run([str(binary), "repo-map", "--query", "service"], cwd=repository,
                              capture_output=True, text=True, check=True).stdout

    try:
        project = repository / "pyproject.toml"
        for contents in (None, '[project]\nname = "other"\n', "malformed = ["):
            if contents is not None:
                project.write_text(contents)
            assert "[installed]" not in query()
        project.write_text('[project]\nname = "example"\n')
        assert f"guidance_file={guidance}" in query()
        assert "[installed]" in query()
        (repository / "repo-map.toml").write_text("version = 1\n")
        assert "[installed]" not in query()
        assert f"guidance_file={repository / 'repo-map.toml'}" in query()
    finally:
        binary.unlink()


@pytest.mark.parametrize("reference", ["issue 571", "Issue #571", "issue-571", "PR 571", "pr #571", "pull request 571", "Review #571"])
def test_native_queries_remove_work_item_references_before_ranking(tmp_path, reference):
    repository = _repository(tmp_path)
    (repository / "number.py").write_text("def unrelated():\n    return 571\n")
    result = _run(repository, repository, "--query", f"{reference} absent_quasar")
    assert "number.py" not in result.stdout


@pytest.mark.parametrize("contents", ["malformed = [", "version = 2\n", 'version = 1\nhints = "wrong"\n',
                                      'version = 1\n[[hints]]\ntriggers = ["service"]\n'])
def test_native_query_reports_invalid_repository_guidance(tmp_path, contents):
    repository = _repository(tmp_path)
    (repository / "repo-map.toml").write_text(contents)
    result = _run(repository, repository, "--query", "service", check=False)
    assert result.returncode != 0
    assert result.stderr and "panicked" not in result.stderr
    assert not result.stdout


def test_native_query_recovers_invalid_cached_source_ranges(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    repository = _repository(checkout)
    _run(repository, repository, "--query", "app.create")
    cache = next((tmp_path / "home/.cache/safeyolo/repo-map").glob("native-*.json"))
    data = json.loads(cache.read_text())
    for entry in data.values():
        for symbol in entry["symbols"]:
            symbol["end"] = 0
    cache.write_text(json.dumps(data))
    result = _run(repository, repository, "--query", "app.create")
    assert "DEFINITION pkg/app.py:5-6" in result.stdout


@pytest.mark.parametrize("class_name,method_name", [("K", "ﬃ"), ("Ａ", "K"), ("é", "µ")])
def test_native_python_names_and_async_status_survive_cache_reapply(tmp_path, monkeypatch, class_name, method_name):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    repository = _repository(checkout)
    path = repository / "pkg/app.py"
    path.write_text(f"class {class_name}:\n    µ: int\n    async\tdef {method_name}(self, K):\n        return K\n")
    expected = reference.build_repo_map(path)
    mapped = _run(repository, path).stdout
    for line in expected.text.splitlines():
        assert line in mapped
    query = "app." + unicodedata.normalize("NFKC", f"{class_name}.{method_name}")
    first = _run(repository, repository, "--query", query).stdout
    assert "DEFINITION pkg/app.py:3-4" in first
    warm = _run(repository, repository, "--query", query).stdout
    assert "indexed=0" in warm and "DEFINITION pkg/app.py:3-4" in warm
    cache = next((tmp_path / "home/.cache/safeyolo/repo-map").glob("native-*.json"))
    data = json.loads(cache.read_text())
    # Old derived entries have no parser version and can contain the source's
    # unnormalized name and the former synchronous async-tab signature.
    for entry in data.values():
        entry.pop("version", None)
        for symbol in entry["symbols"]:
            symbol["name"] = method_name
            symbol["qualified"] = f"{class_name}.{method_name}"
            symbol["signature"] = symbol["signature"].replace("async ", "")
    cache.write_text(json.dumps(data))
    corrected = _run(repository, repository, "--query", query).stdout
    assert "cached=0" in corrected and "DEFINITION pkg/app.py:3-4" in corrected
    assert "indexed=0" in _run(repository, repository, "--query", query).stdout


@settings(max_examples=40, deadline=None, database=None)
@given(filename=st.binary(min_size=1, max_size=12).filter(lambda name: b"\0" not in name and b"/" not in name),
       asynchronous=st.booleans(), argument=st.sampled_from(["item", "item: str", "item: list[str]", "*items: str", "K: str"]),
       gap=st.sampled_from([" ", "\t", " \t", "\f"]), name=st.sampled_from(["generated_probe", "K", "ﬃ", "Ａ", "é"]))
@example(filename=b"case", asynchronous=True, argument="item", gap="\t", name="K")
@example(filename=b"ascii", asynchronous=True, argument="item", gap="\t", name="generated_probe")
def test_native_syntax_and_path_bytes_keep_ast_symbols_without_string_definitions(filename, asynchronous, argument, gap, name):
    with tempfile.TemporaryDirectory(prefix="map-generated-", dir=os.environ.get("TMPDIR")) as directory:
        repository = _repository(Path(directory))
        path = repository / os.fsdecode(b"source-" + filename + b".py")
        path.write_text(f"{'async' + gap if asynchronous else ''}def {name}({argument}) -> str:\n"
                        '    """Source text is not a second definition.\n'
                        'def phantom_function():\n'
                        '    return "phantom"\n'
                        '    """\n'
                        '    return "actual"\n')
        expected, count = reference._python_symbols(path, overview=False)
        assert count == 1
        mapped = _run(repository, path).stdout
        normalized = unicodedata.normalize("NFKC", name)
        for line in expected:
            if f"{normalized}(" in line:
                assert line in mapped
        assert "def phantom_function" not in mapped
        queried = _run(repository, repository, "--query", normalized).stdout
        assert queried.count("DEFINITION ") == 1
        assert "EXAMPLE USE" not in queried
        assert 'return "actual"' in queried


@pytest.mark.parametrize("args", [("--query", "fixture", ".", "pkg"), ("--limit", "0"), ("--unknown",)])
def test_native_repo_map_invalid_arguments_are_actionable(tmp_path, args):
    repository = _repository(tmp_path)
    result = _run(repository, *args, check=False)
    assert result.returncode != 0
    assert result.stderr and "panicked" not in result.stderr
    assert not result.stdout
