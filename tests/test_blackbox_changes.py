"""Materiality and publication controls for trusted blackbox change notices."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/assurance" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


changes = load("blackbox_changes")
notices = load("notify_blackbox")
BASE, HEAD = "a" * 40, "b" * 40
TEST = "tests/blackbox/isolation/test_probe.py"
RUST = "proxy/tests/credential_http/codex.rs"
WORKFLOW = ".github/workflows/blackbox.yml"
ORIGINAL = 'def test_denied():\n    """Denial assurance."""\n    assert origin_count() == 0\n'


class Source:
    def __init__(self, files, sha=BASE):
        self.source, self.sha = files, sha
        self.files = {path: ("100644", "blob", changes.digest(source)) for path, source in files.items()}

    def read(self, name):
        return self.source.get(name, "")


@pytest.fixture
def sources():
    controls = "\n".join(f'[[controls]]\nid = "BB-{number:02}"\ndecisions = ["test"]\n'
                         for number in range(1, 38))
    controls += f'[[witnesses]]\npaths = ["{TEST}"]\ncontrols = ["BB-01"]\nkind = "pytest"\n'
    controls += f'[[witnesses]]\npaths = ["{RUST}"]\ncontrols = ["BB-10"]\nkind = "cargo"\n'
    return {changes.CATALOGUE: controls, changes.MAP: '[[decisions]]\nid = "test"\ntests = []\n',
            TEST: ORIGINAL, RUST: '#[test]\nfn refresh() { assert_eq!(refresh_count(), 1); }\n',
            WORKFLOW: 'on:\n  schedule:\n    - cron: "17 3 * * *"\njobs:\n  guest:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python tests/blackbox/installed_sections.py --lane systrap\n',
            changes.SELF: 'def filter_changes(rows):\n    return rows\n',
            changes.PUBLISHER: 'def notify(rows):\n    return rows\n',
            changes.WORKFLOW: 'on: [push]\njobs:\n  analyze:\n    steps:\n      - run: python tools/assurance/blackbox_changes.py\n'}


def compare(files, edits):
    candidate = files | edits
    candidate = {path: content for path, content in candidate.items() if content is not None}
    return changes.compare(Source(files), Source(candidate, HEAD))


@pytest.mark.parametrize(("path", "before", "after"), [
    (TEST, "origin_count() == 0", "origin_count() <= 1"),
    (TEST, "assert origin_count() == 0", "pytest.skip('disabled')"),
    (TEST, "assert origin_count() == 0", "assert origin_count() == 0, 'changed failure handling'"),
    (RUST, "refresh_count(), 1", "refresh_count(), 2"),
    (changes.SELF, "return rows", "return []"),
    (changes.PUBLISHER, "return rows", "return []"),
    (WORKFLOW, "--lane systrap", "--lane vz"),
    (WORKFLOW, '17 3 * * *', '17 3 * * 1'),
])
def test_material_definitions(sources, path, before, after):
    report = compare(sources, {path: sources[path].replace(before, after)})
    assert report["delta_id"]
    assert [(row["path"], row["status"]) for row in report["changes"]] == [(path, "material")]
    assert report["changes"][0]["reason"]
    if path == TEST:
        assert report["changes"][0]["controls"] == ["BB-01"]
        assert report["changes"][0]["edits"][0]["unit"] == "test_denied#0"


def test_oracle_change_with_unchanged_explanation_is_material(sources):
    assert compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})["delta_id"]


def test_removal_or_new_check_cannot_disappear_with_candidate_map(sources):
    altered = sources[changes.CATALOGUE].replace(f'paths = ["{TEST}"]', 'paths = []')
    report = compare(sources, {TEST: None, changes.CATALOGUE: altered})
    assert {row["path"] for row in report["changes"] if row["status"] == "material"} == {TEST, changes.CATALOGUE}
    assert compare(sources, {"tests/blackbox/isolation/test_new.py": "def test_new():\n    assert False\n"})["delta_id"]


@pytest.mark.parametrize(("path", "content"), [
    (TEST, '# comment\ndef test_denied( ):\n    """Reworded documentation."""\n    assert (origin_count() == 0)\n'),
    (TEST, ORIGINAL.replace("    assert", "    pass\n    assert")),
    (RUST, '// comment\n#[test]\nfn refresh( ) {\n /* nested /* comment */ ok */ assert_eq!(refresh_count(), 1);\n}\n'),
    (WORKFLOW, 'on:\n  schedule:\n    - cron: "42 6 * * *"\njobs:\n  guest:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: python tests/blackbox/installed_sections.py --lane systrap\n'),
    ("uv.lock", 'version = 99\n'),
    ("proxy/Cargo.lock", 'version = 99\n'),
    ("proxy/Cargo.toml", '[dependencies]\nhttp = "2"\n'),
    ("pyproject.toml", '[project]\ndependencies = ["pytest==99"]\n'),
    ("tests/blackbox/artifacts/selection.json", '{"digest":"fresh", "result":"passed"}'),
    ("docs/blackbox-coverage.md", 'Regenerated documentation\n'),
])
def test_mechanical_or_context_changes_stay_quiet(sources, path, content):
    report = compare(sources, {path: content})
    assert report["delta_id"] is None
    assert report["changes"][0]["status"] in {"mechanical", "context", "unclassified"}


def test_dependency_context_is_separate_from_test_selection(sources):
    files = sources | {"pyproject.toml": '[project]\ndependencies = ["pytest==1"]\n[tool.pytest.ini_options]\naddopts = "-ra"\n'}
    assert compare(files, {"pyproject.toml": files["pyproject.toml"].replace("pytest==1", "pytest==2")})["delta_id"] is None
    assert compare(files, {"pyproject.toml": files["pyproject.toml"].replace('"-ra"', '"--ignore=tests/blackbox"')})["delta_id"]


def test_action_revision_alone_and_unrelated_workflow_are_quiet(sources):
    source = sources[WORKFLOW] + '      - uses: actions/setup-python@old\n        with:\n          version: "3.12"\n'
    files = sources | {WORKFLOW: source}
    assert compare(files, {WORKFLOW: source.replace("@old", "@new").replace('"3.12"', '"3.13"')})["delta_id"] is None
    assert compare(sources, {".github/workflows/pages.yml": 'on: [push]\njobs:\n  docs:\n    steps:\n      - run: build-docs\n'})["delta_id"] is None
    assert compare(files, {WORKFLOW: source.replace("actions/setup-python", "other/action")})["delta_id"]


def test_shared_fixture_and_independent_observer_are_followed_without_execution(sources):
    helper = 'def received():\n    return 0\n'
    files = sources | {TEST: 'from tests.receiver import received\ndef test_denied():\n    assert received() == 0\n',
                       "tests/receiver.py": helper}
    report = compare(files, {"tests/receiver.py": helper.replace("0", "1")})
    assert report["delta_id"]
    assert report["changes"][0]["controls"] == ["BB-01"]
    assert compare(sources, {"tests/blackbox/isolation/conftest.py": helper})["delta_id"]
    files = sources | {TEST: ORIGINAL + '\nORACLE = "tests/blackbox/fixtures/oracle.json"\n',
                       "tests/blackbox/fixtures/oracle.json": '{"expected":false}'}
    assert compare(files, {"tests/blackbox/fixtures/oracle.json": '{"expected":true}'})["delta_id"]
    assert compare(sources, {"tests/blackbox/fixtures/unused.json": '{"description":"new input"}'})["delta_id"] is None
    assert compare(sources, {"tests/blackbox/unused.py": "def unused():\n    return False\n"})["delta_id"] is None


def test_sibling_script_import_and_embedded_guest_probe_are_followed(sources):
    files = sources | {TEST: 'from probe_helper import received\ndef test_denied():\n    assert received() == 0\n',
                       "tests/blackbox/isolation/probe_helper.py": "def received():\n    return 0\n"}
    assert compare(files, {"tests/blackbox/isolation/probe_helper.py": "def received():\n    return 1\n"})["delta_id"]
    files[TEST] += '\nPROBE = "scripts/guest_probe.sh"\n'
    files["scripts/guest_probe.sh"] = "test origin_count = 0\n"
    assert compare(files, {"scripts/guest_probe.sh": "test origin_count = 1\n"})["delta_id"]


def test_inline_rust_oracles_are_distinct_from_product_context(sources):
    path = "proxy/src/check.rs"
    files = sources | {path: 'fn product() {}\n#[cfg(test)] mod tests { #[test] fn denied() { assert!(true); } }'}
    files[changes.CATALOGUE] += f'[[witnesses]]\npaths = ["{path}"]\ncontrols = ["BB-10"]\nkind = "cargo"\n'
    assert compare(files, {path: files[path].replace("assert!(true)", "assert!(false)")})["delta_id"]
    assert compare(files, {path: files[path].replace("product() {}", "product() { work(); }")})["delta_id"] is None


def test_rust_literals_are_not_comments_or_whitespace():
    assert changes.rust_tokens('assert_eq!(x, r#"// /*  a b */"#);') != changes.rust_tokens('assert_eq!(x, r#"// /* a b */"#);')
    assert changes.rust_tokens('x == y') != changes.rust_tokens('x = = y')
    assert changes.rust_tokens('x -> y') != changes.rust_tokens('x - > y')
    assert changes.rust_tokens("b' ' != b'a'") != changes.rust_tokens("b'_' != b'a'")
    assert changes.rust_tokens("x&:y") != changes.rust_tokens("x& :y")
    assert changes.rust_tokens("'static") != changes.rust_tokens("' static")
    assert changes.rust_tokens('r#field') != changes.rust_tokens('r #field')
    assert changes.rust_tokens(r"'\x20'") != changes.rust_tokens(r"'\x2 0'")
    with pytest.raises(ValueError, match="unterminated"):
        changes.rust_tokens('r##"unterminated"#')


def test_shell_normalization_preserves_argument_boundaries_and_literals():
    expected = changes.shell_definition("test x = 1\n")
    assert changes.shell_definition("# explanation\n\n  test   x = 1 # comment\n\n") == expected
    assert changes.shell_definition("test x = \\\n 1\n") == expected
    assert changes.shell_definition("echo 'a'b\n") != changes.shell_definition("echo 'a' b\n")
    assert changes.shell_definition('echo "$word"\n') != changes.shell_definition("echo $word\n")
    assert changes.shell_definition("echo 'a\\\nb'\n") != changes.shell_definition("echo 'ab'\n")
    assert changes.shell_definition("echo '#word'\n") != changes.shell_definition("echo ''\n")
    with pytest.raises(ValueError, match="unterminated"):
        changes.shell_definition("echo 'unterminated\n")


def test_explicit_outside_catalogue_and_unrelated_workflow_helpers_stay_visible(sources):
    path = "tests/proxy_contracts/test_event_log_reader.py"
    files = sources | {path: "def test_display():\n    assert True\n"}
    files[changes.CATALOGUE] += f'[[out_of_scope]]\npaths = ["{path}"]\n'
    report = compare(files, {path: "def test_display():\n    assert False\n"})
    assert report["delta_id"] is None
    assert report["changes"][0]["status"] == "unclassified"
    files[".github/workflows/pages.yml"] = "on: [push]\njobs:\n  docs:\n    steps:\n      - run: python scripts/pages.py\n"
    files["scripts/pages.py"] = 'print("old documentation")\n'
    assert compare(files, {"scripts/pages.py": 'print("new documentation")\n'})["delta_id"] is None


def test_verified_same_directory_move_and_selection_update_stay_quiet(sources):
    moved = "tests/blackbox/isolation/test_moved.py"
    report = compare(sources, {TEST: None, moved: ORIGINAL,
                              changes.CATALOGUE: sources[changes.CATALOGUE].replace(TEST, moved)})
    assert report["delta_id"] is None
    # Failing to update a literal required selector is a real collection change.
    files = sources | {WORKFLOW: sources[WORKFLOW].replace("python tests/blackbox/installed_sections.py --lane systrap", f"pytest {TEST}")}
    assert compare(files, {TEST: None, moved: ORIGINAL})["delta_id"]


def test_unproved_move_and_self_filter_edit_are_material(sources):
    assert compare(sources, {TEST: None, "tests/other/test_probe.py": ORIGINAL})["delta_id"]
    source = sources[changes.WORKFLOW]
    assert compare(sources, {changes.WORKFLOW: source.replace("on: [push]", "on: [workflow_dispatch]")})["delta_id"]


def test_delta_identity_survives_rebase_routine_commits_and_later_change(sources):
    edits = {TEST: ORIGINAL.replace("== 0", "== 1")}
    first = compare(sources, edits)
    routine = compare(sources, edits | {"uv.lock": "new dependency"})
    rebased = compare(sources | {"other.py": "unrelated"}, edits)
    assert first["delta_id"] == routine["delta_id"] == rebased["delta_id"]
    assert compare(sources, {TEST: ORIGINAL.replace("== 0", "<= 2")})["delta_id"] != first["delta_id"]


def test_same_file_rebase_and_different_assertions_keep_correct_notice_identity(sources):
    extra = "\ndef test_other():\n    assert unrelated() == 10\n"
    files = sources | {TEST: ORIGINAL + extra}
    first = compare(files, {TEST: files[TEST].replace("origin_count() == 0", "origin_count() == 1")})
    rebased = files | {TEST: files[TEST].replace("unrelated() == 10", "unrelated() == 20")}
    assert compare(rebased, {TEST: rebased[TEST].replace("origin_count() == 0", "origin_count() == 1")})["delta_id"] == first["delta_id"]
    rust_extra = "\n#[test] fn other() { assert!(unrelated()); }"
    files = sources | {RUST: sources[RUST] + rust_extra}
    first = compare(files, {RUST: files[RUST].replace("refresh_count(), 1", "refresh_count(), 2")})
    rebased = files | {RUST: files[RUST].replace("unrelated()", "updated()")}
    assert compare(rebased, {RUST: rebased[RUST].replace("refresh_count(), 1", "refresh_count(), 2")})["delta_id"] == first["delta_id"]
    class_source = 'class TestDenial:\n    def test_a(self):\n        assert first() == 0\n    def test_b(self):\n        assert second() == 0\n'
    files = sources | {TEST: class_source}
    a = compare(files, {TEST: class_source.replace("first() == 0", "first() == 1")})
    b = compare(files, {TEST: class_source.replace("second() == 0", "second() == 1")})
    assert a["delta_id"] != b["delta_id"]
    assert a["changes"][0]["edits"][0]["unit"] == "TestDenial#0.test_a#0"


def test_definition_order_relative_to_executable_globals_is_material(sources):
    definition = "def test_case():\n    assert True\n"
    files = sources | {TEST: definition + "ALIAS = test_case\n"}
    assert compare(files, {TEST: "ALIAS = test_case\n" + definition})["delta_id"]
    class_source = "class TestCase:\n    def check(self):\n        return True\n    ALIAS = check\n"
    files = sources | {TEST: class_source}
    assert compare(files, {TEST: "class TestCase:\n    ALIAS = check\n    def check(self):\n        return True\n"})["delta_id"]


def event(kind="pull_request_target"):
    repository = {"full_name": notices.REPOSITORY, "default_branch": "master"}
    if kind == "push":
        return {"repository": repository, "ref": "refs/heads/master", "before": BASE, "after": HEAD}
    return {"repository": repository, "pull_request": {"number": 123, "draft": True, "user": {"login": "craigbalding"},
             "base": {"repo": repository, "ref": "master", "sha": BASE},
             "head": {"repo": {"full_name": "fork/repo"}, "sha": HEAD}}}


class GitHub:
    def __init__(self):
        self.comments = {}
        self.posts = []
        self.associated = []
        self.head = HEAD

    def api(self, endpoint, payload=None):
        path = endpoint.split("?", 1)[0]
        if payload is not None:
            comment = {"id": len(self.posts) + 1, "body": payload["body"],
                       "html_url": "https://github.com/notice", "user": {"login": notices.BOT, "type": "Bot"}}
            self.comments.setdefault(path, []).append(comment)
            self.posts.append((path, comment))
            return comment
        if path == "pulls/123":
            return {"head": {"sha": self.head}}
        if path.endswith("/pulls"):
            return self.associated
        return self.comments.get(path, [])


@pytest.fixture
def github(monkeypatch):
    fake = GitHub()
    monkeypatch.setattr(notices, "api", fake.api)
    return fake


def test_craig_authored_draft_fork_later_revision_retry_and_merge(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
    assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    later = compare(sources, {TEST: ORIGINAL.replace("== 0", "<= 2")})
    assert notices.publish(later, event(), "pull_request_target")["status"] == "published"
    assert len(github.posts) == 2  # NEW comments create NEW mentions.
    assert all(comment["body"].count("@craigbalding") == 1 for _, comment in github.posts)
    github.associated = [{"merged_at": "now", "number": 123, "base": {"repo": {"full_name": notices.REPOSITORY}}}]
    assert notices.publish(later, event("push"), "push")["status"] == "duplicate"
    assert len(github.posts) == 2


def test_direct_default_change_and_reverse_publication_order(sources, github):
    report = compare(sources, {RUST: sources[RUST].replace(", 1", ", 2")})
    result = notices.publish(report, event("push"), "push")
    assert result["status"] == "published"
    assert github.posts[0][0] == "issues/1557/comments"
    body = github.posts[0][1]["body"]
    assert "BB-10" in body and f"/compare/{BASE}..{HEAD}" in body and "Direct default-branch change" in body
    assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    assert notices.publish(report, event("push"), "push")["status"] == "duplicate"


def test_quiet_sequence_never_reads_or_writes_comments_then_material_notifies(sources, github):
    for number in range(10):
        report = compare(sources, {"uv.lock": str(number), "tests/blackbox/artifacts/selection.json": json.dumps({"run": number})})
        assert notices.publish(report, event(), "pull_request_target")["status"] == "quiet"
    assert not github.posts
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 9")})
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"


def test_forged_human_marker_cannot_suppress_a_notice(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    github.comments["issues/123/comments"] = [{"user": {"login": "craigbalding", "type": "User"},
                                               "body": f"<!-- safeyolo-bb-delta:{report['delta_id']} -->"}]
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"


def test_ambiguous_post_is_recovered_by_canonical_comment_before_retry(sources, github, monkeypatch):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    original = github.api

    def lost_reply(endpoint, payload=None):
        result = original(endpoint, payload)
        if payload is not None:
            raise subprocess.TimeoutExpired("gh", 120)
        return result

    monkeypatch.setattr(notices, "api", lost_reply)
    with pytest.raises(subprocess.TimeoutExpired):
        notices.publish(report, event(), "pull_request_target")
    monkeypatch.setattr(notices, "api", original)
    assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    assert len(github.posts) == 1


def test_stale_or_failed_untrusted_report_cannot_publish(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    for edit in ({"status": "failed"}, {"trusted_base": HEAD}, {"head": BASE}, {"delta_id": "not a digest"}):
        with pytest.raises(ValueError):
            notices.publish(report | edit, event(), "pull_request_target")
    github.head = "c" * 40
    assert notices.publish(report, event(), "pull_request_target")["status"] == "superseded"
    assert not github.posts
    with pytest.raises(ValueError, match="nightly"):
        notices.publish(report, event(), "schedule")


def test_workflow_does_not_execute_candidate_with_publication_token():
    workflow = yaml.load((ROOT / changes.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request_target", "push"}
    assert "opened" in workflow["on"]["pull_request_target"]["types"]
    analyzer, publisher = workflow["jobs"]["analyze"], workflow["jobs"]["publish"]
    assert workflow["permissions"] == {"contents": "read"}
    assert publisher["permissions"]["issues"] == "write"
    assert publisher["permissions"]["contents"] == "read"
    assert "needs.analyze.outputs.delta" in publisher["concurrency"]["group"]
    steps = json.dumps(analyzer["steps"])
    assert "candidate" not in " ".join(step.get("run", "") for step in analyzer["steps"])
    assert "persist-credentials" in steps and "--head" in steps
    assert "head.repo" not in steps and "head.ref" not in steps


def test_candidate_git_blobs_are_bounded_and_never_executed(tmp_path, sources):
    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    git("init", "-q")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Fixture")
    for name, content in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    marker = tmp_path / "must-not-exist"
    path = root / TEST
    path.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n" + ORIGINAL)
    git("add", ".")
    git("commit", "-qm", "untrusted head")
    head = git("rev-parse", "HEAD")
    git("checkout", "--detach", base)
    report, markdown = tmp_path / "report.json", tmp_path / "report.md"
    result = subprocess.run([sys.executable, "-I", str(ROOT / changes.SELF), "--repository", str(root),
                             "--base", base, "--head", head, "--json", str(report), "--markdown", str(markdown)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(report.read_text())["delta_id"]
    assert not marker.exists()
    path.unlink()
    path.symlink_to(marker)
    git("add", ".")
    git("commit", "-qm", "untrusted link")
    revision = changes.Revision(root, git("rev-parse", "HEAD"))
    with pytest.raises(ValueError, match="non-regular"):
        revision.read(TEST)
    failed = subprocess.run([sys.executable, "-I", str(ROOT / changes.SELF), "--repository", str(root),
                             "--base", base, "--head", revision.sha, "--json", str(report), "--markdown", str(markdown)],
                            capture_output=True, text=True)
    assert failed.returncode == 1
    assert json.loads(report.read_text())["status"] == "failed"
    assert "impact is unknown" in markdown.read_text()


def test_incomplete_history_is_explicit_and_cannot_repeat_mentions(sources, github, monkeypatch):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})

    def unavailable(_endpoint):
        raise ValueError("deduplication history unavailable")

    monkeypatch.setattr(notices, "pages", unavailable)
    for _ in range(2):
        with pytest.raises(ValueError, match="history unavailable"):
            notices.publish(report, event(), "pull_request_target")
    assert not github.posts


def test_yaml_alias_bomb_and_invalid_python_are_analysis_failures(sources):
    with pytest.raises((ValueError, yaml.YAMLError)):
        changes.bounded_yaml("value: &cycle [*cycle]")
    with pytest.raises(SyntaxError):
        compare(sources, {TEST: "def invalid syntax\n"})
    with pytest.raises(ValueError, match="catalogue"):
        compare(sources | {changes.CATALOGUE: sources[changes.CATALOGUE].replace('id = "BB-37"', 'id = "BB-38"')}, {})


def test_report_cannot_inject_another_mention(sources):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    report = copy.deepcopy(report)
    report["changes"][0]["path"] = "bad](@someone)/@craigbalding\n`x`.py"
    body = notices.notice_body(report, notices.event_context(event(), "pull_request_target"), report["changes"])
    assert body.count("@craigbalding") == 1
    assert "@someone" not in body
