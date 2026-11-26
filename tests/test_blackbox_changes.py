"""Materiality and publication controls for trusted blackbox change notices."""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import os
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
                         for number in range(1, 39))
    controls += f'[[witnesses]]\npaths = ["{TEST}"]\ncontrols = ["BB-01"]\nkind = "pytest"\n'
    controls += f'[[witnesses]]\npaths = ["{RUST}"]\ncontrols = ["BB-10"]\nkind = "cargo"\n'
    return {changes.CATALOGUE: controls, changes.MAP: '[[decisions]]\nid = "test"\ntests = []\n',
            TEST: ORIGINAL, RUST: '#[test]\nfn refresh() { assert_eq!(refresh_count(), 1); }\n',
            WORKFLOW: 'on:\n  schedule:\n    - cron: "17 3 * * *"\njobs:\n  guest:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python tests/blackbox/installed_sections.py --lane systrap\n',
            changes.SELF: 'def filter_changes(rows):\n    return rows\n',
            changes.PUBLISHER: 'def notify(rows):\n    return rows\n\nnotify([])\n',
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


@pytest.mark.parametrize(("original", "before", "after"), [
    ('def test_auth():\n    expected = 403\n    actual = request_as_guest()\n    assert actual == expected\n',
     'expected = 403', 'expected = 200'),
    ('def test_auth():\n    expected = 403\n    actual = request_as_guest()\n    assert actual == expected\n',
     'request_as_guest()', 'request_as_admin()'),
    ('def test_auth():\n    actual = request("guest")\n    assert actual == 403\n',
     '"guest"', '"admin"'),
    ('def test_auth():\n    tolerance = 0\n    observed = 1\n    assert observed <= tolerance\n',
     'tolerance = 0', 'tolerance = 1'),
    ('def test_auth():\n    options = {"role": "guest"}\n    actual = request(options)\n    assert actual == 403\n',
     '"guest"', '"admin"'),
    ('def test_auth():\n    options = {}\n    options["role"] = "guest"\n    assert request(options) == 403\n',
     '"guest"', '"admin"'),
    ('def test_auth():\n    run = lambda: request_as_guest()\n    assert run() == 403\n',
     'request_as_guest()', 'request_as_admin()'),
    ('def test_auth():\n    failure = PermissionError\n    with pytest.raises(failure):\n        request_as_guest()\n',
     'PermissionError', 'Exception'),
    ('def test_auth():\n    selected = "guest"\n    pytest.importorskip(selected)\n    assert request_as_guest() == 403\n',
     '"guest"', '"admin"'),
    ('def test_response():\n    protocol = "old framing"\n    assert response() == 1\n',
     'old framing', 'new framing'),
])
def test_unmapped_ci_test_setup_and_oracles_remain_material(tmp_path, git_sources, original, before, after):
    root, git = git_sources
    path = "tests/test_ci_regression.py"
    (root / path).write_text(original)
    workflow = root / WORKFLOW
    workflow.write_text(workflow.read_text() + f'      - run: pytest {path}\n')
    git("add", ".")
    git("commit", "-qm", "original ancillary regression")
    base = git("rev-parse", "HEAD")
    changed = original.replace(before, after)
    assert changes.regression_definition(original) != changes.regression_definition(changed)
    (root / path).write_text(changed)
    git("add", ".")
    git("commit", "-qm", "changed regression setup")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert report["delta_id"]
    assert report["changes"][0]["status"] == "material"


def test_unmapped_ci_test_selection_and_mapped_setup_remain_material(sources):
    path = "tests/test_ci_regression.py"
    original = 'def test_response():\n    protocol = "old framing"\n    assert response() == 1\n'
    files = sources | {path: original, WORKFLOW: sources[WORKFLOW] + f'      - run: pytest {path}\n'}
    assert compare(files, {path: original.replace("== 1", "== 2")})["delta_id"]
    assert compare(files, {path: original.replace("assert response() == 1", "pytest.skip('disabled')")})["delta_id"]
    assert compare(files, {path: original.replace("def test_response():", "@pytest.mark.parametrize('expected', [1, 2])\ndef test_response(expected):")})["delta_id"]
    # The same setup belongs to the full oracle when the trusted catalogue
    # identifies this test as BB evidence, including outside the BB tree.
    files[changes.CATALOGUE] += f'[[witnesses]]\npaths = ["{path}"]\ncontrols = ["BB-01"]\nkind = "pytest"\n'
    assert compare(files, {path: original.replace("old framing", "new framing")})["delta_id"]


def test_github_cli_fixture_framing_keeps_other_setup_and_oracles(sources, github):
    # Exercise the actual recurring CLI control's accepted diagnostic adaptation.
    framed = inspect.getsource(test_recurring_git_changes_through_both_clis)
    raw = framed.replace("next(arg for arg in sys.argv if arg.startswith('repos/'))", "sys.argv[2]").replace(
        "if '--include' in sys.argv:\n    print('HTTP/2.0 200 OK')\n    print('X-Github-Request-Id: fixture')\n    print()\n", "")
    assert raw != framed
    path = "tests/test_ci_regression.py"
    files = sources | {path: raw, WORKFLOW: sources[WORKFLOW] + f'      - run: pytest {path}\n'}
    report = compare(files, {path: framed})
    assert report["delta_id"] is None
    assert report["changes"][0]["status"] == "unclassified"
    assert notices.publish(report, event(), "pull_request_target")["status"] == "quiet"
    assert not github.posts
    for before, after in [
        ('state = tmp_path / "comments.json"', 'state = tmp_path / "other.json"'),
        ('enumerate((1, 0, 1)', 'enumerate((1, 1, 1)'),
        ('assert len(comments) == 3', 'assert len(comments) == 2'),
        ("arg.startswith('repos/')", "arg.startswith('issues/')"),
        ("if '--method' in sys.argv:", "if False:"),
        ("print('HTTP/2.0 200 OK')", "print('HTTP/2.0 403 Forbidden')"),
    ]:
        assert before in framed
        assert compare(files, {path: framed.replace(before, after)})["delta_id"]
    later = compare(files, {path: framed.replace('assert len(comments) == 3', 'assert len(comments) == 2')})
    assert notices.publish(later, event(), "pull_request_target")["status"] == "published"
    assert len(github.posts) == 1


def test_notification_transport_diagnostics_are_visible_without_a_mention(sources, github):
    publisher = (ROOT / changes.PUBLISHER).read_text()
    # Complete inspected adapter before the included-header diagnostic change.
    raw_api = '''def api(endpoint: str, payload: dict | None = None):
    command = ["gh", "api", f"repos/{REPOSITORY}/{endpoint}"]
    if payload is not None:
        command.extend(["--method", "POST", "--input", "-"])
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, check=True, timeout=120)
    if len(result.stdout) > 8 * MAX_REPORT:
        raise ValueError("GitHub response exceeds byte bound")
    return json.loads(result.stdout)
'''
    raw = publisher[:publisher.index("def api(")] + raw_api + "\n" + publisher[publisher.index("def pages("):]
    raw = raw.replace(inspect.getsource(notices.api_failure), "")
    files = sources | {changes.PUBLISHER: raw}
    report = compare(files, {changes.PUBLISHER: publisher})
    assert report["delta_id"] is None
    assert report["changes"][0]["status"] == "unclassified"
    assert {edit["unit"] for edit in report["changes"][0]["edits"]} == {"api#0", "api_failure#0"}
    assert notices.publish(report, event(), "pull_request_target")["status"] == "quiet"
    assert not github.posts
    # A later genuine assertion change in the same comparison still publishes.
    material = compare(files, {changes.PUBLISHER: publisher,
                               TEST: ORIGINAL.replace("== 0", "== 1")})
    assert notices.publish(material, event(), "pull_request_target")["status"] == "published"
    assert len(github.posts) == 1


@pytest.mark.parametrize(("before", "after"), [
    ('    command = ["gh", "api",',
     '    if payload is not None and "BB-01" in payload["body"]:\n        raise ValueError("BB-01 notice disabled")\n    command = ["gh", "api",'),
    ('    command = ["gh", "api",',
     '    if payload is not None:\n        return {}\n    command = ["gh", "api",'),
    ('f"repos/{REPOSITORY}/{endpoint}"', 'f"repos/{REPOSITORY}/issues/999/comments"'),
    ('    if result.returncode:', '    if not result.returncode:'),
    ('        response = json.loads(body)', '        raise ValueError("notice disabled by helper")'),
])
def test_notification_api_decisions_reach_analyzer_cli(tmp_path, git_sources, before, after):
    root, git = git_sources
    publisher = (ROOT / changes.PUBLISHER).read_text()
    path = root / changes.PUBLISHER
    path.write_text(publisher)
    git("add", ".")
    git("commit", "-qm", "original notification adapter")
    base = git("rev-parse", "HEAD")
    assert before in publisher
    path.write_text(publisher.replace(before, after))
    git("add", ".")
    git("commit", "-qm", "changed notification decision")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert report["delta_id"]
    assert [(row["path"], row["status"]) for row in report["changes"]] == [(changes.PUBLISHER, "material")]


@pytest.mark.parametrize("helper", [False, True])
def test_notification_filter_effect_and_detection(sources, monkeypatch, helper):
    publisher = (ROOT / changes.PUBLISHER).read_text()
    guard = '    if payload is not None and "BB-01" in payload["body"]:\n        raise ValueError("BB-01 notice disabled")\n'
    if helper:
        publisher = publisher.replace('    command = ["gh", "api",',
                                      '    if reject_notice(payload):\n        raise ValueError("BB-01 notice disabled")\n    command = ["gh", "api",')
        publisher += '\ndef reject_notice(payload):\n    return False\n'
        filtered = publisher.replace('def reject_notice(payload):\n    return False\n',
                                     'def reject_notice(payload):\n    return payload is not None and "BB-01" in payload["body"]\n')
    else:
        filtered = publisher.replace('    command = ["gh", "api",', guard + '    command = ["gh", "api",')
    files = sources | {changes.PUBLISHER: publisher}
    material = compare(files, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert material["delta_id"]
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    github = GitHub()

    def run(command, *, input, **kwargs):
        endpoint = next(arg for arg in command if arg.startswith("repos/")).removeprefix(f"repos/{notices.REPOSITORY}/")
        response = github.api(endpoint, json.loads(input) if input is not None else None)
        return subprocess.CompletedProcess(command, 0, "HTTP/2.0 200 OK\n\n" + json.dumps(response), "")

    # Run the actual publisher and adapter against an in-memory GitHub response.
    # The subprocess boundary cannot reach GitHub or a commenting credential.
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", run)
        for source, suppressed in ((publisher, False), (filtered, True)):
            github.comments.clear()
            github.posts.clear()
            namespace = {"__name__": "publisher_fixture"}
            exec(compile(source, changes.PUBLISHER, "exec"), namespace)
            if suppressed:
                with pytest.raises(ValueError, match="BB-01 notice disabled"):
                    namespace["publish"](material, event(), "pull_request_target")
                assert not github.posts
            else:
                assert namespace["publish"](material, event(), "pull_request_target")["status"] == "published"
                assert len(github.posts) == 1
                assert "@craigbalding" in github.posts[0][1]["body"]
    assert compare(files, {changes.PUBLISHER: filtered})["delta_id"]


@pytest.mark.parametrize(("before", "after"), [
    ('report.get("status") != "complete"', 'report.get("status") == "complete"'),
    ('if not material:', 'if material:'),
    ('if already_notified(context, delta, current):', 'if False:'),
    ('comment.get("user", {}).get("login") != BOT', 'comment.get("user", {}).get("login") == BOT'),
    ('@craigbalding {target}', 'quiet {target}'),
    ('os.environ.get("GITHUB_ACTIONS") != "true"', 'os.environ.get("GITHUB_ACTIONS") == "true"'),
    ('payload: dict | None = None', 'payload: dict | None = {}'),
    ('REPOSITORY = "craigbalding/safeyolo"', 'REPOSITORY = "other/repo"'),
    ('#!/usr/bin/env python3', '#!/bin/true'),
])
def test_notification_guards_and_transport_interface_stay_material(sources, before, after):
    publisher = (ROOT / changes.PUBLISHER).read_text()
    assert before in publisher
    files = sources | {changes.PUBLISHER: publisher}
    report = compare(files, {changes.PUBLISHER: publisher.replace(before, after)})
    assert report["delta_id"]
    assert report["changes"][0]["status"] == "material"


def test_notification_helpers_reached_by_guard_and_definition_side_effects_stay_material(sources):
    publisher = (ROOT / changes.PUBLISHER).read_text()
    files = sources | {changes.PUBLISHER: publisher + '\ndef new_filter():\n    return True\n'}
    assert compare(files, {changes.PUBLISHER: files[changes.PUBLISHER].replace('if not material:', 'if new_filter():')})["delta_id"]
    assert compare(files, {changes.PUBLISHER: files[changes.PUBLISHER].replace('def new_filter():', '@disable_notices\ndef new_filter():')})["delta_id"]
    assert compare(files, {changes.PUBLISHER: publisher.replace('def api(endpoint: str, payload: dict | None = None):',
                                                               'def api(endpoint: str, payload: dict | None = None):\n    assert payload is None')})["delta_id"]
    assert compare(files, {changes.PUBLISHER: publisher + '\ndef unknown_oracle():\n    assert False\n'})["delta_id"]
    adapter_helper = publisher.replace('    command = ["gh", "api",',
                                       '    if reject_notice(payload):\n        return {}\n    command = ["gh", "api",')
    adapter_helper += '\ndef reject_notice(payload):\n    return False\n'
    files = sources | {changes.PUBLISHER: adapter_helper}
    assert compare(files, {changes.PUBLISHER: adapter_helper.replace('def reject_notice(payload):\n    return False\n',
                                                                   'def reject_notice(payload):\n    return True\n')})["delta_id"]
    # The finite diagnostic exception includes definition order. Calling the
    # publisher before its error helper exists can change failure behavior.
    helper = inspect.getsource(notices.api_failure)
    reordered = publisher.replace(helper, "") + "\n" + helper
    assert compare(sources | {changes.PUBLISHER: publisher}, {changes.PUBLISHER: reordered})["delta_id"]


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


def test_external_rust_test_module_declarations_preserve_selection_and_later_oracles(sources):
    path = "proxy/src/check.rs"
    declaration = '#[cfg(test)]\n#[path = "check_tests.rs"]\nmod tests;\n'
    files = sources | {path: 'fn product() {}\n' + declaration}
    files[changes.CATALOGUE] += f'[[witnesses]]\npaths = ["{path}"]\ncontrols = ["BB-10"]\nkind = "cargo"\n'
    assert compare(files, {path: files[path].replace("product() {}", "product() { work(); }")})["delta_id"] is None
    for before, after in [("check_tests.rs", "other_tests.rs"), ("mod tests;", "mod replacement;"),
                          (declaration, "")]:
        assert compare(files, {path: files[path].replace(before, after)})["delta_id"]
    files[path] += '#[cfg(test)] mod inline_tests { #[test] fn denied() { assert!(true); } }'
    assert compare(files, {path: files[path].replace("assert!(true)", "assert!(false)")})["delta_id"]
    assert changes.rust_definition(declaration, inline=True) == changes.rust_tokens(declaration)


def test_rust_test_item_prefix_keeps_nested_semicolons_and_rejects_unbalanced_bodies():
    source = '#[cfg(test)] fn oracle(input: [u8; 3]) { assert_eq!(input, [0; 3]); }'
    assert changes.rust_definition(source, inline=True) == changes.rust_tokens(source)
    assert changes.rust_definition(source, inline=True) != changes.rust_definition(source.replace('[0; 3]', '[1; 3]'), inline=True)
    with pytest.raises(ValueError, match="unbalanced inline Rust test module"):
        changes.rust_definition('#[cfg(test)] mod tests { fn oracle() {}', inline=True)


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


@pytest.mark.parametrize("path", ["scripts/guest_probe.sh", "tests/blackbox/test_probe.py"])
def test_interpreter_changes_are_material(sources, path):
    body = "exit 1\n" if path.endswith(".sh") else "raise SystemExit(1)\n"
    interpreter = "#!/bin/sh\n" if path.endswith(".sh") else "#!/usr/bin/env python3\n"
    files = sources | {path: interpreter + body}
    if path.endswith(".sh"):
        files[TEST] += f'\nPROBE = "{path}"\n'
    report = compare(files, {path: "#!/bin/true\n" + body})
    assert report["delta_id"]
    assert report["changes"][0]["status"] == "material"
    assert compare(files, {path: interpreter + "# explanatory comment\n" + body})["delta_id"] is None


@pytest.mark.parametrize("path", ["proxy/tests/new_denial.rs", "proxy/tests/new_denial/main.rs"])
def test_new_automatic_rust_test_targets_are_material(sources, path):
    report = compare(sources, {path: '#[test]\nfn denied() { assert_eq!(origin_count(), 0); }\n'})
    assert report["delta_id"]
    assert report["changes"][0]["status"] == "material"
    # A new, unreferenced nested helper is not an automatic Cargo target.
    assert compare(sources, {"proxy/tests/helpers/unused.rs": "fn unused() {}\n"})["delta_id"] is None


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
        self.merged_at = None
        self.merge_commit = None

    def api(self, endpoint, payload=None):
        path = endpoint.split("?", 1)[0]
        if payload is not None:
            comment = {"id": len(self.posts) + 1, "body": payload["body"],
                       "html_url": "https://github.com/notice", "user": {"login": notices.BOT, "type": "Bot"}}
            self.comments.setdefault(path, []).append(comment)
            self.posts.append((path, comment))
            return comment
        if path == "pulls/123":
            return {"head": {"sha": self.head}, "merged_at": self.merged_at,
                    "merge_commit_sha": self.merge_commit}
        if path.endswith("/pulls"):
            return self.associated
        return self.comments.get(path, [])


@pytest.fixture
def github(monkeypatch):
    fake = GitHub()
    monkeypatch.setattr(notices, "api", fake.api)
    monkeypatch.setenv("GITHUB_RUN_ID", "100")
    return fake


def test_craig_authored_draft_fork_later_revision_retry_and_merge(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
    assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    later = compare(sources, {TEST: ORIGINAL.replace("== 0", "<= 2")})
    assert notices.publish(later, event(), "pull_request_target")["status"] == "published"
    assert len(github.posts) == 2  # NEW comments create NEW mentions.
    assert {endpoint for endpoint, _ in github.posts} == {"issues/123/comments"}
    assert all(comment["body"].count("@craigbalding") == 1 for _, comment in github.posts)
    github.associated = [{"merged_at": "now", "number": 123, "base": {"repo": {"full_name": notices.REPOSITORY}}}]
    assert notices.publish(later, event("push"), "push")["status"] == "duplicate"
    assert len(github.posts) == 2


def test_routine_revision_and_rebase_keep_the_latest_pr_notice(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
    updated = event()
    updated["pull_request"]["head"]["sha"] = github.head = "c" * 40
    updated["pull_request"]["base"]["sha"] = "d" * 40
    report = report | {"base": "d" * 40, "trusted_base": "d" * 40, "head": github.head}
    assert notices.publish(report, updated, "pull_request_target")["status"] == "duplicate"
    assert len(github.posts) == 1


def test_direct_default_change_and_reverse_publication_order(sources, github):
    report = compare(sources, {RUST: sources[RUST].replace(", 1", ", 2")})
    result = notices.publish(report, event("push"), "push")
    assert result["status"] == "published"
    assert github.posts[0][0] == "issues/1557/comments"
    body = github.posts[0][1]["body"]
    assert "BB-10" in body and f"/compare/{BASE}..{HEAD}" in body and "Direct default-branch change" in body
    github.merged_at, github.merge_commit = "now", HEAD
    assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    assert notices.publish(report, event("push"), "push")["status"] == "duplicate"


def test_recurring_direct_changes_notify_but_each_event_retry_stays_quiet(sources, github, monkeypatch):
    files = sources
    for number, expected in enumerate((1, 0, 1), start=1):
        base, head = f"{number:040x}", f"{number + 1:040x}"
        updated = files | {TEST: ORIGINAL.replace("== 0", f"== {expected}")}
        report = changes.compare(Source(files, base), Source(updated, head))
        push = event("push") | {"before": base, "after": head}
        monkeypatch.setenv("GITHUB_RUN_ID", str(number))
        assert notices.publish(report, push, "push")["status"] == "published"
        assert notices.publish(report, push, "push")["status"] == "duplicate"
        files = updated
    assert len(github.posts) == 3


def test_pr_returning_to_an_earlier_notified_delta_receives_a_fresh_notice(sources, github):
    for expected in (1, 2, 1):
        report = compare(sources, {TEST: ORIGINAL.replace("== 0", f"== {expected}")})
        assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
        assert notices.publish(report, event(), "pull_request_target")["status"] == "duplicate"
    assert len(github.posts) == 3


def test_unrelated_pr_and_direct_change_do_not_suppress_each_other(sources, github, monkeypatch):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert notices.publish(report, event("push"), "push")["status"] == "published"
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
    monkeypatch.setenv("GITHUB_RUN_ID", "101")
    assert notices.publish(report, event("push"), "push")["status"] == "published"
    assert len(github.posts) == 3


def test_merge_matches_only_the_latest_pr_delta(sources, github, monkeypatch):
    earlier = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    latest = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 2")})
    assert notices.publish(earlier, event(), "pull_request_target")["status"] == "published"
    assert notices.publish(latest, event(), "pull_request_target")["status"] == "published"
    github.associated = [{"merged_at": "now", "number": 123, "base": {"repo": {"full_name": notices.REPOSITORY}}}]
    merged = "c" * 40
    push = event("push") | {"after": merged}
    assert notices.publish(latest | {"head": merged}, push, "push")["status"] == "duplicate"
    monkeypatch.setenv("GITHUB_RUN_ID", "101")
    assert notices.publish(earlier | {"head": merged}, push, "push")["status"] == "published"


def test_quiet_sequence_never_reads_or_writes_comments_then_material_notifies(sources, github):
    for number in range(10):
        report = compare(sources, {"uv.lock": str(number), "tests/blackbox/artifacts/selection.json": json.dumps({"run": number})})
        assert notices.publish(report, event(), "pull_request_target")["status"] == "quiet"
    assert not github.posts
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 9")})
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"


def test_forged_human_marker_cannot_suppress_a_notice(sources, github):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    context = notices.event_context(event(), "pull_request_target") | {"run_id": "100"}
    github.comments["issues/123/comments"] = [{"user": {"login": "craigbalding", "type": "User"},
                                               "body": notices.notice_body(report, context, report["changes"])}]
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


def test_all_current_controls_reach_publisher(sources, github):
    files = sources | {changes.MAP: f'[[decisions]]\nid = "test"\ntests = ["{TEST}"]\n'}
    report = compare(files, {TEST: ORIGINAL.replace("== 0", "== 1")})
    assert report["changes"][0]["controls"] == [f"BB-{number:02}" for number in range(1, 39)]
    assert notices.publish(report, event(), "pull_request_target")["status"] == "published"
    assert "BB-38" in github.posts[0][1]["body"]


@pytest.mark.parametrize("controls", [None, "BB-38", ["BB-00"], ["BB-39"], ["BB-038"], [38], ["BB-01"] * 39])
def test_invalid_report_controls_cannot_publish(sources, github, controls):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    report["changes"][0]["controls"] = controls
    with pytest.raises(ValueError, match="invalid change record"):
        notices.publish(report, event(), "pull_request_target")
    assert not github.posts


def test_workflow_does_not_execute_candidate_with_publication_token():
    workflow = yaml.load((ROOT / changes.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request_target", "push"}
    assert "opened" in workflow["on"]["pull_request_target"]["types"]
    analyzer, publisher = workflow["jobs"]["analyze"], workflow["jobs"]["publish"]
    assert workflow["permissions"] == {"contents": "read"}
    assert analyzer.get("permissions", workflow["permissions"]) == {"contents": "read"}
    assert publisher["permissions"] == {"contents": "read", "actions": "read",
                                        "issues": "write", "pull-requests": "write"}
    assert "needs.analyze.outputs.delta" in publisher["concurrency"]["group"]
    steps = json.dumps(analyzer["steps"])
    assert "candidate" not in " ".join(step.get("run", "") for step in analyzer["steps"])
    assert "persist-credentials" in steps and "--head" in steps
    assert "head.repo" not in steps and "head.ref" not in steps


@pytest.fixture
def git_sources(tmp_path, sources):
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
    return root, git


def analyze_cli(root, base, head, output):
    report, markdown = output / "report.json", output / "report.md"
    result = subprocess.run([sys.executable, "-I", str(ROOT / changes.SELF), "--repository", str(root),
                             "--base", base, "--head", head, "--json", str(report), "--markdown", str(markdown)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(report.read_text())


def test_current_catalogue_and_bb38_witness_reach_publisher(tmp_path, git_sources, github):
    root, git = git_sources
    witness = "proxy/tests/host_execution.rs"
    for name in (changes.CATALOGUE, changes.MAP, witness):
        (root / name).write_bytes((ROOT / name).read_bytes())
    git("add", ".")
    git("commit", "-qm", "current catalogue and BB-38 witness")
    base = git("rev-parse", "HEAD")
    unchanged = analyze_cli(root, base, base, tmp_path)
    assert unchanged["status"] == "complete"
    assert unchanged["changes"] == []
    assert unchanged["delta_id"] is None

    (root / "README.md").write_text("Documentation-only change.\n")
    git("add", ".")
    git("commit", "-qm", "documentation only")
    quiet = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert quiet["status"] == "complete"
    assert quiet["delta_id"] is None
    assert not any(row["status"] == "material" for row in quiet["changes"])
    push = event("push") | {"before": base, "after": quiet["head"]}
    assert notices.publish(quiet, push, "push")["status"] == "quiet"
    assert not github.posts

    path = root / witness
    original = path.read_text()
    assert original.count("assert!(first.dispatch);") == 1
    path.write_text(original.replace("assert!(first.dispatch);", "assert!(!first.dispatch);"))
    git("add", ".")
    git("commit", "-qm", "BB-38 oracle change")
    material = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert material["status"] == "complete"
    assert material["delta_id"]
    assert [(row["path"], row["controls"]) for row in material["changes"] if row["status"] == "material"] == [
        (witness, ["BB-38"])]
    push = event("push") | {"before": base, "after": material["head"]}
    assert notices.publish(material, push, "push")["status"] == "published"
    assert notices.publish(material, push, "push")["status"] == "duplicate"
    assert len(github.posts) == 1
    assert "BB-38" in github.posts[0][1]["body"]


def test_trusted_workflow_bootstrap_runs_selected_interpreters(tmp_path, git_sources):
    root, git = git_sources
    workflow = yaml.load((ROOT / changes.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    analyze, publish = (workflow["jobs"][job]["steps"] for job in ("analyze", "publish"))
    install = next(step["run"] for step in analyze if step.get("run", "").startswith("uv sync "))
    compare_step = next(step["run"] for step in analyze if step.get("name") == "Compare executable assurance definitions")
    publish_step = next(step["run"] for step in publish if step.get("name") == "Publish a new notice only for a material delta")
    summary_step = next(step["run"] for step in analyze if step.get("name") == "Report analysis and publication state")
    for path in ("tools/acceptance/pyproject.toml", "tools/acceptance/uv.lock"):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / path).read_bytes())
    git("rm", changes.SELF, changes.PUBLISHER)
    git("add", ".")
    git("commit", "-qm", "trusted base predating notification tools")
    old_base = git("rev-parse", "HEAD")
    for path in (changes.SELF, changes.PUBLISHER):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / path).read_bytes())
    git("add", ".")
    git("commit", "-qm", "trusted notification tools and parser lock")
    base = git("rev-parse", "HEAD")
    (root / TEST).write_text(ORIGINAL.replace("== 0", "== 1"))
    git("add", ".")
    git("commit", "-qm", "candidate assertion change")
    head = git("rev-parse", "HEAD")
    workspace = tmp_path / "runner"
    workspace.mkdir()
    trusted = workspace / "trusted"
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(root), str(trusted)], check=True)
    subprocess.run(["git", "-C", str(trusted), "checkout", "-q", "--detach", base], check=True)
    output = tmp_path / "reports"
    output.mkdir()
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"repository": {"full_name": notices.REPOSITORY, "default_branch": "master"},
                                     "ref": "refs/heads/master", "before": base, "after": base}))
    env = {key: value for key, value in os.environ.items()
           if key not in {"UV_PROJECT_ENVIRONMENT", "VIRTUAL_ENV", "GH_TOKEN", "GITHUB_TOKEN"}}
    env["PATH"] = str(Path(sys.base_prefix) / "bin") + os.pathsep + env["PATH"]
    env.update(RUNNER_TEMP=str(output), NOTICE_BASE=base, NOTICE_HEAD=base,
               GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="push", GITHUB_EVENT_PATH=str(event_path),
               GITHUB_STEP_SUMMARY=str(tmp_path / "summary.md"))

    def run(script):
        return subprocess.run(["bash", "-e", "-c", script], cwd=workspace, env=env,
                              capture_output=True, text=True, timeout=180)

    # Use the workflow's frozen group in a fresh trusted checkout, rather than
    # the development Python that imports this test and already has PyYAML.
    result = run(install)
    assert result.returncode == 0, result.stderr
    result = run(compare_step)
    assert result.returncode == 0, result.stderr
    report = output / "blackbox-changes.json"
    assert json.loads(report.read_text())["delta_id"] is None
    (output / "analysis").mkdir()
    (output / "analysis/blackbox-changes.json").write_bytes(report.read_bytes())
    # The publisher's actual system-Python command uses only the standard
    # library. A quiet report returns before any GitHub API operation.
    result = run("python3 -I -c 'import sys; assert sys.prefix == sys.base_prefix'")
    assert result.returncode == 0, result.stderr
    result = run(publish_step)
    assert result.returncode == 0, result.stderr
    assert json.loads((output / "blackbox-notice.json").read_text())["status"] == "quiet"
    env["NOTICE_HEAD"] = head
    result = run(compare_step)
    assert result.returncode == 0, result.stderr
    assert json.loads(report.read_text())["delta_id"]
    assert subprocess.check_output(["git", "-C", str(trusted), "rev-parse", "HEAD"], text=True).strip() == base

    # An old trusted source cannot bootstrap itself from candidate code. Its
    # actual failing command and always-run summary must retain unknown impact.
    subprocess.run(["git", "-C", str(trusted), "checkout", "-q", old_base], check=True)
    report.unlink()
    (output / "blackbox-changes.md").unlink()
    env["NOTICE_BASE"] = old_base
    result = run(compare_step)
    assert result.returncode != 0 and "blackbox_changes.py" in result.stderr
    assert not report.exists()
    assert run(summary_step).returncode == 0
    assert "Assurance impact is unknown" in Path(env["GITHUB_STEP_SUMMARY"]).read_text()


@pytest.mark.parametrize(("setting", "target", "source"), [
    ("autolib", "fixture", "src/lib.rs"),
    ("autobins", "credential_check", "src/bin/credential_check.rs"),
    ("autoexamples", "credential_check", "examples/credential_check.rs"),
    ("autotests", "credential_check", "tests/credential_check.rs"),
    ("autobenches", "credential_check", "benches/credential_check.rs"),
])
def test_cargo_automatic_target_selection_reaches_analyzer_cli(tmp_path, git_sources, setting, target, source):
    root, git = git_sources
    manifest = root / "proxy/Cargo.toml"
    original = '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2024"\n'
    # Keep one explicit target so disabling automatic library discovery remains
    # a valid package, while the selected implicit target actually disappears.
    original += '\n[[test]]\nname = "explicit"\npath = "explicit.rs"\n'
    manifest.write_text(original)
    (manifest.parent / "explicit.rs").write_text("#[test]\nfn explicit() { assert!(true); }\n")
    witness = manifest.parent / source
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text("fn main() {}\n#[test]\nfn denied() { assert!(true); }\n")
    catalogue = root / changes.CATALOGUE
    catalogue.write_text(catalogue.read_text() + f'[[witnesses]]\npaths = ["proxy/{source}"]\ncontrols = ["BB-01"]\nkind = "cargo"\n')

    def targets():
        metadata = subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1",
                                            "--manifest-path", str(manifest)], text=True)
        return {row["name"] for row in json.loads(metadata)["packages"][0]["targets"]}

    git("add", ".")
    git("commit", "-qm", "automatic Cargo target")
    base = git("rev-parse", "HEAD")
    before = targets()
    assert target in before
    manifest.write_text(original.replace('[package]\n', f'[package]\n{setting} = false\n'))
    assert targets() == before - {target}
    git("add", ".")
    git("commit", "-qm", "disable automatic Cargo target")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert report["delta_id"]
    assert [(row["path"], row["status"]) for row in report["changes"]] == [("proxy/Cargo.toml", "material")]


@pytest.mark.parametrize(("kind", "source"), [
    ("bin", "src/bin/inherited.rs"),
    ("example", "examples/inherited.rs"),
    ("test", "tests/inherited.rs"),
    ("bench", "benches/inherited.rs"),
])
@pytest.mark.parametrize("changed_manifest", ["workspace", "member", "workspace-pointer"])
def test_cargo_inherited_edition_selection_reaches_analyzer_cli(tmp_path, git_sources, kind, source, changed_manifest):
    root, git = git_sources
    workspace = root / "Cargo.toml"
    workspace.write_text('[workspace]\nmembers = ["proxy"]\nresolver = "2"\n[workspace.package]\nedition = "2024"\n')
    member = root / "proxy/Cargo.toml"
    member.write_text('[package]\nname = "fixture"\nversion = "0.1.0"\nedition.workspace = true\n'
                      f'\n[[{kind}]]\nname = "explicit"\npath = "explicit.rs"\n')
    if changed_manifest != "workspace":
        workspace.write_text(workspace.read_text().replace('"2024"', '"2015"'))
        if changed_manifest == "member":
            member.write_text(member.read_text().replace('edition.workspace = true', 'edition = "2024"'))
        else:
            modern = root / "modern"
            modern.mkdir()
            (modern / "Cargo.toml").write_text(workspace.read_text().replace('["proxy"]', '["../proxy"]').replace('"2015"', '"2024"'))
            member.write_text(member.read_text().replace('[package]\n', '[package]\nworkspace = "../modern"\n'))
    (member.parent / "explicit.rs").write_text("fn main() {}\n#[test]\nfn explicit() { assert!(true); }\n")
    (member.parent / "src").mkdir(exist_ok=True)
    (member.parent / "src/lib.rs").write_text("#[test]\nfn library() { assert!(true); }\n")
    witness = member.parent / source
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text("fn main() {}\n#[test]\nfn inherited() { assert!(true); }\n")
    catalogue = root / changes.CATALOGUE
    catalogue.write_text(catalogue.read_text() + '[[witnesses]]\npaths = ["proxy/Cargo.toml"]\ncontrols = ["BB-01"]\nkind = "cargo"\n')

    def targets():
        metadata = subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1",
                                            "--manifest-path", str(member)], text=True)
        return {row["name"] for row in json.loads(metadata)["packages"][0]["targets"]}

    git("add", ".")
    git("commit", "-qm", "inherited target discovery")
    base = git("rev-parse", "HEAD")
    before = targets()
    assert "inherited" in before and "explicit" in before
    manifest = workspace if changed_manifest == "workspace" else member
    if changed_manifest == "workspace":
        manifest.write_text(manifest.read_text().replace('"2024"', '"2015"'))
    elif changed_manifest == "member":
        manifest.write_text(manifest.read_text().replace('edition = "2024"', 'edition.workspace = true'))
    else:
        manifest.write_text(manifest.read_text().replace('workspace = "../modern"', 'workspace = ".."'))
    assert targets() == before - {"inherited"}
    git("add", ".")
    git("commit", "-qm", "change inherited discovery edition")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert report["delta_id"]
    assert [(row["path"], row["status"]) for row in report["changes"]] == [(str(manifest.relative_to(root)), "material")]


@pytest.mark.parametrize(("before", "after", "selection"), [
    ('members = ["proxy", "witness"]', 'members = ["proxy"]', "workspace_members"),
    ('members = ["p*", "w*"]', 'members = ["p*", "w*"]\nexclude = ["witness"]', "workspace_members"),
    ('members = ["proxy", "witness"]', 'members = ["proxy", "witness"]\ndefault-members = ["proxy"]', "workspace_default_members"),
])
def test_cargo_workspace_selection_reaches_analyzer_cli(tmp_path, git_sources, before, after, selection):
    root, git = git_sources
    workspace = root / "Cargo.toml"
    workspace.write_text(f'[workspace]\nresolver = "2"\n{before}\n')
    for name in ("proxy", "witness"):
        package = root / name
        package.mkdir(exist_ok=True)
        (package / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n')
        (package / "src").mkdir()
        (package / "src/lib.rs").write_text("#[test]\nfn denied() { assert!(true); }\n")

    def selected():
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1",
                                                       "--manifest-path", str(workspace)], text=True))
        return {row["name"] for row in metadata["packages"] if row["id"] in metadata[selection]}

    git("add", ".")
    git("commit", "-qm", "workspace witnesses")
    base = git("rev-parse", "HEAD")
    assert selected() == {"proxy", "witness"}
    workspace.write_text(workspace.read_text().replace(before, after))
    assert selected() == {"proxy"}
    git("add", ".")
    git("commit", "-qm", "deselect workspace witness")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert report["delta_id"]
    assert [(row["path"], row["status"]) for row in report["changes"]] == [("Cargo.toml", "material")]


def test_cargo_workspace_dependency_and_metadata_changes_stay_quiet(sources):
    manifest = ('[workspace]\nmembers = ["proxy", "witness"]\nresolver = "2"\n'
                '[workspace.package]\nedition = "2024"\nversion = "0.1.0"\n'
                '[workspace.dependencies]\nhttp = "1"\n')
    files = sources | {"Cargo.toml": manifest}
    edited = manifest.replace('http = "1"', 'http = "2"').replace('version = "0.1.0"', 'version = "0.2.0"')
    assert compare(files, {"Cargo.toml": edited})["delta_id"] is None
    assert compare(files, {"Cargo.toml": manifest.replace('["proxy", "witness"]', '["witness", "proxy"]')})["delta_id"] is None


@pytest.mark.parametrize("edition", ["2015", "2024"])
def test_cargo_dependency_and_explicit_discovery_defaults_stay_quiet(sources, edition):
    manifest = f'[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "{edition}"\n'
    manifest += '\n[[test]]\nname = "explicit"\npath = "explicit.rs"\n\n[dependencies]\nhttp = "1"\n'
    files = sources | {"proxy/Cargo.toml": manifest}
    assert compare(files, {"proxy/Cargo.toml": manifest.replace('http = "1"', 'http = "2"')})["delta_id"] is None
    default = "false" if edition == "2015" else "true"
    explicit_default = manifest.replace('[package]\n', f'[package]\nautotests = {default}\n')
    assert compare(files, {"proxy/Cargo.toml": explicit_default})["delta_id"] is None
    changed = explicit_default.replace(f'autotests = {default}', f'autotests = {"true" if default == "false" else "false"}')
    assert compare(files, {"proxy/Cargo.toml": changed})["delta_id"]


@pytest.mark.parametrize("table", ["[lib]", "[[bin]]", "[[example]]", "[[test]]", "[[bench]]"])
def test_cargo_explicit_target_selection_is_material(sources, table):
    manifest = '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2024"\n'
    manifest += f'\n{table}\nname = "denial"\npath = "denial.rs"\ntest = true\n'
    files = sources | {"proxy/Cargo.toml": manifest}
    report = compare(files, {"proxy/Cargo.toml": manifest.replace("test = true", "test = false")})
    assert report["delta_id"]
    assert report["changes"][0]["status"] == "material"


def test_interpreter_and_new_cargo_target_reach_analyzer_cli(tmp_path, git_sources):
    root, git = git_sources
    script = root / "tests/blackbox/guest_probe.sh"
    script.write_text("#!/bin/sh\nexit 1\n")
    script.chmod(0o755)
    manifest = root / "proxy/Cargo.toml"
    manifest.write_text('[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n')
    (root / "proxy/src").mkdir()
    (root / "proxy/src/lib.rs").write_text("")
    git("add", ".")
    git("commit", "-qm", "executable fixture")
    base = git("rev-parse", "HEAD")
    assert subprocess.run([str(script)], check=False).returncode == 1
    script.write_text("#!/bin/true\nexit 1\n")
    assert subprocess.run([str(script)], check=False).returncode == 0
    (root / "proxy/tests/new_denial.rs").write_text("#[test]\nfn denied() { assert!(true); }\n")
    metadata = subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1",
                                        "--manifest-path", str(manifest)], text=True)
    assert any(target["name"] == "new_denial" and "test" in target["kind"]
               for target in json.loads(metadata)["packages"][0]["targets"])
    git("add", ".")
    git("commit", "-qm", "changed interpreter and new test")
    report = analyze_cli(root, base, git("rev-parse", "HEAD"), tmp_path)
    assert {row["path"] for row in report["changes"] if row["status"] == "material"} == {
        "tests/blackbox/guest_probe.sh", "proxy/tests/new_denial.rs"}


def test_recurring_git_changes_through_both_clis(tmp_path, git_sources):
    root, git = git_sources
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    state = tmp_path / "comments.json"
    fake_gh.write_text(f"#!{sys.executable}\n" + '''import json, pathlib, sys
state = pathlib.Path(''' + repr(str(state)) + ''')
rows = json.loads(state.read_text()) if state.exists() else []
endpoint = next(arg for arg in sys.argv if arg.startswith('repos/')).split('?', 1)[0]
if '--include' in sys.argv:
    print('HTTP/2.0 200 OK')
    print('X-Github-Request-Id: fixture')
    print()
if '--method' in sys.argv:
    body = json.load(sys.stdin)['body']
    comment = {'id': len(rows) + 1, 'body': body, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
               'html_url': 'https://github.com/fixture/comment'}
    rows.append(comment)
    state.write_text(json.dumps(rows))
    print(json.dumps(comment))
else:
    print(json.dumps(rows if endpoint.endswith('/comments') else []))
''')
    fake_gh.chmod(0o755)
    event_path, result_path = tmp_path / "event.json", tmp_path / "result.json"
    publisher_env = os.environ | {"PATH": str(fake_bin) + ":" + str(Path(sys.executable).parent),
                                 "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
                                 "GITHUB_EVENT_PATH": str(event_path)}
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        publisher_env.pop(name, None)
    for number, expected in enumerate((1, 0, 1), start=1):
        base = git("rev-parse", "HEAD")
        (root / TEST).write_text(ORIGINAL.replace("== 0", f"== {expected}"))
        git("add", ".")
        git("commit", "-qm", f"oracle {expected}")
        head = git("rev-parse", "HEAD")
        report = analyze_cli(root, base, head, tmp_path)
        assert report["delta_id"]
        event_path.write_text(json.dumps(event("push") | {"before": base, "after": head}))
        publisher_env["GITHUB_RUN_ID"] = str(number)
        for expected_status in ("published", "duplicate"):
            result = subprocess.run([sys.executable, "-I", str(ROOT / changes.PUBLISHER),
                                     "--report", str(tmp_path / "report.json"), "--result", str(result_path)],
                                    env=publisher_env, capture_output=True, text=True)
            assert result.returncode == 0, result.stderr + result.stdout
            assert json.loads(result_path.read_text())["status"] == expected_status
    comments = json.loads(state.read_text())
    assert len(comments) == 3
    assert all(comment["body"].count("@craigbalding") == 1 for comment in comments)


def test_candidate_git_blobs_are_bounded_and_never_executed(tmp_path, git_sources):
    root, git = git_sources
    base = git("rev-parse", "HEAD")
    marker = tmp_path / "must-not-exist"
    path = root / TEST
    path.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n" + ORIGINAL)
    git("add", ".")
    git("commit", "-qm", "untrusted head")
    head = git("rev-parse", "HEAD")
    git("checkout", "--detach", base)
    assert analyze_cli(root, base, head, tmp_path)["delta_id"]
    assert not marker.exists()
    path.unlink()
    path.symlink_to(marker)
    git("add", ".")
    git("commit", "-qm", "untrusted link")
    revision = changes.Revision(root, git("rev-parse", "HEAD"))
    with pytest.raises(ValueError, match="non-regular"):
        revision.read(TEST)
    report, markdown = tmp_path / "report.json", tmp_path / "report.md"
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
        compare(sources | {changes.CATALOGUE: sources[changes.CATALOGUE].replace('id = "BB-38"', 'id = "BB-39"')}, {})


def test_report_cannot_inject_another_mention(sources):
    report = compare(sources, {TEST: ORIGINAL.replace("== 0", "== 1")})
    report = copy.deepcopy(report)
    report["changes"][0]["path"] = "bad](@someone)/@craigbalding\n`x`.py"
    context = notices.event_context(event(), "pull_request_target") | {"run_id": "100"}
    body = notices.notice_body(report, context, report["changes"])
    assert body.count("@craigbalding") == 1
    assert "@someone" not in body
