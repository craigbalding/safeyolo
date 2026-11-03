"""Exercise the trusted caller with real offline child processes; no model calls."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from scripts import run_claude_blackbox as caller

SOURCE = "a" * 40


@pytest.fixture
def invocation(tmp_path, monkeypatch):
    controller = tmp_path / "controller with spaces"
    (controller / "scripts").mkdir(parents=True)
    (controller / "tests/blackbox").mkdir(parents=True)
    (controller / "tests/__init__.py").touch()
    (controller / "tests/blackbox/__init__.py").touch()
    (controller / ".venv").symlink_to(sys.prefix, target_is_directory=True)
    child = textwrap.dedent('''\
        import json, os, pathlib, sys
        args = sys.argv[1:]
        root = pathlib.Path.cwd()
        stage = 'selection' if '--platform' in args else 'smoke' if '--prepared-config' in args else 'readiness'
        mask = os.umask(0o077)
        os.umask(mask)
        with (root / 'events').open('a') as output:
            output.write(json.dumps({'stage':stage, 'args':args, 'python':sys.executable, 'umask':mask})+'\\n')
        print('PRIVATE diagnostic and token sentinel')
        print('PRIVATE stderr sentinel', file=sys.stderr)
        if stage == 'smoke':
            assert os.environ['SAFEYOLO_CLAUDE_SMOKE_CREDENTIAL'] == 'host-access-only'
        code = int(os.environ.get('FAIL_'+stage.upper(), '0'))
        directory = pathlib.Path(args[args.index('--output' if stage == 'selection' else '--artifacts')+1])
        directory.mkdir(parents=True)
        def save(name, value):
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        if stage == 'selection':
            save('selection.json', {'schema':'safeyolo.blackbox-inputs/v1',
                'status':'failed' if code else 'selected', 'default_branch':'master',
                'default_branch_head':'c'*40, 'host':{'source_revision':os.environ.get('SELECTED_SOURCE', 'a'*40)},
                'guest':{'index':{'digest':'sha256:'+'b'*64}}})
        elif stage == 'readiness':
            if os.environ.get('PACKAGE_FIXTURE_ROOT'):
                sys.path.insert(0, os.environ['PACKAGE_FIXTURE_ROOT'])
                from tests.blackbox.installed_workloads import prepare_package
                prepare_package(directory, 'caller-umask')
            save('retained-run.json', {'exit':code})
            save('installed-inputs.json', {'host_source_revision':'a'*40})
            save('guest/installed-sections.json', {'preparation':{'config_dir':str(root/'prepared')}})
        elif not os.environ.get('MISSING_SMOKE_REPORT'):
            save('guest/claude/claude-smoke.json', {'exit':code, 'status':'failed' if code else 'passed',
                'model_attempts':1, 'cleanup':'stopped'})
            save('guest/installed-sections.json', {'sections':[{'section':'claude','exit':code,'cleanup':'stopped'}]})
            if os.environ.get('INVALID_SMOKE_REPORT'):
                (directory / 'guest/claude/claude-smoke.json').write_text('invalid JSON')
        sys.exit(code)
    ''')
    child = ("def controller_identity():\n"
             "    return {'controller_revision':'d'*40, 'controller_dirty':False}\n"
             "if __name__ == '__main__':\n" + textwrap.indent(child, "    "))
    (controller / "scripts/select_blackbox_artifacts.py").write_text(child)
    (controller / "tests/blackbox/retained_inputs.py").write_text(child)
    provision = controller / "provision host binding"
    provision.write_text("#!/bin/sh\nset -eu\n"
                         'test "$1" = "$PWD/prepared"\ntest "$2" = host-access-only\n'
                         'mkdir -p "$1/private-state"\nprintf fixture > "$1/private-state/credential"\n'
                         "printf '%s\\n' '{\"stage\":\"binding\"}' >> events\n"
                         "echo 'PRIVATE provisioner diagnostic'\nexit \"${FAIL_BINDING:-0}\"\n")
    provision.chmod(0o700)
    monkeypatch.setattr(caller, "ROOT", controller)
    monkeypatch.setattr(caller, "controller_identity", lambda: {"controller_revision": "d" * 40, "controller_dirty": False})
    for name in ("SELECTION", "READINESS", "BINDING", "SMOKE"):
        monkeypatch.delenv("FAIL_" + name, raising=False)
    monkeypatch.delenv("MISSING_SMOKE_REPORT", raising=False)
    monkeypatch.delenv("INVALID_SMOKE_REPORT", raising=False)
    monkeypatch.delenv("SELECTED_SOURCE", raising=False)
    monkeypatch.delenv("PACKAGE_FIXTURE_ROOT", raising=False)
    args = argparse.Namespace(trigger="nightly", ref="refs/heads/master", source_revision=None,
                              host_run=None, guest_index=None, provision=provision,
                              credential="host-access-only", output=tmp_path / "new private attempt")
    return args, controller


def events(controller):
    path = controller / "events"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.parametrize("trigger", ["nightly", "manual", "merge"])
def test_trusted_caller_selects_then_checks_then_binds_then_runs_once(invocation, trigger):
    args, controller = invocation
    args.trigger = trigger
    if trigger == "merge":
        args.source_revision = SOURCE
    if trigger == "manual":
        args.host_run = 123
        args.guest_index = "sha256:" + "b" * 64
    report = caller.run(args)
    assert report["exit"] == 0 and report["stage"] == "complete"
    rows = events(controller)
    assert [row["stage"] for row in rows] == ["selection", "readiness", "binding", "smoke"]
    if trigger == "manual":
        assert rows[0]["args"][-4:] == ["--host-run", "123", "--guest-index", args.guest_index]
    else:
        assert "--host-run" not in rows[0]["args"] and "--guest-index" not in rows[0]["args"]
    assert "--prepared-config" in rows[3]["args"]
    assert rows[3]["args"][rows[3]["args"].index("--section")+1] == "claude"
    assert report["smoke"]["model_attempts"] == 1
    assert "PRIVATE" not in json.dumps(report)
    assert "PRIVATE" in (args.output / "private.log").read_text()
    assert "PRIVATE provisioner" not in (args.output / "private.log").read_text()
    assert json.loads((args.output / "result.json").read_bytes()) == report


@pytest.mark.parametrize(("stage", "code", "stages"), [
    ("SELECTION", 37, ["selection"]),
    ("READINESS", 29, ["selection", "readiness"]),
    ("BINDING", 23, ["selection", "readiness", "binding"]),
    ("SMOKE", 1, ["selection", "readiness", "binding", "smoke"]),
])
def test_failed_step_preserves_exit_and_never_admits_later_work(invocation, monkeypatch, stage, code, stages):
    args, controller = invocation
    monkeypatch.setenv("FAIL_" + stage, str(code))
    report = caller.run(args)
    assert report["exit"] == code
    assert [row["stage"] for row in events(controller)] == stages
    assert "PRIVATE" not in json.dumps(report)
    if stage == "SMOKE":
        assert report["smoke"]["status"] == "failed"
        assert report["cleanup"]["sections"][0]["cleanup"] == "stopped"


@pytest.mark.parametrize(("trigger", "ref", "revision", "selected_source", "selected"), [
    ("pull_request", "refs/heads/master", None, SOURCE, False),
    ("merge", "refs/heads/master", None, SOURCE, False),
    ("merge", "refs/heads/master", "not-a-sha", SOURCE, False),
    ("nightly", "refs/heads/feature", None, SOURCE, True),
    ("manual", "refs/pull/123/merge", None, SOURCE, True),
    ("merge", "refs/heads/master", SOURCE, "c" * 40, True),
])
def test_pr_ref_and_mismatched_merge_inputs_cannot_admit_credentials(invocation, monkeypatch,
                                                                  trigger, ref, revision, selected_source, selected):
    args, controller = invocation
    args.trigger, args.ref, args.source_revision = trigger, ref, revision
    monkeypatch.setenv("SELECTED_SOURCE", selected_source)
    report = caller.run(args)
    assert report["exit"] == 2
    assert [row["stage"] for row in events(controller)] == (["selection"] if selected else [])


def test_existing_attempt_is_preserved(invocation):
    args, controller = invocation
    args.output.mkdir()
    retained = args.output / "result.json"
    retained.write_text("previous failure")
    with pytest.raises(FileExistsError):
        caller.run(args)
    assert retained.read_text() == "previous failure"
    assert not events(controller)


def test_cli_does_not_accept_a_pr_trigger():
    result = subprocess.run([sys.executable, str(Path(caller.__file__)), "pull_request"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_report_loss_cannot_return_success(invocation, monkeypatch):
    args, _ = invocation
    monkeypatch.setenv("MISSING_SMOKE_REPORT", "1")
    report = caller.run(args)
    assert report["exit"] == 2


def test_invalid_report_preserves_actual_failure_and_other_observations(invocation, monkeypatch):
    args, _ = invocation
    monkeypatch.setenv("FAIL_SMOKE", "19")
    monkeypatch.setenv("INVALID_SMOKE_REPORT", "1")
    report = caller.run(args)
    assert report["exit"] == 19
    assert report["report_failures"] == {"smoke": "JSONDecodeError"}
    assert report["cleanup"]["sections"][0]["cleanup"] == "stopped"


def test_dirty_controller_cannot_start_selection_or_provisioning(invocation, monkeypatch):
    args, controller = invocation
    monkeypatch.setattr(caller, "controller_identity", lambda: {"controller_revision": None, "controller_dirty": True})
    report = caller.run(args)
    assert report["exit"] == 2 and report["stage"] == "admission"
    assert not events(controller)


@pytest.mark.parametrize("code", [0, 17])
@pytest.mark.parametrize("build_package", [False, True])
def test_deployment_entry_returns_decoded_exit_and_only_nonsecret_json(invocation, monkeypatch, code, build_package):
    args, controller = invocation
    if build_package and not shutil.which("dpkg-deb"):
        pytest.skip("the real readiness package fixture requires dpkg-deb")
    script = controller / "scripts/run_claude_blackbox.py"
    script.write_text(Path(caller.__file__).read_text())
    monkeypatch.setenv("FAIL_SMOKE", str(code))
    if build_package:
        monkeypatch.setenv("PACKAGE_FIXTURE_ROOT", str(Path(caller.__file__).resolve().parents[1]))
    result = subprocess.run([str(controller / ".venv/bin/python"), str(script), "nightly",
                             "--ref", args.ref, "--provision", str(args.provision),
                             "--credential", args.credential, "--output", str(args.output)],
                            capture_output=True, text=True, check=False, umask=0o022)
    assert result.returncode == code, result.stderr
    report = json.loads(result.stdout)
    assert report["exit"] == code
    assert report == json.loads((args.output / "result.json").read_bytes())
    assert "PRIVATE" not in result.stdout + result.stderr
    assert [row["umask"] for row in events(controller) if row["stage"] != "binding"] == [0o077, 0o022, 0o077]
    if build_package:
        assert (args.output / "readiness/package-source/DEBIAN").stat().st_mode & 0o777 == 0o755
        assert (args.output / "readiness/safeyolo-p2-fixture.deb").is_file()
    for path in (args.output, args.output / "inputs", args.output / "smoke",
                 controller / "prepared", controller / "prepared/private-state"):
        assert path.stat().st_mode & 0o777 == 0o700, path
    for path in (args.output / "private.log", args.output / "result.json",
                 controller / "prepared/private-state/credential"):
        assert path.stat().st_mode & 0o777 == 0o600, path
