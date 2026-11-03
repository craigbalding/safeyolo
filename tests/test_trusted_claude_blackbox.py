"""Exercise the trusted caller with real offline child processes; no model calls."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from scripts import run_claude_blackbox as caller
from scripts.select_blackbox_artifacts import installed_binaries
from tests.blackbox import retained_inputs

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
            prepared = root/'prepared'
            if os.environ.get('ADMISSION_HOME'):
                (prepared/'agents/owner/home').mkdir(parents=True)
            if os.environ.get('ADMISSION_PID'):
                (prepared/'data').mkdir(parents=True)
                (prepared/'data/proxy-process.json').write_text(json.dumps({'pid':int(os.environ['ADMISSION_PID'])}))
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
    definitions = "import hashlib, json\nfrom pathlib import Path\n"
    for function in (installed_binaries, retained_inputs.sha256, retained_inputs.selected, retained_inputs.verify_installed):
        definitions += inspect.getsource(function) + "\n"
    (controller / "tests/blackbox/retained_inputs.py").write_text(definitions + child)
    for name in ("claude_smoke.py", "installed_sections.py", "installed_host_smoke.py"):
        shutil.copy2(Path(retained_inputs.__file__).with_name(name), controller / "tests/blackbox" / name)
    provision = controller / "provision host binding"
    provision.write_text("#!/bin/sh\nset -eu\n"
                         'test "$1" = "${EXPECTED_PREPARED:-$PWD/prepared}"\ntest "$2" = host-access-only\n'
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
                              credential="host-access-only", output=tmp_path / "new private attempt",
                              selection=None, prepared_config=None, readiness=None)
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


@pytest.fixture
def retained_invocation(invocation, monkeypatch):
    args, controller = invocation
    source = controller / "retained installation"
    source.mkdir()
    linux = {'host_uid': os.getuid(), 'host_gid': os.getgid(), 'uid_base': 100000, 'gid_base': 100000,
             'runsc': '/verified/runsc', 'runsc_origin': 'bundled'}
    configuration = '\n[linux]\n' + ''.join(f'{key} = {json.dumps(value)}\n' for key, value in linux.items())
    (source / 'config.toml').write_text(configuration)
    doctor = {'state': 'ready', 'path': '/verified/runsc', 'version': 'qualified-runsc', 'origin': 'bundled'}
    native = textwrap.dedent(f'''\
        #!{sys.executable}
        import json, os, pathlib, sys
        root = pathlib.Path(sys.argv[sys.argv.index('--root')+1])
        stage = sys.argv[-1]
        with pathlib.Path({str(controller / 'events')!r}).open('a') as output:
            output.write(json.dumps({{'stage':stage}})+'\\n')
        if stage == 'doctor':
            print(json.dumps({{'linux':dict({doctor!r}, state=os.environ.get('DOCTOR_STATE', 'ready'))}}))
        elif stage == 'init':
            root.mkdir()
            (root/'config.toml').write_text('')
            print('PRIVATE init diagnostic')
        elif stage == 'stop':
            pass
        else:
            sys.exit(97)
    ''')
    hashes = {}
    for name in installed_binaries('linux-amd64'):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(native if name == 'bin/safeyolo' else name)
        path.chmod(0o700)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (source / 'package-info').write_text(f'source_commit={SOURCE}\nprofile=production\nplatform=linux-amd64\nguest_compatibility=v1\n')
    guest = {'version': 'retained-guest', 'compatibility': 'v1',
             'index': {'digest': 'sha256:' + 'b'*64, 'size': 123},
             'child': {'digest': 'sha256:' + 'c'*64, 'size': 456},
             'archive': {'digest': 'sha256:' + 'f'*64, 'size': 789}}
    (source / 'share').mkdir()
    (source / 'share/guest-selection.json').write_text(json.dumps({
        'repository': 'ghcr.io/craigbalding/safeyolo-guest', 'version': guest['version'],
        'compatibility': 'v1', 'platform': 'linux/amd64', 'index': guest['index'],
        'manifest': guest['child'], 'archive': guest['archive']}))
    selection = {'schema': 'safeyolo.blackbox-inputs/v1', 'status': 'selected', 'default_branch': 'master',
                 'default_branch_head': 'c'*40, 'platform': 'linux-amd64',
                 'selection_method': 'operator-retained-input-reuse',
                 'host': {'source_revision': SOURCE, 'executables_sha256': hashes,
                          'archive': {'name': 'absent-host.tar.gz', 'sha256': 'f'*64, 'size': 12}}, 'guest': guest}
    args.selection = controller / 'frozen selection.json'
    args.selection.write_text(json.dumps(selection))
    proof = controller / 'original reports'
    (proof / 'guest/isolation').mkdir(parents=True)
    (proof / 'selection.json').write_bytes(args.selection.read_bytes())
    retained_inputs.verify_installed(args.selection, source, proof)
    (proof / 'retained-run.json').write_text(json.dumps({
        'exit': 0, 'lane': 'systrap', 'host_id': platform.node(), 'host_system': platform.system(),
        'host_architecture': platform.machine(), 'controller_revision': 'e'*40,
        'controller_dirty': False, 'finished_at': 'original-time'}))
    prior_instance = controller / 'original isolation state'
    prior_instance.mkdir()
    (prior_instance / 'config.toml').write_text(configuration)
    (proof / 'guest/installed-sections.json').write_text(json.dumps({
        'source_revision': SOURCE, 'lane': 'systrap',
        'preparation': {'exit': 0, 'config_dir': str(source), 'reused_installation': True},
        'sections': [{'section': name, 'config_dir': str(prior_instance), 'prepared_config_dir': str(source),
                      'exit': 0, 'result': 'passed', 'cleanup': 'stopped', 'cleanup_failures': []}
                     for name in caller.SECTIONS['systrap']]}))
    (proof / 'guest/isolation/installed-rust-runtime.json').write_text(json.dumps({
        'status': 'attached_ready', 'cli': {'source_revision': SOURCE},
        'substrate': {key: value for key, value in doctor.items() if key != 'state'}}))
    # The original successful witness and host secrets must survive the new run.
    (source / 'agents/old/home').mkdir(parents=True)
    (source / 'agents/old/home/proof').write_text('original accepted proof')
    (source / 'data/coord/nats/bin').mkdir(parents=True)
    (source / 'data/coord/nats/bin/nats-server').write_text('verified nats fixture')
    (source / 'data/credential').write_text('PRIVATE original host secret')
    args.trigger, args.prepared_config, args.readiness = 'manual', source, proof
    monkeypatch.setenv('EXPECTED_PREPARED', str(args.output / 'prepared'))
    return args, controller


@pytest.mark.parametrize('owner', ['live', 'stopped'])
def test_manual_reuse_preserves_original_owner_and_proof_and_uses_fresh_state(retained_invocation, owner):
    args, controller = retained_invocation
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    if owner == 'stopped':
        process.terminate()
        process.wait()
    receipt = args.prepared_config / 'data/proxy-process.json'
    receipt.write_text(json.dumps({'pid': process.pid}))
    original = {path: path.read_bytes() for path in args.prepared_config.rglob('*') if path.is_file()}
    proof = {path: path.read_bytes() for path in args.readiness.rglob('*') if path.is_file()}
    try:
        report = caller.run(args)
        assert report['exit'] == 0, report
        assert [row['stage'] for row in events(controller)] == ['doctor', 'init', 'binding', 'smoke']
        assert report['selection_mode'] == 'retained-manual' and report['readiness_reused']
        assert report['controller_revision'] == 'd'*40
        assert report['readiness']['controller_revision'] == 'e'*40
        assert report['installed']['host_source_revision'] == SOURCE
        assert report['readiness_selection'] == json.loads(args.selection.read_bytes())
        assert (args.output / 'inputs/selection.json').read_bytes() == args.selection.read_bytes()
        assert (args.output / 'readiness/retained-run.json').read_bytes() == proof[args.readiness / 'retained-run.json']
        assert not (args.output / 'prepared/agents/old').exists()
        assert not (args.output / 'prepared/data/credential').exists()
        assert all(path.read_bytes() == content for path, content in original.items())
        assert all(path.read_bytes() == content for path, content in proof.items())
        if owner == 'live':
            assert process.poll() is None
        assert 'PRIVATE' not in json.dumps(report)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


@pytest.mark.parametrize('fault', ['installed-source', 'installed-bytes', 'missing-readiness', 'failed-readiness',
                                 'host', 'controller', 'missing-section', 'failed-section', 'cleanup',
                                 'readiness-inputs', 'selection', 'configuration', 'runtime', 'doctor'])
def test_invalid_reuse_cannot_provision_or_start_a_model(retained_invocation, monkeypatch, fault):
    args, controller = retained_invocation
    path = args.readiness / 'retained-run.json'
    if fault == 'installed-source':
        path = args.prepared_config / 'package-info'
        path.write_text(path.read_text().replace(SOURCE, 'b'*40))
    elif fault == 'installed-bytes':
        (args.prepared_config / 'bin/safeyolo-proxy').write_text('tampered')
    elif fault == 'missing-readiness':
        path.unlink()
    elif fault in {'failed-readiness', 'host', 'controller'}:
        value = json.loads(path.read_bytes())
        value[{'failed-readiness': 'exit', 'host': 'host_id', 'controller': 'controller_dirty'}[fault]] = {
            'failed-readiness': 1, 'host': 'another-host', 'controller': True}[fault]
        path.write_text(json.dumps(value))
    elif fault in {'missing-section', 'failed-section', 'cleanup'}:
        path = args.readiness / 'guest/installed-sections.json'
        value = json.loads(path.read_bytes())
        if fault == 'missing-section':
            value['sections'].pop()
        else:
            value['sections'][0]['exit' if fault == 'failed-section' else 'cleanup'] = 1 if fault == 'failed-section' else 'failed'
        path.write_text(json.dumps(value))
    elif fault == 'readiness-inputs':
        path = args.readiness / 'installed-inputs.json'
        value = json.loads(path.read_bytes())
        value['host_source_revision'] = 'b'*40
        path.write_text(json.dumps(value))
    elif fault == 'selection':
        path = args.readiness / 'selection.json'
        value = json.loads(path.read_bytes())
        value['host']['archive']['sha256'] = '0'*64
        path.write_text(json.dumps(value))
    elif fault == 'configuration':
        with (args.prepared_config / 'config.toml').open('a') as output:
            output.write('apparmor_profile = "changed"\n')
    elif fault == 'runtime':
        path = args.readiness / 'guest/isolation/installed-rust-runtime.json'
        value = json.loads(path.read_bytes())
        value['substrate']['version'] = 'another-runtime'
        path.write_text(json.dumps(value))
    else:
        monkeypatch.setenv('DOCTOR_STATE', 'unavailable')
    report = caller.run(args)
    assert report['exit'] == 2, report
    assert all(row['stage'] == 'doctor' for row in events(controller))
    assert not (args.output / 'prepared').exists()
    assert 'PRIVATE' not in json.dumps(report)


@pytest.mark.parametrize('trigger', ['nightly', 'merge'])
def test_retained_inputs_are_explicit_manual_proof(retained_invocation, trigger):
    args, controller = retained_invocation
    args.trigger, args.source_revision = trigger, SOURCE
    report = caller.run(args)
    assert report['exit'] == 2 and not events(controller)


@pytest.mark.parametrize('code', [0, 23])
@pytest.mark.parametrize('caller_fixture', ['retained_invocation', 'prepared_invocation'])
def test_retained_cli_returns_private_reports_and_real_exit(request, monkeypatch, code, caller_fixture):
    args, controller = request.getfixturevalue(caller_fixture)
    script = controller / 'scripts/run_claude_blackbox.py'
    script.write_text(Path(caller.__file__).read_text())
    monkeypatch.setenv('FAIL_SMOKE', str(code))
    command = [sys.executable, str(script), 'manual', '--ref', args.ref,
               '--selection', str(args.selection), '--prepared-config', str(args.prepared_config),
               '--provision', str(args.provision), '--credential', args.credential, '--output', str(args.output)]
    if args.readiness:
        command += ['--readiness', str(args.readiness)]
    result = subprocess.run(command,
                            capture_output=True, text=True, check=False)
    assert result.returncode == code, result.stderr + result.stdout
    report = json.loads(result.stdout)
    assert report == json.loads((args.output / 'result.json').read_bytes())
    assert 'PRIVATE' not in result.stdout + result.stderr
    assert 'PRIVATE init diagnostic' in (args.output / 'private.log').read_text()
    for name in ('result.json', 'private.log', 'inputs/selection.json',
                 'prepared/config.toml', 'prepared/private-state/credential'):
        assert (args.output / name).stat().st_mode & 0o777 == 0o600
    assert (args.output/'readiness/retained-run.json').stat().st_mode & 0o777 == (0o600 if args.readiness else 0o644)
    assert args.output.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('owner', ['home', 'live', 'stopped'])
@pytest.mark.parametrize('caller_fixture', ['invocation', 'prepared_invocation'])
def test_caller_checks_dedicated_ownership_before_provisioning(request, monkeypatch, owner, caller_fixture):
    args, controller = request.getfixturevalue(caller_fixture)
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    if owner != 'live':
        process.terminate()
        process.wait()
    monkeypatch.setenv('ADMISSION_PID', str(process.pid))
    if owner == 'home':
        monkeypatch.setenv('ADMISSION_HOME', '1')
    try:
        report = caller.run(args)
        assert report['exit'] == (0 if owner == 'stopped' else 2)
        stages = [row['stage'] for row in events(controller)]
        if caller_fixture == 'invocation':
            assert stages == (['selection', 'readiness', 'binding', 'smoke']
                              if owner == 'stopped' else ['selection', 'readiness'])
        else:
            assert 'continuity' in stages
            assert [stage for stage in stages if stage in {'binding', 'smoke'}] == (
                ['binding', 'smoke'] if owner == 'stopped' else [])
        if owner == 'live':
            assert process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


@pytest.mark.parametrize('failure', ['binding', 'missing-report', 'invalid-report'])
def test_retained_failure_and_report_return_cannot_pass(retained_invocation, monkeypatch, failure):
    args, controller = retained_invocation
    variable = {'binding': 'FAIL_BINDING', 'missing-report': 'MISSING_SMOKE_REPORT',
                'invalid-report': 'INVALID_SMOKE_REPORT'}[failure]
    monkeypatch.setenv(variable, '31' if failure == 'binding' else '1')
    report = caller.run(args)
    assert report['exit'] == (31 if failure == 'binding' else 2)
    assert 'PRIVATE' not in json.dumps(report)
    assert json.loads((args.output / 'result.json').read_bytes()) == report
    if failure == 'binding':
        assert [row['stage'] for row in events(controller)] == ['doctor', 'init', 'binding']


@pytest.mark.parametrize('missing', ['selection', 'prepared_config'])
def test_incomplete_manual_reuse_is_refused_before_work(retained_invocation, missing):
    args, controller = retained_invocation
    setattr(args, missing, None)
    assert caller.run(args)['exit'] == 2
    assert not events(controller)


def test_retained_runtime_timeout_returns_failure_before_provisioning(retained_invocation, monkeypatch):
    args, controller = retained_invocation

    def stalled_doctor(arguments, **options):
        assert arguments[-1] == 'doctor' and options['timeout'] == 15
        raise subprocess.TimeoutExpired(arguments, options['timeout'], output=b'PRIVATE diagnostics')

    monkeypatch.setattr(caller.subprocess, 'run', stalled_doctor)
    report = caller.run(args)
    assert report['exit'] == 2 and report['failure'] == 'command timed out'
    assert report['readiness_reused'] is False
    assert not events(controller)
    assert 'PRIVATE' not in json.dumps(report)


@pytest.fixture
def prepared_invocation(retained_invocation):
    """Use the actual retained and section report writers; control only runtime work."""
    args, controller = retained_invocation
    args.readiness = None
    (controller/'scripts/run_claude_blackbox.py').write_bytes(Path(caller.__file__).read_bytes())
    instruments = controller / 'tests/blackbox'
    (instruments / 'controlled-claude.py').write_text((instruments / 'retained_inputs.py').read_text().replace(
        'directory.mkdir(parents=True)', 'directory.mkdir(parents=True, exist_ok=True)'))
    (instruments / 'retained_inputs.py').write_bytes(Path(retained_inputs.__file__).read_bytes())
    with (controller / 'scripts/select_blackbox_artifacts.py').open('a') as output:
        output.write('\n' + inspect.getsource(installed_binaries))
    # The installed CLI's native identity and the real sections are qualified
    # separately. This boundary supplies their commands without booting guests.
    wrapper = textwrap.dedent('''\
        import argparse, os, pathlib, subprocess, sys
        root = pathlib.Path.cwd()
        sys.path.insert(0, str(root))
        from tests.blackbox.installed_sections import SECTIONS, run_sections
        parser = argparse.ArgumentParser()
        parser.add_argument('lane')
        parser.add_argument('--prepared-config', type=pathlib.Path)
        parser.add_argument('--install-commit')
        parser.add_argument('--artifacts', type=pathlib.Path)
        parser.add_argument('--section', action='append')
        args = parser.parse_args()
        if args.section == ['claude']:
            sys.exit(subprocess.call([sys.executable, str(root/'tests/blackbox/controlled-claude.py'),
                '--prepared-config', str(args.prepared_config), '--section', 'claude',
                '--artifacts', str(args.artifacts.parent)]))
        directory = args.artifacts.parent/'section-state'
        directory.mkdir()
        sections = tuple(args.section or SECTIONS[args.lane])
        if os.environ.get('INCOMPLETE_READINESS'):
            sections = ('isolation',)
        code = run_sections(args.lane, sections, root, args.install_commit,
                            directory, args.artifacts, prepared_config=args.prepared_config)
        sys.exit(0 if os.environ.get('FALSE_READINESS_SUCCESS') else code)
    ''')
    (instruments / 'run-installed.sh').write_text(f'#!{sys.executable}\n' + wrapper)
    (instruments / 'run-installed.sh').chmod(0o700)
    section = textwrap.dedent('''\
        import json, os, pathlib, sys
        from unittest.mock import patch
        root = pathlib.Path.cwd()
        sys.path.insert(0, str(root))
        from tests.blackbox.installed_host_smoke import _base_report, _substrate_identity
        instance = pathlib.Path(os.environ['SAFEYOLO_TEST_CONFIG_DIR'])
        instance.mkdir()
        source = pathlib.Path(os.environ['SAFEYOLO_BLACKBOX_PREPARED_CONFIG_DIR'])
        (instance/'config.toml').write_bytes((source/'config.toml').read_bytes())
        with (root/'events').open('a') as output:
            output.write(json.dumps({'stage':instance.name, 'instance':str(instance), 'umask':os.umask(0o022)})+'\\n')
        if instance.name == 'isolation':
            # This Ubuntu caller fixture supplies Linux doctor/runsc inputs.
            # Select that branch only for substrate discovery on any test host.
            with patch('tests.blackbox.installed_host_smoke.platform.system', return_value='Linux'):
                substrate = _substrate_identity(source)
            report = _base_report({'source_revision':'a'*40}, {}, substrate)
            report['status'] = 'attached_ready'
            artifacts = pathlib.Path(os.environ['SAFEYOLO_BLACKBOX_ARTIFACTS_DIR'])
            (artifacts/'installed-rust-runtime.json').write_text(json.dumps(report))
        if instance.name == 'continuity':
            if os.environ.get('ADMISSION_HOME'):
                (source/'agents/owner/home').mkdir(parents=True)
            if os.environ.get('ADMISSION_PID'):
                (source/'data/proxy-process.json').write_text(json.dumps({'pid':int(os.environ['ADMISSION_PID'])}))
        sys.exit(int(os.environ.get('FAIL_READINESS', '0')))
    ''')
    (instruments / 'run-tests.sh').write_text(f'#!{sys.executable}\n' + section)
    (instruments / 'run-tests.sh').chmod(0o700)
    (instruments / 'installed_state_transition.py').write_text(section)
    (controller / '.gitignore').write_text('__pycache__/\n/events\n/retained installation/\n/original reports/\n'
                                          '/original isolation state/\n/frozen selection.json\n')
    for command in (['git', 'init', '-q'], ['git', 'add', '.'],
                    ['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
                     'commit', '-qm', 'Controlled runtime commands']):
        subprocess.run(command, cwd=controller, check=True, capture_output=True)
    return args, controller


@pytest.mark.parametrize('owner', ['live', 'stopped'])
def test_missing_readiness_runs_maintained_sections_before_binding_and_preserves_owners(prepared_invocation, owner):
    args, controller = prepared_invocation
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    if owner == 'stopped':
        process.terminate()
        process.wait()
    (args.prepared_config/'data/proxy-process.json').write_text(json.dumps({'pid': process.pid}))
    original = {path: path.read_bytes() for path in args.prepared_config.rglob('*') if path.is_file()}
    proof = {path: path.read_bytes() for path in (controller/'original reports').rglob('*') if path.is_file()}
    try:
        report = caller.run(args)
        assert report['exit'] == 0, report
        stages = [row['stage'] for row in events(controller)]
        assert stages == ['doctor', 'init', 'isolation', 'doctor', 'stop', 'workloads', 'stop',
                          'access', 'stop', 'lifecycle', 'stop', 'continuity', 'stop', 'binding', 'smoke']
        assert report['selection_mode'] == 'retained-manual' and report['readiness_reused'] is False
        assert report['readiness_origin'] is None
        assert report['readiness']['controller_revision'] == subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=controller, text=True).strip()
        assert report['readiness']['reused_installation'] is True
        assert report['installed']['host_source_revision'] == SOURCE
        assert report['readiness_selection'] == json.loads(args.selection.read_bytes())
        rows = report['readiness_sections']['sections']
        assert [row['section'] for row in rows] == list(caller.SECTIONS['systrap'])
        assert all(row['cleanup'] == 'stopped' and row['result'] == 'passed' for row in rows)
        assert len({row['config_dir'] for row in rows}) == len(rows)
        assert all(row['prepared_config_dir'] == str(args.output/'prepared') for row in rows)
        assert all(row['umask'] == 0o022 for row in events(controller) if row['stage'] in caller.SECTIONS['systrap'])
        assert not (args.output/'prepared/agents/old').exists()
        assert not (args.output/'prepared/data/credential').exists()
        assert all(path.read_bytes() == content for path, content in {**original, **proof}.items())
        if owner == 'live':
            assert process.poll() is None
        assert 'PRIVATE' not in json.dumps(report)
        assert json.loads((args.output/'result.json').read_bytes()) == report
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


@pytest.mark.parametrize('fault', ['exit', 'false-success', 'incomplete', 'installed-bytes', 'doctor'])
def test_prepared_readiness_failure_never_provisions(prepared_invocation, monkeypatch, fault):
    args, controller = prepared_invocation
    if fault in {'exit', 'false-success'}:
        monkeypatch.setenv('FAIL_READINESS', '19')
        if fault == 'false-success':
            monkeypatch.setenv('FALSE_READINESS_SUCCESS', '1')
    elif fault == 'incomplete':
        monkeypatch.setenv('INCOMPLETE_READINESS', '1')
    elif fault == 'installed-bytes':
        (args.prepared_config/'bin/safeyolo-proxy').write_text('tampered')
    else:
        monkeypatch.setenv('DOCTOR_STATE', 'unavailable')
    report = caller.run(args)
    assert report['exit'] == 2 and report['stage'] == 'credential-free-installed', report
    assert all(row['stage'] not in {'binding', 'smoke', 'selection'} for row in events(controller))
    if fault in {'exit', 'false-success', 'incomplete'}:
        assert report['readiness_sections']['sections'][0]['section'] == 'isolation'
        assert report['readiness']['exit'] == (2 if fault == 'exit' else 0)
    else:
        assert not (args.output/'prepared').exists()
    assert 'PRIVATE' not in json.dumps(report)


@pytest.mark.parametrize('sections', [['isolation'], ['isolation', 'access']])
def test_prepared_retained_entry_forwards_explicit_nonsecret_sections(prepared_invocation, monkeypatch, sections):
    args, controller = prepared_invocation
    monkeypatch.setattr(retained_inputs, 'ROOT', controller)
    assert retained_inputs.run(args.selection, 'systrap', args.output, sections, False,
                               prepared_config=args.prepared_config) == 0
    report = json.loads((args.output/'guest/installed-sections.json').read_bytes())
    assert [row['section'] for row in report['sections']] == sections
    assert all(row['result'] == 'passed' and row['cleanup'] == 'stopped' for row in report['sections'])
    assert report['preparation']['config_dir'] == str(args.prepared_config)
