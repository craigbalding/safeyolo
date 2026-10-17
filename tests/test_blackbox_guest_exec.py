"""Reach maintained guest-command callers without booting a sandbox."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.blackbox import guest_exec, installed_access, installed_lifecycle, installed_workloads


@pytest.mark.parametrize('user', ['agent', 'root'])
def test_guest_dispatcher_uses_selected_native_cli_without_a_python_package(tmp_path, user):
    """An isolated test interpreter forwards literals to the selected native shell."""
    ambient = tmp_path / 'ambient'
    venv.EnvBuilder(with_pip=False, symlinks=True).create(ambient)
    python = ambient / 'bin/python'
    root = tmp_path / 'selected instance'
    (root / 'bin').mkdir(parents=True)
    native = root / 'bin/safeyolo'
    native.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit 7\n')
    native.chmod(0o755)
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root))
    environment.pop('PYTHONPATH', None)
    environment.pop('SAFEYOLO_NATIVE_CONFIG_PATH', None)
    subprocess.run([str(python), '-c', "import importlib.util; assert importlib.util.find_spec('safeyolo') is None"],
                   env=environment, cwd=tmp_path, check=True, timeout=10)
    literal = "printf '%s' 'literal $(must not execute)'"
    result = subprocess.run([
        str(python), str(Path(guest_exec.__file__).resolve()), '--cli', str(native),
        'marker', '--user', user, '-c', literal,
    ], env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 7, result.stderr
    command = literal if user == 'agent' else 'exec sudo -n /bin/bash -lc ' + shlex.quote(literal)
    assert result.stdout.splitlines() == ['--root', str(root), 'agent', 'shell', 'marker', '-c', command]
    assert not (root / 'agents').exists()


def test_guest_dispatcher_does_not_import_an_ambient_package_or_select_path_decoys(tmp_path, monkeypatch):
    decoy = tmp_path / 'decoy'
    (decoy / 'safeyolo').mkdir(parents=True)
    (decoy / 'safeyolo/__init__.py').write_text("raise AssertionError('ambient package imported')\n")
    marker = tmp_path / 'decoy-called'
    (decoy / 'safeyolo-command').write_text(f'#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 99\n')
    (decoy / 'safeyolo-command').chmod(0o755)
    selected = tmp_path / 'selected'
    selected.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit 7\n')
    selected.chmod(0o755)
    environment = dict(os.environ, PATH=f'{decoy}:{os.environ["PATH"]}', PYTHONPATH=str(decoy),
                       SAFEYOLO_CONFIG_DIR=str(tmp_path / 'root'))
    result = subprocess.run([sys.executable, str(Path(guest_exec.__file__).resolve()),
                             '--cli', str(selected), 'worker', '-c', 'literal'],
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 7, result.stderr
    assert not marker.exists()


def test_runner_readiness_and_both_isolation_invocations_reach_native_shell(tmp_path):
    source = Path('tests/blackbox/run-tests.sh').read_text().splitlines()
    selected = [line.strip() for line in source if '"$SCRIPT_DIR/guest_exec.py"' in line]
    assert len(selected) == 4
    cli = tmp_path / 'safeyolo'
    record = tmp_path / 'calls'
    cli.write_text(f'#!{sys.executable}\nimport json,sys\n'
                   f'with open({str(record)!r}, "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")\n')
    cli.chmod(0o755)
    root = tmp_path / 'root'
    environment = dict(os.environ, SCRIPT_DIR=str(Path('tests/blackbox').resolve()),
                       INSTALLED_CLI=str(cli), AGENT_NAME='marker', SAFEYOLO_CONFIG_DIR=str(root))
    calls = []
    for line in selected:
        if '--prepare-tests' in line:
            invocation = line.removeprefix('if ! ').removesuffix('; then')
        elif line.startswith('if '):
            invocation = line.removeprefix('if ').removesuffix('; then')
        else:
            invocation = line.removesuffix('\\') + " 'printf literal'"
        result = subprocess.run(['bash', '-c', invocation], env=environment,
                                input='runner stdin', capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        calls.append(json.loads(record.read_text().splitlines()[-1]))
    prefix = ['--root', str(root), 'agent', 'shell', 'marker', '-c']
    assert calls[0] == [*prefix, 'true']
    assert calls[1][:-1] == prefix
    assert shlex.split(calls[1][-1]) == [
        'exec', 'sudo', '-n', '/bin/bash', '-lc',
        'bash /workspace/tests/blackbox/prepare-guest-tests.sh',
    ]
    assert calls[2] == [*prefix, 'printf literal']
    assert calls[3][:-1] == prefix
    assert shlex.split(calls[3][-1]) == ['exec', 'sudo', '-n', '/bin/bash', '-lc', 'printf literal']


@pytest.mark.parametrize('installer,offline', [('apt-get', False), ('apk', False), ('apt-get', True)])
@pytest.mark.parametrize('install_exit', [0, 17])
def test_guest_test_setup_uses_lock_and_stops_on_package_failure(tmp_path, install_exit, installer, offline):
    """An interpreter-free guest uses hashed requirements; OS install errors stop setup."""
    tools = tmp_path / 'tools'
    tools.mkdir()
    (tools / 'dirname').symlink_to(shutil.which('dirname'))
    record = tmp_path / 'calls'
    python = tools / 'python3'
    inputs = tmp_path / 'offline inputs $literal'
    for name in ('debs/python.deb', 'wheels/pytest.whl'):
        path = inputs / name
        path.parent.mkdir(parents=True)
        path.touch()
    python.write_text(f'''#!{sys.executable}
import json, sys
arguments = sys.argv[1:]
with open({str(record)!r}, 'a') as out: out.write(json.dumps(['python3', *arguments]) + '\\n')
if arguments == ['-m', 'pip', '--version']:
    sys.exit(1)
if arguments[:3] == ['-m', 'pip', 'install']:
    from pathlib import Path
    assert '--require-hashes' in arguments
    requirements = Path(arguments[arguments.index('-r') + 1])
    assert requirements == Path('tests/blackbox/guest-requirements.txt').resolve()
    assert '--hash=sha256:' in requirements.read_text()
    if {offline!r}:
        assert '--no-index' in arguments
        assert arguments[arguments.index('--find-links') + 1] == {str(inputs / 'wheels')!r}
    else:
        assert '--no-index' not in arguments and '--find-links' not in arguments
if arguments[:1] == ['-c']:
    assert arguments[1] == 'import pytest, httpx, pytest_timeout'
''')
    python.chmod(0o755)
    package_installer = tools / installer
    package_installer.write_text(f'#!{sys.executable}\nimport json, os, sys\n'
                                f'with open({str(record)!r}, "a") as out: out.write(json.dumps([{installer!r}, *sys.argv[1:]]) + "\\n")\n'
                                f'if {offline!r}: assert os.environ["DEBIAN_FRONTEND"] == "noninteractive"\n'
                                f'sys.exit({install_exit})\n')
    package_installer.chmod(0o755)
    arguments = [str(inputs)] if offline else []
    result = subprocess.run(['/bin/bash', 'tests/blackbox/prepare-guest-tests.sh', *arguments],
                            env=dict(os.environ, PATH=str(tools)), text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == install_exit, result.stderr
    calls = [json.loads(line) for line in record.read_text().splitlines()]
    if offline:
        assert calls[0] == [
            'apt-get', '-o', 'Dir::Etc::sourcelist=/dev/null', '-o', 'Dir::Etc::sourceparts=-',
            '-o', 'Dpkg::Use-Pty=0', '-y', '--no-install-recommends', 'install',
            str(inputs / 'debs/python.deb'),
        ]
        assert ['apt-get', 'update'] not in calls
    elif installer == 'apt-get':
        assert ['apt-get', 'update'] in calls
    else:
        assert ['apk', 'add', 'python3', 'py3-pip'] in calls
    installs = [call for call in calls if call[:4] == ['python3', '-m', 'pip', 'install']]
    assert bool(installs) == (install_exit == 0)
    assert (calls[-1][1:2] == ['-c']) == (install_exit == 0)


@pytest.mark.parametrize('missing', ['all', 'debs', 'wheels', 'relative-path'])
def test_offline_guest_setup_refuses_missing_inputs_before_package_commands(tmp_path, missing):
    inputs = tmp_path / 'offline'
    for name in ('debs/python.deb', 'wheels/pytest.whl'):
        if missing not in ('all', name.split('/')[0]):
            path = inputs / name
            path.parent.mkdir(parents=True)
            path.touch()
    selected = 'relative/offline' if missing == 'relative-path' else str(inputs)
    # An empty PATH makes any accidental online package command fail distinctly.
    result = subprocess.run(['/bin/bash', 'tests/blackbox/prepare-guest-tests.sh', selected],
                            env=dict(os.environ, PATH=str(tmp_path / 'no-tools')),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert 'Offline guest test inputs need' in result.stderr
    assert 'command not found' not in result.stderr


@pytest.mark.parametrize('agent', ['bbtest', 'bbpeer', 'bbowner'])
@pytest.mark.parametrize('prepare_exit', [0, 17])
@pytest.mark.parametrize('offline', [False, True])
def test_guest_preparation_preserves_selected_root_and_propagates_failure(tmp_path, monkeypatch, agent, prepare_exit, offline):
    cli = tmp_path / 'native-cli'
    record = tmp_path / 'calls'
    cli.write_text(f'#!{sys.executable}\nimport json, sys\n'
                   f'with open({str(record)!r}, "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                   f'sys.exit({prepare_exit})\n')
    cli.chmod(0o755)
    root = str(tmp_path / 'selected root')
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=root)
    inputs = '/workspace/offline inputs $(must not execute)'
    environment.pop('SAFEYOLO_GUEST_TEST_INPUTS', None)
    if offline:
        environment['SAFEYOLO_GUEST_TEST_INPUTS'] = inputs
    monkeypatch.setenv('SAFEYOLO_GUEST_TEST_INPUTS', '/unrelated ambient inputs')
    if prepare_exit:
        with pytest.raises(SystemExit) as error:
            guest_exec.prepare_guest_tests(str(cli), agent, env=environment)
        assert error.value.code == 2
    else:
        guest_exec.prepare_guest_tests(str(cli), agent, env=environment)
    call = json.loads(record.read_text())
    assert call[:-1] == ['--root', root, 'agent', 'shell', agent, '-c']
    root_command = shlex.split(call[-1])
    assert root_command[:5] == ['exec', 'sudo', '-n', '/bin/bash', '-lc']
    assert shlex.split(root_command[-1]) == [
        'bash', '/workspace/tests/blackbox/prepare-guest-tests.sh', *([inputs] if offline else [])
    ]
    # Reach the maintained runner's conversion of guest setup failures.
    if agent == 'bbtest':
        runner = Path('tests/blackbox/run-tests.sh').read_text()
        start = runner.index('    if ! python3 "$SCRIPT_DIR/guest_exec.py" --cli "$INSTALLED_CLI" "$AGENT_NAME" --prepare-tests; then')
        block = runner[start:runner.index('    fi', start) + len('    fi')]
        result = subprocess.run(['/bin/bash', '-c', block], capture_output=True, text=True, timeout=10,
                                env=dict(environment, SCRIPT_DIR=str(Path('tests/blackbox').resolve()),
                                         INSTALLED_CLI=str(cli), AGENT_NAME=agent))
        assert result.returncode == (2 if prepare_exit else 0), result.stderr
        assert ('dependencies could not be prepared' in result.stderr) == bool(prepare_exit)


def test_workload_producer_preserves_root_identity_and_literal_arguments(monkeypatch):
    monkeypatch.setenv('SAFEYOLO_CONFIG_DIR', '/selected-root')
    cli = '/selected-root/bin/safeyolo'
    literal = 'with spaces $(not-expanded)'
    args = installed_workloads.guest_args(cli, 'marker', literal, 'package', '--sha', 'abc')
    assert args[:-1] == [cli, '--root', '/selected-root', 'agent', 'shell', 'marker', '-c']
    root_command = shlex.split(args[-1])
    assert root_command[:5] == ['exec', 'sudo', '-n', '/bin/bash', '-lc']
    request = shlex.split(root_command[-1])
    assert request[:4] == ['cd', '/workspace', '&&', 'python3']
    assert request[request.index('--marker') + 1] == literal
    for args in (installed_access.guest_command(cli, 'marker', 'systrap', literal, 'coord'),
                 installed_lifecycle.guest_command(cli, 'marker', 'tls', literal)):
        assert args[:-1] == [cli, '--root', '/selected-root', 'agent', 'shell', 'marker', '-c']
        assert shlex.split(args[-1])[shlex.split(args[-1]).index('--marker') + 1] == literal


@pytest.mark.parametrize('wrong_uid', [False, True])
def test_operator_attachment_opens_independent_shell_before_detach(tmp_path, monkeypatch, wrong_uid):
    """Reach the real PTY/subprocess boundary with a controlled guest transport."""
    root = tmp_path / 'selected root'
    root.mkdir()
    calls, marker = root / 'calls', root / 'marker'
    native = root / 'safeyolo'
    native.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys, tty
root = pathlib.Path({str(root)!r})
assert sys.argv[1:3] == ['--root', str(root)], 'ambient root selected'
arguments = sys.argv[3:]
with (root / 'calls').open('a') as output:
    output.write(json.dumps(arguments) + '\\n')
operation = arguments[1]
if operation == 'configure':
    (root / 'marker').write_text(arguments[-1].split("'")[1].removesuffix('\\\\n'))
elif operation == 'status':
    print(json.dumps({{'agent_state':'running', 'agent_id':'ag-owned',
                      'run_id':'run-owned', 'launch_id':'launch-owned'}}))
elif operation == 'attach':
    tty.setraw(0)
    print((root / 'marker').read_text(), flush=True)
    assert os.read(0, 2) == b'\\x02d'
    assert (root / 'shell-opened').exists(), 'detached before independent shell'
elif operation == 'shell':
    (root / 'shell-opened').touch()
    print(os.getpid())
    print({'0' if wrong_uid else '1000'})
''')
    native.chmod(0o755)
    monkeypatch.setenv('SAFEYOLO_CONFIG_DIR', str(tmp_path / 'unrelated root'))
    if wrong_uid:
        with pytest.raises(AssertionError):
            installed_access.operator_terminal(str(native), root, 'bbtest', 'r3-marker')
    else:
        result = installed_access.operator_terminal(str(native), root, 'bbtest', 'r3-marker')
        assert result['detached_command_running'] and result['shell_uid'] == 1000
        assert result['agent_id'] == 'ag-owned' and marker.read_text() == 'r3-marker'
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert [command[1] for command in commands[:5]] == ['configure', 'start', 'status', 'attach', 'shell']
    assert commands[4][:4] == ['agent', 'shell', 'bbtest', '-c']


@pytest.mark.parametrize('platform,failure', [
    (platform, failure)
    for platform in ('systrap', 'vz') for failure in (None, 'same-run', 'lost-origin')
] + [('vz', 'coord-start'), ('systrap', 'prepare-tests'), ('vz', 'prepare-tests')])
@pytest.mark.parametrize('offline', [False, True])
def test_operator_restart_retains_selected_guest_transport_and_requires_fresh_run_and_delivery(
    tmp_path, monkeypatch, platform, failure, offline
):
    """Reach native lifecycle and guest-call subprocesses with a controlled transport."""
    root = tmp_path / 'selected root'
    (root / 'data').mkdir(parents=True)
    (root / 'data/instance_id').write_text('sy-owned\n')
    (root / 'policy.toml').write_text('[hosts]\n')
    native = root / 'safeyolo'
    inputs = '/workspace/offline inputs $literal'
    monkeypatch.delenv('SAFEYOLO_GUEST_TEST_INPUTS', raising=False)
    if offline:
        monkeypatch.setenv('SAFEYOLO_GUEST_TEST_INPUTS', inputs)
    native.write_text(f'''#!{sys.executable}
import json, os, pathlib, shlex, sys
root = pathlib.Path({str(root)!r})
assert sys.argv[1:3] == ['--root', str(root)], 'ambient root selected'
arguments = sys.argv[3:]
with (root / 'calls').open('a') as output:
    output.write(json.dumps(arguments) + '\\n')
if arguments[:2] == ['agent', 'shell']:
    request = shlex.split(arguments[-1])
    if request[-1].startswith('bash /workspace/tests/blackbox/prepare-guest-tests.sh'):
        assert request[:5] == ['exec', 'sudo', '-n', '/bin/bash', '-lc']
        assert shlex.split(request[-1])[2:] == {([inputs] if offline else [])!r}
        sys.exit(17 if {failure!r} == 'prepare-tests' else 0)
    assert request[request.index('--platform') + 1] == {platform!r}, 'wrong guest bridge selected'
    phase = request[request.index('--phase') + 1]
    marker = request[request.index('--marker') + 1]
    result = {{'marker': marker, 'platform': {platform!r}}}
    if phase == 'coord-read':
        result['found'] = request[request.index('--message') + 1]
    print('P3_OBSERVATION=' + json.dumps({{'phase': phase, 'agent': 'bbtest',
          'forwarder': {{'pid': os.getpid()}}, 'result': result}}))
elif arguments == ['agent', 'stop', 'bbtest']:
    (root / 'stopped').touch()
elif arguments == ['agent', 'attach', 'bbtest']:
    assert (root / 'stopped').exists()
    print('coding-agent terminal is absent', file=sys.stderr)
    sys.exit(1)
elif arguments == ['agent', 'start', 'bbtest']:
    (root / 'stopped').unlink()
elif arguments == ['agent', 'status', 'bbtest']:
    stopped = (root / 'stopped').exists()
    print(json.dumps({{'runtime_state': 'stopped' if stopped else 'running', 'agent_id': 'ag-owned',
                      'run_id': {'"run-before"' if failure == 'same-run' else '"run-after"'}}}))
else:
    allowed = [['stop'], ['start']]
    if {platform!r} == 'vz':
        allowed.append(['coord', 'start', '--client-port', '46370', '--monitor-port', '46372'])
    assert arguments in allowed, arguments
    if arguments[0] == 'coord' and {failure!r} == 'coord-start':
        sys.exit(19)
''')
    native.chmod(0o755)
    monkeypatch.setenv('SAFEYOLO_CONFIG_DIR', str(root))
    deliveries = [SimpleNamespace(host='api.github.com', path=f'/installed-flow/r3-{phase}/bbtest')
                  for phase in ('before', 'after')]
    if failure == 'lost-origin':
        deliveries.pop()
    sinkhole = SimpleNamespace(get_requests=lambda: deliveries)
    terminal = {'agent_id': 'ag-owned', 'run_id': 'run-before'}
    if failure:
        expected_error = SystemExit if failure == 'prepare-tests' else AssertionError
        with pytest.raises(expected_error):
            installed_access.operator_restart(str(native), root, 'bbtest', 'r3', terminal,
                                              sinkhole, platform=platform)
    else:
        result = installed_access.operator_restart(str(native), root, 'bbtest', 'r3', terminal,
                                                  sinkhole, platform=platform)
        assert result['before_run_id'] != result['after_run_id']
        assert result['traffic_before']['platform'] == result['traffic_after']['platform'] == platform
        assert result['retained_coord']['found'] == 'p3-first:r3'
        assert result['allowed_origin_deliveries'] == 2
    calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
    lifecycle = [call for call in calls if call[:2] != ['agent', 'shell']]
    expected = [['agent', 'stop', 'bbtest'], ['agent', 'status', 'bbtest'],
                ['agent', 'attach', 'bbtest'], ['stop']]
    if platform == 'vz':
        expected.append(['coord', 'start', '--client-port', '46370', '--monitor-port', '46372'])
    if failure == 'coord-start':
        assert lifecycle == expected
        return
    if failure == 'prepare-tests':
        assert lifecycle == [*expected, ['start'], ['agent', 'start', 'bbtest']]
        guest_calls = [call for call in calls if call[:2] == ['agent', 'shell']]
        assert len(guest_calls) == 2  # Before-restart traffic, then the failed preparation.
        return
    assert lifecycle == [*expected, ['start'], ['agent', 'start', 'bbtest'], ['agent', 'status', 'bbtest']]


@pytest.fixture
def lifecycle_cli_probe(tmp_path):
    """Record real subprocess operands; the guest workload remains controlled."""
    cli = tmp_path / 'lifecycle-cli'
    calls = tmp_path / 'guest-calls.jsonl'
    cli.write_text(f'''#!{sys.executable}
import json, os, shlex, sys
arguments = sys.argv[1:]
request = shlex.split(arguments[-1])
phase = request[request.index('--phase') + 1]
agent = arguments[arguments.index('shell') + 1]
result = {{'argv': arguments, 'root': os.environ.get('SAFEYOLO_CONFIG_DIR'),
          'platform': request[request.index('--platform') + 1],
          'status': 200 if phase == 'echo' else 403}}
with open({str(calls)!r}, 'a') as output:
    output.write(json.dumps(result) + '\\n')
print('P4_OBSERVATION=' + json.dumps({{'phase': phase, 'agent': agent,
      'forwarder': {{'pid': os.getpid()}}, 'result': result}}))
''')
    cli.chmod(0o755)
    return str(cli), calls


@pytest.mark.parametrize('invocation', ['ambient', 'owner', 'missing-root', 'empty'])
def test_lifecycle_guest_selects_root_from_its_subprocess_environment(tmp_path, monkeypatch,
                                                                  lifecycle_cli_probe, invocation):
    subject, owner = str(tmp_path / 'subject'), str(tmp_path / 'owner with spaces')
    monkeypatch.setenv('SAFEYOLO_CONFIG_DIR', subject)
    monkeypatch.setenv('SAFEYOLO_BLACKBOX_PLATFORM', 'systrap')
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=owner)
    expected_root = owner
    if invocation == 'ambient':
        environment, expected_root = None, subject
    elif invocation == 'missing-root':
        environment.pop('SAFEYOLO_CONFIG_DIR')
        expected_root = None
    elif invocation == 'empty':
        environment, expected_root = {}, None
    cli, _ = lifecycle_cli_probe

    result = installed_lifecycle.guest(cli, 'bbowner', 'echo', 'p4-marker', env=environment)
    selected = ['--root', expected_root] if expected_root else []
    assert result['argv'][:-1] == [*selected, 'agent', 'shell', 'bbowner', '-c']
    assert result['root'] == expected_root
    assert result['platform'] == 'systrap'
    assert os.environ['SAFEYOLO_CONFIG_DIR'] == subject


def test_lifecycle_owner_controls_use_owner_root_for_both_guest_calls(tmp_path, monkeypatch, lifecycle_cli_probe):
    subject = tmp_path / 'subject'
    owner = tmp_path / 'owner'
    owner.mkdir()
    monkeypatch.setenv('SAFEYOLO_CONFIG_DIR', str(subject))
    config, policy = owner / 'config.toml', owner / 'policy.toml'
    config.write_text('readiness_file = "ready.json"\n')
    policy.write_text('budget = 12000\n')
    pid = os.getpid()
    readiness = {'pid': pid, 'instance_id': 'owner-instance'}
    (owner / 'ready.json').write_text(json.dumps(readiness))
    runtime = {'pid': pid, 'receipt': {'start_token': installed_lifecycle._process_start_token(pid)},
               'readiness': readiness}
    observation = {'runtime': runtime, 'config_sha256': installed_lifecycle._sha256(config),
                   'policy_sha256': installed_lifecycle._sha256(policy)}
    # Process/file identity is real; guest health and origin observations are
    # controlled so this test isolates the owner -> guest command boundary.
    monkeypatch.setattr(installed_lifecycle, '_probe_agent_health', lambda *_args: {'status': 200})
    marker = 'p4-owner'
    sinkhole = SimpleNamespace(get_requests=lambda **kwargs: (
        [SimpleNamespace(path=f'/p4/echo/{marker}')] if kwargs['host'] == installed_lifecycle.FIXTURE else []
    ))
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(owner))
    cli, calls = lifecycle_cli_probe

    result = installed_lifecycle.owner_controls(cli, owner, owner / 'proxy.sock', observation,
                                              environment, marker, sinkhole)
    assert result == {'pid': pid, 'instance_id': 'owner-instance', 'allowed': 200, 'denied': 403}
    operands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert len(operands) == 2
    for operand in operands:
        assert operand['argv'][:-1] == ['--root', str(owner), 'agent', 'shell', 'bbowner', '-c']
        assert operand['root'] == str(owner)
    assert os.environ['SAFEYOLO_CONFIG_DIR'] == str(subject)
