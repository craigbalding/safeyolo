"""Reach maintained guest-command callers without booting a sandbox."""

from __future__ import annotations

import json
import os
import shlex
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
    assert len(selected) == 3
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
        if line.startswith('if '):
            invocation = line.removeprefix('if ').removesuffix('; then')
        else:
            invocation = line.removesuffix('\\') + " 'printf literal'"
        result = subprocess.run(['bash', '-c', invocation], env=environment,
                                input='runner stdin', capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        calls.append(json.loads(record.read_text().splitlines()[-1]))
    prefix = ['--root', str(root), 'agent', 'shell', 'marker', '-c']
    assert calls[0] == [*prefix, 'true']
    assert calls[1] == [*prefix, 'printf literal']
    assert calls[2][:-1] == prefix
    assert shlex.split(calls[2][-1]) == ['exec', 'sudo', '-n', '/bin/bash', '-lc', 'printf literal']


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
