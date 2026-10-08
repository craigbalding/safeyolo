"""Reach maintained guest-command callers without booting a sandbox."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import venv
from pathlib import Path

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
