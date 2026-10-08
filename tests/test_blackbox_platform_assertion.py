"""The lane gate observes the actual backend and rejects stale or foreign state."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / 'blackbox/assert-platform.py'


@pytest.fixture
def probe(tmp_path, monkeypatch):
    import sys
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location('bb_assert_platform', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / 'root'
    (root / 'agents/worker').mkdir(parents=True)
    (root / 'agents/worker/runtime.json').write_text(json.dumps({'backend_pid': 42, 'backend_token': 'owned'}))
    monkeypatch.setattr(module, '_process_start_token', lambda pid: 'owned')
    monkeypatch.setattr(sys, 'platform', 'linux')
    return module, root


@pytest.mark.parametrize('platform', ['systrap', 'kvm'])
def test_running_platform_uses_actual_runsc_arguments(probe, monkeypatch, platform):
    module, root = probe
    monkeypatch.setattr(module, '_process_command_line', lambda pid: [b'runsc-sandbox',
        b'--bundle=' + os.fsencode(root / 'agents/worker'), ('--platform=' + platform).encode()])
    result = module.running_platform(root, 'worker')
    assert result['platform'] == platform and result['pid'] == 42


@pytest.mark.parametrize('defect', ['stale', 'foreign-bundle', 'unknown-backend', 'ambiguous-platform'])
def test_platform_gate_refuses_unowned_or_ambiguous_backend(probe, monkeypatch, defect):
    module, root = probe
    argv = [b'runsc-sandbox', b'--bundle=' + os.fsencode(root / 'agents/worker'), b'--platform=kvm']
    if defect == 'stale':
        monkeypatch.setattr(module, '_process_start_token', lambda pid: 'reused')
    elif defect == 'foreign-bundle':
        argv[1] = b'--bundle=/other/agent'
    elif defect == 'unknown-backend':
        argv[0] = b'python'
    else:
        argv.append(b'--platform=systrap')
    monkeypatch.setattr(module, '_process_command_line', lambda pid: argv)
    with pytest.raises(ValueError):
        module.running_platform(root, 'worker')


def test_vz_gate_checks_actual_helper_and_agent_control_socket(probe, monkeypatch):
    module, root = probe
    monkeypatch.setattr(module.sys, 'platform', 'darwin')
    monkeypatch.setattr(module, '_process_executable', lambda pid: (root / 'bin/safeyolo-vm').resolve())
    argv = [os.fsencode(root / 'bin/safeyolo-vm'), b'run', b'--control-socket',
            os.fsencode(root / 'data/vm-control/worker.sock')]
    monkeypatch.setattr(module, '_process_command_line', lambda pid: argv)
    assert module.running_platform(root, 'worker')['platform'] == 'vz'
    argv[-1] = b'/other/control.sock'
    with pytest.raises(ValueError, match='another agent'):
        module.running_platform(root, 'worker')
