#!/usr/bin/env python3
"""Bind an installed black-box lane to its running native sandbox backend.

A host's ability to use KVM does not prove this guest uses KVM. Inspect the
owned process, its birth identity, and its actual backend arguments instead.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from installed_host_smoke import _process_command_line, _process_executable, _process_start_token


def running_platform(root: Path, agent: str) -> dict:
    directory = root / 'agents' / agent
    run = json.loads((directory / 'runtime.json').read_text())
    pid, token = run.get('backend_pid'), run.get('backend_token')
    if type(pid) is not int or pid <= 1 or not token or _process_start_token(pid) != token:
        raise ValueError('native sandbox receipt does not own a live backend')
    argv = _process_command_line(pid)
    if sys.platform == 'darwin':
        executable = _process_executable(pid)
        expected = (root / 'bin/safeyolo-vm').resolve()
        control = os.fsencode(root / 'data/vm-control' / f'{agent}.sock')
        if executable != expected or b'--control-socket' not in argv or argv[-1] == b'--control-socket':
            raise ValueError('running VZ helper does not belong to the selected agent')
        if argv[argv.index(b'--control-socket') + 1] != control:
            raise ValueError('running VZ helper has another agent control socket')
        selected = 'vz'
    else:
        if not argv or Path(os.fsdecode(argv[0])).name != 'runsc-sandbox':
            raise ValueError('running backend is not a runsc sandbox')
        if b'--bundle=' + os.fsencode(directory) not in argv:
            raise ValueError('runsc backend belongs to another bundle')
        platforms = [arg.removeprefix(b'--platform=') for arg in argv if arg.startswith(b'--platform=')]
        if len(platforms) != 1 or platforms[0] not in {b'kvm', b'systrap'}:
            raise ValueError('running runsc backend has no unique supported platform')
        selected = platforms[0].decode()
    return {'platform': selected, 'pid': pid, 'start_token': token, 'agent': agent,
            'config_dir': str(root), 'argv': [os.fsdecode(arg) for arg in argv]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('expected', choices=('systrap', 'kvm', 'vz'))
    parser.add_argument('config_dir', type=Path)
    parser.add_argument('agent')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = running_platform(args.config_dir.resolve(), args.agent)
        if evidence['platform'] != args.expected:
            raise ValueError(f"blackbox lane expected {args.expected!r}, selected {evidence['platform']!r}")
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(f"Isolation platform: {evidence['platform']} (owned backend PID {evidence['pid']})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
