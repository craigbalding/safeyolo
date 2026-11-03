#!/usr/bin/env python3
"""Qualify installed relays in an owned disposable Linux/gVisor or physical VZ guest.

Run with --cli PATH --root INSTANCE --agent NAME --platform systrap|kvm|vz
--revision FULL_SHA --output REPORT --disposable-guest. The instance must already
be running with candidate guest assets. This invokes real pkill and killall as
guest root; never select an agent with other work in it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import signal
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def deadline(_signum, _frame):
    raise TimeoutError('relay proof exceeded 120 seconds')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--agent', required=True)
    parser.add_argument('--platform', required=True, choices=('systrap', 'kvm', 'vz'))
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--disposable-guest', action='store_true', required=True)
    args = parser.parse_args()
    source = (ROOT / 'tests/blackbox/isolation/relay_names.py').read_text()
    command = f'sudo -n python3 -u -c {shlex.quote(source)} --platform {args.platform} --disposable-guest'
    shell = [args.cli, '--root', str(args.root), 'agent', 'shell', args.agent, '-c']
    context = json.loads((args.root / 'agents' / args.agent
                          / 'config-share/host-launch-context.json').read_text())
    if args.platform == 'vz':
        runtime = Path(context['host_package']) / 'bin/safeyolo-vm'
    else:
        configuration = tomllib.loads((args.root / 'config.toml').read_text())
        runtime = Path(configuration['linux']['runsc'])
    runtime_command = [str(runtime), 'version' if args.platform == 'vz' else '--version']
    report = {
        'revision': args.revision, 'platform': args.platform, 'host': list(os.uname()),
        'started_at': datetime.now(UTC).isoformat(), 'shell_command': shell,
        'host_cli': subprocess.check_output([args.cli, '--version'], text=True).strip(),
        'runtime_command': runtime_command,
        'runtime_version': subprocess.check_output(runtime_command, text=True).strip(),
        'runtime_sha256': hashlib.sha256(runtime.read_bytes()).hexdigest(),
        'launch_context': {key: context[key] for key in ('generation', 'host_package', 'guest_inputs')},
        'stages': [],
    }
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(120)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Keep stderr separate and retain partial observations even if a check fails.
    with args.output.with_suffix('.stderr').open('w') as errors:
        with subprocess.Popen([*shell, command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=errors, text=True) as existing:
            try:
                for stage in ('inputs', 'ready', 'pkill', 'killall', 'passed'):
                    line = existing.stdout.readline()
                    assert line, f'existing shell ended before {stage}; see retained stderr'
                    observed = json.loads(line)
                    report['stages'].append(observed)
                    assert observed['stage'] == stage, observed
                    if stage == 'passed':
                        break
                    if stage == 'inputs':
                        for name in ('guest-proxy-forwarder', 'guest-shell-bridge'):
                            source_name = ROOT / f'cli/src/safeyolo/{name}.sh'
                            assert observed['assets'][name] == hashlib.sha256(source_name.read_bytes()).hexdigest()
                    else:
                        marker = f'fresh-shell-after-{stage}'
                        fresh = subprocess.run([*shell, f'printf %s {shlex.quote(marker)}'],
                                               check=True, capture_output=True, text=True, timeout=15)
                        assert fresh.stdout == marker, fresh.stdout
                        observed['new_host_shell'] = marker
                    existing.stdin.write('\n')
                    existing.stdin.flush()
                assert existing.wait(timeout=10) == 0
                report['status'] = 'passed'
            finally:
                signal.alarm(0)
                if existing.poll() is None:
                    existing.terminate()
                    existing.wait(timeout=10)
                report['ended_at'] = datetime.now(UTC).isoformat()
                report['existing_shell_exit'] = existing.returncode
                args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"relay proof {report['status']}: {args.output}")


if __name__ == '__main__':
    main()
