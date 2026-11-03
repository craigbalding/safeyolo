"""Exercise installed relay names and real name-based signals in a disposable guest.

The host companion owns the existing shell, opens new shells at each checkpoint,
and supplies the acknowledgements. This program must run as guest root: all relay
and control PIDs must be signalable by the account executing pkill and killall.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def relays(names: set[str]) -> dict[int, dict]:
    """Read actual names and births, including forked connection workers."""
    found = {}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            comm = (directory / 'comm').read_text().strip()
            if comm not in names:
                continue
            fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
            status = (directory / 'status').read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue  # A completed connection can exit during enumeration.
        if fields[0] != 'Z':
            found[int(directory.name)] = {
                'comm': comm, 'ppid': int(fields[1]), 'start': fields[19],
                'uids': next(line.split()[1:] for line in status if line.startswith('Uid:')),
            }
    return found


def health(stream: socket.socket) -> dict:
    """Send traffic on this exact connection without reconnecting it."""
    token = Path('/app/agent_token').read_text().strip()
    stream.sendall((
        'GET http://_safeyolo.proxy.internal/health HTTP/1.1\r\n'
        'Host: _safeyolo.proxy.internal\r\n'
        f'Authorization: Bearer {token}\r\n\r\n'
    ).encode())
    response = http.client.HTTPResponse(stream)
    response.begin()
    body = response.read()
    assert response.status == 200, response.status
    assert json.loads(body)['agent_api'] == 'ok', 'Agent API health failed'
    assert not response.will_close, 'proof needs a persistent proxy connection'
    return {'status': response.status, 'agent_api': 'ok'}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=('systrap', 'kvm', 'vz'))
    parser.add_argument('--disposable-guest', action='store_true', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, 'run as guest root so permissions cannot explain survival'
    for executable in ('socat', 'pkill', 'killall'):
        assert shutil.which(executable), f'{executable} is required'
    names = {'sy-proxy-relay'} | ({'sy-shell-relay'} if args.platform == 'vz' else set())
    assets = {
        name: hashlib.sha256(Path('/safeyolo', name).read_bytes()).hexdigest()
        for name in ('guest-proxy-forwarder', 'guest-shell-bridge', 'safeyolo-guest')
    }
    print(json.dumps({'stage': 'inputs', 'assets': assets, 'uname': list(os.uname()),
                      'uid': os.geteuid(), 'socat': subprocess.check_output(
                          ['socat', '-V'], text=True).splitlines()[:3]}), flush=True)
    assert sys.stdin.readline() == '\n', 'host did not verify installed inputs'
    with socket.create_connection(('127.0.0.1', 8080), timeout=10) as existing:
        health(existing)
        before = relays(names)
        for name in names:
            named = {pid: row for pid, row in before.items() if row['comm'] == name}
            assert len(named) >= 2, (name, named)
            assert any(row['ppid'] in named for row in named.values()), (name, named)
        for pid in before:
            os.kill(pid, 0)  # Same root account must be able to signal every relay.
        with tempfile.TemporaryDirectory(prefix='sy-relay-proof-', dir='/run') as scratch:
            for stage in ('ready', 'pkill', 'killall'):
                result = {'stage': stage, 'before': before}
                if stage != 'ready':
                    with subprocess.Popen(['socat', '-u', '-', '/dev/null'], stdin=subprocess.PIPE,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as control:
                        try:
                            for _ in range(100):
                                if Path(f'/proc/{control.pid}/comm').read_text().strip() == 'socat':
                                    break
                                assert control.poll() is None
                                time.sleep(0.01)
                            else:
                                raise AssertionError('ordinary socat never acquired its name')
                            os.kill(control.pid, 0)
                            subprocess.run([stage, 'socat'], check=True, capture_output=True, timeout=5)
                            assert control.wait(timeout=5) == -signal.SIGTERM
                            result.update(command=[stage, 'socat'], control_pid=control.pid,
                                          control_exit=control.returncode)
                        finally:
                            if control.poll() is None:
                                control.terminate()
                                control.wait(timeout=5)
                after = relays(names)
                assert all(after.get(pid) == row for pid, row in before.items()), (before, after)
                result['existing_traffic'] = health(existing)
                with socket.create_connection(('127.0.0.1', 8080), timeout=10) as fresh:
                    result['new_traffic'] = health(fresh)
                probe = subprocess.run(
                    ['/safeyolo/safeyolo-guest', '--stop', f'{scratch}/stop', 'probe', '1' * 32],
                    check=True, capture_output=True, text=True, timeout=10,
                )
                result['diagnostic'] = json.loads(probe.stderr)
                matches = result['diagnostic']['processes']['matches']
                assert set(before) <= {row['pid'] for row in matches}, matches
                print(json.dumps(result), flush=True)
                assert sys.stdin.readline() == '\n', 'host did not confirm a fresh shell'
                health(existing)
    print(json.dumps({'stage': 'passed'}), flush=True)


if __name__ == '__main__':
    main()
