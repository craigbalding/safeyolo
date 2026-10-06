"""Exercise native terminals on a prepared Ubuntu/systrap or physical VZ host.

Run as the ordinary account that owns the disposable native --root. Install
matching host and Linux guest assets, prepare the platform boot inputs, and
start the proxy first. --fixture-parent selects existing disk-backed storage.
--commit is the full source ID reported by those installed assets.

The probe creates two agents and observes real terminal input/output, concurrent
launch, reconnect, independent shell, hook results and selected stop. It stops
and cleans both agents, restores the host default launcher, and preserves their
stopped configuration and fixture files. The caller's proxy stays running.
Accepted guest crash supervision is not repeated.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip
from safeyolo.runtime_identity import process_is_alive, process_start_token


def read_terminal(master: int, screen: bytearray, timeout: float = 0.05) -> bool:
    """Keep consuming terminal output through command exit, as a viewer does."""
    if not select.select([master], [], [], timeout)[0]:
        return False
    try:
        chunk = os.read(master, 65536)
    except OSError as exc:
        if exc.errno == errno.EIO:  # Linux reports PTY EOF this way.
            return False
        raise
    screen.extend(chunk)
    return bool(chunk)


def wait_terminal_exit(process: subprocess.Popen, master: int, screen: bytearray, timeout: float = 30) -> int:
    """A wait without reads can block macOS SSH's final TCSADRAIN restore."""
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        read_terminal(master, screen)
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
    while read_terminal(master, screen, timeout=0):
        pass
    return process.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--fixture-parent', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    parent = args.fixture_parent.resolve(strict=True)
    if len(args.commit) not in (40, 64) or any(character not in '0123456789abcdef' for character in args.commit):
        parser.error('--commit requires a full Git object ID')
    if not shutil.which('tmux'):
        parser.error('install tmux on the selected host before running this probe')
    asset_identities = {}
    selected_identity = None
    for relative in ('bin/safeyolo', 'bin/safeyolo-proxy', 'bin/safeyolo-coord',
                     'assets/guest/safeyolo-guest', 'assets/guest/safeyolo-coord'):
        executable = root / relative
        # The installer verifies Linux guest bytes; they cannot run on macOS.
        if relative.startswith('assets/') and sys.platform == 'darwin':
            version = executable.with_suffix('.version').read_text().strip()
        else:
            version = subprocess.check_output([str(executable), '--version'], text=True, timeout=5).strip()
        assert version.split()[0] == executable.name, f'wrong executable: {relative}: {version}'
        assert f'commit={args.commit} profile=' in version, f'wrong installed source: {relative}: {version}'
        identity = version.partition(' commit=')[2]
        if selected_identity is None:
            selected_identity = identity
        assert identity == selected_identity, f'installed source/profile differs: {relative}: {version}; selected {selected_identity}'
        asset_identities[relative] = version
    command = [str(root / 'bin/safeyolo'), '--root', str(root)]

    def cli(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=140, check=False)
        if check:
            assert result.returncode == 0, f'{arguments}: exit {result.returncode}: {result.stderr[-1200:]}'
        return result

    assert json.loads(cli('status').stdout)['proxy_state'] == 'running', 'start the selected proxy before this probe'
    fixture = Path(tempfile.mkdtemp(prefix='native-terminal-', dir=parent))
    workspace, peer_workspace = fixture / 'workspace', fixture / 'peer-workspace'
    workspace.mkdir()
    peer_workspace.mkdir()
    name = 'terminal-' + uuid.uuid4().hex[:8]
    peer = name + '-peer'
    hooks, script = fixture / 'hooks', fixture / 'launcher.sh'
    script.write_text('''#!/bin/sh
set -eu
case "$1" in
    pre_launch|post_launch) printf '%s %s\\n' "$SAFEYOLO_LAUNCH_ID" "$1" >> "$(dirname "$0")/hooks" ;;
    on_exit) printf '%s on_exit %s\\n' "$SAFEYOLO_LAUNCH_ID" "$SAFEYOLO_AGENT_EXIT_CODE" >> "$(dirname "$0")/hooks"; exit 42 ;;
    *) exec "$SAFEYOLO_LAUNCHER_PRESETS/tmux-window.sh" "$@" ;;
esac
''')
    script.chmod(0o755)
    marker_command = '''test -t 0 && test -t 1 && test -t 2 || exit 91
printf '%s\\n' "$$" >> /workspace/starts
printf 'TTY ready\\n'
while IFS= read -r line; do
    printf '%s\\n' "$line" >> /workspace/input
    printf 'received:%s\\n' "$line"
    if [ "$line" = quit ]; then exit 7; fi
    if [ "$line" = quit0 ]; then exit 0; fi
done
'''
    config = root / 'config.toml'
    initial_settings = load_roundtrip(config)
    had_launcher_table = 'agent_launcher' in initial_settings
    initial_launcher = initial_settings.get('agent_launcher', {}).get('default')

    def host_launcher(value: str | None) -> None:
        document = load_roundtrip(config)
        if value is None:
            document.get('agent_launcher', {}).pop('default', None)
            if not had_launcher_table and not document.get('agent_launcher'):
                document.pop('agent_launcher', None)
        else:
            if 'agent_launcher' not in document:
                document['agent_launcher'] = {}
            document['agent_launcher']['default'] = value
        # Retain native listener changes instead of restoring a stale whole file.
        save_roundtrip(config, document)

    def until(predicate, description: str):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if value := predicate():
                return value
            time.sleep(0.05)
        raise AssertionError(f'timed out: {description}; fixture={fixture}')

    def status(selected: str = name) -> dict:
        return json.loads(cli('agent', 'status', selected).stdout)

    def launch() -> dict:
        return json.loads((root / 'agents' / name / 'current-launch.json').read_text())

    def active(selected: str = name):
        observed = status(selected)
        return observed if observed['agent_state'] == 'running' else None

    def tmux(record: dict, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(['tmux', '-S', record['tmux_socket'], *arguments],
                              capture_output=True, text=True, timeout=5, check=True)

    viewer_env = {**os.environ, 'TERM': 'xterm-256color'}
    viewer_env.pop('TMUX', None)
    viewer_env.pop('TMUX_PANE', None)

    def exercise_viewer(original: dict, record: dict, marker: str, *, detach: bool) -> None:
        master, slave = pty.openpty()
        viewer = subprocess.Popen([*command, 'agent', 'attach', name], stdin=slave,
                                  stdout=slave, stderr=slave, env=viewer_env, start_new_session=True)
        os.close(slave)
        screen = bytearray()
        try:
            def see(value: bytes):
                read_terminal(master, screen)
                return value in screen

            until(lambda: see(b'TTY ready'), 'attached viewer screen')
            os.write(master, (marker + '\n').encode())
            until(lambda: see(('received:' + marker).encode()), 'real viewer output')
            assert marker in (workspace / 'input').read_text(), 'guest did not receive viewer input'
            if detach:
                os.write(master, b'\x02d')
                assert wait_terminal_exit(viewer, master, screen, timeout=10) == 0
        finally:
            os.close(master)
            if viewer.poll() is None:
                os.killpg(viewer.pid, signal.SIGHUP)
            viewer.wait(timeout=10)
        current = until(active, 'coding agent after viewer loss')
        for key in ('agent_id', 'run_id', 'launch_id'):
            assert current[key] == original[key], (key, original, current)
        current_launch = launch()
        for key in ('pid', 'process_token', 'runner_pid', 'runner_token', 'pane_id', 'tmux_socket'):
            assert current_launch[key] == record[key], (key, record, current_launch)
        assert process_start_token(record['pid']) == record['process_token'], 'original command transport exited'
        assert (workspace / 'starts').read_text().splitlines() == [guest_pid], 'viewer loss replaced the guest command'

    created = []
    print(f'root={root} agent={name} peer={peer} fixture={fixture} commit={args.commit}', flush=True)
    try:
        for selected, folder in ((name, workspace), (peer, peer_workspace)):
            cli('agent', 'create', selected, '--workspace', str(folder), '--memory', '640', '--command', marker_command)
            created.append(selected)
        cli('agent', 'configure', peer, '--launcher', 'tmux-window')
        cli('agent', 'start', name, '--sandbox-only')
        sandbox = status()
        assert sandbox['runtime_state'] == 'running' and sandbox['control_state'] == 'ready', sandbox
        assert sandbox['agent_state'] == 'stopped' and sandbox['terminal_state'] == 'absent', sandbox
        assert not (workspace / 'starts').exists(), 'sandbox-only launched the coding command'
        absent = cli('agent', 'attach', name, check=False)
        assert absent.returncode != 0 and 'terminal' in absent.stderr.lower(), absent
        assert status()['run_id'] == sandbox['run_id'], 'absent attach started a new runtime'
        guest_identity = cli('agent', 'shell', name, '-c', '/safeyolo/safeyolo-guest --version').stdout.strip()
        assert guest_identity == asset_identities['assets/guest/safeyolo-guest'], f'booted guest identity differs: {guest_identity}'
        host_launcher(str(script))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            list(workers.map(lambda selected: cli('agent', 'start', selected), (name, peer)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            list(workers.map(lambda _: cli('agent', 'start', name), range(2)))
        original = until(active, 'native coding command')
        peer_original = until(lambda: active(peer), 'independent peer command')
        assert original['run_id'] == sandbox['run_id']
        assert original['launcher']['source'] == 'host default', original
        assert original['run_id'] != peer_original['run_id']
        assert original['launch_id'] != peer_original['launch_id']
        record = launch()
        original_runtime = json.loads((root / 'agents' / name / 'runtime.json').read_text())
        peer_runtime = json.loads((root / 'agents' / peer / 'runtime.json').read_text())
        peer_record = json.loads((root / 'agents' / peer / 'current-launch.json').read_text())
        actual_socket = tmux(record, 'display-message', '-p', '-t', record['pane_id'], '#{socket_path}').stdout.strip()
        assert record['tmux_socket'] == actual_socket
        until(lambda: (workspace / 'starts').exists(), 'guest command startup')
        assert len((workspace / 'starts').read_text().splitlines()) == 1, 'concurrent start duplicated the command'
        guest_pid = (workspace / 'starts').read_text().strip()
        until(lambda: hooks.exists() and len(hooks.read_text().splitlines()) == 2, 'launch hooks')
        next_launcher = 'tmux-pane' if sys.platform == 'linux' else 'tmux-window'
        host_launcher(next_launcher)
        exercise_viewer(original, record, 'detached-viewer', detach=True)
        exercise_viewer(original, record, 'lost-viewer', detach=False)
        exercise_viewer(original, record, 'reopened-viewer', detach=True)
        assert launch()['launcher'] == record['launcher'], 'default change redirected attach'
        assert len(hooks.read_text().splitlines()) == 2, 'reuse/attach repeated hooks'
        assert cli('agent', 'shell', name, '-c', 'printf INDEPENDENT_SHELL').stdout == 'INDEPENDENT_SHELL'
        assert status()['launch_id'] == original['launch_id'], 'independent shell replaced the command'
        tmux(record, 'send-keys', '-t', record['pane_id'], '-l', 'quit')
        tmux(record, 'send-keys', '-t', record['pane_id'], 'Enter')

        def exited():
            value = status()
            return value if value['agent_state'] == 'exited' else None

        ended = until(exited, 'actual command exit')
        assert ended['runtime_state'] == 'running' and ended['control_state'] == 'ready', ended
        assert ended['terminal_state'] == 'absent' and ended['exit_code'] == 7, ended
        assert ended['hook_errors'][-1]['hook'] == 'on_exit' and ended['hook_errors'][-1]['exit_code'] == 42, ended
        assert hooks.read_text().splitlines() == [
            f"{original['launch_id']} pre_launch", f"{original['launch_id']} post_launch", f"{original['launch_id']} on_exit 7",
        ]
        cli('agent', 'start', name)
        restarted = until(active, 'new command in the same sandbox')
        assert restarted['run_id'] == original['run_id'] and restarted['launch_id'] != original['launch_id']
        assert restarted['launcher']['kind'] == next_launcher, restarted
        restarted_record = launch()
        cli('agent', 'stop', name)
        until(lambda: status()['runtime_state'] == 'stopped', 'selected sandbox stop')
        absent = cli('agent', 'attach', name, check=False)
        assert absent.returncode != 0 and 'absent' in absent.stderr.lower(), absent
        stopped = status()
        assert stopped['runtime_state'] == 'stopped' and stopped['run_id'] == original['run_id'], stopped
        current_peer = until(lambda: active(peer), 'peer after selected stop')
        for key in ('agent_id', 'run_id', 'launch_id', 'proxy_attachment'):
            assert current_peer[key] == peer_original[key], (key, current_peer, peer_original)
        assert cli('agent', 'shell', peer, '-c', 'printf PEER_AFTER_STOP').stdout == 'PEER_AFTER_STOP'
        before = tmux(record, 'list-panes', '-a', '-F', '#{pane_id}').stdout
        master, slave = pty.openpty()
        foreground = subprocess.Popen([*command, 'agent', 'start', name, '--foreground'],
                                      stdin=slave, stdout=slave, stderr=slave, env=viewer_env, start_new_session=True)
        os.close(slave)
        screen = bytearray()
        try:
            def foreground_ready():
                read_terminal(master, screen)
                return b'TTY ready' in screen

            until(foreground_ready, 'foreground terminal input/output')
            assert launch()['launcher']['kind'] == 'foreground'
            os.write(master, b'foreground-input\nquit0\n')
            assert wait_terminal_exit(foreground, master, screen) == 0, bytes(screen)[-1200:]
            assert b'received:foreground-input' in screen and b'received:quit0' in screen
        finally:
            os.close(master)
            if foreground.poll() is None:
                os.killpg(foreground.pid, signal.SIGHUP)
                foreground.wait(timeout=10)
        after = tmux(record, 'list-panes', '-a', '-F', '#{pane_id}').stdout
        assert before == after, 'foreground operation created a tmux pane'
        foreground_result = status()
        assert foreground_result['agent_id'] == original['agent_id'] and foreground_result['run_id'] != original['run_id']
        assert foreground_result['runtime_state'] == 'running' and foreground_result['exit_code'] == 0, foreground_result
        report = {'native_terminal_probe': 'passed', 'commit': args.commit, 'root': str(root),
                  'asset_identities': asset_identities, 'booted_guest_identity': guest_identity,
                  'agent': original, 'peer': peer_original, 'command_exit': ended,
                  'foreground': foreground_result}
        final_runtime = json.loads((root / 'agents' / name / 'runtime.json').read_text())
        owned_processes = []
        for runtime in (original_runtime, final_runtime, peer_runtime):
            assert runtime['backend_pid'] > 1 and runtime['backend_token'], runtime
            for prefix in ('backend', 'holder'):
                if runtime.get(f'{prefix}_pid') is not None:
                    owned_processes.append((runtime[f'{prefix}_pid'], runtime[f'{prefix}_token']))
        for current_launch in (record, restarted_record, peer_record, launch()):
            for pid_key, token_key in (('pid', 'process_token'), ('runner_pid', 'runner_token')):
                owned_processes.append((current_launch[pid_key], current_launch[token_key]))
    finally:
        cleanup_errors = []
        for selected in created:
            try:
                cli('agent', 'stop', selected)
                until(lambda: status(selected)['agent_state'] != 'finishing', f'{selected} exit hooks')
                cli('agent', 'cleanup', selected)
            except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
                # Still attempt the other owned agent and restore the setting.
                cleanup_errors.append(f'{selected}: {error}')
        host_launcher(initial_launcher)
        assert not cleanup_errors, 'owned cleanup failed: ' + '; '.join(cleanup_errors)
        for selected in created:
            observed = status(selected)
            assert observed['runtime_state'] == 'stopped' and observed['run_id'] is None, observed
        print('owned agents stopped/cleaned; host default restored; proxy left running', flush=True)
    for pid, token in owned_processes:
        assert not (process_is_alive(pid) and process_start_token(pid) == token), f'owned process still live: {pid}'
    for observed in (original, peer_original, foreground_result):
        socket_path = Path(observed['proxy_attachment']['socket'])
        assert not socket_path.exists(), f'owned agent proxy socket remains: {socket_path}'
    report['owned_processes_stopped'] = [pid for pid, _ in owned_processes]
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
