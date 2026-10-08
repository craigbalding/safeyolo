"""Finite R5 shell preparation and external execution-detector controls."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.blackbox.check_python_execution import inspect_trace

REPO = Path(__file__).resolve().parents[1]
CHECKER = REPO / "tests/blackbox/check_python_execution.py"
JOURNEY = REPO / "tests/blackbox/native-python-journey.sh"


def check(tmp_path, lines):
    trace = tmp_path / "exec.log"
    trace.write_text(lines + '\n10 +++ exited with 0 +++\n')
    result = subprocess.run([sys.executable, str(CHECKER), str(trace),
                             "--filesystem-root", str(tmp_path)], capture_output=True, text=True)
    return result.returncode, json.loads(result.stdout)


@pytest.mark.parametrize("call", [
    'execve("/usr/bin/python3", ["arbitrary-name"], 0xabc) = -1 ENOENT',
    'execve("/home/agent/.venv/bin/python3.12", ["python3.12"], 0xabc) = 0',
    'execve("/usr/bin/python3.13t", ["literal-argv"], 0xabc) = 0',
    'execve("/usr/bin/python3.13t", ["literal-argv"], 0xabc) = -1 ENOENT',
    'execveat(AT_FDCWD, "/usr/local/bin/pypy3", ["pypy3"], 0xabc, 0) = 0',
    'execve("/bin/sh", ["sh", "-c", "exec /usr/bin/python3 -c pass"], 0xabc) = 0\n'
    '10 execve("/usr/bin/python3", ["python3", "-c", "pass"], 0xabc) = -1 ENOENT',
])
def test_detector_reports_direct_absolute_and_shell_python(tmp_path, call):
    code, result = check(tmp_path, '10 ' + call)
    assert code == 1 and result["complete"]
    assert len(result["python_attempts"]) == 1


@pytest.mark.parametrize("shebang", ['#!/usr/bin/env python3', '#!/usr/bin/python3.13t'])
def test_detector_uses_retained_shebang_without_trusting_argv(tmp_path, shebang):
    script = tmp_path / "workload"
    script.write_text(shebang + '\npass\n')
    code, result = check(tmp_path, '10 execve("/workload", ["/bin/true"], 0xabc) = -1 ENOENT')
    assert code == 1 and result["python_attempts"][0]["reason"] == "Python shebang"
    trace = tmp_path / 'exec.log'
    names_only = inspect_trace(trace, None)
    assert not names_only['shebang_lookup'] and not names_only['python_attempts']
    code, result = check(tmp_path, '10 execve("/bin/true", ["python3"], 0xabc) = 0')
    assert code == 0 and not result["python_attempts"]


@pytest.mark.parametrize("root_is_file", [False, True])
def test_detector_refuses_invalid_filesystem_root(tmp_path, root_is_file):
    (tmp_path / 'script').write_text('#!/usr/bin/python3\npass\n')
    code, result = check(tmp_path, '10 execve("/script", ["/script"], 0xabc) = 0')
    assert code == 1 and result['python_attempts'][0]['reason'] == 'Python shebang'
    filesystem = tmp_path / 'invalid-root'
    if root_is_file:
        filesystem.write_text('not a directory\n')
    result = subprocess.run([sys.executable, str(CHECKER), str(tmp_path / 'exec.log'),
                             '--filesystem-root', str(filesystem)], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'Execution observation unavailable' in result.stdout and 'filesystem root' in result.stdout


@pytest.mark.parametrize("line", [
    '',
    '10 execve(0xffffffffffffffda, ["/bin/true"], 0xabc) = 0',
    '10 execve("/usr/bin/py"..., ["/bin/true"], 0xabc) = 0',
    '10 execveat(3, "", ["/bin/true"], 0xabc, AT_EMPTY_PATH) = 0',
    '10 execve("/bin/true", ["true"], 0xabc <unfinished ...>',
    '10 execve("/bin/true", ["true"],',
    '11 execve("/bin/sleep", ["sleep", "60"], 0xabc) = 0',
])
def test_incomplete_observation_cannot_claim_absence(tmp_path, line):
    code, result = check(tmp_path, line)
    assert code == 2 and not result["complete"]


def test_resumed_exec_and_missing_trace(tmp_path):
    code, result = check(tmp_path,
        '10 execve("/bin/true", ["true"], 0xabc <unfinished ...>\n'
        '10 <... execve resumed>) = 0')
    assert code == 0 and result["exec_attempts"] == 1
    result = subprocess.run([sys.executable, str(CHECKER), str(tmp_path / 'absent')],
                            capture_output=True, text=True)
    assert result.returncode == 2 and 'unavailable' in result.stdout


def test_real_tracer_control_never_reports_python_clean(tmp_path):
    tracer = shutil.which('strace')
    if not tracer:
        pytest.skip('real execution observation requires strace')
    trace = tmp_path / 'real.exec'
    fixture = REPO / 'tests/blackbox/attempt-python.sh'
    result = subprocess.run([tracer, '-f', '-s', '4096', '-e', 'trace=execve,execveat',
                             '-o', str(trace), str(fixture)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 97, result.stderr
    observation = inspect_trace(trace, Path('/'))
    if observation['complete']:
        assert len(observation['python_attempts']) >= 3
    else:
        assert observation['incomplete_lines']  # e.g. nested ARM64 gVisor ptrace output.
    refused = subprocess.run([sys.executable, str(CHECKER), str(trace)], capture_output=True, text=True)
    assert refused.returncode in (1, 2)
    negative = tmp_path / 'negative.exec'
    subprocess.run([tracer, '-f', '-s', '4096', '-e', 'trace=execve,execveat',
                    '-o', str(negative), '/bin/true'], check=True, capture_output=True, timeout=15)
    observation = inspect_trace(negative, Path('/'))
    refused = subprocess.run([sys.executable, str(CHECKER), str(negative)], capture_output=True, text=True)
    assert refused.returncode == (0 if observation['complete'] else 2)


@pytest.fixture
def controlled_journey(tmp_path, monkeypatch):
    """Controlled shell outputs prove refusal/cleanup, not installed product execution."""
    bundle, assets, tools = (tmp_path / name for name in ('bundle', 'assets', 'tools'))
    bundle.mkdir()
    (assets / 'rootfs-tree').mkdir(parents=True)
    tools.mkdir()
    for name in ('strace', 'runsc', 'newuidmap', 'newgidmap', 'setfacl', 'unshare', 'curl'):
        path = tools / name
        path.write_text('#!/bin/sh\nexit 0\n')
        path.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.environ['PATH'])
    monkeypatch.delenv('SAFEYOLO_COORD_NATS_BINARY', raising=False)
    cli = bundle / 'cli'
    cli.write_text('''#!/bin/bash
set -eu
if [[ $1 == --version ]]; then echo "safeyolo commit=ffffffffffffffffffffffffffffffffffffffff profile=debug"; exit; fi
root=$2; shift 2
printf '%s %s\\n' "$root" "$*" >> "$CALLS"
case "$*" in
  'agent create '*) mkdir -p "$root/agents/r5check";;
  start) echo '{"pid":123,"token":"controlled"}' > "$root/data/proxy-process.json"; touch "$root/running";;
  'approvals list --json') test -f "$root/running"; echo '[]';;
  'agent start '*) mkdir -p "$root/agents/r5check/home"; if [[ ${PRODUCT_EXIT:-42} != 0 ]]; then exit "$PRODUCT_EXIT"; fi; touch "$root/agents/r5check/running";;
  'agent shell '*)
    printf '%s\\n' "$5" >> "$SHELL_CALLS"
    if [[ $5 == *r5-control.exec* ]]; then
      echo 'fixture control trace' > "$root/agents/r5check/home/r5-control.exec"; exit 127
    fi
    echo 'fixture selected trace' > "$root/agents/r5check/home/r5-guest.exec"
    printf 'safeyolo-guest commit=ffffffffffffffffffffffffffffffffffffffff profile=debug\\nsafeyolo-coord commit=ffffffffffffffffffffffffffffffffffffffff profile=debug\\n{"agent_api": "ok"}\\n'
    ;;
  'agent stop '*) rm -f "$root/agents/r5check/running";;
  stop) rm -f "$root/running"; if [[ $root == */instance && ${FAIL_CLEANUP:-0} == 1 ]]; then exit 43; fi;;
  status|doctor) if [[ -f $root/running ]]; then echo '{"proxy_state": "running"}'; else echo '{"proxy_state": "unavailable"}'; fi;;
  'agent status '*) if [[ -f $root/agents/r5check/running ]]; then echo '{"runtime_state":"running"}'; else echo '{"runtime_state":"stopped"}'; fi;;
  *) echo 'unexpected fixture command' >&2; exit 2;;
esac
''')
    cli.chmod(0o755)
    installer = bundle / 'install.sh'
    installer.write_text('''#!/bin/bash
set -eu
root=$2
mkdir -p "$root/bin" "$root/data"
cp "$(dirname "$0")/cli" "$root/bin/safeyolo"
echo 'admin_port = 9090' > "$root/config.toml"
echo '# independent policy' > "$root/policy.toml"
''')
    installer.chmod(0o755)
    monkeypatch.setenv('CALLS', str(tmp_path / 'calls'))
    monkeypatch.setenv('SHELL_CALLS', str(tmp_path / 'shell-calls'))
    monkeypatch.setenv('PRODUCT_EXIT', '42')
    return [str(JOURNEY), str(bundle), str(assets), str(tmp_path / 'state'), 'f' * 40]


@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_journey_keeps_original_failure_and_stops_owned_state(controlled_journey, monkeypatch, cleanup_fails):
    monkeypatch.setenv('FAIL_CLEANUP', str(int(cleanup_fails)))
    result = subprocess.run(controlled_journey, capture_output=True, text=True)
    state = Path(controlled_journey[3])
    assert result.returncode == 42, result.stderr
    assert (state / 'cleanup.txt').read_text() == f'original_exit=42 cleanup_failed={int(cleanup_fails)}\n'
    assert '"running"' in (state / 'peer-after.json').read_text()
    assert not (state / 'peer/running').exists() and not (state / 'instance/running').exists()
    assert (state / 'peer-policy.toml').read_bytes() == (state / 'peer/policy.toml').read_bytes()


def test_journey_refuses_existing_state_before_mutation(controlled_journey):
    state = Path(controlled_journey[3])
    state.mkdir()
    marker = state / 'operator-data'
    marker.write_text('retain')
    result = subprocess.run(controlled_journey, capture_output=True, text=True)
    assert result.returncode == 2 and marker.read_text() == 'retain'
    assert list(state.iterdir()) == [marker]


@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_journey_reaches_native_guest_shell_and_cleanup_outcome(controlled_journey, monkeypatch, cleanup_fails):
    monkeypatch.setenv('PRODUCT_EXIT', '0')
    monkeypatch.setenv('FAIL_CLEANUP', str(int(cleanup_fails)))
    result = subprocess.run(controlled_journey, capture_output=True, text=True)
    state = Path(controlled_journey[3])
    assert result.returncode == (2 if cleanup_fails else 0), result.stderr
    assert (state / 'cleanup.txt').read_text() == f'original_exit=0 cleanup_failed={int(cleanup_fails)}\n'
    shell_calls = (state.parent / 'shell-calls').read_text()
    assert '/usr/bin/env python3 -c "pass"' in shell_calls
    assert '/safeyolo/safeyolo-guest --version' in shell_calls
    assert '/safeyolo/safeyolo-coord --version' in shell_calls
    assert 'curl --fail --silent --show-error --header @-' in shell_calls
    for command in shell_calls.split('exec strace')[1:]:
        syntax = subprocess.run(['bash', '-n', '-c', 'exec strace' + command], capture_output=True, text=True)
        assert syntax.returncode == 0, syntax.stderr
