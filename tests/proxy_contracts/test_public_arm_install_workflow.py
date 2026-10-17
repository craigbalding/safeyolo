"""Exercise the maintained public onboarding workflow and its observer.

The real Bash callers and staged Python observer run with controlled transport
and installer exits. Metadata checks retain the read-only archive comparison.
"""

import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest
import yaml

from tests.blackbox import observe_guest_metadata as observer

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.load((REPO / '.github/workflows/installed-arm64.yml').read_text(), Loader=yaml.BaseLoader)
PUBLIC = WORKFLOW['jobs']['public-install']


def step_script(name):
    return next(step['run'] for step in PUBLIC['steps'] if step.get('name') == name)


def run_script(script, env):
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                          env=env, text=True, capture_output=True, timeout=20)


def test_public_mode_selects_one_arm_job_and_keeps_old_mode():
    dispatch = WORKFLOW['on']['workflow_dispatch']['inputs']['mode']
    assert dispatch['default'] == 'draft-offline'
    assert dispatch['options'] == ['draft-offline', 'public-install']
    guest = WORKFLOW['on']['workflow_dispatch']['inputs']['guest']
    assert guest['default'] == 'original-g1'
    assert guest['options'] == ['original-g1', 'reduced-33224']
    section = WORKFLOW['on']['workflow_dispatch']['inputs']['section']
    assert section['default'] == 'default'
    assert section['options'] == ['default', 'lifecycle']
    assert PUBLIC['if'] == "github.event_name == 'workflow_dispatch' && inputs.mode == 'public-install'"
    for name in ('acquire-host', 'installed-arm64'):
        assert WORKFLOW['jobs'][name]['if'] == "github.event_name == 'workflow_dispatch' && inputs.mode == 'draft-offline'"
    assert PUBLIC['runs-on'] == 'ubuntu-24.04-arm'
    assert PUBLIC['permissions'] == {'contents': 'read'}
    assert 'needs' not in PUBLIC and 'strategy' not in PUBLIC
    assert int(PUBLIC['timeout-minutes']) == 30
    assert PUBLIC['steps'][-1]['if'] == 'always()'
    for step in PUBLIC['steps']:
        assert '${{ secrets.' not in json.dumps(step)
        if 'run' in step:
            result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
            assert result.returncode == 0, result.stderr
            assert '${{' not in step['run'], 'Expressions must stay out of Bash program text'
    commands = '\n'.join(step.get('run', '') for step in PUBLIC['steps'])
    for excluded in ('cargo ', 'rustup ', 'oras ', '--platform-assets', 'run-installed', 'safeyolo start'):
        assert excluded not in commands
    assert PUBLIC['steps'][-1]['with']['path'].splitlines() == [
        '${{ env.PUBLIC_INSTALL_REPORTS }}/observation.json', '${{ env.PUBLIC_INSTALL_REPORTS }}/execution.txt',
    ]


@pytest.fixture
def public_shell(tmp_path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    checkout = workspace / 'observer-source'
    checkout.symlink_to(REPO, target_is_directory=True)
    tools = tmp_path / 'tools'
    tools.mkdir()
    env = {**os.environ, **WORKFLOW.get('env', {}), **PUBLIC.get('env', {}),
           'RUNNER_TEMP': str(tmp_path), 'GITHUB_ENV': str(tmp_path / 'github-env'),
           'GITHUB_WORKSPACE': str(workspace), 'GITHUB_SHA': 'a' * 40,
           'PATH': str(tools) + os.pathsep + os.environ['PATH']}
    env.pop('BASH_ENV', None)
    result = run_script(step_script('Select fresh observer and report directories'), env)
    assert result.returncode == 0, result.stderr
    env.update(line.split('=', 1) for line in Path(env['GITHUB_ENV']).read_text().splitlines())
    result = run_script(step_script('Stage only the Python observer outside the checkout'), env)
    assert result.returncode == 0, result.stderr
    checkout.unlink()
    work, reports = Path(env['PUBLIC_INSTALL_WORK']), Path(env['PUBLIC_INSTALL_REPORTS'])
    assert (work / 'observer/ubuntu_onboarding.py').read_bytes() == (REPO / 'tests/blackbox/ubuntu_onboarding.py').read_bytes()
    assert (work / 'observer/harness/process_identity.py').is_file()
    return work, reports, env


@contextmanager
def staged_onboarding(work):
    """Load copied helpers, then restore the caller's import paths and modules."""
    previous_path = sys.path[:]
    previous_modules = {name: module for name, module in sys.modules.copy().items()
                        if name == 'harness' or name.startswith('harness.')}
    try:
        for name in previous_modules:
            del sys.modules[name]
        # The real isolated caller sees only the staged namespace. A checkout
        # package later on sys.path must not replace its copied helper.
        harness_spec = importlib.machinery.PathFinder.find_spec('harness', [str(work / 'observer')])
        sys.modules['harness'] = importlib.util.module_from_spec(harness_spec)
        spec = importlib.util.spec_from_file_location('public_onboarding', work / 'observer/ubuntu_onboarding.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in tuple(sys.modules):
            if name == 'harness' or name.startswith('harness.'):
                del sys.modules[name]
        sys.modules.update(previous_modules)
        sys.path[:] = previous_path


@pytest.fixture
def onboarding(public_shell, tmp_path, monkeypatch):
    work, _reports, env = public_shell
    with staged_onboarding(work) as module:
        home = tmp_path / 'runner-home'
        home.mkdir()
        monkeypatch.setattr(module.Path, 'home', lambda: home)
        # The observer is ARM64-specific; only the host inventory is controlled.
        machine = list(os.uname())
        machine[-1] = 'aarch64'
        monkeypatch.setattr(module.os, 'uname', lambda: os.uname_result(machine))
        for key in list(os.environ):
            if key.startswith('SAFEYOLO_') or key in ('GH_TOKEN', 'GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'):
                monkeypatch.delenv(key)
        for key in ('PATH', 'PUBLIC_INSTALL_WORK'):
            monkeypatch.setenv(key, env[key])
        monkeypatch.setenv('HOME', str(home))
        monkeypatch.setenv('XDG_CACHE_HOME', str(home / '.cache'))
        monkeypatch.setattr(module.sys, 'argv', [module.__file__, '--host', os.uname().nodename,
                            '--platform', 'linux-arm64', '--observation-dir', str(work / 'private'),
                            '--observer-source', env['GITHUB_SHA']])
        # No product starts in these refusal cases. Keep unrelated process scans
        # and guest network probes out of this controlled observer test.
        monkeypatch.setattr(module, 'processes', lambda: [])
        monkeypatch.setattr(module, 'listeners', lambda _owned: [])
        monkeypatch.setattr(module, 'witness', lambda *_args: {})
        tools = Path(env['PATH'].split(os.pathsep)[0])
        for name in ('sudo', 'safeyolo'):
            (tools / name).write_text('#!/bin/sh\nexit 0\n')
            (tools / name).chmod(0o755)
        curl = tools / 'curl'
        curl.write_text('#!/bin/bash\nset -eu\n'
                        'printf "%s\\n" "$@" > "$PUBLIC_INSTALL_WORK/download-args"\n'
                        '[[ ${DOWNLOAD_EXIT:-0} == 0 ]] || exit "$DOWNLOAD_EXIT"\n'
                        'cp "$PUBLIC_INSTALL_WORK/installer" install-safeyolo.sh\n')
        curl.chmod(0o755)
        (work / 'installer').write_text('#!/bin/bash\n'
            'printf "%s\\n" "$@" > "$PUBLIC_INSTALL_WORK/installer-args"\nexit 37\n')
        previous_umask = os.umask(0o022)
        try:
            yield module, home
        finally:
            os.umask(previous_umask)


@pytest.mark.parametrize('preloaded', [False, True])
@pytest.mark.parametrize('failure', [None, 'import', 'body'])
def test_staged_onboarding_restores_checkout_imports(public_shell, preloaded, failure):
    work, _reports, _env = public_shell
    previous_path = sys.path[:]
    previous_modules = {name: module for name, module in sys.modules.copy().items()
                        if name == 'harness' or name.startswith('harness.')}
    try:
        for name in previous_modules:
            del sys.modules[name]
        sys.path.insert(0, str(REPO / 'tests/blackbox'))
        if preloaded:
            importlib.import_module('harness.process_identity')
            importlib.import_module('harness.host_listener')
        expected_path = sys.path[:]
        expected_modules = {name: module for name, module in sys.modules.copy().items()
                            if name == 'harness' or name.startswith('harness.')}
        if failure == 'import':
            observer_path = work / 'observer/ubuntu_onboarding.py'
            observer_path.write_text(observer_path.read_text() + '\nraise RuntimeError("observer import failed")\n')
        with pytest.raises(RuntimeError, match='observer .* failed') if failure else nullcontext():
            with staged_onboarding(work) as module:
                helper = sys.modules['harness.process_identity']
                assert Path(helper.__file__).parent == work / 'observer/harness'
                assert module.child_exited is helper.child_exited
                if failure == 'body':
                    raise RuntimeError('observer body failed')
        assert sys.path == expected_path
        assert {name: module for name, module in sys.modules.copy().items()
                if name == 'harness' or name.startswith('harness.')} == expected_modules
        listener = importlib.import_module('harness.host_listener')
        assert Path(listener.__file__) == REPO / 'tests/blackbox/harness/host_listener.py'
    finally:
        for name in tuple(sys.modules):
            if name == 'harness' or name.startswith('harness.'):
                del sys.modules[name]
        sys.modules.update(previous_modules)
        sys.path[:] = previous_path


@pytest.mark.parametrize('cached', [None, 'empty-store', 'blob', 'tree'])
def test_current_observer_requires_an_uncached_store_and_preserves_existing_inputs(onboarding, public_shell, monkeypatch, cached):
    module, home = onboarding
    work, _reports, _env = public_shell
    store = home / '.local/share/safeyolo/guests'
    retained = store / ('trees/sha256/retained/rootfs-tree' if cached == 'tree' else 'blobs/sha256/retained')
    if cached:
        store.mkdir(parents=True)
    if cached in ('blob', 'tree'):
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(b'owned cached guest fixture')
    # An absent store reaches transport. Existing stores, including empty ones,
    # are refused by the current observer before any product command.
    monkeypatch.setenv('DOWNLOAD_EXIT', '37')
    assert module.main() == (2 if cached else 1)
    record = json.loads((work / 'private/result.json').read_text())
    assert record['baseline']['cache_present'][str(store)] == bool(cached)
    assert (work / 'download-args').exists() == (cached is None)
    assert not (work / 'installer-args').exists()
    if cached:
        assert record['product_commands'] == []
        assert not record.get('owns_product_attempt')
        assert not (home / '239-onboarding-project').exists()
    if cached in ('blob', 'tree'):
        assert retained.read_bytes() == b'owned cached guest fixture'


@pytest.mark.parametrize('fault', ['transport', 'installer'])
def test_current_download_and_installer_refusal_keep_source_binding_and_reached_exits(onboarding, public_shell, monkeypatch, fault):
    module, _home = onboarding
    work, _reports, _env = public_shell
    monkeypatch.setenv('DOWNLOAD_EXIT', '37' if fault == 'transport' else '0')
    assert module.main() == 1
    record = json.loads((work / 'private/result.json').read_text())
    assert record['native_source'] == WORKFLOW['env']['HOST_REVISION'] == module.SOURCE
    assert record['expected_host_package']['sha256'] == WORKFLOW['env']['HOST_SHA256']
    assert record['expected_host_package']['bytes'] == int(WORKFLOW['env']['HOST_BYTES'])
    assert (work / 'download-args').read_text().splitlines() == module.DOWNLOAD[1:]
    assert module.DOWNLOAD[-1] == f'https://raw.githubusercontent.com/craigbalding/safeyolo/{module.BOOTSTRAP}/install.sh'
    download = record['product_commands'][0]
    assert download['exit'] == (37 if fault == 'transport' else 0)
    assert len(record['product_commands']) == (1 if fault == 'transport' else 2)
    if fault == 'installer':
        assert module.LAUNCH == ['bash', 'install-safeyolo.sh', '--release', 'host-' + module.SOURCE,
                                 '--launch', '.', '--name', 'first', '--harness', 'claude', '--launcher', 'tmux-window']
        assert (work / 'installer-args').read_text().splitlines() == module.LAUNCH[2:]
        cold = record['product_commands'][1]
        assert cold['command_exit'] == cold['exit_code'] == 37
        assert cold['console_reaped'] and not cold.get('ordinary_q')
        assert record['warm_not_run']
    assert record['observation_outcome'] == 'partial'


@pytest.mark.parametrize('exit_status', [0, 37])
@pytest.mark.parametrize('cleanup', [False, True])
def test_workflow_callers_remove_tokens_and_preserve_observer_exit_and_private_logs(public_shell, exit_status, cleanup):
    work, reports, env = public_shell
    # Control only the observer process. Execute the workflow's env, timeout,
    # Bash redirections, result copy and exit receipt unchanged.
    python = Path(env['PATH'].split(os.pathsep)[0]) / 'python3'
    python.write_text(f'#!{os.sys.executable}\n'
        'import json, os, pathlib, sys\n'
        'work = pathlib.Path(os.environ["PUBLIC_INSTALL_WORK"])\n'
        'private = work / "private"; private.mkdir(exist_ok=True)\n'
        '(private / "result.json").write_text(json.dumps({"observation_outcome": "partial"}))\n'
        '(work / "called.json").write_text(json.dumps({"args": sys.argv[1:], "cwd": os.getcwd(),\n'
        '    "tokens": [key for key in ("GH_TOKEN", "GITHUB_TOKEN") if key in os.environ],\n'
        '    "path": os.environ["PATH"], "ca": os.environ.get("SSL_CERT_FILE")}))\n'
        'print("private-terminal-sentinel"); print("private-diagnostic-sentinel", file=sys.stderr)\n'
        f'sys.exit({exit_status})\n')
    python.chmod(0o755)
    env.update(GH_TOKEN='synthetic-must-not-pass', GITHUB_TOKEN='synthetic-must-not-pass')
    name = ("Finish only this observer's owned cleanup after failure" if cleanup
            else 'Observe one public bootstrap, first launch and normal repeat')
    result = run_script(step_script(name), env)
    assert result.returncode == exit_status, result.stderr
    called = json.loads((work / 'called.json').read_text())
    assert called['args'] == ['-I', '-B', str(work / 'observer/ubuntu_onboarding.py'),
        '--host', os.uname().nodename, '--platform', 'linux-arm64',
        *(['--cleanup-only'] if cleanup else ['--observer-source', env['GITHUB_SHA']]),
        '--observation-dir', str(work / 'private')]
    assert called['cwd'] == str(work) and called['tokens'] == []
    assert called['path'] == env['PATH'] and called['ca'] == env.get('SSL_CERT_FILE')
    prefix = 'cleanup' if cleanup else 'observer'
    for stream in ('stdout', 'stderr'):
        assert stat.S_IMODE((work / f'{prefix}.{stream}').stat().st_mode) == 0o600
    assert result.stdout == result.stderr == ''
    if not cleanup:
        assert (reports / 'execution.txt').read_text() == f'observer_exit={exit_status}\n'
    result = run_script(step_script('Retain reached nonsecret operands, including partial observations'), env)
    assert result.returncode == 0, result.stderr
    assert json.loads((reports / 'observation.json').read_text()) == {'observation_outcome': 'partial'}
    assert sorted(path.name for path in reports.iterdir()) == (['observation.json'] if cleanup else ['execution.txt', 'observation.json'])


def test_report_step_preserves_missing_result_as_unobserved(public_shell):
    _work, reports, env = public_shell
    result = run_script(step_script('Retain reached nonsecret operands, including partial observations'), env)
    assert result.returncode == 0, result.stderr
    assert not list(reports.iterdir())


@pytest.fixture
def metadata_inputs(tmp_path):
    root = tmp_path / 'instance'
    share = root / 'share'
    share.mkdir(parents=True)
    assets = tmp_path / 'assets'
    tree = assets / 'rootfs-tree'
    (tree / 'usr/bin').mkdir(parents=True)
    (tree / 'cache').mkdir()
    bash = tree / 'usr/bin/bash'
    bash.write_bytes(b'original guest executable fixture\n')
    bash.chmod(0o4755)
    (tree / 'usr/bin/bash-hardlink').hardlink_to(bash)
    (tree / 'bash-link').symlink_to('usr/bin/bash')
    (assets / 'cache-paths.txt').write_text('/cache\n')
    (share / 'cache-paths.txt').write_text('/cache\n')
    (share / 'rootfs-tree').symlink_to(tree)
    actual = observer.observe(root, assets)
    assert actual['installed_rootfs_metadata']['type'] == stat.S_IFLNK
    assert actual['installed_rootfs_metadata']['link'] == str(tree)
    members = {}
    with tarfile.open(tmp_path / 'original.tar', 'w') as tar:
        tar.add(tree, arcname='rootfs-tree')
        tar.add(assets / 'cache-paths.txt', arcname='cache-paths.txt')
    with tarfile.open(tmp_path / 'original.tar') as tar:
        for member in tar:
            members[member.name] = member
    # Controlled ownership inventory exercises the original archive contract;
    # the sandbox cannot supply the hosted numeric-owner witness.
    for name, member in members.items():
        if name.startswith('rootfs-tree'):
            member.uid = member.gid = 100000
    for row in actual['entries']:
        if row['path'].startswith('rootfs-tree'):
            row['uid'] = row['gid'] = 100000
    return root, assets, actual, members


@pytest.mark.parametrize('fault,diagnosis', [
    (None, None), ('mode', 'mode'), ('uid', 'uid'), ('type', 'type'),
    ('missing', 'missing_member'), ('extra', 'extra_member'), ('symlink', 'symlink_target'),
    ('hardlink', 'hardlink_relationship'), ('cache', 'cache_text'),
])
def test_complete_metadata_comparison_detects_material_changes(metadata_inputs, fault, diagnosis):
    _root, _assets, actual, members = metadata_inputs
    actual = copy.deepcopy(actual)
    rows = {row['path']: row for row in actual['entries']}
    bash = rows['rootfs-tree/usr/bin/bash']
    if fault in ('mode', 'uid', 'type'):
        bash[fault] = {'mode': 0o755, 'uid': 0, 'type': stat.S_IFDIR}[fault]
    elif fault == 'missing':
        actual['entries'].remove(bash)
    elif fault == 'extra':
        actual['entries'].append(dict(bash, path='rootfs-tree/unexpected'))
    elif fault == 'symlink':
        rows['rootfs-tree/bash-link']['link'] = 'different'
    elif fault == 'hardlink':
        rows['rootfs-tree/usr/bin/bash-hardlink']['ino'] += 1
    elif fault == 'cache':
        actual['installed_cache'] = '/different\n'
    result = observer.compare(actual, members, '/cache\n')
    assert result['metadata_relationship_pass'] == (fault is None), result
    if diagnosis:
        assert result['metadata_mismatches'][diagnosis] > 0


def test_observer_refuses_installed_tree_that_does_not_reach_acquired_assets(metadata_inputs, tmp_path):
    root, assets, _actual, _members = metadata_inputs
    other = tmp_path / 'other'
    other.mkdir()
    link = root / 'share/rootfs-tree'
    link.unlink()
    link.symlink_to(other)
    with pytest.raises(ValueError, match='acquired tree'):
        observer.observe(root, assets)


@pytest.mark.parametrize('fault', ['ownership', 'archive-bytes'])
def test_observer_command_preserves_actual_binding_and_fails_on_wrong_metadata(metadata_inputs, tmp_path, fault):
    root, assets, _actual, members = metadata_inputs
    archive = tmp_path / 'guest.tar'
    with tarfile.open(archive, 'w') as tar:
        for name, member in members.items():
            data = (assets / name).read_bytes() if member.isreg() else None
            tar.addfile(member, io.BytesIO(data) if data is not None else None)
    compressed = tmp_path / 'guest.tar.zst'
    subprocess.run(['zstd', '-q', str(archive), '-o', str(compressed)], check=True)
    digest = hashlib.sha256(compressed.read_bytes()).hexdigest()
    store = tmp_path / 'store'
    tree = store / 'trees/sha256' / digest
    tree.parent.mkdir(parents=True)
    assets.rename(tree)
    link = root / 'share/rootfs-tree'
    link.unlink()
    link.symlink_to(tree / 'rootfs-tree')
    blob = store / 'blobs/sha256' / digest
    blob.parent.mkdir(parents=True)
    compressed.rename(blob)
    selection = {'assets': str(tree), 'archive': {'digest': 'sha256:' + digest, 'size': blob.stat().st_size}}
    (root / 'share/guest-selection.json').write_text(json.dumps(selection))
    if fault == 'archive-bytes':
        with blob.open('ab') as stream:
            stream.write(b'changed')
    output = tmp_path / 'reports'
    result = subprocess.run([os.sys.executable, str(REPO / 'tests/blackbox/observe_guest_metadata.py'),
                             '--root', str(root), '--store', str(store), '--output', str(output)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    binding = json.loads((output / 'acquired-archive.json').read_text())
    assert binding['selected_descriptor'] == selection['archive']
    if fault == 'archive-bytes':
        assert binding['digest'] != selection['archive']['digest']
        assert not (output / 'metadata-observation.json.gz').exists()
    else:
        assert binding['digest'] == selection['archive']['digest']
        assert (output / 'metadata-observation.json.gz').is_file()
        comparison = json.loads((output / 'metadata-comparison.json').read_text())
        assert comparison['archive_members'] == comparison['installed_entries'] == len(members)
        assert comparison['metadata_mismatches']['uid'] == len(members) - 1
        assert comparison['metadata_relationship_pass'] is False
