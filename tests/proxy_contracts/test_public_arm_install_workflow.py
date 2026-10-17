"""Exercise the manual public-install shell path without hosted execution.

Release transport and installer exits are controlled. The workflow's Bash,
receipts and read-only filesystem observer run directly.
"""

import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
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


@pytest.fixture
def public_shell(tmp_path, linux_workflow_stat):
    work = tmp_path / 'public-install'
    reports = work / 'reports'
    reports.mkdir(parents=True)
    (work / 'bundle').mkdir()
    transport = tmp_path / 'transport'
    transport.mkdir()
    command_dir = tmp_path / 'tools'
    command_dir.mkdir()
    (command_dir / 'stat').symlink_to(linux_workflow_stat)
    curl = command_dir / 'curl'
    curl.write_text('#!/bin/bash\nset -eu\nif [[ ${@: -1} == https://api.github.com/* ]]; then\n'
                    'cat "$TRANSPORT/release.json"\nelse\ncat "$TRANSPORT/host.tar.gz"\nfi\n')
    curl.chmod(0o755)
    # Execute the unchanged Python/Bash programs with an isolated Path.home().
    # The test process and child installer retain their actual HOME environment.
    python = command_dir / 'python3'
    python.write_text(f'#!{os.sys.executable}\n'
                      'import os, pathlib, sys\nfrom unittest.mock import patch\n'
                      'with patch.object(pathlib.Path, "home", return_value=pathlib.Path(os.environ["TEST_RUNNER_HOME"])):\n'
                      '    exec(compile(sys.stdin.read(), "<workflow-python>", "exec"))\n')
    python.chmod(0o755)
    source = WORKFLOW['env']['HOST_REVISION']
    fields = f'source_commit={source}\nprofile=production\nplatform=linux-arm64\n'
    fields += 'guest_compatibility=v1\nguest_repository=ghcr.io/craigbalding/safeyolo-guest\nguest_discovery_tag=compat-v1\n'
    with tarfile.open(transport / 'host.tar.gz', 'w:gz') as tar:
        data = fields.encode()
        member = tarfile.TarInfo('safeyolo-linux-arm64-production/package-info')
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    archive = transport / 'host.tar.gz'
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    env = {**os.environ, **WORKFLOW['env'], **PUBLIC['env'],
           'PUBLIC_INSTALL_WORK': str(work), 'PUBLIC_INSTALL_REPORTS': str(reports),
           'TEST_RUNNER_HOME': str(tmp_path / 'runner-home'),
           'TRANSPORT': str(transport), 'PATH': str(command_dir) + os.pathsep + os.environ['PATH'],
           'HOST_SHA256': digest, 'HOST_BYTES': str(archive.stat().st_size)}
    release = {'id': int(env['HOST_RELEASE_ID']), 'draft': False, 'prerelease': False,
                   'tag_name': 'host-' + source, 'target_commitish': source, 'assets': [{
                       'id': int(env['HOST_ARCHIVE_ASSET_ID']), 'name': 'safeyolo-linux-arm64-production.tar.gz',
                       'state': 'uploaded', 'digest': 'sha256:' + digest, 'size': archive.stat().st_size,
                       'browser_download_url': f'https://github.com/craigbalding/safeyolo/releases/download/host-{source}/safeyolo-linux-arm64-production.tar.gz'}]}
    (transport / 'release.json').write_text(json.dumps(release))
    return work, reports, transport, release, env


@pytest.mark.parametrize('cached', [None, 'empty-store', 'blob', 'tree'])
def test_before_state_requires_uncached_original_guest_and_preserves_existing_inputs(public_shell, cached):
    work, reports, _transport, _release, env = public_shell
    store = Path(env['TEST_RUNNER_HOME']) / '.local/share/safeyolo/guests'
    blob = store / 'blobs/sha256' / env['GUEST_ARCHIVE_SHA256']
    tree = store / 'trees/sha256' / env['GUEST_ARCHIVE_SHA256']
    if cached:
        store.mkdir(parents=True)
    if cached == 'blob':
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b'owned cached archive fixture')
    elif cached == 'tree':
        tree.mkdir(parents=True)
        (tree / 'retained').write_bytes(b'owned prepared tree fixture')
    result = run_script(step_script('Record original guest store before installation'), env)
    ready = cached in (None, 'empty-store')
    assert (result.returncode == 0) == ready, result.stderr
    before = json.loads((reports / 'guest-store-before.json').read_text())
    assert before['fixture_ready'] == ready
    assert before['installer_invoked'] is False
    assert before['store'] == {'path': str(store), 'exists': cached is not None}
    assert before['original_blob'] == {'path': str(blob), 'exists': cached == 'blob'}
    assert before['original_tree'] == {'path': str(tree), 'exists': cached == 'tree'}
    assert not (work / 'instance').exists()
    if cached == 'blob':
        assert blob.read_bytes() == b'owned cached archive fixture'
    elif cached == 'tree':
        assert (tree / 'retained').read_bytes() == b'owned prepared tree fixture'


@pytest.mark.parametrize('fault', [None, 'draft', 'source', 'bytes', 'digest'])
def test_public_host_binding_runs_real_shell_and_refuses_changed_inputs(public_shell, fault):
    work, reports, transport, release, env = public_shell
    if fault == 'draft':
        release['draft'] = True
    elif fault == 'source':
        release['target_commitish'] = '0' * 40
    elif fault == 'bytes':
        with (transport / 'host.tar.gz').open('ab') as stream:
            stream.write(b'changed')
    elif fault == 'digest':
        archive = transport / 'host.tar.gz'
        data = bytearray(archive.read_bytes())
        data[20] ^= 1
        archive.write_bytes(data)
    (transport / 'release.json').write_text(json.dumps(release))
    result = run_script(step_script('Download and bind the unchanged public host'), env)
    assert (result.returncode == 0) == (fault is None), result.stderr
    assert (reports / 'release.json').exists()
    assert (reports / 'host-input.json').exists() == (fault is None)
    assert (work / 'bundle/safeyolo-linux-arm64-production/package-info').exists() == (fault is None)


@pytest.mark.parametrize('fault', [None, 'platform', 'index', 'manifest', 'archive-size'])
def test_actual_selection_binding_refuses_wrong_platform_or_guest_before_observation(public_shell, fault):
    _work, reports, _transport, _release, env = public_shell
    selection = {'repository': 'ghcr.io/craigbalding/safeyolo-guest', 'platform': 'linux/arm64',
                 'version': env['GUEST_VERSION'], 'compatibility': env['GUEST_COMPATIBILITY'],
                 'index': {'digest': env['GUEST_INDEX']}, 'manifest': {'digest': env['GUEST_MANIFEST']},
                 'archive': {'digest': 'sha256:' + env['GUEST_ARCHIVE_SHA256'], 'size': int(env['GUEST_ARCHIVE_BYTES'])}}
    if fault == 'platform':
        selection['platform'] = 'darwin/arm64'
    elif fault in ('index', 'manifest'):
        selection[fault]['digest'] = 'sha256:' + '0' * 64
    elif fault == 'archive-size':
        selection['archive']['size'] += 1
    (reports / 'guest-selection.json').write_text(json.dumps(selection))
    # Only the final observer command is controlled here; Bash and jq run unchanged.
    sudo = Path(env['PATH'].split(os.pathsep)[0]) / 'sudo'
    sudo.write_text('#!/bin/bash\ntouch "$PUBLIC_INSTALL_REPORTS/observer-called"\n')
    sudo.chmod(0o755)
    result = run_script(step_script('Bind actual public acquisition and observe all installed metadata'), env)
    assert (result.returncode == 0) == (fault is None), result.stderr
    assert (reports / 'observer-called').exists() == (fault is None)


@pytest.mark.parametrize('installer_exit', [0, 37])
def test_installer_exit_and_timing_receipt_survive_without_credentials(public_shell, installer_exit):
    work, reports, _transport, _release, env = public_shell
    bundle = work / 'bundle/safeyolo-linux-arm64-production'
    bundle.mkdir()
    installer = bundle / 'install.sh'
    installer.write_text('#!/bin/bash\nset -eu\n'
                         '[[ -z ${GH_TOKEN+x} && -z ${GITHUB_TOKEN+x} ]] || exit 99\n'
                         '[[ $(umask) == 0022 ]] || exit 98\n'
                         '[[ $(stat -c %a "$PUBLIC_INSTALL_WORK/install.stdout") == 600 ]] || exit 98\n'
                         '[[ $(stat -c %a "$PUBLIC_INSTALL_WORK/install.stderr") == 600 ]] || exit 98\n'
                         'echo installer-output\necho installer-diagnostic >&2\n'
                         'echo "GET https://example.test/blob?sig=synthetic-private-token" >&2\n'
                         'echo "Authorization: Bearer synthetic-private-token" >&2\n'
                         f'exit {installer_exit}\n')
    installer.chmod(0o755)
    env.update(GH_TOKEN='synthetic-must-not-pass', GITHUB_TOKEN='synthetic-must-not-pass')
    preflight = run_script(step_script('Record original guest store before installation'), env)
    assert preflight.returncode == 0, preflight.stderr
    result = run_script(step_script('Install with default anonymous native guest acquisition'), env)
    assert result.returncode == installer_exit, result.stderr
    receipt = json.loads((reports / 'install-receipt.json').read_text())
    assert receipt['exit'] == installer_exit
    assert receipt['install_seconds'] >= 0
    assert receipt['registry_credentials_supplied'] is False
    assert receipt['guest_store_before'] == 'guest-store-before.json'
    before = json.loads((reports / receipt['guest_store_before']).read_text())
    assert before['fixture_ready'] and before['observed_at'] <= receipt['started_at']
    assert receipt['command'][1:] == ['--root', str(work / 'instance'), '--command-dir', str(work / 'commands')]
    assert (reports / 'install.stdout').read_text() == 'installer-output\n'
    assert (reports / 'install.stderr').read_text().startswith('installer-diagnostic\n')
    assert 'synthetic-must-not-pass' not in result.stdout + result.stderr
    assert 'synthetic-private-token' not in result.stdout + result.stderr + (reports / 'install.stderr').read_text()
    assert 'synthetic-private-token' in (work / 'install.stderr').read_text()
    assert stat.S_IMODE((work / 'install.stdout').stat().st_mode) == 0o600
    assert stat.S_IMODE((work / 'install.stderr').stat().st_mode) == 0o600


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
