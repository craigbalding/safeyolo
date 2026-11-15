#!/usr/bin/env python3
"""Compare #1553 supplementary metadata on the retained native Ubuntu host.

Sylab runs `python3 ubuntu_metadata_probe.py run NEW_OUTPUT` as UID/GID 1000.
The packet imports small specimens without sudo, then separately uses sudo for
the existing privileged baseline and read-only host metadata observation.
No published guest is extracted, changed or started. Kernel user-namespace
effects are reported separately from untested gVisor enforcement.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import time
import tomllib
from pathlib import Path

if __package__:
    from .import_guest import mapped_namespace
    from .make_fixture import create
else:
    from import_guest import mapped_namespace
    from make_fixture import create

SOURCE = Path(__file__).resolve().parent
PREPARED = Path('/home/agent/1562-b682-installed')
PRODUCT = 'b6821094322e4ab261f4c149029839037fe43631'
CASES = ('canonical', 'v2-capability', 'devices', 'raw-acl42')


def attributes(path):
    """Retain raw xattrs and decode only the Linux layouts being compared."""
    result = {}
    for name in os.listxattr(path, follow_symlinks=False):
        raw = os.getxattr(path, name, follow_symlinks=False)
        value = {'hex': raw.hex()}
        if name == 'security.capability' and len(raw) in (20, 24):
            words = struct.unpack('<' + 'I' * (len(raw) // 4), raw)
            value.update(revision=words[0] >> 24, flags=words[0] & 0xffffff,
                         permitted=words[1] | words[3] << 32,
                         inheritable=words[2] | words[4] << 32,
                         root_id=words[5] if len(words) == 6 else 0)
        if name in ('system.posix_acl_access', 'system.posix_acl_default'):
            if raw[:4] != struct.pack('<I', 2) or (len(raw) - 4) % 8:
                raise ValueError(f'Invalid ACL layout: {path} {name}')
            value['entries'] = [dict(zip(('tag', 'permissions', 'id'), entry, strict=True))
                                for entry in struct.iter_unpack('<HHI', raw[4:])]
        result[name] = value
    return result


def snapshot(root):
    """Read metadata and regular contents without opening nodes or FIFO files."""
    rows = {}
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        row = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
               'type': stat.S_IFMT(info.st_mode), 'size': info.st_size,
               'allocated_bytes': info.st_blocks * 512, 'inode': info.st_ino,
               'links': info.st_nlink, 'device': [os.major(info.st_rdev), os.minor(info.st_rdev)],
               'xattrs': attributes(path)}
        if stat.S_ISREG(info.st_mode):
            with path.open('rb') as stream:
                row['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        if stat.S_ISLNK(info.st_mode):
            row['target'] = os.readlink(path)
        rows[str(path.relative_to(root))] = row
    return rows


def access(root, uid, gid):
    """Attempt real operations after dropping namespace root and all groups."""
    # Match a runtime mount's traversal boundary without opening the operator's
    # private parent directories to unrelated host identities.
    os.chdir(root)
    root = Path('.')
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    result = {'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
              'status': Path('/proc/self/status').read_text(), 'operations': {}}
    for name, operation in (
        ('private-read', lambda: (root / 'private/agent').read_text()),
        ('acl-list', lambda: os.listdir(root / 'acl-dir')),
        ('acl-search', lambda: (root / 'acl-dir/inherited').stat().st_uid),
        ('acl-create', lambda: (root / f'acl-dir/created-{uid}').write_text('access probe\n')),
    ):
        try:
            result['operations'][name] = {'value': operation()}
        except OSError as error:
            # A denial is an observed permission result, not missing coverage.
            result['operations'][name] = {'errno': error.errno, 'error': str(error)}
    for name in ('cap-v3', 'cap-v2', 'setid'):
        path = root / name
        if path.exists():
            try:
                observed = subprocess.run(['./' + name, '/proc/self/status'], capture_output=True, text=True,
                                          check=False, timeout=10)
            except OSError as error:
                # An exec refusal is a capability/set-ID effect to compare.
                result[name] = {'errno': error.errno, 'error': str(error)}
            else:
                result[name] = {'exit': observed.returncode, 'stdout': observed.stdout, 'stderr': observed.stderr}
    return result


def baseline(output):
    """Privileged comparison setup only; the candidate never calls this path."""
    assert os.geteuid() == 0
    fixtures = json.loads((output / 'fixtures.json').read_text())
    actions = []
    for case in CASES:
        stage = output / 'baseline' / f'extract-{case}'
        selected = Path(fixtures[case]['path'])
        assert hashlib.sha256(selected.read_bytes()).hexdigest() == fixtures[case]['sha256']
        commands = [
            ['tar', '-xpf', '-', '-C', str(stage), '--numeric-owner', '--same-owner',
             '--acls', '--xattrs', '--xattrs-include=*', '--', 'rootfs-tree', 'cache-paths.txt'],
            [str(PREPARED / 'bin/safeyolo'), 'host', 'remap-rootfs', str(stage / 'rootfs-tree'),
             '100000', '100000', '1000', '1000'],
        ]
        with subprocess.Popen(['zstd', '-dc', '--', str(selected)], stdout=subprocess.PIPE) as decoder:
            try:
                extracted = subprocess.run(commands[0], stdin=decoder.stdout, capture_output=True,
                                           text=True, check=False, timeout=60)
            finally:
                decoder.stdout.close()
            decoder_exit = decoder.wait(timeout=10)
        row = {'case': case, 'tar_command': commands[0], 'tar_exit': extracted.returncode,
               'tar_stdout': extracted.stdout, 'tar_stderr': extracted.stderr, 'zstd_exit': decoder_exit}
        actions.append(row)
        (output / 'baseline-actions.json').write_text(json.dumps(actions, indent=2) + '\n')
        if extracted.returncode == 0 and decoder_exit == 0:
            remapped = subprocess.run(commands[1], capture_output=True, text=True, check=False, timeout=60)
            row.update(remap_command=commands[1], remap_exit=remapped.returncode,
                       remap_stdout=remapped.stdout, remap_stderr=remapped.stderr)
        (output / 'baseline-actions.json').write_text(json.dumps(actions, indent=2) + '\n')
    # This privileged observation reads raw host capability IDs, even when a
    # namespace reader would expose a translated revision-2 value.
    host = {}
    for case in CASES:
        report = json.loads((output / 'candidate' / case / 'preparation.json').read_text())
        for kind, stage in [('candidate', Path(report['stage'])),
                            ('baseline', output / 'baseline' / f'extract-{case}')]:
            root = stage / 'rootfs-tree'
            if root.exists():
                host[f'{kind}/{case}'] = snapshot(root)
    (output / 'host-metadata.json').write_text(json.dumps(host, indent=2) + '\n')


def observe_runtime_namespace(output, command):
    # Same maps as linux_host::Mapping::entries; this is the native kernel,
    # not gVisor's separate filesystem/capability implementation.
    runtime_maps = [(0, 100000, 1000), (1000, 1000, 1), (1001, 101001, 64535)]
    with mapped_namespace(PREPARED, runtime_maps, runtime_maps) as (prefix, maps):
        for case in CASES:
            report = json.loads((output / 'candidate' / case / 'preparation.json').read_text())
            for kind, stage in [('candidate', Path(report['stage'])),
                                ('baseline', output / 'baseline' / f'extract-{case}')]:
                root = stage / 'rootfs-tree'
                if not root.exists():
                    continue
                command(f'{kind}/{case}/runtime-metadata', prefix + [sys.executable, __file__, 'snapshot', root])
                if case in ('canonical', 'v2-capability'):
                    if case == 'canonical':
                        command(f'{kind}/{case}/inherit', prefix + [sys.executable, '-c',
                                'import os,sys; os.umask(0o077); os.close(os.open(sys.argv[1], os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o666))', root / 'acl-dir/inherited'])
                    for uid, gid in ((1000, 1000), (33, 33), (65535, 65535)):
                        command(f'{kind}/{case}/access-{uid}', prefix + [sys.executable, __file__, 'access', root, uid, gid])
                    command(f'{kind}/{case}/runtime-metadata-after-access', prefix + [sys.executable, __file__, 'snapshot', root])
    return maps


def run(output):
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    assert (os.getuid(), os.getgid()) == (1000, 1000)
    # Budget both 64 MiB sparse specimens as fully allocated, plus small
    # archives/metadata, before reserving the existing 5 GiB floor.
    assert shutil.disk_usage(output.parent).free >= 5 * 1024**3 + 192 * 1024**2
    assert dict(line.split('=', 1) for line in (PREPARED / 'package-info').read_text().splitlines())['source_commit'] == PRODUCT
    mapping = tomllib.loads((PREPARED / 'config.toml').read_text())['linux']
    assert tuple(mapping[name] for name in ('uid_base', 'gid_base', 'host_uid', 'host_gid')) == (100000, 100000, 1000, 1000)
    output.mkdir(mode=0o700)
    result = {'started': time.time(), 'result': 'incomplete', 'platform': platform.uname()._asdict(),
              'os_release': Path('/etc/os-release').read_text(), 'python': sys.version,
              'package_source': PRODUCT, 'actions': [], 'limits': 'Kernel namespaces only; no gVisor backend or published-guest replay.'}

    def save():
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    def command(label, arguments, *, env=None):
        row = {'label': label, 'command': list(map(str, arguments))}
        result['actions'].append(row)
        save()
        try:
            observed = subprocess.run(row['command'], capture_output=True, text=True, check=False, timeout=180, env=env)
        except subprocess.TimeoutExpired as error:
            row.update(timeout=True, stdout=(error.stdout or b'').decode(errors='replace'),
                       stderr=(error.stderr or b'').decode(errors='replace'))
            save()
            raise
        row.update(exit=observed.returncode, stdout=observed.stdout, stderr=observed.stderr)
        save()
        return observed

    save()
    try:
        fixtures = create(output / 'specimens')
        (output / 'fixtures.json').write_text(json.dumps(fixtures, indent=2) + '\n')
        (output / 'candidate').mkdir(mode=0o700)
        (output / 'baseline').mkdir(mode=0o700)
        commands = output / 'commands'
        commands.mkdir(mode=0o700)
        for name in ('tar', 'zstd', 'rm', 'unshare', 'tail', 'nsenter', 'newuidmap', 'newgidmap'):
            executable = shutil.which(name)
            assert executable, name
            (commands / name).symlink_to(executable)
        candidate_env = dict(os.environ, PATH=str(commands))
        assert shutil.which('sudo', path=candidate_env['PATH']) is None
        result['sudo_on_candidate_path'] = None
        for case in CASES:
            (output / 'baseline' / f'extract-{case}').mkdir(mode=0o700)
            command('candidate/' + case, [sys.executable, SOURCE / 'import_guest.py', 'prepare',
                    '--archive', fixtures[case]['path'], '--sha256', fixtures[case]['sha256'],
                    '--host-root', PREPARED, '--output', output / 'candidate' / case], env=candidate_env)
        # Host sudo is explicit baseline setup/observation, never a fallback
        # for a failed candidate. Every original candidate failure is retained.
        observed = command('privileged-baseline-and-host-observation',
                           ['sudo', '-n', '--', sys.executable, __file__, 'baseline', output])
        if observed.returncode:
            raise RuntimeError('Baseline setup/observation failed; inspect original output before retry')
        result['runtime_maps'] = observe_runtime_namespace(output, command)
        failures = [row['label'] for row in result['actions']
                    if row['exit'] and not row['label'].startswith('candidate/')]
        result['result'] = ('observation incomplete: ' + ', '.join(failures) if failures else
                            'observed; compare original actions and metadata, including failed specimens; not a feasibility pass')
    finally:
        result['ended'] = time.time()
        save()
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run', 'baseline', 'snapshot', 'access'))
    parser.add_argument('path', type=Path)
    parser.add_argument('ids', type=int, nargs='*')
    args = parser.parse_args()
    if args.operation == 'run':
        run(args.path.absolute())
    elif args.operation == 'baseline':
        baseline(args.path)
    elif args.operation == 'snapshot':
        print(json.dumps(snapshot(args.path), indent=2))
    else:
        print(json.dumps(access(args.path, *args.ids), indent=2))


if __name__ == '__main__':
    main()
