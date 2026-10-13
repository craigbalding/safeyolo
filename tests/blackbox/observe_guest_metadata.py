"""Observe the Linux installation against its acquired guest archive.

Reuse the complete lstat/tar-header comparison used for issue 239's original
guest. Run as a read-only privileged observer after the ordinary installer.
Only observations are written; no owners, modes, links or guest files change.
"""

import argparse
import collections
import gzip
import hashlib
import json
import os
import stat
import subprocess
import tarfile
from pathlib import Path


def metadata(path, name):
    info = path.lstat()
    row = {'path': name, 'mode': stat.S_IMODE(info.st_mode), 'type': stat.S_IFMT(info.st_mode),
               'uid': info.st_uid, 'gid': info.st_gid, 'size': info.st_size, 'dev': info.st_dev,
               'ino': info.st_ino, 'nlink': info.st_nlink}
    if stat.S_ISLNK(info.st_mode):
        row['link'] = os.readlink(path)
    return row


def observe(root, assets):
    share = root / 'share'
    tree = share / 'rootfs-tree'
    resolved = tree.resolve(strict=True)
    if not tree.is_symlink() or resolved != (assets / 'rootfs-tree').resolve(strict=True):
        raise ValueError('Installed rootfs link does not reach the acquired tree')
    rows = [metadata(resolved, 'rootfs-tree')]

    def fail(error):
        raise error

    for parent, dirs, files in os.walk(resolved, followlinks=False, onerror=fail):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            rows.append(metadata(path, 'rootfs-tree/' + str(path.relative_to(resolved))))
    rows.append(metadata(share / 'cache-paths.txt', 'cache-paths.txt'))
    cache = (share / 'cache-paths.txt').read_bytes().decode()
    operands = []
    for operand in cache.splitlines():
        if not operand.startswith('/') or '..' in Path(operand).parts:
            raise ValueError('Invalid installed cache operand')
        path = resolved / operand.lstrip('/')
        operands.append({'operand': operand, 'path': str(path), 'is_directory': path.is_dir(),
                             'metadata': metadata(path, 'rootfs-tree/' + operand.lstrip('/'))})
    with (resolved / 'usr/bin/bash').open('rb') as stream:
        header = stream.read(64)
    if header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Installed bash is not a little-endian 64-bit ELF executable')
    owner = root.stat()
    return {'installed_root': str(root), 'observer_uid': os.getuid(), 'rootfs_link': os.readlink(tree),
                'installed_rootfs_metadata': metadata(tree, 'share/rootfs-tree'),
                'resolved_tree': str(resolved), 'acquired_tree': str(assets / 'rootfs-tree'), 'entries': rows,
                'acquired_cache_metadata': metadata(assets / 'cache-paths.txt', 'cache-paths.txt'),
                'installed_cache': cache, 'acquired_cache': (assets / 'cache-paths.txt').read_bytes().decode(),
                'cache_operands': operands, 'installer_uid': owner.st_uid, 'installer_gid': owner.st_gid,
                'bash_elf_machine': int.from_bytes(header[18:20], 'little'), 'complete': True}


def read_archive(archive):
    members = {}
    cache = None
    with subprocess.Popen(['zstd', '-d', '-q', '-c', str(archive)], stdout=subprocess.PIPE) as decoder:
        try:
            with tarfile.open(fileobj=decoder.stdout, mode='r|') as tar:
                for member in tar:
                    name = member.name.rstrip('/')
                    if name in members or member.type not in (
                        tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.REGTYPE, tarfile.LNKTYPE
                    ):
                        raise ValueError('Duplicate or unsupported archive member: ' + name)
                    members[name] = member
                    if name == 'cache-paths.txt':
                        cache = tar.extractfile(member).read().decode()
        finally:
            decoder.stdout.close()
        if decoder.wait() != 0:
            raise ValueError('Guest archive decompression failed')
    if cache is None:
        raise ValueError('Guest archive has no cache-paths.txt')
    return members, cache


def compare(observation, members, cache):
    rows = {row['path']: row for row in observation['entries']}
    if len(rows) != len(observation['entries']):
        raise ValueError('Duplicate installed observation')
    types = {tarfile.DIRTYPE: stat.S_IFDIR, tarfile.SYMTYPE: stat.S_IFLNK,
             tarfile.REGTYPE: stat.S_IFREG, tarfile.LNKTYPE: stat.S_IFREG}
    errors = collections.Counter()
    samples = {}

    def mismatch(kind, name):
        errors[kind] += 1
        samples.setdefault(kind, name)

    for name in members.keys() - rows.keys():
        mismatch('missing_member', name)
    for name in rows.keys() - members.keys():
        mismatch('extra_member', name)
    expected_groups = collections.defaultdict(set)
    actual_groups = collections.defaultdict(set)
    for name, member in members.items():
        if name not in rows:
            continue
        row = rows[name]
        original = observation['acquired_cache_metadata'] if name == 'cache-paths.txt' else row
        for field, expected in [('mode', member.mode), ('uid', member.uid), ('gid', member.gid),
                                ('type', types[member.type])]:
            if original[field] != expected:
                mismatch(field, name)
        if name.startswith('rootfs-tree') and (member.uid, member.gid) != (100000, 100000):
            mismatch('archive_rootfs_owner', name)
        if member.issym() and row.get('link') != member.linkname:
            mismatch('symlink_target', name)
        if member.isreg() or member.islnk():
            referent = member.linkname if member.islnk() else name
            if referent not in members or not members[referent].isreg():
                raise ValueError('Hardlink does not refer to an original regular member: ' + name)
            if row['size'] != members[referent].size:
                mismatch('regular_size', name)
            expected_groups[referent].add(name)
            actual_groups[(row['dev'], row['ino'])].add(name)
    for group in expected_groups.values():
        present = group & rows.keys()
        first = rows[next(iter(present))]
        if actual_groups[(first['dev'], first['ino'])] != group:
            mismatch('hardlink_relationship', sorted(group)[0])
        if any(rows[name]['nlink'] != len(group) for name in present):
            mismatch('link_count', sorted(group)[0])
    if observation['installed_cache'] != cache or observation['acquired_cache'] != cache:
        mismatch('cache_text', 'cache-paths.txt')
    installed_cache = rows.get('cache-paths.txt')
    if installed_cache is None or (
        installed_cache['uid'], installed_cache['gid'], installed_cache['mode'], installed_cache['size']
    ) != (observation['installer_uid'], observation['installer_gid'], 0o644, len(cache.encode())):
        mismatch('installed_cache_copy', 'cache-paths.txt')
    for operand in observation['cache_operands']:
        if not operand['is_directory']:
            mismatch('cache_operand', operand['operand'])
    if observation['bash_elf_machine'] != 183:
        mismatch('architecture', 'rootfs-tree/usr/bin/bash')
    return {'archive_members': len(members), 'installed_entries': len(rows),
                'rootfs_owner_counts': dict(collections.Counter(
                    f"{row['uid']}:{row['gid']}" for name, row in rows.items() if name != 'cache-paths.txt')),
                'metadata_mismatches': dict(errors), 'first_mismatch': samples, 'metadata_relationship_pass': not errors,
                'hardlink_groups': [sorted(group) for group in expected_groups.values() if len(group) > 1],
                'scope': 'Complete Linux ARM64 guest metadata/cache comparison; no runtime or onboarding claim'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--store', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    selection = json.loads((args.root / 'share/guest-selection.json').read_text())
    digest = selection['archive']['digest'].removeprefix('sha256:')
    assets = args.store / 'trees/sha256' / digest
    if Path(selection['assets']).resolve(strict=True) != assets.resolve(strict=True):
        raise ValueError('Actual selection does not name the default acquired archive tree')
    archive = args.store / 'blobs/sha256' / digest
    with archive.open('rb') as stream:
        actual_digest = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
    binding = {'path': str(archive), 'digest': actual_digest, 'bytes': archive.stat().st_size,
                   'selected_descriptor': selection['archive']}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'acquired-archive.json').write_text(json.dumps(binding, indent=2) + '\n')
    if actual_digest != selection['archive']['digest'] or binding['bytes'] != selection['archive']['size']:
        raise ValueError('Acquired archive bytes differ from the installed selection')
    observation = observe(args.root, assets)
    with gzip.open(args.output / 'metadata-observation.json.gz', 'wt') as stream:
        json.dump(observation, stream)
    members, cache = read_archive(archive)
    comparison = compare(observation, members, cache)
    (args.output / 'metadata-comparison.json').write_text(json.dumps(comparison, indent=2) + '\n')
    print(json.dumps(comparison))
    return 0 if comparison['metadata_relationship_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
