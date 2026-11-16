#!/usr/bin/env bash
# Sylab runs this on the existing native Ubuntu host as UID/GID 1000.
# Inputs: verified archive, the retained 18403 inventory, NEW disk-backed output.
# Effects: one retained import, two small failed/cancelled stages, JSON/logs.
# No backend, download, sudo, host setup, policy or delegated-range change.
set -euo pipefail
[[ $# == 3 ]] || { echo 'Usage: ubuntu_import_probe.sh ARCHIVE INVENTORY NEW_OUTPUT' >&2; exit 64; }
source1553=$(cd -- "$(dirname -- "$0")" && pwd)
python3 - "$source1553" "$1" "$2" "$3" <<'PY'
import hashlib, io, json, os, shutil, stat, subprocess, sys, tarfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from import_guest import import_namespace

source, archive, inventory, output = map(Path, sys.argv[1:])
host_root = Path('/home/agent/1562-b682-installed')
digest = '1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe'
assert (os.getuid(), os.getgid()) == (1000, 1000)
assert hashlib.sha256((host_root / 'host/namespace-entry').read_bytes()).hexdigest() == '7f812349eb1017d2122230d2daf3592fc5952efee881ffc42585d876687a97ee'
assert hashlib.sha256(inventory.read_bytes()).hexdigest() == 'dfc03cca434f907f37459afafcbd1c7c9a9b039303a1e076aabfab274c77a406'
inventory_data = json.loads(inventory.read_text())
assert inventory_data['archive_sha256'] == digest
# Preserve the existing 5 GiB floor. Forecast this archive's logical data,
# per-entry allocation and small specimens against current backing space.
growth = inventory_data['logical_regular_bytes'] + len(inventory_data['records']) * 8192 + 64 * 1024**2
assert shutil.disk_usage(output.parent).free >= 5 * 1024**3 + growth
output.mkdir(mode=0o700)
commands = output / 'commands'
commands.mkdir(mode=0o700)
for tool in ['tar', 'zstd', 'rm', 'unshare', 'tail', 'nsenter', 'newuidmap', 'newgidmap']:
    executable = shutil.which(tool)
    assert executable, tool
    (commands / tool).symlink_to(executable)
os.environ['PATH'] = str(commands.absolute())
assert shutil.which('sudo') is None
base = [sys.executable, str(source / 'import_guest.py'), 'prepare', '--platform', 'linux',
        '--host-root', str(host_root), '--uid-base', '100000', '--gid-base', '100000']

def run(name, selected, sha256, extra=()):
    command = base + ['--archive', str(selected), '--sha256', sha256,
                      '--output', str(output / name), *extra]
    with (output / (name + '.stdout')).open('w') as out, (output / (name + '.stderr')).open('w') as err:
        result = subprocess.run(command, stdout=out, stderr=err, check=False, timeout=660)
    return {'command': command, 'exit': result.returncode}

result = {'uid': os.getuid(), 'gid': os.getgid(), 'sudo_on_path': shutil.which('sudo'),
          'archive_sha256': digest, 'published': run('published', archive, digest)}
(output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
assert result['published']['exit'] == 0, 'Preserve original import failure; do not retry'
report = json.loads((output / 'published/preparation.json').read_text())
stage = Path(report['stage'])
cache = stage / 'cache-paths.txt'
info = cache.lstat()
result['cache'] = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
                   'text': cache.read_text()}
assert stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (1000, 1000)

# The observer runs in archive coordinates so private mapped directories are
# readable. Compare every published rootfs header's type/owner/mode/size/link.
observer = r'''
import json, os, stat, sys
from pathlib import Path
stage, inventory = map(Path, sys.argv[1:])
rows = json.loads(inventory.read_text())['records']
mismatches, checked = [], 0
types = {'5': stat.S_ISDIR, '0': stat.S_ISREG, '1': stat.S_ISREG, '2': stat.S_ISLNK}
for row in rows:
    if row['name'] != 'rootfs-tree' and not row['name'].startswith('rootfs-tree/'):
        continue
    path = stage / row['name']
    info = path.lstat()
    valid = types[row['type']](info.st_mode)
    valid &= (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (row['uid'], row['gid'], int(row['mode'], 8))
    if row['type'] == '0': valid &= info.st_size == row['size']
    if row['type'] == '2': valid &= os.readlink(path) == row['link']
    if row['type'] == '1': valid &= info.st_ino == (stage / row['link']).stat().st_ino
    if not valid: mismatches.append({'name': row['name'], 'observed': [info.st_uid, info.st_gid, oct(info.st_mode), info.st_size]})
    checked += 1
print(json.dumps({'checked': checked, 'mismatches': mismatches}, indent=2))
raise SystemExit(bool(mismatches))
'''
with import_namespace(host_root, 100000, 100000) as (prefix, maps):
    with (output / 'published-metadata.json').open('w') as out:
        observed = subprocess.run(prefix + [sys.executable, '-c', observer, str(stage), str(inventory)],
                                  stdout=out, check=False, timeout=60)
    result['metadata'] = {'exit': observed.returncode, 'maps': maps}
    root = (stage / 'rootfs-tree').lstat()
    result['host_root'] = {'uid': root.st_uid, 'gid': root.st_gid, 'mode': oct(stat.S_IMODE(root.st_mode))}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert observed.returncode == 0

# Small specimens isolate the changed host-cache pass. Missing cache must fail;
# explicit cancellation must propagate. Neither may follow the external link.
external = output / 'external-target'
external.write_bytes(b'external target must survive\n')
before = external.stat()
for name, include_cache in [('missing-cache', False), ('cancelled', True)]:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo('rootfs-tree')
        root.type, root.uid, root.gid, root.mode = tarfile.DIRTYPE, 100000, 100000, 0o700
        link = tarfile.TarInfo('rootfs-tree/external')
        link.type, link.linkname, link.uid, link.gid = tarfile.SYMTYPE, str(external.absolute()), 100000, 100000
        tar.addfile(root)
        tar.addfile(link)
        if include_cache:
            item = tarfile.TarInfo('cache-paths.txt')
            item.uid, item.gid, item.size = 1001, 1001, 0
            tar.addfile(item)
    selected = output / (name + '.tar.zst')
    with selected.open('wb') as out:
        subprocess.run(['zstd', '-q', '-c'], input=raw.getvalue(), stdout=out, check=True)
    extra = ['--cancel-after-extract'] if include_cache else []
    result[name] = run(name, selected, hashlib.sha256(selected.read_bytes()).hexdigest(), extra)
    failed = json.loads((output / name / 'preparation.json').read_text())
    result[name]['preparation'] = failed
    result[name]['stage_absent'] = not os.path.lexists(failed['stage'])
    after = external.stat()
    result[name]['external_preserved'] = external.read_bytes() == b'external target must survive\n' and (before.st_uid, before.st_gid, before.st_mode, before.st_ino) == (after.st_uid, after.st_gid, after.st_mode, after.st_ino)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert result[name]['exit'] != 0 and result[name]['stage_absent'] and result[name]['external_preserved']
print(json.dumps(result, indent=2))
PY
