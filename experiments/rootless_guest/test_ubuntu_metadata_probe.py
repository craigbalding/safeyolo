"""Control the metadata observer; native kernel effects require the Ubuntu packet."""

import errno
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.rootless_guest import ubuntu_metadata_probe as probe


def test_snapshot_reads_regular_sparse_links_and_fifo_without_opening_nodes(tmp_path):
    (tmp_path / 'regular').write_bytes(b'original')
    os.link(tmp_path / 'regular', tmp_path / 'hardlink')
    (tmp_path / 'symlink').symlink_to('regular')
    os.mkfifo(tmp_path / 'fifo', 0o600)
    with (tmp_path / 'sparse').open('wb') as stream:
        stream.write(b'start')
        stream.seek(1024**2 - 3)
        stream.write(b'end')
    rows = probe.snapshot(tmp_path)
    assert rows['hardlink']['inode'] == rows['regular']['inode']
    assert rows['symlink']['target'] == 'regular'
    assert 'sha256' not in rows['fifo']
    assert rows['sparse']['size'] == 1024**2
    # The worker filesystem may fully allocate a seek-created file. Retain
    # that observation; sparsity on native ext4 is still part of the packet.
    assert rows['sparse']['allocated_bytes'] == (tmp_path / 'sparse').stat().st_blocks * 512
    before = rows['regular']['sha256']
    (tmp_path / 'regular').write_bytes(b'mutation')
    assert probe.snapshot(tmp_path)['regular']['sha256'] != before


@pytest.mark.parametrize(('revision', 'root'), [(2, 0), (3, 100000), (3, 101000)])
def test_capability_observer_keeps_raw_root_identity(monkeypatch, revision, root):
    raw = struct.pack('<5I', revision << 24 | 1, 1024, 0, 0, 0)
    if revision == 3:
        raw += struct.pack('<I', root)
    monkeypatch.setattr(os, 'listxattr', lambda *args, **kwargs: ['security.capability'])
    monkeypatch.setattr(os, 'getxattr', lambda *args, **kwargs: raw)
    value = probe.attributes(Path('controlled-xattr'))['security.capability']
    assert value == {'hex': raw.hex(), 'revision': revision, 'root_id': root,
                     'permitted': 1024, 'inheritable': 0, 'flags': 1}


def test_acl_observer_keeps_named_principal_mask_and_errors(monkeypatch):
    raw = struct.pack('<I', 2) + struct.pack('<HHI', 2, 4, 101000) + struct.pack('<HHI', 16, 5, 0xffffffff)
    monkeypatch.setattr(os, 'listxattr', lambda *args, **kwargs: ['system.posix_acl_access'])
    monkeypatch.setattr(os, 'getxattr', lambda *args, **kwargs: raw)
    value = probe.attributes(Path('controlled-xattr'))['system.posix_acl_access']
    assert value['entries'] == [{'tag': 2, 'permissions': 4, 'id': 101000},
                                {'tag': 16, 'permissions': 5, 'id': 0xffffffff}]
    raw = b'bad'
    with pytest.raises(ValueError, match='Invalid ACL'):
        probe.attributes(Path('controlled-xattr'))


def test_xattr_inspection_failure_propagates(monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise PermissionError(errno.EACCES, 'controlled inspection error')
    monkeypatch.setattr(os, 'listxattr', denied)
    with pytest.raises(PermissionError):
        probe.snapshot(tmp_path)


def test_snapshot_cli_preserves_real_observations(tmp_path):
    (tmp_path / 'marker').write_text('actual CLI\n')
    observed = subprocess.run([sys.executable, probe.__file__, 'snapshot', str(tmp_path)],
                              capture_output=True, text=True, check=True, timeout=15)
    assert json.loads(observed.stdout) == probe.snapshot(tmp_path)


def test_access_uses_opened_tree_boundary_and_retains_denials(tmp_path, monkeypatch):
    root = tmp_path / 'private-parent/tree'
    root.mkdir(parents=True)
    (root / 'private').mkdir()
    (root / 'private/agent').write_text('private contents')
    (root / 'cap-v3').symlink_to('/bin/cat')
    monkeypatch.chdir(tmp_path)
    # This worker control checks the observer after entry. It does not claim
    # native credential switching, ACL enforcement or file-capability effects.
    monkeypatch.setattr(os, 'setgroups', lambda groups: None)
    monkeypatch.setattr(os, 'setresuid', lambda *ids: None)
    monkeypatch.setattr(os, 'setresgid', lambda *ids: None)
    observed = probe.access(root, os.getuid(), os.getgid())
    assert observed['operations']['private-read']['value'] == 'private contents'
    assert observed['operations']['acl-search']['errno'] == errno.ENOENT
    assert observed['cap-v3']['exit'] == 0
    assert 'CapEff:' in observed['cap-v3']['stdout']
