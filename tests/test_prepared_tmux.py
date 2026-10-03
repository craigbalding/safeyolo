"""Probe private-runtime transfer and release verification without Mac claims."""

import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tests.blackbox import installed_sections, prepare_tmux


@pytest.mark.parametrize("failure", [None, "tampered", "escape", "symlink"])
def test_release_bytes_are_verified_before_safe_extraction(tmp_path, monkeypatch, failure):
    """Drive the downloader/parser with finite release and hostile archive bytes."""
    data = b"fixture selected source"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo("release/COPYING" if failure not in {"escape", "symlink"} else "../escaped")
        member.size = len(data)
        if failure == "symlink":
            member.name = "release/link"
            member.type = tarfile.SYMTYPE
            member.linkname = "../../escaped"
            member.size = 0
            archive.addfile(member)
        else:
            archive.addfile(member, io.BytesIO(data))
    payload = buffer.getvalue()
    monkeypatch.setitem(prepare_tmux.SOURCES, "tmux", ("https://fixture.test/release",
                        "0" * 64 if failure == "tampered" else hashlib.sha256(payload).hexdigest()))
    monkeypatch.setattr(prepare_tmux.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload))
    if failure:
        with pytest.raises((ValueError, tarfile.FilterError)):
            prepare_tmux.source_archive("tmux", tmp_path)
        assert not (tmp_path.parent / "escaped").exists()
        if failure == "tampered":
            assert not (tmp_path / "tmux").exists(), "a bad digest must stop before archive parsing"
    else:
        source = prepare_tmux.source_archive("tmux", tmp_path)
        assert (source / "COPYING").read_bytes() == data


@pytest.mark.parametrize("failure", [None, "signature", "foreign-library", "missing-observation", "bad-version"])
def test_mac_verification_checks_signature_and_relocation_before_executing(tmp_path, monkeypatch, failure):
    """Use real process boundaries for the verifier's tool responses."""
    commands = tmp_path / "commands"
    commands.mkdir()
    binary = tmp_path / "safeyolo-tmux"
    executed = tmp_path / "executed"
    binary.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(executed)!r}).touch()\n"
                      f"print({'bad version' if failure == 'bad-version' else 'tmux 3.7c'!r})\n")
    binary.chmod(0o755)
    codesign = commands / "codesign"
    codesign.write_text(f"#!/bin/sh\nexit {7 if failure == 'signature' else 0}\n")
    codesign.chmod(0o755)
    library = "/opt/homebrew/lib/libevent.dylib" if failure == "foreign-library" else "/usr/lib/libSystem.B.dylib"
    observation = "" if failure == "missing-observation" else f"{binary}:\n\t{library} (compatibility version 1.0.0)\n"
    otool = commands / "otool"
    otool.write_text(f"#!{sys.executable}\nprint({observation!r}, end='')\n")
    otool.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands))
    if failure:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            prepare_tmux.verify_mac_tmux(binary)
        assert executed.exists() is (failure == "bad-version")
    else:
        assert prepare_tmux.verify_mac_tmux(binary) == "tmux 3.7c"
        assert executed.is_file()


def test_sections_and_continuity_get_only_private_runtime_bytes(tmp_path):
    prepared = tmp_path / "prepared"
    nats = prepared / "data/coord/nats/bin/fixture/nats-server"
    nats.parent.mkdir(parents=True)
    nats.write_bytes(b"selected NATS fixture")
    tmux = prepared / "bin/safeyolo-tmux"
    tmux.parent.mkdir()
    tmux.write_text("#!/bin/sh\nprintf 'tmux 3.7c\\n'\n")
    tmux.chmod(0o755)
    for relative in ("data/coord/nats/nats.pid.json", "data/coord/nats/credentials.json", "data/admin_token",
                     "data/traffic-tmux.sock", "vault.json"):
        (prepared / relative).write_text("private-state-marker")
    # Both call paths use the same transfer helper and real selected lookup.
    for name in (*installed_sections.SECTIONS["vz"], "package-instance"):
        root = tmp_path / name
        installed_sections.copy_prepared_runtime(prepared, root)
        env = {**os.environ, "SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_TMUX_BIN": str(root / "bin/safeyolo-tmux")}
        code = "from safeyolo.traffic_session import find_private_tmux; print(find_private_tmux(allow_system=False))"
        found = subprocess.check_output([sys.executable, "-I", "-c", code], env=env, text=True, timeout=5).strip()
        assert found == str(root / "bin/safeyolo-tmux")
        assert (root / "bin/safeyolo-tmux").read_bytes() == tmux.read_bytes()
        assert not any(b"private-state-marker" in path.read_bytes() for path in root.rglob("*") if path.is_file())
        assert not (root / "data/traffic-tmux.sock").exists()
        (root / "bin/safeyolo-tmux").unlink()
        missing = subprocess.run([sys.executable, "-I", "-c", code], env=env, capture_output=True, text=True, timeout=5)
        assert missing.returncode != 0 and "not executable" in missing.stderr


def test_linux_preparation_preserves_the_supported_prerequisite_and_ignores_foreign_override(tmp_path, monkeypatch):
    if sys.platform != "linux":
        pytest.skip("Linux's supported bootstrap prerequisite")
    commands = tmp_path / "commands"
    commands.mkdir()
    tmux = commands / "tmux"
    tmux.write_text("#!/bin/sh\nprintf 'tmux 3.5a\\n'\n")
    tmux.chmod(0o755)
    cli = tmp_path / "safeyolo"
    cli.write_text(f"#!{sys.executable}\n")
    monkeypatch.setenv("PATH", str(commands))
    monkeypatch.setenv("SAFEYOLO_TMUX_BIN", str(tmp_path / "foreign-runtime"))
    result = prepare_tmux.prepare_tmux(cli, tmp_path / "prepared")
    assert result == {"path": str(tmux), "version": "tmux 3.5a", "sha256": hashlib.sha256(tmux.read_bytes()).hexdigest()}
    assert not (tmp_path / "prepared/bin/safeyolo-tmux").exists(), "Linux needs no redundant private copy"


def test_standalone_producer_help_needs_only_stdlib(tmp_path):
    result = subprocess.run([sys.executable, "-I", str(Path(prepare_tmux.__file__).resolve()), "--help"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and "--config-dir" in result.stdout
