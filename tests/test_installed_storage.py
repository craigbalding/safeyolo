"""Exercise the storage observer's real guest script and replay refusal."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess

import pytest

from tests.blackbox import installed_storage as storage


@pytest.mark.parametrize("damage", [None, "missing", "changed", "overlay"])
def test_storage_guest_script_requires_persistence_and_disposable_overlay(tmp_path, damage):
    directories = {name: tmp_path / name for name in ("home", "workspace", "etc")}
    for directory in directories.values():
        directory.mkdir()

    def guest(*, create, guest_root):
        code = storage.guest_script("storage-control", create=create, guest_root=guest_root)
        for original, replacement in (("/home/agent", directories["home"]),
                                       ("/workspace", directories["workspace"]), ("/etc", directories["etc"])):
            code = code.replace(original, str(replacement))
        # Exercise the real shell workload with this control account's IDs.
        code = code.replace("agent_uid=1000", f"agent_uid={os.getuid()}")
        code = code.replace("agent_gid=1000", f"agent_gid={os.getgid()}")
        code = code.replace("expected_uid=1000", f"expected_uid={os.getuid()}")
        command = (["sudo", "-n"] if guest_root else []) + ["/bin/sh", "-c", code]
        return subprocess.run(command, capture_output=True, text=True, timeout=10)

    for guest_root in (False, True):
        created = guest(create=True, guest_root=guest_root)
        assert created.returncode == 0, created.stderr
        row = storage.observation(created.stdout)
        assert row["uid"] == (0 if guest_root else os.getuid())
        assert row["overlay_present"] is guest_root
    if damage != "overlay":
        (directories["etc"] / "storage-control").unlink()
    marker = directories["home"] / "storage-control-agent"
    if damage == "missing":
        marker.unlink()
    elif damage == "changed":
        marker.write_text("lost marker")
    for guest_root in (False, True):
        restarted = guest(create=False, guest_root=guest_root)
        assert (restarted.returncode == 0) == (damage is None), restarted.stderr
        if damage is None:
            row = storage.observation(restarted.stdout)
            assert len(row["files"]) == 4 and row["overlay_present"] is False


def test_storage_refuses_retained_attempt_before_product_effects(tmp_path):
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "package-info").write_text("source_commit=" + "a" * 40 + "\n")
    settings = tmp_path / "settings.toml"
    settings.write_text(f"[linux]\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\n")
    archive = tmp_path / "guest.tar.zst"
    archive.write_bytes(b"retained archive control")
    output = tmp_path / "retained-attempt"
    output.mkdir()
    saved = output / "original-result"
    saved.write_text("recover this result")
    args = argparse.Namespace(prepared_config=prepared, output=output, install_commit="a" * 40,
                              host_settings=settings, archive=archive,
                              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(FileExistsError):
        storage.qualify(args)
    assert list(output.iterdir()) == [saved]
    assert saved.read_text() == "recover this result"


def test_storage_queries_subids_by_actual_account_name(tmp_path, monkeypatch):
    prepared = tmp_path / "prepared"
    for name, code in (("bin/safeyolo", "echo controlled-acquisition-boundary >&2; exit 73"),
                       ("bin/safeyolo-proxy", "exit 0"), ("libexec/runsc", "exit 0")):
        path = prepared / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + code + "\n")
        path.chmod(0o755)
    (prepared / "native_package.sh").write_text('verify_native_package() { echo verified; }\n')
    package = {"source_commit": "a" * 40}
    (prepared / "package-info").write_text("source_commit=" + package["source_commit"] + "\n")
    archive = tmp_path / "guest.tar.zst"
    archive.write_bytes(b"retained archive control")
    settings = tmp_path / "settings.toml"
    settings.write_text(f"[linux]\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\n")
    username = subprocess.check_output(["id", "-un"], text=True).strip()
    tools = tmp_path / "tools"
    tools.mkdir()
    getsubids = tools / "getsubids"
    getsubids.write_text('#!/bin/sh\nif [ "$1" = -g ]; then shift; fi\n'
                        f'[ "$#" -eq 1 ] && [ "$1" = {shlex.quote(username)} ] || exit 1\n'
                        'printf "0: %s 100000 65536\\n" "$1"\n')
    getsubids.chmod(0o755)
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("USER", "unrelated-account")
    monkeypatch.setenv("LOGNAME", "unrelated-account")
    args = argparse.Namespace(prepared_config=prepared, output=tmp_path / "continuation",
                              install_commit=package["source_commit"], host_settings=settings, archive=archive,
                              archive_sha256=storage.sha(archive), index="sha256:" + "d" * 64)
    with pytest.raises(RuntimeError, match="native-download: exit 73"):
        storage.qualify(args)
    report = json.loads((args.output / "observed.json").read_text())
    assert report["result"] == "incomplete" and report["cleanup_failures"] == []
    actions = {row["label"]: row for row in report["actions"]}
    assert actions["subuids"]["command"] == ["getsubids", username]
    assert actions["subgids"]["command"] == ["getsubids", "-g", username]
    assert actions["subuids"]["exit"] == actions["subgids"]["exit"] == 0
    assert actions["verify-host-package"]["exit"] == actions["runsc-version"]["exit"] == 0
    assert actions["native-download"]["exit"] == 73
    assert "controlled-acquisition-boundary" in actions["native-download"]["stderr"]
