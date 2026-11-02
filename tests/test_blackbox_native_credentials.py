"""Retained and current native credential input contracts and secret confinement."""

import json
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

from tests.blackbox import native_credentials


@pytest.mark.parametrize("storage_option", [False, True])
@pytest.mark.parametrize("write_exit", [0, 1])
def test_credential_setup_selects_supported_storage_before_one_private_write(
        tmp_path, monkeypatch, capsys, storage_option, write_exit):
    binary = tmp_path / "safeyolo"
    data = tmp_path / "instance/data"
    secrets = {"--value-file": "synthetic-access", "--refresh-token-file": "synthetic-refresh",
               "--client-secret-file": "synthetic-client-secret"}
    writes = []
    inputs = []

    def run(command, **kwargs):
        if command[1:] == ["--version"]:
            output = "safeyolo 0.1.0 commit=selected profile=production"
        elif command[1:] == ["credentials", "--help"]:
            assert not data.exists()
            output = "credentials add NAME [--storage local|passphrase]" if storage_option else "credentials add NAME"
        else:
            writes.append(command)
            assert ("--storage" in command) == storage_option
            if storage_option:
                assert command[command.index("--storage") + 1] == "local"
            root = Path(command[command.index("--root") + 1])
            inputs.append(root)
            assert root.parent == data.parent and not root.is_relative_to(data)
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            assert tomllib.loads((root / "config.toml").read_text())["data_dir"] == str(data.resolve())
            for flag, value in secrets.items():
                path = Path(command[command.index(flag) + 1])
                assert path.parent == root and path.read_text() == value
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                assert all(value not in argument for argument in command)
            for flag, value in (("--type", "oauth2"), ("--token-url", "http://127.0.0.1/oauth/token"),
                                ("--client-id", "fixture"), ("--expires-at", "2020-01-01T00:00:00+00:00")):
                assert command[command.index(flag) + 1] == value
            return subprocess.CompletedProcess(command, write_exit, json.dumps(secrets).encode(), b"private child error")
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(native_credentials.subprocess, "run", run)

    def store():
        native_credentials.store_credential(
            data, "contract-secret", secrets["--value-file"], kind="oauth2",
            refresh_token=secrets["--refresh-token-file"], client_secret=secrets["--client-secret-file"],
            token_url="http://127.0.0.1/oauth/token", client_id="fixture",
            expires_at="2020-01-01T00:00:00+00:00", binary=binary)

    if write_exit:
        with pytest.raises(RuntimeError, match="Native synthetic credential setup exited 1") as error:
            store()
        assert all(value not in str(error.value) for value in secrets.values())
        assert "private child error" not in str(error.value)
    else:
        store()
    assert len(writes) == 1
    assert all(not root.exists() for root in inputs)
    assert capsys.readouterr() == ("", "")


def test_credential_setup_help_failure_stops_before_writing(tmp_path, monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, "safeyolo 0.1.0 commit=selected profile=production", "")
        assert command[1:] == ["credentials", "--help"]
        return subprocess.CompletedProcess(command, 1, "private help output", "private help error")

    monkeypatch.setattr(native_credentials.subprocess, "run", run)
    data = tmp_path / "instance/data"
    with pytest.raises(RuntimeError, match="cannot read credentials help") as error:
        native_credentials.store_credential(data, "fixture", "synthetic-access", binary=tmp_path / "safeyolo")
    assert "private help" not in str(error.value)
    assert len(commands) == 2 and not data.parent.exists()
