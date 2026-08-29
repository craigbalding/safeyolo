from __future__ import annotations

import importlib.util
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from safeyolo.coord import mattermost

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str) -> ModuleType:
    path = REPO_ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_portable_bundle(root: Path, *, token_reference: str = "bot-token") -> tuple[Path, Path, Path]:
    root.mkdir(mode=0o700)
    token = root / "bot-token"
    token.write_text("portable-test-token\n", encoding="utf-8")
    token.chmod(0o600)
    state = root / "ordinary-existing-state.sqlite3"
    state.write_text("must remain untouched", encoding="utf-8")
    state.chmod(0o600)
    config = root / "test-config.toml"
    config.write_text(
        "\n".join(
            [
                "version = 1",
                'server_url = "https://mattermost.example"',
                f'bot_token_file = "{token_reference}"',
                'bot_user_id = "' + "b" * 26 + '"',
                'operator_user_id = "' + "o" * 26 + '"',
                'state_file = "ordinary-existing-state.sqlite3"',
                "poll_interval_seconds = 1.0",
                "",
                "[[rooms]]",
                'coord_room = "dedicated-test"',
                'channel_id = "' + "c" * 26 + '"',
                "backfill = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config, token, state


def test_integration_copy_uses_private_disposable_state_and_forces_no_backfill(tmp_path: Path) -> None:
    script = load_script("accept_mattermost_macos_integration.py")
    live_state = tmp_path / "live-state.sqlite3"
    live_state.write_text("must remain untouched", encoding="utf-8")
    config = mattermost.MattermostConfig(
        server_url="https://mattermost.example",
        bot_token_file=tmp_path / "existing-token",
        bot_user_id="b" * 26,
        operator_user_id="o" * 26,
        state_file=live_state,
        poll_interval_seconds=1.0,
        rooms=(mattermost.RoomMapping("test-room", "c" * 26, True),),
    )
    disposable_config = tmp_path / "acceptance" / "config.toml"
    disposable_config.parent.mkdir(mode=0o700)
    disposable_state = disposable_config.parent / "state.sqlite3"

    script._write_disposable_config(config, disposable_config, disposable_state)

    copied = mattermost.load_config(disposable_config)
    assert copied.state_file == disposable_state
    assert copied.bot_token_file == config.bot_token_file
    assert copied.rooms == (mattermost.RoomMapping("test-room", "c" * 26, False),)
    assert stat.S_IMODE(disposable_config.stat().st_mode) == 0o600
    assert live_state.read_text(encoding="utf-8") == "must remain untouched"
    assert not disposable_state.exists()


def test_ordinary_private_bundle_validates_after_relocation_and_source_state_is_ignored(tmp_path: Path) -> None:
    integration = load_script("accept_mattermost_macos_integration.py")
    original = tmp_path / "original-private-bundle"
    config_path, _, source_state = write_portable_bundle(original)
    config_path = integration._private_regular_config(config_path)
    integration._validate_test_source(config_path, mattermost.load_config(config_path))

    relocated = tmp_path / "different-absolute-private-bundle"
    original.rename(relocated)
    relocated_config = integration._private_regular_config(relocated / config_path.name)
    source = mattermost.load_config(relocated_config)
    integration._validate_test_source(relocated_config, source)
    assert source.state_file == relocated / source_state.name
    assert source.state_file.read_text(encoding="utf-8") == "must remain untouched"
    supplied_config = relocated_config.read_text(encoding="utf-8")
    supplied_token = source.bot_token_file.read_text(encoding="utf-8")

    temp_root = tmp_path / "integration-temp"
    temp_root.mkdir(mode=0o700)
    temp_config = temp_root / "config.toml"
    temp_state = temp_root / "state.sqlite3"
    integration._write_disposable_config(source, temp_config, temp_state)
    copied = mattermost.load_config(temp_config)
    assert copied.state_file == temp_state
    assert relocated_config.read_text(encoding="utf-8") == supplied_config
    assert source.bot_token_file.read_text(encoding="utf-8") == supplied_token
    assert source.state_file.read_text(encoding="utf-8") == "must remain untouched"


def test_integration_rejects_absolute_token_even_when_it_is_a_sibling(tmp_path: Path) -> None:
    integration = load_script("accept_mattermost_macos_integration.py")
    bundle = tmp_path / "private-bundle"
    absolute_token = bundle / "bot-token"
    config_path, _, _ = write_portable_bundle(bundle, token_reference=str(absolute_token))
    config = mattermost.load_config(config_path)

    with pytest.raises(integration.AcceptanceError, match="relative sibling filename"):
        integration._validate_test_source(config_path, config)


def test_acceptance_cleanup_removes_only_verified_script_roots(tmp_path: Path) -> None:
    structural = load_script("accept_mattermost_macos.py")
    integration = load_script("accept_mattermost_macos_integration.py")
    sibling = tmp_path / "operator-file"
    sibling.write_text("untouched", encoding="utf-8")

    for module, prefix in (
        (structural, "safeyolo-mm-macos-accept-"),
        (integration, "safeyolo-mm-macos-integration-"),
    ):
        root = tmp_path / f"{prefix}test"
        root.mkdir(mode=0o700)
        (root / "owned").write_text("temporary", encoding="utf-8")
        opened = root.lstat()
        assert module._cleanup(root, (opened.st_dev, opened.st_ino))
        assert not root.exists()
        assert sibling.read_text(encoding="utf-8") == "untouched"


def test_structural_replacement_gate_includes_new_regular_and_hardlinked_copies(tmp_path: Path) -> None:
    structural = load_script("accept_mattermost_macos.py")
    root = tmp_path / "safeyolo-mm-macos-accept-replacements"
    root.mkdir(mode=0o700)
    structural._replacement_guards(root)


def test_structural_schema_probe_closes_its_sqlite_connection(tmp_path: Path) -> None:
    structural = load_script("accept_mattermost_macos.py")
    state_path = tmp_path / "schema.sqlite3"
    conn = sqlite3.connect(state_path)
    conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
    conn.commit()
    conn.close()

    opened: list[sqlite3.Connection] = []
    real_connect = structural.sqlite3.connect

    def tracked_connect(path: Path) -> sqlite3.Connection:
        tracked = real_connect(path)
        opened.append(tracked)
        return tracked

    structural.sqlite3.connect = tracked_connect
    try:
        assert structural._schema_tables(state_path) == {"sentinel"}
    finally:
        structural.sqlite3.connect = real_connect
    assert len(opened) == 1
    try:
        opened[0].execute("SELECT 1")
    except sqlite3.ProgrammingError as exc:
        assert "closed" in str(exc)
    else:
        raise AssertionError("schema probe retained its SQLite connection")


@pytest.mark.parametrize(
    "script_name,code_prefix",
    [
        ("accept_mattermost_macos.py", "MM_MACOS_STRUCTURAL_STEP_4"),
        ("accept_mattermost_macos_integration.py", "MM_MACOS_INTEGRATION_STEP_4"),
    ],
)
def test_acceptance_failure_prints_full_sqlite_chain_and_code(
    script_name: str,
    code_prefix: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = load_script(script_name)
    conn = sqlite3.connect(":memory:")
    try:
        try:
            conn.execute("SELECT * FROM absent_acceptance_table")
        except sqlite3.Error as root:
            try:
                raise mattermost.MattermostAdapterError("state operation wrapper") from root
            except mattermost.MattermostAdapterError as wrapped:
                script._print_failure(4, "state write/read", wrapped)
    finally:
        conn.close()

    stderr = capsys.readouterr().err
    assert f"code={code_prefix}_MATTERMOSTADAPTERERROR" in stderr
    assert "state operation wrapper" in stderr
    assert "no such table: absent_acceptance_table" in stderr
    assert "code=1 name=SQLITE_ERROR" in stderr
    assert "DIAGNOSTIC TRACEBACK BEGIN" in stderr
    assert "DIAGNOSTIC TRACEBACK END" in stderr


def test_integration_child_output_is_not_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    integration = load_script("accept_mattermost_macos_integration.py")
    observed: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(integration.subprocess, "run", fake_run)
    assert integration._run_local_diagnostic(["safeyolo", "check"], timeout=9) == 0
    assert observed["stdin"] is subprocess.DEVNULL
    assert "stdout" not in observed
    assert "stderr" not in observed


def test_acceptance_scripts_expose_only_bounded_arguments() -> None:
    for name in ("accept_mattermost_macos.py", "accept_mattermost_macos_integration.py"):
        path = REPO_ROOT / "scripts" / name
        result = subprocess.run(
            [sys.executable, str(path), "--help"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "cli" / "src")},
        )
        assert "--expected-head" in result.stdout
        assert "--expected-tree" in result.stdout
        assert "--expected-base" in result.stdout
        assert "token" not in result.stdout.lower()
