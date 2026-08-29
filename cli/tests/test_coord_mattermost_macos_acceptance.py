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


def test_preparer_creates_validated_private_single_channel_config_without_touching_live_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    preparer = load_script("prepare_mattermost_macos_test_config.py")
    integration = load_script("accept_mattermost_macos_integration.py")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    token_path = private / "bot-token"
    secret = "acceptance-token-that-must-not-be-printed"
    token_path.write_text(f"{secret}\n", encoding="utf-8")
    token_path.chmod(0o600)
    live_state = tmp_path / "live-state.sqlite3"
    live_state.write_text("untouched", encoding="utf-8")
    output = private / "dedicated-test.toml"

    created = preparer.create_config(
        output,
        server_url="https://mattermost.example",
        bot_token_file=str(token_path),
        bot_user_id="b" * 26,
        operator_user_id="o" * 26,
        coord_room="dedicated-test",
        channel_id="c" * 26,
    )

    assert created == output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert preparer.validate_config(output) == output
    config = mattermost.load_config(output)
    assert config.rooms == (mattermost.RoomMapping("dedicated-test", "c" * 26, False),)
    assert config.bot_token_file == private / ".dedicated-test.bot-token"
    assert config.state_file.parent == private
    assert config.state_file.name.endswith(".integration-source-state.sqlite3")
    assert not config.state_file.exists()
    raw = output.read_text(encoding="utf-8")
    assert 'bot_token_file = ".dedicated-test.bot-token"' in raw
    assert 'state_file = ".dedicated-test.integration-source-state.sqlite3"' in raw
    assert str(private) not in raw
    integration._validate_test_source(output, config)
    assert live_state.read_text(encoding="utf-8") == "untouched"
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_prepared_bundle_validates_after_relocation(tmp_path: Path) -> None:
    preparer = load_script("prepare_mattermost_macos_test_config.py")
    integration = load_script("accept_mattermost_macos_integration.py")
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    source_token = source / "source-token"
    source_token.write_text("portable-token\n", encoding="utf-8")
    source_token.chmod(0o600)
    original_bundle = tmp_path / "original-bundle"
    original_bundle.mkdir(mode=0o700)
    preparer.create_config(
        original_bundle / "dedicated-test.toml",
        server_url="https://mattermost.example",
        bot_token_file=str(source_token),
        bot_user_id="b" * 26,
        operator_user_id="o" * 26,
        coord_room="dedicated-test",
        channel_id="c" * 26,
    )

    relocated_bundle = tmp_path / "different-absolute-bundle"
    original_bundle.rename(relocated_bundle)
    relocated_config = relocated_bundle / "dedicated-test.toml"
    assert preparer.validate_config(relocated_config) == relocated_config
    config = mattermost.load_config(relocated_config)
    assert config.bot_token_file == relocated_bundle / ".dedicated-test.bot-token"
    assert config.state_file == relocated_bundle / ".dedicated-test.integration-source-state.sqlite3"
    integration._validate_test_source(relocated_config, config)
    assert source_token.read_text(encoding="utf-8") == "portable-token\n"

    relocated_bundle.chmod(0o755)
    with pytest.raises(preparer.PreparationError, match="must not be accessible"):
        preparer.validate_config(relocated_config)
    with pytest.raises(integration.AcceptanceError, match="private regular directory"):
        integration._private_regular_config(relocated_config)


def test_preparer_never_overwrites_reserved_bundle_token(tmp_path: Path) -> None:
    preparer = load_script("prepare_mattermost_macos_test_config.py")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    source_token = private / "source-token"
    source_token.write_text("source\n", encoding="utf-8")
    source_token.chmod(0o600)
    reserved = private / ".dedicated-test.bot-token"
    reserved.write_text("untouched\n", encoding="utf-8")
    reserved.chmod(0o600)

    with pytest.raises(preparer.PreparationError, match="refusing to overwrite"):
        preparer.create_config(
            private / "dedicated-test.toml",
            server_url="https://mattermost.example",
            bot_token_file=str(source_token),
            bot_user_id="b" * 26,
            operator_user_id="o" * 26,
            coord_room="dedicated-test",
            channel_id="c" * 26,
        )
    assert reserved.read_text(encoding="utf-8") == "untouched\n"
    assert not (private / "dedicated-test.toml").exists()


def test_preparer_refuses_live_default_config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    preparer = load_script("prepare_mattermost_macos_test_config.py")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    live_config = private / "coord-mattermost.toml"
    monkeypatch.setattr(preparer, "_LIVE_CONFIG", live_config)

    with pytest.raises(preparer.PreparationError, match="live default config"):
        preparer._output_path(live_config)


def test_integration_refuses_existing_source_state(tmp_path: Path) -> None:
    preparer = load_script("prepare_mattermost_macos_test_config.py")
    integration = load_script("accept_mattermost_macos_integration.py")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    token_path = private / "bot-token"
    token_path.write_text("test-token\n", encoding="utf-8")
    token_path.chmod(0o600)
    output = preparer.create_config(
        private / "dedicated-test.toml",
        server_url="https://mattermost.example",
        bot_token_file=str(token_path),
        bot_user_id="b" * 26,
        operator_user_id="o" * 26,
        coord_room="dedicated-test",
        channel_id="c" * 26,
    )
    config = mattermost.load_config(output)
    config.state_file.write_text("must not be used", encoding="utf-8")
    config.state_file.chmod(0o600)

    with pytest.raises(integration.AcceptanceError, match="must not already exist"):
        integration._validate_test_source(output, config)


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

    preparer = REPO_ROOT / "scripts" / "prepare_mattermost_macos_test_config.py"
    result = subprocess.run(
        [sys.executable, str(preparer), "--help"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "cli" / "src")},
    )
    assert "--output" in result.stdout
    assert "--validate" in result.stdout
