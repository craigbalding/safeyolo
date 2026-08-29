from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType

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
        assert "--expected-base" in result.stdout
        assert "token" not in result.stdout.lower()
