"""Retained guest entrypoint staging and native command execution."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from safeyolo.agents_store import save_agent
from safeyolo.vm import get_agent_home_dir, get_agent_status_dir, stage_guest_command_observation

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Guest process identity requires Linux /proc")


@pytest.fixture
def guest(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    save_agent("probe", {"agent_id": "ag-probe", "folder": str(tmp_path)})
    records = get_agent_status_dir("probe") / "guest-commands"
    records.mkdir(parents=True)
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"generation": "boot-1"}))
    source = Path(os.environ.get("SAFEYOLO_GUEST_HELPER", str(Path(__file__).resolve().parents[2] / "guest/command/target/debug/safeyolo-guest")))
    command = [str(source), "--context", str(context), "--records", str(records), "observe"]
    return command, records, context


def test_custom_script_without_shebang_preserves_arguments_and_exit_code(guest, tmp_path):
    script = tmp_path / "custom-command"
    script.write_text('printf "%s\\n" "$1"\nexit 7\n')
    script.chmod(0o755)
    result = subprocess.run([*guest[0], "exec", "--", str(script), "argument with spaces"], capture_output=True, text=True)
    assert result.returncode == 7, result.stderr
    assert result.stdout == "argument with spaces\n"


@pytest.mark.parametrize("entry_kind", ["file", "symlink"])
def test_boot_wraps_both_configured_entrypoints_and_reapplied_setup(guest, entry_kind):
    home = get_agent_home_dir("probe")
    home.mkdir(parents=True)
    for name in (".safeyolo-command", ".safeyolo-interactive-command"):
        path = home / name
        if entry_kind == "symlink":
            target = home / f"{name}.source"
            path.symlink_to(target.name)
            path = target
        path.write_text('#!/bin/sh\nexec custom-agent "$@"\n')
        path.chmod(0o755)
    payload_identities = {}
    stage_guest_command_observation(home, payload_identities)
    stage_guest_command_observation(home, payload_identities)
    for name in (".safeyolo-command", ".safeyolo-interactive-command"):
        assert (home / f"{name}.payload").read_text() == '#!/bin/sh\nexec custom-agent "$@"\n'
    entry = home / ".safeyolo-command"
    entry.write_text("#!/bin/sh\nexec replacement\n")
    stage_guest_command_observation(home, payload_identities)
    assert (home / ".safeyolo-command.payload").read_text() == "#!/bin/sh\nexec replacement\n"
    if entry_kind == "symlink":
        assert (home / ".safeyolo-command.source").read_text() == '#!/bin/sh\nexec custom-agent "$@"\n'
