"""Controlled native CLI outputs for the G7 driver's staged command boundary."""

import json
import os
import sys
import time
from pathlib import Path

if sys.argv[1:] == ["--version"]:
    print(f"{Path(sys.argv[0]).name} 0.1.0 commit=fixture profile=debug")
    sys.exit(0)

assert sys.argv[1] == "--root"
root = Path(sys.argv[2])
parts = sys.argv[3:]
data = json.loads(Path(os.environ["G7_FIXTURE"]).read_text())
failure = os.environ.get("G7_FAILURE")
home = root / "agents/g7/home"
with (root.parent / "calls").open("a") as log:
    log.write(json.dumps(parts) + "\n")

failed_command = json.loads(os.environ.get("G7_FAIL_COMMAND", "[]"))
if failed_command and parts[:len(failed_command)] == failed_command:
    print("original command stdout\nretained ünicode", flush=True)
    print("original command stderr\nretained refusal", file=sys.stderr, flush=True)
    if os.environ.get("G7_COMMAND_TIMEOUT"):
        time.sleep(5)
    sys.exit(23)

if parts[:2] == ["agent", "create"]:
    if os.environ.get("G7_FAIL_SETUP"):
        sys.exit(0)
    files = {".codex/config.toml": '[mcp_servers.safeyolo-coord]\ncommand = "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"\n',
             ".safeyolo/AGENTS.md": (root / "assets/docs/AGENTS.md").read_text(),
             ".g7-codex-command": (root / "assets/contrib/codex-command.sh").read_text(),
             ".safeyolo-command": "#!/bin/sh\nexit 0\n", ".safeyolo/safeyolo-coord-mcp-launcher": "#!/bin/sh\nexit 0\n"}
    for name, content in files.items():
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o600 if name.endswith(".toml") else 0o755)
    (home / ".codex").chmod(0o700)
    (home / ".agents/skills").mkdir(parents=True)
    (home / ".agents/skills/safeyolo").symlink_to("/safeyolo/skills/safeyolo")
    coord = home / ".safeyolo/safeyolo-coord"
    coord.write_bytes((root / "assets/guest/safeyolo-coord").read_bytes())
    coord.chmod(0o755)
elif parts[:2] == ["coord", "grant"]:
    print(json.dumps(data["grant"]))
elif parts[:2] == ["agent", "start"]:
    data["room"], data["marker"] = parts[-2:]
    joined = json.loads(data["guest_files"]["join.json"])
    joined["room_name"] = joined["state"]["room_name"] = data["room"]
    data["guest_files"]["join.json"] = json.dumps(joined)
    sent = json.loads(data["guest_files"]["send.json"])
    sent["envelope"]["body"] = data["marker"]
    data["guest_files"]["send.json"] = json.dumps(sent)
    data["host_history"][0]["body"] = data["marker"]
    read = json.loads(data["guest_files"]["read.json"])
    read["messages"] = data["host_history"]
    data["guest_files"]["read.json"] = json.dumps(read)
    Path(os.environ["G7_FIXTURE"]).write_text(json.dumps(data))
    for name, content in data["guest_files"].items():
        path = home / ".g7" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for path, value in ((home / ".safeyolo-command-supervisor.json", data["current_supervisor"]),
                        (root / "agents/g7/current-launch.json", data["current_launch"]),
                        (root / "agents/g7/config-share/host-launch-context.json", data["context"])):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
    (root / "data/instance_id").write_text(data["instance_id"])
elif parts[:2] == ["agent", "status"]:
    print(json.dumps(data["status"]))
elif parts[:2] == ["coord", "history"]:
    for message in data["host_history"]:
        print(json.dumps(message))
elif parts[:2] == ["agent", "diagnostics"]:
    print(json.dumps(data["vz_helper"]["private_control"]))
elif parts[:2] == ["agent", "shell"]:
    assert parts[2:4] == ["g7", "-c"]
    if parts[4] == "/safeyolo/safeyolo-guest observe check":
        if failure == "guest-check":
            print("stopped")
            print("fixture observation refusal", file=sys.stderr)
            sys.exit(7)
        print("running")
    elif parts[4] == "/safeyolo/safeyolo-guest supervise check":
        print(data["guest_checks"]["supervise"]["stdout"])
    else:
        assert "cat /proc/sys/kernel/random/boot_id" in parts[4]
        output = home / ".g7/proc"
        output.mkdir()
        (output / "boot_id").write_text(data["guest_processes"]["boot_id"])
        for pid, row in data["guest_processes"]["processes"].items():
            for name, content in row.items():
                (output / f"{pid}.{name}").write_text(content)
elif parts == ["agent", "stop", "g7"] and failure == "cleanup":
    print("fixture stop refusal", file=sys.stderr)
    sys.exit(9)
