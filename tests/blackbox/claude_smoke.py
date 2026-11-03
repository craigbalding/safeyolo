#!/usr/bin/env python3
"""Observe one native Claude tool task on a dedicated installed Ubuntu host.

The operator supplies a prepared instance with a host-held Claude subscription.
This instrument never imports a login, approves traffic or retries a model task.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .installed_host_smoke import SmokeError, _cli_identity, _process_start_token
    from .installed_sections import cleanup_instance, owned_processes
else:
    from installed_host_smoke import SmokeError, _cli_identity, _process_start_token
    from installed_sections import cleanup_instance, owned_processes

AGENT = "bbtest"
RESULT = "claude-smoke-result.txt"
TASK = (
    "Read /workspace/claude-smoke-marker.txt and "
    "/home/agent/.claude/skills/safeyolo/SKILL.md using tools. "
    "Write /workspace/claude-smoke-result.txt containing the marker followed by "
    "the first Markdown title (the line starting with '# ') in that skill, "
    "with one newline after each line. Complete this local task without network tools."
)
# Fetch at launch, just like claude-safeyolo. Neither the agent token nor the
# scoped token is interpolated by the host or passed on the command line.
GATEWAY_LAUNCH = r'''set -eu
set +x
export PATH="$HOME/.local/bin:$PATH"
agent_token=$(cat /app/agent_token)
services=$(printf 'Authorization: Bearer %s\n' "$agent_token" |
  curl --fail --silent --show-error --max-time 15 --header @- \
    http://_safeyolo.proxy.internal/gateway/services)
unset agent_token
CLAUDE_CODE_OAUTH_TOKEN=$(printf '%s' "$services" |
  jq -er '.authorized.claude.token | select(type == "string" and startswith("sgw_"))')
unset services
export CLAUDE_CODE_OAUTH_TOKEN
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
exec /home/agent/.safeyolo-command -p --verbose --output-format stream-json
'''


class SmokeFailure(Exception):
    """A categorical failure safe to publish without client or service text."""


def require_dedicated_instance(root: Path) -> None:
    if any((root / "agents").glob("*/home")):
        raise SmokeFailure("requires a dedicated instance with no prior agent homes")
    if owned_processes(root):
        raise SmokeFailure("requires a dedicated instance with no live owned processes")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def task_observation(records: list[dict], actual: bytes | None, expected: bytes) -> dict:
    """Adapt ubuntu_onboarding's paired tool/result and host effect observation.

    Accept Read/Write, shell tools or another successful tool sequence. Export
    identities and counts, never message contents, tool operands or raw errors.
    """
    calls = {}
    successful = set()
    sessions = set()
    finished = []
    models = set()
    for event in records:
        if event.get("session_id"):
            sessions.add(event["session_id"])
        message = event.get("message", {})
        if event.get("type") == "assistant" and message.get("model"):
            models.add(message["model"])
        blocks = message.get("content", [])
        for block in blocks if isinstance(blocks, list) else []:
            if event.get("type") == "assistant" and block.get("type") == "tool_use":
                calls[block["id"]] = block.get("name")
            if event.get("type") == "user" and block.get("type") == "tool_result":
                if block.get("is_error", False) is False and block.get("tool_use_id") in calls:
                    successful.add(block["tool_use_id"])
        if event.get("type") == "result":
            finished.append(event.get("subtype") == "success" and event.get("is_error") is False)
    complete = (len(sessions) == 1 and len(finished) == 1 and finished[0]
                and bool(successful) and bool(models) and actual == expected)
    return {"session_ids": sorted(sessions), "models": sorted(models),
            "tool_calls": len(calls), "successful_tool_results": len(successful),
            "tool_names": sorted({calls[key] for key in successful}),
            "client_completed": len(finished) == 1 and finished[0],
            "output_present": actual is not None, "output_matches": actual == expected,
            "output_sha256": sha256(actual) if actual is not None else None,
            "successful_task": bool(complete)}


def gateway_observation(records: list[dict], runtime: dict) -> list[dict]:
    """Select current native gateway decisions by their host-owned run scope."""
    expected = {"agent": AGENT, "agent_id": runtime["agent_id"], "run_id": runtime["run_id"]}
    matched = []
    for row in records:
        details = row.get("details", {})
        if (row.get("event") == "gateway.allow" and row.get("host") == "api.anthropic.com"
                and details.get("service") == "claude" and details.get("capability") == "inference"
                and details.get("path") == "/v1/messages" and row.get("request_id")
                and details.get("sandbox_run") == expected):
            matched.append({"request_id": row["request_id"], "sandbox_run": expected,
                            "service": "claude", "capability": "inference", "host": row["host"]})
    return matched


def check_staging(root: Path) -> dict:
    home = root / "agents" / AGENT / "home"
    baseline = home / ".safeyolo/AGENTS.md"
    shipped = root / "assets/docs/AGENTS.md"
    command = home / ".safeyolo-command"
    link = home / ".claude/skills/safeyolo"
    if baseline.read_bytes() != shipped.read_bytes():
        raise SmokeFailure("staged baseline differs from installed baseline")
    if not link.is_symlink() or os.readlink(link) != "/safeyolo/skills/safeyolo":
        raise SmokeFailure("staged Claude skill link differs")
    if not command.is_file() or not os.access(command, os.X_OK):
        raise SmokeFailure("staged command is missing or not executable")
    if (home / ".claude/.credentials.json").exists():
        raise SmokeFailure("unexpected client-held provider login")
    configuration = json.loads((home / ".claude.json").read_bytes())
    if (configuration.get("hasCompletedOnboarding") is not True
            or configuration.get("projects", {}).get("/workspace", {}).get("hasTrustDialogAccepted") is not True):
        raise SmokeFailure("staged Claude configuration is incomplete")
    return {"baseline_sha256": sha256(baseline.read_bytes()),
            "command_sha256": sha256(command.read_bytes()), "skill_link": os.readlink(link),
            "configuration_checked": True}


def check_sandbox(runtime: dict) -> dict:
    pid = runtime["backend_pid"]
    token = runtime["backend_token"]
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if (not token or _process_start_token(pid) != token or b"boot" not in arguments
            or b"--platform=systrap" not in arguments
            or ("safeyolo-" + runtime["run_id"]).encode() not in arguments):
        raise SmokeFailure("current gVisor systrap backend was not observed")
    return {"backend": "gvisor", "platform": "systrap", "process_identity_checked": True}


def native_setup(guest, report: dict) -> str:
    version = guest("native-setup", "exec /home/agent/.safeyolo-command --version", seconds=600)
    match = re.fullmatch(rb"\s*(\d+\.\d+\.\d+) \(Claude Code\)\s*", version)
    if match is None:
        raise SmokeFailure("selected client version was not observed")
    report["client_version"] = match[1].decode()
    staged = guest("guest-staging", r'''set -eu
test -r "$HOME/.safeyolo/AGENTS.md"
test -r "$HOME/.claude/skills/safeyolo/SKILL.md"
test ! -e "$HOME/.claude/.credentials.json"
p=$(mise where aqua:anthropics/claude-code)
test "$(od -An -tx1 -N4 "$p/claude" | tr -d ' \n')" = 7f454c46
sha256sum "$p/claude" "$HOME/.safeyolo/AGENTS.md" "$HOME/.claude/skills/safeyolo/SKILL.md"
awk '/^# / {print; exit}' "$HOME/.claude/skills/safeyolo/SKILL.md"
''')
    lines = staged.decode().splitlines()
    if (len(lines) != 4 or any(re.match(r"^[0-9a-f]{64}  /", line) is None for line in lines[:3])
            or lines[1].split()[0] != report["staging"]["baseline_sha256"] or not lines[3].startswith("# ")):
        raise SmokeFailure("native executable, baseline or readable skill was not observed")
    report["client_sha256"] = lines[0].split()[0]
    report["skill_sha256"] = lines[2].split()[0]
    return lines[3]


def completed_task(root: Path, workspace: Path, stream: bytes, expected: bytes, report: dict) -> None:
    records = [json.loads(line) for line in stream.splitlines() if line.strip()]
    result_path = workspace / RESULT
    actual = result_path.read_bytes() if result_path.is_file() else None
    report["task"] = task_observation(records, actual, expected)
    configuration = tomllib.loads((root / "config.toml").read_text())
    audit = Path(configuration.get("audit_log_path", "logs/audit.jsonl"))
    if not audit.is_absolute():
        audit = root / audit
    # A dedicated fresh agent and exact current sandbox_run distinguish this
    # task from retained decisions, including after audit rotation.
    with audit.open("rb") as events:
        audit_records = [json.loads(line) for line in events if line.strip()]
    report["gateway"] = gateway_observation(audit_records, report["runtime"])
    after = json.loads((root / "agents" / AGENT / "runtime.json").read_bytes())
    if any(after.get(key) != report["runtime"].get(key) for key in ("agent_id", "run_id")):
        raise SmokeFailure("sandbox run changed during the task")
    if sha256((root / "agents" / AGENT / "home/.safeyolo-command").read_bytes()) != report["staging"]["command_sha256"]:
        raise SmokeFailure("staged command changed during the task")
    if not report["task"]["successful_task"] or not report["gateway"]:
        raise SmokeFailure("completed tool task, host output and current gateway request did not agree")


def run(root: Path, workspace: Path, credential: str, output: Path, timeout: int) -> int:
    report = {"started_at": datetime.now(UTC).isoformat(), "status": "preparing", "steps": [],
              "service": "claude", "capability": "inference", "agent": AGENT,
              "model_attempts": 0, "cleanup": None}
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root), SAFEYOLO_LOGS_DIR=str(root / "logs"),
                       SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"), SAFEYOLO_CLAUDE_COPY_HOST_STATE="0",
                       SAFEYOLO_RUNSC_PLATFORM="systrap")
    cli = root / "bin/safeyolo"
    owned = False
    exit_code = 2

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")

    def command(label, arguments, *, seconds=180, stdin=None):
        row = {"step": label, "exit": None, "timed_out": False}
        report["steps"].append(row)
        save()
        started = time.monotonic()
        try:
            result = subprocess.run([str(cli), "--root", str(root), *arguments], env=environment,
                                    input=stdin, capture_output=True, timeout=seconds, check=False)
        except subprocess.TimeoutExpired:
            row["timed_out"] = True
            raise SmokeFailure(f"{label}: timeout") from None
        finally:
            row["seconds"] = round(time.monotonic() - started, 3)
            save()
        row["exit"] = result.returncode
        if result.returncode:
            # Preserve reached categories, without copying secret-bearing output.
            statuses = re.findall(rb"(?:API Error: |HTTP/\S+ )(\d{3})", result.stdout + result.stderr)
            row["http_statuses"] = sorted({int(value) for value in statuses})
            raise SmokeFailure(f"{label}: client or command failed")
        return result.stdout

    def guest(label, script, **options):
        return command(label, ["agent", "shell", AGENT, "-c", script], **options)

    save()
    try:
        if not credential:
            raise SmokeFailure("host Claude credential name is required")
        identity = _cli_identity(cli)
        fields = dict(line.split("=", 1) for line in (root / "package-info").read_text().splitlines())
        if identity["profile"] != "production" or fields["platform"] != "linux-amd64":
            raise SmokeFailure("requires an installed Linux AMD64 production package")
        report["source_revision"] = identity["source_revision"]
        report["cli_sha256"] = identity["sha256"]
        require_dedicated_instance(root)
        workspace.mkdir(parents=True, exist_ok=False)
        marker = uuid.uuid4().hex
        (workspace / "claude-smoke-marker.txt").write_text(marker + "\n")
        owned = True
        command("shipped-host-setup", ["agent", "create", AGENT, "--workspace", str(workspace),
                                      "--host-script", str(root / "assets/contrib/claude-host-setup.sh")])
        report["staging"] = check_staging(root)
        command("proxy-start", ["start"])
        command("coord-start", ["coord", "start"])
        command("service-authorization", ["services", "authorize", AGENT, "claude", "--capability",
                                          "inference", "--credential", credential])
        command("sandbox-start", ["agent", "start", AGENT, "--sandbox-only"])
        runtime_path = root / "agents" / AGENT / "runtime.json"
        runtime = json.loads(runtime_path.read_bytes())
        report["runtime"] = {key: runtime[key] for key in ("name", "agent_id", "run_id")}
        report["sandbox"] = check_sandbox(runtime)
        title = native_setup(guest, report)
        expected = (marker + "\n" + title + "\n").encode()
        report["model_attempts"] = 1
        stream = guest("claude-tool-task", GATEWAY_LAUNCH, seconds=timeout, stdin=TASK.encode())
        completed_task(root, workspace, stream, expected, report)
        report["status"] = "passed"
        exit_code = 0
    except (SmokeFailure, SmokeError, OSError, ValueError, KeyError, TypeError) as exc:
        report["status"] = "failed"
        report["failure"] = str(exc) if isinstance(exc, SmokeFailure) else type(exc).__name__
        exit_code = 1
    finally:
        if owned:
            # This is a dedicated instance, never the operator's shared proxy.
            report["cleanup_failures"] = cleanup_instance(cli, root)
            report["cleanup"] = "failed" if report["cleanup_failures"] else "stopped"
            if report["cleanup_failures"]:
                exit_code = 2
                report["status"] = "failed"
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["exit"] = exit_code
        save()
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True, help="New disk-backed workspace")
    parser.add_argument("--credential", required=True, help="Existing host encrypted-store credential name")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized JSON report")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return run(args.root.resolve(), args.workspace.resolve(), args.credential, args.output.resolve(), args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
