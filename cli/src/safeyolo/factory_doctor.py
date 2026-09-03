"""Read-only health inspection for an active supervised factory."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .agents_store import load_agent
from .api import AdminAPI
from .config import get_agents_dir
from .coord import api as coord_api
from .coord import nats_runtime as coord_nats
from .factory_contract import FactoryContractError, load_active_snapshot
from .platform import AgentPlatform, get_platform

DoctorStatus = Literal["PASS", "WARN", "FAIL"]
_AGENT_ID_RE = re.compile(r"ag-[0-9a-f]{32}")
_ATTENTION_ID_RE = re.compile(r"attn-[0-9a-f]{32}")
_SIMPLE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
_MESSAGE_FIELD_RE = re.compile(r"([A-Za-z][A-Za-z0-9_-]*)=([^\s=]+)")
_NON_CORRELATION_FIELDS = {"assignee", "attention_id"}
_MAX_CANONICAL_BODY_BYTES = 64 * 1024
_BACKLOG_COORDINATOR_CONTRACT_SHA256 = (
    "13f1bfd1a670a1f1d0fe4803784ea35c545a751ecf7c44fceba77027bae0d6e3"
)
_STATE_KEYS = {
    "version",
    "thread_id",
    "safe_cursor",
    "recent_attention_ids",
    "in_flight",
    "awaiting_handoffs",
    "briefs",
    "consecutive_failures",
    "owned_process",
}
_MAX_STATE_BYTES = 2 * 1024 * 1024
_SUPERVISOR_LIMITS = {
    "wait_seconds": (1, 300, 300),
    "page_limit": (1, 16, 16),
    "startup_timeout_seconds": (30, 3600, 480),
    "work_timeout_seconds": (30, 86400, 3600),
    "completion_grace_seconds": (5, 600, 90),
    "terminate_grace_seconds": (1, 60, 10),
    "backoff_initial_seconds": (1, 300, 5),
    "backoff_max_seconds": (1, 3600, 300),
}
_COMMAND_HEREDOC_START = 'cat > "$AGENT_HOME/.safeyolo-command" <<\'EOF\'\n'
_COMMAND_HEREDOC_END = '\nEOF\nchmod +x "$AGENT_HOME/.safeyolo-command"'
_INTERACTIVE_CODEX_EXEC = 'exec codex "${args[@]}" "$@"\n'
_SUPERVISED_CODEX_EXEC = (
    'exec python3 "$HOME/.safeyolo/codex-coord-supervisor.py" '
    '-- "${supervised_args[@]}" "$@"\n'
)
_COORD_INSTALL_BLOCK = (
    "# ---- coord-mcp-bootstrap: mcp+httpx install (guarded, idempotent) ----\n"
    'SY_COORD_VENV="$HOME/.safeyolo/venv"\n'
    "if ! \"$SY_COORD_VENV/bin/python\" -c 'import httpx; "
    "from mcp.server.mcpserver import MCPServer' >/dev/null 2>&1; then\n"
    '    if ! { python3 -m venv "$SY_COORD_VENV" \\\n'
    '        && "$SY_COORD_VENV/bin/pip" install --quiet "mcp>=2.0" "httpx>=0.25"; } >&2; then\n'
    '        echo "coord-mcp: could not install mcp+httpx into $SY_COORD_VENV;'
    ' refusing to start the harness without safeyolo-coord" >&2\n'
    "        exit 1\n"
    "    fi\n"
    "    if ! \"$SY_COORD_VENV/bin/python\" -c 'import httpx; "
    "from mcp.server.mcpserver import MCPServer' >/dev/null 2>&1; then\n"
    '        echo "coord-mcp: dependency verification failed in $SY_COORD_VENV;'
    ' refusing to start the harness without safeyolo-coord" >&2\n'
    "        exit 1\n"
    "    fi\n"
    "fi\n"
    "\n"
)
_PROCESS_EXECUTABLE_MARKER = "__SAFEYOLO_PROCESS_EXECUTABLES__"
_PROCESS_EXPECTED_MARKER = "__SAFEYOLO_EXPECTED_EXECUTABLES__"
_PROCESS_STAT_MARKER = "__SAFEYOLO_OWNED_PROCESS_STAT__"


@dataclass(frozen=True)
class FactoryDoctorCheck:
    """One bounded, non-sensitive factory diagnostic."""

    status: DoctorStatus
    component: str
    detail: str
    recovery: str | None = None


@dataclass(frozen=True)
class FactoryDoctorReport:
    """The ordered result of one factory inspection."""

    name: str
    checks: tuple[FactoryDoctorCheck, ...]

    @property
    def status(self) -> DoctorStatus:
        statuses = {item.status for item in self.checks}
        if "FAIL" in statuses:
            return "FAIL"
        if "WARN" in statuses:
            return "WARN"
        return "PASS"


def inspect_factory(name: str) -> FactoryDoctorReport:
    """Inspect one active factory without starting or changing anything."""
    checks: list[FactoryDoctorCheck] = []
    payload: dict[str, Any] | None = None
    snapshot_path: Path | None = None
    try:
        identifier, snapshot_path, payload = load_active_snapshot(name)
    except (FactoryContractError, OSError) as exc:
        checks.append(
            _fail(
                "snapshot",
                f"active snapshot is invalid ({type(exc).__name__})",
                "factory snapshot; run `safeyolo factory check FILE` then `safeyolo factory apply FILE`",
            )
        )
    else:
        checks.append(
            FactoryDoctorCheck(
                "PASS",
                "snapshot",
                f"active snapshot={identifier} schema={payload['schema']}",
            )
        )

    _inspect_proxy(checks)
    _inspect_nats(checks)
    if payload is None or snapshot_path is None:
        return FactoryDoctorReport(name, tuple(checks))

    _inspect_room(checks, payload)
    _inspect_brief(checks, payload)
    try:
        platform = get_platform()
    except Exception as exc:  # platform availability is itself a diagnostic
        checks.append(
            _fail(
                "sandbox-platform",
                f"platform is unavailable ({type(exc).__name__})",
                "sandbox platform; run `safeyolo doctor`",
            )
        )
        platform = None

    for role_name, role in payload["roles"].items():
        _inspect_role(
            checks,
            name=name,
            role_name=role_name,
            role=role,
            payload=payload,
            snapshot_path=snapshot_path,
            platform=platform,
        )
    return FactoryDoctorReport(name, tuple(checks))


def _fail(component: str, detail: str, recovery: str) -> FactoryDoctorCheck:
    return FactoryDoctorCheck("FAIL", component, detail, recovery)


def _proxy_is_healthy() -> bool:
    try:
        health = AdminAPI(token="factory-doctor", timeout=2.0).health()
    except Exception:
        return False
    return health == {"status": "ok"}


def _inspect_proxy(checks: list[FactoryDoctorCheck]) -> None:
    if _proxy_is_healthy():
        checks.append(FactoryDoctorCheck("PASS", "proxy", "traffic proxy is running"))
    else:
        checks.append(_fail("proxy", "traffic proxy is not running", "proxy runtime; run `safeyolo start`"))


def _inspect_nats(checks: list[FactoryDoctorCheck]) -> None:
    try:
        current = coord_nats.status()
    except Exception as exc:
        checks.append(
            _fail(
                "coord-nats",
                f"managed NATS state is unreadable ({type(exc).__name__})",
                "managed Coord/NATS runtime; run `safeyolo status`",
            )
        )
        return
    state = current.get("state")
    if current.get("healthy") is True and state == "healthy":
        checks.append(FactoryDoctorCheck("PASS", "coord-nats", "managed NATS is healthy"))
    else:
        checks.append(
            _fail(
                "coord-nats",
                f"managed NATS state={state or 'unknown'}",
                "managed Coord/NATS runtime; run `safeyolo status` then `safeyolo start`",
            )
        )


def _inspect_room(checks: list[FactoryDoctorCheck], payload: dict[str, Any]) -> None:
    room_name = payload["room"]
    principals = [("operator", "operator")]
    labels = {"operator:operator": "operator"}
    for role in payload["roles"].values():
        agent_name = role["agent"]
        try:
            metadata = load_agent(agent_name)
        except Exception:
            continue
        agent_id = metadata.get("agent_id") if isinstance(metadata, dict) else None
        if isinstance(agent_id, str) and ("agent", agent_id) not in principals:
            principals.append(("agent", agent_id))
            labels[f"agent:{agent_id}"] = f"agent={agent_name}"
    try:
        room = coord_api.inspect_room_access(room_name, principals)
    except Exception as exc:
        checks.append(
            _fail(
                "coord-room",
                f"room or required membership is unavailable ({type(exc).__name__})",
                f"Coord room and grants for room={room_name}",
            )
        )
        return
    checks.append(
        FactoryDoctorCheck(
            "PASS",
            "coord-room",
            f"room={room_name} id={room.get('room_id', 'unknown')} exists",
        )
    )
    for principal, permissions in room["permissions"].items():
        label = labels[principal]
        missing = sorted({"send", "receive"} - set(permissions))
        if missing:
            checks.append(
                _fail(
                    "coord-grant",
                    f"{label} room={room_name} missing={','.join(missing)}",
                    f"Coord grants for {label} in room={room_name}",
                )
            )
        else:
            checks.append(
                FactoryDoctorCheck(
                    "PASS",
                    "coord-grant",
                    f"{label} room={room_name} send,receive",
                )
            )


def _inspect_brief(  # DOC: docs/factories.md
    checks: list[FactoryDoctorCheck], payload: dict[str, Any]
) -> None:
    room_name = payload["room"]
    try:
        current = coord_api.show_brief(room_name)
    except Exception as exc:
        checks.append(
            _fail(
                "coord-brief",
                f"room={room_name} brief state is unavailable ({type(exc).__name__})",
                f"trusted brief; run `safeyolo coord brief show {room_name}`",
            )
        )
        return

    revision = current.get("revision") if isinstance(current, dict) else None
    content_hash = current.get("content_hash") if isinstance(current, dict) else None
    if revision == 0 and content_hash is None:
        mode = ""
        operator_input = payload["operator_input"]
        if payload["name"] == "backlog" and "NEXT" in operator_input["types"]:
            operator_role = payload["roles"][operator_input["to"]]
            if operator_role["contract_sha256"] == _BACKLOG_COORDINATOR_CONTRACT_SHA256:
                mode = " role-contract-intake=valid"
        checks.append(
            FactoryDoctorCheck(
                "PASS",
                "coord-brief",
                f"room={room_name} state=none{mode} "
                f"show=`safeyolo coord brief show {room_name}` "
                f"set=`safeyolo coord brief set {room_name} --file BRIEF.md "
                "--expected-revision 0`",
            )
        )
        return
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision <= 0
        or not isinstance(content_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", content_hash) is None
    ):
        checks.append(
            _fail(
                "coord-brief",
                f"room={room_name} brief metadata is invalid",
                f"trusted brief; run `safeyolo coord brief show {room_name}`",
            )
        )
        return
    checks.append(
        FactoryDoctorCheck(
            "PASS",
            "coord-brief",
            f"room={room_name} revision={revision} content_hash={content_hash} "
            "body=not-inspected meaning=operator-owned "
            f"show=`safeyolo coord brief show {room_name}` "
            f"set=`safeyolo coord brief set {room_name} --file BRIEF.md "
            f"--expected-revision {revision}`",
        )
    )


def _inspect_agent_room(
    checks: list[FactoryDoctorCheck],
    label: str,
    factory_name: str,
    agent_name: str,
    agent_id: str,
) -> None:
    room_name = f"{agent_name}-agent"
    principals = [("operator", "operator"), ("agent", agent_id)]
    try:
        room = coord_api.inspect_room_access(room_name, principals)
    except Exception as exc:
        checks.append(
            _fail(
                "agent-room",
                f"{label} room={room_name} is unavailable ({type(exc).__name__})",
                f"agent room; run `safeyolo factory run {factory_name}`",
            )
        )
        return
    checks.append(
        FactoryDoctorCheck(
            "PASS",
            "agent-room",
            f"{label} room={room_name} id={room.get('room_id', 'unknown')} exists",
        )
    )
    for principal, subject in (
        ("operator:operator", "operator"),
        (f"agent:{agent_id}", agent_name),
    ):
        permissions = room["permissions"].get(principal, [])
        missing = sorted({"send", "receive"} - set(permissions))
        if missing:
            checks.append(
                _fail(
                    "agent-room-grant",
                    f"{label} subject={subject} room={room_name} missing={','.join(missing)}",
                    f"agent-room grants; run `safeyolo factory run {factory_name}`",
                )
            )
        else:
            checks.append(
                FactoryDoctorCheck(
                    "PASS",
                    "agent-room-grant",
                    f"{label} subject={subject} room={room_name} send,receive",
                )
            )


def _inspect_role(
    checks: list[FactoryDoctorCheck],
    *,
    name: str,
    role_name: str,
    role: dict[str, Any],
    payload: dict[str, Any],
    snapshot_path: Path,
    platform: AgentPlatform | None,
) -> None:
    agent_name = role["agent"]
    label = f"role={role_name} agent={agent_name}"
    try:
        metadata = load_agent(agent_name)
    except Exception as exc:
        checks.append(
            _fail(
                "agent-identity",
                f"{label} configuration is unreadable ({type(exc).__name__})",
                f"policy.toml [agents.{agent_name}]",
            )
        )
        return
    if not metadata:
        checks.append(
            _fail(
                "agent-identity",
                f"{label} is not configured",
                f"agent identity; run `safeyolo agent add {agent_name}`",
            )
        )
        return
    agent_id = metadata.get("agent_id")
    if not isinstance(agent_id, str) or _AGENT_ID_RE.fullmatch(agent_id) is None:
        checks.append(
            _fail(
                "agent-identity",
                f"{label} has an invalid durable identity",
                f"policy.toml [agents.{agent_name}].agent_id",
            )
        )
    else:
        checks.append(FactoryDoctorCheck("PASS", "agent-identity", f"{label} id={agent_id}"))
        _inspect_agent_room(checks, label, name, agent_name, agent_id)

    folder = metadata.get("folder")
    try:
        workspace = _resolve_configured_path(folder)
        workspace_exists = workspace.is_dir()
    except (OSError, RuntimeError, ValueError):
        workspace = None
        workspace_exists = False
    if workspace is None:
        checks.append(
            _fail(
                "workspace",
                f"{label} configured workspace path is invalid",
                f"agent workspace; run `safeyolo agent config {agent_name} --folder PATH`",
            )
        )
    elif not workspace_exists:
        checks.append(
            _fail(
                "workspace",
                f"{label} workspace is missing",
                f"agent workspace; run `safeyolo agent config {agent_name} --folder PATH`",
            )
        )
    else:
        checks.append(FactoryDoctorCheck("PASS", "workspace", f"{label} workspace={workspace}"))

    agent_dir = get_agents_dir() / agent_name
    home = agent_dir / "home"
    if not agent_dir.is_dir() or not home.is_dir():
        checks.append(
            _fail(
                "sandbox-storage",
                f"{label} persistent sandbox home is missing",
                f"agent sandbox storage; run `safeyolo factory run {name}`",
            )
        )
    else:
        checks.append(FactoryDoctorCheck("PASS", "sandbox-storage", f"{label} persistent home exists"))

    running = False
    if platform is not None:
        try:
            rootfs = platform.agent_rootfs_path(agent_name)
            rootfs_exists = rootfs.exists()
            running = platform.is_sandbox_running(agent_name)
        except Exception as exc:
            checks.append(
                _fail(
                    "sandbox-runtime",
                    f"{label} runtime state is unreadable ({type(exc).__name__})",
                    f"agent sandbox runtime; run `safeyolo agent status {agent_name}`",
                )
            )
        else:
            if rootfs_exists:
                checks.append(FactoryDoctorCheck("PASS", "sandbox-storage", f"{label} rootfs exists"))
            else:
                checks.append(
                    _fail(
                        "sandbox-storage",
                        f"{label} rootfs is missing",
                        f"agent rootfs; run `safeyolo factory run {name}`",
                    )
                )
            if running:
                checks.append(FactoryDoctorCheck("PASS", "sandbox-runtime", f"{label} state=running"))
            else:
                checks.append(
                    FactoryDoctorCheck(
                        "WARN",
                        "sandbox-runtime",
                        f"{label} state=stopped",
                        f"run `safeyolo factory run {name}`",
                    )
                )

    _inspect_host_script(checks, label, metadata)
    _inspect_staging(checks, name, label, role_name, role, payload, snapshot_path, home)
    owned_process = _inspect_checkpoint(checks, name, label, home)
    if running and platform is not None:
        _inspect_processes(checks, label, agent_name, platform, owned_process)


def _resolve_configured_path(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("configured path is invalid")
    return Path(value).expanduser().resolve()


def _inspect_host_script(checks: list[FactoryDoctorCheck], label: str, metadata: dict[str, Any]) -> None:
    value = metadata.get("host_script")
    try:
        path = _resolve_configured_path(value)
    except (OSError, RuntimeError, ValueError):
        checks.append(
            _fail(
                "host-script",
                f"{label} configured host-script path is invalid",
                "agent host_script binding; run `safeyolo factory run FACTORY`",
            )
        )
        return
    try:
        expected = _bundled_contrib_path("codex-coord-host-setup.sh")
        content_matches = _bounded_bytes(path, 512 * 1024) == _bounded_bytes(expected, 512 * 1024)
    except (OSError, ValueError):
        content_matches = False
    if (
        path.name != "codex-coord-host-setup.sh"
        or not path.is_file()
        or not os.access(path, os.X_OK)
        or not content_matches
    ):
        checks.append(
            _fail(
                "host-script",
                f"{label} is not bound to executable @codex-coord setup",
                "agent host_script binding; run `safeyolo factory run FACTORY`",
            )
        )
    else:
        checks.append(FactoryDoctorCheck("PASS", "host-script", f"{label} uses @codex-coord"))


def _expected_supervisor_config(agent_name: str, role_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    role_agents = {key: value["agent"] for key, value in payload["roles"].items()}
    runtime_handoffs = [
        {
            **handoff,
            "response_to": handoff.get("response_to", [handoff["from"]]),
        }
        for handoff in payload["handoffs"]
    ]
    coordinators: list[str] = []
    for handoff in runtime_handoffs:
        candidate = role_agents[handoff["from"]]
        if handoff["request"] == "TASK" and candidate not in coordinators:
            coordinators.append(candidate)
    return {
        "agent_name": agent_name,
        "agent_room": f"{agent_name}-agent",
        "rooms": [payload["room"]],
        "coordinators": coordinators,
        "workspace": "/workspace",
        "factory": {
            "schema": payload["schema"],
            "name": payload["name"],
            "role": role_name,
            "roles": role_agents,
            "handoffs": runtime_handoffs,
            "operator_input": payload["operator_input"],
            "contract_sha256": payload["roles"][role_name]["contract_sha256"],
        },
    }


def _validate_supervisor_config(staged: Any, expected: dict[str, Any]) -> None:
    if not isinstance(staged, dict):
        raise ValueError("supervisor config is not an object")
    allowed = set(expected) | set(_SUPERVISOR_LIMITS)
    if set(staged) - allowed:
        raise ValueError("supervisor config has unknown fields")
    if any(staged.get(key) != value for key, value in expected.items()):
        raise ValueError("supervisor config does not match factory binding")
    values = {}
    for key, (minimum, maximum, default) in _SUPERVISOR_LIMITS.items():
        value = staged.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError("supervisor config has an invalid runtime limit")
        values[key] = value
    if values["backoff_max_seconds"] < values["backoff_initial_seconds"]:
        raise ValueError("supervisor backoff bounds are invalid")


def _inspect_staging(
    checks: list[FactoryDoctorCheck],
    name: str,
    label: str,
    role_name: str,
    role: dict[str, Any],
    payload: dict[str, Any],
    snapshot_path: Path,
    home: Path,
) -> None:
    recovery = f"staged factory files; run `safeyolo factory run {name}`"
    command = home / ".safeyolo-command"
    supervisor = home / ".safeyolo/codex-coord-supervisor.py"
    supervisor_config = home / ".safeyolo/codex-coord-supervisor.json"
    mcp_server = home / ".safeyolo/safeyolo-coord-mcp.py"
    launcher = home / ".safeyolo/safeyolo-coord-mcp-launcher"
    instructions = home / ".safeyolo/AGENTS.md"
    required_executable = (command, supervisor, mcp_server, launcher)
    missing = [path.name for path in required_executable if not path.is_file() or not os.access(path, os.X_OK)]
    if missing or not supervisor_config.is_file() or not instructions.is_file():
        names = missing[:]
        if not supervisor_config.is_file():
            names.append(supervisor_config.name)
        if not instructions.is_file():
            names.append(instructions.name)
        checks.append(_fail("staging", f"{label} missing or non-executable={','.join(names)}", recovery))
        return
    try:
        command_text = _bounded_text(command, 512 * 1024)
        staged = _bounded_json(supervisor_config, 512 * 1024)
        instructions_text = _bounded_text(instructions, 2 * 1024 * 1024)
        expected_command = _expected_supervised_command()
        expected_artifacts = {
            supervisor: _bundled_contrib_path("codex-coord-supervisor.py"),
            mcp_server: _bundled_contrib_path("safeyolo-coord-mcp.py"),
            launcher: _bundled_contrib_path("safeyolo-coord-mcp-launcher.sh"),
        }
        expected_instructions = _expected_staged_instructions(role["contract_text"])
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        checks.append(_fail("staging", f"{label} staged files are unreadable ({type(exc).__name__})", recovery))
        return
    if command_text != expected_command:
        checks.append(_fail("staging", f"{label} staged command does not match the supervised launcher", recovery))
        return
    try:
        mismatched = [
            path.name
            for path, expected in expected_artifacts.items()
            if _bounded_bytes(path, 2 * 1024 * 1024) != _bounded_bytes(expected, 2 * 1024 * 1024)
        ]
    except (OSError, ValueError) as exc:
        checks.append(_fail("staging", f"{label} staged files are unreadable ({type(exc).__name__})", recovery))
        return
    if mismatched:
        checks.append(_fail("staging", f"{label} staged artifact does not match={','.join(mismatched)}", recovery))
        return
    expected = _expected_supervisor_config(role["agent"], role_name, payload)
    try:
        _validate_supervisor_config(staged, expected)
    except ValueError:
        checks.append(
            _fail("staging", f"{label} supervisor config does not match the active snapshot and role", recovery)
        )
        return
    if instructions_text != expected_instructions:
        checks.append(_fail("staging", f"{label} staged role contract does not match the active snapshot", recovery))
        return
    if not snapshot_path.is_file():
        checks.append(_fail("staging", f"{label} bound snapshot is missing", recovery))
        return
    try:
        codex_config = tomllib.loads(_bounded_text(home / ".codex/config.toml", 512 * 1024))
        mcp = codex_config["mcp_servers"]["safeyolo-coord"]
        timeout = mcp.get("tool_timeout_sec")
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        checks.append(_fail("staging", f"{label} Codex MCP config is unreadable ({type(exc).__name__})", recovery))
        return
    if (
        mcp.get("command") != "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
        or mcp.get("args") != []
        or (
            timeout is not None
            and (
                isinstance(timeout, bool)
                or not isinstance(timeout, int | float)
                or timeout <= 0
            )
        )
    ):
        checks.append(_fail("staging", f"{label} Codex MCP binding or timeout is invalid", recovery))
        return
    checks.append(FactoryDoctorCheck("PASS", "staging", f"{label} command, supervisor, role, and MCP binding match"))


def _bounded_text(path: Path, maximum: int) -> str:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError("file exceeds diagnostic size limit")
    return path.read_text()


def _bounded_bytes(path: Path, maximum: int) -> bytes:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError("file exceeds diagnostic size limit")
    return path.read_bytes()


def _bundled_path(directory: str, filename: str) -> Path:
    package = Path(__file__).resolve().parent
    candidates = (
        package / directory / filename,
        package.parent.parent.parent / directory / filename,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(filename)


def _bundled_contrib_path(filename: str) -> Path:
    return _bundled_path("contrib", filename)


def _expected_staged_instructions(contract_text: str) -> str:
    baseline = _bounded_text(_bundled_path("docs", "AGENTS.md"), 2 * 1024 * 1024)
    return baseline.rstrip() + "\n\n---\n\n" + contract_text.lstrip()


def _expected_supervised_command() -> str:
    source = _bounded_text(_bundled_contrib_path("codex-host-setup.sh"), 2 * 1024 * 1024)
    if source.count(_COMMAND_HEREDOC_START) != 1:
        raise ValueError("cannot locate staged command template")
    template = source.split(_COMMAND_HEREDOC_START, 1)[1]
    if template.count(_COMMAND_HEREDOC_END) != 1:
        raise ValueError("cannot locate staged command terminator")
    command = template.split(_COMMAND_HEREDOC_END, 1)[0] + "\n"
    if command.count(_INTERACTIVE_CODEX_EXEC) != 1:
        raise ValueError("cannot locate Codex command handoff")
    command = command.replace(_INTERACTIVE_CODEX_EXEC, _SUPERVISED_CODEX_EXEC)
    if command.count(_SUPERVISED_CODEX_EXEC) != 1:
        raise ValueError("cannot construct supervised command handoff")
    return command.replace(_SUPERVISED_CODEX_EXEC, _COORD_INSTALL_BLOCK + _SUPERVISED_CODEX_EXEC)


def _bounded_json(path: Path, maximum: int) -> Any:
    return json.loads(_bounded_text(path, maximum))


def _inspect_checkpoint(
    checks: list[FactoryDoctorCheck], name: str, label: str, home: Path
) -> dict[str, Any] | None:
    path = home / ".safeyolo/codex-coord-supervisor-state.json"
    recovery = f"supervisor checkpoint for {label}; run `safeyolo factory run {name}`"
    try:
        state = _bounded_json(path, _MAX_STATE_BYTES)
        summary = _validate_checkpoint(state)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        checks.append(_fail("checkpoint", f"{label} checkpoint is invalid ({type(exc).__name__})", recovery))
        return None
    checks.append(FactoryDoctorCheck("PASS", "checkpoint", f"{label} {summary}"))
    owned = state.get("owned_process")
    return owned if isinstance(owned, dict) else None


def _request_correlation(body: str) -> dict[str, str]:
    tokens = body.split("\n", 1)[0].split()
    if not tokens:
        return {}
    fields = {}
    for token in tokens[1:]:
        match = _MESSAGE_FIELD_RE.fullmatch(token)
        if match is None or match.group(1) in fields:
            return {}
        fields[match.group(1)] = match.group(2)
    return {key: value for key, value in fields.items() if key not in _NON_CORRELATION_FIELDS}


def _validate_in_flight(item: Any) -> None:
    keys = {
        "attention_id",
        "room_name",
        "sender_agent_name",
        "sender_agent_id",
        "sequence",
        "body",
        "requires_terminal",
    }
    if not isinstance(item, dict) or set(item) != keys:
        raise ValueError("invalid in-flight object")
    if not isinstance(item["attention_id"], str) or _ATTENTION_ID_RE.fullmatch(item["attention_id"]) is None:
        raise ValueError("invalid in-flight attention ID")
    if any(not isinstance(item[key], str) for key in ("room_name", "sender_agent_name", "sender_agent_id", "body")):
        raise ValueError("invalid in-flight fields")
    if (
        isinstance(item["sequence"], bool)
        or not isinstance(item["sequence"], int)
        or item["sequence"] < 0
        or not isinstance(item["requires_terminal"], bool)
        or len(item["body"].encode()) > _MAX_CANONICAL_BODY_BYTES
    ):
        raise ValueError("invalid in-flight values")


def _validate_awaiting_handoff(value: Any) -> None:
    if value is None:
        raise ValueError("invalid awaiting handoff")
    keys = {"room_name", "request", "recipient_agent", "body", "correlation"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid awaiting handoff")
    if (
        any(
            not isinstance(value[key], str) or not value[key]
            for key in ("room_name", "request", "recipient_agent", "body")
        )
        or len(value["body"].encode()) > _MAX_CANONICAL_BODY_BYTES
    ):
        raise ValueError("invalid awaiting handoff")
    correlation = value["correlation"]
    if not isinstance(correlation, dict) or not correlation:
        raise ValueError("invalid awaiting correlation")
    for key, item in correlation.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key) is None
            or key in _NON_CORRELATION_FIELDS
            or not isinstance(item, str)
            or not item
            or re.search(r"\s|=", item) is not None
        ):
            raise ValueError("invalid awaiting correlation")
    if correlation != _request_correlation(value["body"]):
        raise ValueError("mismatched awaiting correlation")


def _validate_brief(room_name: Any, current: Any) -> None:
    keys = {"room_id", "object_id", "revision", "markdown", "content_hash"}
    if (
        not isinstance(room_name, str)
        or _SIMPLE_NAME_RE.fullmatch(room_name) is None
        or not isinstance(current, dict)
        or set(current) != keys
    ):
        raise ValueError("invalid brief context")
    markdown = current["markdown"]
    if (
        not isinstance(current["room_id"], str)
        or not current["room_id"]
        or not isinstance(current["object_id"], str)
        or not current["object_id"]
        or isinstance(current["revision"], bool)
        or not isinstance(current["revision"], int)
        or current["revision"] <= 0
        or not isinstance(markdown, str)
        or len(markdown.encode()) > _MAX_CANONICAL_BODY_BYTES
        or not isinstance(current["content_hash"], str)
        or re.fullmatch(r"[0-9a-f]{64}", current["content_hash"]) is None
        or hashlib.sha256(markdown.encode()).hexdigest() != current["content_hash"]
    ):
        raise ValueError("invalid brief context")


def _validate_checkpoint(state: Any) -> str:
    if not isinstance(state, dict):
        raise ValueError("unsupported checkpoint schema")
    legacy_keys = _STATE_KEYS - {"awaiting_handoffs", "briefs"}
    if state.get("version") == 1 and set(state) == legacy_keys:
        state = {**state, "version": 5, "awaiting_handoffs": [], "briefs": {}}
    elif state.get("version") == 2 and set(state) == legacy_keys | {"awaiting_handoff"}:
        awaiting = state.get("awaiting_handoff")
        if isinstance(awaiting, dict) and set(awaiting) == {
            "room_name",
            "request",
            "recipient_agent",
            "body",
        }:
            awaiting = {**awaiting, "correlation": _request_correlation(awaiting.get("body", ""))}
        state = {
            **state,
            "version": 5,
            "awaiting_handoffs": [] if awaiting is None else [awaiting],
            "briefs": {},
        }
        state.pop("awaiting_handoff")
    elif state.get("version") == 3 and set(state) == legacy_keys | {"awaiting_handoff"}:
        awaiting = state.get("awaiting_handoff")
        state = {
            **state,
            "version": 5,
            "awaiting_handoffs": [] if awaiting is None else [awaiting],
            "briefs": {},
        }
        state.pop("awaiting_handoff")
    elif state.get("version") == 4 and set(state) == legacy_keys | {"awaiting_handoff", "briefs"}:
        awaiting = state.get("awaiting_handoff")
        state = {
            **state,
            "version": 5,
            "awaiting_handoffs": [] if awaiting is None else [awaiting],
        }
        state.pop("awaiting_handoff")
    if set(state) != _STATE_KEYS or state.get("version") != 5:
        raise ValueError("unsupported checkpoint schema")
    thread_id = state.get("thread_id")
    if thread_id is not None and (not isinstance(thread_id, str) or not thread_id):
        raise ValueError("invalid thread ID")
    cursor = state.get("safe_cursor")
    failures = state.get("consecutive_failures")
    recent = state.get("recent_attention_ids")
    in_flight = state.get("in_flight")
    if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
        raise ValueError("invalid safe cursor")
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 0:
        raise ValueError("invalid failure counter")
    if (
        not isinstance(recent, list)
        or len(recent) > 256
        or any(not isinstance(item, str) or _ATTENTION_ID_RE.fullmatch(item) is None for item in recent)
    ):
        raise ValueError("invalid attention deduplication data")
    if not isinstance(in_flight, list) or len(in_flight) > 16:
        raise ValueError("invalid in-flight work")
    for item in in_flight:
        _validate_in_flight(item)
    awaiting_handoffs = state.get("awaiting_handoffs")
    if not isinstance(awaiting_handoffs, list) or len(awaiting_handoffs) > 16:
        raise ValueError("invalid awaiting handoffs")
    for awaiting in awaiting_handoffs:
        _validate_awaiting_handoff(awaiting)
    briefs = state.get("briefs")
    if not isinstance(briefs, dict):
        raise ValueError("invalid brief context")
    for room_name, current in briefs.items():
        _validate_brief(room_name, current)
    owned = state.get("owned_process")
    identity = "none"
    if owned is not None:
        if not isinstance(owned, dict) or set(owned) != {"pid", "start_time", "descendants"}:
            raise ValueError("invalid process identity")
        pid = owned.get("pid")
        start = owned.get("start_time")
        descendants = owned.get("descendants")
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 1
            or not isinstance(start, str)
            or not start.isdigit()
            or not isinstance(descendants, list)
            or len(descendants) > 64
        ):
            raise ValueError("invalid process identity")
        for child in descendants:
            if (
                not isinstance(child, dict)
                or set(child) != {"pid", "start_time"}
                or isinstance(child.get("pid"), bool)
                or not isinstance(child.get("pid"), int)
                or child["pid"] <= 1
                or not isinstance(child.get("start_time"), str)
                or not child["start_time"].isdigit()
            ):
                raise ValueError("invalid child process identity")
        identity = f"pid={pid} start={start}"
    return f"safe_cursor={cursor} in_flight={len(in_flight)} failures={failures} process={identity}"


def _process_rows(
    output: str,
) -> tuple[dict[int, tuple[int, int, str]], dict[int, str], dict[str, str], str | None]:
    before, executable_marker, after_executable = output.partition(f"\n{_PROCESS_EXECUTABLE_MARKER}\n")
    executable_text, expected_marker, after_expected = after_executable.partition(f"{_PROCESS_EXPECTED_MARKER}\n")
    expected_text, stat_marker, stat = after_expected.partition(f"{_PROCESS_STAT_MARKER}\n")
    if not executable_marker or not expected_marker or not stat_marker:
        raise ValueError("process identity marker is missing")
    rows: dict[int, tuple[int, int, str]] = {}
    for line in before.splitlines():
        match = re.fullmatch(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)", line)
        if match is None:
            continue
        pid, parent, group = (int(match.group(index)) for index in range(1, 4))
        rows[pid] = (parent, group, match.group(4))
    executables: dict[int, str] = {}
    for line in executable_text.splitlines():
        match = re.fullmatch(r"(\d+)\t(/[^\n]+)", line)
        if match is not None:
            executables[int(match.group(1))] = match.group(2)
    expected: dict[str, str] = {}
    expected_keys = {"python3", "mcp-python", "codex-command", "codex-executable", "node-executable"}
    for line in expected_text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in expected_keys:
            expected[key] = value
    if set(expected) != expected_keys:
        raise ValueError("expected process executable identity is missing")
    try:
        fields = stat.strip().rsplit(") ", 1)[1].split()
        start_time = fields[19]
    except (IndexError, ValueError):
        start_time = None
    return rows, executables, expected, start_time


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _is_supervisor_process(command: str, executable: str | None, expected: dict[str, str]) -> bool:
    tokens = _command_tokens(command)
    return (
        len(tokens) >= 2
        and tokens[0] == "python3"
        and tokens[1] == "/home/agent/.safeyolo/codex-coord-supervisor.py"
        and executable == expected["python3"]
    )


def _is_codex_process(command: str, executable: str | None, expected: dict[str, str]) -> bool:
    tokens = _command_tokens(command)
    if len(tokens) >= 2 and Path(tokens[0]).name == Path(expected["codex-command"]).name:
        return tokens[1] == "exec" and executable == expected["codex-executable"]
    if (
        len(tokens) < 3
        or Path(tokens[0]).name not in {"node", "nodejs"}
        or tokens[2] != "exec"
        or executable != expected["node-executable"]
    ):
        return False
    entrypoint = tokens[1]
    command_path = expected["codex-command"]
    if entrypoint == command_path:
        return True
    # mise's npm shim resolves `codex` to a shell wrapper, then execs node
    # with the package's bin/codex.js entrypoint.  The wrapper and resolved
    # entrypoint stay inside the same per-agent tool root; accepting only that
    # root preserves the executable identity check for arbitrary paths.
    if not entrypoint.startswith("/") or not command_path.startswith("/"):
        return False
    command_root = Path(command_path).parent.parent
    try:
        return Path(entrypoint).is_relative_to(command_root)
    except AttributeError:  # pragma: no cover - Python 3.8 compatibility
        return str(Path(entrypoint)).startswith(f"{command_root}/")


def _is_coord_mcp_process(command: str, executable: str | None, expected: dict[str, str]) -> bool:
    tokens = _command_tokens(command)
    return (
        len(tokens) >= 2
        and tokens[0] == "/home/agent/.safeyolo/venv/bin/python"
        and tokens[1] == "/home/agent/.safeyolo/safeyolo-coord-mcp.py"
        and executable == expected["mcp-python"]
    )


def _is_descendant(rows: dict[int, tuple[int, int, str]], child: int, ancestor: int) -> bool:
    seen: set[int] = set()
    current = child
    while current in rows and current not in seen:
        seen.add(current)
        parent = rows[current][0]
        if parent == ancestor:
            return True
        current = parent
    return False


def _inspect_processes(
    checks: list[FactoryDoctorCheck],
    label: str,
    agent_name: str,
    platform: AgentPlatform,
    owned_process: dict[str, Any] | None,
) -> None:
    recovery = "running factory process tree; rerun `safeyolo factory doctor` after the bounded turn"
    owned_pid = owned_process["pid"] if owned_process is not None else None
    stat_path = f"/proc/{owned_pid}/stat" if owned_pid is not None else "/dev/null"
    command = (
        "ps -eo pid=,ppid=,pgid=,args=; "
        f"printf '\\n{_PROCESS_EXECUTABLE_MARKER}\\n'; "
        "for process_path in /proc/[0-9]*; do "
        "process_pid=${process_path##*/}; "
        'process_executable=$(readlink -f "$process_path/exe" 2>/dev/null) || continue; '
        'printf \'%s\\t%s\\n\' "$process_pid" "$process_executable"; '
        "done; "
        "python3_path=$(command -v python3 2>/dev/null || true); "
        'codex_path=$(command -v "${SAFEYOLO_CODEX_BIN:-codex}" 2>/dev/null || true); '
        "node_path=$(command -v node 2>/dev/null || true); "
        f"printf '{_PROCESS_EXPECTED_MARKER}\\n'; "
        'printf \'python3=%s\\n\' "$(readlink -f "$python3_path" 2>/dev/null || true)"; '
        "printf 'mcp-python=%s\\n' "
        '"$(readlink -f /home/agent/.safeyolo/venv/bin/python 2>/dev/null || true)"; '
        "printf 'codex-command=%s\\n' \"$codex_path\"; "
        'printf \'codex-executable=%s\\n\' "$(readlink -f "$codex_path" 2>/dev/null || true)"; '
        'printf \'node-executable=%s\\n\' "$(readlink -f "$node_path" 2>/dev/null || true)"; '
        f"printf '\\n{_PROCESS_STAT_MARKER}\\n'; cat {stat_path} 2>/dev/null || true"
    )
    try:
        process = platform.popen_in_sandbox(agent_name, command, user="agent")
        stdout, _stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        checks.append(
            _fail(
                "processes",
                f"{label} process inspection timed out",
                recovery,
            )
        )
        return
    except Exception as exc:
        checks.append(
            _fail(
                "processes",
                f"{label} process inspection failed ({type(exc).__name__})",
                "running factory process tree; run `safeyolo agent status AGENT`",
            )
        )
        return
    if process.returncode != 0:
        checks.append(
            _fail(
                "processes",
                f"{label} process inspection exited {process.returncode}",
                recovery,
            )
        )
        return
    try:
        rows, executables, expected, start_time = _process_rows(stdout)
    except ValueError:
        checks.append(_fail("processes", f"{label} process identity output is invalid", recovery))
        return
    supervisors = {
        pid
        for pid, (_parent, _group, process_command) in rows.items()
        if _is_supervisor_process(process_command, executables.get(pid), expected)
    }

    def has_mcp(codex_pid: int) -> bool:
        return any(
            _is_descendant(rows, pid, codex_pid)
            and _is_coord_mcp_process(process_command, executables.get(pid), expected)
            for pid, (_parent, _process_group, process_command) in rows.items()
        )

    def is_codex(pid: int) -> bool:
        row = rows.get(pid)
        return row is not None and row[1] == pid and _is_codex_process(row[2], executables.get(pid), expected)

    # A bounded supervisor owns no Codex process between turns.  The
    # supervisor itself is the durable health signal in that interval.
    if owned_process is None:
        if supervisors:
            checks.append(
                FactoryDoctorCheck(
                    "PASS",
                    "processes",
                    f"{label} bounded supervisor is between Codex turns",
                )
            )
        else:
            checks.append(_fail("processes", f"{label} missing running=supervisor", recovery))
        return

    owned = rows.get(owned_pid)
    if owned is not None and start_time == owned_process["start_time"]:
        parent = owned[0]
        missing: list[str] = []
        if not is_codex(owned_pid):
            missing.append("codex")
        if parent not in supervisors:
            missing.append("supervisor")
        if not has_mcp(owned_pid):
            missing.append("coord-mcp")
        if missing:
            checks.append(
                _fail(
                    "processes",
                    f"{label} missing running={','.join(missing)}",
                    recovery,
                )
            )
            return
        checks.append(FactoryDoctorCheck("PASS", "processes", f"{label} supervisor, Codex, and Coord MCP are running"))
        return

    # The checkpoint can race a normal bounded-turn handoff: its PID may have
    # exited after `ps` but before `/proc/<pid>/stat`, or a fresh Codex PID may
    # already have replaced it.  Keep this a healthy, non-disruptive result as
    # long as the supervisor remains present and any replacement tree is sound.
    replacement = next(
        (
            pid
            for pid, (parent, _group, _command) in rows.items()
            if parent in supervisors and is_codex(pid) and has_mcp(pid)
        ),
        None,
    )
    if supervisors and (
        owned is None or start_time is None or start_time != owned_process["start_time"] or replacement is not None
    ):
        detail = (
            f"{label} bounded supervisor changed Codex turns during inspection"
            if replacement is not None
            else f"{label} bounded supervisor transition observed during inspection"
        )
        checks.append(FactoryDoctorCheck("PASS", "processes", detail))
        return

    missing = ["checkpointed-codex"]
    if not supervisors:
        missing.append("supervisor")
    checks.append(
        _fail(
            "processes",
            f"{label} missing running={','.join(missing)}",
            recovery,
        )
    )
