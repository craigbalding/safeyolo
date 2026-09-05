#!/usr/bin/env python3
"""Stage SafeYolo-owned Codex state without importing host credentials."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

SCHEMA = "safeyolo.codex-provenance/v1"
MARKER_NAME = ".safeyolo-provenance.json"
AUTH_FILE = "auth.json"
CONFIG_FILE = "config.toml"
VALID_STATES = frozenset({"fresh", "agent-local", "legacy-unknown", "reset"})

RECOVERY_GUIDANCE = (
    "No credential content was changed. Inside the agent, fresh activation is "
    "`codex login --device-auth`, then `/home/agent/.safeyolo/"
    "codex-auth-recovery.py adopt`. For unknown or unsafe existing state, "
    "confirm the credential is agent-local before adopting it; to reset, run "
    "`/home/agent/.safeyolo/codex-auth-recovery.py reset`, then `codex login "
    "--device-auth`, then run the adopt command."
)


class CodexStateError(RuntimeError):
    """The agent-local Codex state is unsafe or requires explicit migration."""


def _load_tomlkit():
    try:
        import tomlkit
        from tomlkit.items import InlineTable, Table
    except ImportError as exc:
        raise CodexStateError(
            "SafeYolo Python with tomlkit is required for Codex config staging"
        ) from exc
    return tomlkit, InlineTable, Table


def _label(path: Path) -> str:
    return str(path)


def _lstat(path: Path, description: str) -> os.stat_result:
    try:
        return path.lstat()
    except FileNotFoundError:
        raise CodexStateError(f"{description} is missing: {_label(path)}") from None
    except OSError as exc:
        raise CodexStateError(f"cannot inspect {description}: {exc}") from None


def _present(path: Path, description: str) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CodexStateError(f"cannot inspect {description}: {exc}") from None
    return True


def _validate_owner_mode(
    path: Path,
    description: str,
    *,
    directory: bool = False,
    mode: int | None = None,
) -> os.stat_result:
    info = _lstat(path, description)
    if stat.S_ISLNK(info.st_mode):
        raise CodexStateError(f"unsafe {description}: symlink is not allowed")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise CodexStateError(f"unsafe {description}: expected a directory")
    elif not stat.S_ISREG(info.st_mode):
        raise CodexStateError(f"unsafe {description}: expected a regular file")
    if not directory and info.st_nlink != 1:
        raise CodexStateError(f"unsafe {description}: hard links are not allowed")
    if info.st_uid != os.getuid():
        raise CodexStateError(f"unsafe {description}: owner is not the invoking user")
    actual_mode = stat.S_IMODE(info.st_mode)
    if mode is not None and actual_mode != mode:
        raise CodexStateError(
            f"unsafe {description}: expected mode {mode:04o}, found {actual_mode:04o}"
        )
    if mode is None and actual_mode & 0o022:
        raise CodexStateError(f"unsafe {description}: group/world write is not allowed")
    return info


def _ensure_codex_home(home: Path) -> Path:
    codex_home = home / ".codex"
    if _present(codex_home, "Codex home"):
        _validate_owner_mode(codex_home, "Codex home", directory=True)
    else:
        try:
            codex_home.mkdir(mode=0o700)
        except OSError as exc:
            raise CodexStateError(f"cannot create Codex home: {exc}") from None
        _validate_owner_mode(codex_home, "Codex home", directory=True)
    return codex_home


def _validate_optional_file(path: Path, description: str, *, auth: bool = False) -> bool:
    if not _present(path, description):
        return False
    _validate_owner_mode(path, description, mode=0o600 if auth else None)
    return True


def _read_text_no_follow(path: Path, description: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeError) as exc:
        raise CodexStateError(f"cannot read {description}: {exc}") from None


def _read_marker(path: Path) -> dict[str, str] | None:
    if not _present(path, "Codex provenance marker"):
        return None
    _validate_owner_mode(path, "Codex provenance marker", mode=0o600)
    try:
        value = json.loads(_read_text_no_follow(path, "Codex provenance marker"))
    except json.JSONDecodeError as exc:
        raise CodexStateError(f"invalid Codex provenance marker: {exc}") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "state"}
        or value.get("schema") != SCHEMA
        or value.get("state") not in VALID_STATES
    ):
        raise CodexStateError("invalid Codex provenance marker shape")
    return value


def _atomic_write(path: Path, content: str, mode: int) -> None:
    directory = path.parent
    directory_fd: int | None = None
    temporary: Path | None = None
    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=directory
        )
        temporary = Path(temporary_name)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(directory, os.O_RDONLY)
        os.fsync(directory_fd)
    except OSError as exc:
        raise CodexStateError(f"cannot atomically update {path}: {exc}") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _marker_value(state: str) -> str:
    return json.dumps({"schema": SCHEMA, "state": state}, sort_keys=True) + "\n"


def _read_config(path: Path) -> str:
    if not _present(path, "Codex config"):
        return ""
    _validate_owner_mode(path, "Codex config")
    tomlkit, _inline_table, _table = _load_tomlkit()
    try:
        text = _read_text_no_follow(path, "Codex config")
        tomlkit.parse(text)
    except tomlkit.exceptions.TOMLKitError as exc:
        raise CodexStateError(f"invalid Codex config: {exc}") from None
    return text


def _managed_config(existing: str, launcher: str | None) -> str:
    tomlkit, inline_table_type, table_type = _load_tomlkit()
    try:
        document = tomlkit.parse(existing) if existing else tomlkit.document()
    except tomlkit.exceptions.TOMLKitError as exc:
        raise CodexStateError(f"invalid Codex config: {exc}") from None

    document["forced_chatgpt_auth"] = True
    document["cli_auth_credentials_store"] = "file"

    if launcher is not None:
        servers = document.get("mcp_servers")
        if servers is None:
            servers = tomlkit.table()
            document.add("mcp_servers", servers)
        elif not isinstance(servers, (table_type, inline_table_type)):
            raise CodexStateError("Codex mcp_servers setting must be a table")

        coord = (
            tomlkit.inline_table()
            if isinstance(servers, inline_table_type)
            else tomlkit.table()
        )
        coord["command"] = launcher
        coord["args"] = []
        coord["tool_timeout_sec"] = 330
        servers["safeyolo-coord"] = coord

    managed = tomlkit.dumps(document)
    try:
        parsed = tomlkit.parse(managed).unwrap()
    except tomlkit.exceptions.TOMLKitError as exc:
        raise CodexStateError(f"generated invalid Codex config: {exc}") from None

    if (
        parsed.get("forced_chatgpt_auth") is not True
        or parsed.get("cli_auth_credentials_store") != "file"
    ):
        raise CodexStateError("generated Codex config lacks required auth settings")
    if launcher is not None and parsed.get("mcp_servers", {}).get("safeyolo-coord") != {
        "command": launcher,
        "args": [],
        "tool_timeout_sec": 330,
    }:
        raise CodexStateError("generated Codex config lacks the required Coord MCP settings")
    return managed


def _stage(home: Path, launcher: str | None) -> None:
    codex_home = _ensure_codex_home(home)
    auth_path = codex_home / AUTH_FILE
    config_path = codex_home / CONFIG_FILE
    marker_path = codex_home / MARKER_NAME

    # Metadata-only auth validation is deliberate. Never open, hash, copy,
    # chmod, back up, or otherwise inspect credential bytes here.
    auth_present = _validate_optional_file(auth_path, "Codex auth.json", auth=True)
    existing_config = _read_config(config_path)
    marker = _read_marker(marker_path)

    if marker is None:
        state = "legacy-unknown" if auth_present else "fresh"
        _atomic_write(marker_path, _marker_value(state), 0o600)
        if state == "legacy-unknown":
            raise CodexStateError(
                "Codex auth.json has no SafeYolo provenance marker; explicit adopt or reset is required"
            )
    elif marker["state"] == "legacy-unknown":
        raise CodexStateError(
            "Codex auth.json has unknown provenance; explicit adopt or reset is required"
        )
    elif marker["state"] in {"fresh", "reset"} and auth_present:
        raise CodexStateError(
            "Codex auth.json appeared after a fresh or reset state; explicit adopt or reset is required"
        )
    elif marker["state"] == "agent-local" and not auth_present:
        raise CodexStateError(
            "Codex auth.json is missing from an agent-local state; explicit adopt or reset is required"
        )

    managed = _managed_config(existing_config, launcher)
    if managed != existing_config:
        mode = 0o600
        if _present(config_path, "Codex config"):
            mode = stat.S_IMODE(config_path.stat().st_mode)
        _atomic_write(config_path, managed, mode)


def _recover(home: Path, action: str) -> None:
    codex_home = _ensure_codex_home(home)
    auth_path = codex_home / AUTH_FILE
    marker_path = codex_home / MARKER_NAME
    auth_present = _validate_optional_file(auth_path, "Codex auth.json", auth=True)
    _read_marker(marker_path)

    if action == "adopt":
        if not auth_present:
            raise CodexStateError(
                "cannot adopt missing auth.json; run `codex login --device-auth` first"
            )
        _atomic_write(marker_path, _marker_value("agent-local"), 0o600)
    else:
        if auth_present:
            try:
                auth_path.unlink()
            except OSError as exc:
                raise CodexStateError(f"cannot reset Codex auth.json: {exc}") from None
        _atomic_write(marker_path, _marker_value("reset"), 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--mcp-launcher")
    parser.add_argument("recovery", nargs="?", choices=("adopt", "reset"))
    args = parser.parse_args()
    try:
        if args.recovery is not None:
            _recover(args.home, args.recovery)
        else:
            _stage(args.home, args.mcp_launcher)
    except CodexStateError as exc:
        print(f"codex-state: {exc}", file=sys.stderr)
        print(f"codex-state: {RECOVERY_GUIDANCE}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
