#!/usr/bin/env python3
"""Create or validate a private, single-channel macOS acceptance config."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import traceback
from pathlib import Path

from safeyolo.coord.mattermost import MattermostAdapterError, MattermostConfig, load_config, read_bot_token

_LIVE_CONFIG = Path("~/.safeyolo/coord-mattermost.toml").expanduser()
_STATE_SUFFIX = ".integration-source-state.sqlite3"


class PreparationError(RuntimeError):
    pass


def _quoted(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _private_parent(path: Path) -> Path:
    parent = path.expanduser().parent.resolve(strict=True)
    linked = parent.lstat()
    if not stat.S_ISDIR(linked.st_mode):
        raise PreparationError("output parent must be a regular directory")
    if hasattr(os, "getuid") and linked.st_uid != os.getuid():
        raise PreparationError("output parent must be owned by the current user")
    if stat.S_IMODE(linked.st_mode) & 0o077:
        raise PreparationError("output parent must not be accessible by group or world")
    return parent


def _output_path(path: Path) -> Path:
    parent = _private_parent(path)
    output = parent / path.expanduser().name
    if output == _LIVE_CONFIG.resolve():
        raise PreparationError("live default config path is forbidden")
    try:
        output.lstat()
    except FileNotFoundError:
        return output
    raise PreparationError("output already exists; refusing to overwrite it")


def _private_config(path: Path) -> Path:
    expanded = path.expanduser()
    linked = expanded.lstat()
    if not stat.S_ISREG(linked.st_mode) or stat.S_IMODE(linked.st_mode) & 0o077:
        raise PreparationError("test config must be a private regular non-symlink file")
    if hasattr(os, "getuid") and linked.st_uid != os.getuid():
        raise PreparationError("test config must be owned by the current user")
    resolved = expanded.resolve(strict=True)
    if resolved == _LIVE_CONFIG.resolve():
        raise PreparationError("live default config path is forbidden")
    _private_parent(resolved)
    return resolved


def _validate_loaded(path: Path, config: MattermostConfig) -> None:
    if len(config.rooms) != 1 or config.rooms[0].backfill:
        raise PreparationError("test config must contain exactly one room with backfill=false")
    expected_token = path.with_name(f".{path.stem}.bot-token")
    expected_state = path.with_name(f".{path.stem}{_STATE_SUFFIX}")
    if config.bot_token_file != expected_token:
        raise PreparationError("test config must use its portable sibling bot-token path")
    if config.state_file != expected_state:
        raise PreparationError("test config must use its private sibling integration-source-state path")
    if config.state_file.exists() or config.state_file.is_symlink():
        raise PreparationError("integration-source-state path must not already exist")
    token = read_bot_token(config.bot_token_file)
    del token


def validate_config(path: Path) -> Path:
    config_path = _private_config(path)
    config = load_config(config_path)
    _validate_loaded(config_path, config)
    return config_path


def create_config(
    output_arg: Path,
    *,
    server_url: str,
    bot_token_file: str,
    bot_user_id: str,
    operator_user_id: str,
    coord_room: str,
    channel_id: str,
) -> Path:
    output = _output_path(output_arg)
    source_token_path = Path(bot_token_file).expanduser().resolve(strict=True)
    token_value = read_bot_token(source_token_path)
    token_path = output.with_name(f".{output.stem}.bot-token")
    state_path = output.with_name(f".{output.stem}{_STATE_SUFFIX}")
    for reserved in (token_path, state_path):
        try:
            reserved.lstat()
        except FileNotFoundError:
            continue
        raise PreparationError("portable bundle token/state target already exists; refusing to overwrite it")
    lines = [
        "version = 1",
        f"server_url = {_quoted(server_url)}",
        f"bot_token_file = {_quoted(token_path.name)}",
        f"bot_user_id = {_quoted(bot_user_id)}",
        f"operator_user_id = {_quoted(operator_user_id)}",
        f"state_file = {_quoted(state_path.name)}",
        "poll_interval_seconds = 1.0",
        "",
        "[[rooms]]",
        f"coord_room = {_quoted(coord_room)}",
        f"channel_id = {_quoted(channel_id)}",
        "backfill = false",
    ]
    token_fd = -1
    config_fd = -1
    temporary: Path | None = None
    token_identity: tuple[int, int] | None = None
    output_identity: tuple[int, int] | None = None
    succeeded = False
    try:
        token_fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        token_st = os.fstat(token_fd)
        token_identity = token_st.st_dev, token_st.st_ino
        token_bytes = f"{token_value}\n".encode()
        token_view = memoryview(token_bytes)
        while token_view:
            token_written = os.write(token_fd, token_view)
            token_view = token_view[token_written:]
        os.fsync(token_fd)
        os.close(token_fd)
        token_fd = -1
        config_fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
        temporary = Path(temporary_name)
        os.fchmod(config_fd, 0o600)
        encoded = ("\n".join(lines) + "\n").encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(config_fd, view)
            view = view[written:]
        os.fsync(config_fd)
        config_st = os.fstat(config_fd)
        output_identity = config_st.st_dev, config_st.st_ino
        os.close(config_fd)
        config_fd = -1
        loaded = load_config(temporary)
        _validate_loaded(output, loaded)
        os.link(temporary, output)
        temporary.unlink()
        directory_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        validate_config(output)
        succeeded = True
    finally:
        del token_value
        if token_fd >= 0:
            os.close(token_fd)
        if config_fd >= 0:
            os.close(config_fd)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        if not succeeded:
            for created, identity in ((output, output_identity), (token_path, token_identity)):
                if identity is None:
                    continue
                try:
                    linked = created.lstat()
                    if (linked.st_dev, linked.st_ino) == identity:
                        created.unlink()
                except FileNotFoundError:
                    pass
    return output


def _required(prompt: str) -> str:
    value = input(f"{prompt}: ").strip()
    if not value:
        raise PreparationError(f"{prompt} is required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="Create a new mode-0600 config at this non-live path.")
    mode.add_argument("--validate", type=Path, help="Validate an existing helper-created config without printing it.")
    args = parser.parse_args()
    try:
        if args.validate is not None:
            path = validate_config(args.validate)
            print(
                f"VALIDATION PASS bundle_dir={path.parent} config={path.name} "
                "mode=0700/0600 rooms=1 backfill=false token=sibling state=disposable",
                flush=True,
            )
            return 0
        print(
            "Enter the six dedicated-test values. Input is used only to write the private config; "
            "the bot token file contents are validated but never printed.",
            flush=True,
        )
        path = create_config(
            args.output,
            server_url=_required("Mattermost HTTPS origin"),
            bot_token_file=_required("Private bot token file path"),
            bot_user_id=_required("Dedicated bot user ID"),
            operator_user_id=_required("Operator user ID"),
            coord_room=_required("Dedicated coord room"),
            channel_id=_required("Dedicated Mattermost channel ID"),
        )
        print(
            f"CREATED bundle_dir={path.parent} config={path.name} "
            "mode=0700/0600 rooms=1 backfill=false token=sibling state=disposable",
            flush=True,
        )
        return 0
    except (EOFError, MattermostAdapterError, OSError, PreparationError) as exc:
        print(f"PREPARATION FAIL ({type(exc).__name__}): {exc}", file=sys.stderr, flush=True)
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
