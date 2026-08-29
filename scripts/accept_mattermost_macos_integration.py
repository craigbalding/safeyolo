#!/usr/bin/env python3
"""Run real Mattermost check/once with a disposable test-only config on macOS."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from safeyolo.coord.mattermost import MattermostAdapterError, MattermostConfig, load_config

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class AcceptanceError(RuntimeError):
    pass


def _identity(expected_head: str, expected_base: str) -> tuple[str, str]:
    if not _SHA_RE.fullmatch(expected_head) or not _SHA_RE.fullmatch(expected_base):
        raise AcceptanceError("expected head/base must be full lowercase commit SHAs")
    checkout = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    merge_base = subprocess.run(
        ["git", "merge-base", "HEAD", expected_base],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    head = result.stdout.strip()
    if result.returncode != 0 or head != expected_head or merge_base.returncode != 0:
        raise AcceptanceError("checkout does not match the expected candidate")
    if merge_base.stdout.strip() != expected_base:
        raise AcceptanceError("candidate does not descend from the expected base")
    return head, expected_base


def _private_regular_config(path: Path) -> Path:
    expanded = path.expanduser()
    linked = expanded.lstat()
    if not stat.S_ISREG(linked.st_mode) or stat.S_IMODE(linked.st_mode) & 0o077:
        raise AcceptanceError("test config copy must be a private regular non-symlink file")
    if hasattr(os, "getuid") and linked.st_uid != os.getuid():
        raise AcceptanceError("test config copy must be owned by the current user")
    resolved = expanded.resolve(strict=True)
    if resolved == Path("~/.safeyolo/coord-mattermost.toml").expanduser().resolve():
        raise AcceptanceError("live default config is forbidden; provide a separate test-only copy")
    return resolved


def _available_loopback_port(host: str) -> int:
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _quoted(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _write_disposable_config(config: MattermostConfig, path: Path, state_file: Path) -> None:
    lines = [
        "version = 1",
        f"server_url = {_quoted(config.server_url)}",
        f"bot_token_file = {_quoted(config.bot_token_file)}",
        f"bot_user_id = {_quoted(config.bot_user_id)}",
        f"operator_user_id = {_quoted(config.operator_user_id)}",
        f"state_file = {_quoted(state_file)}",
        f"poll_interval_seconds = {config.poll_interval_seconds!r}",
    ]
    if config.actions is not None:
        actions = config.actions
        port = _available_loopback_port(actions.bind_host)
        lines.extend(
            [
                f"action_listener_host = {_quoted(actions.bind_host)}",
                f"action_listener_port = {port}",
                f"public_callback_base_url = {_quoted(actions.public_base_url)}",
                f"action_capability_ttl_seconds = {actions.capability_ttl_seconds}",
                "trusted_action_agent_ids = ["
                + ", ".join(_quoted(agent_id) for agent_id in actions.trusted_agent_ids)
                + "]",
            ]
        )
    for room in config.rooms:
        lines.extend(
            [
                "",
                "[[rooms]]",
                f"coord_room = {_quoted(room.coord_room)}",
                f"channel_id = {_quoted(room.channel_id)}",
                "backfill = false",
            ]
        )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        encoded = ("\n".join(lines) + "\n").encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _run_silent(command: list[str], *, timeout: int) -> int:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=timeout,
    ).returncode


def _cleanup(root: Path | None, identity: tuple[int, int] | None) -> bool:
    if root is None or identity is None:
        print("CLEANUP PASS: no temporary root was created", flush=True)
        return True
    try:
        linked = root.lstat()
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != identity
            or not root.name.startswith("safeyolo-mm-macos-integration-")
        ):
            raise AcceptanceError("temporary root identity changed; cleanup refused")
        shutil.rmtree(root)
        if root.exists() or root.is_symlink():
            raise AcceptanceError("temporary root remains after cleanup")
    except (AcceptanceError, OSError):
        print("CLEANUP FAIL: verified temporary root was not removed", file=sys.stderr, flush=True)
        return False
    print("CLEANUP PASS: removed only script-created config/state artifacts", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--test-config-copy", type=Path, required=True)
    parser.add_argument("--confirm-dedicated-test-channel", action="store_true")
    parser.add_argument("--allow-run-once-effects", action="store_true")
    args = parser.parse_args()
    root: Path | None = None
    root_identity: tuple[int, int] | None = None
    current_step, current_label = 0, "preflight"
    succeeded = False
    try:
        if sys.platform != "darwin":
            raise AcceptanceError("integration acceptance must run on real macOS")
        head, base = _identity(args.expected_head, args.expected_base)
        source_path = _private_regular_config(args.test_config_copy)
        source = load_config(source_path)
        if len(source.rooms) != 1 or source.rooms[0].backfill:
            raise AcceptanceError("test config copy must contain one room with backfill=false")
        if not args.confirm_dedicated_test_channel:
            raise AcceptanceError("dedicated test-channel confirmation is required")

        print(
            "PREFLIGHT: the source config is read-only and will not be modified. A private copy with a new "
            "temporary state DB and backfill=false will be used. check performs identity/API reads and a brief "
            "loopback bind. run --once does not start the daemon or Funnel, but concurrent activity after its "
            "new-state baseline can append one operator message or project one post in the configured test-only "
            "coord room/channel. No production mapping is permitted.",
            flush=True,
        )
        if not args.allow_run_once_effects:
            raise AcceptanceError("run-once test-channel effects were not explicitly allowed")

        root = Path(tempfile.mkdtemp(prefix="safeyolo-mm-macos-integration-")).resolve()
        root_st = root.lstat()
        root_identity = root_st.st_dev, root_st.st_ino
        temp_config = root / "coord-mattermost-test.toml"
        temp_state = root / "state.sqlite3"
        _write_disposable_config(source, temp_config, temp_state)
        print(
            f"IDENTITY candidate={head} base={base} platform={platform.platform()} "
            f"python={platform.python_version()} sqlite={sqlite3.sqlite_version}",
            flush=True,
        )
        print(f"TEMP_ROOT {root}", flush=True)

        cli = Path(sys.executable).with_name("safeyolo")
        if not cli.is_file():
            raise AcceptanceError("candidate safeyolo console script is unavailable")
        current_step, current_label = 8, "real mattermost check with disposable state/config"
        if _run_silent([str(cli), "coord", "mattermost", "check", "--config", str(temp_config)], timeout=90) != 0:
            raise AcceptanceError("mattermost check returned non-zero")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 9, "real mattermost run --once on dedicated test mapping"
        if (
            _run_silent([str(cli), "coord", "mattermost", "run", "--once", "--config", str(temp_config)], timeout=180)
            != 0
        ):
            raise AcceptanceError("mattermost run --once returned non-zero")
        print(f"PASS {current_step}: {current_label}", flush=True)
        succeeded = True
    except (AcceptanceError, MattermostAdapterError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL {current_step}: {current_label} ({type(exc).__name__})", file=sys.stderr, flush=True)
    finally:
        succeeded = _cleanup(root, root_identity) and succeeded
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
