#!/usr/bin/env python3
"""Run the bounded, secret-free Mattermost state acceptance on real macOS."""

from __future__ import annotations

import argparse
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from safeyolo.coord.mattermost import MattermostAdapterError, MattermostState, load_config


class AcceptanceError(RuntimeError):
    pass


def _passed(number: int, label: str) -> None:
    print(f"PASS {number}: {label}", flush=True)


def _run_silent(command: list[str], *, timeout: int) -> int:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=timeout,
    )
    return result.returncode


def _require_new_state(state_path: Path) -> None:
    lease_path = state_path.with_name(f"{state_path.name}.lock")
    if state_path.exists() and state_path.stat().st_size != 0:
        raise AcceptanceError("configured state_file must be new and empty")
    if state_path.is_symlink() or lease_path.exists() or lease_path.is_symlink():
        raise AcceptanceError("configured state and lease paths must be unused non-symlink paths")
    for suffix in ("-wal", "-shm"):
        if Path(f"{state_path}{suffix}").exists():
            raise AcceptanceError("configured state_file has a pre-existing SQLite sidecar")


def _verify_crash_recovery(config_path: Path, state_path: Path) -> None:
    child = """
import os
import sys
from dataclasses import replace
from pathlib import Path
from safeyolo.coord.mattermost import MattermostState, load_config

config = replace(load_config(Path(sys.argv[1])), state_file=Path(sys.argv[2]))
state = MattermostState(config)
with state._connect() as conn:
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE macos_crash_recovery(value TEXT NOT NULL)")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO macos_crash_recovery(value) VALUES ('durable')")
    conn.execute("COMMIT")
    os._exit(0)
"""
    if _run_silent([sys.executable, "-c", child, str(config_path), str(state_path)], timeout=30) != 0:
        raise AcceptanceError("abrupt WAL writer failed")
    if not Path(f"{state_path}-wal").is_file():
        raise AcceptanceError("abrupt writer did not leave a WAL for recovery")
    recovered_config = replace(load_config(config_path), state_file=state_path)
    recovered = MattermostState(recovered_config)
    try:
        with recovered._connect() as conn:
            row = conn.execute("SELECT value FROM macos_crash_recovery").fetchone()
        if row is None or row[0] != "durable":
            raise AcceptanceError("recovered WAL row does not match committed state")
    finally:
        recovered.close()


def _verify_competing_lease(config_path: Path, state: MattermostState, room: str) -> None:
    child = """
import sys
from pathlib import Path
from safeyolo.coord.mattermost import MattermostAdapterError, MattermostState, load_config

try:
    state = MattermostState(load_config(Path(sys.argv[1])))
    with state.lease():
        raise SystemExit(0)
except MattermostAdapterError as exc:
    raise SystemExit(23 if "another Mattermost adapter process" in str(exc) else 24)
"""
    with state.lease():
        state.set_coord_cursor(room, 37)
        if state.room_state(room)["coord_cursor"] != 37:
            raise AcceptanceError("SQLite read/write failed while sibling lease was held")
        status = _run_silent([sys.executable, "-c", child, str(config_path)], timeout=30)
    if status != 23:
        raise AcceptanceError("competing adapter was not excluded by the sibling lease")


def _verify_replacement_guards(config_path: Path, parent: Path) -> None:
    base = load_config(config_path)
    with tempfile.TemporaryDirectory(prefix="mattermost-macos-guards-", dir=parent) as raw_tmp:
        tmp = Path(raw_tmp)

        state_config = replace(base, state_file=tmp / "state.sqlite3")
        guarded = MattermostState(state_config)
        redirected = tmp / "redirected.sqlite3"
        with sqlite3.connect(redirected) as conn:
            conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
            conn.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
        redirected.chmod(0o600)
        state_config.state_file.unlink()
        state_config.state_file.symlink_to(redirected)
        try:
            try:
                guarded.room_state("backlog")
            except MattermostAdapterError:
                pass
            else:
                raise AcceptanceError("state pathname replacement was accepted")
        finally:
            guarded.close()
        with sqlite3.connect(redirected) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            value = conn.execute("SELECT value FROM sentinel").fetchone()
        if tables != {"sentinel"} or value != ("unchanged",):
            raise AcceptanceError("state replacement target was modified")

        lease_config = replace(base, state_file=tmp / "lease-state.sqlite3")
        first = MattermostState(lease_config)
        second = MattermostState(lease_config)
        try:
            with first.lease():
                first.lease_path.rename(tmp / "original.lock")
                first.lease_path.write_text("", encoding="utf-8")
                first.lease_path.chmod(0o600)
                try:
                    with second.lease():
                        pass
                except MattermostAdapterError:
                    pass
                else:
                    raise AcceptanceError("lease pathname replacement created a second lock domain")
                try:
                    MattermostState(lease_config)
                except MattermostAdapterError:
                    pass
                else:
                    raise AcceptanceError("new adapter accepted the replacement lease identity")
        finally:
            first.close()
            second.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    current_step = 0
    current_label = "platform precondition"
    state: MattermostState | None = None
    try:
        if sys.platform != "darwin":
            raise AcceptanceError("this acceptance must run on real macOS")
        config_path = args.config.expanduser().resolve(strict=True)
        config = load_config(config_path)
        room = config.rooms[0].coord_room
        _require_new_state(config.state_file)

        current_step, current_label = 1, "MattermostState initialization"
        state = MattermostState(config)
        _passed(current_step, current_label)

        current_step, current_label = 2, "WAL mode and real -wal/-shm sidecars"
        with state._connect() as conn:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                raise AcceptanceError("journal mode is not WAL")
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE room_state SET coord_cursor = 1 WHERE coord_room = ?", (room,))
            conn.execute("COMMIT")
            if not Path(f"{config.state_file}-wal").is_file() or not Path(f"{config.state_file}-shm").is_file():
                raise AcceptanceError("WAL sidecars were not created beside state_file")
        _passed(current_step, current_label)

        current_step, current_label = 3, "schema creation"
        with sqlite3.connect(config.state_file) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"metadata", "room_state", "outbound_projection", "inbound_post", "action_capability"}
        if not required.issubset(tables):
            raise AcceptanceError("required Mattermost state schema is incomplete")
        _passed(current_step, current_label)

        current_step, current_label = 4, "durable state read/write"
        state.set_coord_cursor(room, 29)
        if state.room_state(room)["coord_cursor"] != 29:
            raise AcceptanceError("state read did not return the written cursor")
        _passed(current_step, current_label)

        current_step, current_label = 5, "close/reopen and abrupt WAL recovery"
        state.close()
        state = MattermostState(config)
        if state.room_state(room)["coord_cursor"] != 29:
            raise AcceptanceError("reopened state did not retain the written cursor")
        with tempfile.TemporaryDirectory(prefix="mattermost-macos-crash-", dir=config.state_file.parent) as raw_tmp:
            _verify_crash_recovery(config_path, Path(raw_tmp) / "crash.sqlite3")
        _passed(current_step, current_label)

        current_step, current_label = 6, "separate sibling lease and competing adapter exclusion"
        _verify_competing_lease(config_path, state, room)
        _passed(current_step, current_label)

        current_step, current_label = 7, "state and lease pathname replacement fail closed"
        _verify_replacement_guards(config_path, config.state_file.parent)
        _passed(current_step, current_label)

        state.close()
        state = None
        cli = Path(sys.executable).with_name("safeyolo")
        if not cli.is_file():
            raise AcceptanceError("safeyolo console script is not beside the active Python interpreter")

        current_step, current_label = 8, "real mattermost check"
        if (
            _run_silent(
                [str(cli), "coord", "mattermost", "check", "--config", str(config_path)],
                timeout=90,
            )
            != 0
        ):
            raise AcceptanceError("mattermost check returned non-zero")
        _passed(current_step, current_label)

        current_step, current_label = 9, "real mattermost run --once"
        if (
            _run_silent(
                [str(cli), "coord", "mattermost", "run", "--once", "--config", str(config_path)],
                timeout=180,
            )
            != 0
        ):
            raise AcceptanceError("mattermost run --once returned non-zero")
        _passed(current_step, current_label)
        return 0
    except (AcceptanceError, MattermostAdapterError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"FAIL {current_step}: {current_label} ({type(exc).__name__})", file=sys.stderr)
        return 1
    finally:
        if state is not None:
            state.close()


if __name__ == "__main__":
    raise SystemExit(main())
