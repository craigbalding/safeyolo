#!/usr/bin/env python3
"""Exercise Mattermost state/WAL/lease safety in disposable files on macOS."""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from safeyolo.coord.mattermost import MattermostAdapterError, MattermostConfig, MattermostState, RoomMapping

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BOT_ID = "b" * 26
_OPERATOR_ID = "o" * 26
_CHANNEL_ID = "c" * 26
_ROOM = "macos-state-acceptance"


class AcceptanceError(RuntimeError):
    pass


def _config(state_file: Path) -> MattermostConfig:
    return MattermostConfig(
        server_url="https://mattermost.invalid",
        bot_token_file=state_file.with_name("unused-token"),
        bot_user_id=_BOT_ID,
        operator_user_id=_OPERATOR_ID,
        state_file=state_file,
        poll_interval_seconds=1.0,
        rooms=(RoomMapping(_ROOM, _CHANNEL_ID, False),),
    )


def _identity(expected_head: str, expected_tree: str, expected_base: str) -> tuple[str, str, str]:
    if not all(_SHA_RE.fullmatch(value) for value in (expected_head, expected_tree, expected_base)):
        raise AcceptanceError("expected head/tree/base must be full lowercase object SHAs")
    checkout = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"],
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
    values = result.stdout.splitlines()
    if result.returncode != 0 or values != [expected_head, expected_tree] or merge_base.returncode != 0:
        raise AcceptanceError("checkout does not match the expected candidate")
    if merge_base.stdout.strip() != expected_base:
        raise AcceptanceError("candidate does not descend from the expected base")
    return expected_head, expected_tree, expected_base


def _silent_child(source: str, state_path: Path) -> int:
    return subprocess.run(
        [sys.executable, "-c", source, str(state_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    ).returncode


def _crash_recovery(state_path: Path) -> None:
    child = """
import os
import sys
from pathlib import Path
from safeyolo.coord.mattermost import MattermostConfig, MattermostState, RoomMapping

path = Path(sys.argv[1])
config = MattermostConfig(
    server_url="https://mattermost.invalid", bot_token_file=path.with_name("unused-token"),
    bot_user_id="b" * 26, operator_user_id="o" * 26, state_file=path,
    poll_interval_seconds=1.0,
    rooms=(RoomMapping("macos-state-acceptance", "c" * 26, False),),
)
state = MattermostState(config)
with state._connect() as conn:
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE abrupt_recovery(value TEXT NOT NULL)")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO abrupt_recovery(value) VALUES ('committed')")
    conn.execute("COMMIT")
    os._exit(0)
"""
    if _silent_child(child, state_path) != 0 or not Path(f"{state_path}-wal").is_file():
        raise AcceptanceError("abrupt WAL writer did not leave recoverable state")
    recovered = MattermostState(_config(state_path))
    try:
        with recovered._connect() as conn:
            row = conn.execute("SELECT value FROM abrupt_recovery").fetchone()
        if row is None or row[0] != "committed":
            raise AcceptanceError("committed WAL row was not recovered")
    finally:
        recovered.close()


def _competing_lease(state: MattermostState, state_path: Path) -> None:
    child = """
import sys
from pathlib import Path
from safeyolo.coord.mattermost import MattermostAdapterError, MattermostConfig, MattermostState, RoomMapping

path = Path(sys.argv[1])
config = MattermostConfig(
    server_url="https://mattermost.invalid", bot_token_file=path.with_name("unused-token"),
    bot_user_id="b" * 26, operator_user_id="o" * 26, state_file=path,
    poll_interval_seconds=1.0,
    rooms=(RoomMapping("macos-state-acceptance", "c" * 26, False),),
)
try:
    state = MattermostState(config)
    with state.lease():
        raise SystemExit(0)
except MattermostAdapterError as exc:
    raise SystemExit(23 if "another Mattermost adapter process" in str(exc) else 24)
"""
    with state.lease():
        state.set_coord_cursor(_ROOM, 37)
        if state.room_state(_ROOM)["coord_cursor"] != 37:
            raise AcceptanceError("SQLite self-locked while the sibling lease was held")
        status = _silent_child(child, state_path)
    if status != 23:
        raise AcceptanceError("competing adapter was not excluded by the sibling lease")


def _replacement_guards(root: Path) -> None:
    state_path = root / "replacement-state.sqlite3"
    guarded = MattermostState(_config(state_path))
    redirected = root / "redirected.sqlite3"
    with sqlite3.connect(redirected) as conn:
        conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        conn.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
    redirected.chmod(0o600)
    state_path.unlink()
    state_path.symlink_to(redirected)
    try:
        try:
            guarded.room_state(_ROOM)
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

    for replacement_kind in ("copy", "hardlinked-copy"):
        durable_path = root / f"durable-{replacement_kind}.sqlite3"
        durable = MattermostState(_config(durable_path))
        durable.set_coord_cursor(_ROOM, 41)
        durable.close()
        original_path = root / f"durable-{replacement_kind}-original.sqlite3"
        durable_path.rename(original_path)
        copied_path = root / f"durable-{replacement_kind}-copied.sqlite3"
        shutil.copy2(original_path, copied_path)
        copied_path.chmod(0o600)
        if replacement_kind == "copy":
            copied_path.rename(durable_path)
        else:
            os.link(copied_path, durable_path)
        try:
            MattermostState(_config(durable_path))
        except MattermostAdapterError as exc:
            if "state_file identity differs from durable state" not in str(exc):
                raise AcceptanceError(f"{replacement_kind} state replacement failed for the wrong reason") from exc
        else:
            raise AcceptanceError(f"new adapter accepted {replacement_kind} state replacement")

    lease_path = root / "lease-state.sqlite3"
    first = MattermostState(_config(lease_path))
    second = MattermostState(_config(lease_path))
    try:
        with first.lease():
            first.lease_path.rename(root / "original.lock")
            first.lease_path.write_text("", encoding="utf-8")
            first.lease_path.chmod(0o600)
            try:
                with second.lease():
                    pass
            except MattermostAdapterError:
                pass
            else:
                raise AcceptanceError("lease replacement created a second lock domain")
            try:
                MattermostState(_config(lease_path))
            except MattermostAdapterError:
                pass
            else:
                raise AcceptanceError("new adapter accepted the replacement lease identity")
    finally:
        first.close()
        second.close()


def _cleanup(root: Path | None, identity: tuple[int, int] | None) -> bool:
    if root is None or identity is None:
        print("CLEANUP PASS: no temporary root was created", flush=True)
        return True
    try:
        linked = root.lstat()
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != identity
            or not root.name.startswith("safeyolo-mm-macos-accept-")
        ):
            raise AcceptanceError("temporary root identity changed; cleanup refused")
        shutil.rmtree(root)
        if root.exists() or root.is_symlink():
            raise AcceptanceError("temporary root remains after cleanup")
    except (AcceptanceError, OSError):
        print("CLEANUP FAIL: verified temporary root was not removed", file=sys.stderr, flush=True)
        return False
    print("CLEANUP PASS: removed only script-created temporary artifacts", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-base", required=True)
    args = parser.parse_args()
    root: Path | None = None
    root_identity: tuple[int, int] | None = None
    state: MattermostState | None = None
    current_step, current_label = 0, "preflight"
    succeeded = False
    try:
        if sys.platform != "darwin":
            raise AcceptanceError("structural acceptance must run on real macOS")
        head, tree, base = _identity(args.expected_head, args.expected_tree, args.expected_base)
        root = Path(tempfile.mkdtemp(prefix="safeyolo-mm-macos-accept-")).resolve()
        root_st = root.lstat()
        root_identity = root_st.st_dev, root_st.st_ino
        print(
            f"IDENTITY candidate={head} tree={tree} base={base} platform={platform.platform()} "
            f"python={platform.python_version()} sqlite={sqlite3.sqlite_version}",
            flush=True,
        )
        print(f"TEMP_ROOT {root}", flush=True)

        state_path = root / "state.sqlite3"
        current_step, current_label = 1, "MattermostState initialization"
        state = MattermostState(_config(state_path))
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 2, "WAL mode and adjacent sidecars"
        with state._connect() as conn:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                raise AcceptanceError("journal mode is not WAL")
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE room_state SET coord_cursor=1 WHERE coord_room=?", (_ROOM,))
            conn.execute("COMMIT")
            if not Path(f"{state_path}-wal").is_file() or not Path(f"{state_path}-shm").is_file():
                raise AcceptanceError("WAL sidecars were not created beside state_file")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 3, "schema creation"
        with sqlite3.connect(state_path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"metadata", "room_state", "outbound_projection", "inbound_post", "action_capability"}
        if not required.issubset(tables):
            raise AcceptanceError("required schema is incomplete")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 4, "state write/read"
        state.set_coord_cursor(_ROOM, 29)
        if state.room_state(_ROOM)["coord_cursor"] != 29:
            raise AcceptanceError("state read did not return the written cursor")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 5, "close/reopen and abrupt WAL recovery"
        state.close()
        state = MattermostState(_config(state_path))
        if state.room_state(_ROOM)["coord_cursor"] != 29:
            raise AcceptanceError("reopened state lost the written cursor")
        _crash_recovery(root / "crash.sqlite3")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 6, "separate sibling lease and competitor exclusion"
        _competing_lease(state, state_path)
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 7, "state and lease replacement fail closed"
        _replacement_guards(root)
        print(f"PASS {current_step}: {current_label}", flush=True)
        succeeded = True
    except (AcceptanceError, MattermostAdapterError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"FAIL {current_step}: {current_label} ({type(exc).__name__})", file=sys.stderr, flush=True)
    finally:
        if state is not None:
            state.close()
        succeeded = _cleanup(root, root_identity) and succeeded
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
