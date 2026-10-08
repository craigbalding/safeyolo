"""Instance and agent identifiers for the coord v0 substrate."""

from __future__ import annotations

import fcntl
import os
import tempfile
import uuid
from pathlib import Path


def new_instance_id() -> str:
    return f"sy-{uuid.uuid4().hex}"


def new_agent_id() -> str:
    return f"ag-{uuid.uuid4().hex}"


def new_room_id() -> str:
    return f"rm-{uuid.uuid4().hex}"


def new_msg_id() -> str:
    return f"msg-{uuid.uuid4().hex}"


def new_attention_id() -> str:
    """Mint one stable logical attention-edge identifier."""
    return f"attn-{uuid.uuid4().hex}"


def new_operation_id() -> str:
    """Mint a SafeYolo-generated mutation retry handle."""
    return f"op-{uuid.uuid4().hex}"


def new_event_id() -> str:
    """Mint a stable logical outbox/audit edge identifier."""
    return f"evt-{uuid.uuid4().hex}"


def coord_data_dir() -> Path:
    override = os.environ.get("SAFEYOLO_COORD_DATA_DIR")
    if override:
        return Path(override)
    return Path.home() / ".safeyolo" / "data" / "coord"


def instance_id_file() -> Path:
    return coord_data_dir() / "instance_id"


def get_or_create_instance_id() -> str:
    """Return the SafeYolo instance ID, creating it once on first call.

    Race-safe: two concurrent callers on a fresh install will not mint
    different IDs. The first to acquire the exclusive lock writes; the
    second sees the file exists and returns the same value.

    Fast-path readers observe the file atomically: writers stage the ID
    into a sibling temp file and `os.replace` it into place, so a
    concurrent reader sees either "not there yet" or the fully written
    ID — never "exists but empty," which was a subtle race in the
    earlier `path.write_text()` implementation (O_CREAT|O_TRUNC leaves
    an empty file visible to `exists()` before the write completes).
    """
    path = instance_id_file()
    # Fast path: already exists, no lock needed.
    if path.exists():
        return path.read_text().strip()

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".instance_id.lock"
    lock_path.touch()
    with open(lock_path, "r+") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            # Re-check under lock — another process may have written it
            # between our fast-path check and lock acquisition.
            if path.exists():
                return path.read_text().strip()
            iid = new_instance_id()
            # Stage into a sibling temp file then atomically rename into
            # place. Fast-path readers never see a half-written file.
            fd, tmp_name = tempfile.mkstemp(
                dir=path.parent, prefix=".instance_id.", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(iid + "\n")
                os.chmod(tmp_name, 0o600)
                os.replace(tmp_name, path)
            except BaseException:
                # Any failure between mkstemp and replace: clean the
                # temp file so we don't leave debris under coord/.
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    # Another cleanup path already removed the failed stage.
                    pass
                raise
            return iid
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
