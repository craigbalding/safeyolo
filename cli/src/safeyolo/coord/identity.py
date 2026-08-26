"""Instance and agent identifiers for the coord v0 substrate."""

from __future__ import annotations

import os
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


def coord_data_dir() -> Path:
    override = os.environ.get("SAFEYOLO_COORD_DATA_DIR")
    if override:
        return Path(override)
    return Path.home() / ".safeyolo" / "data" / "coord"


def instance_id_file() -> Path:
    return coord_data_dir() / "instance_id"


def get_or_create_instance_id() -> str:
    path = instance_id_file()
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    iid = new_instance_id()
    path.write_text(iid + "\n")
    path.chmod(0o600)
    return iid
