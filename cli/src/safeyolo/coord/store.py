"""SQLite backend for coord control-plane state.

v1 (JetStream) stores messages in NATS — this module keeps only the
registry (rooms, memberships, instance identity). Grants are checked
from here; message history lives in per-room JetStream streams.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .identity import coord_data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS instance (
    id TEXT PRIMARY KEY
);

-- Agent identity lives in agents_store (policy.toml [agents.<name>].agent_id),
-- NOT here. This substrate references agent_id strings but does not own them;
-- the authoritative registry is the main SafeYolo agent registry per #371's
-- unified-identity invariant.

CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    permissions TEXT NOT NULL,
    history_visibility TEXT NOT NULL DEFAULT 'retained',
    granted_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (room_id, principal_kind, principal_id, granted_at)
);
"""


def db_path() -> Path:
    return coord_data_dir() / "v0.db"


@contextmanager
def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_schema() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def now_ms() -> int:
    return int(time.time() * 1000)
