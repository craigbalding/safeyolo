"""SQLite backend for the coord v0 substrate."""

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

CREATE TABLE IF NOT EXISTS messages (
    msg_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    sent_at INTEGER NOT NULL,
    sender_kind TEXT NOT NULL,
    sender_agent_id TEXT,
    sender_agent_name TEXT,
    origin_instance_id TEXT NOT NULL,
    content_type TEXT NOT NULL,
    body TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);
"""


def _ensure_migrations(conn) -> None:
    """Idempotent additive schema migrations for the v0 substrate.

    Kept small and read-first: PRAGMA table_info is cheap and lets us add
    columns to installs that predate later fields (e.g. sender_agent_name
    added for #22) without needing a full migration framework.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
    if "sender_agent_name" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN sender_agent_name TEXT")
    _backfill_agent_names(conn)


def _backfill_agent_names(conn) -> None:
    """Fill `sender_agent_name` for legacy agent rows using the current
    `agent_id → name` mapping. Per bob's #23: after backfill, NULL on an
    agent row means 'agent no longer resolvable' (fact-carrying) rather
    than 'row pre-dates #22' (ambiguous with the removed-agent case).

    Only agent rows are touched: operator rows carry NULL by design
    (`sender_kind='operator'` disambiguates them from the agent-null case).

    Fast-path early return when no gaps exist so this stays cheap on every
    `init_schema()` call (which happens on many code paths).
    """
    has_gaps = conn.execute(
        "SELECT 1 FROM messages "
        "WHERE sender_kind = 'agent' AND sender_agent_name IS NULL "
        "LIMIT 1"
    ).fetchone()
    if not has_gaps:
        return
    # Lazy import to avoid circular reference (store <-> agents_store).
    from safeyolo.agents_store import load_all_agents
    all_agents = load_all_agents()
    id_to_name = {
        meta.get("agent_id"): name
        for name, meta in all_agents.items()
        if meta.get("agent_id")
    }
    if not id_to_name:
        return
    for aid, name in id_to_name.items():
        conn.execute(
            """UPDATE messages SET sender_agent_name = ?
               WHERE sender_kind = 'agent'
                 AND sender_agent_id = ?
                 AND sender_agent_name IS NULL""",
            (name, aid),
        )

# rowid is SQLite's implicit monotonic per-table sequence. Used as the
# `sequence` returned to clients for pagination and wait_for_message cursors.
# Room-local ordering is preserved because rowid monotonically increases
# regardless of room; queries filter room_id and order by rowid.


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
        _ensure_migrations(conn)


def now_ms() -> int:
    return int(time.time() * 1000)
