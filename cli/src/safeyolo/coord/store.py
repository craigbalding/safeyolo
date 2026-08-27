"""Versioned SQLite control-plane store for the coordination kernel."""

from __future__ import annotations

import logging
import sqlite3
import time
from collections import Counter
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from .identity import coord_data_dir

log = logging.getLogger("safeyolo.coord.store")

CURRENT_SCHEMA_VERSION = 2


class SchemaError(RuntimeError):
    """Base class for coordination schema errors."""


class FutureSchemaError(SchemaError):
    """The database was written by newer code."""


class LegacySchemaError(SchemaError):
    """An unversioned database is not the current-master legacy shape."""


_LEGACY_TABLE_STATEMENTS = (
    """CREATE TABLE instance (
           id TEXT PRIMARY KEY
       )""",
    """CREATE TABLE rooms (
           room_id TEXT PRIMARY KEY,
           name TEXT NOT NULL UNIQUE,
           created_at INTEGER NOT NULL
       )""",
    """CREATE TABLE memberships (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           principal_kind TEXT NOT NULL,
           principal_id TEXT NOT NULL,
           permissions TEXT NOT NULL,
           history_visibility TEXT NOT NULL DEFAULT 'retained',
           granted_at INTEGER NOT NULL,
           revoked_at INTEGER,
           PRIMARY KEY (room_id, principal_kind, principal_id, granted_at)
       )""",
)

_OUTBOX_STATEMENTS = (
    """CREATE TABLE coord_outbox (
           event_id TEXT PRIMARY KEY,
           destination TEXT NOT NULL,
           event_type TEXT NOT NULL,
           payload_json TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           delivered_at INTEGER,
           attempt_count INTEGER NOT NULL DEFAULT 0,
           last_error_class TEXT
       )""",
    """CREATE INDEX coord_outbox_pending
       ON coord_outbox(destination, delivered_at, created_at, event_id)""",
)

_OPERATION_STATEMENTS = (
    """CREATE TABLE coord_operations (
           principal_kind TEXT NOT NULL,
           principal_id TEXT NOT NULL,
           operation_type TEXT NOT NULL,
           operation_id TEXT NOT NULL,
           request_hash TEXT NOT NULL,
           outcome_kind TEXT NOT NULL,
           outcome_json TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (
               principal_kind, principal_id, operation_type, operation_id
           )
       )""",
    """CREATE INDEX coord_operations_created
       ON coord_operations(created_at)""",
)


def db_path() -> Path:
    return coord_data_dir() / "v0.db"


def _enable_wal(conn: sqlite3.Connection) -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


@contextmanager
def connect_unchecked():
    """Open the DB without requiring the candidate schema version.

    Migration and outbox recovery intentionally need this narrow path. Normal
    coordination APIs call ``init_schema`` before opening operational state.
    """
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    # Install the wait policy before journal-mode negotiation: on a fresh DB,
    # simultaneous bootstraps can otherwise fail here before BEGIN IMMEDIATE
    # gets the chance to serialize them.
    conn.execute("PRAGMA busy_timeout=5000")
    _enable_wal(conn)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def connect():
    """Open operational state only when its schema is fully current."""
    with connect_unchecked() as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != CURRENT_SCHEMA_VERSION:
            raise SchemaError(
                f"coord schema version {version} is not operational; "
                f"expected {CURRENT_SCHEMA_VERSION}"
            )
        yield conn


def _user_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row["name"]
        for row in conn.execute(
            """SELECT name FROM sqlite_schema
               WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"""
        )
    }


def _normalized_default(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    while normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()
    if len(normalized) >= 2 and normalized[0] == normalized[-1] == "'":
        normalized = normalized[1:-1].replace("''", "'")
    return normalized


def _table_columns(conn: sqlite3.Connection, table: str) -> dict[str, tuple]:
    # Key by column name so declaration order and original SQL formatting do
    # not become accidental compatibility requirements. PK ordinal remains a
    # semantic part of each value.
    return {
        row["name"]: (
            (row["type"] or "").upper(),
            bool(row["notnull"]),
            row["pk"],
            _normalized_default(row["dflt_value"]),
            row["hidden"],
        )
        for row in conn.execute(f'PRAGMA table_xinfo("{table}")')
    }


_EXPECTED_LEGACY_COLUMNS = {
    "instance": {"id": ("TEXT", False, 1, None, 0)},
    "rooms": {
        "room_id": ("TEXT", False, 1, None, 0),
        "name": ("TEXT", True, 0, None, 0),
        "created_at": ("INTEGER", True, 0, None, 0),
    },
    "memberships": {
        "room_id": ("TEXT", True, 1, None, 0),
        "principal_kind": ("TEXT", True, 2, None, 0),
        "principal_id": ("TEXT", True, 3, None, 0),
        "permissions": ("TEXT", True, 0, None, 0),
        "history_visibility": ("TEXT", True, 0, "retained", 0),
        "granted_at": ("INTEGER", True, 4, None, 0),
        "revoked_at": ("INTEGER", False, 0, None, 0),
    },
}


def _index_semantics(conn: sqlite3.Connection, table: str) -> Counter:
    """Project indexes to the properties that affect legacy behaviour."""
    indexes = Counter()
    for index in conn.execute(f'PRAGMA index_list("{table}")'):
        quoted_name = index["name"].replace('"', '""')
        key_columns = tuple(
            (
                row["name"],
                (row["coll"] or "BINARY").upper(),
                bool(row["desc"]),
            )
            for row in conn.execute(f'PRAGMA index_xinfo("{quoted_name}")')
            if row["key"]
        )
        indexes[(bool(index["unique"]), bool(index["partial"]), key_columns)] += 1
    return indexes


def _unique_index(*columns: str) -> tuple:
    return (True, False, tuple((column, "BINARY", False) for column in columns))


_EXPECTED_LEGACY_INDEXES = {
    "instance": Counter({_unique_index("id"): 1}),
    "rooms": Counter(
        {
            _unique_index("room_id"): 1,
            _unique_index("name"): 1,
        }
    ),
    "memberships": Counter(
        {
            _unique_index(
                "room_id",
                "principal_kind",
                "principal_id",
                "granted_at",
            ): 1
        }
    ),
}


def _unquoted_sql_keywords(sql: str) -> list[str]:
    """Extract SQL keywords while ignoring strings, identifiers and comments."""
    keywords = []
    index = 0
    while index < len(sql):
        char = sql[index]
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = len(sql) if newline < 0 else newline + 1
        elif sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = len(sql) if end < 0 else end + 2
        elif char in {"'", '"', "`"}:
            quote = char
            index += 1
            while index < len(sql):
                if sql[index] == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
        elif char == "[":
            end = sql.find("]", index + 1)
            index = len(sql) if end < 0 else end + 1
        elif char.isalpha() or char == "_":
            end = index + 1
            while end < len(sql) and (sql[end].isalnum() or sql[end] == "_"):
                end += 1
            keywords.append(sql[index:end].upper())
            index = end
        else:
            index += 1
    return keywords


def _validate_table_constraint_sql(conn: sqlite3.Connection, table: str) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    keywords = _unquoted_sql_keywords(row["sql"] or "")
    if "CHECK" in keywords:
        raise LegacySchemaError(
            f"unversioned coord table {table!r} has an unexpected CHECK constraint"
        )
    for index, keyword in enumerate(keywords):
        if keyword == "CONFLICT":
            policy = keywords[index + 1] if index + 1 < len(keywords) else None
            if policy != "ABORT":
                raise LegacySchemaError(
                    f"unversioned coord table {table!r} has incompatible conflict policy"
                )
        if keyword == "DEFERRABLE" and (
            index == 0 or keywords[index - 1] != "NOT"
        ):
            raise LegacySchemaError(
                f"unversioned coord table {table!r} has a deferred constraint"
            )


def validate_legacy_schema(conn: sqlite3.Connection) -> None:
    """Validate semantic compatibility with the unversioned master schema."""
    tables = _user_tables(conn)
    expected_tables = set(_EXPECTED_LEGACY_COLUMNS)
    if tables != expected_tables:
        raise LegacySchemaError(
            "unversioned coord DB has incompatible tables: "
            f"expected {sorted(expected_tables)}, got {sorted(tables)}"
        )
    unexpected_objects = [
        (row["type"], row["name"])
        for row in conn.execute(
            """SELECT type, name FROM sqlite_schema
               WHERE type IN ('trigger', 'view') AND name NOT LIKE 'sqlite_%'
               ORDER BY type, name"""
        )
    ]
    if unexpected_objects:
        raise LegacySchemaError(
            f"unversioned coord DB has unexpected schema objects: {unexpected_objects!r}"
        )
    table_properties = {
        row["name"]: (bool(row["wr"]), bool(row["strict"]))
        for row in conn.execute("PRAGMA table_list")
        if row["schema"] == "main" and row["type"] == "table"
    }
    for table, expected in _EXPECTED_LEGACY_COLUMNS.items():
        if table_properties.get(table) != (False, False):
            raise LegacySchemaError(
                f"unversioned coord table {table!r} has incompatible table options"
            )
        actual = _table_columns(conn, table)
        if actual != expected:
            raise LegacySchemaError(
                f"unversioned coord table {table!r} is incompatible: "
                f"expected {expected!r}, got {actual!r}"
            )
        _validate_table_constraint_sql(conn, table)
        actual_indexes = _index_semantics(conn, table)
        expected_indexes = _EXPECTED_LEGACY_INDEXES[table]
        if actual_indexes != expected_indexes:
            raise LegacySchemaError(
                f"unversioned coord table {table!r} has incompatible indexes: "
                f"expected {expected_indexes!r}, got {actual_indexes!r}"
            )
    foreign_keys = [
        (
            row["from"],
            row["table"],
            row["to"],
            row["on_update"].upper(),
            row["on_delete"].upper(),
            row["match"].upper(),
        )
        for row in conn.execute('PRAGMA foreign_key_list("memberships")')
    ]
    expected_foreign_keys = [
        ("room_id", "rooms", "room_id", "NO ACTION", "NO ACTION", "NONE")
    ]
    if foreign_keys != expected_foreign_keys:
        raise LegacySchemaError(
            "unversioned memberships.room_id foreign key is incompatible"
        )


def _run_statements(
    conn: sqlite3.Connection,
    statements: tuple[str, ...],
    after_statement: Callable[[str], None] | None,
) -> None:
    for statement in statements:
        conn.execute(statement)
        if after_statement is not None:
            after_statement(statement)


def _migrate_0_to_1(
    conn: sqlite3.Connection,
    after_statement: Callable[[str], None] | None,
) -> None:
    tables = _user_tables(conn)
    if not tables:
        _run_statements(conn, _LEGACY_TABLE_STATEMENTS, after_statement)
    else:
        validate_legacy_schema(conn)
    _run_statements(conn, _OUTBOX_STATEMENTS, after_statement)
    from .outbox import enqueue_coord_event

    enqueue_coord_event(
        conn,
        "coord.schema_migrated",
        {"from_version": 0, "to_version": 1},
    )


def _migrate_1_to_2(
    conn: sqlite3.Connection,
    after_statement: Callable[[str], None] | None,
) -> None:
    _run_statements(conn, _OPERATION_STATEMENTS, after_statement)
    from .outbox import enqueue_coord_event

    enqueue_coord_event(
        conn,
        "coord.schema_migrated",
        {"from_version": 1, "to_version": 2},
    )


_MIGRATIONS = {1: _migrate_0_to_1, 2: _migrate_1_to_2}


def _enqueue_migration_failure(
    from_version: int,
    to_version: int,
    exc: Exception,
) -> None:
    """Use an older valid outbox without admitting ordinary old-schema use."""
    if from_version < 1:
        return
    try:
        with connect_unchecked() as conn:
            if "coord_outbox" not in _user_tables(conn):
                return
            conn.execute("BEGIN IMMEDIATE")
            from .outbox import enqueue_coord_event

            enqueue_coord_event(
                conn,
                "coord.migration_failed",
                {
                    "from_version": from_version,
                    "to_version": to_version,
                    "error_class": type(exc).__name__,
                },
            )
            conn.execute("COMMIT")
    except Exception as recovery_exc:  # normal logs are the final fallback
        log.warning(
            "could not enqueue coord migration failure: %s",
            type(recovery_exc).__name__,
        )


def init_schema(
    *,
    _after_statement: Callable[[str], None] | None = None,
) -> None:
    """Migrate the coordination DB to current, one explicit transaction per step."""
    with connect_unchecked() as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > CURRENT_SCHEMA_VERSION:
            raise FutureSchemaError(
                f"coord schema version {version} is newer than supported "
                f"version {CURRENT_SCHEMA_VERSION}"
            )
        while version < CURRENT_SCHEMA_VERSION:
            target = version + 1
            migration = _MIGRATIONS[target]
            try:
                conn.execute("BEGIN IMMEDIATE")
                # A concurrent bootstrap may have completed while this process
                # waited for the write lock.
                locked_version = conn.execute("PRAGMA user_version").fetchone()[0]
                if locked_version != version:
                    conn.execute("ROLLBACK")
                    version = locked_version
                    continue
                migration(conn, _after_statement)
                conn.execute(f"PRAGMA user_version = {target}")
                conn.execute("COMMIT")
                version = target
            except Exception as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                log.error(
                    "coord migration %s -> %s rolled back: %s",
                    version,
                    target,
                    type(exc).__name__,
                )
                _enqueue_migration_failure(version, target, exc)
                raise


def require_current_schema() -> None:
    with connect_unchecked() as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != CURRENT_SCHEMA_VERSION:
        raise SchemaError(
            f"coord schema version {version} is not operational; "
            f"expected {CURRENT_SCHEMA_VERSION}"
        )


def now_ms() -> int:
    return int(time.time() * 1000)
