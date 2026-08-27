"""Acceptance contracts for the Stage-0 coordination kernel."""

from __future__ import annotations

import inspect
import json
import logging
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import safeyolo.events as events
from safeyolo.coord import api, outbox, store
from safeyolo.coord.audit import build_coord_event
from safeyolo.coord.kernel import (
    OperationConflictError,
    RevisionConflictError,
    apply_revisioned_change,
    execute_mutation,
)


@pytest.fixture
def kernel_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "coord"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    return tmp_path


def _legacy_db(
    path: Path,
    *,
    room_unique: bool = True,
    foreign_key: bool = True,
    room_name_collation: str | None = None,
    room_name_conflict: str | None = None,
    permissions_constraint: str = "",
):
    """Create semantic current-master state with deliberately different SQL text."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conflict = (
        f" ON CONFLICT {room_name_conflict}"
        if room_name_conflict is not None
        else ""
    )
    unique = f"UNIQUE{conflict}" if room_unique else ""
    reference = "REFERENCES rooms(room_id)" if foreign_key else ""
    collation = (
        f"COLLATE {room_name_collation}" if room_name_collation is not None else ""
    )
    conn.executescript(
        f"""
        CREATE TABLE instance(id TEXT PRIMARY KEY);
        CREATE TABLE rooms(
            created_at INTEGER NOT NULL,
            name TEXT {collation} NOT NULL {unique},
            room_id TEXT PRIMARY KEY
        );
        CREATE TABLE memberships(
            permissions TEXT NOT NULL {permissions_constraint},
            principal_id TEXT NOT NULL,
            room_id TEXT NOT NULL {reference},
            history_visibility TEXT NOT NULL DEFAULT ('retained'),
            revoked_at INTEGER,
            principal_kind TEXT NOT NULL,
            granted_at INTEGER NOT NULL,
            PRIMARY KEY(room_id, principal_kind, principal_id, granted_at)
        );
        """
    )
    conn.execute("INSERT INTO instance VALUES ('sy-legacy')")
    conn.execute(
        "INSERT INTO rooms(room_id, name, created_at) VALUES ('rm-legacy', 'legacy', 1)"
    )
    conn.execute(
        """INSERT INTO memberships
           (room_id, principal_kind, principal_id, permissions, granted_at)
           VALUES ('rm-legacy', 'agent', 'ag-legacy', 'send,receive', 2)"""
    )
    conn.commit()
    conn.close()


def test_fresh_and_repeated_bootstrap_reach_identical_current_schema(kernel_env):
    first = api.bootstrap()
    with store.connect() as conn:
        schema_before = conn.execute(
            """SELECT type, name, tbl_name FROM sqlite_schema
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        ).fetchall()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == (
            store.CURRENT_SCHEMA_VERSION
        )
    assert api.bootstrap() == first
    with store.connect() as conn:
        schema_after = conn.execute(
            """SELECT type, name, tbl_name FROM sqlite_schema
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        ).fetchall()
    assert [tuple(row) for row in schema_after] == [tuple(row) for row in schema_before]


def test_semantic_current_master_legacy_schema_upgrades_without_data_loss(kernel_env):
    _legacy_db(store.db_path())
    api.bootstrap()
    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == (
            store.CURRENT_SCHEMA_VERSION
        )
        assert dict(conn.execute("SELECT * FROM rooms").fetchone()) == {
            "room_id": "rm-legacy",
            "name": "legacy",
            "created_at": 1,
        }
        assert conn.execute(
            "SELECT principal_id FROM memberships"
        ).fetchone()[0] == "ag-legacy"


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_table",
        "extra_column",
        "room_not_unique",
        "missing_fk",
        "unexpected_trigger",
        "unexpected_view",
        "unexpected_index",
        "room_name_nocase",
        "descending_name_index",
        "unexpected_check",
        "replace_conflict_policy",
    ],
)
def test_malformed_unversioned_schema_is_not_blessed(kernel_env, malformation):
    if malformation == "missing_table":
        path = store.db_path()
        path.parent.mkdir(parents=True)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE instance(id TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()
    elif malformation == "room_name_nocase":
        _legacy_db(store.db_path(), room_name_collation="NOCASE")
    elif malformation == "descending_name_index":
        _legacy_db(store.db_path(), room_unique=False)
        with sqlite3.connect(store.db_path()) as conn:
            conn.execute("CREATE UNIQUE INDEX rooms_name_desc ON rooms(name DESC)")
    elif malformation == "unexpected_check":
        _legacy_db(
            store.db_path(),
            permissions_constraint="CHECK(permissions <> 'receive,send')",
        )
    elif malformation == "replace_conflict_policy":
        _legacy_db(store.db_path(), room_name_conflict="REPLACE")
    else:
        _legacy_db(
            store.db_path(),
            room_unique=malformation != "room_not_unique",
            foreign_key=malformation != "missing_fk",
        )
        if malformation == "extra_column":
            with sqlite3.connect(store.db_path()) as conn:
                conn.execute("ALTER TABLE rooms ADD COLUMN accidental TEXT")
        elif malformation == "unexpected_trigger":
            with sqlite3.connect(store.db_path()) as conn:
                conn.execute(
                    """CREATE TRIGGER hostile AFTER INSERT ON rooms
                       BEGIN
                           DELETE FROM rooms WHERE room_id = NEW.room_id;
                       END"""
                )
        elif malformation == "unexpected_view":
            with sqlite3.connect(store.db_path()) as conn:
                conn.execute("CREATE VIEW room_names AS SELECT name FROM rooms")
        elif malformation == "unexpected_index":
            with sqlite3.connect(store.db_path()) as conn:
                conn.execute(
                    "CREATE INDEX memberships_principal ON memberships(principal_id)"
                )
    with pytest.raises(store.LegacySchemaError):
        store.init_schema()
    with sqlite3.connect(store.db_path()) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert "coord_outbox" not in {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }


def test_view_only_unversioned_schema_is_not_classified_as_fresh(kernel_env):
    path = store.db_path()
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE VIEW hostile AS SELECT 1 AS value")

    with pytest.raises(store.LegacySchemaError):
        store.init_schema()

    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute(
            "SELECT type FROM sqlite_schema WHERE name = 'hostile'"
        ).fetchone()[0] == "view"
        assert "coord_outbox" not in {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }


def test_semantically_equivalent_explicit_unique_index_is_admitted(kernel_env):
    _legacy_db(store.db_path(), room_unique=False)
    with sqlite3.connect(store.db_path()) as conn:
        conn.execute("CREATE UNIQUE INDEX rooms_name_unique ON rooms(name)")

    store.init_schema()

    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == (
            store.CURRENT_SCHEMA_VERSION
        )
        assert conn.execute("SELECT name FROM rooms").fetchone()[0] == "legacy"


def test_migrations_do_not_use_executescript():
    source = inspect.getsource(store)
    assert ".executescript(" not in source


def test_simultaneous_bootstraps_serialize_to_one_complete_schema(kernel_env):
    workers = 8
    barrier = threading.Barrier(workers)

    def bootstrap():
        barrier.wait()
        store.init_schema()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda _index: bootstrap(), range(workers)))
    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == (
            store.CURRENT_SCHEMA_VERSION
        )
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute(
            "SELECT count(*) FROM coord_outbox WHERE event_type='coord.schema_migrated'"
        ).fetchone()[0] == store.CURRENT_SCHEMA_VERSION


def _seed_v2_schema() -> None:
    with store.connect_unchecked() as conn:
        conn.execute("BEGIN IMMEDIATE")
        store._migrate_0_to_1(conn, None)
        store._migrate_1_to_2(conn, None)
        conn.execute("PRAGMA user_version = 2")
        conn.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES ('rm-v2', 'v2', 1)"
        )
        conn.execute("COMMIT")


def test_v2_attention_migration_preserves_state(kernel_env):
    _seed_v2_schema()

    store.init_schema()

    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert conn.execute(
            "SELECT name FROM rooms WHERE room_id = 'rm-v2'"
        ).fetchone()[0] == "v2"
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        assert {
            "coord_attention_feeds",
            "coord_attention_edges",
            "coord_message_attention_projection",
        } <= tables

        edge = (
            "ag-future",
            "rm-v2",
            "brief_changed",
            "brief-room",
            7,
        )
        for feed_sequence, revision in enumerate((1, 2), start=1):
            conn.execute(
                """INSERT INTO coord_attention_edges
                   (recipient_agent_id, feed_sequence, attention_id, room_id,
                    kind, object_id, revision_or_sequence,
                    membership_granted_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    edge[0],
                    feed_sequence,
                    f"attn-{'a' * 31}{feed_sequence}",
                    edge[1],
                    edge[2],
                    edge[3],
                    revision,
                    edge[4],
                ),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO coord_attention_edges
                   (recipient_agent_id, feed_sequence, attention_id, room_id,
                    kind, object_id, revision_or_sequence,
                    membership_granted_at, created_at)
                   VALUES (?, 3, ?, ?, ?, ?, 2, ?, 1)""",
                (
                    edge[0],
                    "attn-" + "b" * 32,
                    edge[1],
                    edge[2],
                    edge[3],
                    edge[4],
                ),
            )


def test_v2_attention_migration_failure_rolls_back_and_retries(kernel_env):
    _seed_v2_schema()
    statements = 0

    def fail_after_first(_statement):
        nonlocal statements
        statements += 1
        raise RuntimeError("injected stage-1 migration failure")

    with pytest.raises(RuntimeError, match="injected stage-1"):
        store.init_schema(_after_statement=fail_after_first)
    assert statements == 1
    with store.connect_unchecked() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
        assert "coord_attention_feeds" not in {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        assert conn.execute(
            """SELECT count(*) FROM coord_outbox
               WHERE event_type = 'coord.migration_failed'"""
        ).fetchone()[0] == 1

    store.init_schema()
    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3


def test_pre_outbox_migration_failure_rolls_back_and_only_logs_operationally(
    kernel_env, caplog
):
    def fail(_statement):
        raise RuntimeError("injected")

    with caplog.at_level(logging.ERROR, logger="safeyolo.coord.store"):
        with pytest.raises(RuntimeError, match="injected"):
            store.init_schema(_after_statement=fail)
    with sqlite3.connect(store.db_path()) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert not {
            row[0]
            for row in conn.execute(
                """SELECT name FROM sqlite_schema
                   WHERE type='table' AND name NOT LIKE 'sqlite_%'"""
            )
        }
    assert "rolled back" in caplog.text
    assert not (kernel_env / "logs" / "safeyolo.jsonl").exists()


def test_later_migration_failure_uses_older_outbox_despite_schema_gate(kernel_env):
    with store.connect_unchecked() as conn:
        conn.execute("BEGIN IMMEDIATE")
        store._migrate_0_to_1(conn, None)
        conn.execute("PRAGMA user_version = 1")
        conn.execute("COMMIT")

    def fail(_statement):
        raise RuntimeError("injected")

    with pytest.raises(RuntimeError, match="injected"):
        store.init_schema(_after_statement=fail)
    with pytest.raises(store.SchemaError):
        store.require_current_schema()
    with pytest.raises(store.SchemaError):
        with store.connect():
            pass
    with store.connect_unchecked() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
        assert conn.execute(
            """SELECT count(*) FROM coord_outbox
               WHERE event_type='coord.migration_failed'"""
        ).fetchone()[0] == 1
        assert "coord_operations" not in {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }
    # The recovery projector is deliberately usable on the valid v1 outbox.
    assert outbox.project_pending() == 2
    events = [
        json.loads(line)["event"]
        for line in (kernel_env / "logs" / "safeyolo.jsonl").read_text().splitlines()
    ]
    assert sorted(events) == ["coord.migration_failed", "coord.schema_migrated"]


def test_future_schema_is_rejected_without_stamping(kernel_env):
    store.db_path().parent.mkdir(parents=True)
    with sqlite3.connect(store.db_path()) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(store.FutureSchemaError):
        store.init_schema()
    with sqlite3.connect(store.db_path()) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 99


def _seed_room():
    api.bootstrap()
    with store.connect() as conn:
        conn.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES ('rm-r', 'r', 1)"
        )


def test_grant_and_revoke_replay_original_results_and_conflict(kernel_env):
    _seed_room()
    api.grant(
        "r",
        "agent",
        "ag-a",
        permissions=["receive", "send"],
        operation_id="op-grant",
    )
    api.grant(
        "r",
        "agent",
        "ag-a",
        permissions=["send", "receive"],
        operation_id="op-grant",
    )
    assert api.revoke_grant(
        "r", "agent", "ag-a", operation_id="op-revoke"
    ) is True
    assert api.revoke_grant(
        "r", "agent", "ag-a", operation_id="op-revoke"
    ) is True
    with pytest.raises(OperationConflictError):
        api.grant("r", "agent", "ag-b", operation_id="op-grant")
    with pytest.raises(OperationConflictError):
        api.grant("r", "operator", "operator", operation_id="op-grant")
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM coord_operations").fetchone()[0] == 2
        event_types = [
            row[0]
            for row in conn.execute(
                "SELECT event_type FROM coord_outbox ORDER BY created_at, event_id"
            )
        ]
    assert event_types.count("coord.grant_changed") == 1
    assert event_types.count("coord.grant_revoked") == 1
    assert event_types.count("coord.operation_conflict") == 1


def test_concurrent_same_operation_executes_grant_once(kernel_env):
    _seed_room()
    workers = 12
    barrier = threading.Barrier(workers)

    def grant_once():
        barrier.wait()
        api.grant("r", "agent", "ag-a", operation_id="op-concurrent")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda _index: grant_once(), range(workers)))
    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM memberships WHERE principal_id='ag-a'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT count(*) FROM coord_operations WHERE operation_id='op-concurrent'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT count(*) FROM coord_outbox WHERE event_type='coord.grant_changed'"
        ).fetchone()[0] == 1


def test_grant_revoke_regrant_survives_identical_timestamps(
    kernel_env, monkeypatch
):
    monkeypatch.setattr(store, "now_ms", lambda: 7)
    _seed_room()

    api.grant("r", "agent", "ag-a", operation_id="op-grant-first")
    api.grant("r", "agent", "ag-a", operation_id="op-grant-active-noop")
    assert api.revoke_grant(
        "r", "agent", "ag-a", operation_id="op-revoke-same-ms"
    ) is True
    api.grant("r", "agent", "ag-a", operation_id="op-grant-restored")

    assert api.join_room("r", "agent", "ag-a")["permissions"] == [
        "receive",
        "send",
    ]
    with store.connect() as conn:
        transitions = [
            tuple(row)
            for row in conn.execute(
                """SELECT granted_at, revoked_at FROM memberships
                   WHERE principal_id = 'ag-a' ORDER BY granted_at"""
            )
        ]
        assert transitions == [(7, 7), (8, None)]
        assert conn.execute(
            """SELECT count(*) FROM coord_outbox
               WHERE event_type = 'coord.grant_changed'"""
        ).fetchone()[0] == 2
        assert conn.execute(
            """SELECT count(*) FROM coord_operations
               WHERE operation_type = 'coord.grant'"""
        ).fetchone()[0] == 3


def test_committed_event_remains_pending_until_projector_recovers(
    kernel_env, monkeypatch
):
    _seed_room()
    real_project_pending = outbox.project_pending
    monkeypatch.setattr(outbox, "project_pending", lambda **_kwargs: 0)
    api.grant("r", "agent", "ag-a", operation_id="op-pending")
    with store.connect() as conn:
        row = conn.execute(
            """SELECT delivered_at FROM coord_outbox
               WHERE event_type='coord.grant_changed'"""
        ).fetchone()
        assert row[0] is None
    monkeypatch.setattr(outbox, "project_pending", real_project_pending)
    api.bootstrap()
    with store.connect() as conn:
        assert conn.execute(
            """SELECT delivered_at FROM coord_outbox
               WHERE event_type='coord.grant_changed'"""
        ).fetchone()[0] is not None


def test_benign_revoke_noop_is_recorded_but_not_audit_event(kernel_env):
    _seed_room()
    assert api.revoke_grant("r", "agent", "ag-a", operation_id="op-noop") is False
    assert api.revoke_grant("r", "agent", "ag-a", operation_id="op-noop") is False
    with store.connect() as conn:
        assert conn.execute(
            "SELECT outcome_json FROM coord_operations WHERE operation_id='op-noop'"
        ).fetchone()[0] == "false"
        assert conn.execute(
            "SELECT count(*) FROM coord_outbox WHERE event_type='coord.grant_revoked'"
        ).fetchone()[0] == 0


def test_revision_projection_history_and_deterministic_rejection(kernel_env):
    api.bootstrap()
    with store.connect() as conn:
        conn.execute(
            "CREATE TABLE test_current(object_id TEXT PRIMARY KEY, revision INTEGER, value TEXT)"
        )
        conn.execute(
            """CREATE TABLE test_history(
                   object_id TEXT, revision INTEGER, value TEXT,
                   PRIMARY KEY(object_id, revision))"""
        )

    def change(expected, value):
        def mutate(conn):
            row = conn.execute(
                "SELECT revision FROM test_current WHERE object_id='x'"
            ).fetchone()
            actual = row[0] if row else 0
            return apply_revisioned_change(
                expected_revision=expected,
                actual_revision=actual,
                write_projection=lambda revision: conn.execute(
                    """INSERT INTO test_current VALUES ('x', ?, ?)
                       ON CONFLICT(object_id) DO UPDATE
                       SET revision=excluded.revision, value=excluded.value""",
                    (revision, value),
                ),
                append_history=lambda revision: conn.execute(
                    "INSERT INTO test_history VALUES ('x', ?, ?)",
                    (revision, value),
                ),
            )

        return mutate

    assert execute_mutation(
        operation_id="op-v1",
        operation_type="coord.test_revision",
        request={"expected": 0, "value": "one"},
        mutate=change(0, "one"),
    ) == 1
    assert execute_mutation(
        operation_id="op-v2",
        operation_type="coord.test_revision",
        request={"expected": 1, "value": "two"},
        mutate=change(1, "two"),
    ) == 2
    with pytest.raises(RevisionConflictError):
        execute_mutation(
            operation_id="op-stale",
            operation_type="coord.test_revision",
            request={"expected": 1, "value": "stale"},
            mutate=change(1, "stale"),
        )
    # The deterministic rejection is replayed even though state remains at 2.
    with pytest.raises(RevisionConflictError):
        execute_mutation(
            operation_id="op-stale",
            operation_type="coord.test_revision",
            request={"expected": 1, "value": "stale"},
            mutate=change(1, "stale"),
        )
    with store.connect() as conn:
        assert tuple(conn.execute("SELECT revision, value FROM test_current").fetchone()) == (
            2,
            "two",
        )
        assert [tuple(row) for row in conn.execute(
            "SELECT revision, value FROM test_history ORDER BY revision"
        )] == [(1, "one"), (2, "two")]


def test_infrastructure_failure_rolls_back_and_does_not_consume_id(kernel_env):
    api.bootstrap()
    with pytest.raises(OSError):
        execute_mutation(
            operation_id="op-retryable",
            operation_type="coord.test_failure",
            request={"x": 1},
            mutate=lambda conn: (_ for _ in ()).throw(OSError("disk")),
        )
    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM coord_operations WHERE operation_id='op-retryable'"
        ).fetchone()[0] == 0


def test_history_append_failure_rolls_projection_back_and_id_remains_retryable(
    kernel_env,
):
    api.bootstrap()
    with store.connect() as conn:
        conn.execute(
            "CREATE TABLE test_current(object_id TEXT PRIMARY KEY, revision INTEGER)"
        )
        conn.execute("INSERT INTO test_current VALUES ('x', 1)")

    def broken(conn):
        return apply_revisioned_change(
            expected_revision=1,
            actual_revision=1,
            write_projection=lambda revision: conn.execute(
                "UPDATE test_current SET revision=? WHERE object_id='x'", (revision,)
            ),
            append_history=lambda _revision: (_ for _ in ()).throw(
                OSError("history unavailable")
            ),
        )

    with pytest.raises(OSError, match="history unavailable"):
        execute_mutation(
            operation_id="op-history-retry",
            operation_type="coord.test_history_failure",
            request={"expected": 1},
            mutate=broken,
        )
    with store.connect() as conn:
        assert conn.execute(
            "SELECT revision FROM test_current WHERE object_id='x'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT count(*) FROM coord_operations WHERE operation_id='op-history-retry'"
        ).fetchone()[0] == 0


def test_outbox_replays_same_event_id_after_append_mark_crash(kernel_env):
    api.bootstrap()
    log_path = kernel_env / "logs" / "safeyolo.jsonl"
    log_path.unlink()
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        event_id = outbox.enqueue_coord_event(
            conn,
            "coord.grant_changed",
            {
                "actor": "operator",
                "room_id": "rm-r",
                "operation_id": "op-x",
                "operation_type": "coord.grant",
                "transition": "granted",
            },
        )
        conn.execute("COMMIT")

    def crash(_event_id):
        raise RuntimeError("after append")

    assert outbox.project_pending(_after_append=crash) == 0
    assert outbox.project_pending() == 1
    lines = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert [line["event_id"] for line in lines] == [event_id, event_id]


def test_outbox_does_not_acknowledge_directory_fsync_failure(
    kernel_env, monkeypatch
):
    api.bootstrap()
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        event_id = outbox.enqueue_coord_event(
            conn,
            "coord.grant_changed",
            {
                "actor": "operator",
                "room_id": "rm-r",
                "operation_id": "op-fsync",
                "operation_type": "coord.grant",
                "transition": "granted",
            },
        )
        conn.execute("COMMIT")

    real_fsync_directory = events._fsync_directory
    monkeypatch.setattr(
        events,
        "_fsync_directory",
        lambda _path: (_ for _ in ()).throw(OSError("directory fsync failed")),
    )

    assert outbox.project_pending() == 0
    with store.connect() as conn:
        row = conn.execute(
            """SELECT delivered_at, attempt_count, last_error_class
               FROM coord_outbox WHERE event_id = ?""",
            (event_id,),
        ).fetchone()
        assert tuple(row) == (None, 1, "OSError")

    monkeypatch.setattr(events, "_fsync_directory", real_fsync_directory)
    assert outbox.project_pending() == 1
    with store.connect() as conn:
        row = conn.execute(
            "SELECT delivered_at, attempt_count, last_error_class FROM coord_outbox WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        assert row["delivered_at"] is not None
        assert row["attempt_count"] == 2
        assert row["last_error_class"] is None
    projected = [
        json.loads(line)["event_id"]
        for line in (kernel_env / "logs" / "safeyolo.jsonl").read_text().splitlines()
    ]
    assert projected.count(event_id) == 2


@pytest.mark.parametrize("key", ["body", "brief", "description", "content", "prose"])
def test_coord_audit_rejects_canonical_content_keys(key):
    with pytest.raises(ValueError, match="prohibited/unknown"):
        build_coord_event("coord.grant_changed", {key: "do not log me"})


def test_coord_producers_have_no_direct_jsonl_append_path():
    from safeyolo.coord import audit, kernel

    for module in (api, audit, kernel, store):
        assert "append_event_strict" not in inspect.getsource(module)
