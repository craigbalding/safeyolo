"""Stage-2 sticky operator brief contracts."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from safeyolo.agents_store import save_agent
from safeyolo.coord import api, attention, brief, nats_client, outbox, store
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.identity import new_operation_id
from safeyolo.coord.kernel import OperationConflictError, RevisionConflictError

AGENTS = {
    "alice": "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bob": "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "codey": "ag-cccccccccccccccccccccccccccccccc",
    "later": "ag-dddddddddddddddddddddddddddddddd",
}


def _run(coro):
    return asyncio.run(coro)


def _grant(room: str, agent_id: str, *, operation_id: str | None = None) -> None:
    api.grant(
        room,
        "agent",
        agent_id,
        operation_id=operation_id or new_operation_id(),
    )


@pytest.fixture
def brief_env(nats_env, monkeypatch):
    config_dir = nats_env / "config"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(nats_env / "logs"))
    for name, agent_id in AGENTS.items():
        save_agent(name, {"agent_id": agent_id})
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    return nats_env


def _seed_v3_schema() -> None:
    with store.connect_unchecked() as conn:
        conn.execute("BEGIN IMMEDIATE")
        store._migrate_0_to_1(conn, None)
        store._migrate_1_to_2(conn, None)
        store._migrate_2_to_3(conn, None)
        conn.execute("PRAGMA user_version = 3")
        conn.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES ('rm-v3', 'v3', 1)"
        )
        conn.execute("COMMIT")


def test_v3_migration_adds_brief_projection_history_and_immutability(
    isolated_coord,
):
    _seed_v3_schema()

    store.init_schema()

    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        objects = {
            (row["type"], row["name"])
            for row in conn.execute(
                """SELECT type, name FROM sqlite_schema
                   WHERE name LIKE 'coord_brief%'"""
            )
        }
        assert {
            ("table", "coord_briefs"),
            ("table", "coord_brief_revisions"),
            ("trigger", "coord_brief_revisions_immutable_update"),
            ("trigger", "coord_brief_revisions_immutable_delete"),
        } <= objects
        assert conn.execute(
            "SELECT name FROM rooms WHERE room_id = 'rm-v3'"
        ).fetchone()[0] == "v3"


def test_v3_brief_migration_failure_rolls_back_and_retries(isolated_coord):
    _seed_v3_schema()
    statements = 0

    def fail_after_first(_statement):
        nonlocal statements
        statements += 1
        raise RuntimeError("injected stage-2 migration failure")

    with pytest.raises(RuntimeError, match="injected stage-2"):
        store.init_schema(_after_statement=fail_after_first)
    assert statements == 1
    with store.connect_unchecked() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert "coord_brief_revisions" not in {
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
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        assert conn.execute(
            "SELECT count(*) FROM coord_brief_revisions"
        ).fetchone()[0] == 0


def test_set_replay_history_join_and_metadata_only_audit(brief_env):
    room_id = _run(api.create_room("brief-room"))
    _grant("brief-room", AGENTS["alice"])
    _grant("brief-room", AGENTS["bob"])
    markdown = "# Intent\n\nEvidence before inference."

    first = _run(
        api.set_brief(
            "brief-room",
            markdown,
            expected_revision=0,
            operation_id="op-brief-v1",
        )
    )
    replay = _run(
        api.set_brief(
            "brief-room",
            markdown,
            expected_revision=0,
            operation_id="op-brief-v1",
        )
    )

    assert replay == first
    assert first["revision"] == 1
    assert first["attention_count"] == 2
    joined = api.join_room("brief-room", "agent", AGENTS["alice"])
    assert joined["brief"]["markdown"] == markdown
    assert joined["brief"]["revision"] == 1
    assert api.read_brief(
        "brief-room", "agent", AGENTS["bob"]
    ) == joined["brief"]

    history = api.list_brief_history("brief-room")
    assert history["current_revision"] == 1
    assert [item["revision"] for item in history["revisions"]] == [1]
    assert "markdown" not in history["revisions"][0]
    immutable = api.show_brief("brief-room", revision=1)
    assert immutable["markdown"] == markdown

    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM coord_brief_revisions WHERE room_id = ?",
            (room_id,),
        ).fetchone()[0] == 1
        assert conn.execute(
            """SELECT count(*) FROM coord_attention_edges
               WHERE room_id = ? AND kind = 'brief_changed'""",
            (room_id,),
        ).fetchone()[0] == 2
        audit_payload = conn.execute(
            """SELECT payload_json FROM coord_outbox
               WHERE event_type = 'coord.brief_updated'"""
        ).fetchone()[0]
        hint_payloads = [
            row[0]
            for row in conn.execute(
                """SELECT payload_json FROM coord_outbox
                   WHERE event_type = 'coord.attention_hint'"""
            )
        ]
    assert markdown not in audit_payload
    assert all(markdown not in payload for payload in hint_payloads)
    audit_log = (brief_env / "logs" / "safeyolo.jsonl").read_text()
    assert markdown not in audit_log
    assert '"event": "coord.brief_updated"' in audit_log
    details = json.loads(audit_payload)["details"]
    assert details == {
        "actor": "operator",
        "content_hash": first["content_hash"],
        "object_id": first["object_id"],
        "operation_id": "op-brief-v1",
        "operation_type": "coord.brief.set",
        "revision": 1,
        "room_id": room_id,
    }


def test_operation_conflict_and_deterministic_revision_replay(brief_env):
    room_id = _run(api.create_room("conflicts"))
    brief.set_brief(
        room_id,
        "v1",
        expected_revision=0,
        operation_id="op-v1",
    )

    with pytest.raises(OperationConflictError):
        brief.set_brief(
            room_id,
            "changed input",
            expected_revision=0,
            operation_id="op-v1",
        )
    for _ in range(2):
        with pytest.raises(RevisionConflictError) as exc:
            brief.set_brief(
                room_id,
                "stale",
                expected_revision=0,
                operation_id="op-stale",
            )
        assert exc.value.details == {
            "expected_revision": 0,
            "actual_revision": 1,
        }
    assert api.show_brief("conflicts")["markdown"] == "v1"


def test_concurrent_same_base_edits_have_one_winner(brief_env):
    room_id = _run(api.create_room("concurrent"))
    brief.set_brief(
        room_id,
        "v1",
        expected_revision=0,
        operation_id="op-first",
    )

    def update(label: str):
        try:
            return brief.set_brief(
                room_id,
                label,
                expected_revision=1,
                operation_id=f"op-{label}",
            )
        except RevisionConflictError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(update, ("left", "right")))

    successes = [value for value in outcomes if isinstance(value, dict)]
    conflicts = [
        value for value in outcomes if isinstance(value, RevisionConflictError)
    ]
    assert len(successes) == len(conflicts) == 1
    assert successes[0]["revision"] == 2
    assert conflicts[0].details["actual_revision"] == 2
    with store.connect() as conn:
        assert [
            row[0]
            for row in conn.execute(
                """SELECT revision FROM coord_brief_revisions
                   WHERE room_id = ? ORDER BY revision""",
                (room_id,),
            )
        ] == [1, 2]


def test_attention_failure_rolls_back_state_history_event_and_operation(
    brief_env, monkeypatch
):
    room_id = _run(api.create_room("atomic"))
    _grant("atomic", AGENTS["alice"])
    brief.set_brief(
        room_id,
        "v1",
        expected_revision=0,
        operation_id="op-atomic-v1",
    )
    real_create = attention.create_state_attention_edges
    monkeypatch.setattr(
        attention,
        "create_state_attention_edges",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("edge storage")),
    )

    with pytest.raises(OSError, match="edge storage"):
        brief.set_brief(
            room_id,
            "v2",
            expected_revision=1,
            operation_id="op-atomic-v2",
        )

    with store.connect() as conn:
        assert conn.execute(
            "SELECT revision FROM coord_briefs WHERE room_id = ?", (room_id,)
        ).fetchone()[0] == 1
        assert conn.execute(
            """SELECT count(*) FROM coord_brief_revisions
               WHERE room_id = ? AND revision = 2""",
            (room_id,),
        ).fetchone()[0] == 0
        assert conn.execute(
            """SELECT count(*) FROM coord_operations
               WHERE operation_id = 'op-atomic-v2'"""
        ).fetchone()[0] == 0
        assert conn.execute(
            """SELECT count(*) FROM coord_outbox
               WHERE event_type = 'coord.brief_updated'
                 AND payload_json LIKE '%op-atomic-v2%'"""
        ).fetchone()[0] == 0

    monkeypatch.setattr(attention, "create_state_attention_edges", real_create)
    assert brief.set_brief(
        room_id,
        "v2",
        expected_revision=1,
        operation_id="op-atomic-v2",
    )["revision"] == 2


def test_attention_resolution_revocation_later_join_and_restart(brief_env):
    room_id = _run(api.create_room("state"))
    for name in ("alice", "bob", "codey"):
        _grant("state", AGENTS[name])

    changed = _run(
        api.set_brief(
            "state",
            "# v1\n\nOne persistent instruction.",
            expected_revision=0,
            operation_id="op-state-v1",
        )
    )
    edges = {}
    for name in ("alice", "bob", "codey"):
        page = attention.read_feed(AGENTS[name], 0, 10)
        assert len(page["edges"]) == 1
        edge = page["edges"][0]
        assert edge == {
            "attention_id": edge["attention_id"],
            "room_id": room_id,
            "kind": "brief_changed",
            "object_id": changed["object_id"],
            "revision_or_sequence": 1,
        }
        edges[name] = edge

    resolved = _run(
        api.read_attention(AGENTS["alice"], edges["alice"]["attention_id"])
    )
    assert resolved["object"] == api.read_brief(
        "state", "agent", AGENTS["alice"]
    )
    assert resolved["object"]["markdown"] == "# v1\n\nOne persistent instruction."
    assert "markdown" not in resolved["edge"]

    api.revoke_grant(
        "state",
        "agent",
        AGENTS["codey"],
        operation_id="op-revoke-codey",
    )
    assert attention.read_feed(AGENTS["codey"], 0, 10)["edges"] == []
    with pytest.raises(api.NotFoundError):
        _run(
            api.read_attention(
                AGENTS["codey"], edges["codey"]["attention_id"]
            )
        )
    with pytest.raises(api.NoMembershipError):
        api.read_brief("state", "agent", AGENTS["codey"])

    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)
    assert api.show_brief("state")["revision"] == 1
    assert api.show_brief("state", revision=1)["markdown"].startswith("# v1")

    _grant("state", AGENTS["later"])
    later = api.join_room("state", "agent", AGENTS["later"])
    assert later["brief"]["revision"] == 1
    assert later["brief"]["markdown"].startswith("# v1")


def test_hint_outage_keeps_committed_edge_pending_for_recovery(
    brief_env, monkeypatch
):
    _run(api.create_room("hint-recovery"))
    _grant("hint-recovery", AGENTS["alice"])

    async def unavailable(_agent_id, _attention_id):
        raise OSError("nats unavailable")

    monkeypatch.setattr(nats_client, "publish_attention_hint", unavailable)
    result = _run(
        api.set_brief(
            "hint-recovery",
            "# Durable despite a wake outage",
            expected_revision=0,
            operation_id="op-hint-recovery",
        )
    )
    assert result["revision"] == 1
    assert len(attention.read_feed(AGENTS["alice"], 0, 10)["edges"]) == 1
    with store.connect() as conn:
        pending = conn.execute(
            """SELECT delivered_at, attempt_count, last_error_class
               FROM coord_outbox
               WHERE event_type = 'coord.attention_hint'"""
        ).fetchone()
    assert tuple(pending) == (None, 1, "OSError")

    published = []

    async def record_publish(agent_id, attention_id):
        published.append((agent_id, attention_id))

    monkeypatch.setattr(nats_client, "publish_attention_hint", record_publish)
    assert _run(outbox.project_attention_hints()) == 1
    assert published[0][0] == AGENTS["alice"]
    with store.connect() as conn:
        assert conn.execute(
            """SELECT delivered_at FROM coord_outbox
               WHERE event_type = 'coord.attention_hint'"""
        ).fetchone()[0] is not None


@pytest.mark.parametrize(
    ("markdown", "message"),
    (
        ("", "non-empty"),
        ("   ", "non-empty"),
        ("x" * (brief.MAX_BRIEF_BYTES + 1), "exceeds"),
        ("bad\ud800", "valid UTF-8"),
    ),
)
def test_markdown_validation_is_bounded(brief_env, markdown, message):
    room_id = _run(api.create_room(f"bounds-{new_operation_id()}"))
    with pytest.raises(ValueError, match=message):
        brief.set_brief(
            room_id,
            markdown,
            expected_revision=0,
            operation_id=new_operation_id(),
        )


def test_history_rows_cannot_be_updated_or_deleted(brief_env):
    room_id = _run(api.create_room("immutable"))
    brief.set_brief(
        room_id,
        "v1",
        expected_revision=0,
        operation_id="op-immutable",
    )
    with store.connect() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(
                """UPDATE coord_brief_revisions SET markdown = 'forged'
                   WHERE room_id = ? AND revision = 1""",
                (room_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(
                """DELETE FROM coord_brief_revisions
                   WHERE room_id = ? AND revision = 1""",
                (room_id,),
            )
