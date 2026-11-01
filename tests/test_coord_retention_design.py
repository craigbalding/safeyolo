"""Executable proposal for #394; no production cleanup is installed.

The fixture loads the native schema and executes the native authorization
queries. Only the proposed floor/cleanup and provider observations are models.
Use small caps to challenge the contract without compiling the native product.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from time import monotonic, sleep

import nats
import pytest
from nats.js.errors import NotFoundError

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "proxy/src/agent_api/coord.rs").read_text()


def native_query(function: str, beginning: str) -> str:
    """Take the actual SQL literal from the named native function, or fail."""
    body = SOURCE.split(f"fn {function}(", 1)[1].split("\nfn ", 1)[0]
    matches = re.findall(r'"(' + re.escape(beginning) + r'[^"\\]*)"', body)
    assert len(matches) == 1, (function, matches)
    return matches[0]


FEED_QUERY = native_query("read_attention_feed", "SELECT e.attention_id")
EDGE_QUERY = native_query("read_attention_edge", "SELECT e.attention_id")


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


@pytest.fixture
def ledger(tmp_path: Path) -> Path:
    path = tmp_path / "proposal.db"
    with closing(connect(path)) as db, db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript((ROOT / "proxy/src/coord_schema.sql").read_text())
        # Test-only DDL. Production schema/version 5 is unchanged.
        db.execute("""ALTER TABLE coord_attention_feeds ADD COLUMN discarded_through INTEGER NOT NULL DEFAULT 0
                      CHECK(discarded_through>=0 AND discarded_through<=last_sequence)""")
        for room in ("rm-a", "rm-b"):
            db.execute("INSERT INTO rooms VALUES(?,?,0)", (room, room))
            for agent in ("ag-bob", "ag-alice"):
                db.execute("INSERT INTO memberships VALUES(?,'agent',?,'receive','retained',1,NULL)", (room, agent))
        # Delivered audit rows deliberately share the hint outbox table.
        for event in ("coord.attention_projection_lost", "coord.brief_updated"):
            payload = json.dumps({"event": event, "details": {"room_id": "rm-a", "from_sequence": 7, "to_sequence": 9}})
            db.execute("INSERT INTO coord_outbox VALUES(?,'audit-jsonl',?,?,0,1,0,NULL)", (event, event, payload))
    return path


def compact(db: sqlite3.Connection, agent: str, cap: int, expired: frozenset = frozenset()) -> dict:
    """Retire a prefix and its hints in the caller's write transaction.

    expired contains exact (attention_id, room_id, canonical sequence, grant)
    observations of missing messages. Unknown provider results contribute none.
    A retained brief or a message without such an observation stops that prefix.
    """
    assert cap > 0
    feed = db.execute("SELECT * FROM coord_attention_feeds WHERE recipient_agent_id=?", (agent,)).fetchone()
    if feed is None:
        return {"edges_deleted": 0, "hints_deleted": 0, "discarded_through": 0}
    floor = max(feed["discarded_through"], feed["last_sequence"] - cap)
    rows = db.execute(
        "SELECT * FROM coord_attention_edges WHERE recipient_agent_id=? AND feed_sequence>? ORDER BY feed_sequence",
        (agent, floor),
    )
    for row in rows:
        proof = (row["attention_id"], row["room_id"], row["revision_or_sequence"], row["membership_granted_at"])
        if row["kind"] != "message" or proof not in expired:
            break
        floor = row["feed_sequence"]
    db.execute("UPDATE coord_attention_feeds SET discarded_through=? WHERE recipient_agent_id=?", (floor, agent))
    # Filter both destination and event type. delivered_at alone is insufficient.
    hints = db.execute(
        """DELETE FROM coord_outbox WHERE destination='attention-nats' AND event_type='coord.attention_hint'
           AND (delivered_at IS NOT NULL OR event_id IN
             (SELECT 'evt-' || substr(attention_id,6) FROM coord_attention_edges WHERE recipient_agent_id=? AND feed_sequence<=?))""",
        (agent, floor),
    ).rowcount
    edges = db.execute(
        "DELETE FROM coord_attention_edges WHERE recipient_agent_id=? AND feed_sequence<=?", (agent, floor)
    ).rowcount
    return {"edges_deleted": edges, "hints_deleted": hints, "discarded_through": floor}


def cleanup(path: Path, cap: int, *, agent: str = "ag-bob", expired: frozenset = frozenset()) -> dict:
    with closing(connect(path)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        return compact(db, agent, cap, expired)


def append(path: Path, number: int, *, cap: int | None = None, room: str = "rm-a", agent: str = "ag-bob",
           grant: int = 1, kind: str = "message") -> int:
    """Model one native materialization transaction, including its hint."""
    with closing(connect(path)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR IGNORE INTO coord_attention_feeds(recipient_agent_id) VALUES(?)", (agent,))
        sequence = db.execute(
            "UPDATE coord_attention_feeds SET last_sequence=last_sequence+1 WHERE recipient_agent_id=? RETURNING last_sequence",
            (agent,),
        ).fetchone()[0]
        attention = f"attn-{agent}-{room}-{number}"
        db.execute(
            "INSERT INTO coord_attention_edges VALUES(?,?,?,?,?,?,?,?,?)",
            (agent, sequence, attention, room, kind, f"msg-{room}-{number}", number, grant, number),
        )
        db.execute(
            """INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at)
               VALUES(?,'attention-nats','coord.attention_hint',json_object('attention_id',?,'recipient_agent_id',?,'feed_sequence',?),?)""",
            (f"evt-{attention.removeprefix('attn-')}", attention, agent, sequence, number),
        )
        if cap is not None:
            compact(db, agent, cap)
        return sequence


def native_page(db: sqlite3.Connection, since: int, limit: int, agent: str = "ag-bob") -> dict:
    """Run the native query and its current caller-owned cursor calculation."""
    feed = db.execute("SELECT last_sequence FROM coord_attention_feeds WHERE recipient_agent_id=?", (agent,)).fetchone()
    highwater = feed[0] if feed else 0
    edges = [dict(row) for row in db.execute(FEED_QUERY, (agent, since, limit))]
    if len(edges) == limit:
        next_cursor = db.execute("SELECT feed_sequence FROM coord_attention_edges WHERE attention_id=?",
                                 (edges[-1]["attention_id"],)).fetchone()[0]
    else:
        next_cursor = max(since, highwater)
    return {"status": 200, "edges": edges, "next_cursor": next_cursor}


def page(path: Path, since: int, limit: int = 200, agent: str = "ag-bob") -> dict:
    with closing(connect(path)) as db, db:
        db.execute("BEGIN")
        feed = db.execute("SELECT * FROM coord_attention_feeds WHERE recipient_agent_id=?", (agent,)).fetchone()
        floor = feed["discarded_through"] if feed else 0
        if since < floor:
            return {"status": 409, "error": "coord_attention_truncated", "requested_cursor": since,
                    "discarded_through": floor, "highwater": feed["last_sequence"],
                    "unavailable_range": [since + 1, floor], "retry_since": floor}
        return native_page(db, since, limit, agent)


def resolve(path: Path, attention: str, observation: str, *, agent: str = "ag-bob", after_probe=lambda: None) -> dict:
    """Model classification around the native pre/post-provider access query."""
    with closing(connect(path)) as db:
        before = db.execute(EDGE_QUERY, (agent, attention)).fetchone()
    if before is None:
        return {"status": 404}
    after_probe()
    with closing(connect(path)) as db, db:
        db.execute("BEGIN")
        after = db.execute(EDGE_QUERY, (agent, attention)).fetchone()
        if after is None or tuple(after) != tuple(before):
            return {"status": 404}
        sequence = db.execute("SELECT feed_sequence FROM coord_attention_edges WHERE attention_id=?", (attention,)).fetchone()[0]
    if observation == "missing_message":
        return {"status": 410, "error": "coord_attention_canonical_missing", "edge": dict(after), "feed_sequence": sequence}
    if observation in ("timeout", "missing_stream"):
        return {"status": 503}
    if observation == "wrong_object":
        return {"status": 500}
    assert observation == "present"
    return {"status": 200, "edge": dict(after), "object": {"msg_id": after["object_id"]}}


def proof(path: Path, number: int, room: str = "rm-a") -> tuple:
    with closing(connect(path)) as db:
        row = db.execute(
            "SELECT attention_id,room_id,revision_or_sequence,membership_granted_at FROM coord_attention_edges WHERE revision_or_sequence=? AND room_id=?",
            (number, room),
        ).fetchone()
        return tuple(row)


def test_native_query_exposes_the_silent_delete_counterexample(ledger):
    for number in range(1, 5):
        append(ledger, number)
    with closing(connect(ledger)) as db, db:
        db.execute("DELETE FROM coord_attention_edges WHERE feed_sequence<=2")
        old = native_page(db, 0, 200)
    assert old["next_cursor"] == 4
    assert len(old["edges"]) == 2
    assert "unavailable_range" not in old  # Two logical edges silently skipped.


def test_cap_discloses_the_exact_prefix_and_keeps_callers_independent(ledger):
    for number in range(1, 6):
        append(ledger, number)
    fast = page(ledger, 0)
    assert fast["next_cursor"] == 5
    result = cleanup(ledger, 3)
    assert result == {"edges_deleted": 2, "hints_deleted": 2, "discarded_through": 2}
    stale = page(ledger, 0)
    assert stale == {"status": 409, "error": "coord_attention_truncated", "requested_cursor": 0,
                     "discarded_through": 2, "highwater": 5, "unavailable_range": [1, 2], "retry_since": 2}
    assert "next_cursor" not in stale
    assert page(ledger, fast["next_cursor"])["next_cursor"] == 5
    # A caller deliberately accepts the disclosed loss, then resolves retained
    # attention. The suggestion in a 409 is never an automatic cursor update.
    first = page(ledger, stale["retry_since"], 1)
    assert first["next_cursor"] == 3
    assert first["edges"][0]["revision_or_sequence"] == 3
    assert page(ledger, 3)["next_cursor"] == 5


def test_hints_and_one_caller_advancing_are_not_consumption(ledger):
    append(ledger, 1)
    attention = proof(ledger, 1)[0]
    with closing(connect(ledger)) as db, db:
        db.execute("UPDATE coord_outbox SET delivered_at=10 WHERE destination='attention-nats'")
    assert page(ledger, 0)["next_cursor"] == 1
    assert cleanup(ledger, 3) == {"edges_deleted": 0, "hints_deleted": 1, "discarded_through": 0}
    assert page(ledger, 0)["edges"][0]["attention_id"] == attention
    assert resolve(ledger, attention, "present")["status"] == 200


@pytest.mark.parametrize("observation,expected", [
    ("missing_message", 410), ("timeout", 503), ("missing_stream", 503), ("wrong_object", 500), ("present", 200),
])
def test_retained_edge_classifies_canonical_expiry_without_advancing(ledger, observation, expected):
    append(ledger, 1)
    edge = page(ledger, 0)["edges"][0]
    result = resolve(ledger, edge["attention_id"], observation)
    assert result["status"] == expected
    assert "next_cursor" not in result
    assert page(ledger, 0)["edges"] == [edge]
    assert cleanup(ledger, 3)["discarded_through"] == 0


def test_only_a_confirmed_expired_prefix_is_reclaimed(ledger):
    for number in range(1, 5):
        append(ledger, number, kind="brief_changed" if number == 2 else "message")
    expired = frozenset(proof(ledger, n) for n in (1, 3, 4))
    assert cleanup(ledger, 5, expired=expired)["discarded_through"] == 1
    assert [edge["revision_or_sequence"] for edge in page(ledger, 1)["edges"]] == [2, 3, 4]
    # Interior orphans stay bounded rows; a floor must not hide the live brief.
    assert resolve(ledger, proof(ledger, 3)[0], "missing_message")["status"] == 410
    assert cleanup(ledger, 2, expired=expired)["discarded_through"] == 4
    assert page(ledger, 1)["unavailable_range"] == [2, 4]
    assert page(ledger, 4) == {"status": 200, "edges": [], "next_cursor": 4}


def test_wrong_expiry_identity_and_unknown_provider_do_not_justify_deletion(ledger):
    append(ledger, 1)
    identity = proof(ledger, 1)
    wrong_generation = (*identity[:3], 999)
    assert cleanup(ledger, 3, expired=frozenset([wrong_generation]))["edges_deleted"] == 0
    assert cleanup(ledger, 3)["edges_deleted"] == 0


def test_revoke_regrant_and_superseded_active_generations_do_not_resurrect(ledger):
    append(ledger, 1)
    old = proof(ledger, 1)[0]
    with closing(connect(ledger)) as db, db:
        db.execute("UPDATE memberships SET revoked_at=2 WHERE principal_id='ag-bob' AND room_id='rm-a'")
    assert page(ledger, 0)["edges"] == []
    assert resolve(ledger, old, "missing_message") == {"status": 404}
    with closing(connect(ledger)) as db, db:
        db.execute("INSERT INTO memberships VALUES('rm-a','agent','ag-bob','receive','retained',3,NULL)")
    append(ledger, 2, grant=3)
    assert [edge["revision_or_sequence"] for edge in page(ledger, 0)["edges"]] == [2]
    # Match the native permission-change path, which can leave older grants active.
    with closing(connect(ledger)) as db, db:
        db.execute("INSERT INTO memberships VALUES('rm-a','agent','ag-bob','send','retained',4,NULL)")
    assert page(ledger, 0)["edges"] == []
    assert resolve(ledger, proof(ledger, 2)[0], "missing_message") == {"status": 404}
    cleanup(ledger, 1)
    loss = page(ledger, 0)
    assert loss["unavailable_range"] == [1, 1]
    assert "room_id" not in loss and "edge" not in loss
    with closing(connect(ledger)) as db:
        assert db.execute("SELECT count(*) FROM memberships WHERE room_id='rm-a' AND principal_id='ag-bob'").fetchone()[0] == 3


@pytest.mark.parametrize("regrant", [False, True])
def test_revoke_during_provider_io_hides_even_expiry_metadata(ledger, regrant):
    append(ledger, 1)
    assert resolve(ledger, proof(ledger, 1)[0], "missing_message", agent="ag-alice") == {"status": 404}

    def revoke():
        with closing(connect(ledger)) as db, db:
            db.execute("UPDATE memberships SET revoked_at=2 WHERE principal_id='ag-bob'")
            if regrant:
                db.execute("INSERT INTO memberships VALUES('rm-a','agent','ag-bob','receive','retained',3,NULL)")

    assert resolve(ledger, proof(ledger, 1)[0], "missing_message", after_probe=revoke) == {"status": 404}
    assert resolve(ledger, "attn-unknown", "missing_message") == {"status": 404}


def test_compaction_between_feed_and_object_read_requires_a_fresh_feed(ledger):
    append(ledger, 1)
    first = page(ledger, 0)["edges"][0]
    append(ledger, 2, cap=1)
    assert resolve(ledger, first["attention_id"], "present") == {"status": 404}
    assert page(ledger, 0)["status"] == 409


def test_counts_audit_and_projection_frontier_survive_repeat_cleanup(ledger):
    for number in range(1, 6):
        append(ledger, number)
    with closing(connect(ledger)) as db, db:
        db.execute("INSERT INTO coord_message_attention_projection VALUES('rm-a',5,0)")
    assert cleanup(ledger, 2)["edges_deleted"] == 3
    assert cleanup(ledger, 20) == {"edges_deleted": 0, "hints_deleted": 0, "discarded_through": 3}
    with closing(connect(ledger)) as db:
        assert db.execute("SELECT last_sequence FROM coord_attention_feeds").fetchone()[0] == 5
        assert db.execute("SELECT last_sequence FROM coord_message_attention_projection").fetchone()[0] == 5
        assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='audit-jsonl'").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM coord_attention_edges").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='attention-nats'").fetchone()[0] == 2


def test_sql_failure_rolls_back_floor_hints_and_edges_together(ledger):
    for number in range(1, 4):
        append(ledger, number)
    with closing(connect(ledger)) as db:
        db.execute("CREATE TRIGGER fail_cleanup BEFORE DELETE ON coord_attention_edges BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected cleanup failure"):
        cleanup(ledger, 1)
    assert page(ledger, 0)["status"] == 200
    with closing(connect(ledger)) as db:
        assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='attention-nats'").fetchone()[0] == 3
        db.execute("DROP TRIGGER fail_cleanup")
    assert cleanup(ledger, 1)["edges_deleted"] == 2


@pytest.mark.parametrize("commit", [False, True])
def test_process_exit_at_commit_boundary_reopens_consistently(ledger, commit):
    for number in range(1, 4):
        append(ledger, number)
    child = """
import os, runpy, sys
from pathlib import Path
model = runpy.run_path(sys.argv[1])
db = model['connect'](Path(sys.argv[2]))
db.execute('BEGIN IMMEDIATE')
model['compact'](db, 'ag-bob', 1)
if sys.argv[3] == 'True':
    db.commit()
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", child, __file__, str(ledger), str(commit)], timeout=10, check=False)
    assert result.returncode == 73
    assert page(ledger, 0)["status"] == (409 if commit else 200)
    assert cleanup(ledger, 1)["edges_deleted"] == (0 if commit else 2)
    assert page(ledger, 2)["next_cursor"] == 3


def test_read_snapshot_does_not_mix_a_new_floor_with_old_edges(ledger):
    for number in range(1, 4):
        append(ledger, number)
    with closing(connect(ledger)) as reader, reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT discarded_through FROM coord_attention_feeds").fetchone()[0] == 0
        cleanup(ledger, 1)  # Another WAL connection commits while this reader lives.
        assert len(native_page(reader, 0, 200)["edges"]) == 3
        assert reader.execute("SELECT discarded_through FROM coord_attention_feeds").fetchone()[0] == 0
    assert page(ledger, 0)["unavailable_range"] == [1, 2]


def test_concurrent_writers_and_cleaners_keep_a_bounded_suffix(ledger):
    start = Barrier(3)

    def writer(offset):
        start.wait(timeout=5)
        return [append(ledger, number, cap=3) for number in range(offset, offset + 12)]

    def cleaner():
        start.wait(timeout=5)
        return [cleanup(ledger, 3) for _ in range(12)]

    with ThreadPoolExecutor(max_workers=3) as executor:
        left, right, sweeps = [executor.submit(call, *args) for call, args in
                               ((writer, (1,)), (writer, (101,)), (cleaner, ()))]
        allocated = left.result(timeout=10) + right.result(timeout=10)
        assert all(result["edges_deleted"] >= 0 for result in sweeps.result(timeout=10))
    assert sorted(allocated) == list(range(1, 25))
    with closing(connect(ledger)) as db:
        # Independent set oracle: every admitted sequence is either in the
        # disclosed prefix or in the exact retained suffix, never neither.
        retained = {row[0] for row in db.execute("SELECT feed_sequence FROM coord_attention_edges")}
        floor, highwater = db.execute("SELECT discarded_through,last_sequence FROM coord_attention_feeds").fetchone()
        assert retained == set(range(floor + 1, highwater + 1)) == {22, 23, 24}
        assert set(range(1, floor + 1)) | retained == set(allocated)
        assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='attention-nats'").fetchone()[0] == 3


def test_cap_is_per_recipient_across_rooms_and_is_not_a_room_history_cursor(ledger):
    for number in range(1, 5):
        append(ledger, number * 100, room="rm-a" if number % 2 else "rm-b", cap=2)
    append(ledger, 9999, agent="ag-alice", cap=2)
    assert page(ledger, 0)["unavailable_range"] == [1, 2]
    bob = page(ledger, 2)
    assert bob["next_cursor"] == 4
    assert [edge["revision_or_sequence"] for edge in bob["edges"]] == [300, 400]
    assert page(ledger, 0, agent="ag-alice")["next_cursor"] == 1
    # Preserve the current legal future-cursor behavior, without a new limit.
    assert page(ledger, 10000)["next_cursor"] == 10000


@pytest.fixture
def owned_nats(_binary_cache, tmp_path):
    """Run the existing checksum-pinned NATS input with an isolated file store."""
    binary = Path(_binary_cache)
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    assert f'"{digest}"' in (ROOT / "proxy/src/coord_rooms.rs").read_text()
    ports = tmp_path / "ports"
    ports.mkdir()
    with (tmp_path / "nats.log").open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "-js", "-a", "127.0.0.1", "-p", "-1", "-sd", str(tmp_path / "jetstream"),
             "--ports_file_dir", str(ports)], stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = monotonic() + 5
            record = ports / f"nats-server_{process.pid}.ports"
            while True:
                assert process.poll() is None, (tmp_path / "nats.log").read_text()
                assert monotonic() < deadline, "test-owned NATS did not publish its ports"
                if record.exists():
                    try:
                        listeners = json.loads(record.read_text())
                    except json.JSONDecodeError:
                        # NATS can expose the file before finishing its first
                        # write. Retry only that bounded readiness race.
                        sleep(0.01)
                        continue
                    break
                sleep(0.01)
            yield listeners["nats"][0]
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise


@pytest.mark.asyncio
async def test_real_nats_retention_distinguishes_a_missing_message_from_a_missing_stream(ledger, owned_nats):
    """Ground the model's expiry input in the native owner's pinned server."""
    client = await nats.connect(owned_nats, connect_timeout=2, allow_reconnect=False)
    try:
        js = client.jetstream(timeout=2)
        await js.add_stream(name="ROOM_rm-a", subjects=["rooms.rm-a"], max_msgs=1, max_age=0.2)
        first = await js.publish("rooms.rm-a", b'{"msg_id":"msg-rm-a-1"}')
        second = await js.publish("rooms.rm-a", b'{"msg_id":"msg-rm-a-2"}')
        with pytest.raises(NotFoundError) as removed_by_count:
            await js.get_msg("ROOM_rm-a", seq=first.seq)
        assert removed_by_count.value.err_code == 10037
        with pytest.raises(NotFoundError) as missing_stream:
            await js.get_msg("ROOM_missing", seq=second.seq)
        assert missing_stream.value.err_code != 10037
        deadline = monotonic() + 3
        while True:
            try:
                await js.get_msg("ROOM_rm-a", seq=second.seq)
            except NotFoundError as error:
                assert error.err_code == 10037
                break
            assert monotonic() < deadline, "canonical message did not expire"
            await asyncio.sleep(0.01)
        append(ledger, first.seq)
        assert resolve(ledger, proof(ledger, first.seq)[0], "missing_message")["status"] == 410
        assert cleanup(ledger, 3, expired=frozenset([proof(ledger, first.seq)]))["discarded_through"] == 1
        assert page(ledger, 0)["unavailable_range"] == [1, 1]
    finally:
        await client.close()
