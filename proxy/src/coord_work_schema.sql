-- Current native work projections and immutable versions. No lease worker.
CREATE TABLE IF NOT EXISTS coord_work_revisions (
    work_id TEXT NOT NULL,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    version INTEGER NOT NULL CHECK(version > 0),
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(work_id, version)
);
CREATE TABLE IF NOT EXISTS coord_work (
    work_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    version INTEGER NOT NULL CHECK(version > 0),
    state TEXT NOT NULL CHECK(state IN ('open','claimed','done')),
    document_json TEXT NOT NULL,
    FOREIGN KEY(work_id, version) REFERENCES coord_work_revisions(work_id, version)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS coord_work_room ON coord_work(room_id, work_id);
CREATE TRIGGER IF NOT EXISTS coord_work_revisions_immutable_update
BEFORE UPDATE ON coord_work_revisions
BEGIN SELECT RAISE(ABORT, 'coord work revisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS coord_work_revisions_immutable_delete
BEFORE DELETE ON coord_work_revisions
BEGIN SELECT RAISE(ABORT, 'coord work revisions are immutable'); END;
