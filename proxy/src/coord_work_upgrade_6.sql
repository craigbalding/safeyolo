-- Upgrade the current native work projection. Immutable revisions, operation
-- receipts, claims, attention and outbox rows keep their identities and bytes.
CREATE TABLE coord_work_upgrade (
    work_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    version INTEGER NOT NULL CHECK(version > 0),
    state TEXT NOT NULL CHECK(state IN ('open','claimed','done','cancelled')),
    document_json TEXT NOT NULL,
    FOREIGN KEY(work_id, version) REFERENCES coord_work_revisions(work_id, version)
        DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO coord_work_upgrade SELECT * FROM coord_work;
DROP TABLE coord_work;
ALTER TABLE coord_work_upgrade RENAME TO coord_work;
CREATE INDEX coord_work_room ON coord_work(room_id, work_id);
PRAGMA user_version=6;
