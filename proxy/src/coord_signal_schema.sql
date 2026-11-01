-- Material claims retain their original author and every canonical revision.
CREATE TABLE IF NOT EXISTS coord_signal_revisions (
    signal_id TEXT NOT NULL,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    revision INTEGER NOT NULL CHECK(revision > 0),
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(signal_id, revision)
);
CREATE TABLE IF NOT EXISTS coord_signals (
    signal_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL CHECK(state IN ('current','resolved','superseded')),
    needs_operator INTEGER NOT NULL CHECK(needs_operator IN (0,1)),
    author_kind TEXT NOT NULL,
    author_id TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    document_json TEXT NOT NULL,
    FOREIGN KEY(signal_id, revision) REFERENCES coord_signal_revisions(signal_id, revision)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS coord_signals_room ON coord_signals(room_id, signal_id);
CREATE INDEX IF NOT EXISTS coord_signals_pages ON coord_signals(needs_operator, signal_id);
CREATE INDEX IF NOT EXISTS coord_signals_author ON coord_signals(room_id, author_kind, author_id, created_at);
CREATE INDEX IF NOT EXISTS coord_signal_page_window ON coord_signal_revisions(room_id, created_at);
CREATE TRIGGER IF NOT EXISTS coord_signal_revisions_immutable_update
BEFORE UPDATE ON coord_signal_revisions
BEGIN SELECT RAISE(ABORT, 'coord signal revisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS coord_signal_revisions_immutable_delete
BEFORE DELETE ON coord_signal_revisions
BEGIN SELECT RAISE(ABORT, 'coord signal revisions are immutable'); END;
