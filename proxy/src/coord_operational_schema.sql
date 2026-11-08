-- References and delivery state only. Evidence stays with its source owner.
CREATE TABLE IF NOT EXISTS coord_operational_references (
    event_id TEXT PRIMARY KEY,
    reference_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
