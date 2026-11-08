-- References and delivery state only. Evidence stays with its source owner.
CREATE TABLE IF NOT EXISTS coord_operational_references (
    event_id TEXT PRIMARY KEY,
    reference_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coord_observation_health (
    agent_id TEXT NOT NULL,
    source TEXT NOT NULL,
    last_success_at INTEGER,
    unavailable_reason TEXT,
    changed_at INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    last_observed_at INTEGER NOT NULL,
    reference_json TEXT,
    PRIMARY KEY (agent_id, source)
);
