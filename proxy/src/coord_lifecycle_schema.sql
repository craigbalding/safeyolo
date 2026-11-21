-- Host lifecycle receipts only. Work and its acceptance remain in Coord Work.
CREATE TABLE IF NOT EXISTS coord_lifecycle (
    agent_id TEXT PRIMARY KEY,
    document_json TEXT NOT NULL
);
