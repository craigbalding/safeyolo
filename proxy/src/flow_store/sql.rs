// SQL retained from cli/src/safeyolo/storage/flow_store.py at 99bb0df9 (MIT).
pub(super) const FLOWS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,

    ts_start INTEGER NOT NULL,
    ts_end INTEGER,
    duration_ms INTEGER,

    engagement_id TEXT NOT NULL,
    agent_id TEXT,
    evidence_owner TEXT,
    trusted_transport_identity TEXT,
    initiator TEXT,
    attribution_status TEXT,
    attribution_provenance_json TEXT,
    source_id TEXT,

    run TEXT,
    test TEXT,
    role TEXT,
    test_agent TEXT,
    suite TEXT,
    subject TEXT,
    step TEXT,
    intent TEXT,
    expect TEXT,
    context_json TEXT,

    source_type TEXT,
    flow_state TEXT NOT NULL,

    scheme TEXT,
    host TEXT NOT NULL,
    port INTEGER,
    method TEXT,
    path TEXT,
    query_string TEXT,
    full_url TEXT,

    status_code INTEGER,
    reason TEXT,

    request_content_type TEXT,
    response_content_type TEXT,
    is_websocket INTEGER NOT NULL DEFAULT 0,

    request_headers_json TEXT,
    response_headers_json TEXT,

    request_body_encoding TEXT,
    response_body_encoding TEXT,

    request_body_blob BLOB,
    response_body_blob BLOB,

    request_body_text_preview TEXT,
    response_body_text_preview TEXT,
    response_body_text_index TEXT,
    request_body_text_index TEXT,

    request_body_size INTEGER NOT NULL DEFAULT 0,
    response_body_size INTEGER NOT NULL DEFAULT 0,

    request_body_stored INTEGER NOT NULL DEFAULT 0,
    response_body_stored INTEGER NOT NULL DEFAULT 0,

    request_body_truncated INTEGER NOT NULL DEFAULT 0,
    response_body_truncated INTEGER NOT NULL DEFAULT 0
);
"#;

pub(super) const FTS_TABLE: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS flow_fts USING fts5(
    flow_id UNINDEXED,
    engagement_id UNINDEXED,
    agent_id UNINDEXED,
    host UNINDEXED,
    path UNINDEXED,
    run UNINDEXED,
    test UNINDEXED,
    response_body_text,
    tokenize = 'unicode61'
);
"#;

pub(super) const REQUEST_FTS_TABLE: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS flow_request_fts USING fts5(
    flow_id UNINDEXED,
    engagement_id UNINDEXED,
    agent_id UNINDEXED,
    host UNINDEXED,
    path UNINDEXED,
    run UNINDEXED,
    test UNINDEXED,
    request_body_text,
    tokenize = 'unicode61'
);
"#;

pub(super) const FLOW_TAGS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS flow_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(id),
    UNIQUE(flow_id, tag)
);
"#;

pub(super) const INDEXES: &str = r#"CREATE INDEX IF NOT EXISTS idx_flows_engagement_ts ON flows (engagement_id, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_engagement_agent_ts ON flows (engagement_id, agent_id, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_evidence_owner_ts ON flows (evidence_owner, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_attribution_status_ts ON flows (attribution_status, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_engagement_test_ts ON flows (engagement_id, test, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_agent_test_intent_ts ON flows (agent_id, test, intent, ts_start DESC);
CREATE INDEX IF NOT EXISTS idx_flows_engagement_host_path ON flows (engagement_id, host, path);
CREATE INDEX IF NOT EXISTS idx_flows_engagement_status_ts ON flows (engagement_id, status_code, ts_start DESC);"#;

pub(super) const INSERT: &str = r#"
        INSERT INTO flows (
            request_id, ts_start, ts_end, duration_ms,
            engagement_id, agent_id, evidence_owner,
            trusted_transport_identity, initiator, attribution_status,
            attribution_provenance_json, source_id,
            run, test, role, test_agent, suite, subject, step, intent, expect, context_json,
            source_type, flow_state,
            scheme, host, port, method, path, query_string, full_url,
            status_code, reason,
            request_content_type, response_content_type, is_websocket,
            request_headers_json, response_headers_json,
            request_body_encoding, response_body_encoding,
            request_body_blob, response_body_blob,
            request_body_text_preview, response_body_text_preview,
            response_body_text_index, request_body_text_index,
            request_body_size, response_body_size,
            request_body_stored, response_body_stored,
            request_body_truncated, response_body_truncated
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?
        )
        "#;

pub(super) const DETAIL: &str = r#"
        SELECT id, request_id, ts_start, ts_end, duration_ms,
               engagement_id, agent_id, evidence_owner,
               trusted_transport_identity, initiator, attribution_status,
               attribution_provenance_json, source_id,
               run, test, role, test_agent, suite, subject, step, intent, expect,
               context_json,
               source_type, flow_state,
               scheme, host, port, method, path, query_string, full_url,
               status_code, reason,
               request_content_type, response_content_type, is_websocket,
               request_headers_json, response_headers_json,
               request_body_text_preview, response_body_text_preview,
               request_body_size, response_body_size,
               request_body_stored, response_body_stored,
               request_body_truncated, response_body_truncated
        FROM flows WHERE id = ?
        "#;

pub(super) const REQUEST_BODY: &str = r#"
        SELECT request_body_blob, request_body_encoding,
               request_content_type, request_body_size,
               request_body_stored, request_body_truncated
        FROM flows WHERE id = ?
        "#;

pub(super) const RESPONSE_BODY: &str = r#"
        SELECT response_body_blob, response_body_encoding,
               response_content_type, response_body_size,
               response_body_stored, response_body_truncated
        FROM flows WHERE id = ?
        "#;
