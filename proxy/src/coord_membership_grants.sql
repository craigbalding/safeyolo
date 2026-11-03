-- Separately sourced room access. The policy's issued-access receipt activates
-- a prepared row; membership preparation alone grants no usable authority.
CREATE TABLE IF NOT EXISTS coord_membership_grants (
    approval_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    agent_id TEXT NOT NULL,
    permissions TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    issued_json TEXT NOT NULL,
    authority_digest TEXT NOT NULL,
    policy_file TEXT NOT NULL,
    identity_root TEXT NOT NULL,
    revoked_at INTEGER
);
-- A new collaboration is one operator-approved effect. These rows prepare
-- its named participants; the matching native approval receipt activates them.
CREATE TABLE IF NOT EXISTS coord_collaboration_grants (
    approval_id TEXT NOT NULL,
    room_id TEXT NOT NULL REFERENCES rooms(room_id),
    agent_id TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    authority_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    policy_file TEXT NOT NULL,
    identity_root TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY(approval_id, agent_id)
);
