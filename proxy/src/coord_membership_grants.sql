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
