-- Explicit SafeYolo peers and home routes. No NATS account is exported.
CREATE TABLE IF NOT EXISTS coord_federation_peers (
    instance_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK(epoch > 0),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1))
);
CREATE TABLE IF NOT EXISTS coord_federation_agents (
    principal_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES coord_federation_peers(instance_id),
    agent_id TEXT NOT NULL,
    display_name TEXT NOT NULL UNIQUE,
    UNIQUE(instance_id, agent_id)
);
CREATE TABLE IF NOT EXISTS coord_federation_homes (
    name TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    url TEXT NOT NULL,
    ca_file TEXT NOT NULL,
    token_file TEXT NOT NULL,
    revision TEXT NOT NULL
);
