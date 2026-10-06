-- Fresh native Coord store: the existing operational version-5 schema.
-- Adapted from cli/src/safeyolo/coord/store.py. No historical-state conversion.
CREATE TABLE instance (
           id TEXT PRIMARY KEY
       );
CREATE TABLE rooms (
           room_id TEXT PRIMARY KEY,
           name TEXT NOT NULL UNIQUE,
           created_at INTEGER NOT NULL
       );
CREATE TABLE memberships (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           principal_kind TEXT NOT NULL,
           principal_id TEXT NOT NULL,
           permissions TEXT NOT NULL,
           history_visibility TEXT NOT NULL DEFAULT 'retained',
           granted_at INTEGER NOT NULL,
           revoked_at INTEGER,
           PRIMARY KEY (room_id, principal_kind, principal_id, granted_at)
       );
CREATE TABLE coord_outbox (
           event_id TEXT PRIMARY KEY,
           destination TEXT NOT NULL,
           event_type TEXT NOT NULL,
           payload_json TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           delivered_at INTEGER,
           attempt_count INTEGER NOT NULL DEFAULT 0,
           last_error_class TEXT
       );
CREATE INDEX coord_outbox_pending
       ON coord_outbox(destination, delivered_at, created_at, event_id);
CREATE TABLE coord_operations (
           principal_kind TEXT NOT NULL,
           principal_id TEXT NOT NULL,
           operation_type TEXT NOT NULL,
           operation_id TEXT NOT NULL,
           request_hash TEXT NOT NULL,
           outcome_kind TEXT NOT NULL,
           outcome_json TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (
               principal_kind, principal_id, operation_type, operation_id
           )
       );
CREATE INDEX coord_operations_created
       ON coord_operations(created_at);
CREATE TABLE coord_attention_feeds (
           recipient_agent_id TEXT PRIMARY KEY,
           last_sequence INTEGER NOT NULL DEFAULT 0
               CHECK(last_sequence >= 0)
       );
CREATE TABLE coord_attention_edges (
           recipient_agent_id TEXT NOT NULL,
           feed_sequence INTEGER NOT NULL CHECK(feed_sequence > 0),
           attention_id TEXT NOT NULL UNIQUE,
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           kind TEXT NOT NULL,
           object_id TEXT NOT NULL,
           revision_or_sequence INTEGER NOT NULL
               CHECK(revision_or_sequence >= 0),
           membership_granted_at INTEGER NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (recipient_agent_id, feed_sequence),
           UNIQUE (
               recipient_agent_id, kind, object_id, revision_or_sequence,
               membership_granted_at
           )
       );
CREATE INDEX coord_attention_edges_room_object
       ON coord_attention_edges(room_id, kind, object_id);
CREATE UNIQUE INDEX coord_attention_edges_message_logical
       ON coord_attention_edges(
           recipient_agent_id, object_id, membership_granted_at
       ) WHERE kind = 'message';
CREATE TABLE coord_message_attention_projection (
           room_id TEXT PRIMARY KEY REFERENCES rooms(room_id),
           last_sequence INTEGER NOT NULL DEFAULT 0
               CHECK(last_sequence >= 0),
           updated_at INTEGER NOT NULL
       );
CREATE TABLE coord_brief_revisions (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           revision INTEGER NOT NULL CHECK(revision > 0),
           markdown TEXT NOT NULL,
           content_hash TEXT NOT NULL CHECK(length(content_hash) = 64),
           actor_kind TEXT NOT NULL CHECK(actor_kind = 'operator'),
           actor_id TEXT NOT NULL,
           operation_id TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (room_id, revision)
       );
CREATE TABLE coord_briefs (
           room_id TEXT PRIMARY KEY REFERENCES rooms(room_id),
           revision INTEGER NOT NULL CHECK(revision > 0),
           markdown TEXT NOT NULL,
           content_hash TEXT NOT NULL CHECK(length(content_hash) = 64),
           actor_kind TEXT NOT NULL CHECK(actor_kind = 'operator'),
           actor_id TEXT NOT NULL,
           operation_id TEXT NOT NULL,
           updated_at INTEGER NOT NULL,
           FOREIGN KEY (room_id, revision)
               REFERENCES coord_brief_revisions(room_id, revision)
               DEFERRABLE INITIALLY DEFERRED
       );
CREATE TRIGGER coord_brief_revisions_immutable_update
       BEFORE UPDATE ON coord_brief_revisions
       BEGIN
           SELECT RAISE(ABORT, 'coord brief revisions are immutable');
       END;
CREATE TRIGGER coord_brief_revisions_immutable_delete
       BEFORE DELETE ON coord_brief_revisions
       BEGIN
           SELECT RAISE(ABORT, 'coord brief revisions are immutable');
       END;
CREATE TABLE coord_capability_advertisements (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           agent_id TEXT NOT NULL,
           capability TEXT NOT NULL CHECK(length(capability) BETWEEN 3 AND 129),
           operation_id TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (room_id, agent_id, capability)
       );
CREATE TABLE coord_resource_advertisements (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 64),
           resource TEXT NOT NULL CHECK(length(resource) BETWEEN 1 AND 64),
           operation_id TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (room_id, provider, resource)
       );
CREATE TABLE coord_capability_declarations (
           room_id TEXT NOT NULL REFERENCES rooms(room_id),
           agent_id TEXT NOT NULL,
           capability TEXT NOT NULL CHECK(length(capability) BETWEEN 3 AND 129),
           asserted_at INTEGER NOT NULL,
           valid_until INTEGER NOT NULL CHECK(valid_until > asserted_at),
           PRIMARY KEY (room_id, agent_id, capability)
       );
CREATE INDEX coord_capability_declarations_expiry
       ON coord_capability_declarations(valid_until);
PRAGMA user_version=5;
