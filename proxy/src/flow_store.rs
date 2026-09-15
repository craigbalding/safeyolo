//! Retained SQLite flow schema and synchronous record storage.
//!
//! Matches the shipped Python FlowStore's schema, lazy body settings and
//! separate best-effort FTS updates. Failed row/tag writes roll back together:
//! a subsequent successful record cannot publish a previously failed record.
//! Callers must run filesystem/database operations off asynchronous workers.

mod details;
mod query;
pub use query::QueryError;
pub(crate) use query::integer;
mod gzip;
mod sql;

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use flate2::{Compression, GzBuilder};
use num_bigint::BigInt;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, params_from_iter};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::circuits::CircuitValue;

/// Categorical failures never include SQLite text, paths or recorded content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Database,
    Integrity,
    Operational,
    Programming,
    SchemaVersion,
    Poisoned,
    Type,
    Value,
    Attribute,
    Overflow,
    Compression,
    BadGzip,
    UnexpectedEof,
    Deflate,
    Compatibility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(ErrorKind);
impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ErrorKind::Database => "flow database operation failed",
            ErrorKind::Integrity => "flow database constraint failed",
            ErrorKind::Operational => "flow database operation unavailable",
            ErrorKind::Programming => "unsupported flow database parameter",
            ErrorKind::SchemaVersion => "unsupported flow database schema version",
            ErrorKind::Poisoned => "flow database lock poisoned",
            ErrorKind::Type => "invalid consumed flow value type",
            ErrorKind::Value => "invalid consumed flow value",
            ErrorKind::Attribute => "flow operation unavailable for consumed value",
            ErrorKind::Overflow => "flow integer exceeds SQLite range",
            ErrorKind::Compression => "flow body compression operation failed",
            ErrorKind::BadGzip => "invalid stored gzip member",
            ErrorKind::UnexpectedEof => "incomplete stored gzip member",
            ErrorKind::Deflate => "invalid stored deflate data",
            ErrorKind::Compatibility => "flow value cannot be represented",
        })
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self(match error {
            rusqlite::Error::SqliteFailure(error, _) => match error.code {
                rusqlite::ErrorCode::ConstraintViolation | rusqlite::ErrorCode::TypeMismatch => {
                    ErrorKind::Integrity
                }
                rusqlite::ErrorCode::DatabaseBusy
                | rusqlite::ErrorCode::DatabaseLocked
                | rusqlite::ErrorCode::CannotOpen
                | rusqlite::ErrorCode::ReadOnly
                | rusqlite::ErrorCode::SystemIoFailure
                | rusqlite::ErrorCode::DiskFull
                | rusqlite::ErrorCode::Unknown => ErrorKind::Operational,
                _ => ErrorKind::Database,
            },
            _ => ErrorKind::Database,
        })
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Keep source values unchanged; comparison/slicing occurs only when reached.
/// No Debug/Serialize because caller-supplied values may contain private data.
pub struct Settings {
    pub max_request_body_bytes: CircuitValue,
    pub max_response_body_bytes: CircuitValue,
    pub preview_text_chars: CircuitValue,
    pub compress_bodies: CircuitValue,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 1_048_576.into(),
            max_response_body_bytes: 4_194_304.into(),
            preview_text_chars: 8192.into(),
            compress_bodies: CircuitValue::Bool(true),
        }
    }
}

/// Metadata uses the source column names; unconsumed fields are ignored.
/// Header/context JSON is already serialized by the capture owner.
pub struct FlowRecord<'a> {
    pub metadata: &'a Map<String, Value>,
    pub request_body: Option<BodyInput<'a>>,
    pub response_body: Option<BodyInput<'a>>,
}

/// Bytes retained only after the complete source body decoder succeeded.
/// `original_size` counts decoded bytes before the configured storage slice.
/// The store checks that the prefix covers every byte that slice requires.
pub struct BodyInput<'a> {
    bytes: &'a [u8],
    original_size: usize,
}
impl<'a> BodyInput<'a> {
    pub fn complete(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            original_size: bytes.len(),
        }
    }
    pub fn decoded_prefix(bytes: &'a [u8], original_size: usize) -> Self {
        Self {
            bytes,
            original_size,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recorded {
    pub id: i64,
    pub response_fts_failed: bool,
    pub request_fts_failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Request,
    Response,
}

/// Returned encoding describes storage, even when `body` was decompressed.
pub struct StoredBody {
    pub metadata: Map<String, Value>,
    pub body: Zeroizing<Vec<u8>>,
}
impl Drop for StoredBody {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut Value::Object(std::mem::take(&mut self.metadata)));
    }
}

pub struct FlowStore {
    pub(super) connection: Mutex<Option<Connection>>,
    settings: Settings,
}

struct ConnectionGuard<'a>(MutexGuard<'a, Option<Connection>>);
impl Deref for ConnectionGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("checked flow connection")
    }
}
impl DerefMut for ConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("checked flow connection")
    }
}

impl FlowStore {
    /// Recorder startup retains the assigned store even if initialization fails.
    /// A typed path error leaves no connection; reached query operations then
    /// fail with Attribute, as the source's assigned-but-unopened store does.
    /// Install a writer only when the returned initialization error is absent.
    pub fn start(
        path: std::result::Result<&Path, ErrorKind>,
        settings: Settings,
    ) -> (Self, Option<Error>) {
        let connection = path.map_err(Error).and_then(|path| {
            // Python sqlite3.connect defaults to uri=False. URI-looking input
            // is a literal filename, while SQLite still handles :memory:/empty.
            // Bundled SQLite also enables URI recognition at compile time.
            // Prefixing ./ prevents its file: recognizer while keeping the
            // same literal pathname addressed by Python uri=False.
            let literal = if path.as_os_str().as_encoded_bytes().starts_with(b"file:") {
                Cow::Owned(Path::new(".").join(path))
            } else {
                Cow::Borrowed(path)
            };
            Connection::open_with_flags(
                literal.as_ref(),
                OpenFlags::default() - OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(Error::from)
        });
        let (connection, error) = match connection {
            Ok(mut connection) => {
                let error = Self::initialize(&mut connection).err();
                (Some(connection), error)
            }
            Err(error) => (None, Some(error)),
        };
        (
            Self {
                connection: Mutex::new(connection),
                settings,
            },
            error,
        )
    }

    pub fn open(path: &Path, settings: Settings) -> Result<Self> {
        let (store, error) = Self::start(Ok(path), settings);
        match error {
            Some(error) => Err(error),
            None => Ok(store),
        }
    }

    fn initialize(connection: &mut Connection) -> Result<()> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;")?;
        connection.execute_batch(sql::FLOWS_TABLE)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 2 {
            return Err(Error(ErrorKind::SchemaVersion));
        }
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(flows)")?
            .query_map([], |row| row.get(1))?
            .collect::<rusqlite::Result<_>>()?;
        for column in [
            "test_agent",
            "suite",
            "subject",
            "step",
            "intent",
            "expect",
            "evidence_owner",
            "trusted_transport_identity",
            "initiator",
            "attribution_status",
            "attribution_provenance_json",
        ] {
            if !columns.iter().any(|value| value == column) {
                connection.execute(&format!("ALTER TABLE flows ADD COLUMN {column} TEXT"), [])?;
            }
        }
        if version < 2 {
            connection.execute_batch("BEGIN DEFERRED")?;
            connection.execute("UPDATE flows SET evidence_owner=agent_id, attribution_status=CASE WHEN agent_id IS NOT NULL THEN 'resolved' ELSE 'unavailable' END, initiator='unknown', attribution_provenance_json='{\"migration\":\"flow_store_v1\",\"transport_identity\":\"unknown\"}' WHERE evidence_owner IS NULL", [])?;
        }
        connection.execute_batch("PRAGMA user_version=2;")?;
        for statement in [
            sql::FTS_TABLE,
            sql::REQUEST_FTS_TABLE,
            sql::FLOW_TAGS_TABLE,
            sql::INDEXES,
            "CREATE INDEX IF NOT EXISTS idx_flow_tags_flow_id ON flow_tags (flow_id); CREATE INDEX IF NOT EXISTS idx_flow_tags_tag ON flow_tags (tag, value);",
        ] {
            connection.execute_batch(statement)?;
        }
        if !connection.is_autocommit() {
            connection.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    fn lock(&self) -> Result<ConnectionGuard<'_>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?;
        if connection.is_none() {
            return Err(Error(ErrorKind::Attribute));
        }
        Ok(ConnectionGuard(connection))
    }

    /// An allocation optimization only. Other source values require full decode
    /// so their comparison/slice behavior remains deferred until recording.
    pub fn capture_limit(&self, side: Side) -> Option<usize> {
        let value = match side {
            Side::Request => &self.settings.max_request_body_bytes,
            Side::Response => &self.settings.max_response_body_bytes,
        };
        usize::try_from(value.integer()?).ok()
    }

    pub fn record(&self, record: FlowRecord<'_>, now_ms: i64) -> Result<Recorded> {
        let metadata = record.metadata;
        let missing_ct = Value::String(String::new());
        let request_ct = metadata.get("request_content_type").unwrap_or(&missing_ct);
        let response_ct = metadata.get("response_content_type").unwrap_or(&missing_ct);
        let request = PreparedBody::new(
            record
                .request_body
                .unwrap_or_else(|| BodyInput::complete(&[])),
            request_ct,
            &self.settings.max_request_body_bytes,
            &self.settings,
            now_ms,
        )?;
        let response = PreparedBody::new(
            record
                .response_body
                .unwrap_or_else(|| BodyInput::complete(&[])),
            response_ct,
            &self.settings.max_response_body_bytes,
            &self.settings,
            now_ms,
        )?;
        let owner = present(metadata.get("evidence_owner"))
            .or_else(|| metadata.get("agent_id"))
            .unwrap_or(&Value::Null);
        let agent = present(metadata.get("agent_id")).unwrap_or(owner);
        let status = Value::String(
            if truthy(owner) {
                "resolved"
            } else {
                "unavailable"
            }
            .into(),
        );
        let unknown = Value::String("unknown".into());
        let provenance = metadata
            .get("attribution_provenance_json")
            .unwrap_or(&Value::Null);
        let rendered_provenance = match provenance {
            Value::Object(_) => Some(Zeroizing::new(crate::python_json::encode(provenance))),
            Value::Null => Some(Zeroizing::new(
                "{\"compatibility\": \"implicit_agent_id\"}".to_owned(),
            )),
            _ => None,
        };
        let mut values = SqlParams(Vec::with_capacity(52));
        for field in METADATA_COLUMNS {
            let value = match *field {
                "evidence_owner" => owner,
                "agent_id" => agent,
                "attribution_status" => present(metadata.get(*field)).unwrap_or(&status),
                "initiator" => present(metadata.get(*field)).unwrap_or(&unknown),
                _ => metadata.get(*field).unwrap_or(&Value::Null),
            };
            values.0.push(if *field == "attribution_provenance_json" {
                if let Some(text) = &rendered_provenance {
                    SqlValue::Text(text.to_string())
                } else {
                    sql_value(value)?
                }
            } else {
                sql_value(value)?
            });
        }
        values.0.extend([
            sql_value(request_ct)?,
            sql_value(response_ct)?,
            SqlValue::Integer(i64::from(metadata.get("is_websocket").is_some_and(truthy))),
            sql_value(metadata.get("request_headers_json").unwrap_or(&Value::Null))?,
            sql_value(
                metadata
                    .get("response_headers_json")
                    .unwrap_or(&Value::Null),
            )?,
            request.encoding(),
            response.encoding(),
            request.blob(),
            response.blob(),
            SqlValue::Text(request.preview.to_string()),
            SqlValue::Text(response.preview.to_string()),
            SqlValue::Text(response.index.to_string()),
            SqlValue::Text(request.index.to_string()),
            SqlValue::Integer(request.size),
            SqlValue::Integer(response.size),
            SqlValue::Integer(i64::from(!request.data.is_empty())),
            SqlValue::Integer(i64::from(!response.data.is_empty())),
            SqlValue::Integer(i64::from(request.truncated)),
            SqlValue::Integer(i64::from(response.truncated)),
        ]);
        let id = {
            let mut connection = self.lock()?;
            let transaction = connection.transaction()?;
            transaction.execute(sql::INSERT, params_from_iter(&values.0))?;
            let id = transaction.last_insert_rowid();
            if let Some(tags) = metadata
                .get("provenance_tags")
                .filter(|value| truthy(value))
            {
                let tags = tags.as_object().ok_or(Error(ErrorKind::Attribute))?;
                for (tag, value) in tags {
                    let value = SqlParams(vec![sql_value(value)?]);
                    transaction.execute("INSERT OR REPLACE INTO flow_tags (flow_id,tag,value,created_at) VALUES (?,?,?,?)", params![id, tag, &value.0[0], now_ms])?;
                }
            }
            transaction.commit()?;
            id
        };
        let mut fts = SqlParams(vec![SqlValue::Integer(id)]);
        for value in [
            metadata.get("engagement_id").unwrap_or(&Value::Null),
            agent,
            metadata.get("host").unwrap_or(&Value::Null),
            metadata.get("path").unwrap_or(&Value::Null),
            metadata.get("run").unwrap_or(&Value::Null),
            metadata.get("test").unwrap_or(&Value::Null),
        ] {
            fts.0.push(sql_value(value)?);
        }
        Ok(Recorded {
            id,
            response_fts_failed: !response.index.is_empty()
                && self
                    .insert_fts(Side::Response, &fts, &response.index)
                    .is_err(),
            request_fts_failed: !request.index.is_empty()
                && self
                    .insert_fts(Side::Request, &fts, &request.index)
                    .is_err(),
        })
    }

    fn insert_fts(&self, side: Side, values: &SqlParams, text: &str) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let sql = match side {
            Side::Request => "INSERT INTO flow_request_fts VALUES (?,?,?,?,?,?,?,?)",
            Side::Response => "INSERT INTO flow_fts VALUES (?,?,?,?,?,?,?,?)",
        };
        let mut statement = transaction.prepare(sql)?;
        for (index, value) in values.0.iter().enumerate() {
            statement.raw_bind_parameter(index + 1, value)?;
        }
        statement.raw_bind_parameter(8, text)?;
        statement.raw_execute()?;
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    pub fn get_flow(&self, id: i64) -> Result<Option<Map<String, Value>>> {
        let row = {
            let connection = self.lock()?;
            connection
                .query_row(sql::DETAIL, [id], |row| Ok(row_map(row)))
                .optional()?
        };
        let Some(mut row) = row.transpose()? else {
            return Ok(None);
        };
        // Python attaches tags in a separate lock acquisition.
        row.insert("tags".into(), self.get_flow_tags(id)?);
        Ok(Some(row))
    }

    pub fn body(&self, id: i64, side: Side) -> Result<Option<StoredBody>> {
        let connection = self.lock()?;
        let (sql, prefix) = match side {
            Side::Request => (sql::REQUEST_BODY, "request"),
            Side::Response => (sql::RESPONSE_BODY, "response"),
        };
        let value = connection
            .query_row(sql, [id], |row| {
                let body = row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default();
                let mut fields = Map::new();
                for index in 1..row.as_ref().column_count() {
                    let key = row.as_ref().column_name(index)?;
                    let value = row.get_ref(index)?;
                    match json_value(value) {
                        Ok(value) => {
                            fields.insert(key.into(), value);
                        }
                        Err(error) => return Ok(Err(error)),
                    }
                }
                Ok(Ok(StoredBody {
                    metadata: fields,
                    body: Zeroizing::new(body),
                }))
            })
            .optional()?;
        drop(connection);
        let Some(mut value) = value.transpose()? else {
            return Ok(None);
        };
        if !value.body.is_empty()
            && value
                .metadata
                .get(&format!("{prefix}_body_encoding"))
                .and_then(Value::as_str)
                == Some("gzip")
        {
            value.body = gzip::decode(&value.body)?;
        }
        Ok(Some(value))
    }
}

const METADATA_COLUMNS: &[&str] = &[
    "request_id",
    "ts_start",
    "ts_end",
    "duration_ms",
    "engagement_id",
    "agent_id",
    "evidence_owner",
    "trusted_transport_identity",
    "initiator",
    "attribution_status",
    "attribution_provenance_json",
    "source_id",
    "run",
    "test",
    "role",
    "test_agent",
    "suite",
    "subject",
    "step",
    "intent",
    "expect",
    "context_json",
    "source_type",
    "flow_state",
    "scheme",
    "host",
    "port",
    "method",
    "path",
    "query_string",
    "full_url",
    "status_code",
    "reason",
];

fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(_) => CircuitValue::from(value.clone()).truthy(),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn sql_value(value: &Value) -> Result<SqlValue> {
    Ok(match value {
        Value::Null => SqlValue::Null,
        Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
        Value::String(value) => SqlValue::Text(value.clone()),
        Value::Number(number) => {
            let spelling = number.as_str();
            if spelling.contains(['.', 'e', 'E']) {
                SqlValue::Real(number.as_f64().ok_or(Error(ErrorKind::Overflow))?)
            } else {
                SqlValue::Integer(number.as_i64().ok_or(Error(ErrorKind::Overflow))?)
            }
        }
        _ => return Err(Error(ErrorKind::Programming)),
    })
}
fn json_value(value: ValueRef<'_>) -> Result<Value> {
    Ok(match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::from(value),
        ValueRef::Real(value) => Value::Number(
            serde_json::Number::from_f64(value).ok_or(Error(ErrorKind::Compatibility))?,
        ),
        ValueRef::Text(value) => Value::String(
            std::str::from_utf8(value)
                .map_err(|_| Error(ErrorKind::Compatibility))?
                .into(),
        ),
        ValueRef::Blob(_) => return Err(Error(ErrorKind::Compatibility)),
    })
}
fn row_map(row: &Row<'_>) -> Result<Map<String, Value>> {
    let mut result = Map::new();
    for index in 0..row.as_ref().column_count() {
        result.insert(
            row.as_ref().column_name(index)?.into(),
            json_value(row.get_ref(index)?)?,
        );
    }
    Ok(result)
}
struct SqlParams(Vec<SqlValue>);
impl Drop for SqlParams {
    fn drop(&mut self) {
        for value in &mut self.0 {
            match value {
                SqlValue::Text(value) => value.zeroize(),
                SqlValue::Blob(value) => value.zeroize(),
                _ => {}
            }
        }
    }
}

struct PreparedBody {
    data: Zeroizing<Vec<u8>>,
    preview: Zeroizing<String>,
    index: Zeroizing<String>,
    compressed: bool,
    size: i64,
    truncated: bool,
}
impl PreparedBody {
    fn new(
        body: BodyInput<'_>,
        content_type: &Value,
        limit: &CircuitValue,
        settings: &Settings,
        now_ms: i64,
    ) -> Result<Self> {
        let size = i64::try_from(body.original_size).map_err(|_| Error(ErrorKind::Overflow))?;
        let (length, truncated) = slice_length(body.original_size, limit)?;
        if body.bytes.len() > body.original_size || body.bytes.len() < length {
            return Err(Error(ErrorKind::Value));
        }
        let body = &body.bytes[..length];
        let text_like = is_text_like_content_type(content_type)?;
        let index = Zeroizing::new(if text_like {
            String::from_utf8_lossy(body).into_owned()
        } else {
            String::new()
        });
        let preview = if !index.is_empty() {
            let (length, _) = slice_length(index.chars().count(), &settings.preview_text_chars)?;
            Zeroizing::new(index.chars().take(length).collect::<String>())
        } else {
            Zeroizing::new(String::new())
        };
        let compressed = settings.compress_bodies.truthy();
        let data = if compressed && !body.is_empty() {
            // Gzip bytes are interoperable; the clock is explicit for reproducible records.
            let seconds = u32::try_from(now_ms / 1000).map_err(|_| Error(ErrorKind::Overflow))?;
            let mut encoder = GzBuilder::new()
                .mtime(seconds)
                .write(Vec::new(), Compression::best());
            encoder
                .write_all(body)
                .map_err(|_| Error(ErrorKind::Compression))?;
            Zeroizing::new(
                encoder
                    .finish()
                    .map_err(|_| Error(ErrorKind::Compression))?,
            )
        } else {
            Zeroizing::new(body.to_vec())
        };
        Ok(Self {
            data,
            preview,
            index,
            compressed,
            size,
            truncated,
        })
    }
    fn encoding(&self) -> SqlValue {
        if self.data.is_empty() {
            SqlValue::Null
        } else {
            SqlValue::Text(if self.compressed { "gzip" } else { "identity" }.into())
        }
    }
    fn blob(&self) -> SqlValue {
        if self.data.is_empty() {
            SqlValue::Null
        } else {
            SqlValue::Blob(self.data.to_vec())
        }
    }
}

fn slice_length(length: usize, limit: &CircuitValue) -> Result<(usize, bool)> {
    let length_value = CircuitValue::from(BigInt::from(length));
    if length_value
        .compare(limit)
        .map_err(|_| Error(ErrorKind::Type))?
        != Some(Ordering::Greater)
    {
        return Ok((length, false));
    }
    let end = limit.integer().ok_or(Error(ErrorKind::Type))?;
    let size = BigInt::from(length);
    let end = if end < BigInt::from(0) {
        &size + end
    } else {
        end
    };
    let end = end.max(BigInt::from(0)).min(size);
    Ok((
        usize::try_from(end).map_err(|_| Error(ErrorKind::Overflow))?,
        true,
    ))
}

pub fn is_text_like_content_type(value: &Value) -> Result<bool> {
    if !truthy(value) {
        return Ok(false);
    }
    let text = value.as_str().ok_or(Error(ErrorKind::Attribute))?;
    let base = text
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(crate::policy::python_whitespace);
    static PATTERN: OnceLock<std::result::Result<fancy_regex::Regex, ()>> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| crate::inspection::compile_python_pattern(
        r"^(text/.*|application/json|application/javascript|application/xml|application/x-www-form-urlencoded|application/problem\+json|application/graphql-response\+json|application/[a-zA-Z0-9._-]+\+json|application/[a-zA-Z0-9._-]+\+xml)$", true).map_err(|_| ()));
    pattern
        .as_ref()
        .map_err(|_| Error(ErrorKind::Compatibility))?
        .is_match(base)
        .map_err(|_| Error(ErrorKind::Compatibility))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_start_keeps_source_pending_migration_until_owner_drop() {
        let directory = tempfile::tempdir().unwrap();
        for version in [1, 2] {
            let path = directory.path().join(format!("pending{version}.db"));
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(&format!("CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value); PRAGMA user_version={version};")).unwrap();
            drop(connection);
            let (store, error) = FlowStore::start(Ok(&path), Settings::default());
            assert_eq!(error.unwrap().kind(), ErrorKind::Operational);
            {
                let connection = store.lock().unwrap();
                assert_eq!(connection.is_autocommit(), version == 2);
                assert_eq!(
                    connection
                        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                        .unwrap(),
                    2
                );
                assert_eq!(
                    connection
                        .query_row(
                            "SELECT COUNT(*) FROM sqlite_master WHERE name='flow_fts'",
                            [],
                            |row| row.get::<_, i64>(0)
                        )
                        .unwrap(),
                    1
                );
            }
            let external = Connection::open(&path).unwrap();
            assert_eq!(
                external
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            drop(store);
            assert_eq!(
                external
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name='flow_fts'",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                i64::from(version == 2)
            );
        }
    }

    #[test]
    fn connection_settings_are_the_source_pragmas() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            FlowStore::open(&directory.path().join("flows.db"), Settings::default()).unwrap();
        let connection = store.lock().unwrap();
        for (pragma, expected) in [
            ("synchronous", 1),
            ("temp_store", 2),
            ("foreign_keys", 1),
            ("busy_timeout", 5000),
            ("user_version", 2),
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                expected,
                "{pragma}"
            );
        }
    }
}
