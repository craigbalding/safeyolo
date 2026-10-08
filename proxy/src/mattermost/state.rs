//! One private adapter delivery ledger, never canonical Coord authority.
use super::config::{Config, coord_id};
use crate::Error;
use rusqlite::{Connection, OptionalExtension, ffi, params};
use serde_json::{Value, json};
use std::{
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_millis().min(i64::MAX as u128) as i64)
}

pub(super) fn private_file(path: &Path, create: bool) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    if create {
        options.write(true).create(true).mode(0o600);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("Mattermost file must be private, regular and operator-owned".into());
    }
    if identity(&metadata) != identity(&fs::symlink_metadata(path)?) {
        return Err("Mattermost file identity changed".into());
    }
    Ok(file)
}
pub(super) fn token(path: &Path) -> Result<Zeroizing<String>, Error> {
    let mut file = private_file(path, false)?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("Mattermost token file exceeds limit".into());
    }
    let token = Zeroizing::new(std::str::from_utf8(&bytes)?.trim().to_owned());
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err("Mattermost token file requires one non-empty token".into());
    }
    Ok(token)
}
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn fd_identity(fd: i32) -> Option<(u64, u64)> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return None;
    }
    #[cfg(target_os = "macos")]
    let device = metadata.st_dev as u64;
    #[cfg(not(target_os = "macos"))]
    let device = metadata.st_dev;
    Some((device, metadata.st_ino))
}

// Prefix of unixFile in the existing bundled SQLite 3.53.2 (public domain),
// sqlite3.c in libsqlite3-sys 0.38.2. Keep this prefix aligned with that source
// when updating SQLite. FILE_POINTER names this connection's actual writer;
// process-wide descriptor snapshots cannot identify it across FD reuse.
#[repr(C)]
struct SqliteUnixFile {
    methods: *const ffi::sqlite3_io_methods,
    vfs: *mut ffi::sqlite3_vfs,
    inode: *mut libc::c_void,
    descriptor: libc::c_int,
}

fn sqlite_file_identity(db: &Connection) -> Result<(u64, u64), Error> {
    let mut vfs: *mut ffi::sqlite3_vfs = std::ptr::null_mut();
    let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
    // Both outputs belong to this live connection; SQLite defines their types
    // for these file controls. Neither pointer is retained beyond this call.
    let (vfs_status, file_status) = unsafe {
        (
            ffi::sqlite3_file_control(
                db.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_VFS_POINTER,
                std::ptr::from_mut(&mut vfs).cast(),
            ),
            ffi::sqlite3_file_control(
                db.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                std::ptr::from_mut(&mut file).cast(),
            ),
        )
    };
    if vfs_status != ffi::SQLITE_OK
        || file_status != ffi::SQLITE_OK
        || vfs.is_null()
        || file.is_null()
    {
        return Err("SQLite state file identity is unavailable".into());
    }
    // Production uses bundled SQLite's Unix VFS on Linux and macOS. Check its
    // name and allocation size before reading the adapted unixFile prefix.
    let layout_matches = unsafe {
        !(*vfs).zName.is_null()
            && CStr::from_ptr((*vfs).zName).to_bytes().starts_with(b"unix")
            && (*vfs).szOsFile as usize >= std::mem::size_of::<SqliteUnixFile>()
    };
    if !layout_matches {
        return Err("SQLite state file layout is unavailable".into());
    }
    // The bundled Unix VFS allocates a unixFile; the prefix contains only
    // native pointers and an int. Confirm the VFS association before fstat.
    let writer = unsafe { &*file.cast::<SqliteUnixFile>() };
    if writer.vfs != vfs {
        return Err("SQLite state file layout changed".into());
    }
    fd_identity(writer.descriptor).ok_or_else(|| "SQLite state file identity is unavailable".into())
}

pub(super) struct State {
    pub db: Connection,
    path: PathBuf,
    lease_path: PathBuf,
    parent: File,
    anchor: File,
    lease: File,
}
impl State {
    pub fn open(config: &Config) -> Result<Self, Error> {
        let path = &config.state;
        let parent_path = path.parent().ok_or("Mattermost state has no parent")?;
        if !parent_path.exists() {
            fs::create_dir_all(parent_path)?;
            fs::set_permissions(parent_path, fs::Permissions::from_mode(0o700))?;
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent_path)?;
        let metadata = parent.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
            || identity(&metadata) != identity(&fs::symlink_metadata(parent_path)?)
        {
            return Err("Mattermost state parent must be owned and not writable by others".into());
        }
        let anchor = private_file(path, true)?;
        let mut lease_name = path.as_os_str().to_owned();
        lease_name.push(".lock");
        let lease_path = PathBuf::from(lease_name);
        let lease = private_file(&lease_path, true)?;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another Mattermost adapter owns this state lease".into());
        }
        // The native VFS needs the real path for adjacent WAL sidecars. Keep
        // this connection and validate its writer before any schema/state write.
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let mut state = Self {
            db,
            path: path.clone(),
            lease_path,
            parent,
            anchor,
            lease,
        };
        state.validate()?;
        state.db.busy_timeout(Duration::from_secs(10))?;
        let existing_tables: i64 = state.db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )?;
        if existing_tables != 0 {
            let schema: Option<String> = state
                .db
                .query_row(
                    "SELECT value FROM metadata WHERE key='native_schema'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if schema.as_deref() != Some("safeyolo.mattermost.native/v1") {
                return Err("Mattermost native adapter requires a fresh state path; preserve the previous store".into());
            }
        }
        // Coord sequences are u64. TEXT affinity preserves their decimal value
        // above i64::MAX; INTEGER affinity would coerce that text to lossy REAL.
        state.db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS room_state(coord_room TEXT PRIMARY KEY,channel_id TEXT UNIQUE NOT NULL,coord_cursor TEXT NOT NULL DEFAULT '0',inbound_since INTEGER NOT NULL DEFAULT 0,initialized INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS outbound_projection(coord_msg_id TEXT PRIMARY KEY,coord_room TEXT NOT NULL,channel_id TEXT NOT NULL,projection_key TEXT UNIQUE NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','sent')),mattermost_post_id TEXT UNIQUE,created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS inbound_post(mattermost_post_id TEXT PRIMARY KEY,coord_room TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('ignored','pending','sent')),reason TEXT,coord_msg_id TEXT,created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS action_capability(capability_hash TEXT PRIMARY KEY,coord_msg_id TEXT UNIQUE NOT NULL REFERENCES outbound_projection(coord_msg_id),coord_room TEXT NOT NULL,channel_id TEXT NOT NULL,projection_key TEXT UNIQUE NOT NULL,adapter_id TEXT NOT NULL,allowed_actions TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('issued','pending','used')),mattermost_post_id TEXT UNIQUE,expires_at INTEGER NOT NULL,selected_action TEXT,coord_action_msg_id TEXT,
                CHECK((status='issued' AND selected_action IS NULL AND coord_action_msg_id IS NULL) OR (status='pending' AND selected_action IS NOT NULL AND coord_action_msg_id IS NULL) OR (status='used' AND selected_action IS NOT NULL AND coord_action_msg_id IS NOT NULL)));")?;
        let transaction = state
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (key, value) in [
            ("native_schema", "safeyolo.mattermost.native/v1".to_owned()),
            ("adapter_id", config.id.clone()),
            (
                "state_identity",
                format!(
                    "{}:{}",
                    state.anchor.metadata()?.dev(),
                    state.anchor.metadata()?.ino()
                ),
            ),
            (
                "lease_identity",
                format!(
                    "{}:{}",
                    state.lease.metadata()?.dev(),
                    state.lease.metadata()?.ino()
                ),
            ),
        ] {
            let stored: Option<String> = transaction
                .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                    r.get(0)
                })
                .optional()?;
            if stored.as_ref().is_some_and(|v| v != &value) {
                return Err("Mattermost state belongs to a different configuration or file identity; select a fresh state path".into());
            }
            transaction.execute(
                "INSERT OR IGNORE INTO metadata VALUES (?1,?2)",
                params![key, value],
            )?;
        }
        for room in &config.rooms {
            transaction.execute(
                "INSERT OR IGNORE INTO room_state(coord_room,channel_id) VALUES (?1,?2)",
                params![room.name, room.channel],
            )?;
        }
        transaction.commit()?;
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<(), Error> {
        for (file, path, directory) in [
            (
                &self.parent,
                self.path.parent().ok_or("state has no parent")?,
                true,
            ),
            (&self.anchor, self.path.as_path(), false),
            (&self.lease, self.lease_path.as_path(), false),
        ] {
            let opened = file.metadata()?;
            let linked = fs::symlink_metadata(path)?;
            if opened.uid() != unsafe { libc::geteuid() }
                || opened.mode() & if directory { 0o022 } else { 0o077 } != 0
                || linked.file_type().is_symlink()
                || linked.is_dir() != directory
                || (!directory && !linked.is_file())
                || identity(&opened) != identity(&linked)
            {
                return Err("Mattermost state/lease identity or permissions changed".into());
            }
        }
        if sqlite_file_identity(&self.db)? != identity(&self.anchor.metadata()?) {
            return Err("SQLite state descriptor identity changed".into());
        }
        Ok(())
    }
    pub fn query(&self, sql: &str, parameters: impl rusqlite::Params) -> Result<Vec<Value>, Error> {
        self.validate()?;
        let mut statement = self.db.prepare(sql)?;
        let names: Vec<_> = statement
            .column_names()
            .iter()
            .map(|v| (*v).to_owned())
            .collect();
        let rows = statement
            .query_map(parameters, |row| {
                let mut value = serde_json::Map::new();
                for (index, name) in names.iter().enumerate() {
                    let entry = match row.get_ref(index)? {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(v) => json!(v),
                        rusqlite::types::ValueRef::Text(v) => json!(
                            std::str::from_utf8(v).map_err(|_| rusqlite::Error::InvalidQuery)?
                        ),
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    value.insert(name.clone(), entry);
                }
                Ok(Value::Object(value))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        self.validate()?;
        Ok(rows)
    }
    pub fn execute(&self, sql: &str, parameters: impl rusqlite::Params) -> Result<usize, Error> {
        self.validate()?;
        let count = self.db.execute(sql, parameters)?;
        self.validate()?;
        Ok(count)
    }
    pub fn initialize_room(
        &self,
        room: &str,
        cursor: u64,
        inbound_since: i64,
    ) -> Result<usize, Error> {
        self.execute(
            "UPDATE room_state SET initialized=1,coord_cursor=?2,inbound_since=?3 WHERE coord_room=?1 AND initialized=0",
            params![room, cursor.to_string(), inbound_since],
        )
    }
    pub fn set_coord_cursor(&self, room: &str, cursor: u64) -> Result<usize, Error> {
        self.execute(
            "UPDATE room_state SET coord_cursor=?2 WHERE coord_room=?1",
            params![room, cursor.to_string()],
        )
    }
    pub fn coord_cursor(&self, room: &str) -> Result<u64, Error> {
        let row = self
            .query(
                "SELECT coord_cursor FROM room_state WHERE coord_room=?1",
                [room],
            )?
            .into_iter()
            .next()
            .ok_or("Mattermost room state is missing")?;
        row["coord_cursor"]
            .as_str()
            .ok_or("invalid projection cursor")?
            .parse()
            .map_err(|_| "invalid projection cursor".into())
    }
    pub fn finish_projection(&mut self, msg: &str, post: &str) -> Result<(), Error> {
        self.validate()?;
        let transaction = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if transaction.execute("UPDATE outbound_projection SET status='sent',mattermost_post_id=?2 WHERE coord_msg_id=?1 AND status='pending'", params![msg,post])? != 1 { return Err("projection completion does not match pending state".into()); }
        transaction.execute("UPDATE action_capability SET mattermost_post_id=?2 WHERE coord_msg_id=?1 AND mattermost_post_id IS NULL", params![msg,post])?;
        transaction.commit()?;
        self.validate()
    }
    pub fn begin_action(
        &mut self,
        payload: &Value,
        adapter: &str,
        consume: bool,
    ) -> Result<Value, u16> {
        self.validate().map_err(|_| 503u16)?;
        let context = &payload["context"];
        let token = context["capability"].as_str().ok_or(400u16)?;
        let digest = crate::coord_setup::sha256(token.as_bytes());
        let row = self
            .query(
                "SELECT * FROM action_capability WHERE capability_hash=?1",
                [&digest],
            )
            .map_err(|_| 503u16)?
            .into_iter()
            .next()
            .ok_or(403u16)?;
        let projection = self
            .query(
                "SELECT * FROM outbound_projection WHERE coord_msg_id=?1",
                [row["coord_msg_id"].as_str().ok_or(503u16)?],
            )
            .map_err(|_| 503u16)?
            .into_iter()
            .next()
            .ok_or(403u16)?;
        let allowed: Value = serde_json::from_str(row["allowed_actions"].as_str().ok_or(503u16)?)
            .map_err(|_| 503u16)?;
        let root = payload
            .get("root_id")
            .filter(|v| !v.is_null() && *v != "")
            .unwrap_or(&payload["post_id"]);
        if row["adapter_id"] != adapter
            || context["adapter_id"] != adapter
            || context["projection_key"] != row["projection_key"]
            || row["channel_id"] != payload["channel_id"]
            || row["mattermost_post_id"] != payload["post_id"]
            || root != &payload["post_id"]
            || projection["status"] != "sent"
            || projection["mattermost_post_id"] != payload["post_id"]
            || projection["coord_room"] != row["coord_room"]
            || projection["channel_id"] != row["channel_id"]
            || projection["projection_key"] != row["projection_key"]
            || !allowed
                .as_array()
                .is_some_and(|v| v.contains(&context["action"]))
        {
            return Err(403);
        }
        if row["expires_at"].as_i64().ok_or(503u16)? <= now() {
            return Err(410);
        }
        match row["status"].as_str() {
            Some("used") => return Err(409),
            Some("pending") => return Err(503),
            Some("issued") => {}
            _ => return Err(503),
        }
        if consume && self.execute("UPDATE action_capability SET status='pending',selected_action=?2 WHERE capability_hash=?1 AND status='issued'", params![digest,context["action"].as_str().ok_or(400u16)?]).map_err(|_| 503u16)? != 1 { return Err(409); }
        Ok(row)
    }
    pub fn finish_action(&self, hash: &str, msg: &str) -> Result<(), Error> {
        if !coord_id(msg, "msg-") || self.execute("UPDATE action_capability SET status='used',coord_action_msg_id=?2 WHERE capability_hash=?1 AND status='pending'", params![hash,msg])? != 1 { return Err("action completion does not match pending state".into()); }
        Ok(())
    }
}
