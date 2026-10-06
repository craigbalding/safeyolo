//! Operator-owned fresh Coord rooms and the existing private NATS runtime.
//! Agents reach only the Agent API. These mutations have no remote route.

use crate::{Error, coord_supervisor::atomic_write};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const NATS_VERSION: &str = "2.14.5";
fn directory(root: &Path) -> Result<PathBuf, Error> {
    let config_path = if root == crate::host_platform::config_dir() {
        crate::host_platform::config_path()
    } else {
        root.join("config.toml")
    };
    let config = crate::native_config::read(&config_path)?;
    Ok(config
        .data_dir
        .ok_or("native data directory is missing")?
        .join("coord"))
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| t.as_millis() as i64)
}

pub fn bootstrap(root: &Path) -> Result<(), Error> {
    let data = directory(root)?;
    fs::create_dir_all(&data)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
    let _lock = crate::host_platform::lock_host_state(&data.join("bootstrap.lock"))?;
    let id = fs::read_to_string(root.join("data/instance_id"))?;
    let mut connection = Connection::open(data.join("v0.db"))?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let version: u32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 {
        let tables: u32 = transaction.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if tables != 0 {
            return Err(
                "native Coord requires fresh state; old-store conversion is unsupported".into(),
            );
        }
        transaction.execute_batch(include_str!("coord_schema.sql"))?;
        transaction.execute("INSERT INTO instance(id) VALUES (?1)", [id.trim()])?;
    } else if version != 5 {
        return Err(
            format!("Coord schema {version} is not operational; expected version 5").into(),
        );
    }
    let stored: String = transaction.query_row("SELECT id FROM instance", [], |row| row.get(0))?;
    if stored != id.trim() {
        return Err("Coord identity differs from this native instance; preserve the store and select its owning root".into());
    }
    transaction.commit()?;
    fs::set_permissions(data.join("v0.db"), fs::Permissions::from_mode(0o600))?;
    if !data.join("instance_id").exists() {
        atomic_write(&data.join("instance_id"), id.trim().as_bytes(), 0o600)?;
    }
    Ok(())
}

fn open(root: &Path) -> Result<Connection, Error> {
    let connection = Connection::open_with_flags(
        directory(root)?.join("v0.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys=ON;")?;
    if connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))? != 5 {
        return Err("Coord store is not operational".into());
    }
    Ok(connection)
}
fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pin() -> Result<(&'static str, &'static str, &'static str), Error> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok((
            "linux-amd64",
            "5e3b603d47c447bda1f77f9ac16dbf91c90aac4ff3681f8fbbc7201e4ed99355",
            "e1a2f9ba25077f4cf753bee829483bd68fbf0a4eec9b6645a1e5785a6de0c0d1",
        )),
        ("linux", "aarch64") => Ok((
            "linux-arm64",
            "673a98d3faa79dde3f9ebf16d6dfac36a5f694e7ad2015e4954dd7939c85cd4c",
            "ebccb25ba4f364dd8878630f1985d8b24d9e0a6e35aa4d8e1a7ecab38c881419",
        )),
        ("macos", "x86_64") => Ok((
            "darwin-amd64",
            "f95c98d6b6ed2b63c5681b46b092c9585c99767d547cf495730c329234625e96",
            "5df71e798cab833b99514f42d65123bcbd60ef64673b4c543bfd00e6482a22a7",
        )),
        ("macos", "aarch64") => Ok((
            "darwin-arm64",
            "ddd907854d9a2de834af133fa396915fe6442fe6d8909ae31390d1ea7a0fea50",
            "0a8beaf990916185fa8a4e2236f1c6525a8be8f5f1c1d83225458b4baa822e0e",
        )),
        _ => Err("no reviewed NATS binary pin for this host platform".into()),
    }
}
async fn binary(root: &Path, supplied: Option<&Path>) -> Result<PathBuf, Error> {
    let (platform, archive_hash, binary_hash) = pin()?;
    let destination = directory(root)?.join(format!("nats/bin/{NATS_VERSION}/nats-server"));
    let verify = |path: &Path| -> Result<(), Error> {
        if hash(&fs::read(path)?) != binary_hash {
            return Err("NATS executable differs from its reviewed platform pin".into());
        }
        Ok(())
    };
    if destination.try_exists()? {
        verify(&destination)?;
        return Ok(destination);
    }
    fs::create_dir_all(destination.parent().ok_or("NATS path has no parent")?)?;
    if let Some(source) = supplied {
        verify(source)?;
        fs::copy(source, &destination)?;
    } else {
        let archive = tempfile::NamedTempFile::new_in(destination.parent().unwrap())?;
        let url = format!(
            "https://github.com/nats-io/nats-server/releases/download/v{NATS_VERSION}/nats-server-v{NATS_VERSION}-{platform}.tar.gz"
        );
        let status = tokio::process::Command::new("curl")
            .args([
                "--fail",
                "--show-error",
                "--silent",
                "--location",
                "--max-time",
                "120",
                "--output",
            ])
            .arg(archive.path())
            .arg(url)
            .status()
            .await?;
        if !status.success() {
            return Err("cannot acquire reviewed NATS artifact through the configured network route; use coord start --binary PATH with the pinned binary".into());
        }
        if hash(&fs::read(archive.path())?) != archive_hash {
            return Err("NATS download differs from its reviewed archive pin".into());
        }
        let output = tokio::process::Command::new("tar")
            .arg("-xOf")
            .arg(archive.path())
            .arg(format!(
                "nats-server-v{NATS_VERSION}-{platform}/nats-server"
            ))
            .output()
            .await?;
        if !output.status.success() || hash(&output.stdout) != binary_hash {
            return Err("cannot extract the pinned NATS executable".into());
        }
        fs::write(&destination, &output.stdout)?;
    }
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    verify(&destination)?;
    Ok(destination)
}

fn record(root: &Path) -> Result<Option<Value>, Error> {
    crate::guest_commands::read_state(&directory(root)?.join("nats/process.json"))
}
fn identity(value: &Value) -> Result<(i32, &str), Error> {
    let pid = value["pid"]
        .as_i64()
        .and_then(|p| i32::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or("invalid NATS PID")?;
    let token = value["token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or("invalid NATS process token")?;
    Ok((pid, token))
}
fn same_process(value: &Value) -> Result<bool, Error> {
    let (pid, token) = identity(value)?;
    match crate::host_lifecycle::process_token(i64::from(pid)) {
        Some(current) => Ok(current == token),
        None if cfg!(target_os = "linux")
            && fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .is_some_and(|s| {
                    s.rsplit_once(')')
                        .is_some_and(|(_, tail)| tail.split_whitespace().next() == Some("Z"))
                }) =>
        {
            Ok(false)
        }
        None if unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) =>
        {
            Err("recorded NATS process identity is unavailable; ownership is unknown".into())
        }
        None => Ok(false),
    }
}

fn stop_owned(pid: i32, token: &str) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let handle = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        if crate::host_lifecycle::process_token(i64::from(pid)).as_deref() != Some(token) {
            return Err("NATS process changed before signaling; record retained".into());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if crate::host_lifecycle::process_token(i64::from(pid)).as_deref() != Some(token) {
            return Err("NATS process changed before signaling; record retained".into());
        }
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

async fn monitor(port: u16) -> Result<Value, Error> {
    let stream = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    crate::native_client::send_json(
        stream,
        &format!("127.0.0.1:{port}"),
        "/varz",
        "",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(1),
    )
    .await
}
fn observed_ports(nats: &Path, pid: u32) -> Result<(u16, u16), Error> {
    let ports: Value =
        serde_json::from_slice(&fs::read(nats.join(format!("nats-server_{pid}.ports")))?)?;
    let port = |name: &str| -> Result<u16, Error> {
        ports[name]
            .as_array()
            .and_then(|ports| ports.first())
            .and_then(Value::as_str)
            .and_then(|endpoint| endpoint.parse::<hyper::Uri>().ok())
            .and_then(|endpoint| endpoint.port_u16())
            .filter(|port| *port > 0)
            .ok_or_else(|| format!("NATS did not report a valid {name} listener port").into())
    };
    Ok((port("nats")?, port("monitoring")?))
}

async fn verified(root: &Path, value: &Value) -> Result<bool, Error> {
    if !same_process(value)? {
        return Ok(false);
    }
    let (pid, _) = identity(value)?;
    let nats = directory(root)?.join("nats");
    if !crate::host_platform::process_has_path_argument(
        i64::from(pid),
        &nats.join(format!("bin/{NATS_VERSION}/nats-server")),
        b"--config",
        &nats.join("server.conf"),
    ) {
        return Ok(false);
    }
    // NATS /varz has no PID and reports -1 for a dynamic monitor port.
    // Bind both observed endpoints to this process's owned ports file instead.
    let (client, monitor_port) = observed_ports(&nats, pid as u32)?;
    if value["client_port"] != client || value["monitor_port"] != monitor_port {
        return Ok(false);
    }
    let current = monitor(monitor_port).await?;
    Ok(current["server_name"] == value["server_name"]
        && current["server_name"].is_string()
        && current["port"] == value["client_port"])
}

fn listener_ports(
    client: Option<u16>,
    monitor: Option<u16>,
    dynamic: bool,
) -> Result<(i32, i32), Error> {
    if client == Some(0) || monitor == Some(0) {
        return Err("Coord listener ports must be between 1 and 65535".into());
    }
    if client
        .zip(monitor)
        .is_some_and(|(client, monitor)| client == monitor)
    {
        return Err("Coord client and monitor ports must differ".into());
    }
    let client = client.map_or(if dynamic { -1 } else { 4222 }, i32::from);
    let monitor = monitor.map_or(if dynamic { -1 } else { 8222 }, i32::from);
    Ok((client, monitor))
}

pub async fn start(
    root: &Path,
    supplied: Option<&Path>,
    client_port: Option<u16>,
    monitor_port: Option<u16>,
) -> Result<Value, Error> {
    let dynamic = std::env::var_os("SAFEYOLO_NATS_TEST_INSTANCE").is_some();
    let (selected_client, selected_monitor) = listener_ports(client_port, monitor_port, dynamic)?;
    bootstrap(root)?;
    let data = directory(root)?;
    let nats = data.join("nats");
    fs::create_dir_all(&nats)?;
    fs::set_permissions(&nats, fs::Permissions::from_mode(0o700))?;
    let lock_path = nats.join("runtime.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock_path))
            .await??;
    if let Some(saved) = record(root)?
        && same_process(&saved)?
    {
        if verified(root, &saved).await? {
            if client_port.is_some_and(|p| saved["client_port"] != p)
                || monitor_port.is_some_and(|p| saved["monitor_port"] != p)
            {
                return Err(format!(
                    "Coord is already running on client port {} and monitor port {}; stop this instance's Coord before changing listener ports",
                    saved["client_port"], saved["monitor_port"]
                )
                .into());
            }
            return Ok(saved);
        }
        return Err("a recorded NATS process is live but ownership is unverified; preserve it and inspect coord status before restarting".into());
    }
    if selected_client > 0 && selected_client == selected_monitor {
        return Err("Coord client and monitor ports must differ".into());
    }
    let executable = binary(root, supplied).await?;
    let credentials = nats.join("creds");
    if !credentials.exists() {
        atomic_write(
            &credentials,
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )
            .as_bytes(),
            0o600,
        )?;
    }
    let password = zeroize::Zeroizing::new(fs::read_to_string(&credentials)?);
    if password.trim().is_empty() {
        return Err("NATS credential file is empty".into());
    }
    let server_name = format!("safeyolo-{}", uuid::Uuid::new_v4().simple());
    let jetstream = nats.join("jetstream");
    fs::create_dir_all(&jetstream)?;
    let config = nats.join("server.conf");
    atomic_write(&config,format!("host: 127.0.0.1\nport: {selected_client}\nhttp: 127.0.0.1:{selected_monitor}\nserver_name: {server_name}\nmax_payload: 2097152\nports_file_dir: {}\nauthorization {{ user: safeyolo, password: {} }}\njetstream {{ store_dir: {}, max_file_store: 1073741824 }}\n",serde_json::to_string(&nats.to_string_lossy())?,serde_json::to_string(password.trim())?,serde_json::to_string(&jetstream.to_string_lossy())?).as_bytes(),0o600)?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(nats.join("nats-server.log"))?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id().ok_or("NATS has no PID")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let result = async {
        while tokio::time::Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Err("NATS exited during startup; inspect its owned log".into());
            }
            if let Ok((client, monitor_port)) = observed_ports(&nats, pid) {
                let token = crate::host_lifecycle::process_token(i64::from(pid))
                    .ok_or("NATS process identity is unavailable")?;
                let saved = json!({"pid":pid,"token":token,"server_name":server_name,"client_port":client,"monitor_port":monitor_port});
                // Use the same process/server/endpoint check as reuse,
                // status, room clients and stop before publishing endpoints.
                if verified(root, &saved).await.unwrap_or(false) {
                    if (selected_client > 0 && selected_client != i32::from(client))
                        || (selected_monitor > 0 && selected_monitor != i32::from(monitor_port))
                    {
                        return Err("NATS reported listener ports different from the selected ports".into());
                    }
                    atomic_write(&nats.join("process.json"), &serde_json::to_vec(&saved)?, 0o600)?;
                    if dynamic {
                        atomic_write(&nats.join("test-endpoints.json"), &serde_json::to_vec(&saved)?, 0o600)?;
                    }
                    return Ok(saved);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err("NATS did not become ready within eight seconds; inspect its owned log".into())
    }.await;
    if result.is_err() {
        child.kill().await?;
    }
    result
}

pub async fn stop(root: &Path) -> Result<Value, Error> {
    let path = directory(root)?.join("nats");
    let lock = path.join("runtime.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock)).await??;
    let Some(saved) = record(root)? else {
        return Ok(json!({"state":"stopped"}));
    };
    if same_process(&saved)? {
        if !verified(root, &saved).await? {
            return Err("NATS ownership is unverified; no process was signalled".into());
        }
        let (pid, token) = identity(&saved)?;
        stop_owned(pid, token)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while same_process(&saved)? {
            if tokio::time::Instant::now() >= deadline {
                return Err("owned NATS did not stop; process record retained".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    fs::remove_file(path.join("process.json"))?;
    if path.join("test-endpoints.json").exists() {
        fs::remove_file(path.join("test-endpoints.json"))?;
    }
    let ports = path.join(format!("nats-server_{}.ports", saved["pid"]));
    if ports.exists() {
        fs::remove_file(ports)?;
    }
    Ok(json!({"state":"stopped"}))
}

pub async fn status(root: &Path) -> Result<Value, Error> {
    match record(root)? {
        None => Ok(json!({"state":"stopped"})),
        Some(saved) => {
            let state = match same_process(&saved) {
                Ok(false) => "stopped",
                Ok(true) if verified(root, &saved).await.unwrap_or(false) => "running",
                _ => "unknown",
            };
            Ok(
                json!({"state":state,"process":saved,"next_action":if state=="unknown"{json!("inspect the owned NATS log and monitor; do not replace an unverified live process")}else{Value::Null}}),
            )
        }
    }
}

async fn jetstream(root: &Path) -> Result<async_nats::jetstream::Context, Error> {
    let saved = record(root)?.ok_or("NATS is not running; run coord start")?;
    if !verified(root, &saved).await? {
        return Err("NATS ownership or readiness is unverified".into());
    }
    let port = saved["client_port"]
        .as_u64()
        .ok_or("NATS endpoint is missing")?;
    let password =
        zeroize::Zeroizing::new(fs::read_to_string(directory(root)?.join("nats/creds"))?);
    let client = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), password.trim().into())
        .connection_timeout(Duration::from_secs(2))
        .request_timeout(Some(Duration::from_secs(2)))
        .connect(format!("nats://127.0.0.1:{port}"))
        .await?;
    Ok(async_nats::jetstream::new(client))
}

pub async fn create_room(root: &Path, name: &str) -> Result<Value, Error> {
    if name.trim().is_empty() {
        return Err("room name must be nonempty".into());
    }
    bootstrap(root)?;
    let lock = directory(root)?.join("rooms.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock)).await??;
    let connection = open(root)?;
    if connection
        .query_row("SELECT room_id FROM rooms WHERE name=?1", [name], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .is_some()
    {
        return Err("room already exists".into());
    }
    let id = format!("rm-{}", uuid::Uuid::new_v4().simple());
    let stream = format!("ROOM_{id}");
    let js = jetstream(root).await?;
    use async_nats::jetstream::stream::{Config, StorageType};
    js.create_stream(Config {
        name: stream.clone(),
        subjects: vec![format!("rooms.{id}")],
        storage: StorageType::File,
        max_bytes: -1,
        max_age: Duration::from_secs(7 * 24 * 60 * 60),
        max_message_size: 2 * 1024 * 1024,
        max_messages: 100_000,
        duplicate_window: Duration::from_secs(120),
        ..Config::default()
    })
    .await?;
    if let Err(error) = connection.execute(
        "INSERT INTO rooms(room_id,name,created_at) VALUES (?1,?2,?3)",
        params![id, name, now()],
    ) {
        js.delete_stream(stream).await.map_err(|cleanup| {
            format!("room registration failed ({error}); owned stream cleanup failed ({cleanup})")
        })?;
        return Err(error.into());
    }
    Ok(json!({"room_id":id,"room_name":name}))
}

pub fn grant(
    config: &Path,
    room: &str,
    agent: &str,
    permissions: &[String],
    revoke: bool,
) -> Result<Value, Error> {
    let config = crate::native_config::read(config)?;
    let root = config
        .native_config_path
        .as_ref()
        .and_then(|p| p.parent())
        .ok_or("native root is missing")?;
    bootstrap(root)?;
    let policy = fs::read_to_string(config.policy_file.ok_or("native policy path is missing")?)?
        .parse::<toml_edit::DocumentMut>()?;
    let id = policy
        .get("agents")
        .and_then(|agents| agents.get(agent))
        .and_then(|a| a.get("agent_id"))
        .and_then(toml_edit::Item::as_str)
        .ok_or("agent identity is not configured")?;
    let mut permissions = permissions.to_vec();
    if permissions.is_empty() {
        permissions = vec!["send".into(), "receive".into()];
    }
    permissions.sort();
    permissions.dedup();
    if permissions
        .iter()
        .any(|p| !["send", "receive"].contains(&p.as_str()))
    {
        return Err("room permission must be send or receive".into());
    }
    let mut connection = open(root)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id: String =
        transaction.query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |r| {
            r.get(0)
        })?;
    let latest:Option<i64>=transaction.query_row("SELECT MAX(granted_at) FROM memberships WHERE room_id=?1 AND principal_kind='agent' AND principal_id=?2",params![room_id,id],|r|r.get(0))?;
    let active:Option<String>=transaction.query_row("SELECT permissions FROM memberships WHERE room_id=?1 AND principal_kind='agent' AND principal_id=?2 AND revoked_at IS NULL ORDER BY granted_at DESC LIMIT 1",params![room_id,id],|r|r.get(0)).optional()?;
    if revoke {
        transaction.execute("UPDATE memberships SET revoked_at=?3 WHERE room_id=?1 AND principal_kind='agent' AND principal_id=?2 AND revoked_at IS NULL",params![room_id,id,now()])?;
    } else if active.as_deref() != Some(&permissions.join(",")) {
        transaction.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES (?1,'agent',?2,?3,?4)",params![room_id,id,permissions.join(","),now().max(latest.unwrap_or(0)+1)])?;
    }
    transaction.commit()?;
    Ok(json!({"room_id":room_id,"agent_id":id,"permissions":if revoke{vec![]}else{permissions}}))
}

pub async fn run(config: &Path, arguments: &[String]) -> Result<(), Error> {
    let root = config.parent().ok_or("native root is missing")?;
    let result = match arguments {
        [kind, options @ ..] if kind == "start" => {
            let mut binary = None;
            let mut client = None;
            let mut monitor = None;
            let mut options = options.iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--binary" => {
                        let value = options.next().ok_or("--binary requires a path")?;
                        if binary.replace(Path::new(value)).is_some() {
                            return Err("duplicate --binary option".into());
                        }
                    }
                    "--client-port" | "--monitor-port" => {
                        let port = options
                            .next()
                            .and_then(|value| value.parse::<u16>().ok())
                            .filter(|p| *p > 0)
                            .ok_or_else(|| {
                                format!("{option} requires a port between 1 and 65535")
                            })?;
                        let selected = if option == "--client-port" {
                            &mut client
                        } else {
                            &mut monitor
                        };
                        if selected.replace(port).is_some() {
                            return Err(format!("duplicate {option} option").into());
                        }
                    }
                    _ => return Err(format!("unknown coord start option: {option}").into()),
                }
            }
            start(root, binary, client, monitor).await?
        }
        [kind] if kind == "stop" => stop(root).await?,
        [kind] if kind == "status" => status(root).await?,
        [room, kind, name] if room == "room" && kind == "create" => create_room(root, name).await?,
        [room, kind] if room == "room" && kind == "list" => {
            bootstrap(root)?;
            let connection = open(root)?;
            let mut statement =
                connection.prepare("SELECT room_id,name FROM rooms ORDER BY created_at,room_id")?;
            let rows = statement
                .query_map([], |r| {
                    Ok(json!({"room_id":r.get::<_,String>(0)?,"room_name":r.get::<_,String>(1)?}))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            json!({"rooms":rows})
        }
        [kind, room, agent, permissions @ ..] if kind == "grant" => {
            grant(config, room, agent, permissions, false)?
        }
        [kind, room, agent] if kind == "revoke" => grant(config, room, agent, &[], true)?,
        [help] if help == "--help" => {
            println!(
                "safeyolo [--root ROOT] coord start [--binary PINNED_NATS] [--client-port PORT] [--monitor-port PORT]\nsafeyolo [--root ROOT] coord stop|status\nsafeyolo [--root ROOT] coord room create NAME\nsafeyolo [--root ROOT] coord room list\nsafeyolo [--root ROOT] coord grant ROOM AGENT [send] [receive]\nsafeyolo [--root ROOT] coord revoke ROOM AGENT\nNative instance rooms and membership use the existing SQLite/JetStream store. Agents use the scoped Agent API. start acquires the reviewed NATS 2.14.5 binary through the configured route when missing.\nListener ports bind to 127.0.0.1. Explicit ports must be distinct and between 1 and 65535. Omitted ports use 4222/8222, or dynamic ports with SAFEYOLO_NATS_TEST_INSTANCE. A running instance is reused unless an explicit port conflicts. Stop Coord before changing live ports; repeat explicit ports on each new start."
            );
            return Ok(());
        }
        _ => return Err("usage: safeyolo coord --help".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
