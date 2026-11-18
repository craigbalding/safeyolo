//! Temporary native instances use the ordinary root, identity and lifecycle.

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

use crate::{Error, host_platform};

pub const HELP: &str = "safeyolo [--root SOURCE] instance run --ephemeral [--runtime DIRECTORY] [--reuse-guest-assets-from ROOT|default] [--directory PARENT] -- COMMAND [ARGUMENTS...]\nRun COMMAND in a fresh private instance, then stop its agents, proxy and Coord and remove its root. COMMAND receives the selected CLI on PATH and instance-scoped environment. The runtime directory contains bin/safeyolo and bin/safeyolo-proxy (or the binaries directly). It defaults to the selected installation. Guest reuse is explicit: default means HOME/.safeyolo; ROOT selects another installation. Guest bytes are pinned by SHA-256 before the command runs and checked before each guest boot. Base images use the existing read-only guest mounts and private overlays. Configuration, credentials and federation are fresh; host prerequisites and source assets are preserved. --directory selects a short, disk-backed parent (default /var/tmp). Long socket paths fail with a targeted repair. Exit status follows COMMAND. SIGINT/SIGTERM stop its process group and clean up. SIGKILL cannot run cleanup. An unverified cleanup retains the root and reports the recovery command.\nsafeyolo [--root ROOT] instance cleanup\nRetry cleanup of a retained ephemeral root after inspecting its reported ownership failure.\nsafeyolo instance asset-digest PATH\nRead a file or tree and print its SHA-256, including names, file modes and symbolic-link targets.";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    name: String,
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    instance_id: String,
    root: PathBuf,
    runtime: PathBuf,
    runner_pid: u32,
    runner_token: String,
    assets: Vec<Asset>,
}

fn manifest(root: &Path) -> PathBuf {
    root.join("data/ephemeral-instance.json")
}

fn read(root: &Path) -> Result<Instance, Error> {
    let selected: Instance = serde_json::from_slice(&fs::read(manifest(root))?)?;
    if selected.root != root.canonicalize()?
        || fs::read_to_string(root.join("data/instance_id"))?.trim() != selected.instance_id
    {
        return Err(
            "ephemeral instance identity differs from this root; files were preserved".into(),
        );
    }
    Ok(selected)
}

pub(crate) fn validate_config_path(path: &Path) -> Result<(), Error> {
    let root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    if manifest(&root).try_exists()? {
        read(&root)?;
        if path.canonicalize()?.parent() != Some(root.as_path()) {
            return Err(format!(
                "ephemeral config path escapes {}: {}; select a configuration inside this instance",
                root.display(),
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn validate_config(config: &crate::Config) -> Result<(), Error> {
    let Some(root) = config.native_config_dir.as_deref() else {
        return Ok(());
    };
    if !manifest(root).try_exists()? {
        return Ok(());
    }
    read(root)?;
    // Every writer and control endpoint of this disposable instance must stay
    // under its immutable root, including through links and parent components.
    let paths = [
        config.data_dir.as_deref(),
        config.policy_file.as_deref(),
        config.admin_api_token_file.as_deref(),
        Some(config.readiness_file.as_path()),
        config.audit_log_path.as_deref(),
        Some(config.flow_store_db_path.as_path()),
        config.circuit_state_file.as_deref(),
        config.gateway_services_dir.as_deref(),
    ];
    for path in paths
        .into_iter()
        .flatten()
        .chain(
            config
                .listeners
                .iter()
                .map(|listener| listener.socket_path.as_path()),
        )
        .chain(
            config
                .native_settings
                .iter()
                .flat_map(|settings| {
                    [
                        &settings.packet_capture.file,
                        &settings.packet_capture.secrets_token_file,
                    ]
                })
                .filter_map(Option::as_deref),
        )
    {
        if !crate::native_config::resolve_protected_directory(path)?.starts_with(root) {
            return Err(format!(
                "ephemeral instance path escapes {}: {}; choose a path inside this instance",
                root.display(),
                path.display()
            )
            .into());
        }
    }
    if config.data_dir.as_deref() != Some(root.join("data").as_path()) {
        return Err(
            "ephemeral data_dir must remain data; instance identity and Coord belong to this root"
                .into(),
        );
    }
    Ok(())
}

/// Hash link text rather than following links inside a rootfs. Never read devices.
pub fn asset_digest(path: &Path) -> Result<String, Error> {
    fn walk(path: &Path, relative: &Path, hash: &mut Context) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(path)?;
        let kind = metadata.file_type();
        let name = relative.as_os_str().as_bytes();
        hash.update(&(name.len() as u64).to_le_bytes());
        hash.update(name);
        hash.update(&(metadata.permissions().mode() & 0o177777).to_le_bytes());
        if kind.is_symlink() {
            let target = fs::read_link(path)?;
            let bytes = target.as_os_str().as_bytes();
            hash.update(&(bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        } else if kind.is_dir() {
            let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                walk(&entry.path(), &relative.join(entry.file_name()), hash)?;
            }
        } else if kind.is_file() {
            hash.update(&metadata.len().to_le_bytes());
            let mut input = fs::File::open(path)?;
            let mut buffer = [0; 64 * 1024];
            loop {
                let size = input.read(&mut buffer)?;
                if size == 0 {
                    break;
                }
                hash.update(&buffer[..size]);
            }
        } else {
            // Rootfs device nodes and FIFOs have metadata, not file contents.
            // Opening them would have effects or block a fingerprint read.
            hash.update(&metadata.rdev().to_le_bytes());
        }
        Ok(())
    }
    let mut hash = Context::new(&SHA256);
    walk(path, Path::new(""), &mut hash)?;
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn digest(_root: &Path, path: &Path) -> Result<String, Error> {
    match asset_digest(path) {
        Ok(hash) => Ok(hash),
        #[cfg(target_os = "linux")]
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            // Prepared rootfs files use delegated IDs. Reuse the existing import
            // namespace; this never acquires host root or changes asset modes.
            crate::guest_acquisition::asset_digest_in_namespace(_root, path)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn verify_guest_assets(root: &Path) -> Result<(), Error> {
    if !manifest(root).try_exists()? {
        return Ok(());
    }
    let selected = read(root)?;
    for asset in selected.assets {
        if fs::canonicalize(root.join("share").join(&asset.name))? != asset.path
            || digest(root, &asset.path)? != asset.sha256
        {
            return Err(format!("reused guest asset changed: {}; no guest was started. Select the intended source in a fresh instance run", asset.name).into());
        }
    }
    Ok(())
}

pub(crate) fn check_writable_asset(path: &Path) -> Result<(), Error> {
    let root = host_platform::config_dir();
    if !manifest(&root).try_exists()? {
        return Ok(());
    }
    let path = path.canonicalize()?;
    for asset in read(&root)?.assets {
        if path.starts_with(&asset.path) || asset.path.starts_with(&path) {
            return Err(format!("reused guest asset {} is read-only; select a different workspace or use an explicit :ro extra mount", asset.path.display()).into());
        }
    }
    Ok(())
}

pub(crate) fn check_agent_socket_paths(root: &Path, name: &str) -> Result<(), Error> {
    for path in [
        root.join("agents").join(name).join("proxy/proxy.sock"),
        root.join("data/shell-sockets").join(format!("{name}.sock")),
        root.join("data/vm-control").join(format!("{name}.sock")),
    ] {
        check_socket_path(&path, if cfg!(target_os = "macos") { 104 } else { 108 })?;
    }
    Ok(())
}

fn check_socket_path(path: &Path, capacity: usize) -> Result<(), Error> {
    if path.as_os_str().as_bytes().len() >= capacity {
        return Err(format!("Unix socket path is too long ({} bytes; maximum {}): {}. Use a shorter instance --directory or agent name", path.as_os_str().as_bytes().len(), capacity - 1, path.display()).into());
    }
    Ok(())
}

fn scoped(command: &mut Command, root: &Path) -> Result<(), Error> {
    // Preserve unrelated client, proxy and CA settings. Replace the independent
    // historical path overrides so a caller's live selection cannot leak in.
    for name in [
        "SAFEYOLO_COORD_SOCKET",
        "SAFEYOLO_COORD_TOKEN_PATH",
        "SAFEYOLO_HOST_SETUP_LOCK_FD",
        "SAFEYOLO_LOG_PATH",
        "SAFEYOLO_TMUX_SOCKET",
        "SAFEYOLO_TMUX_SESSION",
    ] {
        command.env_remove(name);
    }
    for (name, path) in [
        ("SAFEYOLO_CONFIG_DIR", root.to_owned()),
        ("SAFEYOLO_HOME", root.to_owned()),
        ("SAFEYOLO_NATIVE_CONFIG_PATH", root.join("config.toml")),
        ("SAFEYOLO_LOGS_DIR", root.join("logs")),
        ("SAFEYOLO_COORD_DATA_DIR", root.join("data/coord")),
        ("SAFEYOLO_RUNSC_ROOT", root.join("run")),
        ("SAFEYOLO_EXECUTABLE", root.join("bin/safeyolo")),
        ("SAFEYOLO_COORD_EXECUTABLE", root.join("bin/safeyolo-coord")),
        (
            "SAFEYOLO_COORD_GUEST_BINARY",
            root.join("assets/guest/safeyolo-coord"),
        ),
        ("SAFEYOLO_LAUNCHER_PRESETS", root.join("assets/launchers")),
    ] {
        command.env(name, path);
    }
    command.env("SAFEYOLO_NATS_TEST_INSTANCE", "ephemeral");
    let mut paths = vec![root.join("bin")];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    command.env("PATH", std::env::join_paths(paths)?);
    Ok(())
}

fn stage(root: &Path, runtime: &Path, reuse: Option<&Path>) -> Result<(), Error> {
    let bin = if runtime.join("bin/safeyolo").is_file() {
        runtime.join("bin")
    } else {
        runtime.to_owned()
    };
    for name in ["safeyolo", "safeyolo-proxy"] {
        if !bin.join(name).is_file() {
            return Err(format!("runtime is missing {}", bin.join(name).display()).into());
        }
    }
    std::os::unix::fs::symlink(&bin, root.join("bin"))?;
    for name in ["lib", "libexec", "assets", "package-info"] {
        let source = runtime.join(name);
        if source.try_exists()? {
            std::os::unix::fs::symlink(source.canonicalize()?, root.join(name))?;
        }
    }
    let mut init = Command::new(bin.join("safeyolo"));
    scoped(&mut init, root)?;
    let result = init.arg("--root").arg(root).arg("init").output()?;
    if !result.status.success() {
        return Err(format!(
            "temporary instance init failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    let config_path = root.join("config.toml");
    let mut config: toml_edit::DocumentMut = fs::read_to_string(&config_path)?.parse()?;
    config["admin_port"] = toml_edit::value(0);
    let mut assets = Vec::new();
    fs::create_dir(root.join("share"))?;
    if let Some(source) = reuse {
        let source = source.canonicalize()?;
        let source_config = crate::native_config::read(&source.join("config.toml"))?;
        let source_settings = source_config.native_settings.unwrap_or_default();
        config["protected_host_directories"] = toml_edit::value(
            source_settings
                .protected_host_directories
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<toml_edit::Array>(),
        );
        #[cfg(target_os = "linux")]
        if let Some(mut settings) = source_settings.linux {
            if settings.runsc_origin == "bundled" {
                settings.runsc = runtime.join("libexec/runsc").canonicalize()?;
            }
            let source_document: toml_edit::DocumentMut =
                fs::read_to_string(source.join("config.toml"))?.parse()?;
            config["linux"] = source_document["linux"].clone();
            config["linux"]["runsc"] =
                toml_edit::value(settings.runsc.to_str().ok_or("runsc path must be UTF-8")?);
            let entry = source.join("host/namespace-entry");
            if entry.is_file() {
                fs::create_dir(root.join("host"))?;
                std::os::unix::fs::symlink(entry, root.join("host/namespace-entry"))?;
            }
        }
        // Save mapping before hashing files owned by delegated sandbox IDs.
        fs::write(&config_path, config.to_string())?;
        let inputs = crate::guest_acquisition::reusable_boot_inputs(runtime, &source)?;
        let names: &[&str] = if cfg!(target_os = "macos") {
            &["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]
        } else {
            &["rootfs-tree", "cache-paths.txt"]
        };
        for name in names {
            let path = inputs.join(name).canonicalize()?;
            let sha256 = digest(root, &path)?;
            std::os::unix::fs::symlink(&path, root.join("share").join(name))?;
            assets.push(Asset {
                name: (*name).into(),
                path,
                sha256,
            });
        }
    }
    fs::write(config_path, config.to_string())?;
    let selected = Instance {
        instance_id: fs::read_to_string(root.join("data/instance_id"))?
            .trim()
            .into(),
        root: root.to_owned(),
        runtime: runtime.to_owned(),
        runner_pid: std::process::id(),
        runner_token: crate::host_lifecycle::process_token(i64::from(std::process::id()))
            .ok_or("instance runner identity is unavailable")?,
        assets,
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(manifest(root))?;
    file.write_all(&serde_json::to_vec_pretty(&selected)?)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    Ok(())
}

async fn cleanup(root: &Path, remove: bool) -> Result<(), Error> {
    let selected = read(root)?;
    if selected.runner_pid != std::process::id()
        && crate::host_lifecycle::process_token(i64::from(selected.runner_pid)).as_deref()
            == Some(&selected.runner_token)
    {
        return Err(
            "ephemeral command is still running; interrupt its runner before cleanup".into(),
        );
    }
    host_platform::in_config(root.join("config.toml"), async {
        for agent in crate::host_agents::list()? {
            let result = crate::host_lifecycle::operate("cleanup", Some(&agent.id)).await?;
            if result["runtime_state"] != "stopped"
                || result.get("error").is_some_and(|error| !error.is_null())
            {
                return Err(format!("agent {} cleanup: {result}", agent.name).into());
            }
        }
        // A stop failure must remain visible; ordinary proxy stop also reports
        // Coord diagnostics, but its CLI intentionally tolerates Coord absence.
        crate::coord_rooms::stop(root).await?;
        if let Some(record) =
            crate::guest_commands::read_state(&root.join("data/proxy-process.json"))?
        {
            let pid = record["pid"]
                .as_i64()
                .and_then(|p| i32::try_from(p).ok())
                .filter(|pid| *pid > 0)
                .ok_or("invalid proxy PID; record retained")?;
            if !crate::host_commands::proxy_live() && !process_exited(pid) {
                return Err("proxy ownership is unverified; no process was signalled".into());
            }
        }
        crate::host_commands::stop_proxy().await?;
        stop_tmux(root).await?;
        Ok::<_, Error>(())
    })
    .await?;
    read(root)?;
    if remove {
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn process_exited(pid: i32) -> bool {
    if crate::host_runs::process_is_absent(pid) {
        return true;
    }
    #[cfg(target_os = "linux")]
    return fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .is_some_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, fields)| fields.split_whitespace().next() == Some("Z"))
        });
    #[cfg(not(target_os = "linux"))]
    false
}

async fn stop_tmux(root: &Path) -> Result<(), Error> {
    use std::os::unix::fs::FileTypeExt;
    let socket = root.join("data/tmux.sock");
    let metadata = match fs::symlink_metadata(&socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() {
        return Err("tmux endpoint is not an owned socket; root retained".into());
    }
    let binary = root.join("bin/tmux");
    let result = tokio::process::Command::new(&binary)
        .arg("-S")
        .arg(&socket)
        .args(["display-message", "-p", "#{pid}"])
        .output()
        .await?;
    if !result.status.success() {
        return Err("tmux ownership could not be read; root retained".into());
    }
    let pid: i64 = String::from_utf8(result.stdout)?.trim().parse()?;
    // The packaged bin/tmux wrapper execs libexec/tmux. Loose development
    // runtimes can instead put the executable directly in bin.
    if ![root.join("libexec/tmux"), binary.clone()]
        .iter()
        .any(|executable| host_platform::process_has_path_argument(pid, executable, b"-S", &socket))
    {
        return Err("tmux ownership differs from this instance; no server was stopped".into());
    }
    let token =
        crate::host_lifecycle::process_token(pid).ok_or("tmux process identity is unavailable")?;
    let result = tokio::process::Command::new(&binary)
        .arg("-S")
        .arg(&socket)
        .arg("kill-server")
        .output()
        .await?;
    if !result.status.success() {
        return Err("owned tmux server did not accept shutdown; root retained".into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while crate::host_lifecycle::process_token(pid).as_deref() == Some(&token) {
        if tokio::time::Instant::now() >= deadline {
            return Err("owned tmux server did not stop; root retained".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

/// Keep the command leader unreaped until its process group has been stopped.
/// Even after command exit, its PID cannot be reused to select another group.
struct CommandGroup {
    child: std::process::Child,
    reaped: bool,
}

impl Drop for CommandGroup {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }
}

async fn command(
    mut command: Command,
    interrupt: &mut tokio::signal::unix::Signal,
    terminate: &mut tokio::signal::unix::Signal,
) -> Result<i32, Error> {
    use futures_util::FutureExt;
    if interrupt.recv().now_or_never().is_some() {
        return Ok(130);
    }
    if terminate.recv().now_or_never().is_some() {
        return Ok(143);
    }
    command.process_group(0);
    let mut group = CommandGroup {
        child: command.spawn()?,
        reaped: false,
    };
    let pid = i32::try_from(group.child.id())?;
    let mut interrupted = None;
    loop {
        let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                status.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                if error.raw_os_error() == Some(libc::ECHILD) {
                    group.reaped = true;
                }
                return Err(error.into());
            }
        } else if unsafe { status.assume_init().si_pid() } == pid {
            break;
        }
        tokio::select! {
            _ = interrupt.recv() => { interrupted = Some(130); break; }
            _ = terminate.recv() => { interrupted = Some(143); break; }
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
    // This unreaped Child is the authority, never a PID read from disk.
    if unsafe { libc::kill(-pid, libc::SIGTERM) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err(std::io::Error::last_os_error().into());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err(std::io::Error::last_os_error().into());
    }
    group.reaped = true;
    let status = group.child.wait()?;
    use std::os::unix::process::ExitStatusExt;
    Ok(interrupted.unwrap_or_else(|| status.code().unwrap_or(128 + status.signal().unwrap_or(1))))
}

pub async fn run(source: &Path, args: &[OsString]) -> Result<i32, Error> {
    if args == [OsStr::new("--help")] {
        println!("{HELP}");
        return Ok(0);
    }
    if let [kind, path] = args
        && kind == "asset-digest"
    {
        println!("{}", asset_digest(Path::new(path))?);
        return Ok(0);
    }
    if args == [OsStr::new("cleanup")] {
        cleanup(&source.canonicalize()?, true).await?;
        return Ok(0);
    }
    let Some((options, argv)) = args
        .iter()
        .position(|arg| arg == "--")
        .map(|split| (&args[..split], &args[split + 1..]))
    else {
        return Err(HELP.into());
    };
    if argv.is_empty() || options.first().is_none_or(|arg| arg != "run") {
        return Err(HELP.into());
    }
    let mut ephemeral = false;
    let mut runtime = source.to_owned();
    let mut reuse = None;
    let mut parent = PathBuf::from("/var/tmp");
    let mut options = options[1..].iter();
    while let Some(option) = options.next() {
        if option == "--ephemeral" {
            ephemeral = true;
            continue;
        }
        let value = options.next().ok_or("instance option requires a value")?;
        match option.to_str() {
            Some("--runtime") => runtime = value.into(),
            Some("--directory") => parent = value.into(),
            Some("--reuse-guest-assets-from") => {
                reuse = Some(if value == "default" {
                    PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unavailable")?)
                        .join(".safeyolo")
                } else {
                    value.into()
                })
            }
            _ => {
                return Err(
                    format!("unknown instance option: {}", option.to_string_lossy()).into(),
                );
            }
        }
    }
    if !ephemeral {
        return Err("instance run requires --ephemeral".into());
    }
    let runtime = runtime.canonicalize()?;
    let directory = tempfile::Builder::new().prefix("sy-").tempdir_in(&parent)?;
    let root = directory.path().canonicalize()?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    check_agent_socket_paths(&root, "test")?;
    stage(&root, &runtime, reuse.as_deref())?;
    // From publication of identity onward, cleanup errors retain evidence.
    let _retained = directory.keep();
    eprintln!("Ephemeral SafeYolo instance: {}", root.display());
    let mut selected = Command::new(&argv[0]);
    selected
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    scoped(&mut selected, &root)?;
    let outcome = command(selected, &mut interrupt, &mut terminate).await;
    if let Err(error) = cleanup(&root, outcome.is_ok()).await {
        return Err(format!("ephemeral cleanup failed: {error}; root retained at {}. Inspect its status, then retry: {} --root {} instance cleanup", root.display(), root.join("bin/safeyolo").display(), root.display()).into());
    }
    if let Err(error) = outcome {
        return Err(format!("command failed: {error}; root retained at {}. Inspect this instance, then run: {} --root {} instance cleanup", root.display(), root.join("bin/safeyolo").display(), root.display()).into());
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_socket_limit_counts_bytes_and_includes_the_terminator() {
        assert!(check_socket_path(Path::new(&"x".repeat(103)), 104).is_ok());
        assert!(
            check_socket_path(Path::new(&"x".repeat(104)), 104)
                .unwrap_err()
                .to_string()
                .contains("shorter instance --directory")
        );
        assert!(check_socket_path(Path::new(&"é".repeat(52)), 104).is_err());
    }

    #[test]
    fn asset_digest_detects_content_mode_and_link_changes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, "one").unwrap();
        let first = asset_digest(root.path()).unwrap();
        fs::write(&file, "two").unwrap();
        assert_ne!(asset_digest(root.path()).unwrap(), first);
        fs::write(&file, "one").unwrap();
        assert_eq!(asset_digest(root.path()).unwrap(), first);
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        fs::set_permissions(&file, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
        assert_ne!(asset_digest(root.path()).unwrap(), first);
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        std::os::unix::fs::symlink("file", root.path().join("link")).unwrap();
        assert_ne!(asset_digest(root.path()).unwrap(), first);
        let fifo = std::ffi::CString::new(root.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(asset_digest(root.path()).is_ok());
    }
}
