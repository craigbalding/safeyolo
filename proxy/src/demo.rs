//! One disposable task, using the native guest, policy and operator owners.

use crate::{Error, host_agents, host_commands, host_lifecycle, host_platform, operator_commands};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Incoming};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use toml_edit::{DocumentMut, Item, value};

pub const HELP: &str = "safeyolo [--root ROOT | --config FILE] demo [--task tiny-web-app] [--workspace PATH] [--agent NAME] [--auth-file FILE] [--keep]\n\nBuild and run a tiny web app in a real guest, then approve its owned JSON request.\nThe native installation needs its prepared guest runtime and normal Codex model access.\nChoose an empty workspace, or use the disposable default. --agent reuses that stopped guest's own configured authentication; its authentication stays in that guest home.\n--auth-file selects an existing Codex auth.json to copy privately into a guest with no login. The interactive default offers your configured host login. A new guest can also use normal Codex device login. Missing authentication is reported before a model task starts.\nDemo stops its selected runtime and removes its fixture permission on exit. By default it removes the disposable workspace and any newly created guest home. --keep retains these files after stopping. A reused guest's home and prior workspace setting remain.\nThe fixture request record and normal proxy audit remain in the instance logs. Ctrl-C or cancel stops the Demo. Lab and tmux are not required.";

const CODEX_COMMAND: &[u8] = include_bytes!("../../contrib/codex-command.sh");
const GUEST_CODEX: &str = "/home/agent/.safeyolo/demo-codex-command";
const BASELINE: &str = include_str!("../../docs/AGENTS.md");
const APP_PORT: u16 = 8000;
const LIMIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Options {
    workspace: Option<PathBuf>,
    agent: Option<String>,
    auth_file: Option<PathBuf>,
    keep: bool,
    task: bool,
}
impl Options {
    fn parse(args: &[String]) -> Result<Self, Error> {
        let mut options = Self::default();
        let mut args = args.iter();
        while let Some(option) = args.next() {
            match option.as_str() {
                "--keep" => options.keep = true,
                "--workspace" => {
                    options.workspace = Some(args.next().ok_or("--workspace needs a path")?.into())
                }
                "--auth-file" => {
                    options.auth_file = Some(args.next().ok_or("--auth-file needs a path")?.into())
                }
                "--agent" => {
                    options.agent = Some(args.next().ok_or("--agent needs a name")?.clone())
                }
                "--task" if args.next().map(String::as_str) == Some("tiny-web-app") => {
                    options.task = true
                }
                _ => return Err(format!("unknown Demo option: {option}; use demo --help").into()),
            }
        }
        Ok(options)
    }
}

fn input() -> mpsc::Receiver<std::io::Result<String>> {
    let (send, receive) = mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if send.blocking_send(line).is_err() {
                break;
            }
        }
    });
    receive
}
async fn prompt(
    input: &mut mpsc::Receiver<std::io::Result<String>>,
    text: &str,
) -> Result<String, Error> {
    print!("{text}");
    std::io::stdout().flush()?;
    Ok(input
        .recv()
        .await
        .transpose()?
        .unwrap_or_else(|| "cancel".into())
        .trim()
        .to_owned())
}
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn safe(text: &str) -> String {
    crate::network_guard::sanitize(text)
}

// The endpoint runs in this command, not in an independently managed process.
// Its log contains only the owned request path and public fixture marker.
struct Fixture {
    port: u16,
    marker: String,
    path: String,
    record_path: PathBuf,
    records: Arc<Mutex<Vec<Value>>>,
    owner: JoinHandle<Result<(), Error>>,
}
impl Fixture {
    async fn start(root: &Path, marker: String) -> Result<Self, Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let path = format!("/demo/{marker}.json");
        let record_path = root
            .join("logs")
            .join(format!("demo-{marker}-requests.jsonl"));
        let mut log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&record_path)?;
        log.sync_all()?;
        let records = Arc::new(Mutex::new(Vec::new()));
        let (request_path, observed, request_marker) =
            (path.clone(), records.clone(), marker.clone());
        let owner = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted?;
                        let mut head = Vec::new();
                        let read = tokio::time::timeout(LIMIT, async {
                            while !head.ends_with(b"\r\n\r\n") && head.len() <= 8192 {
                                let mut byte = [0];
                                stream.read_exact(&mut byte).await?;
                                head.push(byte[0]);
                            }
                            Ok::<_, std::io::Error>(())
                        }).await;
                        if !matches!(read, Ok(Ok(()))) || head.len() > 8192 { continue; }
                        let expected = format!("GET {request_path} HTTP/1.1\r\n");
                        let mut payload = b"{\"error\":\"not found\"}".to_vec();
                        let mut status = "404 Not Found";
                        if head.starts_with(expected.as_bytes()) {
                            let record = json!({"method":"GET", "path":request_path, "marker":request_marker});
                            // Commit delivery evidence before returning the fixture bytes.
                            writeln!(log, "{}", serde_json::to_string(&record)?)?;
                            log.sync_all()?;
                            observed.lock().map_err(|_| "fixture record lock failed")?.push(record);
                            payload = serde_json::to_vec(&json!({"title":"Demo tasks", "items":[{"name":"Plan","minutes":5},{"name":"Build","minutes":12},{"name":"Check","minutes":3}], "marker":request_marker}))?;
                            status = "200 OK";
                        }
                        connections.spawn(async move {
                            let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len());
                            let _ = tokio::time::timeout(LIMIT, async {
                                stream.write_all(response.as_bytes()).await?;
                                stream.write_all(&payload).await?;
                                stream.shutdown().await
                            }).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            port,
            marker,
            path,
            record_path,
            records,
            owner,
        })
    }
    fn destination(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
    fn url(&self) -> String {
        format!("http://{}{}", self.destination(), self.path)
    }
    fn delivered(&self) -> Result<Vec<Value>, Error> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "fixture record lock failed")?
            .clone())
    }
    async fn stop(self) -> Result<(), Error> {
        self.owner.abort();
        match self.owner.await {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(result) => result,
        }
    }
}

/// Local operator edits share the native policy transaction and validation.
/// The ordinary proxy watcher activates them; the task waits for that activation.
fn edit_policy<T>(mutate: impl FnOnce(&mut DocumentMut) -> Result<T, Error>) -> Result<T, Error> {
    let path = crate::native_config::read(&host_platform::config_path())?
        .policy_file
        .ok_or("native policy is missing")?;
    Ok(crate::approvals::policy_transaction(
        &path,
        true,
        |source| {
            let (mut document, context) =
                crate::policy::parse_toml_for_edit(source).map_err(|error| {
                    crate::approvals::ApprovalError {
                        kind: crate::approvals::ErrorKind::Invalid,
                        message: error.to_string(),
                    }
                })?;
            let result =
                mutate(&mut document).map_err(|error| crate::approvals::ApprovalError {
                    kind: crate::approvals::ErrorKind::Invalid,
                    message: error.to_string(),
                })?;
            let source =
                crate::policy::restore_large_toml_integers(&document.to_string(), &context);
            crate::policy::Policy::native_source(
                &source,
                &path,
                None,
                crate::policy::current_time_ms(),
            )
            .map_err(|error| crate::approvals::ApprovalError {
                kind: crate::approvals::ErrorKind::Invalid,
                message: error.to_string(),
            })?;
            Ok((result, source))
        },
        |_, _| Ok(()),
    )?)
}

struct Demo {
    agent: host_agents::Agent,
    original: Option<host_agents::Agent>,
    workspace: PathBuf,
    workspace_created: bool,
    keep: bool,
    destination: Option<String>,
    proxy_record: Option<Value>,
    run_id: Option<String>,
    workspace_identity: (u64, u64),
}
impl Demo {
    async fn prepare(options: &Options) -> Result<Self, Error> {
        let root = host_platform::config_dir();
        let original = if let Some(name) = &options.agent {
            let agents = host_agents::list()?;
            let agent = agents
                .iter()
                .find(|agent| &agent.name == name)
                .ok_or("selected Demo agent is not configured")?;
            host_agents::by_id(&agents, &agent.id)?;
            if host_lifecycle::runtime(agent).await?["runtime_state"] != "stopped" {
                return Err("selected Demo guest must be stopped before changing its workspace; current work remains intact".into());
            }
            Some(agent.clone())
        } else {
            None
        };
        let workspace = options.workspace.clone().unwrap_or_else(|| {
            root.join("data")
                .join(format!("demo-{}", uuid::Uuid::new_v4().simple()))
        });
        let workspace_created = !workspace.try_exists()?;
        if workspace_created {
            fs::create_dir(&workspace)?;
        }
        let prepared = (|| {
            let workspace = crate::host_boot::workspace(&workspace, false)?;
            if fs::read_dir(&workspace)?.next().is_some() {
                return Err("Demo needs an empty workspace; existing files remain intact".into());
            }
            Ok::<_, Error>(workspace)
        })();
        let workspace = match prepared {
            Ok(path) => path,
            Err(error) => {
                if workspace_created {
                    let _ = fs::remove_dir(&workspace);
                }
                return Err(error);
            }
        };
        let name = original
            .as_ref()
            .map(|agent| agent.name.clone())
            .unwrap_or_else(|| {
                format!("demo-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
            });
        let configured = if let Some(original) = &original {
            let directory = root.join("agents").join(&name);
            let _lock = tokio::task::spawn_blocking(move || {
                host_lifecycle::SetupLock::acquire_in(&directory, None)
            })
            .await??;
            if host_lifecycle::runtime(original).await?["runtime_state"] != "stopped" {
                Err("selected guest started during Demo setup; current work remains intact".into())
            } else {
                edit_policy(|document| {
                    let current = &mut document["agents"][&name];
                    if current["agent_id"].as_str() != Some(&original.id)
                        || current["folder"].as_str() != original.folder.as_deref()
                    {
                        return Err("selected guest configuration changed during Demo setup".into());
                    }
                    current["folder"] = value(workspace.to_string_lossy().as_ref());
                    let mut selected = original.clone();
                    selected.folder = Some(workspace.to_string_lossy().into_owned());
                    Ok(selected)
                })
            }
        } else {
            host_agents::configure(
                &name,
                &[("folder".into(), workspace.to_string_lossy().into_owned())],
                true,
                None,
            )
            .await
        };
        let agent = match configured {
            Ok(agent) => agent,
            Err(error) => {
                if workspace_created {
                    let _ = fs::remove_dir(&workspace);
                }
                return Err(error);
            }
        };
        let metadata = workspace.metadata()?;
        Ok(Self {
            agent,
            original,
            workspace,
            workspace_created,
            keep: options.keep,
            destination: None,
            proxy_record: None,
            run_id: None,
            workspace_identity: (metadata.dev(), metadata.ino()),
        })
    }
    async fn boot(&mut self) -> Result<(), Error> {
        self.proxy_record = host_commands::start_proxy().await?;
        let directory = host_platform::config_dir()
            .join("agents")
            .join(&self.agent.name);
        let lock = tokio::task::spawn_blocking(move || {
            host_lifecycle::SetupLock::acquire_in(&directory, None)
        })
        .await??;
        if host_lifecycle::runtime(&self.agent).await?["runtime_state"] != "stopped" {
            return Err(
                "selected guest started before Demo boot; its current work was preserved".into(),
            );
        }
        let home = host_platform::config_dir()
            .join("agents")
            .join(&self.agent.name)
            .join("home");
        stage_codex(&home)?;
        let observed =
            host_lifecycle::start(&self.agent, "sandbox-start", Some(lock), None, false).await?;
        self.run_id = observed["run_id"].as_str().map(str::to_owned);
        if observed["runtime_state"] != "running" || observed["exec"] != true {
            return Err(format!(
                "Demo runtime did not become ready: {}",
                safe(&observed.to_string())
            )
            .into());
        }
        println!(
            "Demo guest: {} ({})\nWorkspace: {}\nRuntime: ready",
            self.agent.name,
            self.agent.id,
            safe(&self.workspace.to_string_lossy())
        );
        Ok(())
    }
    async fn provision_auth(&self, source: &Path) -> Result<(), Error> {
        let directory = host_platform::config_dir()
            .join("agents")
            .join(&self.agent.name);
        let lock_directory = directory.clone();
        let _lock = tokio::task::spawn_blocking(move || {
            host_lifecycle::SetupLock::acquire_in(&lock_directory, None)
        })
        .await??;
        if host_lifecycle::runtime(&self.agent).await?["runtime_state"] != "stopped" {
            return Err("stop the selected guest before supplying its Demo login".into());
        }
        let home = directory.join("home");
        private_directory(&home)?;
        let codex = home.join(".codex");
        private_directory(&codex)?;
        let destination = codex.join("auth.json");
        if fs::symlink_metadata(&destination).is_ok() {
            return Err("selected guest already has Codex authentication; use its existing login without --auth-file".into());
        }
        // The source is an explicit operator input. Read through a checked
        // handle; never follow a guest-controlled destination or log its bytes.
        let source = source.canonicalize()?;
        let mut input = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(source)?;
        if !input.metadata()?.is_file() {
            return Err("Codex authentication input must be a regular file".into());
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&codex)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        std::io::copy(&mut input, &mut temporary)?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(&destination)?;
        crate::coord_setup::codex_state(&home, None, false, Some("adopt"))?;
        println!(
            "Existing Codex login staged privately in the Demo guest. Login status is checked before the task."
        );
        Ok(())
    }
    async fn fixture_permission(&mut self, fixture: &Fixture) -> Result<(), Error> {
        let destination = fixture.destination();
        edit_policy(|document| {
            if document["agents"][&self.agent.name]["agent_id"].as_str() != Some(&self.agent.id) {
                return Err("Demo agent identity changed".into());
            }
            if document["agents"][&self.agent.name]
                .get("hosts")
                .and_then(|hosts| hosts.get(&destination))
                .is_some()
            {
                return Err(
                    "fixture destination already has an operator policy; no rule was replaced"
                        .into(),
                );
            }
            document["agents"][&self.agent.name]["hosts"][&destination] =
                value(toml_edit::InlineTable::from_iter([("egress", "prompt")]));
            Ok(())
        })?;
        self.destination = Some(destination.clone());
        let deadline = tokio::time::Instant::now() + LIMIT;
        loop {
            let active = crate::native_client::admin(
                &host_platform::config_path(),
                "/admin/policy/baseline",
                hyper::Method::GET,
                Value::Null,
                LIMIT,
            )
            .await?;
            if active["effective"]["agents"][&self.agent.name]["hosts"][&destination]["egress"]
                == "prompt"
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("Demo fixture approval rule was not confirmed active".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn cleanup(&self) -> Result<(), Error> {
        // Native stop verifies process incarnation and backend ownership before
        // any deletion. A stop failure preserves the files for diagnosis.
        let directory = host_platform::config_dir()
            .join("agents")
            .join(&self.agent.name);
        let lock_directory = directory.clone();
        let lock = tokio::task::spawn_blocking(move || {
            host_lifecycle::SetupLock::acquire_in(&lock_directory, None)
        })
        .await??;
        let current = host_lifecycle::runtime(&self.agent).await?;
        if current["runtime_state"] != "stopped"
            && (self.run_id.is_none() || current["run_id"].as_str() != self.run_id.as_deref())
        {
            return Err(
                "selected guest runtime changed; its process and files were preserved".into(),
            );
        }
        host_lifecycle::stop(&self.agent, Some(lock)).await?;
        let lock = tokio::task::spawn_blocking(move || {
            host_lifecycle::SetupLock::acquire_in(&directory, None)
        })
        .await??;
        if crate::host_runs::observe(&self.agent.name).await["runtime_state"] != "stopped" {
            return Err("Demo guest stop is unverified; files were preserved".into());
        }
        let metadata = fs::symlink_metadata(&self.workspace)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != self.workspace_identity {
            return Err("Demo workspace was replaced; its files were preserved".into());
        }
        edit_policy(|document| {
            let agents = document["agents"]
                .as_table_like_mut()
                .ok_or("agents are unavailable")?;
            let current = agents
                .get_mut(&self.agent.name)
                .ok_or("Demo agent configuration was removed")?;
            if current["agent_id"].as_str() != Some(&self.agent.id) {
                return Err("Demo identity changed; configuration was preserved".into());
            }
            if let Some(destination) = &self.destination
                && let Some(hosts) = current.get_mut("hosts").and_then(Item::as_table_like_mut)
            {
                hosts.remove(destination);
            }
            if let Some(original) = &self.original {
                if current["folder"].as_str() != Some(self.workspace.to_string_lossy().as_ref()) {
                    return Err("Demo workspace configuration changed; files were preserved".into());
                }
                current["folder"] = original.folder.as_deref().map(value).unwrap_or(Item::None);
            } else if !self.keep {
                agents.remove(&self.agent.name);
            }
            Ok(())
        })?;
        if !self.keep {
            if self.original.is_none() {
                fs::remove_dir_all(
                    host_platform::config_dir()
                        .join("agents")
                        .join(&self.agent.name),
                )?;
            }
            if self.workspace_created {
                fs::remove_dir_all(&self.workspace)?;
            } else {
                for entry in fs::read_dir(&self.workspace)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        fs::remove_dir_all(entry.path())?;
                    } else {
                        fs::remove_file(entry.path())?;
                    }
                }
            }
        }
        drop(lock);
        if let Some(record) = &self.proxy_record {
            let mut another_runtime = false;
            for agent in host_agents::list()? {
                if host_lifecycle::runtime(&agent).await?["runtime_state"] != "stopped" {
                    another_runtime = true;
                }
            }
            if !another_runtime
                && crate::guest_commands::read_state(
                    &host_platform::config_dir().join("data/proxy-process.json"),
                )?
                .as_ref()
                    == Some(record)
            {
                host_commands::stop_proxy().await?;
            }
        }
        println!(
            "Demo cleanup: guest stopped; fixture permission removed; files {}.",
            if self.keep { "retained" } else { "removed" }
        );
        if self.keep {
            println!(
                "Retained workspace: {}\nRetained guest: {}",
                safe(&self.workspace.to_string_lossy()),
                self.agent.name
            );
        }
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<(), Error> {
    if !crate::coord_setup::safe(path, true, None)? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn stage_codex(home: &Path) -> Result<(), Error> {
    private_directory(home)?;
    let managed = home.join(".safeyolo");
    private_directory(&managed)?;
    let path = managed.join("demo-codex-command");
    crate::coord_setup::safe(&path, false, None)?;
    crate::coord_supervisor::atomic_write(&path, CODEX_COMMAND, 0o700)?;
    Ok(())
}

struct DemoCommand(tokio::process::Child);
impl Drop for DemoCommand {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}
async fn guest_status(agent: &str, command: &str) -> Result<bool, Error> {
    let command = format!(
        "export CODEX_HOME=/home/agent/.codex; export PATH=/home/agent/.local/bin:/home/agent/.mise/shims:\"$PATH\"; (\n{command}\n) < /dev/null"
    );
    let mut child = DemoCommand(host_platform::spawn_guest_command(agent, &command, false).await?);
    Ok(child.0.wait().await?.success())
}

fn codex_auth(home: &Path) -> Result<bool, Error> {
    let directory = home.join(".codex");
    let info = match fs::symlink_metadata(&directory) {
        Ok(info) => info,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o022 != 0 {
        return Err(
            "selected guest's Codex home has unsafe metadata; authentication was left intact"
                .into(),
        );
    }
    let auth = directory.join("auth.json");
    let present = match fs::symlink_metadata(&auth) {
        Ok(info) => {
            if !info.is_file()
                || info.uid() != unsafe { libc::geteuid() }
                || info.nlink() != 1
                || info.mode() & 0o777 != 0o600
            {
                return Err("selected guest's Codex auth metadata is unsafe; credential content was not read".into());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let marker = crate::guest_commands::read_state(&directory.join(".safeyolo-provenance.json"))?;
    if marker
        .as_ref()
        .is_some_and(|marker| marker["schema"] != "safeyolo.codex-provenance/v1")
    {
        return Err(
            "selected guest's Codex provenance is invalid; authentication was left intact".into(),
        );
    }
    match marker.as_ref().and_then(|marker| marker.get("state")).and_then(Value::as_str) {
        Some("agent-local") if present => Ok(true),
        Some("external-provider") if !present => Ok(true),
        _ if present => Err("Codex authentication has not been explicitly adopted for this guest; keep the guest and complete its normal authentication recovery".into()),
        _ => Ok(false),
    }
}

fn task(fixture: &Fixture) -> String {
    format!(
        "Build and run a tiny Python standard-library web application in /workspace/app.py. It must fetch JSON from {} using HTTP_PROXY (keep the proxy configured; remove NO_PROXY exclusions for that fixture fetch). Input has a title, items with minutes, and a marker. Serve JSON at http://127.0.0.1:{APP_PORT}/ with keys title, count, total_minutes and marker calculated from that input. Do not hard-code the fixture data or marker into the response. Start the app in this guest and keep its process running. Initially SafeYolo returns HTTP 428 for the fixture request. Show the actual response, then retry the same request while the human operator decides through the normal host approval path. Never change policy or approve your own request. The app may return 503 until the JSON is available. Continue after approval, independently fetch your app's response, and report the actual result. Use a bounded retry (up to ten minutes) and stop if the operator rejects or cancels. Do not claim success from narration, create a fake model/fixture, or start another model. Leave the app running for the host's independent read. The host owns cleanup. No API key, Lab, tmux, public preview or password manager is needed.",
        fixture.url()
    )
}

async fn app_response(agent: &str) -> Result<Value, Error> {
    tokio::time::timeout(LIMIT, async {
        let stream = host_platform::open_guest_port(agent, APP_PORT).await?;
        let (mut client, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let response = async move {
            let response = client
                .send_request(
                    Request::builder()
                        .uri("/")
                        .header("host", "localhost")
                        .header("connection", "close")
                        .body(Full::new(Bytes::new()))?,
                )
                .await?;
            if !response.status().is_success() {
                return Err("app response is not yet successful".into());
            }
            let mut body: Incoming = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame?.into_data() {
                    if bytes.len() + data.len() > 65536 {
                        return Err("app response exceeds 64 KiB".into());
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            Ok::<Value, Error>(serde_json::from_slice(&bytes)?)
        };
        // Drive the connection in this future so cancellation and timeout also
        // drop its guest transport, without leaving a spawned driver behind.
        let (_, app) = tokio::try_join!(
            async { connection.await.map_err(|error| -> Error { error.into() }) },
            response
        )?;
        Ok::<Value, Error>(app)
    })
    .await?
}
fn app_matches(app: &Value, fixture: &Fixture) -> bool {
    app["title"] == "Demo tasks"
        && app["count"] == 3
        && app["total_minutes"] == 20
        && app["marker"] == fixture.marker
}
fn app_code(workspace: &Path) -> Result<(), Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(workspace.join("app.py"))?;
    if !file.metadata()?.is_file() {
        return Err("app.py is not a regular source file".into());
    }
    let mut code = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut code)?;
    if code.is_empty() || code.len() > 128 * 1024 {
        return Err("app.py source is empty or exceeds the diagnostic limit".into());
    }
    Ok(())
}

async fn session(
    demo: &Demo,
    fixture: &Fixture,
    input: &mut mpsc::Receiver<std::io::Result<String>>,
) -> Result<(), Error> {
    let name = &demo.agent.name;
    if prompt(
        input,
        "Runtime is ready. Enter to build the tiny app, or cancel: ",
    )
    .await?
        == "cancel"
    {
        return Err("Demo cancelled after runtime creation".into());
    }
    if !guest_status(name, &format!("{GUEST_CODEX} --version")).await? {
        return Err("Codex setup failed after runtime creation; no model task started".into());
    }
    let home = host_platform::config_dir()
        .join("agents")
        .join(name)
        .join("home");
    if !codex_auth(&home)? {
        if prompt(input, "This guest needs its own Codex authentication. Type login for normal device sign-in, or cancel: ").await? != "login" {
            return Err(format!("Codex authentication is missing for {name}; the operator must supply this guest's normal login or select its already authenticated guest with --agent").into());
        }
        if !guest_status(
            name,
            "codex -c 'cli_auth_credentials_store=\"file\"' login --device-auth",
        )
        .await?
        {
            return Err("Codex device login failed; no model task started".into());
        }
        // Adoption runs inside the guest. A guest-created path cannot redirect
        // a host write outside the operator's explicit mounts.
        if !guest_status(name, "set -e; { test -d /home/agent/.codex && test ! -L /home/agent/.codex && test -f /home/agent/.codex/auth.json && test ! -L /home/agent/.codex/auth.json; } || exit 1; umask 077; demo_auth_marker=$(mktemp /home/agent/.codex/.provenance.XXXXXX) || exit; printf '%s\\n' '{\"schema\":\"safeyolo.codex-provenance/v1\",\"state\":\"agent-local\"}' > \"$demo_auth_marker\"; mv -- \"$demo_auth_marker\" /home/agent/.codex/.safeyolo-provenance.json").await? || !codex_auth(&home)? {
            return Err(
                "Codex guest-local authentication adoption failed; no model task started".into(),
            );
        }
    }
    if !guest_status(name, "codex login status").await? {
        return Err("the selected guest's actual Codex authentication is unavailable; no model task started".into());
    }
    // Bind the ordinary sandbox instructions for this invocation. A selected
    // guest's retained baseline and role configuration are never replaced.
    let developer = format!(
        "developer_instructions={}",
        toml_edit::Value::from(BASELINE)
    );
    let command = format!(
        "exec /safeyolo/safeyolo-guest observe exec -- {GUEST_CODEX} exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --color never -C /workspace -c {} {} < /dev/null",
        quote(&developer),
        quote(&task(fixture))
    );
    println!(
        "Task: build a tiny app from the owned JSON fixture.\nInput: {}\nExpected app: title=Demo tasks, count=3, total_minutes=20, marker={}\nFixture request record: {}",
        fixture.url(),
        fixture.marker,
        safe(&fixture.record_path.to_string_lossy())
    );
    let mut codex = DemoCommand(host_platform::spawn_guest_command(name, &command, false).await?);
    let mut exit = None;
    let mut approval_id = None::<String>;
    let mut approved = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        if exit.is_none() {
            exit = codex.0.try_wait()?;
        }
        if exit.is_some_and(|status| !status.success()) {
            return Err(
                format!("Codex harness failed after setup (exit {})", exit.unwrap()).into(),
            );
        }
        if fixture.owner.is_finished() {
            return Err("owned fixture server stopped; delivery is unverified".into());
        }
        let records = fixture.delivered()?;
        if !approved && !records.is_empty() {
            // The same normal resolver may have been used from another host
            // terminal while this command displayed evidence.
            if let Some(id) = &approval_id {
                approved =
                    operator_commands::approval(&host_platform::config_dir(), id, Some(name))
                        .await?["status"]
                        == "approved";
            }
            if !approved {
                return Err(
                    "fixture delivery has no confirmed operator approval; Demo failed".into(),
                );
            }
        }
        if approval_id.is_none() {
            let pending =
                operator_commands::pending(&host_platform::config_dir(), Some(name)).await?;
            if let Some(approval) = pending["approvals"]
                .as_array()
                .ok_or("pending approvals are unavailable")?
                .iter()
                .find(|entry| entry["target"] == fixture.destination())
            {
                let id = approval["request_id"]
                    .as_str()
                    .ok_or("pending request ID is unavailable")?
                    .to_owned();
                let view =
                    operator_commands::approval(&host_platform::config_dir(), &id, Some(name))
                        .await?;
                if view["action"]["host"] != "127.0.0.1" || view["action"]["port"] != fixture.port {
                    return Err("approval action does not match the owned fixture".into());
                }
                println!(
                    "Observation: SafeYolo requires approval; the fixture has received zero requests.\n{}\nDemo removes this fixture permission during cleanup.",
                    serde_json::to_string_pretty(&view)?
                );
                match operator_commands::flow(&host_platform::config_dir(), &id, Some(name)).await {
                    Ok(flow) if flow["status"].as_u64().is_some() => println!(
                        "Observation: native traffic request {} returned HTTP {}.",
                        safe(&id),
                        flow["status"]
                    ),
                    Ok(_) => println!(
                        "The saved traffic response is not available yet; the canonical approval is pending."
                    ),
                    Err(error) => println!(
                        "Traffic detail is unavailable: {}. The canonical approval remains pending.",
                        safe(&error.to_string())
                    ),
                }
                approval_id = Some(id);
            }
        }
        if let Some(id) = &approval_id
            && !approved
        {
            match prompt(input, "Type approve, reject, evidence, or cancel: ")
                .await?
                .as_str()
            {
                "approve" => {
                    let view = operator_commands::resolve(
                        &host_platform::config_dir(),
                        id,
                        "approve",
                        Some(name),
                    )
                    .await?;
                    if view["status"] != "approved" {
                        return Err(
                            "operator approval was not confirmed; read its canonical state".into(),
                        );
                    }
                    approved = true;
                    println!(
                        "Permission effect: this Demo agent can reuse access to {} until cleanup removes its fixture permission.",
                        fixture.destination()
                    );
                    println!(
                        "Observation: normal operator approval confirmed. Waiting for the real app and fixture delivery."
                    );
                }
                "reject" => {
                    operator_commands::resolve(
                        &host_platform::config_dir(),
                        id,
                        "reject",
                        Some(name),
                    )
                    .await?;
                    return Err("Demo fixture request rejected by the operator".into());
                }
                "evidence" => {
                    operator_commands::run(
                        &host_platform::config_path(),
                        &[
                            "traffic".into(),
                            "list".into(),
                            "--agent".into(),
                            name.clone(),
                            "--filter".into(),
                            "~c 428".into(),
                            "--json".into(),
                        ],
                    )
                    .await?;
                }
                "cancel" => return Err("Demo cancelled".into()),
                _ => println!("Enter an explicit decision or open evidence."),
            }
        }
        if approved
            && !fixture.delivered()?.is_empty()
            && let Ok(app) = app_response(name).await
            && app_matches(&app, fixture)
        {
            app_code(&demo.workspace)?;
            println!(
                "Observation: independently read the running guest app: {}\nObservation: owned fixture delivery: {}\nInterpretation: the app's real JSON request continued after normal approval.",
                serde_json::to_string(&app)?,
                serde_json::to_string(&fixture.delivered()?)?
            );
            // Observe the model command's actual outcome as supporting evidence.
            // The app response and origin delivery establish the useful result.
            if let Some(status) = exit {
                println!("Codex command exit: {status}");
            }
            if prompt(input, "Result is ready. Enter to finish, or cancel: ").await? == "cancel" {
                return Err("Demo cancelled after the app result".into());
            }
            return Ok(());
        }
        if exit.is_some() && approval_id.is_none() {
            return Err("Codex ended without an authoritative fixture approval request; app outcome is unverified".into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Demo did not produce the approved app response within ten minutes".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn run(config: &Path, args: &[String]) -> Result<(), Error> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let mut options = Options::parse(args)?;
    let config = config
        .canonicalize()
        .map_err(|error| format!("Demo needs an installed native instance: {error}"))?;
    host_platform::in_config(config, async {
        let mut input = input();
        println!("Build a tiny web app that summarizes JSON from an owned service.");
        if !options.task && !matches!(prompt(&mut input, "Choose 1 for the tiny web-app task, or cancel [1]: ").await?.as_str(), "" | "1" | "tiny-web-app") { return Err("Demo cancelled before setup".into()); }
        println!("Cleanup: stop the Demo guest and remove its fixture permission; {} disposable files. Reused guest authentication and prior workspace settings remain.", if options.keep {"retain"} else {"remove"});
        if !options.task && options.agent.is_none() && options.auth_file.is_none() {
            let codex_home = std::env::var_os("CODEX_HOME").map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|path| PathBuf::from(path).join(".codex")));
            if let Some(auth) = codex_home.map(|path| path.join("auth.json"))
                && auth.try_exists()?
                && prompt(&mut input, "Reuse this host's configured Codex login in the disposable Demo guest? [y/N] ").await? == "y"
            {
                options.auth_file = Some(auth);
            }
        }
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut demo = Demo::prepare(&options).await?;
        // Finish native boot ownership publication before handling cancellation.
        let mut result;
        let mut fixture = None;
        match Fixture::start(&host_platform::config_dir(), uuid::Uuid::new_v4().simple().to_string()).await {
            Ok(owned) => {
                result = (|| {
                    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(demo.workspace.join("TASK.md"))?;
                    file.write_all(task(&owned).as_bytes())?;
                    Ok::<_, Error>(())
                })();
                fixture = Some(owned);
            }
            Err(error) => result = Err(error),
        }
        if result.is_ok() && let Some(auth) = &options.auth_file {
            result = demo.provision_auth(auth).await;
        }
        if result.is_ok() { result = demo.boot().await; }
        if result.is_ok() {
            result = demo.fixture_permission(fixture.as_ref().ok_or("Demo fixture is unavailable")?).await;
        }
        if result.is_ok() {
            result = tokio::select! {
                result = session(&demo, fixture.as_ref().ok_or("Demo fixture is unavailable")?, &mut input) => result,
                _ = interrupt.recv() => Err("Demo cancelled by Ctrl-C".into()),
                _ = terminate.recv() => Err("Demo cancelled by termination".into()),
            };
        }
        if let Err(error) = &result { eprintln!("Demo outcome: {}", safe(&error.to_string())); }
        let stopped = if let Some(fixture) = fixture { fixture.stop().await } else { Ok(()) };
        let cleanup = demo.cleanup().await;
        if let Err(error) = cleanup { return Err(format!("Demo cleanup is incomplete: {}; retained guest={}, workspace={}", safe(&error.to_string()), demo.agent.name, safe(&demo.workspace.to_string_lossy())).into()); }
        stopped?;
        result
    }).await
}

#[cfg(test)]
mod tests;
