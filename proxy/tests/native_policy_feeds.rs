//! Installed CLI and live native proxy controls. The local HTTP forward proxy
//! supplies feed bytes and records sinkhole traffic; it never visits a target.

use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Origin {
    address: String,
    responses: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    held: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Origin {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let responses: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::default();
        let requests: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::new(AtomicBool::new(false));
        let worker_held = held.clone();
        let (worker_responses, worker_requests, worker_stop) =
            (responses.clone(), requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 65536 {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8_lossy(&request).to_string();
                let destination = request.split_whitespace().nth(1).unwrap_or("").to_owned();
                worker_requests.lock().unwrap().push(request);
                while worker_held.load(Ordering::Acquire) && !worker_stop.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(5));
                }
                let response = worker_responses
                    .lock()
                    .unwrap()
                    .get(&destination)
                    .cloned()
                    .unwrap_or_else(|| {
                        if destination.starts_with("http://feeds.test/") {
                            response(503, "text/plain", b"outage\n", "")
                        } else {
                            response(200, "text/plain", b"sinkhole\n", "")
                        }
                    });
                let _ = stream.write_all(&response);
            }
        });
        Self {
            address,
            responses,
            requests,
            stop,
            held,
            worker: Some(worker),
        }
    }
    fn reply(&self, endpoint: &str, bytes: Vec<u8>) {
        self.responses
            .lock()
            .unwrap()
            .insert(endpoint.into(), bytes);
    }
    fn feed(&self, body: &[u8], etag: &str) {
        self.reply(
            ENDPOINT,
            response(200, "text/plain", body, &format!("ETag: {etag}\r\n")),
        );
    }
    fn feed_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("http://feeds.test/"))
            .cloned()
            .collect()
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn response(status: u16, content_type: &str, body: &[u8], headers: &str) -> Vec<u8> {
    let mut result=format!("HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",body.len()).into_bytes();
    result.extend_from_slice(body);
    result
}
const ENDPOINT: &str = "http://feeds.test/private-test-key/list?token=synthetic-query-secret";
const FIRST: &[u8] = b"a.test\nb.test\nc.test\nd.test\n";
const SECOND: &[u8] = b"b.test\nc.test\nd.test\ne.test\n";

struct Instance {
    root: PathBuf,
    proxy: String,
}
impl Instance {
    fn new(root: &Path, origin: &Origin) -> Self {
        let instance = Self {
            root: root.to_owned(),
            proxy: origin.address.clone(),
        };
        let output = instance.cli(&["init"]);
        successful(&output);
        fs::create_dir_all(root.join("bin")).unwrap();
        symlink(env!("CARGO_BIN_EXE_safeyolo"), root.join("bin/safeyolo")).unwrap();
        symlink(
            env!("CARGO_BIN_EXE_safeyolo-proxy"),
            root.join("bin/safeyolo-proxy"),
        )
        .unwrap();
        fs::write(root.join("config.toml"),format!("admin_port=0\nflow_store_enabled=false\nparent_proxy={}\n[[listeners]]\nagent_id='alice'\nsocket_path='traffic.sock'\n",json!(origin.address))).unwrap();
        instance
    }
    fn command(&self, args: &[&str]) -> Command {
        let executable = if self.root.join("bin/safeyolo").exists() {
            self.root.join("bin/safeyolo")
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_safeyolo"))
        };
        let mut command = Command::new(executable);
        command
            .arg("--root")
            .arg(&self.root)
            .args(args)
            .env("http_proxy", &self.proxy)
            .env("https_proxy", &self.proxy)
            .env("HTTP_PROXY", &self.proxy)
            .env("HTTPS_PROXY", &self.proxy);
        command
    }
    fn cli(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
    fn json(&self, args: &[&str]) -> Value {
        let result = self.cli(args);
        successful(&result);
        serde_json::from_slice(&result.stdout).unwrap()
    }
    fn configure(&self, overrides: Value) -> Output {
        let mut config = json!({"endpoint":ENDPOINT,"format":"domains","scope":"hostname",
            "cadence_seconds":2,"max_age_seconds":20,"timeout_seconds":3,"max_bytes":256,
            "min_entries":2,"max_entries":20,"max_change_percent":60,"retry_seconds":4,
            "max_retry_seconds":8,"on_stale":"deny","on_unavailable":"deny"});
        for (key, value) in overrides.as_object().unwrap() {
            config[key] = value.clone();
        }
        let input = self.root.join("source-input.toml");
        fs::write(
            &input,
            toml::to_string(&BTreeMap::from([(
                "sources",
                BTreeMap::from([(
                    "test",
                    serde_json::from_value::<safeyolo_proxy::policy_feeds::Source>(config).unwrap(),
                )]),
            )]))
            .unwrap(),
        )
        .unwrap();
        self.cli(&["policy", "feeds", "configure", input.to_str().unwrap()])
    }
    fn source_status(&self) -> Value {
        self.json(&["policy", "feeds", "status"])["sources"]["test"].clone()
    }
    fn snapshot(&self) -> Vec<u8> {
        fs::read(self.root.join("data/policy-feeds/test/accepted.json")).unwrap()
    }
    fn request(&self, host: &str) -> u16 {
        let mut stream = UnixStream::connect(self.root.join("traffic.sock")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        String::from_utf8_lossy(&bytes)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }
    fn wait_for(&self, description: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(16);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "timed out: {description}; status={}",
                self.source_status()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn apply(&self) {
        let candidate = self.root.join("candidate.toml");
        fs::write(&candidate,"[lists]\nbad = {feed='test'}\n[hosts]\n'*' = {egress='allow',unknown_creds='allow'}\n'$bad' = {egress='deny'}\n").unwrap();
        successful(&self.cli(&["policy", "apply", candidate.to_str().unwrap()]));
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
    }
}
fn successful(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn installed_setup_refresh_retention_expiry_restart_rollback_and_recovery() {
    let origin = Origin::new();
    origin.feed(FIRST, "\"one\"");
    let temporary = tempfile::tempdir().unwrap();
    let instance = Instance::new(&temporary.path().join("i"), &origin);
    successful(&instance.configure(json!({})));
    let initial = instance.source_status();
    assert!(initial["snapshot"]["version"].is_string());
    assert_eq!(
        fs::metadata(instance.root.join("policy-feeds.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    instance.json(&["start"]);
    instance.apply();
    assert_eq!(instance.request("a.test"), 403);
    assert_eq!(instance.request("A.TEST"), 403);
    assert_eq!(instance.request("a.test."), 403);
    assert_eq!(instance.request("e.test"), 200);

    // A conditional success leaves evidence age and version untouched.
    origin.reply(
        ENDPOINT,
        response(304, "text/plain", b"", "ETag: \"one\"\r\n"),
    );
    let requests = origin.feed_requests().len();
    instance.wait_for("automatic conditional fetch", || {
        origin.feed_requests().len() > requests
    });
    assert!(
        origin
            .feed_requests()
            .last()
            .unwrap()
            .contains("If-None-Match: \"one\"")
    );
    assert_eq!(instance.source_status()["snapshot"], initial["snapshot"]);

    origin.feed(SECOND, "\"two\"");
    instance.wait_for("changed membership activated", || {
        instance.request("a.test") == 200 && instance.request("e.test") == 403
    });
    let second = instance.snapshot();
    let active = instance.json(&["policy", "show"]);
    assert_eq!(
        active["list_files"]["bad"]["active_snapshot"]["source_sha256"],
        instance.source_status()["snapshot"]["source_sha256"]
    );
    assert_eq!(active["list_files"]["bad"]["saved_matches_active"], true);

    // Rejected bytes do not change data or create repeated requests/approvals.
    origin.reply(
        ENDPOINT,
        response(200, "text/html", b"<html>sign in</html>\n", ""),
    );
    instance.wait_for("failed refresh recorded", || {
        instance.source_status()["last_failure"]
            .as_str()
            .is_some_and(|error| error.contains("content type"))
    });
    assert_eq!(instance.snapshot(), second);
    assert_eq!(instance.request("e.test"), 403);
    let failed = instance.source_status();
    let count = origin.feed_requests().len();
    instance.json(&["stop"]);
    instance.json(&["start"]);
    thread::sleep(Duration::from_millis(350));
    assert_eq!(
        origin.feed_requests().len(),
        count,
        "restart reset the retry deadline"
    );
    assert_eq!(
        instance.source_status()["next_refresh"],
        failed["next_refresh"]
    );
    assert_eq!(instance.request("e.test"), 403);

    // Rollback keeps original acquisition time and the current retry schedule.
    instance.json(&["policy", "feeds", "rollback", "test"]);
    instance.wait_for("rollback activated", || {
        instance.request("a.test") == 403 && instance.request("e.test") == 200
    });
    assert_eq!(instance.source_status()["snapshot"], initial["snapshot"]);
    assert_eq!(
        instance.source_status()["next_refresh"],
        failed["next_refresh"]
    );

    // Choose an explicit shorter usable age; old evidence must then deny all
    // governed traffic without waiting for a successful reload or an approval.
    let output = instance.configure(json!({"max_age_seconds":1}));
    assert!(!output.status.success());
    instance.wait_for("expiry denies unknown members", || {
        instance.request("ordinary.test") == 403
    });
    assert_eq!(instance.request("a.test"), 403);
    assert!(instance.source_status()["stale"].as_bool().unwrap());

    // Different accepted bytes recover automatically after the bounded retry.
    origin.feed(b"b.test\nc.test\nd.test\nf.test\n", "\"three\"");
    // Set a useful age before recovery so this test can inspect activated data.
    successful(&instance.configure(json!({"max_age_seconds":20})));
    instance.wait_for("recovery activated", || {
        instance.request("f.test") == 403 && instance.request("ordinary.test") == 200
    });
    let summary = instance.source_status();
    assert!(summary["last_failure"].is_null());
    assert_eq!(summary["consecutive_failures"], 0);
    for visible in [
        summary.to_string(),
        instance.json(&["policy", "show"]).to_string(),
        fs::read_to_string(instance.root.join("logs/proxy.log")).unwrap(),
    ] {
        assert!(!visible.contains("private-test-key"));
        assert!(!visible.contains("synthetic-query-secret"));
    }
    assert!(
        !origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.starts_with("GET http://f.test/"))
    );
    println!(
        "installed CLI: first snapshot, automatic conditional/change updates, rejection retention, persisted retry, restart, rollback, expiry, recovery and redaction passed"
    );
}

#[test]
fn installed_download_validation_and_adopted_redirect_boundaries() {
    let origin = Origin::new();
    origin.feed(FIRST, "\"one\"");
    let temporary = tempfile::tempdir().unwrap();
    let instance = Instance::new(&temporary.path().join("i"), &origin);
    for name in ["hagezi", "stevenblack"] {
        let example = instance.cli(&["policy", "feeds", "example", name]);
        successful(&example);
        let parsed: toml::Value =
            toml::from_str(std::str::from_utf8(&example.stdout).unwrap()).unwrap();
        assert!(
            parsed["sources"][name]["endpoint"]
                .as_str()
                .unwrap()
                .starts_with("https://")
        );
    }
    successful(&instance.configure(json!({})));
    let accepted = instance.snapshot();
    thread::sleep(Duration::from_secs(1));
    instance.json(&["policy", "feeds", "refresh", "test"]);
    assert_eq!(
        instance.snapshot(),
        accepted,
        "unchanged HTTP 200 renewed evidence"
    );
    origin.feed(
        b"# changed wrapper, unchanged evidence\na.test\nb.test\nc.test\nd.test\n",
        "\"wrapper\"",
    );
    instance.json(&["policy", "feeds", "refresh", "test"]);
    let wrapped: Value = serde_json::from_slice(&instance.snapshot()).unwrap();
    let original: Value = serde_json::from_slice(&accepted).unwrap();
    assert_eq!(
        wrapped["evidence_first_observed_at"],
        original["evidence_first_observed_at"]
    );
    let accepted = instance.snapshot();
    for (index, (name, reply)) in [
        (
            "HTML",
            response(200, "text/plain", b"<html>login</html>\n", ""),
        ),
        ("empty", response(200, "text/plain", b"# no entries\n", "")),
        (
            "truncated",
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\na.test\nb.test\n".to_vec(),
        ),
        ("oversize", response(200, "text/plain", &[b'x'; 257], "")),
        (
            "streaming oversize",
            [
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
                &[b'x'; 257],
            ]
            .concat(),
        ),
        (
            "churn",
            response(200, "text/plain", b"new.test\nunrelated.test\n", ""),
        ),
        (
            "URL",
            response(
                200,
                "text/plain",
                b"https://shared.test/one\nhttps://shared.test/two\n",
                "",
            ),
        ),
        (
            "redirect",
            response(
                302,
                "text/plain",
                b"",
                "Location: http://unadopted.test/private\r\n",
            ),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        origin.reply(ENDPOINT, reply);
        let output = instance.cli(&["policy", "feeds", "refresh", "test"]);
        assert!(!output.status.success(), "accepted {name}");
        assert_eq!(
            instance.snapshot(),
            accepted,
            "replaced accepted data for {name}"
        );
        let status = instance.source_status();
        assert!(status["last_failure"].is_string());
        let delay =
            status["next_refresh"].as_u64().unwrap() - status["last_attempt"].as_u64().unwrap();
        let expected = if index == 0 { 4 } else { 8 };
        assert!(
            (expected..=expected + 4).contains(&delay),
            "retry delay {delay} after {name}"
        );
    }
    assert!(
        !origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.contains("unadopted.test"))
    );
    let target = "http://feeds.test/adopted-final";
    origin.reply(
        ENDPOINT,
        response(302, "text/plain", b"", &format!("Location: {target}\r\n")),
    );
    origin.reply(
        target,
        response(200, "text/plain", SECOND, "ETag: \"two\"\r\n"),
    );
    successful(&instance.configure(json!({"redirect_endpoints":[target]})));
    assert_eq!(instance.source_status()["snapshot"]["entries"], 4);
    assert!(
        origin
            .feed_requests()
            .iter()
            .any(|request| request.contains(target))
    );
    println!(
        "installed acquisition: HTML, empty, truncation, size, churn, URL scope and redirect rejection retained accepted bytes; adopted redirect succeeded"
    );
}

#[test]
fn installed_first_start_failure_recovers_automatically_without_approvals() {
    let origin = Origin::new();
    let temporary = tempfile::tempdir().unwrap();
    let instance = Instance::new(&temporary.path().join("i"), &origin);
    assert!(!instance.configure(json!({})).status.success());
    let first = instance.source_status();
    assert!(first["snapshot"].is_null());
    assert!(first["last_failure"].as_str().unwrap().contains("503"));
    instance.json(&["start"]);
    instance.apply();
    for _ in 0..3 {
        assert_eq!(instance.request("ordinary.test"), 403);
    }
    let approvals = instance.json(&["approvals", "list", "--json"]);
    assert!(
        !approvals.to_string().contains("pending"),
        "feed failure created approvals: {approvals}"
    );
    origin.feed(FIRST, "\"first\"");
    instance.wait_for("first usable snapshot after source recovery", || {
        instance.request("a.test") == 403 && instance.request("ordinary.test") == 200
    });
    assert!(instance.source_status()["snapshot"]["version"].is_string());
    println!(
        "installed first-start outage: proxy started fail closed, no approvals, automatic first snapshot recovered enforcement"
    );
}

#[test]
fn pending_acquisition_rechecks_source_adoption_and_retains_interrupted_schedule() {
    let origin = Origin::new();
    origin.feed(FIRST, "\"one\"");
    let temporary = tempfile::tempdir().unwrap();
    let instance = Instance::new(&temporary.path().join("i"), &origin);
    let target = "http://feeds.test/adopted-final";
    successful(&instance.configure(
        json!({"redirect_endpoints":[target],"retry_seconds":15,"max_retry_seconds":30}),
    ));
    let accepted = instance.snapshot();
    origin.reply(
        ENDPOINT,
        response(302, "text/plain", b"", &format!("Location: {target}\r\n")),
    );
    origin.reply(target, response(200, "text/plain", SECOND, ""));
    origin.held.store(true, Ordering::Release);
    let count = origin.feed_requests().len();
    let mut child = instance
        .command(&["policy", "feeds", "refresh", "test"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    instance.wait_for("pending source request", || {
        origin.feed_requests().len() > count
    });
    #[cfg(target_os = "linux")]
    {
        let mut children = std::collections::BTreeSet::new();
        for task in fs::read_dir(format!("/proc/{}/task", child.id())).unwrap() {
            let path = task.unwrap().path().join("children");
            for id in fs::read_to_string(path).unwrap().split_whitespace() {
                children.insert(id.to_owned());
            }
        }
        assert!(
            !children.is_empty(),
            "pending acquisition has no transport child"
        );
        for id in children {
            let argv = fs::read(format!("/proc/{id}/cmdline")).unwrap();
            let argv = String::from_utf8_lossy(&argv);
            assert!(!argv.contains("private-test-key"));
            assert!(!argv.contains("synthetic-query-secret"));
        }
    }
    // Configure is allowed to save while the old read is pending. It cannot
    // start a competing writer or grant the removed redirect destination.
    successful(
        &instance
            .configure(json!({"redirect_endpoints":[],"retry_seconds":15,"max_retry_seconds":30})),
    );
    origin.held.store(false, Ordering::Release);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(instance.snapshot(), accepted);
    assert!(
        !origin
            .feed_requests()
            .iter()
            .any(|request| request.contains(target))
    );

    origin.feed(FIRST, "\"one\"");
    instance.json(&["policy", "feeds", "refresh", "test"]);
    let current = instance.snapshot();
    origin.held.store(true, Ordering::Release);
    let count = origin.feed_requests().len();
    child = instance
        .command(&["policy", "feeds", "refresh", "test"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    instance.wait_for("request before interruption", || {
        origin.feed_requests().len() > count
    });
    let pending = instance.source_status();
    assert_eq!(pending["attempt_pending_or_interrupted"], true);
    child.kill().unwrap();
    child.wait().unwrap();
    origin.held.store(false, Ordering::Release);
    assert_eq!(instance.snapshot(), current);
    assert_eq!(
        instance.source_status()["next_refresh"],
        pending["next_refresh"]
    );
    instance.json(&["start"]);
    thread::sleep(Duration::from_millis(350));
    assert_eq!(
        origin.feed_requests().len(),
        count + 1,
        "restart replayed an interrupted acquisition before its deadline"
    );
    println!(
        "pending acquisition: changed adoption prevented redirect/publication; interruption retained accepted bytes and the reserved retry deadline"
    );
}

#[test]
fn feed_setup_and_candidate_check_keep_the_selected_policy_directory() {
    let origin = Origin::new();
    origin.feed(FIRST, "\"one\"");
    let temporary = tempfile::tempdir().unwrap();
    let instance = Instance::new(&temporary.path().join("i"), &origin);
    let config = instance.root.join("config.toml");
    let initial = fs::read_to_string(&config).unwrap();
    fs::write(&config, "invalid config\n").unwrap();
    successful(&instance.cli(&["policy", "feeds", "--help"]));
    successful(&instance.cli(&["policy", "feeds", "example", "hagezi"]));
    let directory = instance.root.join("policy");
    fs::create_dir(&directory).unwrap();
    fs::rename(
        instance.root.join("policy.toml"),
        directory.join("current.toml"),
    )
    .unwrap();
    fs::write(
        &config,
        format!("policy_file='policy/current.toml'\n{initial}"),
    )
    .unwrap();
    successful(&instance.configure(json!({})));
    assert_eq!(
        instance.json(&["policy", "feeds", "status"])["policy_directory"],
        json!(directory)
    );
    assert!(directory.join("policy-feeds.toml").is_file());
    assert!(!instance.root.join("policy-feeds.toml").exists());
    let candidate = temporary.path().join("outside-candidate.toml");
    fs::write(temporary.path().join("local-hosts.txt"), "local.test\n").unwrap();
    fs::write(
        &candidate,
        "[lists]\nbad={feed='test'}\nlocal='local-hosts.txt'\n[hosts]\n'$bad'={egress='deny'}\n'$local'={egress='deny'}\n",
    )
    .unwrap();
    successful(&instance.cli(&["policy", "check", candidate.to_str().unwrap()]));
    println!(
        "selected context: custom policy_file owns feed configuration/snapshots and external candidate feed resolution; help stays readable with invalid runtime configuration"
    );
}
