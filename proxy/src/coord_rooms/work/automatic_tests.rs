//! Real proxy/service and native Work boundaries; fixtures own every effect.
use super::*;
use crate::policy::checks;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::Notify,
};

const ALICE: &str = "ag-alice";
const BOB: &str = "ag-bob";

struct Provider {
    port: u16,
    calls: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
    mode: Arc<AtomicUsize>,
    reached: Arc<Notify>,
    release: Arc<Notify>,
    requests: Arc<std::sync::Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let effects = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(AtomicUsize::new(0));
        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let requests = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let (c, e, m, n, r) = (
            calls.clone(),
            effects.clone(),
            mode.clone(),
            reached.clone(),
            release.clone(),
        );
        let observed = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (c, e, m, n, r) = (c.clone(), e.clone(), m.clone(), n.clone(), r.clone());
                let observed = observed.clone();
                tokio::spawn(async move {
                    let mut head = vec![];
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(socket.read_u8().await.unwrap());
                    }
                    let head = String::from_utf8(head).unwrap();
                    let path = head.split_whitespace().nth(1).unwrap();
                    let length: usize = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .unwrap_or_else(|| "0".into())
                        .parse()
                        .unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap();
                    c.fetch_add(1, Ordering::SeqCst);
                    let action = path == "/notify" || path == "/reserve";
                    {
                        let mut requests = observed.lock().unwrap();
                        let duplicate = path == "/reserve"
                            && requests
                                .iter()
                                .any(|v| v["input"]["invocation_id"] == input["invocation_id"]);
                        if action && !duplicate {
                            e.fetch_add(1, Ordering::SeqCst);
                        }
                        requests.push(json!({"path":path,"input":input}));
                    }
                    let mode = m.load(Ordering::SeqCst);
                    if mode == 4 || action && mode == 5 {
                        n.notify_one();
                        r.notified().await;
                    }
                    if action && mode == 3 {
                        return;
                    } // Effect happened; reply is lost.
                    let positive = mode != 1
                        && if path == "/author" {
                            input["subject"]["value"] == "1"
                        } else if path == "/verify" {
                            let artifact: Value =
                                serde_json::from_str(input["subject"]["value"].as_str().unwrap())
                                    .unwrap();
                            STANDARD
                                .decode(artifact["artifact_base64"].as_str().unwrap())
                                .unwrap()
                                == b"wanted"
                        } else {
                            true
                        };
                    let body = if action {
                        "action completed".to_owned()
                    } else if mode == 2 {
                        "malformed".into()
                    } else if mode == 6 {
                        json!({"finding":{"kind":"failure","reason":"controlled provider failure"}})
                            .to_string()
                    } else {
                        json!({"finding":{"kind":"finding","positive":positive},"source_revision":"controlled-snapshot"}).to_string()
                    };
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                });
            }
        });
        Self {
            port,
            calls,
            effects,
            mode,
            reached,
            release,
            requests,
            task,
        }
    }
}

fn definition(port: u16, action: bool) -> Value {
    json!({"source_id":"owned-fixture","meaning":"controlled predicate, or explicit authorized notification action",
        "subject":"value","result_type":"finding","influences":["hard_exclusion"],
        "implementation_version":"fixture-1","configuration_version":"adopted-1","max_age_seconds":60,
        "inputs":{"repository":"owner/repo","expected_author_id":"42"},
        "source":{"kind":"service","operation":{"gate_id":"bound","service":"fixture","capability":"invoke",
            "endpoint":format!("http://127.0.0.1:{port}"),"method":"POST","path":"/author",
            "effects":if action {"active"}else{"passive"},"mapping":"typed"},
            "limits":{"timeout_ms":5000,"max_input_bytes":32768,"max_output_bytes":32768,
                "max_concurrent":1,"max_pending":1,"max_cached":0}}})
}
fn binding(name: &str, boundary: &str, input: &str) -> Value {
    let mut v = json!({"name":name,"room":"owned","factory":"native","boundary":boundary,"job":name,"input":input,
        "on_failure":"hold","require":{"op":"finding","check":name}});
    if boundary == "admit_issue" {
        v["repository"] = json!("owner/repo");
    }
    if boundary == "after_complete" {
        v.as_object_mut().unwrap().remove("require");
        v["on_failure"] = json!("report");
        v["retry"] = json!("never");
    }
    v
}
fn definitions(port: u16) -> Value {
    let mut verify = definition(port, false);
    verify["source"]["operation"]["path"] = json!("/verify");
    let mut notify = definition(port, true);
    notify["source"]["operation"]["path"] = json!("/notify");
    json!({"checks":{"author":definition(port,false),"verify":verify,"notify":notify},"check_rules":[],
        "work_bindings":[binding("author","admit_issue","github_issue"),binding("verify","verify_output","published_artifact"),binding("notify","after_complete","completed_work")]})
}
async fn fixture_proxy(provider: &Provider) -> (tempfile::TempDir, crate::Proxy, Value) {
    let (root, conn, reference) = super::factory_tests::approved().await;
    for (old, new) in [("alice", ALICE), ("bob", BOB)] {
        conn.execute(
            "UPDATE memberships SET principal_id=?1 WHERE principal_id=?2",
            params![new, old],
        )
        .unwrap();
    }
    conn.execute(
        "UPDATE instance SET id=?1",
        ["sy-dddddddddddddddddddddddddddddddd"],
    )
    .unwrap();
    drop(conn);
    fs::write(
        root.path().join("data/instance_id"),
        "sy-dddddddddddddddddddddddddddddddd",
    )
    .unwrap();
    fs::write(
        root.path().join("data/coord/instance_id"),
        "sy-dddddddddddddddddddddddddddddddd",
    )
    .unwrap();
    for directory in ["logs", "services", "builtin-services"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    fs::write(
        root.path().join("data/admin_token"),
        "synthetic-work-admin-token",
    )
    .unwrap();
    fs::write(
        root.path().join("data/agent_token"),
        "synthetic-work-agent-token",
    )
    .unwrap();
    let checks: checks::Checks = serde_json::from_value(definitions(provider.port)).unwrap();
    fs::write(root.path().join("policy.toml"), format!("{}\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[hosts.'127.0.0.1']\negress='allow'\nservice='fixture'\n[agents.'gate:bound'.services.fixture]\ncapability='invoke'\n[controls.credentials]\nenabled=false\n[controls.patterns]\nenabled=false\n[controls.network]\nhomoglyph=false\n",toml::to_string(&checks).unwrap())).unwrap();
    fs::write(root.path().join("services/fixture.yaml"), "schema_version: 1\nname: fixture\ndefault_host: 127.0.0.1\ncapabilities:\n  invoke:\n    routes:\n      - methods: [POST]\n        path: /**\n").unwrap();
    fs::write(root.path().join("config.toml"), format!("data_dir={:?}\nadmin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n",root.path().join("data"))).unwrap();
    let config = crate::native_config::read(&root.path().join("config.toml")).unwrap();
    let proxy = crate::Proxy::start(config).await.unwrap();
    (root, proxy, reference)
}
fn current_value(root: &Path, id: &str) -> Value {
    read(
        &mut super::super::super::open(root).unwrap(),
        "owned",
        Actor::Operator,
        id,
    )
    .unwrap()
}
fn input(work: &Value, action: &str) -> Value {
    json!({"action":action,"work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"]})
}
async fn submit(
    proxy: &crate::Proxy,
    root: &Path,
    actor: Actor<'_>,
    value: Value,
    op: &str,
) -> Result<Value, WorkError> {
    automatic::mutate(
        &proxy.runtime,
        root,
        "owned",
        actor,
        serde_json::from_value(value).unwrap(),
        Some(op),
        None,
    )
    .await
}
fn publication(work: &Value, bytes: &[u8]) -> Value {
    let mut value = input(work, "publish_output");
    value["target_ref"] = json!(format!("sha256:{}", checks::content_digest(bytes)));
    value["artifact_base64"] = json!(STANDARD.encode(bytes));
    value["expected_target_generation"] = work["target_generation"].clone();
    value["execution_outcome"] = json!("succeeded");
    value["summary"] = json!("Retained exact bytes");
    value
}
fn approval(work: &Value) -> Value {
    let mut value = input(work, "decide_acceptance");
    value["expected_target_generation"] = work["target_generation"].clone();
    value["expected_requirements_version"] = work["acceptance_requirements"]["version"].clone();
    value["verdict"] = json!("approve");
    value["summary"] = json!("Independent review of exact output");
    value
}
async fn api(root: &Path, value: &Value) -> (u16, Value) {
    post(
        root,
        "http://_safeyolo.proxy.internal/api/coord/rooms/owned/work",
        "synthetic-work-agent-token",
        &value.to_string(),
    )
    .await
}
async fn post(root: &Path, uri: &str, token: &str, bytes: &str) -> (u16, Value) {
    let mut socket = UnixStream::connect(root.join("alice.sock")).await.unwrap();
    let host: hyper::Uri = uri.parse().unwrap();
    socket.write_all(format!("POST {uri} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bytes}",host.authority().unwrap(),bytes.len()).as_bytes()).await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        socket.read_to_string(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    let (head, body) = reply.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_str(body).unwrap_or_else(|_| json!(body)),
    )
}

/// Use the real job supervisor with a pinned shell helper. No VM is involved.
/// Its append-only launch count is independent of the HTTP provider's counter.
fn adopt_counted_jobs(root: &Path, proxy: &crate::Proxy, provider: &Provider) {
    use std::os::unix::fs::PermissionsExt;
    let helper = root.join("counted-helper");
    let marker = root.join("job-starts");
    let script = format!(
        r#"#!/bin/sh
printf 'job\n' >> '{}'
printf '%s' '{{"finding":{{"kind":"finding","positive":true}},"source_revision":"counted-helper"}}'
printf '%s' '{{"completion":{{"kind":"guest_call_completed","reported_status":0}},"error":null}}' > "$2"
"#,
        marker.display()
    );
    fs::write(&helper, &script).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&marker, "").unwrap();
    fs::write(root.join("fixture.cpio"), "fixture, no VM").unwrap();
    fs::write(root.join("checker.py"), "fixture, no Python execution").unwrap();
    let manifest = json!({"protocol":4,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "hyperlight":"0.19.0","unikraft":"0.21.0","kernel_contract":"fixture",
        "helper":{"file":"counted-helper","sha256":checks::content_digest(script.as_bytes())},
        "rootfs":{"file":"fixture.cpio","sha256":checks::content_digest(b"fixture, no VM")},"rootfs_source":"fixture"});
    let manifest = serde_json::to_vec(&manifest).unwrap();
    fs::write(root.join("runtime.json"), &manifest).unwrap();
    let spec = json!({"gate_id":"bound","argv":["/bin/true"],"timeout_seconds":5,
        "max_input_bytes":32768,"max_input_entries":10,"retain_bytes":4096,
        "engine":{"kind":"hyperlight-unikraft",
            "runtime":{"path":"runtime.json","sha256":checks::content_digest(&manifest)},
            "checker":{"path":"checker.py","sha256":checks::content_digest(b"fixture, no Python execution")}}});
    fs::write(
        root.join("counted-job.json"),
        serde_json::to_vec(&spec).unwrap(),
    )
    .unwrap();
    let mut definitions = definitions(provider.port);
    for (name, boundary, input) in [
        ("author", "admit_issue", "github_issue"),
        ("verify", "verify_output", "published_artifact"),
    ] {
        let service_name = format!("provider_{name}");
        definitions["checks"][&service_name] = definitions["checks"][name].clone();
        definitions["work_bindings"]
            .as_array_mut()
            .unwrap()
            .push(binding(&service_name, boundary, input));
        let limits = definitions["checks"][name]["source"]["limits"].clone();
        definitions["checks"][name]["source"] = json!({"kind":"job","spec":root.join("counted-job.json"),"effects":"passive","limits":limits});
    }
    let old: checks::Checks = serde_json::from_value(self::definitions(provider.port)).unwrap();
    let new: checks::Checks = serde_json::from_value(definitions).unwrap();
    let source = fs::read_to_string(root.join("policy.toml")).unwrap();
    let changed = source.replace(
        &toml::to_string(&old).unwrap(),
        &toml::to_string(&new).unwrap(),
    );
    assert_ne!(changed, source);
    fs::write(root.join("policy.toml"), &changed).unwrap();
    crate::apply_native_policy(&proxy.runtime, &changed).unwrap();
}
fn counts(root: &Path, provider: &Provider) -> (usize, usize) {
    (
        fs::read_to_string(root.join("job-starts"))
            .unwrap()
            .lines()
            .count(),
        provider.calls.load(Ordering::SeqCst),
    )
}
fn refresh_checks(root: &Path, proxy: &crate::Proxy) {
    let source = fs::read_to_string(root.join("policy.toml")).unwrap();
    let changed = source.replace("adopted-1", "adopted-2");
    assert_ne!(source, changed);
    fs::write(root.join("policy.toml"), &changed).unwrap();
    crate::apply_native_policy(&proxy.runtime, &changed).unwrap();
}

fn adopt_prerequisite(root: &Path, proxy: &crate::Proxy, provider: &Provider, retry: bool) {
    let old: checks::Checks = serde_json::from_value(definitions(provider.port)).unwrap();
    let mut selected = definitions(provider.port);
    selected["checks"]["author"]["source"]["operation"]["effects"] = json!("active");
    selected["checks"]["author"]["source"]["operation"]["path"] = json!("/reserve");
    let binding = &mut selected["work_bindings"][0];
    binding.as_object_mut().unwrap().remove("require");
    binding["retry"] = json!(if retry { "idempotent" } else { "never" });
    binding["recovery"] = json!({"reconcilers":[BOB],"retryers":if retry {vec![BOB]} else {vec![]},"max_retries":if retry {1} else {0}});
    let new: checks::Checks = serde_json::from_value(selected).unwrap();
    let source = fs::read_to_string(root.join("policy.toml")).unwrap();
    let changed = source.replace(
        &toml::to_string(&old).unwrap(),
        &toml::to_string(&new).unwrap(),
    );
    assert_ne!(changed, source);
    fs::write(root.join("policy.toml"), &changed).unwrap();
    crate::apply_native_policy(&proxy.runtime, &changed).unwrap();
}

fn prerequisite_value(root: &Path) -> Value {
    let conn = super::super::super::open(root).unwrap();
    let document: String = conn.query_row("SELECT outcome_json FROM coord_operations WHERE operation_type='coord.work.prerequisite' ORDER BY operation_id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
    serde_json::from_str(&document).unwrap()
}

fn prerequisite_request() -> Value {
    json!({"action":"create","title":"reserve before admission","external_ref":"https://github.com/owner/repo/issues/1","operation_id":"protected-reservation"})
}

fn recovery_request(invocation: &Value, action: &str) -> Value {
    let mut request = json!({"action":action,"invocation_id":invocation["id"],"expected_version":invocation["version"],
        "summary":"Read the external reservation by its exact invocation ID","evidence_refs":["fixture:reservation-by-invocation-id"]});
    if action == "resolve_prerequisite" {
        request["outcome"] = json!("completed");
    }
    request
}

#[tokio::test]
async fn prerequisite_is_durable_before_creation_and_dispatches_once_under_concurrency() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    let request = prerequisite_request();
    let mut mutation = request.clone();
    mutation.as_object_mut().unwrap().remove("operation_id");
    let runtime = proxy.runtime.read().unwrap().clone();
    let files = runtime
        .config
        .native_config_dir
        .as_deref()
        .zip(runtime.config.policy_file.as_deref());
    let configured = automatic::configuration(files, None).unwrap();
    preflight(
        files,
        &configured,
        &mut super::super::super::open(root.path()).unwrap(),
        "owned",
        Actor::Agent(ALICE),
        serde_json::from_value(mutation).unwrap(),
        Some("protected-reservation"),
    )
    .unwrap();
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "passive preflight"
    );
    let mut no_identity = request.clone();
    no_identity.as_object_mut().unwrap().remove("operation_id");
    assert_eq!(api(root.path(), &no_identity).await.0, 400);
    for invalid in [
        json!({"title":""}),
        json!({"assignee":{"kind":"agent","id":"missing"}}),
    ] {
        let mut value = request.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        assert_ne!(api(root.path(), &value).await.0, 200);
    }
    assert_eq!(provider.effects.load(Ordering::SeqCst), 0);
    provider.mode.store(5, Ordering::SeqCst);
    let task_root = root.path().to_owned();
    let task_request = request.clone();
    let pending = tokio::spawn(async move { api(&task_root, &task_request).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.reached.notified(),
    )
    .await
    .unwrap();
    let before = prerequisite_value(root.path());
    assert_eq!(before["record"]["state"], "dispatching");
    let conn = super::super::super::open(root.path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(api(root.path(), &request).await.0, 409);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    provider.release.notify_one();
    let (status, receipt) = pending.await.unwrap();
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(receipt["work"]["automatic"][0]["id"], before["id"]);
    assert_eq!(receipt["work"]["automatic"][0]["state"], "completed");
    let id = before["id"].as_str().unwrap();
    let cli = super::super::super::work_cli::run(
        root.path(),
        &["prerequisite".into(), "owned".into(), id.into()],
    )
    .await
    .unwrap();
    assert_eq!(cli["id"], before["id"]);
    assert_eq!(cli["record"]["state"], "completed");
    let mut socket = UnixStream::connect(root.path().join("alice.sock"))
        .await
        .unwrap();
    socket.write_all(format!("GET http://_safeyolo.proxy.internal/api/coord/rooms/owned/work?invocation_id={id} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer synthetic-work-agent-token\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(serde_json::from_str::<Value>(body).unwrap(), cli);
    let client = crate::coord_tools::Client {
        socket: Some(root.path().join("alice.sock")),
        token_file: root.path().join("data/agent_token"),
        home: None,
    };
    assert_eq!(
        client
            .call(
                "read_work_prerequisite",
                &json!({"room_name":"owned","invocation_id":id})
            )
            .await
            .unwrap(),
        cli
    );
    for (tool, action) in [
        ("resolve_work_prerequisite", "resolve_prerequisite"),
        ("retry_work_prerequisite", "retry_prerequisite"),
    ] {
        let mut recovery = recovery_request(&cli, action);
        recovery.as_object_mut().unwrap().remove("action");
        recovery["room_name"] = json!("owned");
        recovery["operation_id"] = json!(tool);
        let error = client.call(tool, &recovery).await.unwrap_err().to_string();
        assert!(error.contains("recovery permission"), "{error}");
    }
    assert_eq!(api(root.path(), &request).await, (200, receipt));
    let mut changed = request.clone();
    changed["title"] = json!("changed protected input");
    assert_eq!(api(root.path(), &changed).await.0, 409);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.requests.lock().unwrap()[0]["input"]["invocation_id"],
        before["id"]
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_success_survives_failed_protected_commit_and_exact_restart_replay() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    let conn = super::super::super::open(root.path()).unwrap();
    conn.execute_batch("CREATE TRIGGER controlled_commit_failure BEFORE INSERT ON coord_work BEGIN SELECT RAISE(ABORT,'controlled protected commit failure'); END;").unwrap();
    let request = prerequisite_request();
    assert_eq!(api(root.path(), &request).await.0, 503);
    let invocation = prerequisite_value(root.path());
    assert_eq!(invocation["record"]["state"], "completed");
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    let mut changed = request.clone();
    changed["title"] = json!("changed before protected commit");
    assert_eq!(api(root.path(), &changed).await.0, 409);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    conn.execute_batch("DROP TRIGGER controlled_commit_failure")
        .unwrap();
    proxy.shutdown().await;
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    let (status, receipt) = api(root.path(), &request).await;
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(receipt["work"]["automatic"][0]["id"], invocation["id"]);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_changed_selector_cannot_escape_retained_operation_identity() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    provider.mode.store(3, Ordering::SeqCst);
    let request = prerequisite_request();
    let (status, held) = api(root.path(), &request).await;
    assert_eq!(status, 409, "{held}");
    let invocation = prerequisite_value(root.path());
    assert_eq!(invocation["record"]["state"], "uncertain");
    let id = invocation["id"].as_str().unwrap();
    assert!(held["error"].as_str().unwrap().contains(id), "{held}");
    let client = crate::coord_tools::Client {
        socket: Some(root.path().join("alice.sock")),
        token_file: root.path().join("data/agent_token"),
        home: None,
    };
    assert_eq!(
        client
            .call(
                "read_work_prerequisite",
                &json!({"room_name":"owned","invocation_id":id})
            )
            .await
            .unwrap(),
        invocation
    );
    proxy.shutdown().await;
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    for reference in [
        None,
        Some(Value::Null),
        Some(json!("https://github.com/other/repo/issues/1")),
        Some(json!("https://github.com/owner/repo/issues/2")),
    ] {
        let mut changed = request.clone();
        if let Some(reference) = reference {
            changed["external_ref"] = reference;
        } else {
            changed.as_object_mut().unwrap().remove("external_ref");
        }
        let (status, refused) = api(root.path(), &changed).await;
        assert_eq!(status, 409, "{refused}");
        assert!(
            refused["error"]
                .as_str()
                .unwrap()
                .contains("original canonical request"),
            "{refused}"
        );
        // The committing path must reject the same change without binding selection.
        changed.as_object_mut().unwrap().remove("operation_id");
        assert_eq!(
            mutate(
                None,
                &mut super::super::super::open(root.path()).unwrap(),
                "owned",
                Actor::Agent(ALICE),
                serde_json::from_value(changed).unwrap(),
                Some("protected-reservation")
            )
            .unwrap_err()
            .0,
            409
        );
    }
    let conn = super::super::super::open(root.path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(api(root.path(), &request).await.0, 409);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    let mut generic = request;
    generic.as_object_mut().unwrap().remove("external_ref");
    generic["operation_id"] = json!("separate-generic-operation");
    assert_eq!(api(root.path(), &generic).await.0, 200);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_lost_reply_requires_distinct_recovery_and_bounded_idempotent_retry() {
    for complete_retry in [false, true] {
        let provider = Provider::start().await;
        let (root, proxy, _) = fixture_proxy(&provider).await;
        adopt_prerequisite(root.path(), &proxy, &provider, true);
        provider.mode.store(3, Ordering::SeqCst);
        let request = prerequisite_request();
        assert_eq!(api(root.path(), &request).await.0, 409);
        let invocation = prerequisite_value(root.path());
        assert_eq!(invocation["record"]["state"], "uncertain");
        assert_eq!(invocation["attempts"], 1);
        assert_eq!(api(root.path(), &request).await.0, 409);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        for action in ["resolve_prerequisite", "retry_prerequisite"] {
            assert_eq!(
                submit(
                    &proxy,
                    root.path(),
                    Actor::Agent(ALICE),
                    recovery_request(&invocation, action),
                    action
                )
                .await
                .unwrap_err()
                .0,
                403
            );
        }
        let retry = recovery_request(&invocation, "retry_prerequisite");
        let selected = submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            retry.clone(),
            "select-retry",
        )
        .await
        .unwrap();
        assert_eq!(selected["prerequisite"]["record"]["state"], "pending");
        assert_eq!(
            submit(
                &proxy,
                root.path(),
                Actor::Agent(BOB),
                retry,
                "select-retry"
            )
            .await
            .unwrap(),
            selected
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "selection grants no execution to the recovery actor"
        );
        if complete_retry {
            provider.mode.store(0, Ordering::SeqCst);
        }
        assert_eq!(
            api(root.path(), &request).await.0,
            if complete_retry { 200 } else { 409 }
        );
        let after = prerequisite_value(root.path());
        assert_eq!(after["id"], invocation["id"]);
        assert_eq!(after["attempts"], 2);
        assert_eq!(
            provider.effects.load(Ordering::SeqCst),
            1,
            "the external service deduplicates by invocation ID"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        if !complete_retry {
            assert_eq!(
                submit(
                    &proxy,
                    root.path(),
                    Actor::Agent(BOB),
                    recovery_request(&after, "retry_prerequisite"),
                    "exhausted-retry"
                )
                .await
                .unwrap_err()
                .0,
                403
            );
            let reconciled = submit(
                &proxy,
                root.path(),
                Actor::Agent(BOB),
                recovery_request(&after, "resolve_prerequisite"),
                "external-observation",
            )
            .await
            .unwrap();
            assert_eq!(reconciled["prerequisite"]["record"]["state"], "completed");
            assert_eq!(api(root.path(), &request).await.0, 200);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        }
        let requests = provider.requests.lock().unwrap().clone();
        assert_eq!(
            requests[0]["input"], requests[1]["input"],
            "retry preserves exact external inputs"
        );
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn prerequisite_never_retries_without_adoption_and_revoked_recovery_cannot_progress() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    provider.mode.store(3, Ordering::SeqCst);
    let request = prerequisite_request();
    assert_eq!(api(root.path(), &request).await.0, 409);
    let invocation = prerequisite_value(root.path());
    assert_eq!(
        submit(
            &proxy,
            root.path(),
            Actor::Operator,
            recovery_request(&invocation, "retry_prerequisite"),
            "no-retry-adoption"
        )
        .await
        .unwrap_err()
        .0,
        403
    );
    refresh_checks(root.path(), &proxy);
    assert_eq!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            recovery_request(&invocation, "resolve_prerequisite"),
            "revoked-recovery"
        )
        .await
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(api(root.path(), &request).await.0, 409);
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_pending_revocation_retains_uncertainty_and_prevents_commit() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, true);
    provider.mode.store(5, Ordering::SeqCst);
    // Keep the policy watcher's next 25 ms tick pending while the real response
    // arrives. Retention must also catch revocation when polling has not yet done so.
    tokio::time::pause();
    let clock_hold = tokio::spawn(async {
        let started = std::time::Instant::now();
        while started.elapsed() < std::time::Duration::from_secs(5) {
            tokio::task::yield_now().await;
        }
    });
    let task_root = root.path().to_owned();
    let pending = tokio::spawn(async move { api(&task_root, &prerequisite_request()).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.reached.notified(),
    )
    .await
    .unwrap();
    let invocation = prerequisite_value(root.path());
    assert_eq!(invocation["record"]["state"], "dispatching");
    refresh_checks(root.path(), &proxy);
    provider.release.notify_one();
    let response = pending.await.unwrap();
    clock_hold.abort();
    tokio::time::resume();
    assert_ne!(response.0, 200);
    let retained = prerequisite_value(root.path());
    assert_eq!(retained["record"]["state"], "uncertain");
    assert_eq!(retained["id"], invocation["id"]);
    assert_eq!(retained["attempts"], 1);
    assert_eq!(
        retained["record"]["evidence"]["execution"]["http_status"],
        200
    );
    assert!(
        retained["record"]["detail"]
            .as_str()
            .unwrap()
            .contains("authority")
    );
    assert_eq!(api(root.path(), &prerequisite_request()).await.0, 409);
    for action in ["resolve_prerequisite", "retry_prerequisite"] {
        assert_eq!(
            submit(
                &proxy,
                root.path(),
                Actor::Agent(BOB),
                recovery_request(&retained, action),
                action,
            )
            .await
            .unwrap_err()
            .0,
            403
        );
    }
    assert_eq!(prerequisite_value(root.path()), retained);
    let conn = super::super::super::open(root.path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_completed_effect_does_not_restore_revoked_requester_membership() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    provider.mode.store(5, Ordering::SeqCst);
    let task_root = root.path().to_owned();
    let pending = tokio::spawn(async move { api(&task_root, &prerequisite_request()).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.reached.notified(),
    )
    .await
    .unwrap();
    let conn = super::super::super::open(root.path()).unwrap();
    conn.execute("DELETE FROM memberships WHERE principal_id=?1", [ALICE])
        .unwrap();
    provider.release.notify_one();
    assert_eq!(pending.await.unwrap().0, 404);
    let retained = prerequisite_value(root.path());
    assert_eq!(retained["record"]["state"], "completed");
    assert_eq!(
        retained["record"]["evidence"]["execution"]["http_status"],
        200
    );
    assert_eq!(api(root.path(), &prerequisite_request()).await.0, 404);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn prerequisite_crash_after_dispatch_recovers_without_blind_repetition() {
    const CHILD_ROOT: &str = "SAFEYOLO_PREREQUISITE_CRASH_ROOT";
    if let Ok(root) = std::env::var(CHILD_ROOT) {
        let root = Path::new(&root);
        let proxy =
            crate::Proxy::start(crate::native_config::read(&root.join("config.toml")).unwrap())
                .await
                .unwrap();
        let _ = api(root, &prerequisite_request()).await;
        proxy.shutdown().await;
        panic!("parent must kill the child after observing the reservation");
    }
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_prerequisite(root.path(), &proxy, &provider, false);
    proxy.shutdown().await;
    provider.mode.store(5, Ordering::SeqCst);
    let log = fs::File::create(root.path().join("prerequisite-child.log")).unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "coord_rooms::work::tests::automatic_tests::prerequisite_crash_after_dispatch_recovers_without_blind_repetition", "--nocapture"])
        .env(CHILD_ROOT, root.path()).stdout(log.try_clone().unwrap()).stderr(log).kill_on_drop(true).spawn().unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(8),
        provider.reached.notified(),
    )
    .await
    .unwrap();
    let before = prerequisite_value(root.path());
    assert_eq!(before["record"]["state"], "dispatching");
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    child.kill().await.unwrap();
    assert!(!child.wait().await.unwrap().success());
    provider.release.notify_one();
    provider.mode.store(0, Ordering::SeqCst);
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    let after = prerequisite_value(root.path());
    assert_eq!(after["id"], before["id"]);
    assert_eq!(after["record"]["state"], "uncertain");
    assert_eq!(api(root.path(), &prerequisite_request()).await.0, 409);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        recovery_request(&after, "resolve_prerequisite"),
        "crash-reconciliation",
    )
    .await
    .unwrap();
    assert_eq!(api(root.path(), &prerequisite_request()).await.0, 200);
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_preflight_refuses_invalid_requests_before_jobs_or_provider_contacts() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_counted_jobs(root.path(), &proxy, &provider);
    let create = json!({"action":"create","title":"assigned issue","external_ref":"https://github.com/owner/repo/issues/1","assignee":{"kind":"agent","id":BOB},"operation_id":"create-assigned"});
    let (status, receipt) = api(root.path(), &create).await;
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(counts(root.path(), &provider), (1, 1));
    let work = &receipt["work"];
    let mut cases = vec![(
        "other assignee",
        input(work, "claim"),
        403,
        "assigned participant",
    )];
    let mut value = input(work, "reassign");
    value["agent_id"] = json!(ALICE);
    cases.push(("reassignment", value, 403, "only the operator"));
    for (field, value) in [
        ("expected_version", json!(0)),
        ("expected_version", json!(999)),
        ("expected_generation", json!(1)),
    ] {
        let mut request = input(work, "claim");
        request[field] = value.clone();
        cases.push((
            field,
            request,
            if field == "expected_version" && value == 0 {
                400
            } else {
                409
            },
            "version",
        ));
    }
    let mut empty = create.clone();
    empty.as_object_mut().unwrap().remove("operation_id");
    empty["title"] = json!("");
    cases.push(("empty title", empty, 400, "title"));
    for (index, (label, mut request, expected, detail)) in cases.into_iter().enumerate() {
        request["operation_id"] = json!(format!("invalid-{index}"));
        let before = counts(root.path(), &provider);
        let (status, result) = api(root.path(), &request).await;
        assert_eq!(status, expected, "{label}: {result}");
        assert!(result.to_string().contains(detail), "{label}: {result}");
        assert_eq!(counts(root.path(), &provider), before, "{label}");
    }
    let before = counts(root.path(), &provider);
    assert_eq!(api(root.path(), &create).await.1, receipt);
    let mut changed = create.clone();
    changed["title"] = json!("changed input");
    assert_eq!(api(root.path(), &changed).await.0, 409);
    assert_eq!(counts(root.path(), &provider), before);
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        input(work, "claim"),
        "assigned-claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    assert_eq!(counts(root.path(), &provider), (2, 2));
    let before = counts(root.path(), &provider);
    assert_eq!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            input(&work, "claim"),
            "already-claimed"
        )
        .await
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(counts(root.path(), &provider), before);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        publication(&work, b"wanted"),
        "output",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), work["work_id"].as_str().unwrap());
    assert_eq!(counts(root.path(), &provider), (3, 3));
    // New policy makes the previous automatic findings inapplicable, so these
    // acceptance attempts would otherwise launch fresh verifiers.
    refresh_checks(root.path(), &proxy);
    let mut cases = vec![
        (Actor::Agent(ALICE), approval(&work), 403),
        (Actor::Agent(BOB), approval(&work), 403),
    ];
    for (field, value) in [
        ("expected_version", json!(1)),
        ("expected_generation", json!(0)),
        ("expected_target_generation", json!(0)),
        ("expected_requirements_version", json!(0)),
    ] {
        let mut request = approval(&work);
        request[field] = value;
        cases.push((Actor::Agent(BOB), request, 409));
    }
    for (index, (actor, request, status)) in cases.into_iter().enumerate() {
        let before = counts(root.path(), &provider);
        assert_eq!(
            submit(
                &proxy,
                root.path(),
                actor,
                request,
                &format!("invalid-accept-{index}")
            )
            .await
            .unwrap_err()
            .0,
            status
        );
        assert_eq!(counts(root.path(), &provider), before);
    }
    assert_eq!(
        current_value(root.path(), work["work_id"].as_str().unwrap())["version"],
        work["version"]
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 0);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_preflight_preserves_positive_negative_and_failed_findings() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_counted_jobs(root.path(), &proxy, &provider);
    let create = json!({"action":"create","title":"finding outcomes","external_ref":"https://github.com/owner/repo/issues/1"});
    for (index, mode) in [1, 2, 6, 0].into_iter().enumerate() {
        provider.mode.store(mode, Ordering::SeqCst);
        let mut request = create.clone();
        request["operation_id"] = json!(format!("finding-{mode}"));
        let (status, result) = api(root.path(), &request).await;
        assert_eq!(
            status,
            if mode == 0 { 200 } else { 409 },
            "{mode}: {result}"
        );
        assert_eq!(counts(root.path(), &provider), (index + 1, index + 1));
        let conn = super::super::super::open(root.path()).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            if mode == 0 { 1 } else { 0 }
        );
    }
    assert_eq!(provider.effects.load(Ordering::SeqCst), 0);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_preflight_does_not_replace_transactional_state_or_requirement_validation() {
    for change in ["assignment", "requirements"] {
        let provider = Provider::start().await;
        let (root, proxy, _) = fixture_proxy(&provider).await;
        adopt_counted_jobs(root.path(), &proxy, &provider);
        let work = submit(&proxy,root.path(),Actor::Agent(ALICE),json!({"action":"create","title":"race","external_ref":"https://github.com/owner/repo/issues/1","assignee":{"kind":"agent","id":BOB}}),"create").await.unwrap()["work"].clone();
        provider.mode.store(4, Ordering::SeqCst);
        let state = proxy.runtime.clone();
        let path = root.path().to_owned();
        let request = input(&work, "claim");
        let pending = tokio::spawn(async move {
            automatic::mutate(
                &state,
                &path,
                "owned",
                Actor::Agent(BOB),
                serde_json::from_value(request).unwrap(),
                Some("pending"),
                None,
            )
            .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            provider.reached.notified(),
        )
        .await
        .unwrap();
        assert_eq!(counts(root.path(), &provider), (2, 2));
        let mut conn = super::super::super::open(root.path()).unwrap();
        conn.busy_timeout(std::time::Duration::from_millis(100))
            .unwrap();
        conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").unwrap();
        let mut mutation = if change == "assignment" {
            input(&work, "reassign")
        } else {
            input(&work, "set_requirements")
        };
        if change == "assignment" {
            mutation["agent_id"] = json!(ALICE);
        } else {
            let r = &work["acceptance_requirements"];
            for field in ["authorities", "deciders", "independent"] {
                mutation[field] = r[field].clone();
            }
            mutation["expected_requirements_version"] = r["version"].clone();
            mutation["checks"] = json!([]);
            mutation["challenges"] = json!([]);
            mutation["reason"] = json!("Changed while the provider was pending");
        }
        let changed = mutate(
            None,
            &mut conn,
            "owned",
            Actor::Operator,
            serde_json::from_value(mutation).unwrap(),
            Some("concurrent-change"),
        )
        .unwrap()["work"]
            .clone();
        // A global policy writer must also remain available while the provider waits.
        refresh_checks(root.path(), &proxy);
        provider.release.notify_one();
        assert_eq!(pending.await.unwrap().unwrap_err().0, 409);
        assert_eq!(
            current_value(root.path(), work["work_id"].as_str().unwrap())["version"],
            changed["version"]
        );
        assert_eq!(counts(root.path(), &provider), (2, 2));
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn automatic_concurrent_exact_requests_share_the_committed_receipt_and_replay() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    adopt_counted_jobs(root.path(), &proxy, &provider);
    provider.mode.store(4, Ordering::SeqCst);
    let request = json!({"action":"create","title":"concurrent","external_ref":"https://github.com/owner/repo/issues/1","operation_id":"same-operation"});
    let mut pending = Vec::new();
    for _ in 0..2 {
        let path = root.path().to_owned();
        let request = request.clone();
        pending.push(tokio::spawn(async move { api(&path, &request).await }));
    }
    // Hold the first provider response until both requests passed preflight.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while counts(root.path(), &provider).0 != 2 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for _ in 0..2 {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            provider.reached.notified(),
        )
        .await
        .unwrap();
        provider.release.notify_one();
    }
    let first = pending.remove(0).await.unwrap();
    let second = pending.remove(0).await.unwrap();
    assert_eq!(first.0, 200, "{:?}", first);
    assert_eq!(second, first);
    assert_eq!(counts(root.path(), &provider), (2, 2));
    assert_eq!(api(root.path(), &request).await, first);
    assert_eq!(counts(root.path(), &provider), (2, 2));
    let conn = super::super::super::open(root.path()).unwrap();
    for table in ["coord_work", "coord_work_revisions", "coord_operations"] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "{table}"
        );
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_configuration_rejects_unknown_jobs_types_effects_and_dependencies() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
    for (old, new) in [
        ("job = \"author\"", "job = \"missing\""),
        (
            "boundary = \"admit_issue\"",
            "boundary = \"arbitrary_shell\"",
        ),
        ("input = \"github_issue\"", "input = \"completed_work\""),
        ("result_type = \"finding\"", "result_type = \"fact\""),
        ("effects = \"passive\"", "effects = \"active\""),
        ("retry = \"never\"", "retry = \"always\""),
        (
            "job = \"author\"",
            "job = \"author\"\ndepends_on = ['notify']",
        ),
    ] {
        let changed = source.replace(old, new);
        assert_ne!(changed, source, "{old}");
        assert!(
            crate::policy::Policy::parse(&changed, crate::policy::Format::Toml).is_err(),
            "{old}"
        );
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_admission_covers_api_cli_import_omitted_factory_and_existing_delegation() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let denied = json!({"action":"create","title":"denied issue","external_ref":"https://github.com/owner/repo/issues/2","operation_id":"denied-api"});
    let (status, body) = api(root.path(), &denied).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        super::super::super::open(root.path())
            .unwrap()
            .query_row("SELECT count(*) FROM coord_work", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    for (index, url) in [
        "https://GITHUB.com/OWNER/REPO/issues/0002#comment",
        "http://github.com:80/owner/repo/issues/2/",
        "https://github.com./%6fwner/repo/issues/2",
        "https://api.github.com/repos/owner/repo/issues/2",
    ]
    .into_iter()
    .enumerate()
    {
        let mut alias = denied.clone();
        alias["external_ref"] = json!(url);
        alias["operation_id"] = json!(format!("alias-{index}"));
        let (status, result) = api(root.path(), &alias).await;
        assert_eq!(status, 409, "{url}: {result}");
    }
    let imported = super::super::super::work_cli::run(
        root.path(),
        &[
            "import-github".into(),
            "owned".into(),
            "https://github.com/owner/repo/issues/2".into(),
            "--operation-id".into(),
            "denied-import".into(),
        ],
    )
    .await;
    assert!(imported.is_err());
    let mut conn = super::super::super::open(root.path()).unwrap();
    let direct = mutate(Some((root.path(),&root.path().join("policy.toml"))),&mut conn,"owned",Actor::Agent(ALICE),serde_json::from_value(json!({"action":"create","title":"direct","external_ref":"https://github.com/owner/repo/issues/1"})).unwrap(),Some("direct"));
    assert_eq!(direct.unwrap_err().0, 409);
    let generic = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"ordinary generic work"}),
        "generic",
    )
    .await
    .unwrap();
    assert!(generic["work"]["factory"].is_null());
    let existing = mutate(None,&mut conn,"owned",Actor::Agent(ALICE),serde_json::from_value(json!({"action":"create","title":"predates adoption","external_ref":"https://github.com/owner/repo/issues/2"})).unwrap(),Some("old")).unwrap()["work"].clone();
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Operator,
            {
                let mut v = input(&existing, "reassign");
                v["agent_id"] = json!(ALICE);
                v
            },
            "delegate-denied"
        )
        .await
        .is_err()
    );
    assert_eq!(
        current_value(root.path(), existing["work_id"].as_str().unwrap())["state"],
        "open"
    );
    let allowed = json!({"action":"create","title":"allowed issue","external_ref":"https://github.com/owner/repo/issues/1","operation_id":"allowed-api"});
    let (status, receipt) = api(root.path(), &allowed).await;
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(receipt["work"]["factory"]["reference"], reference);
    assert_eq!(receipt["work"]["automatic"][0]["state"], "satisfied");
    let calls = provider.calls.load(Ordering::SeqCst);
    assert_eq!(api(root.path(), &allowed).await.1, receipt);
    assert_eq!(provider.calls.load(Ordering::SeqCst), calls);
    // A later delegation refreshes the relevant issue read, even within its
    // prior result's freshness period. An idempotent replay above stays a replay.
    provider.mode.store(1, Ordering::SeqCst);
    let mut delegated = input(&receipt["work"], "reassign");
    delegated["agent_id"] = json!(ALICE);
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Operator,
            delegated,
            "refreshed-delegation"
        )
        .await
        .is_err()
    );
    assert!(provider.calls.load(Ordering::SeqCst) > calls);
    provider.mode.store(0, Ordering::SeqCst);
    let imported = super::super::super::work_cli::run(
        root.path(),
        &[
            "import-github".into(),
            "owned".into(),
            "https://github.com/owner/repo/issues/1".into(),
            "--operation-id".into(),
            "allowed-import".into(),
        ],
    )
    .await
    .unwrap();
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&imported["work"], "claim"),
        "operator-admitted-claim",
    )
    .await
    .unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_output_verification_cannot_replace_independent_reviews_or_reuse_other_bytes() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    let work = submit(&proxy,root.path(),Actor::Agent(ALICE),json!({"action":"create","title":"artifact work","external_ref":"https://github.com/owner/repo/issues/1"}),"create").await.unwrap()["work"].clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    let mut bad = publication(&work, b"wanted");
    bad["artifact_base64"] = json!(STANDARD.encode(b"substitution"));
    assert_eq!(
        submit(&proxy, root.path(), Actor::Agent(ALICE), bad, "mismatch")
            .await
            .unwrap_err()
            .0,
        400
    );
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"wanted"),
        "output",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    assert_eq!(
        work["automatic"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["binding"]["name"] == "verify")
            .unwrap()["state"],
        "satisfied"
    );
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            approval(&work),
            "missing-human"
        )
        .await
        .is_err()
    );
    let check_id = work["factory"]["current_checks"][0].as_str().unwrap();
    let check = current_value(root.path(), check_id);
    let check = submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        input(&check, "claim"),
        "review-claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let mut answer = input(&check, "answer_check");
    answer["verdict"] = json!("approve");
    answer["summary"] = json!("Independent fixture inspection");
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        answer,
        "review-answer",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        approval(&work),
        "accept",
    )
    .await
    .unwrap();
    assert_eq!(
        current_value(root.path(), id)["acceptance_status"]["state"],
        "accepted"
    );
    let work = current_value(root.path(), id);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"replacement"),
        "output2",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    assert_ne!(work["acceptance_status"]["state"], "accepted");
    assert_eq!(work["target_generation"], 2);
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            approval(&work),
            "old-result"
        )
        .await
        .is_err()
    );
    // An authority can remove participant reviews, but that does not supply a machine finding.
    let mut amend = input(&work, "set_requirements");
    let r = &work["acceptance_requirements"];
    for field in ["authorities", "deciders", "independent"] {
        amend[field] = r[field].clone();
    }
    amend["expected_requirements_version"] = r["version"].clone();
    amend["checks"] = json!([]);
    amend["challenges"] = json!([]);
    amend["reason"] = json!("Retain automatic verification alone for this fixture");
    submit(&proxy, root.path(), Actor::Agent(BOB), amend, "amend")
        .await
        .unwrap();
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            approval(&current_value(root.path(), id)),
            "machine-still-required"
        )
        .await
        .is_err()
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_pending_admission_revalidates_revocation_without_holding_coord_or_policy_locks()
{
    for revoke_policy in [false, true] {
        let provider = Provider::start().await;
        let (root, proxy, _) = fixture_proxy(&provider).await;
        provider.mode.store(4, Ordering::SeqCst);
        let state = proxy.runtime.clone();
        let path = root.path().to_owned();
        let pending = tokio::spawn(async move {
            automatic::mutate(&state,&path,"owned",Actor::Agent(ALICE),serde_json::from_value(json!({"action":"create","title":"held","external_ref":"https://github.com/owner/repo/issues/1"})).unwrap(),Some("held"),None).await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            provider.reached.notified(),
        )
        .await
        .unwrap();
        // These writes must succeed while evidence is held at the real provider.
        let conn = super::super::super::open(root.path()).unwrap();
        conn.busy_timeout(std::time::Duration::from_millis(100))
            .unwrap();
        if !revoke_policy {
            conn.execute("DELETE FROM memberships WHERE principal_id=?1", [ALICE])
                .unwrap();
        }
        let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
        let revoked = source.replace(
            "[agents.'gate:bound'.services.fixture]\ncapability='invoke'\n",
            "",
        );
        assert_ne!(source, revoked);
        if revoke_policy {
            crate::apply_native_policy(&proxy.runtime, &revoked).unwrap();
        }
        provider.release.notify_one();
        assert!(pending.await.unwrap().is_err());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM coord_work", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(provider.effects.load(Ordering::SeqCst), 0);
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn automatic_missing_malformed_stale_and_substituted_output_evidence_holds_acceptance() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"explicit factory artifact","factory":reference}),
        "create",
    )
    .await
    .unwrap()["work"]
        .clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    let mut output = publication(&work, b"wanted");
    output.as_object_mut().unwrap().remove("artifact_base64");
    submit(&proxy, root.path(), Actor::Agent(ALICE), output, "missing")
        .await
        .unwrap();
    let work = current_value(root.path(), id);
    assert!(
        work["automatic"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("artifact_base64")
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(BOB),
            approval(&work),
            "missing-refusal"
        )
        .await
        .is_err()
    );
    provider.mode.store(2, Ordering::SeqCst);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"wanted"),
        "malformed",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    assert_eq!(work["automatic"][0]["state"], "unavailable");
    let mut forged = approval(&work);
    forged["evidence"] = json!({"positive":true});
    assert!(serde_json::from_value::<Mutation>(forged).is_err());
    provider.mode.store(0, Ordering::SeqCst);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"wanted"),
        "good",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    let mut record: automatic::Obligation =
        serde_json::from_value(work["automatic"][0].clone()).unwrap();
    let policy = proxy.runtime.read().unwrap().policy.clone().unwrap();
    let evidence = record.evidence.as_ref().unwrap().clone();
    assert_eq!(
        policy.named_checks().work_truth(
            &record.binding,
            &record.subject,
            evidence.clone(),
            now() as u64
        ),
        checks::Truth::True
    );
    assert_eq!(
        policy.named_checks().work_truth(
            &record.binding,
            &checks::Subject::Value {
                value: "substitute".into()
            },
            evidence.clone(),
            now() as u64
        ),
        checks::Truth::Unavailable
    );
    let expired = evidence.expires_at_ms.unwrap();
    assert_eq!(
        policy
            .named_checks()
            .work_truth(&record.binding, &record.subject, evidence, expired),
        checks::Truth::Unavailable
    );
    record
        .evidence
        .as_mut()
        .unwrap()
        .result
        .as_mut()
        .unwrap()
        .configuration_version = "substituted".into();
    assert_eq!(
        policy.named_checks().work_truth(
            &record.binding,
            &record.subject,
            record.evidence.unwrap(),
            now() as u64
        ),
        checks::Truth::Unavailable
    );
    proxy.shutdown().await;
}

async fn poll_action(root: &Path, id: &str, state: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let work = current_value(root, id);
            if work["automatic"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["binding"]["boundary"] == "after_complete" && r["state"] == state)
            {
                break work;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {state}; current Work: {}",
            current_value(root, id)
        )
    })
}

#[tokio::test]
async fn automatic_follow_up_recovers_a_committed_pending_obligation_once() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"follow-up","factory":reference}),
        "create",
    )
    .await
    .unwrap()["work"]
        .clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    // The same transactional core can commit while the owning proxy is offline.
    let completion = input(&work, "complete");
    let receipt = mutate(
        Some((root.path(), &root.path().join("policy.toml"))),
        &mut super::super::super::open(root.path()).unwrap(),
        "owned",
        Actor::Agent(ALICE),
        serde_json::from_value(completion.clone()).unwrap(),
        Some("commit-before-exit"),
    )
    .unwrap();
    assert_eq!(receipt["work"]["state"], "done");
    assert_eq!(receipt["work"]["automatic"][0]["state"], "pending");
    assert_eq!(provider.effects.load(Ordering::SeqCst), 0);
    proxy.shutdown().await;
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    let work = poll_action(root.path(), id, "completed").await;
    assert_eq!(work["state"], "done");
    assert!(
        work["automatic"][0]["evidence"]["result"].is_null(),
        "an action must not masquerade as a boolean check"
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    let recovered = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        completion,
        "commit-before-exit",
    )
    .await
    .unwrap();
    assert_eq!(recovered, receipt);
    proxy.shutdown().await;
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    automatic::drain(&proxy.runtime, root.path(), Some(id))
        .await
        .unwrap();
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_action_failure_is_uncertain_and_cannot_undo_the_completed_transition() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"uncertain follow-up","factory":reference,
            "external_ref":"https://github.com/owner/repo/issues/1","assignee":{"kind":"agent","id":ALICE}}),
        "create",
    )
    .await
    .unwrap()["work"]
        .clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    provider.mode.store(3, Ordering::SeqCst);
    let receipt = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "complete"),
        "complete",
    )
    .await
    .unwrap();
    assert_eq!(receipt["work"]["state"], "done");
    let work = poll_action(root.path(), id, "uncertain").await;
    assert_eq!(work["state"], "done");
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    automatic::drain(&proxy.runtime, root.path(), Some(id))
        .await
        .unwrap();
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    // Reusing a binding name for a different boundary must not erase an
    // earlier uncertain action or dispatch it again.
    let action_id = work["automatic"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["binding"]["boundary"] == "after_complete")
        .unwrap()["id"]
        .clone();
    let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
    let base = &source[source.find("[agents.alice]").unwrap()..];
    let mut selected = definitions(provider.port);
    let bindings = selected["work_bindings"].as_array_mut().unwrap();
    bindings.retain(|b| b["boundary"] != "after_complete");
    let mut reused = binding("notify", "admit_issue", "github_issue");
    reused["job"] = json!("author");
    reused["require"]["check"] = json!("author");
    bindings.push(reused);
    let selected: checks::Checks = serde_json::from_value(selected).unwrap();
    let changed = format!("{}\n{base}", toml::to_string(&selected).unwrap());
    crate::apply_native_policy(&proxy.runtime, &changed).unwrap();
    let mut continuation = input(&work, "continue");
    continuation["reason"] =
        json!("Current admission selection changed; retain earlier action uncertainty");
    continuation["evidence_refs"] = json!(["fixture:adopted-binding-change"]);
    submit(
        &proxy,
        root.path(),
        Actor::Operator,
        continuation,
        "continued",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    assert!(
        work["automatic"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == action_id && r["state"] == "uncertain")
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    let mut resolve = input(&work, "resolve_action");
    resolve["obligation_id"] = action_id.clone();
    resolve["outcome"] = json!("completed");
    resolve["summary"] = json!("Provider effect counter confirms this obligation");
    resolve["evidence_refs"] = json!(["fixture:external-effect-count=1"]);
    assert_eq!(
        submit(
            &proxy,
            root.path(),
            Actor::Agent(ALICE),
            resolve.clone(),
            "forged-resolution"
        )
        .await
        .unwrap_err()
        .0,
        403
    );
    submit(&proxy, root.path(), Actor::Operator, resolve, "resolve")
        .await
        .unwrap();
    assert_eq!(
        current_value(root.path(), id)["automatic"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == action_id)
            .unwrap()["resolution"]["author"]["kind"],
        "operator"
    );
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_crash_after_action_dispatch_keeps_the_same_uncertain_obligation() {
    const CHILD_ROOT: &str = "SAFEYOLO_BOUND_ACTION_CRASH_ROOT";
    if let Ok(root) = std::env::var(CHILD_ROOT) {
        let root = Path::new(&root);
        let proxy =
            crate::Proxy::start(crate::native_config::read(&root.join("config.toml")).unwrap())
                .await
                .unwrap();
        let reference = crate::factory::work::current_reference(root, "native").unwrap();
        let work = submit(
            &proxy,
            root,
            Actor::Agent(ALICE),
            json!({"action":"create","title":"crash action","factory":reference}),
            "child-create",
        )
        .await
        .unwrap()["work"]
            .clone();
        let work = submit(
            &proxy,
            root,
            Actor::Agent(ALICE),
            input(&work, "claim"),
            "child-claim",
        )
        .await
        .unwrap()["work"]
            .clone();
        fs::write(
            root.join("crash-work-id"),
            work["work_id"].as_str().unwrap(),
        )
        .unwrap();
        let _ = submit(
            &proxy,
            root,
            Actor::Agent(ALICE),
            input(&work, "complete"),
            "child-complete",
        )
        .await;
        panic!("parent should have killed the child after observing the effect");
    }
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    proxy.shutdown().await;
    provider.mode.store(5, Ordering::SeqCst);
    let log = fs::File::create(root.path().join("child.log")).unwrap();
    let mut child=tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","coord_rooms::work::tests::automatic_tests::automatic_crash_after_action_dispatch_keeps_the_same_uncertain_obligation","--nocapture"])
        .env(CHILD_ROOT,root.path()).stdout(log.try_clone().unwrap()).stderr(log).kill_on_drop(true).spawn().unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(8),
        provider.reached.notified(),
    )
    .await
    .unwrap();
    let id = fs::read_to_string(root.path().join("crash-work-id")).unwrap();
    let before = current_value(root.path(), &id);
    assert_eq!(before["state"], "done");
    assert_eq!(before["automatic"][0]["state"], "dispatching");
    let obligation = before["automatic"][0]["id"].clone();
    child.kill().await.unwrap();
    let status = child.wait().await.unwrap();
    assert!(!status.success());
    provider.release.notify_one();
    provider.mode.store(0, Ordering::SeqCst);
    // A removed policy must not conceal dispatch uncertainty retained by the old process.
    let policy_path = root.path().join("policy.toml");
    let mut changed: toml_edit::DocumentMut =
        fs::read_to_string(&policy_path).unwrap().parse().unwrap();
    changed.as_table_mut().remove("work_bindings");
    fs::write(&policy_path, changed.to_string()).unwrap();
    let proxy =
        crate::Proxy::start(crate::native_config::read(&root.path().join("config.toml")).unwrap())
            .await
            .unwrap();
    let after = poll_action(root.path(), &id, "uncertain").await;
    assert_eq!(after["state"], "done");
    assert_eq!(after["automatic"][0]["id"], obligation);
    automatic::drain(&proxy.runtime, root.path(), Some(&id))
        .await
        .unwrap();
    assert_eq!(provider.effects.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn automatic_service_request_rule_prevents_the_authorized_effect() {
    let provider = Provider::start().await;
    let (root, proxy, _) = fixture_proxy(&provider).await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let effects = Arc::new(AtomicUsize::new(0));
    let observed = effects.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut head = vec![];
            while !head.ends_with(b"\r\n\r\n") {
                let Ok(byte) = socket.read_u8().await else {
                    break;
                };
                head.push(byte);
            }
            if head.starts_with(b"POST /effect ") {
                observed.fetch_add(1, Ordering::SeqCst);
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
                    )
                    .await
                    .unwrap();
            }
        }
    });
    let mut named: checks::Checks = serde_json::from_value(definitions(provider.port)).unwrap();
    let mut request_check = definition(provider.port, false);
    request_check["subject"] = json!("http_path");
    request_check["source"]["operation"]["path"] = json!("/threat");
    named.checks.insert(
        "request_check".into(),
        serde_json::from_value(request_check).unwrap(),
    );
    named.rules.push(serde_json::from_value(json!({"name":"before_fixture_effect","host":"127.0.0.1","agent":"alice","stage":"request","influence":"hard_exclusion","priority":0,"required":true,"when":{"op":"finding","check":"request_check"},"on_match":"deny","on_unavailable":"unresolved"})).unwrap());
    let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
    let base = &source[source.find("[agents.alice]").unwrap()..];
    let source = format!(
        "{}\n{base}\n[agents.alice.services.fixture]\ncapability='invoke'\n",
        toml::to_string(&named).unwrap()
    );
    crate::apply_native_policy(&proxy.runtime, &source).unwrap();
    let token = proxy
        .runtime
        .read()
        .unwrap()
        .policy
        .as_ref()
        .unwrap()
        .gateway()
        .unwrap()
        .capability_token("alice", "fixture", "invoke")
        .unwrap();
    let (status, denial) = post(
        root.path(),
        &format!("http://127.0.0.1:{port}/effect"),
        token.expose_secret(),
        "{}",
    )
    .await;
    assert_eq!(status, 403, "{denial}");
    assert_eq!(denial["action"], "deny");
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    named.rules.clear();
    let source = format!(
        "{}\n{base}\n[agents.alice.services.fixture]\ncapability='invoke'\n",
        toml::to_string(&named).unwrap()
    );
    crate::apply_native_policy(&proxy.runtime, &source).unwrap();
    let (status, reply) = post(
        root.path(),
        &format!("http://127.0.0.1:{port}/effect"),
        token.expose_secret(),
        "{}",
    )
    .await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn automatic_cli_reads_new_verifiers_and_identifies_recorded_offline_status() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
    let mut without_bindings: toml_edit::DocumentMut = source.parse().unwrap();
    without_bindings.as_table_mut().remove("work_bindings");
    crate::apply_native_policy(&proxy.runtime, &without_bindings.to_string()).unwrap();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"new verifier","factory":reference}),
        "create",
    )
    .await
    .unwrap()["work"]
        .clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"wanted"),
        "publish",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    let r = &work["acceptance_requirements"];
    let mut amend = input(&work, "set_requirements");
    for field in ["authorities", "deciders", "independent"] {
        amend[field] = r[field].clone();
    }
    amend["expected_requirements_version"] = r["version"].clone();
    amend["checks"] = json!([]);
    amend["challenges"] = json!([]);
    amend["reason"] = json!("Isolate machine status; retain the independent decider");
    submit(&proxy, root.path(), Actor::Agent(BOB), amend, "amend")
        .await
        .unwrap();
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        approval(&current_value(root.path(), id)),
        "approve",
    )
    .await
    .unwrap();
    let recorded = current_value(root.path(), id);
    assert!(
        recorded
            .get("automatic")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    );
    let show = vec!["show".into(), "owned".into(), id.into()];
    let cli = &super::super::super::work_cli::run;
    assert_eq!(
        cli(root.path(), &show).await.unwrap()["acceptance_status"]["state"],
        "accepted"
    );

    crate::apply_native_policy(&proxy.runtime, &source).unwrap();
    let live = crate::native_client::admin(
        &root.path().join("config.toml"),
        &format!("/admin/coord/rooms/owned/work?work_id={id}"),
        hyper::Method::GET,
        Value::Null,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(live["acceptance_status"]["state"], "pending");
    let required = &live["acceptance_status"]["obligations"][0];
    assert_eq!(required["binding"], "verify");
    assert_eq!(required["job"], "verify");
    assert_eq!(required["authority"]["factory"], "native");
    assert!(
        required["recovery"]
            .as_str()
            .unwrap()
            .contains("running proxy")
    );
    assert_eq!(
        cli(root.path(), &show).await.unwrap()["acceptance_status"],
        live["acceptance_status"]
    );

    let generic = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"ordinary generic work"}),
        "generic",
    )
    .await
    .unwrap()["work"]
        .clone();
    let generic = current_value(root.path(), generic["work_id"].as_str().unwrap());
    let listed = cli(root.path(), &["list".into(), "owned".into()])
        .await
        .unwrap();
    let items = listed["items"].as_array().unwrap();
    let status = &items.iter().find(|w| w["work_id"] == id).unwrap()["acceptance_status"];
    assert_eq!(status["state"], "pending");
    assert_eq!(status["recorded_state"], "accepted");
    assert!(
        status["reason"]
            .as_str()
            .unwrap()
            .contains("has not been read")
    );
    assert_eq!(
        items
            .iter()
            .find(|w| w["work_id"] == generic["work_id"])
            .unwrap()["acceptance_status"],
        generic["acceptance_status"]
    );
    let mut historical = show.clone();
    historical.extend(["--version".into(), recorded["version"].to_string()]);
    let mut historical_record = recorded.clone();
    historical_record
        .as_object_mut()
        .unwrap()
        .remove("acceptance_status");
    assert_eq!(
        cli(root.path(), &historical).await.unwrap(),
        historical_record,
        "historical reads keep their recorded meaning"
    );
    proxy.shutdown().await;
    let offline = cli(root.path(), &show).await.unwrap();
    assert_eq!(offline["acceptance_status"]["state"], "pending");
    assert_eq!(offline["acceptance_status"]["recorded_state"], "accepted");
    assert!(
        offline["acceptance_status"]["reason"]
            .as_str()
            .unwrap()
            .contains("proxy is running")
    );
    assert_eq!(current_value(root.path(), id), recorded);
}

#[tokio::test]
async fn automatic_current_authority_read_invalidates_a_previously_accepted_finding() {
    let provider = Provider::start().await;
    let (root, proxy, reference) = fixture_proxy(&provider).await;
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        json!({"action":"create","title":"current authority","factory":reference}),
        "create",
    )
    .await
    .unwrap()["work"]
        .clone();
    let work = submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        input(&work, "claim"),
        "claim",
    )
    .await
    .unwrap()["work"]
        .clone();
    let id = work["work_id"].as_str().unwrap();
    submit(
        &proxy,
        root.path(),
        Actor::Agent(ALICE),
        publication(&work, b"wanted"),
        "publish",
    )
    .await
    .unwrap();
    let work = current_value(root.path(), id);
    let r = &work["acceptance_requirements"];
    let mut amend = input(&work, "set_requirements");
    for field in ["authorities", "deciders", "independent"] {
        amend[field] = r[field].clone();
    }
    amend["expected_requirements_version"] = r["version"].clone();
    amend["checks"] = json!([]);
    amend["challenges"] = json!([]);
    amend["reason"] =
        json!("Controlled machine-only obligation; independent reviewer remains decider");
    submit(&proxy, root.path(), Actor::Agent(BOB), amend, "amend")
        .await
        .unwrap();
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        approval(&current_value(root.path(), id)),
        "approve",
    )
    .await
    .unwrap();
    let url = format!("/admin/coord/rooms/owned/work?work_id={id}");
    let work = crate::native_client::admin(
        &root.path().join("config.toml"),
        &url,
        hyper::Method::GET,
        Value::Null,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(work["acceptance_status"]["state"], "accepted");
    let source = fs::read_to_string(root.path().join("policy.toml")).unwrap();
    let changed = source.replace("adopted-1", "adopted-2");
    assert_ne!(source, changed);
    crate::apply_native_policy(&proxy.runtime, &changed).unwrap();
    let work = crate::native_client::admin(
        &root.path().join("config.toml"),
        &url,
        hyper::Method::GET,
        Value::Null,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(work["acceptance_status"]["state"], "pending");
    assert_eq!(
        work["automatic"][0]["state"], "satisfied",
        "retain the historical finding separately from current applicability"
    );
    assert_eq!(
        work["acceptance_status"]["obligations"][0]["status"],
        "pending"
    );
    let mut removed: toml_edit::DocumentMut = changed.parse().unwrap();
    removed.as_table_mut().remove("work_bindings");
    let removed = removed.to_string();
    crate::apply_native_policy(&proxy.runtime, &removed).unwrap();
    // Current operator selection controls enforcement; an old binding is not permanent policy.
    // Its cancellation still needs the live authority, not merely a changed saved file.
    let before = current_value(root.path(), id);
    let mut conn = crate::coord_rooms::open(root.path()).unwrap();
    assert!(
        mutate(
            Some((root.path(), &root.path().join("policy.toml"))),
            &mut conn,
            "owned",
            Actor::Agent(BOB),
            serde_json::from_value(approval(&before)).unwrap(),
            Some("offline-remove"),
        )
        .is_err()
    );
    drop(conn);
    submit(
        &proxy,
        root.path(),
        Actor::Agent(BOB),
        approval(&before),
        "current-policy-removal",
    )
    .await
    .unwrap();
    let work = crate::native_client::admin(
        &root.path().join("config.toml"),
        &url,
        hyper::Method::GET,
        Value::Null,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(work["acceptance_status"]["state"], "accepted");
    assert_eq!(work["automatic"][0]["state"], "cancelled");
    // Adding a selected verifier later must also make current acceptance pending.
    crate::apply_native_policy(&proxy.runtime, &source).unwrap();
    let work = crate::native_client::admin(
        &root.path().join("config.toml"),
        &url,
        hyper::Method::GET,
        Value::Null,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(work["acceptance_status"]["state"], "pending");
    assert_eq!(
        work["acceptance_status"]["obligations"][0]["state"],
        "pending"
    );
    proxy.shutdown().await;
}
