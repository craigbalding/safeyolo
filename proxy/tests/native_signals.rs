//! Real KV push, local policy activation and existing approval/effect owners.
use safeyolo_proxy::{
    Proxy, coord_rooms, native_config,
    signals::{Evidence, Subject, Update},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};
#[cfg(target_os = "linux")]
#[path = "support/controlled_runs.rs"]
mod controlled_runs;

const ALICE: &str = "ag-11111111111111111111111111111111";
const BOB: &str = "ag-22222222222222222222222222222222";
// Reuse the repository's native-artifact binding to exercise an installed package.
fn native_binary(name: &str, built: &str) -> PathBuf {
    std::env::var_os("SAFEYOLO_NATIVE_ARTIFACTS")
        .map(|directory| PathBuf::from(directory).join(name))
        .unwrap_or_else(|| PathBuf::from(built))
}
struct NatsCleanup(PathBuf);
impl Drop for NatsCleanup {
    fn drop(&mut self) {
        let _ =
            std::process::Command::new(native_binary("safeyolo", env!("CARGO_BIN_EXE_safeyolo")))
                .arg("--root")
                .arg(&self.0)
                .args(["coord", "stop"])
                .output();
    }
}
fn now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}
async fn cli(root: &Path, args: &[&str]) -> Output {
    tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(native_binary("safeyolo", env!("CARGO_BIN_EXE_safeyolo")))
            .arg("--root")
            .arg(root)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
async fn origin() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut byte = [0; 1];
                while !bytes.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    bytes.push(byte[0]);
                }
                let body = if String::from_utf8_lossy(&bytes).contains("/maintained-list") {
                    "http-listed.test\n"
                } else {
                    "ok"
                };
                let _ = stream
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes())
                    .await;
            });
        }
    });
    (address, task)
}
#[cfg(target_os = "linux")]
fn process_sample() -> (u64, u64) {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let fields = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let ticks = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    (rss, ticks)
}
fn config(root: &Path, parent: &str, service: bool) {
    fs::write(root.join("config.toml"),format!("admin_port=0\nflow_store_enabled=false\nparent_proxy={}\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n{}",json!(parent),
        if service{"[[ingress_bindings]]\nname='selected-web'\nagent='alice'\nlisten='127.0.0.1:0'\n"}else{""})).unwrap();
}
fn feed_config(root: &Path) {
    let mut text = String::new();
    for name in ["shared", "quarantine", "approved"] {
        text.push_str(&format!(
            r#"
[sources.{name}]
endpoint='https://fixture.invalid/{name}'
distributed=true
format='domains'
scope='hostname'
cadence_seconds=3600
max_age_seconds=3600
timeout_seconds=1
max_bytes=16384
min_entries=1
max_entries=100
max_change_percent=100
retry_seconds=1
max_retry_seconds=2
on_stale='retain'
on_unavailable='deny'
"#
        ));
    }
    fs::write(root.join("policy-feeds.toml"), text).unwrap();
    fs::write(
        root.join("policy.toml"),
        format!(
            r#"
[agents.alice]
agent_id='{ALICE}'
[agents.bob]
agent_id='{BOB}'
[lists]
shared={{feed='shared'}}
quarantine={{feed='quarantine'}}
approved={{feed='approved'}}
[hosts.'*']
egress='allow'
unknown_creds='allow'
[hosts.'$shared']
egress='deny'
[agents.alice.hosts.'$quarantine']
egress='deny'
[agents.alice.hosts.'$approved']
egress='deny'
"#
        ),
    )
    .unwrap();
}
fn signal_config(root: &Path, port: u16, credentials: &Path, authority: &str) -> PathBuf {
    let source = |keys: &str, list: Option<&str>| {
        let mut value = json!({"endpoint":{"mode":"loopback","url":format!("nats://127.0.0.1:{port}")},"username":"safeyolo","credential_file":credentials,
        "bucket":"signals","keys":keys,"source_id":"fixture","max_bytes":16384,"max_signals":100,"max_age_seconds":3600,"retry_seconds":1});
        if let Some(list) = list {
            value["list"] = json!(list);
        }
        value
    };
    let value = json!({"sources":{"list":source("lists.>",Some("shared")),"advisories":source("advisories.>",None)},
        "rules":{"web":{"source":"advisories","agents":["alice","bob"],"min_severity":7,"distribution":"debian:trixie","authority":authority,
            "on_stale":"release","on_inactive":"release","response":{"kind":"list","feeds":{"alice":"quarantine","bob":"approved"},"body":"blocked.test\n"}}}});
    let file = root.join("signal-input.toml");
    let typed: toml::Value = serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
    fs::write(&file, toml::to_string(&typed).unwrap()).unwrap();
    file
}
async fn request(root: &Path, agent: &str, host: &str) -> u16 {
    let mut stream = UnixStream::connect(root.join(format!("{agent}.sock")))
        .await
        .unwrap();
    stream
        .write_all(
            format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&bytes)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
async fn drive(
    proxies: &mut [&mut Proxy],
    root: &Path,
    description: &str,
    condition: impl Fn() -> bool,
) {
    let started = Instant::now();
    while !condition() {
        for proxy in proxies.iter_mut() {
            proxy.reload_policy_if_changed().await.unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{description}; retained status={}",
            safeyolo_proxy::signals::status(root).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
fn revision(root: &Path, source: &str, id: &str) -> u64 {
    safeyolo_proxy::signals::status(root).unwrap()["sources"][source]["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["evidence"]["id"] == id)
        .and_then(|entry| entry["evidence"]["revision"].as_u64())
        .unwrap_or(0)
}
fn membership(root: &Path, name: &str) -> Option<usize> {
    fs::read(root.join(format!("data/policy-feeds/{name}/accepted.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|v| v["entries"].as_array().map(Vec::len))
}
async fn publish(kv: &async_nats::jetstream::kv::Store, update: &Update) {
    kv.put(&update.id, serde_json::to_vec(update).unwrap().into())
        .await
        .unwrap();
}
fn response(root: &Path) -> Value {
    fs::read(root.join("data/signals/responses/web/alice.json"))
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap_or(Value::Null)
}
async fn configure_change(root: &Path, change: impl FnOnce(&mut toml::Value)) {
    let mut value: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("signals.toml")).unwrap()).unwrap();
    change(&mut value);
    let file = root.join("changed-signals.toml");
    fs::write(&file, toml::to_string(&value).unwrap()).unwrap();
    success(cli(root, &["signals", "configure", file.to_str().unwrap()]).await);
}
fn advisory(revision: u64, severity: u8) -> Update {
    Update {
        source_id: "fixture".into(),
        id: "advisories.debian.web".into(),
        revision,
        observed_at: now(),
        expires_at: now() + 3600,
        withdrawn: false,
        evidence_refs: vec!["fixture:service-advisory".into()],
        evidence: Evidence::Advisory {
            distribution: Some("debian:trixie".into()),
            severity: severity.into(),
            subject: Subject::Service {
                name: "selected-web".into(),
            },
        },
    }
}

#[test]
fn advisory_numeric_wire_round_trips_with_the_current_json_features() {
    for severity in [9.0, 8.5] {
        let mut update = advisory(1, 9);
        if let Evidence::Advisory {
            severity: score, ..
        } = &mut update.evidence
        {
            *score = severity;
        }
        let bytes = serde_json::to_vec(&update).unwrap();
        let received: Update = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(received, update);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the approved NATS binary via SAFEYOLO_COORD_NATS_BINARY"]
async fn push_two_instances_recovery_local_changes_and_real_scoped_response() {
    let binary =
        PathBuf::from(std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("pinned NATS binary"));
    let temp = tempfile::Builder::new()
        .prefix("signals-native-")
        .tempdir()
        .unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    for root in [&a, &b] {
        success(cli(root, &["init"]).await);
    }
    let (parent, origin) = origin().await;
    for root in [&a, &b] {
        config(root, &parent, false);
        feed_config(root);
    }
    let available = || {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let port = available();
    let monitor = available();
    coord_rooms::start(&a, Some(&binary), Some(port), Some(monitor))
        .await
        .unwrap();
    let _cleanup = NatsCleanup(a.clone());
    let credentials = a.join("data/coord/nats/creds");
    let password = fs::read_to_string(&credentials).unwrap();
    let connection = async_nats::ConnectOptions::with_user_and_password(
        "safeyolo".into(),
        password.trim().into(),
    )
    .connect(format!("nats://127.0.0.1:{port}"))
    .await
    .unwrap();
    let kv = async_nats::jetstream::new(connection)
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: "signals".into(),
            history: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    let mut ap = Proxy::start(native_config::read(&a.join("config.toml")).unwrap())
        .await
        .unwrap();
    let mut bp = Proxy::start(native_config::read(&b.join("config.toml")).unwrap())
        .await
        .unwrap();
    #[cfg(target_os = "linux")]
    let baseline = {
        let before = process_sample();
        let start = Instant::now();
        for _ in 0..15 {
            ap.reload_policy_if_changed().await.unwrap();
            bp.reload_policy_if_changed().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let after = process_sample();
        (after.0, after.1 - before.1, start.elapsed().as_secs_f64())
    };
    for root in [&a, &b] {
        let file = signal_config(root, port, &credentials, "standing");
        success(cli(root, &["signals", "configure", file.to_str().unwrap()]).await);
    }
    // Current-state list arrives while both existing watches remain connected.
    for _ in 0..10 {
        ap.reload_policy_if_changed().await.unwrap();
        bp.reload_policy_if_changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    #[cfg(target_os = "linux")]
    {
        let active = process_sample();
        let start = Instant::now();
        for _ in 0..15 {
            ap.reload_policy_if_changed().await.unwrap();
            bp.reload_policy_if_changed().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let idle = process_sample();
        println!(
            "SIGNALS_RESOURCE_OBSERVATION baseline_two_proxies_rss_kib={} baseline_cpu_ticks={} baseline_seconds={:.3} active_four_watches_rss_kib={} idle_end_rss_kib={} idle_cpu_ticks={} idle_seconds={:.3} clock_ticks_per_second={}",
            baseline.0,
            baseline.1,
            baseline.2,
            active.0,
            idle.0,
            idle.1 - active.1,
            start.elapsed().as_secs_f64(),
            unsafe { libc::sysconf(libc::_SC_CLK_TCK) }
        );
    }
    let list = Update {
        source_id: "fixture".into(),
        id: "lists.current".into(),
        revision: 1,
        observed_at: now() - 30,
        expires_at: now() + 3600,
        withdrawn: false,
        evidence_refs: vec!["fixture:list".into()],
        evidence: Evidence::List {
            body: "listed.test\n".into(),
        },
    };
    publish(&kv, &list).await;
    drive(&mut [&mut ap, &mut bp], &a, "both list snapshots", || {
        revision(&a, "list", "lists.current") == 1 && revision(&b, "list", "lists.current") == 1
    })
    .await;
    for proxy in [&mut ap, &mut bp] {
        proxy.reload_policy_if_changed().await.unwrap();
    }
    assert_eq!(request(&a, "alice", "listed.test").await, 403);
    assert_eq!(request(&b, "alice", "listed.test").await, 403);
    assert_eq!(request(&a, "alice", "other.test").await, 200);
    let finding = advisory(1, 9);
    publish(&kv, &finding).await;
    drive(
        &mut [&mut ap, &mut bp],
        &a,
        "connected advisory arrival",
        || revision(&a, "advisories", &finding.id) == 1 && membership(&a, "quarantine") == Some(0),
    )
    .await;
    assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    // No republish: a newly listening local service makes this finding apply.
    config(&a, &parent, true);
    ap.reload(native_config::read(&a.join("config.toml")).unwrap())
        .await
        .unwrap();
    drive(
        &mut [&mut ap],
        &a,
        "existing finding applies to new service",
        || membership(&a, "quarantine") == Some(1),
    )
    .await;
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(request(&a, "alice", "blocked.test").await, 403);
    assert_eq!(request(&a, "bob", "blocked.test").await, 200);
    assert_eq!(request(&b, "alice", "blocked.test").await, 200);
    // Duplicate delivery cannot renew evidence or create another response episode.
    let before = fs::read(a.join("data/signals/responses/web/alice.json")).unwrap();
    publish(&kv, &finding).await;
    for _ in 0..4 {
        ap.reload_policy_if_changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let after: Value =
        serde_json::from_slice(&fs::read(a.join("data/signals/responses/web/alice.json")).unwrap())
            .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&before).unwrap()["episode"],
        after["episode"]
    );
    let correction = advisory(2, 3);
    publish(&kv, &correction).await;
    drive(
        &mut [&mut ap],
        &a,
        "below-threshold correction releases",
        || revision(&a, "advisories", &finding.id) == 2 && membership(&a, "quarantine") == Some(0),
    )
    .await;
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    // Stop one consumer, publish current state once, recover without republishing.
    bp.shutdown().await;
    let mut list2 = list.clone();
    list2.revision = 2;
    list2.evidence = Evidence::List {
        body: "new-listed.test\n".into(),
    };
    publish(&kv, &list2).await;
    bp = Proxy::start(native_config::read(&b.join("config.toml")).unwrap())
        .await
        .unwrap();
    drive(
        &mut [&mut ap, &mut bp],
        &b,
        "restarted consumer recovers current list",
        || revision(&b, "list", "lists.current") == 2,
    )
    .await;
    bp.reload_policy_if_changed().await.unwrap();
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(request(&b, "alice", "new-listed.test").await, 403);
    assert_eq!(request(&b, "alice", "listed.test").await, 200);
    assert_eq!(
        safeyolo_proxy::signals::status(&b).unwrap()["sources"]["list"]["accepted"][0]["evidence"]
            ["observed_at"],
        list.observed_at
    );
    // A disconnected broker does not sit on the policy admission path.
    coord_rooms::stop(&a).await.unwrap();
    assert_eq!(request(&a, "alice", "listed.test").await, 200);
    assert_eq!(request(&b, "alice", "new-listed.test").await, 403);
    coord_rooms::start(&a, Some(&binary), Some(port), Some(monitor))
        .await
        .unwrap();
    let withdrawn = {
        let mut value = advisory(3, 9);
        value.withdrawn = true;
        value
    };
    publish(&kv, &withdrawn).await;
    drive(
        &mut [&mut ap, &mut bp],
        &a,
        "broker reconnect recovers withdrawal",
        || {
            revision(&a, "advisories", &finding.id) == 3
                && revision(&b, "advisories", &finding.id) == 3
        },
    )
    .await;
    // An operator-selected approval is scoped to the original finding.
    configure_change(&a, |v| {
        v["rules"]["web"]["authority"] = toml::Value::String("approval".into())
    })
    .await;
    publish(&kv, &advisory(4, 9)).await;
    drive(&mut [&mut ap], &a, "one pending scoped approval", || {
        response(&a)["status"] == "pending_approval"
    })
    .await;
    let mut old = response(&a)["approval_id"].as_str().unwrap().to_owned();
    assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    for _ in 0..3 {
        ap.reload_policy_if_changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(response(&a)["approval_id"], old);
    let preview: Value = serde_json::from_str(&success(
        cli(&a, &["approvals", "show", &old, "--json"]).await,
    ))
    .unwrap();
    assert_eq!(
        preview["action"]["findings"][0]["evidence"]["subject"]["name"],
        "selected-web"
    );
    let original_expiry = preview["authority"]["expires_at"].clone();
    publish(&kv, &advisory(5, 9)).await;
    drive(&mut [&mut ap],&a,"unchanged finding revision reuses pending approval",||{
        revision(&a,"advisories",&finding.id)==5
            && safeyolo_proxy::signals::status(&a).unwrap()["responses"][0]["selection"]["findings"][0]["revision"]==5
    }).await;
    assert_eq!(response(&a)["approval_id"], old);
    let preview: Value = serde_json::from_str(&success(
        cli(&a, &["approvals", "show", &old, "--json"]).await,
    ))
    .unwrap();
    assert_eq!(preview["authority"]["expires_at"], original_expiry);
    // An unchanged finding cannot carry an old approval into a broader effect.
    let authored = fs::read_to_string(a.join("policy.toml")).unwrap();
    fs::write(
        a.join("policy.toml"),
        format!("{authored}\n[hosts.'$quarantine']\negress='deny'\n"),
    )
    .unwrap();
    drive(
        &mut [&mut ap],
        &a,
        "changed policy scope replaces pending approval",
        || response(&a)["status"] == "pending_approval" && response(&a)["approval_id"] != old,
    )
    .await;
    let stale = cli(
        &a,
        &["approvals", "approve", &old, "--option", "once", "--json"],
    )
    .await;
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&stale.stdout),
            String::from_utf8_lossy(&stale.stderr)
        )
        .contains("superseded")
    );
    old = response(&a)["approval_id"].as_str().unwrap().to_owned();
    fs::write(a.join("policy.toml"), authored).unwrap();
    drive(
        &mut [&mut ap],
        &a,
        "restored scope needs its current approval",
        || response(&a)["status"] == "pending_approval" && response(&a)["approval_id"] != old,
    )
    .await;
    old = response(&a)["approval_id"].as_str().unwrap().to_owned();
    publish(&kv, &advisory(6, 2)).await;
    drive(
        &mut [&mut ap],
        &a,
        "correction before delayed approval",
        || revision(&a, "advisories", &finding.id) == 6 && response(&a)["active"] == false,
    )
    .await;
    let delayed = cli(
        &a,
        &["approvals", "approve", &old, "--option", "once", "--json"],
    )
    .await;
    let delayed = format!(
        "{}{}",
        String::from_utf8_lossy(&delayed.stdout),
        String::from_utf8_lossy(&delayed.stderr)
    );
    assert!(
        delayed.to_ascii_lowercase().contains("superseded"),
        "{delayed}"
    );
    assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    publish(&kv, &advisory(7, 9)).await;
    drive(
        &mut [&mut ap],
        &a,
        "fresh approval after changed evidence",
        || response(&a)["status"] == "pending_approval" && response(&a)["approval_id"] != old,
    )
    .await;
    let approved = response(&a)["approval_id"].as_str().unwrap().to_owned();
    success(cli(&a, &["approvals", "show", &approved, "--json"]).await);
    success(
        cli(
            &a,
            &[
                "approvals",
                "approve",
                &approved,
                "--option",
                "once",
                "--json",
            ],
        )
        .await,
    );
    drive(&mut [&mut ap], &a, "approved real response", || {
        response(&a)["status"] == "verified" && membership(&a, "quarantine") == Some(1)
    })
    .await;
    assert_eq!(request(&a, "alice", "blocked.test").await, 403);
    let episode = response(&a)["episode"].clone();
    success(
        cli(
            &a,
            &[
                "approvals",
                "approve",
                &approved,
                "--option",
                "once",
                "--json",
            ],
        )
        .await,
    );
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(response(&a)["episode"], episode);
    // Authenticated assertions still cannot supply commands or another source.
    let mut forged = advisory(8, 9);
    forged.source_id = "forged".into();
    publish(&kv, &forged).await;
    let mut command = json!(advisory(9, 9));
    command["command"] = json!("stop all agents");
    kv.put(&finding.id, serde_json::to_vec(&command).unwrap().into())
        .await
        .unwrap();
    for _ in 0..5 {
        ap.reload_policy_if_changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(revision(&a, "advisories", &finding.id), 7);
    assert_eq!(response(&a)["episode"], episode);
    assert!(
        async_nats::ConnectOptions::with_user_and_password(
            "safeyolo".into(),
            "unauthorised-fixture".into()
        )
        .connect(format!("nats://127.0.0.1:{port}"))
        .await
        .is_err()
    );
    // Expiry changes desired state without a source publication at the deadline.
    let mut expiring = advisory(10, 9);
    expiring.expires_at = now() + 2;
    publish(&kv, &expiring).await;
    drive(&mut [&mut ap], &a, "expiring evidence arrived", || {
        revision(&a, "advisories", &finding.id) == 10
    })
    .await;
    drive(
        &mut [&mut ap],
        &a,
        "expiry releases adopted temporary response",
        || response(&a)["active"] == false && membership(&a, "quarantine") == Some(0),
    )
    .await;
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    // A failed existing-owner request stays failed and does not report success.
    configure_change(&a,|v|{
        v["rules"]["web"]["authority"]=toml::Value::String("standing".into());
        v["rules"]["web"]["response"]=toml::from_str(&format!("kind='work'\nroom='missing'\nassignee='{ALICE}'\ntitle='Assess selected signal'\nrequirement='https://fixture.invalid/requirement'\n")).unwrap();
    }).await;
    publish(&kv, &advisory(11, 9)).await;
    drive(&mut [&mut ap], &a, "failed Work owner is explicit", || {
        response(&a)["status"] == "failed"
    })
    .await;
    let failed = response(&a);
    ap.reload_policy_if_changed().await.unwrap();
    assert_eq!(response(&a)["episode"], failed["episode"]);
    // Notification and Work dispatch use retained canonical owner receipts.
    coord_rooms::create_room(&a, "responses").await.unwrap();
    coord_rooms::grant(
        &a.join("config.toml"),
        "responses",
        "alice",
        &["send".into(), "receive".into()],
        false,
        None,
    )
    .unwrap();
    configure_change(&a, |v| {
        v["rules"]["web"]["response"]["room"] = toml::Value::String("responses".into())
    })
    .await;
    drive(&mut [&mut ap], &a, "assigned existing-owner Work", || {
        response(&a)["status"] == "dispatched"
    })
    .await;
    let db = rusqlite::Connection::open(a.join("data/coord/v0.db")).unwrap();
    let work_count = || {
        db.query_row("SELECT count(*) FROM coord_work", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    };
    assert_eq!(work_count(), 1);
    let dispatched = response(&a);
    let notification = &dispatched["result"]["input"];
    assert_eq!(notification["attention_intent"]["mode"], "targeted");
    assert_eq!(
        notification["attention_recipients"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(notification["attention_recipients"][0]["agent_id"], ALICE);
    let attention = notification["attention_recipients"][0]["attention_id"]
        .as_str()
        .unwrap();
    let retained: (String, String, i64) = db.query_row(
        "SELECT recipient_agent_id,object_id,revision_or_sequence FROM coord_attention_edges WHERE attention_id=?1 AND kind='message'",
        [attention], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(retained.0, ALICE);
    assert_eq!(retained.1, notification["envelope"]["msg_id"]);
    assert_eq!(retained.2, notification["sequence"].as_i64().unwrap());
    publish(&kv, &advisory(12, 9)).await;
    drive(
        &mut [&mut ap],
        &a,
        "unchanged finding revision reuses Work",
        || {
            safeyolo_proxy::signals::status(&a).unwrap()["responses"][0]["selection"]["findings"][0]
                ["revision"]
                == 12
        },
    )
    .await;
    for _ in 0..5 {
        ap.reload_policy_if_changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(response(&a)["episode"], dispatched["episode"]);
    assert_eq!(work_count(), 1);
    // The same retained finding follows actual effective package changes, without
    // a new publication or a desired-image manifest standing in for the guest.
    #[cfg(target_os = "linux")]
    {
        let generation = "1234567890abcdef1234567890abcdef";
        let _run = controlled_runs::agent_run(&a, "alice", ALICE, generation);
        let inventory = a.join("effective-inventory.json");
        let write_inventory = |version: Option<&str>, run: &str| {
            let packages = version
                .map(|v| json!({"curl":v}))
                .unwrap_or_else(|| json!({}));
            fs::write(&inventory,json!({"agent_id":ALICE,"run_id":run,"observed_at":now(),"distribution":"debian:trixie","packages":packages,"services":[]}).to_string()).unwrap();
        };
        write_inventory(Some("8.0-1"), generation);
        configure_change(&a,|v|{
            v["rules"]["web"]["response"]=toml::from_str("kind='list'\nbody='blocked.test\\n'\n[feeds]\nalice='quarantine'\nbob='approved'\n").unwrap();
            v["rules"]["web"]["response"]["body"]=toml::Value::String("blocked.test\n".into());
            v["rules"]["web"].as_table_mut().unwrap().insert("inventory".into(),toml::Value::String(inventory.to_str().unwrap().into()));
            v["rules"]["web"].as_table_mut().unwrap().insert("inventory_max_age_seconds".into(),toml::Value::Integer(60));
        }).await;
        let mut package = advisory(13, 9);
        package.evidence = Evidence::Advisory {
            distribution: Some("debian:trixie".into()),
            severity: 9.0,
            subject: Subject::Package {
                name: "curl".into(),
                distribution: "debian:trixie".into(),
                fixed_version: "8.0-1+deb13u1".into(),
            },
        };
        publish(&kv, &package).await;
        drive(
            &mut [&mut ap],
            &a,
            "effective vulnerable package applies",
            || response(&a)["status"] == "verified" && response(&a)["active"] == true,
        )
        .await;
        assert_eq!(request(&a, "alice", "blocked.test").await, 403);
        assert_eq!(request(&a, "bob", "blocked.test").await, 200);
        write_inventory(Some("8.0-1+deb13u1"), generation);
        drive(
            &mut [&mut ap],
            &a,
            "effective package repair releases without republish",
            || response(&a)["status"] == "verified" && response(&a)["active"] == false,
        )
        .await;
        assert_eq!(request(&a, "alice", "blocked.test").await, 200);
        write_inventory(Some("8.0-1"), "replaced-run");
        drive(&mut [&mut ap],&a,"replaced inventory stays unknown",||{
            safeyolo_proxy::signals::status(&a).unwrap()["responses"][0]["selection"]["applicability"]=="unknown_or_stale"
        }).await;
        assert_eq!(request(&a, "alice", "blocked.test").await, 200);
    }
    let work: String = db
        .query_row("SELECT document_json FROM coord_work", [], |row| row.get(0))
        .unwrap();
    let work: Value = serde_json::from_str(&work).unwrap();
    assert_eq!(work["assignee"]["id"], ALICE);
    assert!(
        work["external_ref"]
            .as_str()
            .unwrap()
            .starts_with("coord://responses/")
    );
    assert!(!work["external_ref"].as_str().unwrap().ends_with("null"));
    for _ in 0..3 {
        ap.reload_policy_if_changed().await.unwrap();
    }
    assert_eq!(work_count(), 1);
    // The established HTTP acquisition owner publishes a complete accepted view;
    // the same two receivers adopt it with no new transport on their request path.
    let publisher = temp.path().join("publisher");
    success(cli(&publisher, &["init"]).await);
    feed_config(&publisher);
    let mut sources: toml::Value =
        toml::from_str(&fs::read_to_string(a.join("signals.toml")).unwrap()).unwrap();
    sources.as_table_mut().unwrap().remove("rules");
    sources["sources"]
        .as_table_mut()
        .unwrap()
        .retain(|key, _| key == "list");
    sources["sources"]["list"]
        .as_table_mut()
        .unwrap()
        .remove("list");
    sources["sources"]["list"]
        .as_table_mut()
        .unwrap()
        .insert("follow".into(), toml::Value::Boolean(false));
    let input = publisher.join("signal-input.toml");
    fs::write(&input, toml::to_string(&sources).unwrap()).unwrap();
    success(
        cli(
            &publisher,
            &["signals", "configure", input.to_str().unwrap()],
        )
        .await,
    );
    let mut feeds: toml::Value =
        toml::from_str(&fs::read_to_string(publisher.join("policy-feeds.toml")).unwrap()).unwrap();
    feeds["sources"]["shared"]["distributed"] = toml::Value::Boolean(false);
    feeds["sources"]["shared"]["endpoint"] =
        toml::Value::String("http://feeds.test/maintained-list".into());
    feeds["sources"]["shared"].as_table_mut().unwrap().insert(
        "publish".into(),
        toml::from_str("source='list'\nkey='lists.current'").unwrap(),
    );
    let input = publisher.join("feed-input.toml");
    fs::write(&input, toml::to_string(&feeds).unwrap()).unwrap();
    let acquisition =
        tokio::process::Command::new(native_binary("safeyolo", env!("CARGO_BIN_EXE_safeyolo")))
            .arg("--root")
            .arg(&publisher)
            .args(["policy", "feeds", "configure"])
            .arg(&input)
            .env("http_proxy", &parent)
            .env("https_proxy", &parent)
            .env("HTTP_PROXY", &parent)
            .env("HTTPS_PROXY", &parent)
            .output()
            .await
            .unwrap();
    success(acquisition);
    drive(
        &mut [&mut ap, &mut bp],
        &a,
        "HTTP accepted view distributes to both consumers",
        || revision(&a, "list", "lists.current") == 3 && revision(&b, "list", "lists.current") == 3,
    )
    .await;
    ap.reload_policy_if_changed().await.unwrap();
    bp.reload_policy_if_changed().await.unwrap();
    assert_eq!(request(&a, "alice", "http-listed.test").await, 403);
    assert_eq!(request(&b, "alice", "http-listed.test").await, 403);
    let published: Value = serde_json::from_slice(
        &fs::read(publisher.join("data/policy-feeds/shared/accepted.json")).unwrap(),
    )
    .unwrap();
    let received: Value = serde_json::from_slice(
        &fs::read(b.join("data/policy-feeds/shared/accepted.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        received["provider_observed_at"],
        published["evidence_first_observed_at"]
    );
    // A standalone native proxy must follow its timer without a test driver
    // calling reload. With SAFEYOLO_NATIVE_ARTIFACTS this executes packaged bytes.
    let standalone = temp.path().join("standalone");
    success(cli(&standalone, &["init"]).await);
    config(&standalone, &parent, false);
    feed_config(&standalone);
    let input = signal_config(&standalone, port, &credentials, "standing");
    success(
        cli(
            &standalone,
            &["signals", "configure", input.to_str().unwrap()],
        )
        .await,
    );
    let mut child = tokio::process::Command::new(native_binary(
        "safeyolo-proxy",
        env!("CARGO_BIN_EXE_safeyolo-proxy"),
    ))
    .arg("--config")
    .arg(standalone.join("config.toml"))
    .stdout(std::process::Stdio::null())
    .stderr(fs::File::create(standalone.join("proxy-stderr.log")).unwrap())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    drive(
        &mut [],
        &standalone,
        "standalone proxy recovers current accepted view",
        || revision(&standalone, "list", "lists.current") == 3,
    )
    .await;
    assert_eq!(request(&standalone, "alice", "http-listed.test").await, 403);
    let mut pushed = list2.clone();
    pushed.revision = 4;
    pushed.observed_at = now();
    pushed.expires_at = now() + 3600;
    pushed.evidence = Evidence::List {
        body: "standalone.test\n".into(),
    };
    publish(&kv, &pushed).await;
    drive(
        &mut [],
        &standalone,
        "standalone connected push activates automatically",
        || revision(&standalone, "list", "lists.current") == 4,
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let added = request(&standalone, "alice", "standalone.test").await;
        let removed = request(&standalone, "alice", "http-listed.test").await;
        if added == 403 && removed == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "standalone network policy did not activate pushed revision: added={added}, removed={removed}; retained status={}",
            safeyolo_proxy::signals::status(&standalone).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    child.kill().await.unwrap();
    ap.shutdown().await;
    bp.shutdown().await;
    coord_rooms::stop(&a).await.unwrap();
    origin.abort();
}
