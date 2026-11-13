//! Exercise live collection through the ordinary native proxy and gateway.
use super::*;
use crate::policy::checks::{Candidate, Evidence};
use std::{collections::BTreeMap, path::Path, sync::atomic::AtomicUsize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::Notify,
};

fn definition(port: u16, timeout_ms: u64) -> serde_json::Value {
    json!({"source_id":"owned-assessor","meaning":"positive is a controlled threat finding", "subject":"hostname",
        "result_type":"finding","influences":["hard_exclusion"],"implementation_version":"adapter-1",
        "configuration_version":"selected-1","max_age_seconds":1,
        "source":{"kind":"service","operation":{"gate_id":"assess","service":"assessor","capability":"reader",
            "endpoint":format!("http://127.0.0.1:{port}"),"method":"GET","path":"/check/{subject}","effects":"active","mapping":"typed"},
            "limits":{"timeout_ms":timeout_ms,"max_input_bytes":2048,"max_output_bytes":1024,"max_concurrent":1,"max_pending":1,"max_cached":8}}})
}
fn candidate(host: &str) -> Candidate {
    serde_json::from_value(
        json!({"agent":"alice","host":host,"port":443,"scheme":"https","method":"GET","path":"/","ip":"192.0.2.8"}),
    )
    .unwrap()
}
fn setup(root: &Path, definition: serde_json::Value, scoped: bool, grant: bool) -> crate::Config {
    let mut rule = json!({"name":"exclude","host":"*","stage":"connect","influence":"hard_exclusion","priority":0,
        "required":true,"when":{"op":"finding","check":"assess"},"on_match":"deny","on_unavailable":"unresolved"});
    if scoped {
        rule["agent"] = json!("alice");
    }
    test_policy(root, json!({"assess":definition}), vec![rule]);
    let config = test_configuration(
        root,
        "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n",
    );
    std::fs::write(root.join("services/assessor.yaml"),"schema_version: 1\nname: assessor\ndefault_host: 127.0.0.1\ncapabilities:\n  reader:\n    routes:\n      - methods: [GET]\n        path: /check/**\n").unwrap();
    let mut policy = std::fs::read_to_string(root.join("policy.toml")).unwrap();
    policy.push_str("\n[hosts.'127.0.0.1']\nservice='assessor'\negress='allow'\n[controls.credentials]\nenabled=false\n[controls.patterns]\nenabled=false\n");
    if grant {
        policy.push_str("\n[agents.'gate:assess'.services.assessor]\ncapability='reader'\n");
    }
    std::fs::write(root.join("policy.toml"), policy).unwrap();
    config
}
async fn read_head(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    head
}
async fn reply(socket: &mut tokio::net::TcpStream, status: u16, body: &[u8]) {
    socket
        .write_all(
            format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let _ = socket.write_all(body).await;
}
async fn collect(proxy: &crate::Proxy, host: &str) -> BTreeMap<String, Evidence> {
    let runtime = proxy.runtime.read().unwrap().clone();
    let target = candidate(host);
    runtime
        .policy
        .as_ref()
        .unwrap()
        .named_checks()
        .collect_live(
            &target.request(),
            Stage::Connect,
            &runtime,
            &proxy.runtime,
            &[],
        )
        .await
        .unwrap()
}
fn action(proxy: &crate::Proxy, host: &str, evidence: BTreeMap<String, Evidence>) -> Action {
    let runtime = proxy.runtime.read().unwrap().clone();
    runtime
        .policy
        .as_ref()
        .unwrap()
        .named_checks()
        .evaluate(
            &candidate(host).request(),
            Stage::Connect,
            evidence,
            crate::policy::current_time_ms() as u64,
        )
        .action
}
fn isolated(name: &str) -> bool {
    isolated_native_test(name)
}

#[tokio::test]
async fn native_live_service_preserves_typed_results_cache_freshness_and_offline_preview() {
    if isolated(
        "http::policy_checks::execution_tests::native_live_service_preserves_typed_results_cache_freshness_and_offline_preview",
    ) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = origin.accept().await.unwrap();
            let head = read_head(&mut socket).await;
            assert!(String::from_utf8_lossy(&head).starts_with("GET /check/"));
            assert!(
                String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .contains("user-agent: safeyolo-policy-check\r\n")
            );
            assert!(!String::from_utf8_lossy(&head).contains("sgw_"));
            observed.fetch_add(1, Ordering::SeqCst);
            reply(
                &mut socket,
                200,
                br#"{"finding":{"kind":"finding","positive":true},"source_revision":"fixture-v1"}"#,
            )
            .await;
        }
    });
    let config = setup(root.path(), definition(port, 3000), true, true);
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let policy = runtime.policy.as_ref().unwrap();
    let preview = policy
        .evaluate_candidate(&candidate("example.test").request())
        .await
        .unwrap();
    assert!(preview.to_string().contains("offline_unavailable"));
    assert!(preview.to_string().contains("active"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "offline preview invoked an active operation"
    );
    let started = std::time::Instant::now();
    let evidence = collect(&proxy, "example.test").await;
    assert!(
        evidence["assess"].unavailable.is_none(),
        "{:?}",
        evidence["assess"].unavailable
    );
    let execution = evidence["assess"].execution.as_ref().unwrap();
    assert_eq!(execution["kind"], "service");
    assert_eq!(execution["gate_principal"], "gate:assess");
    assert!(execution["caller_id"].as_str().unwrap().starts_with("job-"));
    assert_eq!(action(&proxy, "example.test", evidence), Action::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let evidence = collect(&proxy, "example.test").await;
    assert_eq!(evidence["assess"].acquisition, "reused_live_evidence");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < Duration::from_secs(2));
    collect(&proxy, "other.test").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "subject binding reused unrelated evidence"
    );
    tokio::time::sleep(Duration::from_millis(1050)).await;
    collect(&proxy, "example.test").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "expired evidence was reused"
    );
    proxy.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn native_live_service_distinguishes_negative_malformed_refused_and_oversized_results() {
    if isolated(
        "http::policy_checks::execution_tests::native_live_service_distinguishes_negative_malformed_refused_and_oversized_results",
    ) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let cases=[(200,br#"{"finding":{"kind":"finding","positive":false}}"#.to_vec()),(200,b"PASS".to_vec()),
            (503,b"unavailable".to_vec()),(200,vec![b'x';1025]),
            (200,br#"{"finding":{"kind":"fact","value":"PASS"}}"#.to_vec()),
            (200,br#"{"subject":{"kind":"hostname","hostname":"forged"},"finding":{"kind":"finding","positive":false}}"#.to_vec())];
        for (status, body) in cases {
            let (mut socket, _) = origin.accept().await.unwrap();
            read_head(&mut socket).await;
            reply(&mut socket, status, &body).await;
        }
    });
    let config = setup(root.path(), definition(port, 3000), true, true);
    let proxy = crate::Proxy::start(config).await.unwrap();
    for (index, expected) in [
        None,
        Some("malformed"),
        Some("provider unavailable"),
        Some("output limit"),
        Some("incompatible"),
        Some("malformed"),
    ]
    .into_iter()
    .enumerate()
    {
        let host = format!("subject-{index}.test");
        let evidence = collect(&proxy, &host).await;
        let runtime = proxy.runtime.read().unwrap().clone();
        let result = runtime.policy.as_ref().unwrap().named_checks().evaluate(
            &candidate(&host).request(),
            Stage::Connect,
            evidence,
            crate::policy::current_time_ms() as u64,
        );
        match expected {
            None => {
                assert_eq!(result.action, Action::Allow);
                assert!(matches!(
                    result.evidence["assess"].result.as_ref().unwrap().finding,
                    checks::Finding::Finding { positive: false }
                ));
            }
            Some(expected) => {
                assert_eq!(result.action, Action::Unresolved);
                assert_eq!(
                    result.evidence["assess"].execution.as_ref().unwrap()["proxy_request_started"],
                    true
                );
                assert_eq!(
                    result.evidence["assess"].execution.as_ref().unwrap()["http_status"],
                    if index == 2 { 503 } else { 200 }
                );
                assert!(
                    result.evidence["assess"]
                        .unavailable
                        .as_ref()
                        .unwrap()
                        .contains(expected),
                    "{:?}",
                    result.evidence["assess"].unavailable
                );
            }
        }
    }
    proxy.shutdown().await;
    server.await.unwrap();
}

#[tokio::test]
async fn native_live_service_missing_grants_and_cycles_fail_without_contact() {
    if isolated(
        "http::policy_checks::execution_tests::native_live_service_missing_grants_and_cycles_fail_without_contact",
    ) {
        return;
    }
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    for (scoped, grant, reason) in [
        (true, false, "missing check dependency grant"),
        (false, true, "503"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut check = definition(port, 2000);
        if !scoped {
            check["subject"] = json!("ip");
        }
        let config = setup(root.path(), check, scoped, grant);
        let proxy = crate::Proxy::start(config).await.unwrap();
        let evidence = collect(&proxy, "example.test").await;
        assert_eq!(
            action(&proxy, "example.test", evidence.clone()),
            Action::Unresolved
        );
        assert!(
            evidence["assess"]
                .unavailable
                .as_ref()
                .unwrap()
                .contains(reason),
            "{:?}",
            evidence["assess"].unavailable
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(40), origin.accept())
                .await
                .is_err()
        );
        if !scoped {
            let audit =
                std::fs::read_to_string(root.path().join("logs/audit.jsonl")).unwrap_or_default();
            assert!(
                audit.contains("recursive/cyclic check dependency"),
                "{audit}"
            );
        }
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn native_live_service_limits_pending_cancels_transport_and_discards_late_evidence() {
    if isolated(
        "http::policy_checks::execution_tests::native_live_service_limits_pending_cancels_transport_and_discards_late_evidence",
    ) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let contacted = Arc::new(Notify::new());
    let closed = Arc::new(Notify::new());
    let (seen, ended) = (contacted.clone(), closed.clone());
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        read_head(&mut socket).await;
        seen.notify_one();
        assert_eq!(
            socket.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        ended.notify_one();
        let (mut socket, _) = origin.accept().await.unwrap();
        read_head(&mut socket).await;
        reply(
            &mut socket,
            200,
            br#"{"finding":{"kind":"finding","positive":false}}"#,
        )
        .await;
    });
    let config = setup(root.path(), definition(port, 250), true, true);
    let proxy = Arc::new(crate::Proxy::start(config).await.unwrap());
    let first_proxy = proxy.clone();
    let first = tokio::spawn(async move { collect(&first_proxy, "first.test").await });
    tokio::time::timeout(Duration::from_secs(3), contacted.notified())
        .await
        .expect("check never reached provider");
    let queued_proxy = proxy.clone();
    let queued = tokio::spawn(async move { collect(&queued_proxy, "queued.test").await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let third = collect(&proxy, "third.test").await;
    assert!(
        third["assess"]
            .unavailable
            .as_ref()
            .unwrap()
            .contains("pending limit")
    );
    queued.abort();
    let _ = queued.await;
    let timed = first.await.unwrap();
    assert!(
        timed["assess"]
            .unavailable
            .as_ref()
            .unwrap()
            .contains("deadline")
    );
    tokio::time::timeout(Duration::from_secs(2), closed.notified())
        .await
        .unwrap();
    let repeated = collect(&proxy, "first.test").await;
    assert!(
        repeated["assess"].unavailable.is_none(),
        "{:?}",
        repeated["assess"].unavailable
    );
    assert_eq!(action(&proxy, "first.test", repeated), Action::Allow);
    server.await.unwrap();
    let proxy = Arc::try_unwrap(proxy).ok().unwrap();
    proxy.shutdown().await;
    assert!(
        !std::fs::read_dir(root.path().join("data"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("check-"))
    );
}

#[tokio::test]
async fn native_policy_change_during_service_wait_cannot_restore_old_admission() {
    if isolated(
        "http::policy_checks::execution_tests::native_policy_change_during_service_wait_cannot_restore_old_admission",
    ) {
        return;
    }
    // This exact-test child owns the process and its umask.
    unsafe {
        libc::umask(0);
    }
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let contacted = Arc::new(Notify::new());
    let released = Arc::new(Notify::new());
    let (seen, finish) = (contacted.clone(), released.clone());
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        read_head(&mut socket).await;
        seen.notify_one();
        finish.notified().await;
        reply(
            &mut socket,
            200,
            br#"{"finding":{"kind":"finding","positive":false}}"#,
        )
        .await;
    });
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = setup(root.path(), definition(port, 5000), true, true);
    config.parent_proxy = Some(format!("http://{}", target.local_addr().unwrap()));
    config.parent_proxy_agents = vec!["alice".into()];
    let mut proxy = crate::Proxy::start(config.clone()).await.unwrap();
    let mut socket = UnixStream::connect(root.path().join("alice.sock"))
        .await
        .unwrap();
    let policy = proxy
        .runtime
        .read()
        .unwrap()
        .policy
        .as_ref()
        .unwrap()
        .clone();
    socket.write_all(b"GET http://example.test/report HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), contacted.notified())
        .await
        .expect("check never reached provider");
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::fs::PermissionsExt;
        let directories: Vec<_> = std::fs::read_dir(root.path().join("data"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("check-")
            })
            .collect();
        assert_eq!(directories.len(), 1, "expected the held service listener");
        assert_eq!(
            directories[0].metadata().unwrap().permissions().mode() & 0o777,
            0o700,
            "service listener directory must be private under umask 000"
        );
    }
    let source = std::fs::read_to_string(root.path().join("policy.toml")).unwrap();
    std::fs::write(
        root.path().join("policy.toml"),
        source.replace("selected-1", "selected-2"),
    )
    .unwrap();
    proxy.reload(config).await.unwrap();
    released.notify_one();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(String::from_utf8_lossy(&response).contains("policy or authority changed"));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err(),
        "old permission reached assessed target"
    );
    assert!(!Arc::ptr_eq(
        &policy,
        proxy.runtime.read().unwrap().policy.as_ref().unwrap()
    ));
    socket.shutdown().await.unwrap();
    server.await.unwrap();
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(root.path().join("logs/audit.jsonl")).unwrap();
    let executions: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &serde_json::Value| event["event"] == "ops.policy_check_executed")
        .collect();
    assert!(executions.iter().any(
        |event| event["details"]["evidence"]["result"]["configuration_version"] == "selected-1"
    ));
}

fn job_configuration(linux: Option<&crate::linux_host::Settings>) -> String {
    let mut configuration = "admin_port=0\nflow_store_enabled=false\nlisteners=[]\n".to_owned();
    if let Some(linux) = linux {
        // Serialize the typed settings directly: JSON turns absent options into null.
        configuration.push_str(&toml::to_string(&BTreeMap::from([("linux", linux)])).unwrap());
    }
    configuration
}

#[test]
fn native_job_fixture_preserves_selected_optional_linux_settings() {
    for apparmor_profile in [None, Some("selected-profile".to_owned())] {
        let root = tempfile::tempdir().unwrap();
        let linux = crate::linux_host::Settings {
            host_uid: 1000,
            host_gid: 1000,
            uid_base: 100000,
            gid_base: 200000,
            runsc: "/selected/bin/runsc".into(),
            runsc_origin: "system".into(),
            apparmor_profile,
        };
        let config = test_configuration(root.path(), &job_configuration(Some(&linux)));
        assert_eq!(config.native_settings.unwrap().linux, Some(linux));
    }
    let root = tempfile::tempdir().unwrap();
    let config = test_configuration(root.path(), &job_configuration(None));
    assert!(config.native_settings.unwrap().linux.is_none());
}

/// Observe the owned backend before testing cancellation, rather than merely
/// cancelling an admission that has not started a sandbox.
async fn running_check_job(root: &Path) -> (std::path::PathBuf, serde_json::Value) {
    #[cfg(not(target_os = "macos"))]
    let parent = root.join("data");
    #[cfg(target_os = "macos")]
    let parent = std::env::temp_dir();
    let selected = root.join("config.toml").canonicalize().unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            for entry in std::fs::read_dir(&parent).unwrap() {
                let job_root = entry.unwrap().path();
                if !job_root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("job-")
                    || job_root.join("config.toml").canonicalize().ok().as_ref() != Some(&selected)
                {
                    continue;
                }
                let Ok(agents) = std::fs::read_dir(job_root.join("agents")) else {
                    continue;
                };
                for agent in agents {
                    let agent = agent.unwrap();
                    let name = agent.file_name().to_string_lossy().into_owned();
                    let observed =
                        crate::host_platform::in_config(job_root.join("config.toml"), async {
                            let state = crate::host_runs::observe(&name).await;
                            let record = crate::host_runs::read(&name).unwrap();
                            (state, record)
                        })
                        .await;
                    if observed.0["runtime_state"] == "running" {
                        return (
                            job_root,
                            observed.1.expect("running backend needs a host record"),
                        );
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("check did not reach a running owned backend before cancellation")
}

/// Run explicitly on a prepared native Linux/macOS host. Reuse its immutable
/// host/guest inputs; the test owns fresh policy, credentials and job state.
#[tokio::test]
#[ignore = "requires SAFEYOLO_POLICY_CHECK_PREPARED pointing to a prepared native instance"]
async fn native_installed_job_check_binds_observed_execution_and_reuses_only_valid_evidence() {
    let prepared =
        std::path::PathBuf::from(std::env::var_os("SAFEYOLO_POLICY_CHECK_PREPARED").expect(
            "SAFEYOLO_POLICY_CHECK_PREPARED must name an existing prepared native instance",
        ));
    let (host, guest) = crate::guest_acquisition::selected_boot_inputs(&prepared).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("check-proof-")
        .tempdir_in(prepared.parent().unwrap())
        .unwrap();
    let root = directory.path();
    let mut definition = definition(9, 120_000);
    definition["max_age_seconds"] = json!(300);
    definition["source"] = json!({"kind":"job","spec":root.join("check.json"),"effects":"passive",
        "limits":{"timeout_ms":120_000,"max_input_bytes":8192,"max_output_bytes":8192,"max_concurrent":1,"max_pending":0,"max_cached":8}});
    let rule = json!({"name":"exclude","host":"*","agent":"alice","stage":"connect","influence":"hard_exclusion","priority":0,
        "required":true,"when":{"op":"finding","check":"assess"},"on_match":"deny","on_unavailable":"unresolved"});
    test_policy(root, json!({"assess":definition}), vec![rule]);
    let selected = crate::native_config::read(&prepared.join("config.toml")).unwrap();
    let configuration = job_configuration(
        selected
            .native_settings
            .as_ref()
            .and_then(|settings| settings.linux.as_ref()),
    );
    let config = test_configuration(root, &configuration);
    for name in ["bin", "libexec", "host", "package-info", "SHA256SUMS"] {
        std::os::unix::fs::symlink(host.join(name), root.join(name)).unwrap();
    }
    std::os::unix::fs::symlink(&guest, root.join("share")).unwrap();
    let mut spec = json!({"gate_id":"typed-job-proof","argv":["/bin/sh","-c",
        "test ! -w /input/request.json || exit 91; cat /input/request.json >&2; printf '%s' '{\"finding\":{\"kind\":\"finding\",\"positive\":false},\"source_revision\":\"owned-job-v1\"}'"],
        "timeout_seconds":30,"max_input_bytes":8192,"max_input_entries":1,"retain_bytes":8192,"memory_mb":512,"network":false});
    std::fs::write(root.join("check.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    let mut proxy = crate::Proxy::start(config.clone()).await.unwrap();
    let started = std::time::Instant::now();
    let evidence = collect(&proxy, "example.test").await;
    let entry = &evidence["assess"];
    assert!(
        entry.unavailable.is_none(),
        "{:?}; {:?}",
        entry.unavailable,
        entry.execution
    );
    let run = entry.execution.as_ref().unwrap()["run_id"].clone();
    assert_eq!(
        entry.execution.as_ref().unwrap()["outcome"],
        json!({"kind":"exit","code":0})
    );
    assert_eq!(
        entry.execution.as_ref().unwrap()["gate_principal"],
        "gate:typed-job-proof"
    );
    assert_eq!(
        entry.result.as_ref().unwrap().subject,
        checks::Subject::Hostname {
            hostname: "example.test".into()
        }
    );
    assert_eq!(action(&proxy, "example.test", evidence), Action::Allow);
    let cold = started.elapsed();
    let started = std::time::Instant::now();
    for _ in 0..16 {
        let cached = collect(&proxy, "example.test").await;
        assert_eq!(cached["assess"].acquisition, "reused_live_evidence");
        assert_eq!(cached["assess"].execution.as_ref().unwrap()["run_id"], run);
    }
    println!(
        "job cold={cold:?}; 16 valid repeated requests={:?}",
        started.elapsed()
    );
    // Replacing the selected host specification must invalidate previous reuse.
    spec["argv"] = json!(["/bin/sh", "-c", "printf PASS"]);
    std::fs::write(root.join("check.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    let evidence = collect(&proxy, "example.test").await;
    assert!(
        evidence["assess"]
            .unavailable
            .as_ref()
            .unwrap()
            .contains("malformed")
    );
    assert_ne!(
        evidence["assess"].execution.as_ref().unwrap()["run_id"],
        run
    );
    spec["argv"] = json!([
        "/bin/sh",
        "-c",
        "printf '%s' '{\"finding\":{\"kind\":\"finding\",\"positive\":false}}'; exit 7"
    ]);
    std::fs::write(root.join("check.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    let evidence = collect(&proxy, "example.test").await;
    assert!(
        evidence["assess"]
            .unavailable
            .as_ref()
            .unwrap()
            .contains("execution failed")
    );
    assert_eq!(
        evidence["assess"].execution.as_ref().unwrap()["outcome"],
        json!({"kind":"exit","code":7})
    );
    spec["argv"] = json!(["/bin/sleep", "30"]);
    spec["timeout_seconds"] = json!(1);
    std::fs::write(root.join("check.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    let evidence = collect(&proxy, "example.test").await;
    assert!(
        evidence["assess"]
            .unavailable
            .as_ref()
            .unwrap()
            .contains("execution failed")
    );
    assert_eq!(
        evidence["assess"].execution.as_ref().unwrap()["outcome"],
        json!({"kind":"timeout"})
    );
    // Keep the job timeout longer than the outer check deadline. This tests
    // cancellation of the real backend, not the runner's own timeout above.
    spec["argv"] = json!(["/bin/sleep", "120"]);
    spec["timeout_seconds"] = json!(120);
    std::fs::write(root.join("check.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    let policy = root.join("policy.toml");
    let mut checks: toml::Value =
        toml::from_str(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    checks["checks"]["assess"]["source"]["limits"]["timeout_ms"] = toml::Value::Integer(30_000);
    std::fs::write(&policy, toml::to_string(&checks).unwrap()).unwrap();
    proxy.reload(config).await.unwrap();
    let proxy = Arc::new(proxy);
    for cancel_caller in [false, true] {
        let client = proxy.clone();
        let pending = tokio::spawn(async move { collect(&client, "cancelled.test").await });
        let (job_root, record) = running_check_job(root).await;
        assert!(!crate::host_runs::saved_process_is_dead(&record, "backend"));
        if cancel_caller {
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
        } else {
            let evidence = pending.await.unwrap();
            assert!(
                evidence["assess"]
                    .unavailable
                    .as_ref()
                    .unwrap()
                    .contains("check execution deadline exceeded")
            );
            assert!(
                evidence["assess"].result.is_none(),
                "late job output gained authority"
            );
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            while job_root.exists() || !crate::host_runs::saved_process_is_dead(&record, "backend")
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("cancelled job left its backend or owned runtime behind");
    }
    assert!(!std::fs::read_dir(root.join("data")).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("job-")
    }));
    let proxy = Arc::try_unwrap(proxy).ok().unwrap();
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(root.join("logs/audit.jsonl")).unwrap();
    assert_eq!(
        audit
            .lines()
            .filter(|line| {
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                event["event"] == "ops.policy_check_cancelled"
            })
            .count(),
        2,
        "deadline and caller cancellation must remain observable"
    );
}

#[tokio::test]
async fn native_shutdown_joins_cancelled_check_transport_and_removes_its_listener() {
    if isolated(
        "http::policy_checks::execution_tests::native_shutdown_joins_cancelled_check_transport_and_removes_its_listener",
    ) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let contacted = Arc::new(Notify::new());
    let seen = contacted.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        read_head(&mut socket).await;
        seen.notify_one();
        assert_eq!(
            socket.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let config = setup(root.path(), definition(port, 5000), true, true);
    let proxy = Arc::new(crate::Proxy::start(config).await.unwrap());
    let client = proxy.clone();
    let pending = tokio::spawn(async move { collect(&client, "cancelled.test").await });
    tokio::time::timeout(Duration::from_secs(3), contacted.notified())
        .await
        .unwrap();
    pending.abort();
    let _ = pending.await;
    let proxy = Arc::try_unwrap(proxy).ok().unwrap();
    tokio::time::timeout(Duration::from_secs(3), proxy.shutdown())
        .await
        .unwrap();
    server.await.unwrap();
    assert!(
        !std::fs::read_dir(root.path().join("data"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("check-"))
    );
    let audit = std::fs::read_to_string(root.path().join("logs/audit.jsonl")).unwrap();
    assert!(audit.contains("ops.policy_check_cancelled"));
}

#[tokio::test]
async fn native_service_check_keeps_scoped_credentials_and_saved_authority() {
    if isolated(
        "http::policy_checks::execution_tests::native_service_check_keeps_scoped_credentials_and_saved_authority",
    ) {
        return;
    }
    for (kind, header, expected) in [
        (
            "bearer",
            "Authorization",
            "Bearer synthetic-check-provider-secret",
        ),
        ("api_key", "X-Api-Key", "synthetic-check-provider-secret"),
        (
            "basic",
            "Authorization",
            "Basic Y2hlY2stY2xpZW50OnN5bnRoZXRpYy1jaGVjay1wcm92aWRlci1zZWNyZXQ=",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let config = setup(root.path(), definition(port, 3000), true, true);
        let service = root.path().join("services/assessor.yaml");
        let source = std::fs::read_to_string(&service).unwrap();
        std::fs::write(service,format!("{source}\nauth: {{type: {kind}, header: {header}, allow_http: true, username: check-client}}\n")).unwrap();
        let policy = root.path().join("policy.toml");
        let source = std::fs::read_to_string(&policy).unwrap();
        std::fs::write(&policy,source.replace("[agents.'gate:assess'.services.assessor]\ncapability='reader'",
            "[agents.'gate:assess'.services.assessor]\ncapability='reader'\ntoken='check-secret'")).unwrap();
        let before = std::fs::read(&policy).unwrap();
        crate::credentials::open(&root.path().join("data"))
            .unwrap()
            .store(crate::credentials::Credential::new(
                "check-secret",
                kind,
                crate::credentials::Secret::new("synthetic-check-provider-secret"),
            ))
            .unwrap();
        let expected = (header.to_owned(), expected.to_owned());
        let server = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let head = String::from_utf8(read_head(&mut socket).await).unwrap();
            assert!(
                head.lines()
                    .filter_map(|line| line.split_once(':'))
                    .any(|(name, value)| name.eq_ignore_ascii_case(&expected.0)
                        && value.trim() == expected.1),
                "{kind} credential selection differed"
            );
            assert!(!head.contains("sgw_"));
            reply(
                &mut socket,
                200,
                br#"{"finding":{"kind":"finding","positive":false}}"#,
            )
            .await;
        });
        let proxy = crate::Proxy::start(config).await.unwrap();
        let evidence = collect(&proxy, "example.test").await;
        assert!(
            evidence["assess"].unavailable.is_none(),
            "{:?}",
            evidence["assess"].unavailable
        );
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains("synthetic-check-provider-secret")
        );
        let cached = collect(&proxy, "example.test").await;
        assert_eq!(cached["assess"].acquisition, "reused_live_evidence");
        assert_eq!(std::fs::read(&policy).unwrap(), before);
        assert!(!root.path().join("agents").exists());
        proxy.shutdown().await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn native_check_input_and_network_dependency_denials_make_no_target_contact() {
    if isolated(
        "http::policy_checks::execution_tests::native_check_input_and_network_dependency_denials_make_no_target_contact",
    ) {
        return;
    }
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    for (mode, reason) in [
        ("input", "input limit"),
        ("route", "not authorized"),
        ("network", "HTTP 403"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut check = definition(port, 3000);
        if mode == "input" {
            check["source"]["limits"]["max_input_bytes"] = json!(4);
        }
        if mode == "route" {
            check["source"]["operation"]["path"] = json!("/unadopted-operation");
        }
        let config = setup(root.path(), check, true, true);
        if mode == "network" {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(root.path().join("policy.toml"))
                    .unwrap(),
                "\n[agents.'gate:assess'.hosts.'127.0.0.1:{port}']\negress='deny'"
            )
            .unwrap();
        }
        let proxy = crate::Proxy::start(config).await.unwrap();
        let evidence = collect(&proxy, "example.test").await;
        assert!(
            evidence["assess"]
                .unavailable
                .as_ref()
                .unwrap()
                .contains(reason),
            "{:?}",
            evidence["assess"].unavailable
        );
        assert_eq!(action(&proxy, "example.test", evidence), Action::Unresolved);
        assert!(
            tokio::time::timeout(Duration::from_millis(40), origin.accept())
                .await
                .is_err()
        );
        proxy.shutdown().await;
    }
}
