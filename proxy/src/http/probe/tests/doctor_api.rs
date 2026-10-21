//! Native doctor consumes the real probe and source-scoped trace API.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_doctor_probes_each_uds_and_reports_missing_or_failed_controls() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir(root.join("data")).unwrap();
    for name in ["builtin-services", "services"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    std::fs::write(root.join("data/agent_token"), "synthetic-doctor-token").unwrap();
    std::fs::write(
        root.join("policy.toml"),
        "[hosts]\n\"*\"={egress=\"deny\"}\n",
    )
    .unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!(
        "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id=\"alice\"\nsource_id=\"192.0.2.10\"\nsocket_path={:?}\n[[listeners]]\nagent_id=\"bob\"\nsource_id=\"192.0.2.11\"\nsocket_path={:?}\n",
        root.join("alice.sock"), root.join("bob.sock")
    )).unwrap();
    let mut proxy = Proxy::start(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    let report = crate::host_doctor::pipeline(&config).await;
    assert_eq!(report["verdict"], "pass", "{report}");
    assert_eq!(report["agents"].as_array().unwrap().len(), 2);
    for agent in report["agents"].as_array().unwrap() {
        assert_eq!(agent["verdict"], "pass", "{agent}");
        assert_eq!(agent["probe_status"], 200);
        let steps = agent["steps"].as_array().unwrap();
        let first: Vec<_> = steps
            .iter()
            .filter(|step| step["hook"] == "request")
            .map(|step| step["control"].as_str().unwrap())
            .collect();
        assert_eq!(
            first,
            [
                "network",
                "circuits",
                "credentials",
                "services",
                "patterns",
                "test_context",
                "probe-sink"
            ]
        );
        assert!(
            steps
                .iter()
                .filter(|step| step["state"] == "evaluated")
                .all(|step| step["duration_us"].as_u64().is_some())
        );
        assert_eq!(agent["not_loaded"], json!([]));
        let context = steps
            .iter()
            .find(|step| step["control"] == "test_context" && step["hook"] == "request")
            .unwrap();
        assert_eq!(context["outcome"], "allowed");
    }
    assert_eq!(
        crate::host_commands::run(config.clone(), &["doctor".into()])
            .await
            .unwrap(),
        0
    );

    // Inject a genuinely missing runtime control after the healthy observation.
    // Listener ownership, policy and the trace API remain the same.
    {
        let mut generation = proxy.runtime.write().unwrap();
        Arc::make_mut(&mut generation).credential_guard = None;
    }
    let missing = crate::host_doctor::pipeline(&config).await;
    assert_eq!(missing["verdict"], "fail", "{missing}");
    assert_eq!(missing["agents"][0]["probe_status"], 502);
    assert!(missing.to_string().contains("credentials: not loaded"));
    assert_eq!(
        crate::host_commands::run(config.clone(), &["doctor".into()])
            .await
            .unwrap(),
        1
    );

    // A broken trace store cannot turn the existing deny policy into allow.
    proxy
        .reload(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    {
        let mut generation = proxy.runtime.write().unwrap();
        Arc::make_mut(&mut generation).traces =
            Arc::new(crate::trace::TraceStore::new(crate::trace::Settings {
                ttl_s: json!("synthetic-invalid-ttl").into(),
                ..crate::trace::Settings::default()
            }));
    }
    let failed = crate::host_doctor::pipeline(&config).await;
    assert_eq!(failed["verdict"], "fail", "{failed}");
    assert_eq!(failed["agents"][0]["probe_status"], 200);
    assert!(failed.to_string().contains("trace unavailable"));
    for opt_in in ["", "X-SafeYolo-Trace: 1\r\n"] {
        let denied = exchange(root, "alice", &format!("GET http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\n{opt_in}Connection: close\r\n\r\n")).await;
        assert_eq!(status(&denied), 403);
        assert_eq!(
            header(&denied, "x-blocked-by").as_deref(),
            Some("network-guard")
        );
    }
    timeout(LIMIT, proxy.shutdown()).await.unwrap();
    let audit = std::fs::read_to_string(root.join("logs/audit.jsonl")).unwrap();
    assert!(!audit.contains("traffic.egress"));
    assert!(!audit.contains("synthetic-doctor-token"));
}
