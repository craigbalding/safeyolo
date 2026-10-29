//! Retained run provenance uses the existing native producer and actual CLI.

use super::{correlation::correlation_rows, *};

pub(super) const AGENT_ID: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUN_A: &str = "0123456789abcdef0123456789abcdef";
const RUN_B: &str = "fedcba9876543210fedcba9876543210";

fn binding(id: &str) -> Value {
    json!({"agent":"alice","agent_id":AGENT_ID,"run_id":id})
}

#[cfg(target_os = "linux")]
pub(super) fn start_owned(root: &Path) -> super::owned_run::OwnedRun {
    fs::create_dir_all(root.join("bin")).unwrap();
    let mut owned = super::owned_run::OwnedRun::start(root);
    let path = root.join("agents/alice/runtime.json");
    let mut run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run["name"] = json!("alice");
    run["agent_id"] = json!(AGENT_ID);
    run["state"] = json!("running");
    fs::write(path, run.to_string()).unwrap();
    let path = root.join("agents/alice/config-share/host-launch-context.json");
    let mut context: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    context["agent_id"] = json!(AGENT_ID);
    fs::write(path, context.to_string()).unwrap();
    // Namespace entry precedes the fixture shell's final exec. Wait for the
    // actual authority used at ingress, including that backend command/birth,
    // before this test sends supervised traffic.
    let policy =
        safeyolo_proxy::policy::Policy::from_native_path(&root.join("policy.toml")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while policy.agent_run("alice").is_none() {
        assert!(
            owned.child.try_wait().unwrap().is_none(),
            "owned backend exited before authority became available"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "owned backend did not establish current run authority"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    owned
}

pub(super) fn recorded_binding(root: &Path) -> Value {
    let run: Value =
        serde_json::from_slice(&fs::read(root.join("agents/alice/runtime.json")).unwrap()).unwrap();
    binding(run["run_id"].as_str().unwrap())
}

#[cfg(target_os = "linux")]
pub(super) fn mark_stopped(root: &Path) {
    let path = root.join("agents/alice/runtime.json");
    let mut run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run["state"] = json!("stopped");
    fs::write(path, run.to_string()).unwrap();
}

pub(super) async fn accepted_client(root: &Path) -> (UnixStream, String) {
    async fn ingresses(root: &Path, count: usize) -> Vec<Value> {
        timeout(Duration::from_secs(5), async {
            loop {
                let rows: Vec<_> = fs::read_to_string(root.join("audit.jsonl"))
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|line| parse_record(line).ok())
                    .filter(|row| {
                        row["event"] == "network.connection"
                            && row["details"]["leg"] == "client_to_proxy"
                            && row["details"]["state"] == "open"
                    })
                    .collect();
                if rows.len() >= count {
                    return rows;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    // Both completed source/model requests precede this deliberately partial
    // request. Wait for its actual ingress publication before replacement.
    ingresses(root, 2).await;
    let mut stream = UnixStream::connect(root.join("alice.sock")).await.unwrap();
    stream
        .write_all(
            b"GET http://not-contacted.invalid/stale HTTP/1.1\r\nHost: not-contacted.invalid\r\n",
        )
        .await
        .unwrap();
    let rows = ingresses(root, 3).await;
    assert_eq!(
        rows.last().unwrap()["details"]["sandbox_run"],
        recorded_binding(root)
    );
    (
        stream,
        rows.last().unwrap()["details"]["connection_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

pub(super) async fn assert_native_runs(root: &Path, bytes: &[u8], bindings: &[Value], stale: &str) {
    assert_eq!(bindings.len(), 2);
    assert_ne!(bindings[0], bindings[1]);
    assert_eq!(recorded_binding(root), bindings[1]);
    let rows: Vec<_> = std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| parse_record(line).unwrap())
        .collect();
    let nsm: Vec<_> = rows
        .iter()
        .filter(|row| row["schema_version"] == 2)
        .collect();
    assert!(!nsm.is_empty());
    assert!(
        nsm.iter()
            .all(|row| bindings.contains(&row["details"]["sandbox_run"])),
        "unbound emitted records: {:?}",
        nsm.iter()
            .filter(|row| !bindings.contains(&row["details"]["sandbox_run"]))
            .collect::<Vec<_>>()
    );
    let first = nsm[0];
    assert!(nsm.iter().all(
        |row| row["details"]["instance_id"] == first["details"]["instance_id"]
            && row["details"]["runtime_id"] == first["details"]["runtime_id"]
    ));
    assert!(nsm.iter().any(|row| row["event"] == "network.connection"
        && row["details"]["connection_id"] == stale
        && row["details"]["state"] == "closed"
        && row["details"]["sandbox_run"] == bindings[0]));
    for run in bindings {
        for event in [
            "network.connection",
            "traffic.flow",
            "security.indicator",
            "gateway.allow",
            "security.network_guard.evaluated",
            "security.credential_guard",
        ] {
            assert!(
                nsm.iter()
                    .any(|row| row["event"] == event && row["details"]["sandbox_run"] == *run),
                "missing {event} in {run}"
            );
        }
    }
    let paths = [
        root.join("run-records-a.jsonl"),
        root.join("run-records-b.jsonl"),
    ];
    let mut split = [Vec::new(), Vec::new()];
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        split[index % 2].extend_from_slice(line);
    }
    for (path, content) in paths.iter().zip(&split) {
        fs::write(path, content).unwrap();
    }
    for offline in [false, true] {
        let selected_root = if offline {
            root.join("no-installation")
        } else {
            root.to_owned()
        };
        let mut files = Vec::new();
        if offline {
            // A repeated copy retains every physical location without adding
            // independent evidence. The producer bytes themselves stay intact.
            for path in [&paths[0], &paths[1], &paths[0]] {
                files.extend(["--file", path.to_str().unwrap()]);
            }
        }
        let mut args = vec!["logs", "list", "--lines", "1000", "--json"];
        args.extend(&files);
        let listing = success(&selected_root, &args).await;
        assert_eq!(listing["namespaces"].as_array().unwrap().len(), 1);
        let namespace = &listing["namespaces"][0];
        let groups = namespace["agents"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        for run in bindings {
            let group = groups
                .iter()
                .find(|group| group["sandbox_run"] == *run)
                .unwrap();
            assert_eq!(group["run_context"], "recorded");
            let exposure = group["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| record["indicator"]["indicator_type"] == "prompt_injection_exposure")
                .unwrap();
            for (kind, field) in [
                ("request", "request_id"),
                ("connection", "details.connection_id"),
            ] {
                let reference = exposure["references"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|reference| reference["kind"] == kind && reference["field"] == field)
                    .unwrap();
                let mut args = vec![
                    "logs",
                    kind,
                    reference["id"].as_str().unwrap(),
                    "--instance",
                    namespace["instance_id"].as_str().unwrap(),
                    "--runtime",
                    namespace["runtime_id"].as_str().unwrap(),
                    "--agent",
                    group["agent"].as_str().unwrap(),
                    "--sandbox-run",
                    group["sandbox_run"]["run_id"].as_str().unwrap(),
                    "--lines",
                    "1000",
                    "--json",
                ];
                args.extend(&files);
                let pivot = success(&selected_root, &args).await;
                let records = pivot["records"].as_array().unwrap();
                assert!(!records.is_empty());
                assert!(
                    records
                        .iter()
                        .all(|entry| entry["record"]["details"]["sandbox_run"] == *run
                            && entry["run_context"] == "recorded")
                );
                assert!(
                    records
                        .iter()
                        .any(|entry| entry["record"]["event"] == "network.connection")
                );
                assert!(
                    records
                        .iter()
                        .any(|entry| entry["record"]["event"] == "gateway.allow")
                );
                assert!(
                    records
                        .iter()
                        .any(|entry| entry["record"]["event"] == "security.credential_guard")
                );
                if offline {
                    assert!(
                        pivot["search"]["duplicate_namespace_rows"]
                            .as_u64()
                            .unwrap()
                            > 0
                    );
                    assert!(
                        records
                            .iter()
                            .any(|entry| entry["locations"].as_array().unwrap().len() > 1)
                    );
                }
                args.retain(|arg| *arg != "--json");
                let ordinary = cli(&selected_root, &args).await;
                assert!(ordinary.status.success());
                assert!(
                    String::from_utf8(ordinary.stdout)
                        .unwrap()
                        .contains(run["run_id"].as_str().unwrap())
                );
            }
        }
        args.retain(|arg| *arg != "--json");
        let ordinary = cli(&selected_root, &args).await;
        assert!(ordinary.status.success());
        let text = String::from_utf8(ordinary.stdout).unwrap();
        assert!(
            bindings
                .iter()
                .all(|run| text.contains(run["run_id"].as_str().unwrap()))
        );
    }
    assert_eq!(fs::read(root.join("audit.jsonl")).unwrap(), bytes);
    for (path, content) in paths.iter().zip(split) {
        assert_eq!(fs::read(path).unwrap(), content);
    }
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(!text.contains("amber lighthouse"));
    assert!(!text.contains("synthetic-correlation-credential"));
    assert!(!text.contains("spoofed-run"));
}

fn bound_rows() -> Vec<Value> {
    correlation_rows()
        .into_iter()
        .enumerate()
        .map(|(index, mut row)| {
            row["details"]["sandbox_run"] = binding(RUN_A);
            row.as_object_mut()
                .unwrap()
                .entry("event_id")
                .or_insert_with(|| json!(format!("run-event-{index}")));
            row
        })
        .collect()
}

async fn selected(root: &Path) -> Value {
    let mut args = pivot_args("request", "F1");
    args.extend(["--sandbox-run", RUN_A]);
    success(root, &args).await
}

fn not_linked(view: &Value) {
    assert!(
        view["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["status"] != "linked"),
        "{view}"
    );
}

#[tokio::test]
async fn every_run_relationship_requires_the_same_recorded_binding() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let original = bound_rows();
    write_rows(root.path(), &original);
    assert_eq!(
        correlation::only_correlation(&selected(root.path()).await)["status"],
        "linked"
    );
    for index in 0..original.len() {
        for replacement in [
            Some(binding(RUN_B)),
            None,
            Some(Value::Null),
            Some(json!({"agent":"alice","agent_id":"different-agent-id","run_id":RUN_A})),
        ] {
            let mut rows = original.clone();
            if let Some(run) = replacement {
                rows[index]["details"]["sandbox_run"] = run;
            } else {
                rows[index]["details"]
                    .as_object_mut()
                    .unwrap()
                    .remove("sandbox_run");
            }
            write_rows(root.path(), &rows);
            let bytes = fs::read(root.path().join("audit.jsonl")).unwrap();
            let view = selected(root.path()).await;
            if index < 7 || index == original.len() - 1 {
                not_linked(&view);
            }
            assert!(
                view["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|entry| entry["sandbox_run"]["run_id"] == RUN_A)
            );
            let unfiltered = success(root.path(), &pivot_args("request", "F1")).await;
            if index < 7 || index == original.len() - 1 {
                not_linked(&unfiltered);
            }
            for view in [&view, &unfiltered] {
                for link in view["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|link| link["status"] == "available")
                {
                    let from = link["from_line"].as_u64().unwrap() as usize - 1;
                    assert!(link["record_lines"].as_array().unwrap().iter().all(|line| rows[line.as_u64().unwrap() as usize - 1]["details"]["sandbox_run"] == rows[from]["details"]["sandbox_run"]));
                }
            }
            assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), bytes);
        }
    }
    write_rows(root.path(), &correlation_rows());
    assert_eq!(
        correlation::only_correlation(&success(root.path(), &pivot_args("request", "F1")).await)["status"],
        "linked"
    );
    assert!(
        selected(root.path()).await["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let listing = success(root.path(), &["logs", "list", "--json"]).await;
    assert_eq!(
        listing["namespaces"][0]["agents"][0]["run_context"],
        "unavailable"
    );
}

#[tokio::test]
async fn run_selection_cannot_hide_conflicting_event_or_transport_owners() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let original = bound_rows();
    for index in [0, 5, 6, original.len() - 1] {
        for same_event in [true, false] {
            let mut rows = original.clone();
            let mut other = rows[index].clone();
            other["details"]["sandbox_run"] = binding(RUN_B);
            if !same_event {
                other["event_id"] = json!("another-event");
            }
            rows.push(other);
            write_rows(root.path(), &rows);
            let view = selected(root.path()).await;
            if same_event || index < 7 {
                not_linked(&view);
            } else {
                assert_eq!(correlation::only_correlation(&view)["status"], "linked");
            }
            let list = success(
                root.path(),
                &["logs", "list", "--sandbox-run", RUN_A, "--json"],
            )
            .await;
            if same_event || index < 7 {
                assert!(
                    list["search"]["conflicting_nsm_records"].as_u64().unwrap() > 0,
                    "{list}"
                );
            }
        }
    }
}

#[tokio::test]
async fn run_contract_errors_are_validated_outside_the_window_without_echoing_input() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    for run in [
        json!("PRIVATE_RUN"),
        json!({}),
        json!({"agent":"alice","agent_id":AGENT_ID,"run_id":"PRIVATE_RUN"}),
        json!({"agent":"mallory","agent_id":AGENT_ID,"run_id":RUN_A}),
        json!({"agent":"alice","agent_id":" ","run_id":RUN_A}),
        json!({"agent":"alice","agent_id":AGENT_ID,"run_id":RUN_A,"payload":"PRIVATE_RUN"}),
    ] {
        for mut row in correlation_rows() {
            row["details"]["sandbox_run"] = run.clone();
            fs::write(root.path().join("audit.jsonl"), row.to_string()).unwrap();
            let output = cli(
                root.path(),
                &[
                    "logs", "list", "--lines", "0", "--agent", "nobody", "--json",
                ],
            )
            .await;
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_RUN"));
        }
    }
    write_rows(root.path(), &bound_rows());
    for args in [
        vec!["logs", "list", "--sandbox-run", ""],
        vec![
            "logs",
            "request",
            "F1",
            "--instance",
            "I1",
            "--runtime",
            "R1",
            "--sandbox-run",
            "",
        ],
        vec!["logs", "--sandbox-run", RUN_A],
    ] {
        assert!(!cli(root.path(), &args).await.status.success());
    }
}

#[tokio::test]
async fn request_decisions_cannot_borrow_another_runs_ingress_or_flow() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let mut rows = bound_rows();
    let mut decision = decisions::scoped_decision();
    decision["details"]["sandbox_run"] = binding(RUN_A);
    rows.push(decision);
    let decision_line = rows.len();
    for index in [2, 6, decision_line - 1] {
        for run in [Value::Null, binding(RUN_B)] {
            let mut mixed = rows.clone();
            mixed[index]["details"]["sandbox_run"] = run;
            write_rows(root.path(), &mixed);
            for view in [
                selected(root.path()).await,
                success(root.path(), &pivot_args("connection", "S1")).await,
                success(root.path(), &pivot_args("request", "F1")).await,
            ] {
                for link in view["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|link| link["from_line"] == decision_line)
                {
                    if index != 2 || link["field"] == "details.client_connection_id" {
                        assert_eq!(link["status"], "unavailable", "{view}");
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn listing_keeps_run_unknowns_windows_and_escaped_keys_distinct() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let mut known = bound_rows()[0].clone();
    known["details"]["sandbox_run"]["agent_id"] = json!("agent\n\u{1b}[31m");
    let mut unknown = known.clone();
    unknown["event_id"] = json!("unknown-run-context");
    unknown["details"]["connection_id"] = json!("unknown-connection");
    unknown["details"]
        .as_object_mut()
        .unwrap()
        .remove("attribution");
    let mut unavailable = connection("no-run", "no-run-event");
    unavailable["details"]["attribution"] = known["details"]["attribution"].clone();
    write_rows(root.path(), &[known.clone(), unknown, unavailable]);
    let bytes = fs::read(root.path().join("audit.jsonl")).unwrap();
    let view = success(root.path(), &["logs", "list", "--json"]).await;
    let groups = view["namespaces"][0]["agents"].as_array().unwrap();
    assert!(groups.iter().any(|group| group["run_context"] == "recorded"
        && group["sandbox_run"] == known["details"]["sandbox_run"]));
    assert!(groups.iter().any(|group| group["run_context"] == "unknown"));
    assert!(
        groups
            .iter()
            .any(|group| group["run_context"] == "unavailable" && group["sandbox_run"].is_null())
    );
    let output = cli(root.path(), &["logs", "list"]).await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("agent\\n\\u001b[31m"));
    let selected = success(
        root.path(),
        &[
            "logs",
            "list",
            "--sandbox-run",
            RUN_A,
            "--lines",
            "1",
            "--json",
        ],
    )
    .await;
    assert!(selected["namespaces"].as_array().unwrap().is_empty());
    assert_eq!(selected["search"]["omitted_rows"], 2);
    assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), bytes);
}
