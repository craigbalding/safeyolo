//! Concrete request decisions use the existing producer, reader and CLI.
use super::*;

fn scoped_decision() -> Value {
    let mut value = row(
        "security.credential_guard",
        json!({
            "instance_id":"I1","runtime_id":"R1","client_connection_id":"C1",
            "connection_id":"C1","rule":"fixture","location":"header:authorization",
            "attribution":{"evidence_owner":"alice","trusted_transport_identity":"alice",
                "attribution_status":"resolved"}
        }),
    );
    value["event_id"] = json!("decision-1");
    value["request_id"] = json!("F1");
    value["addon"] = json!("credential-guard");
    value["host"] = json!("origin.invalid");
    value["decision"] = json!("allow");
    value
}

fn support() -> Vec<Value> {
    correlation::correlation_rows()
        .into_iter()
        .filter(|row| {
            row["event"] == "traffic.flow" && row["request_id"] == "F1"
                || row["event"] == "network.connection"
                    && matches!(row["details"]["connection_id"].as_str(), Some("C1" | "S1"))
        })
        .collect()
}

fn flow_link(result: &Value) -> &Value {
    result["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|link| link["event"] == "traffic.flow")
        .unwrap()
}

/// Inspect exact real producer bytes in configured and split offline modes.
/// Every existing decision is found from request, ingress and upstream pivots.
pub(super) async fn assert_native_views(root: &Path, bytes: &[u8]) {
    let rows: Vec<Value> = std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| parse_record(line).unwrap())
        .collect();
    let decisions: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["event"] == "security.network_guard.evaluated"
                || row["event"] == "security.network_guard"
                || row["event"] == "security.credential_guard"
                || row["event"] == "gateway.allow"
        })
        .collect();
    assert!(
        decisions
            .iter()
            .any(|row| row["event"] == "security.network_guard.evaluated")
    );
    assert!(
        decisions
            .iter()
            .any(|row| row["event"] == "security.credential_guard"
                || row["event"] == "gateway.allow")
    );
    let paths = [root.join("decisions.jsonl"), root.join("transports.jsonl")];
    let mut split = [Vec::new(), Vec::new()];
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let row = parse_record(std::str::from_utf8(line).unwrap()).unwrap();
        split[usize::from(!decisions.contains(&&row))].extend_from_slice(line);
    }
    for (path, contents) in paths.iter().zip(&split) {
        fs::write(path, contents).unwrap();
    }
    for decision in decisions {
        assert_eq!(decision["schema_version"], 2, "{decision}");
        let client = decision["details"]["client_connection_id"]
            .as_str()
            .unwrap();
        let request = decision["request_id"].as_str().unwrap();
        let flow = rows
            .iter()
            .find(|row| row["event"] == "traffic.flow" && row["request_id"] == request);
        let mut pivots = vec![("request", request), ("connection", client)];
        if let Some(server) = flow.and_then(|flow| flow["details"]["server_connection_id"].as_str())
        {
            pivots.push(("connection", server));
        }
        for offline in [false, true] {
            for (kind, id) in &pivots {
                let mut args = vec![
                    "logs",
                    kind,
                    id,
                    "--instance",
                    decision["details"]["instance_id"].as_str().unwrap(),
                    "--runtime",
                    decision["details"]["runtime_id"].as_str().unwrap(),
                    "--agent",
                    "alice",
                    "--lines",
                    "1000",
                    "--json",
                ];
                if offline {
                    for path in &paths {
                        args.extend(["--file", path.to_str().unwrap()]);
                    }
                }
                let selected_root = root.join("no-installed-decision-instance");
                let cli_root = if offline {
                    selected_root.as_path()
                } else {
                    root
                };
                let result = success(cli_root, &args).await;
                let entry = result["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["record"] == *decision)
                    .unwrap_or_else(|| panic!("{result}"));
                let physical = if offline {
                    let line = entry["line"]["line"].as_u64().unwrap() as usize;
                    let input = entry["line"]["input"].as_u64().unwrap() as usize;
                    std::str::from_utf8(&split[input - 1])
                        .unwrap()
                        .lines()
                        .nth(line - 1)
                        .unwrap()
                } else {
                    std::str::from_utf8(bytes)
                        .unwrap()
                        .lines()
                        .nth(entry["line"].as_u64().unwrap() as usize - 1)
                        .unwrap()
                };
                assert_eq!(parse_record(physical).unwrap(), *decision);
                let from = &entry["line"];
                let links: Vec<_> = result["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|link| link["from_line"] == *from)
                    .collect();
                assert_eq!(links.len(), 2);
                assert_eq!(links[0]["status"], "available");
                assert_eq!(
                    links[1]["status"],
                    if flow.is_some() {
                        "available"
                    } else {
                        "unavailable"
                    }
                );
                if decision["decision"] == "deny" {
                    assert!(
                        flow.is_none_or(|flow| flow["details"]["server_connection_id"].is_null())
                    );
                    assert!(
                        !result["records"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|entry| entry["record"]["details"]["leg"] == "proxy_to_upstream")
                    );
                }
                args.retain(|arg| *arg != "--json");
                let ordinary = cli(cli_root, &args).await;
                assert!(ordinary.status.success());
                let text = String::from_utf8(ordinary.stdout).unwrap();
                assert!(text.contains(decision["event"].as_str().unwrap()));
                assert!(!text.contains("key-nativefixture"));
                assert!(!text.contains("synthetic-correlation-credential"));
            }
        }
    }
    for (path, contents) in paths.iter().zip(split) {
        assert_eq!(fs::read(path).unwrap(), contents);
    }
    assert_eq!(fs::read(root.join("audit.jsonl")).unwrap(), bytes);
    assert!(
        !std::str::from_utf8(bytes)
            .unwrap()
            .contains("key-nativefixture")
    );
}

#[tokio::test]
async fn decision_joins_require_exact_scope_attribution_and_ownership() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    for mutation in 0..12 {
        let mut decision = scoped_decision();
        let mut rows = support();
        match mutation {
            0 => {}
            1 => decision["details"]["instance_id"] = json!("foreign-instance"),
            2 => decision["details"]["runtime_id"] = json!("foreign-runtime"),
            3 => decision["agent"] = json!("foreign-agent"),
            4 => decision["schema_version"] = json!(1),
            5 => {
                decision.as_object_mut().unwrap().remove("schema_version");
            }
            6 => decision["details"]["attribution"]["attribution_status"] = json!("unavailable"),
            7 => decision["details"]["attribution"]["evidence_owner"] = json!("foreign-agent"),
            8 => {
                rows.retain(|row| row["event"] != "traffic.flow");
            }
            9 => {
                let mut conflict = decision.clone();
                conflict["decision"] = json!("deny");
                rows.push(conflict);
            }
            10 => {
                let mut conflict = rows
                    .iter()
                    .find(|row| row["event"] == "traffic.flow")
                    .unwrap()
                    .clone();
                conflict["details"]["client_connection_id"] = json!("another-client");
                rows.push(conflict);
            }
            11 => {
                for row in &mut rows {
                    row["details"]["attribution"]["attribution_status"] = json!("conflict");
                }
            }
            _ => unreachable!(),
        }
        rows.push(decision);
        write_rows(root.path(), &rows);
        let result = success(root.path(), &pivot_args("request", "F1")).await;
        let links: Vec<_> = result["links"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|link| link["event"] == "traffic.flow")
            .collect();
        if (1..=5).contains(&mutation) {
            assert!(links.is_empty(), "case {mutation}: {result}");
        } else {
            assert_eq!(
                links.len(),
                if mutation == 9 { 2 } else { 1 },
                "case {mutation}"
            );
            assert!(
                links.iter().all(|link| link["status"]
                    == if mutation == 0 {
                        "available"
                    } else {
                        "unavailable"
                    }),
                "case {mutation}: {result}"
            );
        }
    }
}

#[tokio::test]
async fn split_decisions_preserve_copies_windows_and_ignore_approval_ids() {
    let root = tempfile::tempdir().unwrap();
    let paths = [root.path().join("a.jsonl"), root.path().join("b.jsonl")];
    let decision = scoped_decision();
    fs::write(&paths[0], format!("{decision}\n")).unwrap();
    let mut rows = support();
    let mut unrelated = scoped_decision();
    unrelated["request_id"] = json!("UNRELATED");
    unrelated["event_id"] = json!("unrelated-event");
    unrelated["details"]["approval_id"] = json!("F1");
    unrelated["details"]["source"] = json!({"request_id":"F1"});
    unrelated["details"]["server_connection_id"] = json!("UNRELATED-SERVER");
    rows.push(unrelated);
    fs::write(
        &paths[1],
        rows.iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let before: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
    let mut args = pivot_args("request", "F1");
    for path in [&paths[0], &paths[1], &paths[0]] {
        args.extend(["--file", path.to_str().unwrap()]);
    }
    let full = success(root.path(), &args).await;
    assert_eq!(flow_link(&full)["status"], "available");
    assert_eq!(full["search"]["duplicate_namespace_rows"], 1);
    assert!(
        !full["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["record"]["request_id"] == "UNRELATED")
    );
    let entry = full["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["record"] == decision)
        .unwrap();
    assert_eq!(
        entry["locations"],
        json!([{"input":1,"line":1},{"input":3,"line":1}])
    );
    args.extend(["--lines", "1"]);
    let window = success(root.path(), &args).await;
    assert_eq!(flow_link(&window)["status"], "unavailable");
    assert!(window["search"]["omitted_rows"].as_u64().unwrap() > 0);
    for (path, bytes) in paths.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
