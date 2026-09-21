use super::*;

use crate::{
    Proxy,
    audit::{Event, Kind, Severity, Submission},
};
use serde_json::{Value, json};
use std::{fs, sync::Arc};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOKEN: &str = "operator-audit-submit-failure";
const POLICY: &str = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
"#;
const SERVICE_POLICY: &str = "version = '2.0'\n[agents.alice]\nimage = 'owned-image'\n";
const CONTROL_BODY: &[u8] =
    br#"{"service":"mail","capability":"read","credential":"control-entry"}"#;
const DECLINED_BODY: &[u8] =
    br#"{"service":"mail","capability":"read","credential":"declined-entry"}"#;

#[tokio::test]
async fn synchronous_audit_submission_failure_commits_mutations_then_closes_connection() {
    for mutation in ["baseline", "mode", "host"] {
        let directory = TempDir::new().unwrap();
        let config = config(directory.path());
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let port = proxy.admin.as_ref().unwrap().address().port();

        // The runtime owns this writer. Poisoning its mutex makes the real
        // admin listener's Writer::emit return a synchronous submission error.
        proxy.runtime.read().unwrap().audit.poison_for_test();

        let (path, body) = match mutation {
            "baseline" => (
                "/admin/policy/baseline",
                br#"{"policy":{"budget":17,"permissions":[{"action":"network:request","resource":"replacement.example","effect":"allow"}]}}"#.as_slice(),
            ),
            "mode" => ("/plugins/network-guard/mode", br#"{"mode":"warn"}"#.as_slice()),
            "host" => (
                "/admin/policy/host/allow",
                br#"{"host":"sync-failure.example","rate":5}"#.as_slice(),
            ),
            _ => unreachable!(),
        };
        let method = if matches!(mutation, "baseline" | "mode") {
            "PUT"
        } else {
            "POST"
        };
        let response = raw_admin_request(port, method, path, body).await;

        // admin_listener propagates a synchronous submission error. Hyper
        // closes this request's connection without inventing a response.
        assert!(
            response.is_empty(),
            "{mutation} submission error produced an HTTP response: {:?}",
            String::from_utf8_lossy(&response)
        );

        let policy_path = config.policy_file.as_ref().unwrap();
        match mutation {
            "baseline" => {
                let source = std::fs::read_to_string(policy_path).unwrap();
                let document: toml_edit::DocumentMut = source.parse().unwrap();
                assert_eq!(document["budget"].as_integer(), Some(17));
                let permissions = document["permissions"].as_array().unwrap();
                assert_eq!(permissions.len(), 1);
                let permission = permissions.get(0).unwrap().as_inline_table().unwrap();
                assert_eq!(
                    permission.get("action").and_then(toml_edit::Value::as_str),
                    Some("network:request")
                );
                assert_eq!(
                    permission
                        .get("resource")
                        .and_then(toml_edit::Value::as_str),
                    Some("replacement.example")
                );
                assert_eq!(
                    permission.get("effect").and_then(toml_edit::Value::as_str),
                    Some("allow")
                );
                assert!(!source.contains("resource = \"*\""));
            }
            "mode" => assert_eq!(
                proxy.runtime.read().unwrap().operator_modes.network_block(),
                false,
                "mode mutation was rolled back"
            ),
            "host" => assert!(
                std::fs::read_to_string(policy_path)
                    .unwrap()
                    .contains("sync-failure.example"),
                "host write was rolled back"
            ),
            _ => unreachable!(),
        }
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn closed_service_admission_rejects_authenticated_mutation_without_commit_or_audit() {
    let directory = TempDir::new().unwrap();
    let config = service_config(directory.path());
    let policy_path = directory.path().join("policy.toml");
    let audit_path = directory.path().join("audit.jsonl");
    let proxy = Proxy::start(config).await.unwrap();
    let port = proxy.admin.as_ref().unwrap().address().port();
    let runtime = proxy.runtime.read().unwrap().clone();
    let writer = runtime.audit.clone();

    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.path().join(".policy.toml.lock"))
        .unwrap();
    lock.lock().unwrap();

    let writer_references = Arc::strong_count(&writer);
    let control = tokio::spawn(raw_admin_request(
        port,
        "POST",
        "/admin/agents/alice/services",
        CONTROL_BODY,
    ));
    // The service worker retains this writer reference before waiting on the
    // held file lock, so admission is observable without a timing sleep.
    tokio::time::timeout(Duration::from_secs(3), async {
        while Arc::strong_count(&writer) < writer_references + 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    // Proxy::shutdown calls this same admission fence before it stops the
    // listener. Keeping the listener live here lets an authenticated request
    // demonstrate that its mutation cannot start after that fence closes.
    runtime.service_mutations.stop_admission().await;
    let declined =
        raw_admin_request(port, "POST", "/admin/agents/alice/services", DECLINED_BODY).await;
    assert!(
        !declined.starts_with(b"HTTP/1.1 2"),
        "closed admission must not report a committed mutation: {}",
        String::from_utf8_lossy(&declined)
    );
    let before_release = fs::read_to_string(&policy_path).unwrap();
    assert!(!before_release.contains("control-entry"));
    assert!(!before_release.contains("declined-entry"));

    lock.unlock().unwrap();
    let control = control.await.unwrap();
    assert!(
        control.starts_with(b"HTTP/1.1 200"),
        "admitted control must report its committed mutation: {}",
        String::from_utf8_lossy(&control)
    );
    assert!(writer.wait_for_drain(Duration::from_secs(3)).unwrap());

    let policy = fs::read_to_string(&policy_path).unwrap();
    assert!(policy.contains("control-entry"));
    assert!(!policy.contains("declined-entry"));
    let audit_rows: Vec<Value> = fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .unwrap();
    let authorization_events: Vec<_> = audit_rows
        .iter()
        .filter(|row| row["event"] == "admin.agent_service_authorized")
        .collect();
    assert_eq!(authorization_events.len(), 1);
    assert_eq!(
        authorization_events[0]["details"]["credential"],
        "control-entry"
    );

    proxy.shutdown().await;
    assert_eq!(
        writer
            .emit(Event::new(
                "ops.service_mutation_shutdown_probe",
                Kind::Ops,
                Severity::Low,
                "Service mutation shutdown probe",
            ))
            .unwrap(),
        Submission::Stopped,
        "proxy shutdown must stop the writer after the admitted control's audit attempt"
    );
}

fn config(directory: &Path) -> Config {
    std::fs::write(directory.join("policy.toml"), POLICY).unwrap();
    std::fs::write(directory.join("operator-token"), TOKEN).unwrap();
    serde_json::from_value(json!({
        "listeners": [],
        "policy_file": directory.join("policy.toml"),
        "data_dir": directory.join("data"),
        "agent_api_enabled": false,
        "admin_port": 0,
        "admin_api_token_file": directory.join("operator-token"),
        "readiness_file": directory.join("ready.json"),
        "flow_store_enabled": false,
        "audit_log_path": directory.join("audit.jsonl"),
        "event_log": directory.join("events.jsonl")
    }))
    .unwrap()
}

fn service_config(directory: &Path) -> Config {
    let policy_path = directory.join("policy.toml");
    let token_path = directory.join("operator-token");
    let builtin_services = directory.join("builtin-services");
    let services = directory.join("services");
    fs::write(&policy_path, SERVICE_POLICY).unwrap();
    fs::create_dir(&builtin_services).unwrap();
    fs::create_dir(&services).unwrap();
    fs::write(
        services.join("mail.yaml"),
        "schema_version: 1\nname: mail\nauth: {type: bearer}\ncapabilities:\n  read:\n    routes: []\n",
    )
    .unwrap();
    fs::write(&token_path, TOKEN).unwrap();
    serde_json::from_value(json!({
        "listeners": [],
        "policy_file": policy_path,
        "data_dir": directory.join("data"),
        "gateway_builtin_services_dir": builtin_services,
        "gateway_services_dir": services,
        "agent_api_enabled": false,
        "admin_port": 0,
        "admin_api_token_file": token_path,
        "readiness_file": directory.join("ready.json"),
        "flow_store_enabled": false,
        "circuit_breaker_enabled": false,
        "audit_log_path": directory.join("audit.jsonl"),
        "event_log": directory.join("events.jsonl")
    }))
    .unwrap()
}

async fn raw_admin_request(port: u16, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
