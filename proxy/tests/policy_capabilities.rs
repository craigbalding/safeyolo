//! Current native HTTP/tool boundaries. Controlled ingress is not guest qualification.
#![cfg(target_os = "linux")]
use safeyolo_proxy::{
    coord_tools::Client,
    policy::{Policy, capabilities},
};
use serde_json::{Value, json};
use std::{fs, process::Command};
#[path = "support/controlled_runs.rs"]
mod controlled_runs;
#[allow(dead_code)]
#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::*;

fn candidate(definition: &str, value: Value) -> Value {
    json!({"definition":definition,"value":value,"definition_version":capabilities::discover()["definition_version"]})
}
fn validate(input: Value) -> Result<Value, safeyolo_proxy::Error> {
    capabilities::validate(serde_json::from_value(input)?)
}
#[test]
fn generated_types_and_authoritative_validators_agree() {
    let discovery = capabilities::discover();
    let controls = discovery["definitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["definition"] == "controls")
        .unwrap();
    assert_eq!(
        controls["schema"]["$defs"]["Network"]["properties"]["homoglyph"]["type"],
        "boolean"
    );
    assert!(!controls["declared_effects"].is_null());
    let value =
        json!({"network":{"action":"warn","homoglyph":false},"test_context":{"declared_ttl":120}});
    let result = validate(candidate("controls", value.clone())).unwrap();
    assert_eq!(result["authorized"], false);
    let root = tempfile::tempdir().unwrap();
    let source = "[controls.network]\naction='warn'\nhomoglyph=false\n[controls.test_context]\ndeclared_ttl=120\n";
    fs::write(root.path().join("policy.toml"), source).unwrap();
    Policy::from_native_path(&root.path().join("policy.toml")).unwrap();
    for value in [
        json!({"network":{"action":"invented"}}),
        json!({"network":{"homoglyph":"false"}}),
        json!({"test_context":{"declared_ttl":0}}),
        json!({"extra":true}),
    ] {
        assert!(validate(candidate("controls", value)).is_err());
    }
    assert!(
        validate(candidate(
            "support_operation",
            json!({"action":"guest_probe","timeout_seconds":0})
        ))
        .is_err()
    );
    assert!(
        validate(candidate(
            "support_operation",
            json!({"action":"guest_log","path":"relative"})
        ))
        .is_err()
    );
    assert!(validate(candidate("desktop_present", json!({"ttl_seconds":0}))).is_err());
    assert!(
        validate(candidate(
            "desktop_present",
            json!({"browser_url":"https://user:secret@example.test"})
        ))
        .is_err()
    );
    let mut stale = candidate("controls", json!({}));
    stale["definition_version"] = json!("obsolete");
    assert!(validate(stale).is_err());
}

#[tokio::test]
async fn installed_tools_discover_compose_validate_without_policy_disclosure_or_effects() {
    let fixture = Fixture::new().await;
    let source = fixture.source();
    let client = Client {
        socket: Some(fixture.root.path().join("worker.sock")),
        token_file: fixture.root.path().join("data/agent_token"),
        home: None,
    };
    let before = client
        .call("discover_policy_capabilities", &json!({}))
        .await
        .unwrap();
    assert!(before.get("observations").is_none());
    let controls = before["definitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["definition"] == "controls")
        .unwrap();
    let selected = json!({"network":{"action":controls["schema"]["$defs"]["Action"]["enum"][1]}});
    let result=client.call("validate_policy_capability",&json!({"definition":controls["validator"]["definition"],"value":selected,"definition_version":before["definition_version"]})).await.unwrap();
    assert_eq!(result["valid"], true);
    assert_eq!(result["authorized"], false);
    for _ in 0..2 {
        assert_eq!(
            client
                .call("discover_policy_capabilities", &json!({}))
                .await
                .unwrap(),
            before
        );
    }
    assert_eq!(fixture.source(), source);
    let observer = fixture
        .agent("worker", "GET", "/policy/capabilities?observe=true", None)
        .await;
    assert_eq!(observer.status, 200);
    assert_eq!(
        observer.json()["observations"]["support"]["observation"],
        "unknown"
    );
    for query in [
        "?agent=helper",
        "?target_id=hidden",
        "?snapshot_id=obsolete",
        "?observe=true&agent=helper",
    ] {
        let reply = fixture
            .agent(
                "worker",
                "GET",
                &format!("/policy/capabilities{query}"),
                None,
            )
            .await;
        assert_eq!(reply.status, 400);
        assert!(!String::from_utf8_lossy(&reply.body).contains(SECRET));
    }
    assert!(!before.to_string().contains(WORKER_ID));
    assert!(!before.to_string().contains(SECRET));
    let output = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .args(["policy", "capabilities"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Scope:"));
    fixture.stop().await;
}

async fn grant(fixture: &Fixture, admin: bool) -> Value {
    let mut input = json!({"expected_revision":null,"grant":{
        "instance_id":"sy-11111111111111111111111111111111","support":{"name":"helper","agent_id":HELPER_ID},
        "targets":[{"name":"worker","agent_id":WORKER_ID}],"guest_admin":admin,"guest_logs":[],"lifecycle":[],"expires_at":null,"acknowledgment":null}});
    let preview = fixture
        .admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(input.clone()),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    input["grant"] = preview.json()["after"].clone();
    input["grant"]["acknowledgment"] = preview.json()["acknowledgment"].clone();
    input["authority"] = preview.json()["authority"].clone();
    let result = fixture
        .admin("POST", "/admin/support-grants/incident/apply", Some(input))
        .await;
    assert_eq!(result.status, 200, "{}", result.json());
    result.json()
}

#[tokio::test]
async fn current_permissions_readiness_and_undisclosed_targets_remain_distinct() {
    let fixture = Fixture::new().await;
    let _run = controlled_runs::agent_run(
        fixture.root.path(),
        "helper",
        HELPER_ID,
        "0123456789abcdef0123456789abcdef",
    );
    grant(&fixture, false).await;
    let mut request = json!({"definition_version":capabilities::discover()["definition_version"],"request":{
        "operation_id":"observation-only","grant":"incident","target_id":WORKER_ID,"expected_run":null,
        "operation":{"action":"guest_command","command":"touch must-not-execute","timeout_seconds":1}}});
    let read = fixture
        .agent(
            "helper",
            "POST",
            "/policy/capabilities/support",
            Some(request.clone()),
        )
        .await;
    assert_eq!(read.status, 200);
    assert_eq!(read.json()["supported"], true);
    assert_eq!(read.json()["granted"], false);
    assert_eq!(read.json()["prohibited"], true);
    assert_eq!(read.json()["requestable"], true);
    let client = Client {
        socket: Some(fixture.root.path().join("helper.sock")),
        token_file: fixture.root.path().join("data/agent_token"),
        home: None,
    };
    let tool_observation = client
        .call("observe_support_capability", &request)
        .await
        .unwrap();
    assert_eq!(tool_observation["prohibited"], true);
    let denied_execution = fixture
        .agent(
            "helper",
            "POST",
            "/support/operations",
            Some(request["request"].clone()),
        )
        .await;
    assert_eq!(denied_execution.status, 403);
    let source = fixture.source();
    // Existing operator flow changes the grant; the old observation cannot grant execution.
    let revoke = fixture
        .admin(
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":read.json()["grant_revision"]})),
        )
        .await;
    assert_eq!(revoke.status, 200, "{}", revoke.json());
    grant(&fixture, true).await;
    let read = fixture
        .agent(
            "helper",
            "POST",
            "/policy/capabilities/support",
            Some(request.clone()),
        )
        .await;
    assert_eq!(read.json()["granted"], true, "{}", read.json());
    assert_eq!(read.json()["unavailable"], true, "{}", read.json());
    assert!(!fixture.root.path().join("must-not-execute").exists());
    assert_ne!(fixture.source(), source);
    let saved = fixture.source();
    let mut document: toml::Value = toml::from_str(&saved).unwrap();
    let mut expired: Value =
        serde_json::from_str(document["support_grants"]["incident"].as_str().unwrap()).unwrap();
    expired["expires_at"] = json!("2000-01-01T00:00:00Z");
    let expired_preview = fixture
        .admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(json!({"expected_revision":read.json()["grant_revision"],"grant":expired})),
        )
        .await;
    assert_eq!(expired_preview.status, 200, "{}", expired_preview.json());
    expired = expired_preview.json()["after"].clone();
    expired["acknowledgment"] = expired_preview.json()["acknowledgment"].clone();
    // An acknowledged expired grant retains metadata, but cannot disclose live runtime.
    document["support_grants"]["incident"] = toml::Value::String(expired.to_string());
    fs::write(
        fixture.root.path().join("policy.toml"),
        toml::to_string(&document).unwrap(),
    )
    .unwrap();
    let expired_read = fixture
        .agent(
            "helper",
            "POST",
            "/policy/capabilities/support",
            Some(request.clone()),
        )
        .await
        .json();
    assert_eq!(expired_read["runtime_observation"], "unknown");
    assert!(expired_read["unavailable"].is_null());
    fs::write(fixture.root.path().join("policy.toml"), saved).unwrap();
    request["request"]["target_id"] = json!(HELPER_ID);
    assert_eq!(
        fixture
            .agent(
                "helper",
                "POST",
                "/policy/capabilities/support",
                Some(request.clone())
            )
            .await
            .json()["observation"],
        "unknown"
    );
    request["request"]["target_id"] = json!(WORKER_ID);
    assert_eq!(
        fixture
            .agent(
                "worker",
                "POST",
                "/policy/capabilities/support",
                Some(request.clone())
            )
            .await
            .json()["observation"],
        "unknown"
    );
    request["definition_version"] = json!("obsolete");
    assert!(
        fixture
            .agent(
                "helper",
                "POST",
                "/policy/capabilities/support",
                Some(request)
            )
            .await
            .json()
            .get("error")
            .is_some()
    );
    fixture.stop().await;
}

#[test]
fn compiled_definition_version_tracks_operation_source_and_schema_changes() {
    use ring::digest::{Context, SHA256};
    use std::path::{Path, PathBuf};
    fn files(directory: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, paths)
            } else if path.extension().is_some_and(|extension| extension == "rs")
                || path.file_name().is_some_and(|name| name == "Cargo.toml")
            {
                paths.push(path)
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = vec![
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("build.rs"),
        root.join("../scripts/rust_build_identity.rs"),
    ];
    files(&root.join("src"), &mut paths);
    files(&root.join("vendor"), &mut paths);
    paths.sort();
    let fingerprint = |change: bool| {
        let mut context = Context::new(&SHA256);
        for path in &paths {
            context.update(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .as_bytes(),
            );
            context.update(&[0]);
            let source = fs::read(path).unwrap();
            if change && path.ends_with("policy/native.rs") {
                let text = String::from_utf8(source).unwrap();
                assert!(text.contains("    Block,"));
                // Renaming this serde enum variant changes accepted operation syntax
                // and its derived schema. The installed version must change too.
                context.update(text.replacen("    Block,", "    Refuse,", 1).as_bytes());
            } else {
                context.update(&source)
            }
            context.update(&[0]);
        }
        context
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        capabilities::discover()["definition_version"],
        fingerprint(false)
    );
    assert_ne!(fingerprint(false), fingerprint(true));
}

#[tokio::test]
async fn configured_service_discovery_omits_secret_and_other_agent_fields() {
    let fixture = Fixture::new().await;
    fs::write(fixture.root.path().join("services/example.yaml"),"schema_version: 1\nname: example\ndescription: Example public description\ncapabilities:\n  read:\n    routes:\n      - methods: [GET]\n        path: '/**'\n").unwrap();
    let fixture = fixture.restart().await;
    fixture.apply(&format!("{}\n[agents.worker.services.example]\ncapability='read'\ntoken='{SECRET}'\naccount='private-worker-account'\n[agents.helper.services.example]\ncapability='read'\ntoken='another-agent-secret'\naccount='private-helper-account'\n",fixture.source())).await;
    let read = fixture
        .agent("worker", "GET", "/policy/capabilities?observe=true", None)
        .await;
    assert_eq!(read.status, 200);
    let view = read.json();
    let encoded = view.to_string();
    for hidden in [
        SECRET,
        "another-agent-secret",
        "private-helper-account",
        "private-worker-account",
        "sgw_",
    ] {
        assert!(
            !encoded.contains(hidden),
            "discovery exposed secret-bearing service state"
        );
    }
    assert_eq!(
        view["observations"]["services"]["authorized"][0]["service"],
        "example"
    );
    assert_eq!(
        view["observations"]["services"]["authorized"][0]["configured_authorization"],
        true
    );
    assert_eq!(
        view["observations"]["services"]["authorized"][0]["readiness_observation"],
        "unknown"
    );
    let saved = fixture.source();
    fs::write(fixture.root.path().join("policy.toml"), "invalid ! policy").unwrap();
    let read = fixture
        .agent("worker", "GET", "/policy/capabilities?observe=true", None)
        .await;
    assert_eq!(
        read.json()["observations"]["support"]["observation"],
        "unknown"
    );
    fs::write(fixture.root.path().join("policy.toml"), saved).unwrap();
    fixture.stop().await;
}
