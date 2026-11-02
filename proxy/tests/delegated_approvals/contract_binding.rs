//! Derived bindings share the canonical run-grant owner and real request checks.
use super::*;

const TEMPLATE: &str = "delegated.binding.v1";
const CONTRACT: &str = r#"schema_version: 1
name: scoped
default_host: HOST
auth:
  type: bearer
  allow_http: true
capabilities:
  reader:
    contract:
      template: delegated.binding.v1
      bindings:
        project: {type: string}
        count: {type: integer}
        enabled: {type: boolean}
        labels: {type: string_list}
        choice: {type: enum, options: [alpha, beta]}
      operations:
        - name: read
          request:
            method: GET
            path: /data/{project}
            path_params: {project: {equals_var: project}}
            query: {allow: {project: {equals_var: project}}}
        - name: inspect
          request:
            method: GET
            path: /inspect/{project}
            path_params: {project: {equals_var: project}}
        - name: write
          request:
            method: POST
            path: /data/{project}
            path_params: {project: {equals_var: project}}
            body:
              allow:
                project: {equals_var: project}
                count: {equals_var: count}
                enabled: {equals_var: enabled}
                labels: {equals_var: labels}
                choice: {equals_var: choice}
        - name: stateful
          requires_enforcement: state_enforcement
          request: {method: DELETE, path: "/data/{project}"}
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_enforcement: declared
risky_routes:
  - methods: [POST]
    path: /data/*
    tactics: [impact]
"#;

async fn setup() -> (Fixture, Backend, safeyolo_proxy::credentials::Vault) {
    let (f, backend, vault) = service_authorization::setup().await;
    fs::write(
        f.root.path().join("services/scoped.yaml"),
        CONTRACT.replace("HOST", &f.address.ip().to_string()),
    )
    .unwrap();
    let mut source: toml::Value = toml::from_str(&f.source()).unwrap();
    source["hosts"].as_table_mut().unwrap().insert(
        f.address.ip().to_string(),
        toml::Value::try_from(json!({"service":"scoped"})).unwrap(),
    );
    for agent in ["worker", "helper", "peer"] {
        source["agents"][agent].as_table_mut().unwrap().insert("services".into(), toml::Value::try_from(json!({"scoped":{"capability":"reader","token":"provider","account":"work-account"}})).unwrap());
    }
    fs::write(
        f.root.path().join("policy.toml"),
        toml::to_string(&source).unwrap(),
    )
    .unwrap();
    (f.restart().await, backend, vault)
}

fn envelope(f: &Fixture) -> Value {
    let mut input = proposal(f);
    input["delegation"]["scopes"] = json!([{"type":"contract_binding", "service":"scoped", "capability":"reader", "template":TEMPLATE,
        "bound_values":{"project":["alpha","beta"],"count":[2],"enabled":[true],"labels":[["x","y"]],"choice":["alpha","beta"]}, "grantable_operations":["read","write"]}]);
    input
}
fn values(project: &str) -> Value {
    json!({"project":project,"count":2,"enabled":true,"labels":["x","y"],"choice":"alpha"})
}
async fn submit(f: &Fixture, agent: &str, bound: Value, operations: Value) -> Reply {
    f.agent(agent, "POST", "/gateway/submit-binding", Some(json!({"service":"scoped","capability":"reader","bindings":bound,"grantable_operations":operations}))).await
}
async fn header(f: &Fixture, agent: &str) -> String {
    let catalog = f
        .agent(agent, "GET", "/gateway/services", None)
        .await
        .json();
    format!(
        "Authorization: Bearer {}\r\n",
        catalog["authorized"]["scoped"]["token"].as_str().unwrap()
    )
}
async fn use_binding(f: &Fixture, agent: &str, method: &str, path: &str) -> Reply {
    f.request(agent, f.address, method, path, &header(f, agent).await)
        .await
}
async fn permitted(f: &Fixture, path: &str) {
    let observer = tokio::spawn(origin(f.origin.clone()));
    let reply = use_binding(f, "worker", "GET", path).await;
    assert_eq!(
        reply.status,
        200,
        "{path}: {}",
        String::from_utf8_lossy(&reply.body)
    );
    let raw = String::from_utf8(observer.await.unwrap()).unwrap();
    assert!(raw.starts_with(&format!("GET {path} ")));
    assert!(raw.contains(SECRET));
    assert!(!raw.contains("sgw_"));
}
async fn grant(f: &Fixture, project: &str) -> String {
    let submitted = submit(f, "worker", values(project), json!(["read", "write"])).await;
    assert_eq!(submitted.status, 202, "{}", submitted.json());
    let id = submitted.id();
    let approved = decide(f, "helper", &id, "approve", "run").await;
    assert_eq!(approved.status, 200, "{}", approved.json());
    assert_eq!(approved.json()["grant_active"], true, "{}", approved.json());
    id
}

#[tokio::test]
async fn complete_fixed_binding_option_race_retry_and_separate_access() {
    let (f, _backend, _vault) = setup().await;
    delegate(&f, envelope(&f)).await;
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/alpha").await.status,
        403
    );
    let request = submit(&f, "worker", values("alpha"), json!(["read"])).await;
    assert_eq!(request.status, 202, "{}", request.json());
    let id = request.id();
    let view = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(view.status, 200, "{}", view.json());
    let view = view.json();
    assert_eq!(view["observed"]["template"], TEMPLATE);
    assert_eq!(view["observed"]["grantable_operations"], json!(["read"]));
    assert_eq!(
        view["choices"][0]["binding_envelopes"][0]["bound_value_choice_indices"]["project"],
        0
    );
    assert!(!view.to_string().contains(SECRET));
    assert_eq!(view["options"].as_array().unwrap().len(), 1);
    assert_eq!(
        decide(&f, "worker", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(
        decide(&f, "helper", &id, "approve", "persistent")
            .await
            .status,
        409
    );
    let widened = f.agent("helper","POST",&format!("/approvals/{id}/resolve"),Some(json!({"delegation":"local","decision":"approve","option":"run","bindings":{"project":"other"}}))).await;
    assert_eq!(widened.status, 400);
    let (a, b) = tokio::join!(
        decide(&f, "helper", &id, "approve", "run"),
        decide(&f, "peer", &id, "approve", "run")
    );
    assert_eq!(a.status, 200, "{}", a.json());
    assert_eq!(b.status, 200, "{}", b.json());
    let document: toml::Value = toml::from_str(&f.source()).unwrap();
    assert_eq!(
        document["agents"]["worker"]["binding_grants"]
            .as_table()
            .unwrap()
            .len(),
        1
    );
    no_origin(&f).await;
    permitted(&f, "/data/alpha?project=alpha").await;
    for (agent, method, path) in [
        ("worker", "GET", "/data/alpha?project=beta"),
        ("worker", "GET", "/data/beta"),
        ("worker", "GET", "/inspect/alpha"),
        ("worker", "POST", "/data/alpha"),
        ("helper", "GET", "/data/alpha"),
        ("peer", "GET", "/data/alpha"),
    ] {
        assert_eq!(
            use_binding(&f, agent, method, path).await.status,
            403,
            "{agent}/{method}/{path}"
        );
    }
    let foreign = f
        .request(
            "helper",
            f.address,
            "GET",
            "/data/alpha",
            &header(&f, "worker").await,
        )
        .await;
    assert_eq!(foreign.status, 403);
    no_origin(&f).await;
    // A second binding grants write, but cannot approve its risk decision.
    grant(&f, "alpha").await;
    assert_eq!(
        use_binding(&f, "worker", "POST", "/data/alpha")
            .await
            .status,
        428
    );
    no_origin(&f).await;
    let source = f
        .source()
        .replace("egress = \"allow\"", "egress = \"deny\"");
    f.apply(&source).await;
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/alpha").await.status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn binding_envelope_types_operations_and_whole_scope_containment() {
    let (f, _backend, _vault) = setup().await;
    for (field, value) in [
        ("service", json!("missing")),
        ("capability", json!("missing")),
        ("template", json!("missing")),
        ("grantable_operations", json!(["stateful"])),
        ("grantable_operations", json!(["unknown"])),
        ("bound_values", json!({"project":["a/b"]})),
        ("bound_values", json!({"project":["alpha"],"count":[true]})),
        ("bound_values", json!({"project":["alpha"],"labels":["x"]})),
        ("bound_values", json!({"project":["alpha"],"unknown":["x"]})),
    ] {
        let mut input = envelope(&f);
        input["delegation"]["scopes"][0][field] = value;
        let result = f
            .admin(
                "POST",
                "/admin/approval-delegations/local/preview",
                Some(input),
            )
            .await;
        assert_ne!(
            result.status,
            200,
            "accepted unsupported {field}: {}",
            result.json()
        );
    }
    let mut unresolved = envelope(&f);
    unresolved["delegation"]["scopes"][0]["bound_values"]["project"] = json!(["alpha", "{other}"]);
    assert_ne!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/preview",
            Some(unresolved)
        )
        .await
        .status,
        200
    );
    delegate(&f, envelope(&f)).await;
    for (bound, operations) in [
        (values("foreign"), json!(["read"])),
        (values("alpha"), json!(["inspect"])),
        (values("alpha"), json!(["read", "inspect"])),
    ] {
        let result = submit(&f, "worker", bound, operations).await;
        assert_eq!(result.status, 202, "{}", result.json());
        assert_eq!(
            f.agent(
                "helper",
                "GET",
                &format!("/approvals/{}", result.id()),
                None
            )
            .await
            .status,
            404
        );
        assert_eq!(
            decide(&f, "helper", &result.id(), "approve", "run")
                .await
                .status,
            409
        );
    }
    let mut invalid = values("alpha");
    invalid["count"] = json!(true);
    assert_eq!(
        submit(&f, "worker", invalid, json!(["read"])).await.json()["decision"],
        "denied_out_of_scope"
    );
    assert_eq!(
        submit(&f, "worker", values("alpha"), json!(["stateful"]))
            .await
            .json()["decision"],
        "denied_out_of_scope"
    );
    // Neither complete option may be assembled from two partial scopes.
    let mut input = envelope(&f);
    // Read the exact revision from the encoded authoritative record.
    let doc: toml::Value = toml::from_str(&f.source()).unwrap();
    let stored: Value =
        serde_json::from_str(doc["approval_delegations"]["local"].as_str().unwrap()).unwrap();
    input["expected_revision"] = stored["acknowledgment"].clone();
    input["delegation"]["scopes"][0]["grantable_operations"] = json!(["read"]);
    let mut second = input["delegation"]["scopes"][0].clone();
    second["grantable_operations"] = json!(["write"]);
    input["delegation"]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(second);
    delegate(&f, input).await;
    let request = submit(&f, "worker", values("beta"), json!(["read", "write"])).await;
    assert_eq!(
        decide(&f, "helper", &request.id(), "approve", "run")
            .await
            .status,
        409
    );
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/beta").await.status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

async fn operator_binding(f: &Fixture) {
    let submitted = submit(f, "worker", values("operator"), json!(["read", "inspect"])).await;
    assert_eq!(submitted.status, 202, "{}", submitted.json());
    let result = f
        .admin(
            "POST",
            &format!("/admin/approvals/{}", submitted.id()),
            Some(json!({"decision":"approve","option":"persistent"})),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.json());
}

#[tokio::test]
async fn binding_restart_revoke_narrow_expiry_and_run_replacement_preserve_operator_access() {
    for cause in [
        "revoke",
        "narrow",
        "grant_expiry",
        "delegation_expiry",
        "worker_stop",
        "worker_run",
        "worker_identity",
        "reviewer_identity",
        "definition",
    ] {
        let (f, _backend, _vault) = setup().await;
        operator_binding(&f).await;
        let mut input = envelope(&f);
        if cause == "grant_expiry" {
            input["delegation"]["grant_seconds"] = json!(3);
        }
        if cause == "delegation_expiry" {
            input["delegation"]["expires_at"] = json!(
                (time::OffsetDateTime::now_utc() + time::Duration::seconds(5))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            );
        }
        let (mut input, revision) = delegate(&f, input).await;
        let id = grant(&f, "alpha").await;
        permitted(&f, "/data/alpha").await;
        permitted(&f, "/data/operator").await;
        let mut f = f.restart().await;
        permitted(&f, "/data/alpha").await;
        match cause {
            "revoke" => {
                assert_eq!(
                    f.admin(
                        "POST",
                        "/admin/approval-delegations/local/revoke",
                        Some(json!({"expected_revision":revision}))
                    )
                    .await
                    .status,
                    200
                );
            }
            "narrow" => {
                input["expected_revision"] = json!(revision);
                input["delegation"]["acknowledgment"] = Value::Null;
                input["delegation"]["definition_revisions"] = json!({});
                input["delegation"]["scopes"][0]["bound_values"]["project"] = json!(["beta"]);
                delegate(&f, input).await;
            }
            "grant_expiry" => tokio::time::sleep(Duration::from_millis(3100)).await,
            "delegation_expiry" => tokio::time::sleep(Duration::from_millis(5100)).await,
            "worker_stop" | "worker_run" => {
                let path = f.root.path().join("agents/worker/runtime.json");
                let mut run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                if cause == "worker_stop" {
                    run["state"] = json!("stopped");
                } else {
                    run["run_id"] = json!("1123456789abcdef0123456789abcdef");
                }
                fs::write(path, run.to_string()).unwrap();
            }
            "worker_identity" | "reviewer_identity" => {
                let old = if cause == "worker_identity" {
                    WORKER_ID
                } else {
                    HELPER_ID
                };
                let source = f.source().replace(
                    &format!("agent_id = \"{old}\""),
                    "agent_id = \"ag-99999999999999999999999999999999\"",
                );
                fs::write(f.root.path().join("policy.toml"), source).unwrap();
            }
            "definition" => {
                fs::write(
                    f.root.path().join("services/scoped.yaml"),
                    CONTRACT
                        .replace("HOST", &f.address.ip().to_string())
                        .replace("deny_unknown: true", "deny_unknown: false")
                        .replace(
                            "path: /inspect/{project}",
                            "path: /inspect-changed/{project}",
                        ),
                )
                .unwrap();
                f = f.restart().await;
            }
            _ => unreachable!(),
        }
        let reply = use_binding(&f, "worker", "GET", "/data/alpha").await;
        assert_eq!(
            reply.status,
            403,
            "{cause}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        let view = f
            .admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json();
        assert_eq!(view["grant_active"], false, "{cause}: {view}");
        // Independent operator access is not run-bound, including after recreation.
        permitted(&f, "/data/operator").await;
        no_origin(&f).await;
        f.stop().await;
    }
}

#[tokio::test]
async fn binding_canonical_failure_restart_and_audit_failure_keep_one_record_without_replay() {
    let (f, _backend, _vault) = setup().await;
    delegate(&f, envelope(&f)).await;
    let submitted = submit(&f, "worker", values("alpha"), json!(["read"])).await;
    let id = submitted.id();
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_binding_result BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    let accepted = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(accepted["status"], "approved");
    assert_eq!(accepted["grant_active"], true);
    let saved = f.source();
    no_origin(&f).await;
    db.execute_batch("DROP TRIGGER fail_binding_result")
        .unwrap();
    drop(db);
    let f = f.restart().await;
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    assert_eq!(f.source(), saved);
    let recovered = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(accepted["result"], recovered["result"]);
    permitted(&f, "/data/alpha").await;
    let next = submit(&f, "worker", values("beta"), json!(["read"])).await;
    assert_eq!(next.status, 202);
    f.make_audit_unavailable();
    let approved = decide(&f, "helper", &next.id(), "approve", "run").await;
    assert_eq!(approved.status, 200, "{}", approved.json());
    assert_eq!(
        approved.json()["audit_status"],
        "unavailable; the canonical decision is saved"
    );
    permitted(&f, "/data/beta").await;
    f.stop().await;
}

async fn body_status(f: &Fixture, body: Value) -> u16 {
    let mut stream = tokio::net::UnixStream::connect(f.root.path().join("worker.sock"))
        .await
        .unwrap();
    let body = body.to_string();
    let header = header(f, "worker").await;
    stream.write_all(format!("POST http://{}/data/alpha HTTP/1.1\r\nHost: {}\r\n{header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",f.address,f.address,body.len()).as_bytes()).await.unwrap();
    let mut response = vec![];
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn bound_scalar_and_list_values_are_enforced_on_the_real_body_path() {
    let (f, _backend, _vault) = setup().await;
    let mut source: toml::Value = toml::from_str(&f.source()).unwrap();
    source["risk"][0]["decision"] = toml::Value::String("allow".into());
    f.apply(&toml::to_string(&source).unwrap()).await;
    delegate(&f, envelope(&f)).await;
    grant(&f, "alpha").await;
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(body_status(&f, values("alpha")).await, 200);
    assert!(!observer.await.unwrap().is_empty());
    for (field, value) in [
        ("project", json!("beta")),
        ("count", json!(3)),
        ("enabled", json!(false)),
        ("labels", json!(["x"])),
        ("choice", json!("beta")),
    ] {
        let mut bound = values("alpha");
        bound[field] = value;
        assert_eq!(body_status(&f, bound).await, 403, "{field}");
    }
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn binding_storage_activation_stale_request_and_denial_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let (f, _backend, _vault) = setup().await;
    delegate(&f, envelope(&f)).await;
    let denied = submit(&f, "worker", values("beta"), json!(["read"]))
        .await
        .id();
    assert_eq!(f.resolve(&denied, "reject").await.status, 200);
    assert_eq!(
        decide(&f, "helper", &denied, "approve", "run").await.json()["status"],
        "rejected"
    );
    let id = submit(&f, "worker", values("alpha"), json!(["read"]))
        .await
        .id();
    let before = f.source();
    let permissions = fs::metadata(f.root.path()).unwrap().permissions();
    fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let failed = decide(&f, "helper", &id, "approve", "run").await;
    fs::set_permissions(f.root.path(), permissions).unwrap();
    assert_eq!(failed.status, 409);
    assert_eq!(f.source(), before);
    let invalid = format!("{before}\n[credential.activation_failure]\nmatch=['(?a)(?u)']\n");
    fs::write(f.root.path().join("policy.toml"), &invalid).unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(f.source(), invalid);
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/alpha").await.status,
        403
    );
    fs::write(f.root.path().join("policy.toml"), &before).unwrap();
    let changed = before.replace("budget = 4000", "budget = 3999");
    assert_ne!(changed, before);
    f.apply(&changed).await;
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/alpha").await.status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn binding_alone_does_not_authorize_a_service_or_another_agents_token() {
    let (f, _backend, _vault) = setup().await;
    let mut source: toml::Value = toml::from_str(&f.source()).unwrap();
    source["agents"]["worker"]
        .as_table_mut()
        .unwrap()
        .remove("services");
    f.apply(&toml::to_string(&source).unwrap()).await;
    delegate(&f, envelope(&f)).await;
    grant(&f, "alpha").await;
    let services = f
        .agent("worker", "GET", "/gateway/services", None)
        .await
        .json();
    assert!(services["authorized"]["scoped"].is_null());
    let helper_token = header(&f, "helper").await;
    assert_eq!(
        f.request("worker", f.address, "GET", "/data/alpha", &helper_token)
            .await
            .status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn binding_decision_cannot_override_an_explicit_gateway_deny() {
    let (f, _backend, _vault) = setup().await;
    let mut source: toml::Value = toml::from_str(&f.source()).unwrap();
    source["hosts"][f.address.ip().to_string()].as_table_mut().unwrap().insert("rules".into(),toml::Value::try_from(json!([
        {"action":"gateway:request","resource":"*","effect":"deny","condition":{"agent":"worker","capability":"reader","method":"GET"}}
    ])).unwrap());
    f.apply(&toml::to_string(&source).unwrap()).await;
    delegate(&f, envelope(&f)).await;
    let id = grant(&f, "alpha").await;
    assert_eq!(
        use_binding(&f, "worker", "GET", "/data/alpha").await.status,
        403
    );
    let view = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(view["grant_active"], true, "{view}");
    no_origin(&f).await;
    f.stop().await;
}
