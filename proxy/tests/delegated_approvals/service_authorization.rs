//! Service access uses canonical decisions and the real gateway/origin boundary.
use super::*;
use safeyolo_proxy::credentials::{Credential, Secret, Vault};

async fn setup() -> (Fixture, Backend, Vault) {
    let f = Fixture::new().await;
    let backend = Backend(runs(&f));
    fs::write(f.root.path().join("services/scoped.yaml"), format!(
        "schema_version: 1\nname: scoped\ndefault_host: {}\nauth:\n  type: bearer\n  allow_http: true\ncapabilities:\n  reader:\n    routes:\n      - methods: [GET, POST]\n        path: /data/*\nrisky_routes:\n  - methods: [POST]\n    path: /data/*\n    tactics: [impact]\n", f.address.ip())).unwrap();
    fs::write(
        f.root.path().join("data/credentials.key"),
        "synthetic-service-key",
    )
    .unwrap();
    let vault = Vault::unlock(
        f.root.path().join("data/credentials.enc"),
        &Secret::new("synthetic-service-key"),
    )
    .unwrap();
    vault
        .store(Credential::new("provider", "api_key", Secret::new(SECRET)))
        .unwrap();
    vault
        .store(Credential::new(
            "alternate",
            "api_key",
            Secret::new("other-secret"),
        ))
        .unwrap();
    let definition = f.root.path().join("services/scoped.yaml");
    let expanded = fs::read_to_string(&definition).unwrap().replace(
        "risky_routes:",
        "  writer:\n    routes:\n      - methods: [GET]\n        path: /other/*\nrisky_routes:",
    );
    fs::write(&definition, &expanded).unwrap();
    fs::write(
        f.root.path().join("services/other.yaml"),
        expanded.replace("name: scoped", "name: other"),
    )
    .unwrap();
    let source = format!(
        "{}\n[[risk]]\naccount='work-account'\ntactics=['impact']\ndecision='require_approval'\n",
        f.source()
            .replace("egress='prompt'", "egress='allow'")
            .replace("budget=40", "budget=4000")
    );
    fs::write(f.root.path().join("policy.toml"), source).unwrap();
    (f.restart().await, backend, vault)
}

fn service_proposal(f: &Fixture) -> Value {
    let mut input = proposal(f);
    input["delegation"]["scopes"] = json!([{"type":"service_authorization", "service":"scoped", "capability":"reader", "account":"work-account", "credential":"provider", "resources":["/data/*"]}]);
    input
}

async fn request(f: &Fixture, paths: Value) -> Reply {
    f.agent("worker", "POST", "/gateway/request-access", Some(json!({"service":"scoped", "capability":"reader", "account":"work-account", "credential":"provider", "resources":paths}))).await
}

async fn token(f: &Fixture) -> String {
    f.agent("worker", "GET", "/gateway/services", None)
        .await
        .json()["authorized"]["scoped"]["token"]
        .as_str()
        .expect("worker scoped token")
        .into()
}

async fn permitted(f: &Fixture, token: &str, path: &str) {
    let observer = tokio::spawn(origin(f.origin.clone()));
    let reply = f
        .request(
            "worker",
            f.address,
            "GET",
            path,
            &format!("Authorization: Bearer {token}\r\n"),
        )
        .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let raw = String::from_utf8(observer.await.unwrap()).unwrap();
    assert!(raw.starts_with(&format!("GET {path} ")));
    assert!(
        raw.to_ascii_lowercase()
            .contains(&format!("authorization: bearer {SECRET}"))
    );
    assert!(!raw.contains("sgw_"));
}

#[tokio::test]
async fn delegated_service_race_scope_risk_revocation_and_operator_access() {
    let (f, _backend, _vault) = setup().await;
    let mut envelope = service_proposal(&f);
    envelope["delegation"]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "type":"gateway_route", "service":"scoped", "capability":"reader",
            "binding_id":null, "method":"POST", "path":"/data/chosen"
        }));
    let (_, revision) = delegate(&f, envelope).await;
    let pending = request(&f, json!(["/data/chosen"])).await;
    assert_eq!(pending.status, 202, "{}", pending.json());
    let id = pending.id();
    let view = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(view.status, 200, "{}", view.json());
    assert_eq!(
        view.json()["observed"]["resource_scope"],
        json!(["/data/chosen"])
    );
    assert_eq!(view.json()["choices"][0]["option"], "run");
    assert!(!view.json().to_string().contains(SECRET));
    assert_eq!(
        decide(&f, "worker", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(
        decide(&f, "helper", &id, "approve", "credential:provider")
            .await
            .status,
        409
    );
    let (one, two) = tokio::join!(
        decide(&f, "helper", &id, "approve", "run"),
        decide(&f, "peer", &id, "approve", "run")
    );
    assert_eq!(one.status, 200, "{}", one.json());
    assert_eq!(two.status, 200, "{}", two.json());
    assert_eq!(one.json()["grant_active"], true);
    assert_eq!(
        f.admin("GET", "/admin/approval-delegations", None)
            .await
            .json()["issued_access"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    no_origin(&f).await;
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    let header = format!("Authorization: Bearer {selected}\r\n");
    assert_eq!(
        f.request("worker", f.address, "GET", "/data/other", &header)
            .await
            .status,
        403
    );
    let risky = f
        .request("worker", f.address, "POST", "/data/chosen", &header)
        .await;
    assert_eq!(risky.status, 428);
    no_origin(&f).await;
    let separately_approved = decide(&f, "helper", &risky.id(), "approve", "delegated_once").await;
    assert_eq!(
        separately_approved.status,
        200,
        "{}",
        separately_approved.json()
    );
    no_origin(&f).await;
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(
        f.request("worker", f.address, "POST", "/data/chosen", &header)
            .await
            .status,
        200
    );
    let raw = String::from_utf8(observer.await.unwrap()).unwrap();
    assert!(raw.starts_with("POST /data/chosen ") && raw.contains(SECRET) && !raw.contains("sgw_"));
    assert_eq!(
        f.request("worker", f.address, "POST", "/data/chosen", &header)
            .await
            .status,
        428
    );
    assert_eq!(
        f.admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["grant_active"],
        true
    );
    assert_eq!(
        f.request("helper", f.address, "GET", "/data/chosen", &header)
            .await
            .status,
        403
    );
    assert!(
        f.agent("helper", "GET", "/gateway/services", None)
            .await
            .json()["authorized"]["scoped"]
            .is_null()
    );
    no_origin(&f).await;
    // Independent operator authorization survives removal of this delegation.
    let operator = f.admin("POST", "/admin/agents/worker/services", Some(json!({"service":"scoped","capability":"reader","credential":"provider","account":"work-account"}))).await;
    assert_eq!(operator.status, 200, "{}", operator.json());
    let revoked = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    assert_eq!(
        f.request("worker", f.address, "GET", "/data/chosen", &header)
            .await
            .status,
        403
    );
    permitted(&f, &token(&f).await, "/data/other").await;
    f.stop().await;
}

#[tokio::test]
async fn service_envelope_fields_and_partial_delegations_cannot_widen_access() {
    let (f, _backend, _vault) = setup().await;
    let pending = request(&f, json!(["/data/one", "/data/two"])).await;
    assert_eq!(pending.status, 202);
    let id = pending.id();
    for (field, wrong) in [
        ("account", json!("other")),
        ("credential", json!("alternate")),
        ("service", json!("other")),
        ("capability", json!("writer")),
        ("resources", json!(["/elsewhere/*"])),
    ] {
        let mut candidate = service_proposal(&f);
        candidate["delegation"]["scopes"][0][field] = wrong;
        let preview = f
            .admin(
                "POST",
                "/admin/approval-delegations/local/preview",
                Some(candidate.clone()),
            )
            .await;
        if preview.status == 200 {
            let (_, revision) = delegate(&f, candidate).await;
            assert_eq!(
                decide(&f, "helper", &id, "approve", "run").await.status,
                409,
                "{field}"
            );
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
        } else {
            assert_eq!(preview.status, 409, "{field}");
        }
    }
    let mut input = service_proposal(&f);
    input["delegation"]["scopes"][0]["resources"] = json!(["/data/one"]);
    delegate(&f, input.clone()).await;
    input["delegation"]["scopes"][0]["resources"] = json!(["/data/two"]);
    let preview = f
        .admin(
            "POST",
            "/admin/approval-delegations/second/preview",
            Some(input.clone()),
        )
        .await
        .json();
    input["delegation"] = preview["after"].clone();
    input["delegation"]["acknowledgment"] = preview["acknowledgment"].clone();
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/second/apply",
            Some(input)
        )
        .await
        .status,
        200
    );
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    no_origin(&f).await;
    assert!(
        f.agent("worker", "GET", "/gateway/services", None)
            .await
            .json()["authorized"]["scoped"]
            .is_null()
    );
    f.stop().await;
}

#[tokio::test]
async fn service_preflight_and_file_reload_reject_unsupported_bounds_without_banning_breadth() {
    let (f, _backend, _vault) = setup().await;
    let before = f.source();
    for field in ["once", "ports", "method", "payload"] {
        let mut input = service_proposal(&f);
        input["delegation"]["scopes"][0][field] = json!(true);
        assert_eq!(
            f.admin(
                "POST",
                "/admin/approval-delegations/local/preview",
                Some(input)
            )
            .await
            .status,
            409
        );
    }
    let mut self_benefit = service_proposal(&f);
    self_benefit["delegation"]["beneficiaries"] = json!([{"name":"helper","agent_id":HELPER_ID}]);
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/preview",
            Some(self_benefit)
        )
        .await
        .status,
        409
    );
    assert_eq!(f.source(), before);
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/apply",
            Some(service_proposal(&f))
        )
        .await
        .status,
        409
    );
    let mut broad = service_proposal(&f);
    broad["delegation"]["scopes"][0]["resources"] = json!(["*"]);
    broad["delegation"]["grant_seconds"] = json!(60 * 60 * 24 * 365_u64);
    delegate(&f, broad).await;
    let mut document: toml::Value = toml::from_str(&f.source()).unwrap();
    let mut encoded: Value =
        serde_json::from_str(document["approval_delegations"]["local"].as_str().unwrap()).unwrap();
    encoded["scopes"][0]["credential_binding"] = Value::Null;
    document["approval_delegations"]["local"] = toml::Value::String(encoded.to_string());
    let saved = f.source();
    let invalid = f
        .admin(
            "PUT",
            "/admin/policy/baseline",
            Some(json!({"source":toml::to_string(&document).unwrap()})),
        )
        .await;
    assert_ne!(invalid.status, 200);
    assert_eq!(f.source(), saved);
    for extra in [
        json!({"lifetime":"once"}),
        json!({"ttl_seconds":1}),
        json!({"ports":[443]}),
    ] {
        let mut request = json!({"service":"scoped","capability":"reader","account":"work-account","credential":"provider","resources":["/data/chosen"]});
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            f.agent("worker", "POST", "/gateway/request-access", Some(request))
                .await
                .status,
            400
        );
    }
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn service_lost_canonical_write_and_proxy_restart_recover_the_same_grant_without_replay() {
    let (f, _backend, _vault) = setup().await;
    delegate(&f, service_proposal(&f)).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_service_result BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
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
    let old = token(&f).await;
    let saved = f.source();
    no_origin(&f).await;
    db.execute_batch("DROP TRIGGER fail_service_result")
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
    let selected = token(&f).await;
    assert_ne!(old, selected);
    no_origin(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    f.stop().await;
}

#[tokio::test]
async fn service_run_stop_narrowing_and_expiry_remove_only_derived_access() {
    let (f, _backend, _vault) = setup().await;
    let (mut input, revision) = delegate(&f, service_proposal(&f)).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    let path = f.root.path().join("agents/worker/runtime.json");
    let run = fs::read(&path).unwrap();
    let mut stopped: Value = serde_json::from_slice(&run).unwrap();
    stopped["state"] = json!("stopped");
    fs::write(&path, stopped.to_string()).unwrap();
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n")
        )
        .await
        .status,
        403
    );
    no_origin(&f).await;
    fs::write(&path, &run).unwrap();
    permitted(&f, &selected, "/data/chosen").await;
    input["expected_revision"] = json!(revision);
    input["delegation"]["scopes"][0]["resources"] = json!(["/data/other"]);
    input["delegation"]["definition_revisions"] = json!({});
    input["delegation"]["acknowledgment"] = Value::Null;
    let (_, revision) = delegate(&f, input).await;
    let refused = f
        .request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n"),
        )
        .await;
    // Removing the final service route uses the existing reserved-token refusal.
    assert_eq!(refused.status, 503, "{}", refused.json());
    assert!(String::from_utf8_lossy(&refused.body).contains("GATEWAY_CONFIGURATION_ERROR"));
    no_origin(&f).await;
    let mut bounded = service_proposal(&f);
    bounded["expected_revision"] = json!(revision);
    bounded["delegation"]["grant_seconds"] = json!(1);
    delegate(&f, bounded).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n")
        )
        .await
        .status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn failed_service_persistence_activation_and_audit_do_not_hide_authority() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (f, _backend, _vault) = setup().await;
    delegate(&f, service_proposal(&f)).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    let before = f.source();
    let permissions = fs::metadata(f.root.path()).unwrap().permissions();
    fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let failed = decide(&f, "helper", &id, "approve", "run").await;
    fs::set_permissions(f.root.path(), permissions).unwrap();
    assert_eq!(failed.status, 409);
    assert_eq!(f.source(), before);
    let policy = f.root.path().join("policy.toml");
    let invalid = format!("{before}\n[credential.activation_failure]\nmatch=['(?a)(?u)']\n");
    fs::write(&policy, &invalid).unwrap();
    let held = fs::File::open(&policy).unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(f.source(), invalid);
    assert_ne!(
        held.metadata().unwrap().ino(),
        fs::metadata(&policy).unwrap().ino()
    );
    assert!(
        f.agent("worker", "GET", "/gateway/services", None)
            .await
            .json()["authorized"]["scoped"]
            .is_null()
    );
    no_origin(&f).await;
    fs::write(policy, before).unwrap();
    f.make_audit_unavailable();
    let approved = decide(&f, "helper", &id, "approve", "run").await;
    assert_eq!(approved.status, 200, "{}", approved.json());
    assert_eq!(
        approved.json()["audit_status"],
        "unavailable; the canonical decision is saved"
    );
    let saved = f.source();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    assert_eq!(f.source(), saved);
    no_origin(&f).await;
    permitted(&f, &token(&f).await, "/data/chosen").await;
    f.stop().await;
}

#[tokio::test]
async fn service_authorization_does_not_supply_a_contract_binding() {
    let (mut f, _backend, _vault) = setup().await;
    fs::write(f.root.path().join("services/scoped.yaml"), format!(
        "schema_version: 1\nname: scoped\ndefault_host: {}\nauth:\n  type: bearer\n  allow_http: true\ncapabilities:\n  reader:\n    contract:\n      template: scoped.v1\n      bindings:\n        project:\n          source: operator\n          type: enum\n          options: [alpha, beta]\n      operations:\n        - name: write\n          request:\n            method: POST\n            path: /data/chosen\n            body:\n              allow:\n                project:\n                  equals_var: project\n      enforcement:\n        request_shape: enforced\n        transport_hygiene: enforced\n        state_capture: declared\n        state_enforcement: declared\n        response_validators: declared\n", f.address.ip())).unwrap();
    assert!(f.proxy.reload_services_if_changed().await.unwrap());
    delegate(&f, service_proposal(&f)).await;
    let pending = request(&f, json!(["/data/chosen"])).await;
    assert_eq!(pending.status, 202, "{}", pending.json());
    assert_eq!(
        decide(&f, "helper", &pending.id(), "approve", "run")
            .await
            .status,
        200
    );
    let selected = token(&f).await;
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "POST",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n")
        )
        .await
        .status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn service_credential_and_definition_changes_and_run_stop_invalidate_access() {
    let (f, _backend, vault) = setup().await;
    delegate(&f, service_proposal(&f)).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    vault
        .store(Credential::new(
            "provider",
            "api_key",
            Secret::new("replacement-secret"),
        ))
        .unwrap();
    assert_ne!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n")
        )
        .await
        .status,
        200
    );
    no_origin(&f).await;
    let changed = request(&f, json!(["/data/chosen"])).await;
    assert_eq!(changed.status, 202);
    assert_eq!(
        decide(&f, "helper", &changed.id(), "approve", "run")
            .await
            .status,
        409
    );
    vault
        .store(Credential::new("provider", "api_key", Secret::new(SECRET)))
        .unwrap();
    let mut f = f.restart().await;
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    let definition = f.root.path().join("services/scoped.yaml");
    fs::write(
        &definition,
        fs::read_to_string(&definition)
            .unwrap()
            .replace("[GET, POST]", "[GET, POST, DELETE]"),
    )
    .unwrap();
    assert!(f.proxy.reload_services_if_changed().await.unwrap());
    let fresh = token(&f).await;
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {fresh}\r\n")
        )
        .await
        .status,
        403
    );
    no_origin(&f).await;
    let path = f.root.path().join("agents/worker/runtime.json");
    let mut run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run["state"] = json!("stopped");
    fs::write(path, run.to_string()).unwrap();
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {fresh}\r\n")
        )
        .await
        .status,
        403
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn credential_free_service_needs_no_vault_or_secret_storage() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    fs::write(f.root.path().join("services/scoped.yaml"), format!(
        "schema_version: 1\nname: scoped\ndefault_host: {}\ncapabilities:\n  reader:\n    routes:\n      - methods: [GET]\n        path: /data/*\n", f.address.ip())).unwrap();
    fs::write(
        f.root.path().join("policy.toml"),
        f.source().replace("egress='prompt'", "egress='allow'"),
    )
    .unwrap();
    let f = f.restart().await;
    let mut envelope = service_proposal(&f);
    envelope["delegation"]["scopes"][0]["credential"] = json!("");
    delegate(&f, envelope).await;
    let pending = f.agent("worker", "POST", "/gateway/request-access", Some(json!({"service":"scoped", "capability":"reader", "account":"work-account", "credential":"", "resources":["/data/chosen"]}))).await;
    assert_eq!(pending.status, 202, "{}", pending.json());
    let approved = decide(&f, "helper", &pending.id(), "approve", "run").await;
    assert_eq!(approved.status, 200, "{}", approved.json());
    assert_eq!(approved.json()["grant_active"], true);
    no_origin(&f).await;
    let selected = token(&f).await;
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n")
        )
        .await
        .status,
        200
    );
    let raw = String::from_utf8(observer.await.unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(!raw.contains("authorization:") && !raw.contains("sgw_"));
    assert!(!f.root.path().join("data/credentials.enc").exists());
    assert!(!f.root.path().join("data/credentials.key").exists());
    f.stop().await;
}

#[tokio::test]
async fn service_receipt_recovery_reports_an_expired_credential_as_inactive() {
    let (f, _backend, vault) = setup().await;
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(5);
    let mut credential = Credential::new("provider", "api_key", Secret::new(SECRET));
    credential.expires_at = Some(
        expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    );
    vault.store(credential).unwrap();
    delegate(&f, service_proposal(&f)).await;
    let id = request(&f, json!(["/data/chosen"])).await.id();
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_service_result BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
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
    let selected = token(&f).await;
    permitted(&f, &selected, "/data/chosen").await;
    let remaining = expires_at - time::OffsetDateTime::now_utc();
    if remaining.is_positive() {
        tokio::time::sleep(remaining.unsigned_abs() + Duration::from_millis(50)).await;
    }
    let expired = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(expired["status"], "approved");
    assert_eq!(expired["result"], accepted["result"]);
    assert_eq!(expired["grant_active"], false, "{expired}");
    let refused = f
        .request(
            "worker",
            f.address,
            "GET",
            "/data/chosen",
            &format!("Authorization: Bearer {selected}\r\n"),
        )
        .await;
    assert_ne!(refused.status, 200);
    no_origin(&f).await;
    f.stop().await;
}
