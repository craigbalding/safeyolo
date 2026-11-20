use super::*;
use ring::signature::KeyPair;

fn key() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[41; 32]).unwrap()
}

fn resign(candidate: &mut SignedBundle) {
    candidate.sha256 = digest(&candidate.bundle);
    candidate.signature = STANDARD.encode(
        key()
            .sign(&SignedBundle::signing_message(&candidate.bundle))
            .as_ref(),
    );
}

fn with_check(mut candidate: SignedBundle) -> SignedBundle {
    let check:checks::Check=serde_json::from_value(json!({"source_id":"destination-policy","meaning":"conflict with the adopted destination/task constraint","subject":"value","result_type":"finding",
        "influences":["hard_exclusion"],"implementation_version":"1","configuration_version":"1","max_age_seconds":60,
        "inputs":{"allowed_path":"/export"},"source":{"kind":"job","spec":"destination.json","effects":"passive","limits":{
            "timeout_ms":1000,"max_input_bytes":8192,"max_output_bytes":8192,"max_concurrent":1,"max_pending":0,"max_cached":1}}})).unwrap();
    let job:crate::jobs::JobSpec=serde_json::from_value(json!({"gate_id":"export-destination","argv":["/usr/bin/python3","-c",
        "import json; r=json.load(open('/input/request.json')); s=json.loads(r['subject']['value']); print(json.dumps({'finding':{'kind':'finding','positive':s['action']['path'] != r['inputs']['allowed_path']},'source_revision':'fixture-1'}))"],
        "timeout_seconds":1,"max_input_bytes":8192,"max_input_entries":1,"retain_bytes":8192,"memory_mb":128,"network":false})).unwrap();
    candidate.bundle.requires.push("platform-job-v1".into());
    candidate
        .bundle
        .checks
        .insert("exports.destination".into(), check);
    candidate.bundle.jobs.insert("destination.json".into(), job);
    candidate
        .bundle
        .challenge
        .steps
        .push(checks::challenges::Step::Check {
            check: "exports.destination".into(),
            on_positive: checks::challenges::Positive::Question(checks::challenges::Question {
                field: "conflict".into(),
                question: "Explain the conflicting destination/task evidence".into(),
            }),
        });
    for (path, positive) in [("/export", false), ("/untrusted-export", true)] {
        candidate.bundle.fixtures.push(Fixture {
            check: "exports.destination".into(),
            subject: checks::Subject::Value {
                value: json!({"action":{"path":path}}).to_string(),
            },
            positive,
        });
    }
    resign(&mut candidate);
    candidate
}
fn signed(revision: u64, previous: Option<String>) -> SignedBundle {
    let bundle:Bundle=serde_json::from_value(json!({"format":"safeyolo.control-update/v1","name":"exports","publisher":"defender","revision":revision,"previous":previous,
        "observed_at":now()-1,"expires_at":now()+50,"withdrawn":false,
        "requires":["gateway-route-v1"],"changes":format!("require origin revision {revision}"),"checks":{},"jobs":{},"fixtures":[],
        "challenge":{"agents":["alice"],"service":"demo","capability":"writer","methods":["POST"],"path":"/export","revision":revision.to_string(),
            "steps":[{"kind":"question","field":format!("origin_{revision}"),"question":"Identify the instruction origin"}]}})).unwrap();
    SignedBundle {
        sha256: digest(&bundle),
        signature: STANDARD.encode(key().sign(&SignedBundle::signing_message(&bundle)).as_ref()),
        bundle,
    }
}
fn bounds() -> Value {
    json!({"agents":["alice"],"services":["demo"],"capabilities":["writer"],"methods":["POST"],"paths":["/export"],"effects":["passive"],
    "max_timeout_ms":1000,"max_memory_mb":128,"max_input_bytes":8192,"max_output_bytes":8192,"max_concurrent":1,"max_pending":0,"max_cached":1,
    "allow_network":false,"allow_guest_root":false})
}
fn config(root: &Path, automatic: bool) -> Configuration {
    serde_json::from_value(json!({"sources":{"updates":{"endpoint":{"mode":"loopback","url":"nats://127.0.0.1:4222"},"username":"fixture",
        "credential_file":root.join("unused"),"bucket":"updates","keys":"controls.exports","source_id":"observations","max_bytes":100000,"max_signals":10,"max_age_seconds":60,"retry_seconds":1}},
        "control_updates":{"exports":{"source":"updates","key":"controls.exports","publisher":"defender","public_key":STANDARD.encode(key().public_key().as_ref()),
            "automatic":if automatic{bounds()}else{Value::Null},"qualification":bounds(),"fixtures":[],"on_withdraw":"previous"}}})).unwrap()
}
fn announce(
    root: &Path,
    config: &Configuration,
    signed: &SignedBundle,
    revision: u64,
    withdrawn: bool,
) {
    let update = Update {
        source_id: "observations".into(),
        id: "controls.exports".into(),
        revision,
        observed_at: signed.bundle.observed_at,
        expires_at: signed.bundle.expires_at,
        withdrawn,
        evidence_refs: vec![],
        evidence: Evidence::ControlUpdate {
            candidate: json!(signed),
        },
    };
    save(
        &accepted_path(root, "updates", "controls.exports"),
        &Accepted {
            source_digest: digest(&config.sources["updates"]),
            update,
        },
    )
    .unwrap();
}
async fn fixture(root: &Path) -> crate::Proxy {
    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("policy.toml"),"[agents.alice]\nagent_id='ag-11111111111111111111111111111111'\n[hosts.'*']\negress='deny'\n[controls.credentials]\nenabled=false\n").unwrap();
    let config:crate::Config=serde_json::from_value(json!({"native_product":true,"policy_file":root.join("policy.toml"),"data_dir":root.join("data"),
        "listeners":[],
        "admin_port":0,"readiness_file":root.join("ready"),"audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"circuit_breaker_enabled":false})).unwrap();
    crate::Proxy::start(config).await.unwrap()
}
fn save_config(root: &Path, config: &Configuration) {
    fs::write(root.join("signals.toml"), toml::to_string(config).unwrap()).unwrap();
}

#[test]
fn signed_native_update_rejects_tamper_wrong_publisher_and_unknown_primitive() {
    let candidate = signed(1, None);
    let public = STANDARD.encode(key().public_key().as_ref());
    candidate.verify("exports", "defender", &public).unwrap();
    let mut changed = candidate.clone();
    changed.bundle.changes.push('x');
    assert!(changed.verify("exports", "defender", &public).is_err());
    assert!(
        candidate
            .verify("exports", "other-publisher", &public)
            .is_err()
    );
    let mut changed = candidate.clone();
    changed.bundle.requires.push("arbitrary-host-script".into());
    changed.sha256 = digest(&changed.bundle);
    changed.signature = STANDARD.encode(
        key()
            .sign(&SignedBundle::signing_message(&changed.bundle))
            .as_ref(),
    );
    assert!(
        changed
            .verify("exports", "defender", &public)
            .unwrap_err()
            .to_string()
            .contains("incompatible")
    );
}

#[tokio::test]
async fn receipt_does_not_adopt_automatic_revisions_are_coherent_and_withdrawal_does_not_oscillate()
{
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let proxy = fixture(root).await;
    let mut config = config(root, true);
    let v1 = signed(1, None);
    let v2 = signed(2, Some(v1.sha256.clone()));
    let base = fs::read_to_string(root.join("policy.toml")).unwrap();
    // A source is permission to receive observations, independently of signing
    // or control-adoption authority. Retained content alone changes no policy.
    let authorizer = config.control_updates.remove("exports").unwrap();
    save_config(root, &config);
    announce(root, &config, &v1, 1, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(fs::read_to_string(root.join("policy.toml")).unwrap(), base);
    config.control_updates.insert("exports".into(), authorizer);
    save_config(root, &config);
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(
        status(root).unwrap()["exports"]["active"]["sha256"],
        v1.sha256
    );
    announce(root, &config, &v2, 2, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    let policy = proxy.runtime.read().unwrap().policy.clone().unwrap();
    let challenge = &policy.named_checks().route_challenges["exports"];
    assert_eq!(challenge.revision, v2.sha256);
    assert_eq!(
        status(root).unwrap()["exports"]["active"]["sha256"],
        v2.sha256
    );
    // Repeated delivery and withdrawal preserve one coherent result and never
    // toggle between the replacement and the withdrawn revision.
    let saved = fs::read_to_string(root.join("policy.toml")).unwrap();
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(fs::read_to_string(root.join("policy.toml")).unwrap(), saved);
    let mut withdrawal = signed(3, Some(v1.sha256.clone()));
    withdrawal.bundle.withdrawn = true;
    withdrawal.sha256 = digest(&withdrawal.bundle);
    withdrawal.signature = STANDARD.encode(
        key()
            .sign(&SignedBundle::signing_message(&withdrawal.bundle))
            .as_ref(),
    );
    announce(root, &config, &withdrawal, 3, true);
    for _ in 0..3 {
        reconcile(root, &proxy.runtime).await.unwrap();
        assert_eq!(
            status(root).unwrap()["exports"]["active"]["sha256"],
            v1.sha256
        );
    }
    assert_eq!(
        crate::policy::parse_toml_document(&fs::read_to_string(root.join("policy.toml")).unwrap())
            .unwrap()["hosts"]["*"]["egress"],
        "deny"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn changed_scope_uses_one_existing_approval_and_rejected_content_retains_active() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let proxy = fixture(root).await;
    let mut config = config(root, true);
    save_config(root, &config);
    let v1 = signed(1, None);
    announce(root, &config, &v1, 1, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    let mut v2 = signed(2, Some(v1.sha256.clone()));
    v2.bundle.challenge.path = "/other".into();
    v2.sha256 = digest(&v2.bundle);
    v2.signature = STANDARD.encode(
        key()
            .sign(&SignedBundle::signing_message(&v2.bundle))
            .as_ref(),
    );
    announce(root, &config, &v2, 2, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    let pending = status(root).unwrap()["exports"].clone();
    assert_eq!(pending["state"], "pending_approval");
    let id = pending["approval_id"].as_str().unwrap();
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(status(root).unwrap()["exports"]["approval_id"], id);
    let writer = proxy.runtime.read().unwrap().audit.clone();
    assert!(
        resolve(
            &proxy.runtime,
            &writer,
            id,
            approvals::network_action::Decision::Approve,
            true
        )
        .is_err()
    );
    resolve(
        &proxy.runtime,
        &writer,
        id,
        approvals::network_action::Decision::Approve,
        false,
    )
    .unwrap();
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(
        status(root).unwrap()["exports"]["active"]["sha256"],
        v2.sha256
    );
    let mut changed = v2.clone();
    changed.bundle.revision = 3; // invalid signature
    announce(root, &config, &changed, 3, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(status(root).unwrap()["exports"]["state"], "rejected");
    assert_eq!(
        status(root).unwrap()["exports"]["active"]["sha256"],
        v2.sha256
    );
    config.control_updates.get_mut("exports").unwrap().pin = Some(v1.sha256.clone());
    save_config(root, &config);
    reconcile(root, &proxy.runtime).await.unwrap();
    let recovered = status(root).unwrap()["exports"].clone();
    assert_eq!(recovered["state"], "rolled_back");
    assert_eq!(recovered["active"]["sha256"], v1.sha256);
    assert_eq!(recovered["active"]["generation"], 3);
    proxy.shutdown().await;
}

#[tokio::test]
async fn unavailable_isolated_qualification_and_failed_save_preserve_previous_revision() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let proxy = fixture(root).await;
    let mut config = config(root, true);
    save_config(root, &config);
    let v1 = signed(1, None);
    announce(root, &config, &v1, 1, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    let base = fs::read(root.join("policy.toml")).unwrap();
    let before = proxy.runtime.read().unwrap().clone();
    let v2 = with_check(signed(2, Some(v1.sha256.clone())));
    config.control_updates.get_mut("exports").unwrap().fixtures = vec![Fixture {
        check: "exports.destination".into(),
        subject: checks::Subject::Value {
            value: json!({"action":{"path":"/export"}}).to_string(),
        },
        positive: false,
    }];
    save_config(root, &config);
    announce(root, &config, &v2, 2, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    let unavailable = status(root).unwrap()["exports"].clone();
    assert_eq!(unavailable["state"], "unavailable");
    assert_eq!(unavailable["active"]["sha256"], v1.sha256);
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), base);
    assert!(std::sync::Arc::ptr_eq(
        &before,
        &proxy.runtime.read().unwrap()
    ));
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(status(root).unwrap()["exports"], unavailable);
    // The same native transaction must preserve its complete saved/live pair
    // when a later valid (question-only) candidate cannot be saved.
    let v3 = signed(3, Some(v1.sha256.clone()));
    announce(root, &config, &v3, 3, false);
    if unsafe { libc::geteuid() } != 0 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o500)).unwrap();
        reconcile(root, &proxy.runtime).await.unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(status(root).unwrap()["exports"]["state"], "failed");
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), base);
        assert!(std::sync::Arc::ptr_eq(
            &before,
            &proxy.runtime.read().unwrap()
        ));
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn transport_cannot_forge_signed_withdrawal_or_renew_evidence_times() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let proxy = fixture(root).await;
    let config = config(root, true);
    save_config(root, &config);
    let v1 = signed(1, None);
    announce(root, &config, &v1, 1, false);
    reconcile(root, &proxy.runtime).await.unwrap();
    announce(root, &config, &v1, 2, true);
    reconcile(root, &proxy.runtime).await.unwrap();
    assert_eq!(status(root).unwrap()["exports"]["state"], "rejected");
    assert_eq!(
        status(root).unwrap()["exports"]["active"]["sha256"],
        v1.sha256
    );
    proxy.shutdown().await;
}
