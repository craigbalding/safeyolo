//! Exercise the shared durable transaction with real saved/runtime state.
use super::*;
use std::os::unix::fs::PermissionsExt;

async fn fixture() -> (tempfile::TempDir, Proxy, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("policy");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("policy.toml");
    std::fs::write(&path, "budget=40\n[hosts]\n'example.invalid'={egress='deny'}\n[controls.credentials]\nenabled=false\n").unwrap();
    let config: Config = serde_json::from_value(json!({"native_product":true,
        "policy_file":path,"data_dir":root.path().join("data"),
        "listeners":[{"agent_id":"worker","socket_path":root.path().join("worker.sock")}],
        "admin_port":0,"readiness_file":root.path().join("ready"),
        "audit_log_path":root.path().join("audit.jsonl"),"flow_store_enabled":false,
        "circuit_breaker_enabled":false}))
    .unwrap();
    let proxy = Proxy::start(config).await.unwrap();
    (root, proxy, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalogue_discovery_uses_actual_bytes_and_activates_coherent_gateway_definitions() {
    use crate::host_execution::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::BTreeMap;
    let (root, mut proxy, path) = fixture().await;
    let key = Ed25519KeyPair::from_seed_unchecked(&[53; 32]).unwrap();
    let mut package: Package = serde_json::from_str(include_str!(
        "../tests/fixtures/host_execution/package.json"
    ))
    .unwrap();
    package
        .operations
        .get_mut("restart")
        .unwrap()
        .enforcement
        .unresolved
        .clear();
    let rule = UpdateRule {
        ceiling: package.operations["restart"].clone(),
        allow_narrower: true,
        allow_implementation_updates: true,
    };
    let signed = |package: &Package| {
        SignedCatalogue::sign(
            CatalogueRevision {
                publisher: "publisher".into(),
                announcement_revision: package.version * 2,
                package: package.clone(),
                observed_at: now() - 1,
                expires_at: now() + 600,
                withdrawn: false,
                previous: None,
            },
            &key,
        )
    };
    let source = root.path().join("observed.json");
    let active = signed(&package);
    std::fs::write(&source, serde_json::to_vec(&active).unwrap()).unwrap();
    let adoption = CatalogueAdoption {
        policy: CataloguePolicy {
            publisher: "publisher".into(),
            public_key: STANDARD.encode(key.public_key().as_ref()),
            package_name: package.name.clone(),
            operations: BTreeMap::from([("restart".into(), rule)]),
            families: Vec::new(),
            on_withdraw: Withdrawal::Retain,
        },
        active: active.clone(),
        observed: active,
        previous: None,
        pin: None,
        observed_file: Some(ObservedCatalogueFile {
            path: source.clone(),
            max_bytes: 131072,
        }),
    };
    let original = std::fs::read_to_string(&path).unwrap();
    let encoded = serde_json::to_string(&serde_json::to_string(&adoption).unwrap()).unwrap();
    let adopted = format!(
        "{original}\n[host_catalogues]\n'{}'={encoded}\n",
        package.name
    );
    apply_native_policy(&proxy.runtime, &adopted).unwrap();
    let registry = || {
        proxy
            .runtime
            .read()
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry()
            .unwrap()
    };
    let name = format!("{}:restart", package.name);
    assert_eq!(
        registry().services[&name].raw["host_execution_source"]["package_sha256"],
        revision(&package)
    );
    let changed = std::fs::metadata(&source).unwrap().modified().unwrap();
    let original_len = std::fs::metadata(&source).unwrap().len();
    package.version += 1;
    package
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .executable_sha256 = "b".repeat(64);
    std::fs::write(&source, serde_json::to_vec(&signed(&package)).unwrap()).unwrap();
    assert_eq!(std::fs::metadata(&source).unwrap().len(), original_len);
    std::fs::File::open(&source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(changed))
        .unwrap();
    // A saved operator edit takes precedence over a pending automatic update.
    std::fs::write(&path, format!("{adopted}\n# operator source refresh\n")).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    assert!(!proxy.reload_policy_if_changed().await.unwrap());
    let runtime = proxy.runtime.read().unwrap().clone();
    let registry = runtime
        .policy
        .as_ref()
        .unwrap()
        .gateway()
        .unwrap()
        .registry()
        .unwrap();
    assert_eq!(
        registry.services[&name].raw["host_execution_source"]["package_sha256"],
        revision(&package)
    );
    assert_eq!(
        registry.services[&name].raw["host_catalogue_status"]["state"],
        "active"
    );
    let saved = std::fs::read_to_string(&path).unwrap();
    assert_ne!(saved, adopted);
    let document = crate::policy::parse_toml_document(&saved).unwrap();
    let retained: CatalogueAdoption =
        serde_json::from_str(document["host_catalogues"][&package.name].as_str().unwrap()).unwrap();
    assert_eq!(
        revision(&retained.active.catalogue.package),
        revision(&package)
    );
    let mut broadened = package.clone();
    broadened.version += 1;
    broadened
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .identity
        .principal = "root".into();
    std::fs::write(&source, serde_json::to_vec(&signed(&broadened)).unwrap()).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    let runtime = proxy.runtime.read().unwrap().clone();
    let registry = runtime
        .policy
        .as_ref()
        .unwrap()
        .gateway()
        .unwrap()
        .registry()
        .unwrap();
    // Coherent retained input, with the exact unresolved update visible. The
    // target's invocation check refuses a mismatched package operation.
    assert_eq!(
        registry.services[&name].raw["host_catalogue_status"]["state"],
        "awaiting_review"
    );
    assert_eq!(
        registry.services[&name].raw["host_execution_source"]["package_sha256"],
        revision(&package)
    );
    let saved = std::fs::read_to_string(&path).unwrap();
    let state = proxy.runtime.clone();
    let target = path.clone();
    let result = tokio::task::spawn_blocking(move || {
        adopt_native_policy(
            &state,
            |source, runtime, _| {
                let (mut document, context) = policy::parse_toml_for_edit(source)
                    .map_err(|e| approvals::invalid(e.to_string()))?;
                document.as_table_mut().remove("host_catalogues");
                let source = policy::restore_large_toml_integers(&document.to_string(), &context);
                let candidate = runtime
                    .policy
                    .as_ref()
                    .unwrap()
                    .reload_native_source(&source, &target)
                    .map_err(|e| approvals::invalid(e.to_string()))?;
                Ok((source, candidate))
            },
            || {
                Err(approvals::invalid(
                    "controlled receipt failure after catalogue activation",
                ))
            },
        )
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);
    assert_eq!(
        proxy
            .runtime
            .read()
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry()
            .unwrap()
            .services[&name]
            .raw["host_execution_source"]["package_sha256"],
        revision(&package)
    );
    proxy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_save_failure_preserves_saved_and_active_policy() {
    let (_root, proxy, path) = fixture().await;
    let saved = std::fs::read_to_string(&path).unwrap();
    let before = proxy.runtime.read().unwrap().clone();
    let state = proxy.runtime.clone();
    let target = path.clone();
    let result = tokio::task::spawn_blocking(move || {
        adopt_native_policy(
            &state,
            |source, runtime, _| {
                let source = source.replace("budget=40", "budget=58");
                let candidate = runtime
                    .policy
                    .as_ref()
                    .unwrap()
                    .reload_native_source(&source, &target)
                    .unwrap();
                // The canonical journal lives outside this directory. Fail the actual
                // policy save after admission has acquired its lock.
                std::fs::set_permissions(
                    target.parent().unwrap(),
                    std::fs::Permissions::from_mode(0o500),
                )
                .unwrap();
                Ok((source, candidate))
            },
            || panic!("a failed save must not retain an applied receipt"),
        )
    })
    .await
    .unwrap();
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(result.unwrap_err().kind, approvals::ErrorKind::Io);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);
    let after = proxy.runtime.read().unwrap().clone();
    assert!(Arc::ptr_eq(&before, &after));
    assert_eq!(
        after.policy.as_ref().unwrap().native_source_text(),
        Some(saved.as_str())
    );
    proxy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_receipt_failure_rolls_back_actual_saved_and_active_policy() {
    let (_root, proxy, path) = fixture().await;
    let saved = std::fs::read_to_string(&path).unwrap();
    let active = saved.clone();
    let saved = active.replace("budget=40", "budget=41");
    std::fs::write(&path, &saved).unwrap();
    let state = proxy.runtime.clone();
    let target = path.clone();
    let original = saved.clone();
    let result = tokio::task::spawn_blocking(move || {
        adopt_native_policy(
            &state,
            |source, runtime, _| {
                let source = source.replace("budget=41", "budget=58");
                let candidate = runtime
                    .policy
                    .as_ref()
                    .unwrap()
                    .reload_native_source(&source, &target)
                    .unwrap();
                Ok((source, candidate))
            },
            || {
                assert_ne!(
                    std::fs::read_to_string(&target).unwrap(),
                    original,
                    "callback must follow the real save"
                );
                Err(approvals::invalid(
                    "controlled receipt failure after activation",
                ))
            },
        )
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind, approvals::ErrorKind::Activation);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);
    assert_eq!(
        proxy
            .runtime
            .read()
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .native_source_text(),
        Some(active.as_str())
    );
    proxy.shutdown().await;
}
