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
