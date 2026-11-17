//! Supervisor fixtures exercise the real job entry point. These are not VM proof.
use super::*;
use base64::Engine;

fn fixture(script: &str) -> (tempfile::TempDir, JobSpec, std::path::PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("hyperlight-test-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let helper = root.path().join("helper-source");
    let marker = root.path().join("helper.pid");
    let quoted = format!("'{}'", marker.display().to_string().replace('\'', "'\\''"));
    fs::write(
        &helper,
        format!("#!/bin/sh\nprintf '%s' \"$$\" > {quoted}\n{script}\n"),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("python.cpio"), b"fixture, no VM").unwrap();
    fs::write(
        root.path().join("checker.py"),
        b"fixture, no Python execution",
    )
    .unwrap();
    let manifest = root.path().join("runtime.json");
    let value = json!({"protocol":4,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "hyperlight":"0.19.0","unikraft":"0.21.0","kernel_contract":"fixture",
        "helper":{"file":"helper-source","sha256":digest(&fs::read(&helper).unwrap())},
        "rootfs":{"file":"python.cpio","sha256":digest(b"fixture, no VM")},"rootfs_source":"fixture"});
    fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut spec = super::super::tests::spec();
    spec.engine = JobEngine::HyperlightUnikraft {
        reuse_initialization: true,
        runtime: PinnedArtifact {
            path: manifest.clone(),
            sha256: digest(&fs::read(&manifest).unwrap()),
        },
        checker: PinnedArtifact {
            path: root.path().join("checker.py"),
            sha256: digest(b"fixture, no Python execution"),
        },
    };
    let config = root.path().join("config.toml");
    fs::write(&config, "").unwrap();
    (root, spec, config)
}

fn assert_reaped(root: &Path) {
    let pid: i32 = fs::read_to_string(root.join("helper.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    if alive {
        // A regression must not leave its spinning fixture behind.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    assert!(
        !alive,
        "job returned while its helper PID {pid} still existed"
    );
}

#[tokio::test]
async fn pinned_helper_captures_complete_streams_and_removes_runtime() {
    let (root, spec, config) = fixture(
        "printf 'abcdefghijklmnopqrstuv'\nprintf 'error text' >&2\nprintf '%s' '{\"completion\":{\"kind\":\"guest_call_completed\",\"reported_status\":0},\"error\":null}' > \"$2\"",
    );
    let result = run(&config, &spec, None, None, &[]).await.unwrap();
    assert_eq!(result.engine, "hyperlight-unikraft");
    assert_eq!(result.outcome_source, "host_helper");
    assert_eq!(result.outcome, Some(Outcome::Exit { code: 0 }));
    assert!(result.observation_error.is_none());
    assert_eq!(result.stdout.bytes, 22);
    assert_eq!(result.stdout.sha256, digest(b"abcdefghijklmnopqrstuv"));
    assert_eq!(
        super::super::STANDARD
            .decode(result.stdout.retained_base64)
            .unwrap(),
        b"abcdefghijklmnop"
    );
    assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
}

#[tokio::test]
async fn operator_selected_artifact_links_still_verify_the_copied_bytes() {
    let (root, spec, config) = fixture(
        "printf '%s' '{\"completion\":{\"kind\":\"guest_call_completed\",\"reported_status\":0},\"error\":null}' > \"$2\"",
    );
    let source = root.path().join("helper-source");
    let target = root.path().join("versioned-helper");
    fs::rename(&source, &target).unwrap();
    std::os::unix::fs::symlink(&target, &source).unwrap();
    let result = run(&config, &spec, None, None, &[]).await.unwrap();
    assert_eq!(result.outcome, Some(Outcome::Exit { code: 0 }));
    fs::write(&target, "changed after adoption").unwrap();
    assert!(
        run(&config, &spec, None, None, &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("digest mismatch")
    );
}

#[tokio::test]
async fn substituted_artifacts_and_manifest_architecture_fail_before_spawn() {
    let (root, mut spec, config) = fixture("exit 0");
    fs::write(root.path().join("helper-source"), "substituted").unwrap();
    assert!(
        run(&config, &spec, None, None, &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("digest mismatch")
    );
    let JobEngine::HyperlightUnikraft { runtime, .. } = &mut spec.engine else {
        unreachable!()
    };
    let mut manifest: Value = serde_json::from_slice(&fs::read(&runtime.path).unwrap()).unwrap();
    manifest["architecture"] = "incompatible-architecture".into();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    fs::write(&runtime.path, &bytes).unwrap();
    runtime.sha256 = digest(&bytes);
    assert!(
        run(&config, &spec, None, None, &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("host is")
    );
    assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
}

#[tokio::test]
async fn missing_artifacts_identify_role_path_and_os_error_before_discovery() {
    for (missing, role) in [
        ("runtime.json", "runtime manifest"),
        ("helper-source", "helper"),
        ("core.elf", "core guest"),
        ("checker.py", "Python checker"),
        ("python.cpio", "Unikraft runtime"),
    ] {
        let (root, mut spec, config) = fixture("exit 99");
        let JobEngine::HyperlightUnikraft { runtime, checker } = &mut spec.engine else {
            unreachable!()
        };
        runtime.path = "runtime.json".into();
        checker.path = "checker.py".into();
        if missing == "core.elf" {
            fs::copy(root.path().join("checker.py"), root.path().join(missing)).unwrap();
            spec.engine = JobEngine::Hyperlight {
                runtime: runtime.clone(),
                guest: PinnedArtifact {
                    path: missing.into(),
                    sha256: checker.sha256.clone(),
                },
                function: "Check".into(),
            };
        }
        let path = root.path().join(missing);
        fs::remove_file(&path).unwrap();
        let os_error = fs::File::open(&path).unwrap_err().to_string();
        let retained: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        let spec_path = root.path().join("job.json");
        fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        let error = super::super::command(
            &config,
            &["validate".into(), spec_path.display().to_string()],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains(&format!("Hyperlight {role}")), "{error}");
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains(&os_error), "{error}");
        assert!(!path.exists());
        assert!(!root.path().join("helper.pid").exists());
        assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
        for (path, bytes) in retained {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

#[tokio::test]
async fn missing_or_failed_vm_report_cannot_make_a_successful_helper_exit_pass() {
    for script in [
        "exit 0",
        "printf '%s' '{\"completion\":null,\"error\":\"startup failed\"}' > \"$2\"",
    ] {
        let (_root, spec, config) = fixture(script);
        let result = run(&config, &spec, None, None, &[]).await.unwrap();
        assert_eq!(result.outcome, Some(Outcome::Exit { code: 0 }));
        assert!(result.observation_error.is_some());
    }
}

#[tokio::test]
async fn deadline_kills_and_reaps_a_spinning_helper_before_returning() {
    let (root, mut spec, config) = fixture("while :; do :; done");
    spec.timeout_seconds = 1;
    let started = std::time::Instant::now();
    let result = run(&config, &spec, None, None, &[]).await.unwrap();
    assert_eq!(result.outcome, Some(Outcome::Timeout));
    assert_eq!(
        result.helper_process_status,
        Some(HelperProcessStatus::Signal {
            number: libc::SIGKILL
        })
    );
    assert_eq!(result.outcome_source, "host_watchdog");
    assert_reaped(root.path());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
    // A new invocation still starts, and does not inherit the expired runtime.
    let (_next, next_spec, next_config) = fixture(
        "printf '%s' '{\"completion\":{\"kind\":\"guest_call_completed\",\"reported_status\":0},\"error\":null}' > \"$2\"",
    );
    assert_eq!(
        run(&next_config, &next_spec, None, None, &[])
            .await
            .unwrap()
            .outcome,
        Some(Outcome::Exit { code: 0 })
    );
}

#[tokio::test]
async fn cancellation_stops_a_blocked_helper_and_preserves_no_runtime() {
    let (root, spec, config) = fixture("exec /bin/sleep 999");
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let cancel = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        sender.send(true).unwrap();
    };
    let (result, ()) = tokio::join!(run(&config, &spec, None, Some(receiver), &[]), cancel);
    let result = result.unwrap();
    assert_eq!(
        result.helper_process_status,
        Some(HelperProcessStatus::Signal {
            number: libc::SIGKILL
        })
    );
    assert_eq!(
        result.outcome,
        Some(Outcome::Interrupted {
            signal: libc::SIGTERM
        })
    );
    assert_reaped(root.path());
    assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
}

#[test]
fn unsupported_authority_is_refused_and_relative_artifacts_follow_adopted_spec() {
    let (root, mut spec, _) = fixture("exit 0");
    spec.network = true;
    assert!(spec.validate().unwrap_err().to_string().contains("network"));
    spec.network = false;
    spec.privilege = Privilege::GuestRoot;
    assert!(
        spec.validate()
            .unwrap_err()
            .to_string()
            .contains("guest-root")
    );
    spec.privilege = Privilege::Unprivileged;
    let JobEngine::HyperlightUnikraft { runtime, .. } = &mut spec.engine else {
        unreachable!()
    };
    runtime.path = "runtime.json".into();
    spec.resolve_artifacts(root.path());
    let JobEngine::HyperlightUnikraft { runtime, .. } = &spec.engine else {
        unreachable!()
    };
    assert_eq!(runtime.path, root.path().join("runtime.json"));
}

#[test]
fn template_identity_tracks_frozen_inputs_and_keeps_invocation_authority_separate() {
    let (_root, mut spec, _) = fixture("exit 0");
    let original = template_key(&spec).unwrap();
    spec.gate_id = "another-principal".into();
    spec.argv = vec!["different invocation input".into()];
    spec.timeout_seconds += 1;
    assert_eq!(template_key(&spec).unwrap(), original);
    spec.memory_mb += 1;
    assert_ne!(template_key(&spec).unwrap(), original);
    spec.memory_mb -= 1;
    let JobEngine::HyperlightUnikraft { checker, .. } = &mut spec.engine else {
        unreachable!()
    };
    checker.sha256 = "a".repeat(64);
    assert_ne!(template_key(&spec).unwrap(), original);
    let JobEngine::HyperlightUnikraft { runtime, .. } = &mut spec.engine else {
        unreachable!()
    };
    runtime.sha256 = "b".repeat(64);
    assert_ne!(template_key(&spec).unwrap(), original);
    let mut value = serde_json::to_value(&spec).unwrap();
    value["engine"]
        .as_object_mut()
        .unwrap()
        .remove("reuse_initialization");
    let default: JobSpec = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(
        default.engine,
        JobEngine::HyperlightUnikraft {
            reuse_initialization: true,
            ..
        }
    ));
    value["engine"]["reuse_initialization"] = false.into();
    let cold: JobSpec = serde_json::from_value(value).unwrap();
    assert!(matches!(
        cold.engine,
        JobEngine::HyperlightUnikraft {
            reuse_initialization: false,
            ..
        }
    ));
}

#[test]
fn shutdown_removes_idle_templates_and_preserves_a_live_mapping_lease() {
    let (root, _spec, config) = fixture("exit 0");
    let directory = root.path().join("data/hyperlight-templates");
    let idle = directory.join("template-idle");
    let active = directory.join("template-active");
    fs::create_dir_all(&idle).unwrap();
    fs::create_dir(&active).unwrap();
    let lease = fs::File::create(active.join("lease")).unwrap();
    lease.try_lock_shared().unwrap();
    clear_templates(&config).unwrap();
    assert!(!idle.exists());
    assert!(active.exists());
    drop(lease);
    clear_templates(&config).unwrap();
    assert!(!active.exists());
}
