//! Supervisor fixtures exercise the real job entry point. These are not VM proof.
use super::*;
use base64::Engine;

// One-shot faults are local to each current-thread Tokio test. The real stop
// and caller paths still own, wait for and dispose of real child processes.
thread_local! {
    pub(super) static GROUP_KILL_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    pub(super) static CHILD_KILL_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

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
async fn live_console_precedes_completion_and_survives_cancellation() {
    let marker = b"template-spin-entered\n";
    let (root, mut spec, config) =
        fixture("printf 'template-spin-entered\\n'; exec /bin/sleep 999");
    spec.retain_bytes = marker.len();
    let path = root.path().join("current.console");
    let console = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .await
        .unwrap();
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let observe = async {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if tokio::fs::read(&path).await.unwrap() == marker {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        sender.send(true).unwrap();
    };
    let (result, ()) = tokio::join!(
        run(&config, &spec, None, Some(receiver), &[], Some(console)),
        observe
    );
    let result = result.unwrap();
    assert_eq!(
        result.outcome,
        Some(Outcome::Interrupted {
            signal: libc::SIGTERM
        })
    );
    assert_eq!(
        result.helper_process_status,
        Some(HelperProcessStatus::Signal {
            number: libc::SIGKILL
        })
    );
    assert_eq!(result.stdout.bytes, marker.len() as u64);
    assert_eq!(
        super::super::STANDARD
            .decode(result.stdout.retained_base64)
            .unwrap(),
        marker
    );
    assert_eq!(fs::read(&path).unwrap(), marker);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_reaped(root.path());
    assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
}

#[tokio::test]
async fn console_command_refuses_a_previous_invocations_file_before_spawn() {
    let (root, spec, config) = fixture("exec /bin/sleep 999");
    let path = root.path().join("job.json");
    fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
    let console = root.path().join("previous.console");
    fs::write(&console, b"template-spin-entered\n").unwrap();
    let args = vec![
        "run".into(),
        path.display().to_string(),
        "--console-file".into(),
        console.display().to_string(),
    ];
    let error = super::super::command(&config, &args).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(!root.path().join("helper.pid").exists());
    assert_eq!(fs::read(console).unwrap(), b"template-spin-entered\n");
}

#[tokio::test]
async fn pinned_helper_captures_complete_streams_and_removes_runtime() {
    let (root, spec, config) = fixture(
        "printf 'abcdefghijklmnopqrstuv'\nprintf 'error text' >&2\nprintf '%s' '{\"completion\":{\"kind\":\"guest_call_completed\",\"reported_status\":0},\"error\":null}' > \"$2\"",
    );
    let result = run(&config, &spec, None, None, &[], None).await.unwrap();
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
    let result = run(&config, &spec, None, None, &[], None).await.unwrap();
    assert_eq!(result.outcome, Some(Outcome::Exit { code: 0 }));
    fs::write(&target, "changed after adoption").unwrap();
    assert!(
        run(&config, &spec, None, None, &[], None)
            .await
            .unwrap_err()
            .to_string()
            .contains("digest mismatch")
    );
}

#[tokio::test]
async fn substituted_artifacts_and_manifest_architecture_fail_before_spawn() {
    for file in ["runtime.json", "helper-source", "checker.py", "python.cpio"] {
        let (root, spec, config) = fixture("exit 99");
        // A retained cache must not bypass verification of any current input.
        fs::create_dir_all(root.path().join("data/hyperlight-templates/template-old")).unwrap();
        fs::write(root.path().join(file), "substituted").unwrap();
        let error = run(&config, &spec, None, None, &[], None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("digest mismatch"), "{file}: {error}");
        assert!(!root.path().join("helper.pid").exists());
        assert!(
            root.path()
                .join("data/hyperlight-templates/template-old")
                .exists()
        );
        assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 1);
    }
    for (field, value, diagnostic) in [
        ("protocol", json!(3), "ABI version"),
        ("hyperlight", json!("incompatible"), "ABI version"),
        ("unikraft", json!("incompatible"), "ABI version"),
        ("os", json!("incompatible-os"), "host is"),
        (
            "architecture",
            json!("incompatible-architecture"),
            "host is",
        ),
    ] {
        let (root, mut spec, config) = fixture("exit 99");
        let JobEngine::HyperlightUnikraft { runtime, .. } = &mut spec.engine else {
            unreachable!()
        };
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&runtime.path).unwrap()).unwrap();
        manifest[field] = value;
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&runtime.path, &bytes).unwrap();
        // Even a newly adopted digest cannot authorize an incompatible ABI.
        runtime.sha256 = digest(&bytes);
        let error = run(&config, &spec, None, None, &[], None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(diagnostic), "{field}: {error}");
        assert!(!root.path().join("helper.pid").exists());
        assert_eq!(fs::read_dir(root.path().join("data")).unwrap().count(), 0);
    }
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
        let JobEngine::HyperlightUnikraft {
            runtime,
            checker,
            reuse_initialization,
        } = &mut spec.engine
        else {
            unreachable!()
        };
        runtime.path = "runtime.json".into();
        checker.path = "checker.py".into();
        if missing == "core.elf" {
            fs::copy(root.path().join("checker.py"), root.path().join(missing)).unwrap();
            spec.engine = JobEngine::Hyperlight {
                reuse_initialization: *reuse_initialization,
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
        let result = run(&config, &spec, None, None, &[], None).await.unwrap();
        assert_eq!(result.outcome, Some(Outcome::Exit { code: 0 }));
        assert!(result.observation_error.is_some());
    }
}

#[tokio::test]
async fn reaped_helpers_never_signal_a_stale_process_group() {
    for dropping in [false, true] {
        // A completed wait releases the old group ID. Model its reuse with
        // another owned process, so a stale signal is observable and contained.
        let mut survivor = command(Path::new("/bin/sleep")).arg("999").spawn().unwrap();
        let mut child = command(Path::new("/bin/sh"))
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        child.wait().await.unwrap();
        let mut helper = Helper {
            child,
            group: survivor.id(),
        };
        if !dropping {
            assert_eq!(
                stop(&mut helper).await.unwrap(),
                HelperProcessStatus::Exit { code: 0 }
            );
            assert!(helper.group.is_none());
        }
        drop(helper);
        let survived = survivor.try_wait().unwrap().is_none();
        survivor.kill().await.unwrap();
        survivor.wait().await.unwrap();
        assert!(
            survived,
            "reaped helper signalled the replacement group; drop={dropping}"
        );
    }
}

#[tokio::test]
async fn refused_group_signal_uses_owned_child_termination_and_reaps() {
    let child = command(Path::new("/bin/sleep")).arg("999").spawn().unwrap();
    let mut helper = Helper {
        group: child.id(),
        child,
    };
    GROUP_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
    assert_eq!(
        stop(&mut helper).await.unwrap(),
        HelperProcessStatus::Signal {
            number: libc::SIGKILL
        }
    );
    assert!(helper.group.is_none());
    assert!(helper.child.try_wait().unwrap().is_some());
    assert!(GROUP_KILL_ERROR.with(|error| error.get()).is_none());
}

#[tokio::test]
async fn refused_signals_wait_for_a_delayed_owned_child_exit() {
    let mut child = command(Path::new("/bin/sh"))
        .args(["-c", "printf ready; read release; exit 124"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0; 5];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .await
        .unwrap();
    assert_eq!(&ready, b"ready");
    let mut release = child.stdin.take().unwrap();
    let mut helper = Helper {
        group: child.id(),
        child,
    };
    GROUP_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
    CHILD_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
    let mut stopping = Box::pin(stop(&mut helper));
    tokio::select! {
        biased;
        result = &mut stopping => panic!("stop returned before the owned child was released: {result:?}"),
        _ = tokio::task::yield_now() => {}
    }
    assert!(GROUP_KILL_ERROR.with(|error| error.get()).is_none());
    assert!(CHILD_KILL_ERROR.with(|error| error.get()).is_none());
    release.write_all(b"exit now\n").await.unwrap();
    assert_eq!(
        stopping.await.unwrap(),
        HelperProcessStatus::Exit { code: 124 }
    );
    assert!(helper.group.is_none());
    assert_eq!(helper.child.try_wait().unwrap().unwrap().code(), Some(124));
}

#[tokio::test]
async fn refused_termination_of_a_live_child_remains_a_cleanup_error() {
    let child = command(Path::new("/bin/sleep")).arg("999").spawn().unwrap();
    let mut helper = Helper {
        group: child.id(),
        child,
    };
    GROUP_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
    CHILD_KILL_ERROR.with(|error| error.set(Some(libc::EACCES)));
    let error = stop(&mut helper).await.unwrap_err().to_string();
    let still_live = helper.child.try_wait().unwrap().is_none();
    let group_retained = helper.group.is_some();
    // Remove only the faults; the ordinary stop path must clean up this child.
    stop(&mut helper).await.unwrap();
    assert!(still_live);
    assert!(group_retained);
    assert!(error.contains("process group"));
    assert!(error.contains("direct-child SIGKILL failed"));
    assert!(error.contains("os error 1"));
    assert!(error.contains(&format!("os error {}", libc::EACCES)));
    assert!(error.contains("VM cleanup is unproved"));
}

#[tokio::test]
async fn unproved_child_disposal_preserves_the_callers_runtime() {
    let (root, spec, config) = fixture("exec /bin/sleep 999");
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let cancel = async {
        // The helper's marker synchronizes cancellation with its actual launch.
        tokio::time::timeout(Duration::from_secs(2), async {
            while !root.path().join("helper.pid").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        GROUP_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
        CHILD_KILL_ERROR.with(|error| error.set(Some(libc::EPERM)));
        sender.send(true).unwrap();
    };
    let (result, ()) = tokio::join!(run(&config, &spec, None, Some(receiver), &[], None), cancel);
    let error = result.unwrap_err().to_string();
    assert!(error.contains("process group"));
    assert!(error.contains("direct-child SIGKILL failed"));
    assert!(error.contains("VM cleanup is unproved"));
    let retained: Vec<_> = fs::read_dir(root.path().join("data"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].join("helper").is_file());
    assert!(retained[0].join("input").is_dir());
    assert!(retained[0].join("service-evidence.json").is_file());
    assert!(error.contains(&format!("runtime preserved at {}", retained[0].display())));
}

#[tokio::test]
async fn deadline_kills_and_reaps_a_spinning_helper_before_returning() {
    let (root, mut spec, config) = fixture("while :; do :; done");
    spec.timeout_seconds = 1;
    let started = std::time::Instant::now();
    let result = run(&config, &spec, None, None, &[], None).await.unwrap();
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
        run(&next_config, &next_spec, None, None, &[], None)
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
    let (result, ()) = tokio::join!(run(&config, &spec, None, Some(receiver), &[], None), cancel);
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
    let (_root, spec, _) = fixture("exit 0");
    let original_value = serde_json::to_value(&spec).unwrap();
    for core in [false, true] {
        let mut value = original_value.clone();
        let artifact = if core { "guest" } else { "checker" };
        if core {
            value["engine"] = json!({"kind":"hyperlight", "runtime":value["engine"]["runtime"],
                "guest":value["engine"]["checker"], "function":"Check", "reuse_initialization":true});
        }
        let original = template_key(&serde_json::from_value(value.clone()).unwrap()).unwrap();
        for field in ["memory_mb", "artifact", "runtime"] {
            // Each mutation starts from the original. Otherwise a previous
            // changed artifact can hide a runtime-identity regression.
            let mut changed = value.clone();
            match field {
                "memory_mb" => changed[field] = (spec.memory_mb + 1).into(),
                "artifact" => changed["engine"][artifact]["sha256"] = "a".repeat(64).into(),
                "runtime" => changed["engine"][field]["sha256"] = "b".repeat(64).into(),
                _ => unreachable!(),
            }
            let changed: JobSpec = serde_json::from_value(changed).unwrap();
            assert_ne!(
                template_key(&changed).unwrap(),
                original,
                "{artifact}/{field}"
            );
        }
        value["gate_id"] = "another-principal".into();
        value["argv"] = json!(["different invocation input"]);
        value["timeout_seconds"] = (spec.timeout_seconds + 1).into();
        if core {
            value["engine"]["function"] = "another-entry".into();
        }
        assert_eq!(
            template_key(&serde_json::from_value(value).unwrap()).unwrap(),
            original
        );
    }
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

#[tokio::test]
async fn template_identity_binds_each_verified_runtime_manifest_input() {
    // Exercise the manifest reader and artifact copier as well as JobSpec's
    // digest. These are the producer fields behind the transitive identity.
    for field in [
        "helper",
        "rootfs",
        "kernel_contract",
        "protocol",
        "hyperlight",
        "unikraft",
        "os",
        "architecture",
    ] {
        let (root, mut spec, _) = fixture("exit 99");
        let original = template_key(&spec).unwrap();
        let JobEngine::HyperlightUnikraft { runtime, .. } = &mut spec.engine else {
            unreachable!()
        };
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&runtime.path).unwrap()).unwrap();
        if field == "helper" || field == "rootfs" {
            let path = root.path().join(manifest[field]["file"].as_str().unwrap());
            fs::write(&path, format!("changed {field} initialization bytes")).unwrap();
            manifest[field]["sha256"] = digest(&fs::read(path).unwrap()).into();
        } else if field == "protocol" {
            manifest[field] = 999.into();
        } else {
            manifest[field] = "changed".into();
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&runtime.path, &bytes).unwrap();
        runtime.sha256 = digest(&bytes);
        assert_ne!(template_key(&spec).unwrap(), original, "{field}");

        let invocation = root.path().join("prepared");
        fs::create_dir(&invocation).unwrap();
        let prepared = prepare(&spec, &invocation).await;
        if matches!(field, "helper" | "rootfs" | "kernel_contract") {
            prepared.unwrap();
            if field == "helper" || field == "rootfs" {
                let copied = if field == "helper" {
                    "helper"
                } else {
                    "python.cpio"
                };
                assert_eq!(
                    digest(&fs::read(invocation.join(copied)).unwrap()),
                    manifest[field]["sha256"].as_str().unwrap(),
                );
            }
        } else {
            assert!(prepared.is_err(), "incompatible {field} was admitted");
        }
        assert!(!root.path().join("helper.pid").exists());
    }
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
    // A concurrent child fixture can briefly inherit this synthetic lease.
    lease.unlock().unwrap();
    drop(lease);
    clear_templates(&config).unwrap();
    assert!(!active.exists());
}
