//! Actual snapshot publication under a path-scoped, child-only close fault.
#![cfg(target_os = "linux")]

use std::{path::PathBuf, process::Command};

use safeyolo_proxy::circuits::{CircuitBreaker, ErrorKind};
use serde_json::{Value, json};
use tempfile::TempDir;

const ORIGINAL: &[u8] = b"{\"states\":{\"previous.invalid\":{}},\"saved_at\":0}\n";

/// Selected explicitly by the parent process below; ordinary test runs do not
/// load a shim, read a default state path, or create a background worker.
#[test]
fn snapshot_child() {
    let Some(directory) = std::env::var_os("CIRCUIT_FAULT_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let breaker = CircuitBreaker::default();
    breaker
        .restore(&json!({"states":{"fresh.invalid":{}}}), 10.0, &mut || 0.5)
        .unwrap();
    let result = breaker.save_file(&directory.join("state.json"), 10.0);
    let outcome = match result {
        Ok(()) => json!({"saved":true}),
        Err(error) => {
            assert_eq!(error.kind(), ErrorKind::Invalid);
            // Compare private error text to categorical OS errors; never print
            // it or depend on a language-specific English diagnostic.
            let errno = [libc::EIO, libc::ENOSPC].into_iter().find(|number| {
                error.to_string() == std::io::Error::from_raw_os_error(*number).to_string()
            });
            assert!(errno.is_some(), "the owned failure must be categorical");
            json!({"saved":false,"errno":errno})
        }
    };
    std::fs::write(directory.join("result.json"), outcome.to_string()).unwrap();
}

#[test]
fn close_failure_prevents_publication_and_overrides_write_failure_once() {
    let shim = TempDir::new().unwrap();
    let source = shim.path().join("fault.c");
    let library = shim.path().join("fault.so");
    std::fs::write(&source, include_str!("fixtures/circuit_close_fault.c")).unwrap();
    let compiled = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .args(["-o"])
        .arg(&library)
        .args(["-ldl"])
        .output()
        .expect("the native build requires a C compiler");
    assert!(compiled.status.success(), "owned fault shim must compile");

    for mode in [
        "none",
        "close_only",
        "write_only",
        "write_close",
        "short_close",
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("state.json");
        let trace = directory.path().join("syscalls.log");
        std::fs::write(&path, ORIGINAL).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "snapshot_child", "--nocapture"])
            .env("LD_PRELOAD", &library)
            .env("CIRCUIT_FAULT_DIRECTORY", directory.path())
            .env("CIRCUIT_FAULT_LOG", &trace)
            .env("CIRCUIT_FAULT_MODE", mode)
            .env("CIRCUIT_FAULT_STYLE", "native")
            .output()
            .unwrap();
        assert!(child.status.success(), "owned child failed: {mode}");
        let outcome: Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("result.json")).unwrap())
                .unwrap();
        let events = std::fs::read_to_string(trace).unwrap();
        assert_eq!(events.matches("close_real_success\n").count(), 1, "{mode}");
        assert!(!events.contains("repeat_close_after_release"), "{mode}");
        assert!(!events.contains("close_real_failure"), "{mode}");
        assert!(!events.contains("write_real_failure"), "{mode}");
        if mode == "none" {
            assert_eq!(outcome, json!({"saved":true}));
            let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["states"], json!({"fresh.invalid":{}}));
            assert_eq!(saved["saved_at"], 10.0);
            assert!(!events.contains("report_"));
        } else {
            let errno = if mode == "write_only" {
                libc::ENOSPC
            } else {
                libc::EIO
            };
            assert_eq!(outcome, json!({"saved":false,"errno":errno}), "{mode}");
            assert_eq!(std::fs::read(&path).unwrap(), ORIGINAL, "{mode}");
            if mode != "close_only" {
                assert!(events.contains("write_report_ENOSPC"), "{mode}");
            }
            if mode != "write_only" {
                assert_eq!(events.matches("close_report_EIO\n").count(), 1, "{mode}");
            }
        }
        assert!(
            std::fs::read_dir(directory.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".circuit-")
            }),
            "no temporary snapshot remains: {mode}"
        );
    }
}
