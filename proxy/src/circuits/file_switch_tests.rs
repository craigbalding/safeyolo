//! File replacement must serialize with callers retaining an older core clone.
#![cfg(target_os = "linux")]

use super::*;
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    sync::{TryLockError, mpsc},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const LIMIT: Duration = Duration::from_secs(5);

fn fifo(path: &Path) {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated path belongs to this TempDir and remains valid
    // for the call. No real operator file or shared FIFO is touched.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

fn fifo_read_is_open(path: &Path) -> bool {
    let expected = fs::metadata(path).unwrap();
    // The test owns one read/write descriptor. A second descriptor for this
    // inode proves that the real read_snapshot has opened the selected FIFO;
    // elapsed time or the old-file rename alone would not prove this boundary.
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| fs::metadata(entry.ok()?.path()).ok())
        .filter(|entry| entry.dev() == expected.dev() && entry.ino() == expected.ino())
        .count()
        >= 2
}

#[test]
fn reset_waits_for_selected_file_publication_and_cannot_be_undone_by_load() {
    let directory = TempDir::new().unwrap();
    let previous = directory.path().join("old.json");
    let selected = directory.path().join("next.fifo");
    fifo(&selected);
    let breaker = CircuitBreaker::default();
    breaker
        .restore(
            &json!({"states":{"shared.invalid":{"state":"closed","failure_count":1}}}),
            10.0,
            &mut || 0.5,
        )
        .unwrap();

    thread::scope(|scope| {
        // Linux permits an owned read/write FIFO open without an external peer.
        // Closing this local writer supplies EOF to the actual file reader, also
        // during assertion unwinding, before scoped thread joins run.
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&selected)
            .unwrap();
        let change_owner = breaker.clone();
        let old_path = &previous;
        let new_path = &selected;
        let change = scope.spawn(move || {
            change_owner.replace_state_file(Some(old_path), Some(new_path), 20.0, &mut || 0.5)
        });
        let deadline = Instant::now() + LIMIT;
        while !fifo_read_is_open(&selected) {
            assert!(
                Instant::now() < deadline,
                "file change never opened selected FIFO"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let saved: Value = serde_json::from_slice(&fs::read(&previous).unwrap()).unwrap();
        assert_eq!(saved["saved_at"], 20.0);
        assert_eq!(saved["states"]["shared.invalid"]["failure_count"], 1);
        assert!(
            matches!(breaker.inner.try_lock(), Err(TryLockError::WouldBlock)),
            "file selection must retain Inner while its file read is pending"
        );
        let reset_owner = breaker.clone();
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (finished_tx, finished_rx) = mpsc::channel();
        let reset = scope.spawn(move || {
            started_tx.send(()).unwrap();
            let result = reset_owner.reset_json_key(&json!("shared.invalid"));
            finished_tx.send(()).unwrap();
            result
        });
        started_rx.recv_timeout(LIMIT).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        writer
            .write_all(b"{\"states\":{\"shared.invalid\":{\"state\":\"closed\",\"failure_count\":9},\"new.invalid\":{}}}")
            .unwrap();
        drop(writer);
        let outcome = change.join().unwrap().unwrap();
        assert!(!outcome.previous_save_failed && !outcome.load_failed);
        finished_rx.recv_timeout(LIMIT).unwrap();
        reset.join().unwrap().unwrap();
    });
    let current = breaker.snapshot(30.0).unwrap();
    assert!(current["states"].get("shared.invalid").is_none());
    assert_eq!(current["states"]["new.invalid"], json!({}));
    let saved: Value = serde_json::from_slice(&fs::read(previous).unwrap()).unwrap();
    assert_eq!(saved["states"]["shared.invalid"]["failure_count"], 1);
    assert!(saved["states"].get("new.invalid").is_none());
}

#[test]
fn file_failures_keep_nonfatal_replacement_and_preserve_settings_and_counters() {
    for mode in [
        "old_save_failure",
        "new_structure_failure",
        "missing",
        "invalid_json",
    ] {
        let directory = TempDir::new().unwrap();
        let previous = directory.path().join("old-destination-is-directory");
        fs::create_dir(&previous).unwrap();
        let next = directory.path().join("next.json");
        match mode {
            "old_save_failure" => fs::write(&next, br#"{"states":{"new.invalid":{}}}"#).unwrap(),
            "new_structure_failure" => {
                fs::write(&next, br#"{"states":{"broken.invalid":7}}"#).unwrap()
            }
            "invalid_json" => fs::write(&next, b"{").unwrap(),
            "missing" => (),
            _ => unreachable!(),
        }
        let breaker = CircuitBreaker::default();
        breaker
            .apply_sensor_config(&json!({"policy_hash":"owned", "addons":{"circuit_breaker":{"failure_threshold":9}}}))
            .unwrap();
        breaker.force_open("old.invalid", 10.0).unwrap();
        assert!(matches!(
            breaker
                .request("old.invalid", RequestGate::default(), 10.0, &mut || 0.5)
                .unwrap()
                .value,
            RequestDecision::Blocked { .. }
        ));
        let before = breaker
            .stats_document(true, 10.0, &mut || 0.5)
            .unwrap()
            .value;
        let result = breaker
            .replace_state_file(Some(&previous), Some(&next), 20.0, &mut || 0.5)
            .unwrap();
        assert!(result.previous_save_failed, "{mode}");
        assert_eq!(
            result.load_failed,
            mode == "new_structure_failure",
            "{mode}"
        );
        let current = breaker.snapshot(30.0).unwrap();
        assert_eq!(
            current["states"],
            if mode == "old_save_failure" {
                json!({"new.invalid":{}})
            } else {
                json!({})
            },
            "{mode}"
        );
        let after = breaker
            .stats_document(true, 20.0, &mut || 0.5)
            .unwrap()
            .value;
        for field in [
            "failure_threshold",
            "timeout_seconds",
            "checks_total",
            "opens_total",
            "half_opens_total",
            "recoveries_total",
        ] {
            assert_eq!(
                before.as_object().unwrap().get(field),
                after.as_object().unwrap().get(field),
                "{mode} {field}"
            );
        }
        assert!(previous.is_dir());
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".circuit-")
        }));
    }
}
