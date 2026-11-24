//! Exercise the actual SQLite page ceiling rather than only record counters.
#![cfg(unix)]
mod common;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::Ed25519KeyPair,
};
use safeyolo_host_executor::*;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    root: PathBuf,
    target: Target,
    key: Ed25519KeyPair,
    limits: LedgerLimits,
}
impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "ledger-capacity-{:032x}",
            u128::from_le_bytes(random)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[81; 32]).unwrap();
        let mut package: Package = serde_json::from_str(include_str!(
            "../../proxy/tests/fixtures/host_execution/package.json"
        ))
        .unwrap();
        let op = package.operations.get_mut("restart").unwrap();
        op.arguments.clear();
        op.execution.argv.truncate(1);
        let target = common::target("capacity-fixture".into(), package.operations, &key);
        target.validate().unwrap();
        Self {
            root,
            target,
            key,
            limits: LedgerLimits {
                jobs: 10,
                mutation_records: 20,
                output_bytes: 40960,
                database_bytes: 131072,
                request_bytes: 131072,
            },
        }
    }
    fn open(&self) -> Ledger {
        Ledger::open(&self.root, &self.target.target_id, self.limits.clone()).unwrap()
    }
    fn signed(&self, action: Action, id: &str, rationale: usize, expires_at: u64) -> Vec<u8> {
        serde_json::to_vec(&SignedRequest::sign(
            Request {
                version: VERSION.into(),
                required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
                request_id: id.into(),
                target_id: self.target.target_id.clone(),
                issuer_id: "issuer".into(),
                grant_id: "grant".into(),
                principal: self.target.issuers["issuer"].authority.grants["grant"]
                    .principal
                    .clone(),
                expires_at,
                expected: Some(
                    self.target
                        .request_revisions("issuer", "grant", &action)
                        .unwrap(),
                ),
                action,
                untrusted_rationale: "a".repeat(rationale),
            },
            "key".into(),
            &self.key,
        ))
        .unwrap()
    }
    fn invoke(&self, ledger: &mut Ledger, rationale: usize) -> Vec<u8> {
        let proposal = self.signed(
            Action::Propose {
                invocation: Invocation {
                    operation_id: "restart".into(),
                    resource_id: "service:demo".into(),
                    operation_sha256: self.target.package.operation_sha256("restart").unwrap(),
                    implementation_sha256: self.target.package.operations["restart"]
                        .implementation_sha256(),
                    arguments: BTreeMap::new(),
                    expected_assessment_sha256: None,
                },
            },
            "proposal",
            0,
            now() + 300,
        );
        let Response::Proposal { prepared, .. } = ledger
            .handle(&self.target, Verb::Propose.path(), &proposal, now())
            .unwrap()
            .response
        else {
            panic!("proposal refused")
        };
        self.signed(
            Action::Invoke {
                invocation: prepared.invocation,
            },
            "invoke",
            rationale,
            prepared.valid_until,
        )
    }
    fn fill_database(&self) {
        let db = rusqlite::Connection::open(self.root.join("jobs.sqlite")).unwrap();
        db.pragma_update(
            None,
            "max_page_count",
            (self.limits.database_bytes / 4096) as i64,
        )
        .unwrap();
        db.execute("CREATE TABLE pressure(bytes BLOB)", []).unwrap();
        while db
            .execute("INSERT INTO pressure VALUES(zeroblob(1024))", [])
            .is_ok()
        {}
        let pages: i64 = db
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        assert_eq!(pages as u64 * 4096, self.limits.database_bytes);
        assert_eq!(
            db.query_row("PRAGMA freelist_count", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn receipt(response: Response) -> Receipt {
    let Response::Job { receipt } = response else {
        panic!("job expected")
    };
    *receipt
}

#[test]
fn file_results_keep_original_and_current_scope_and_detect_replacement() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut f = Fixture::new();
    let output = f.root.join("results");
    fs::create_dir(&output).unwrap();
    let result = output.join("result");
    fs::create_dir(output.join("nested")).unwrap();
    fs::write(&result, b"partial retained result").unwrap();
    fs::write(f.root.join("private"), b"unrelated secret").unwrap();
    std::os::unix::fs::symlink(f.root.join("private"), output.join("escape")).unwrap();
    let mut operations = f.target.package.operations.clone();
    operations
        .get_mut("restart")
        .unwrap()
        .execution
        .filesystem
        .write = vec![
        output.to_str().unwrap().into(),
        output.join("nested").to_str().unwrap().into(),
    ];
    f.target = common::target(f.target.target_id.clone(), operations, &f.key);
    let mut ledger = f.open();
    let invoke = f.invoke(&mut ledger, 0);
    let job = receipt(
        ledger
            .handle(&f.target, Verb::Invoke.path(), &invoke, now())
            .unwrap()
            .response,
    );
    // File reads need no new retained artifact or ledger allocation, including
    // when the existing database has reached its actual SQLite page ceiling.
    f.fill_database();
    let action = |path: &std::path::Path, offset, max_bytes, expected_file_revision| Action::File {
        job_id: job.job_id.clone(),
        path: path.to_str().unwrap().into(),
        offset,
        max_bytes,
        expected_file_revision,
    };
    let read = |ledger: &mut Ledger, f: &Fixture, action: Action| {
        let bytes = f.signed(action, "file-read", 0, now() + 300);
        ledger
            .handle(&f.target, Verb::File.path(), &bytes, now())
            .map(|r| r.response)
    };
    let Response::File {
        data_base64,
        eof,
        total_bytes,
        file_revision,
        ..
    } = read(&mut ledger, &f, action(&result, 0, 7, None)).unwrap()
    else {
        panic!("file result required")
    };
    assert_eq!(STANDARD.decode(data_base64).unwrap(), b"partial");
    assert!(!eof);
    assert_eq!(total_bytes, 23);
    drop(ledger);
    let mut ledger = f.open();
    let Response::File {
        data_base64, eof, ..
    } = read(
        &mut ledger,
        &f,
        action(&result, 7, 100, Some(file_revision.clone())),
    )
    .unwrap()
    else {
        panic!("file result after restart")
    };
    assert_eq!(STANDARD.decode(data_base64).unwrap(), b" retained result");
    assert!(eof);
    fs::write(output.join("empty"), []).unwrap();
    assert!(
        matches!(read(&mut ledger, &f, action(&output.join("empty"), 0, 8, None)).unwrap(), Response::File { eof: true, total_bytes: 0, data_base64, .. } if data_base64.is_empty())
    );
    // Overlapping roots cannot promote a workload-created symlink to a new
    // trusted root. Opening from the outer scope keeps it a denied descendant.
    fs::remove_dir(output.join("nested")).unwrap();
    std::os::unix::fs::symlink(&f.root, output.join("nested")).unwrap();
    assert_eq!(
        read(
            &mut ledger,
            &f,
            action(&output.join("nested/private"), 0, 8, None)
        )
        .unwrap_err()
        .code,
        RefusalCode::Unavailable
    );
    fs::remove_file(output.join("nested")).unwrap();
    fs::create_dir(output.join("nested")).unwrap();
    fs::write(output.join("replacement"), b"replaced").unwrap();
    fs::rename(output.join("replacement"), &result).unwrap();
    assert_eq!(
        read(&mut ledger, &f, action(&result, 0, 7, Some(file_revision)))
            .unwrap_err()
            .code,
        RefusalCode::Stale
    );
    for (path, code) in [
        (f.root.join("absent-private"), RefusalCode::Authority),
        (output.join("../private"), RefusalCode::Arguments),
        (output.join("escape"), RefusalCode::Unavailable),
        (output.clone(), RefusalCode::Arguments),
        (output.join("missing"), RefusalCode::Unavailable),
    ] {
        let error = read(&mut ledger, &f, action(&path, 0, 8, None)).unwrap_err();
        assert_eq!(error.code, code, "{error:?}");
        assert!(!error.message.contains("unrelated secret"));
    }
    for (offset, max_bytes) in [(0, 0), (0, 4097), (9, 1)] {
        assert_eq!(
            read(&mut ledger, &f, action(&result, offset, max_bytes, None))
                .unwrap_err()
                .code,
            RefusalCode::Arguments
        );
    }
    f.target.allowed_verbs.remove(&Verb::File);
    assert_eq!(
        read(&mut ledger, &f, action(&result, 0, 8, None))
            .unwrap_err()
            .code,
        RefusalCode::Authority
    );
    f.target.allowed_verbs.insert(Verb::File);
    f.target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .verbs
        .remove(&Verb::File);
    assert_eq!(
        read(&mut ledger, &f, action(&result, 0, 8, None))
            .unwrap_err()
            .code,
        RefusalCode::Authority
    );
    f.target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .verbs
        .insert(Verb::File);
    let own = f.target.clone();
    f.target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .principal
        .run
        .run_id = "22222222222222222222222222222222".into();
    assert_eq!(
        read(&mut ledger, &f, action(&result, 0, 8, None))
            .unwrap_err()
            .code,
        RefusalCode::Authority
    );
    f.target = own;
    // A later authorised expansion cannot lend an old job new file roots.
    let mut operations = f.target.package.operations.clone();
    operations
        .get_mut("restart")
        .unwrap()
        .execution
        .filesystem
        .write = vec![f.root.to_str().unwrap().into()];
    f.target = common::target(f.target.target_id.clone(), operations.clone(), &f.key);
    assert_eq!(
        read(&mut ledger, &f, action(&f.root.join("private"), 0, 8, None))
            .unwrap_err()
            .code,
        RefusalCode::Authority
    );
    // Narrowing current scope takes effect even though the receipt is retained.
    operations
        .get_mut("restart")
        .unwrap()
        .execution
        .filesystem
        .write
        .clear();
    f.target = common::target(f.target.target_id.clone(), operations, &f.key);
    assert_eq!(
        read(&mut ledger, &f, action(&result, 0, 8, None))
            .unwrap_err()
            .code,
        RefusalCode::Authority
    );
}

#[test]
fn admitted_work_finishes_and_replays_when_every_database_page_is_used() {
    let mut admitted = 0;
    let mut refused = 0;
    for length in [0, 10000, 20000, 53620, 54568, 90000, 105000] {
        let f = Fixture::new();
        let mut ledger = f.open();
        let invoke = f.invoke(&mut ledger, length);
        let first = match ledger.handle(&f.target, Verb::Invoke.path(), &invoke, now()) {
            Ok(value) => value,
            Err(error) => {
                assert_eq!(error.code, RefusalCode::Unavailable);
                assert!(error.message.contains("full"), "{error}");
                assert!(ledger.recover(now()).unwrap().is_empty());
                drop(ledger);
                let mut ledger = f.open();
                assert!(ledger.recover(now()).unwrap().is_empty());
                let shorter = f.invoke(&mut ledger, 0);
                assert!(
                    ledger
                        .handle(&f.target, Verb::Invoke.path(), &shorter, now())
                        .unwrap()
                        .dispatch,
                    "refused admission must not spend the call or request ID"
                );
                refused += 1;
                continue;
            }
        };
        assert!(first.dispatch);
        let job = receipt(first.response);
        f.fill_database();
        ledger.begin(&f.target, &job.job_id, now()).unwrap();
        assert_eq!(
            ledger
                .append_output(&job.job_id, &vec![42; 1024], now())
                .unwrap(),
            1024
        );
        assert_eq!(ledger.append_output(&job.job_id, &[42], now()).unwrap(), 0);
        let current = ledger.observe(&job.job_id).unwrap();
        // Cancellation selectors remain governed by the existing request ceiling.
        let cancel = f.signed(
            Action::Cancel {
                job_id: job.job_id.clone(),
                expected_revision: current.revision,
            },
            &"c".repeat(70000),
            0,
            now() + 300,
        );
        let cancellation = ledger
            .handle(&f.target, Verb::Cancel.path(), &cancel, now())
            .unwrap();
        assert!(receipt(cancellation.response.clone()).cancellation_requested);
        let facts = NativeObservation {
            backend: "fixture".into(),
            enforcement: vec!["observed fixture".into()],
            dependencies: vec![],
            exit_code: None,
            signal: Some(9),
            processes_stopped: true,
            output_truncated: true,
            termination_reason: "cancelled".into(),
        };
        let final_receipt = ledger
            .finish_observed(
                &job.job_id,
                JobState::Cancelled,
                true,
                now(),
                "\u{1}".repeat(10000),
                Some(facts),
            )
            .unwrap();
        assert!(final_receipt.detail.ends_with("[diagnostic truncated]"));
        drop(ledger);
        let mut ledger = f.open();
        assert!(ledger.recover(now()).unwrap().is_empty());
        assert_eq!(
            ledger.observe(&job.job_id).unwrap().state,
            JobState::Cancelled
        );
        let replay = ledger
            .handle(&f.target, Verb::Invoke.path(), &invoke, now())
            .unwrap();
        assert!(!replay.dispatch);
        assert_eq!(receipt(replay.response).job_id, job.job_id);
        let replay = ledger
            .handle(&f.target, Verb::Cancel.path(), &cancel, now())
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&replay.response).unwrap(),
            serde_json::to_vec(&cancellation.response).unwrap()
        );
        let output = f.signed(
            Action::Output {
                job_id: job.job_id.clone(),
                offset: 0,
                max_bytes: 1024,
            },
            "output",
            0,
            now() + 300,
        );
        let Response::Output { retained_bytes, .. } = ledger
            .handle(&f.target, Verb::Output.path(), &output, now())
            .unwrap()
            .response
        else {
            panic!("output unavailable")
        };
        assert_eq!(retained_bytes, 1024);
        admitted += 1;
    }
    assert!(admitted >= 1 && refused >= 1);
}

#[test]
fn restart_recovery_and_quiescence_do_not_need_free_database_pages() {
    for running in [false, true] {
        let f = Fixture::new();
        let mut ledger = f.open();
        let invoke = f.invoke(&mut ledger, 10000);
        let job = receipt(
            ledger
                .handle(&f.target, Verb::Invoke.path(), &invoke, now())
                .unwrap()
                .response,
        );
        if running {
            ledger.begin(&f.target, &job.job_id, now()).unwrap();
        }
        f.fill_database();
        drop(ledger);
        let mut ledger = f.open();
        let recovered = ledger.recover(now()).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, JobState::Uncertain);
        ledger
            .confirm_quiescent(&job.job_id, now(), "independently observed no process")
            .unwrap();
        drop(ledger);
        let mut ledger = f.open();
        assert!(ledger.recover(now()).unwrap().is_empty());
        assert!(
            !ledger
                .handle(&f.target, Verb::Invoke.path(), &invoke, now())
                .unwrap()
                .dispatch
        );
    }
}
