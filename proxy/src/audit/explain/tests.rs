use super::*;
use crate::audit::{Event, Kind, Settings, Severity};
use std::{ffi::CString, os::unix::ffi::OsStrExt};

const ID: &str = "req-0123456789abcdef0123456789abcdef";

#[test]
fn interrupted_read_retries_without_losing_partial_text() {
    struct Interrupted {
        calls: usize,
    }
    impl Read for Interrupted {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            match self.calls {
                1 => {
                    out[0] = 0xc3;
                    Ok(1)
                }
                2 => Err(std::io::ErrorKind::Interrupted.into()),
                3 => {
                    out[..2].copy_from_slice(&[0xa9, b'\n']);
                    Ok(2)
                }
                _ => Ok(0),
            }
        }
    }
    let Ok((lines, incomplete)) = tail(&mut Interrupted { calls: 0 }) else {
        panic!("interrupted read must resume")
    };
    assert!(!incomplete);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].as_slice(), "é".as_bytes());
}

fn event(index: usize) -> Event {
    let mut event = Event::new("traffic.owned", Kind::Traffic, Severity::Low, "owned");
    event.request_id = Some(ID.into());
    event.agent = Some("alice".into());
    event.details = json!({"index":index}).into();
    event
}
fn row(index: usize) -> String {
    format!(r#"{{"request_id":"{ID}","agent":"alice","index":{index}}}"#)
}
fn writer(path: &Path, backups: i32) -> Writer {
    Writer::new(
        path.into(),
        Settings {
            backups: backups.into(),
            ..Settings::default()
        },
    )
}
fn json_report(writer: &Writer) -> Value {
    let mut report = writer.explain(ID, "alice").unwrap();
    let value = serde_json::from_str(&report.render_json(false).unwrap()).unwrap();
    wipe(&mut report);
    value
}

#[test]
fn strict_owner_filter_file_order_suffix_and_gaps() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.log");
    fs::write(&path, format!("{}\nnot-json\n\n", row(0))).unwrap();
    let records = [
        row(1),
        format!(r#"{{"request_id":"{ID}","agent":"bob"}}"#),
        format!(
            r#"{{"request_id":"{ID}","details":{{"attribution":{{"evidence_owner":"alice"}}}}}}"#
        ),
        format!(r#"{{"request_id":"{ID}","agent":true}}"#),
        r#"{"request_id":"other","agent":"alice"}"#.into(),
        row(2),
    ];
    fs::write(directory.path().join("audit.jsonl.1"), records.join("\n")).unwrap();
    fs::write(directory.path().join("audit.jsonl.3"), row(3)).unwrap();
    fs::write(directory.path().join("audit.log.1"), row(99)).unwrap();
    let report = json_report(&writer(&path, 3));
    assert_eq!(report["status"], "complete");
    assert_eq!(
        report["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    let foreign = writer(&path, 3).explain(ID, "charlie").unwrap();
    assert!(
        foreign.as_object().unwrap()["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn universal_newlines_strip_final_line_and_utf8_chunk_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.");
    let prefix = " ".repeat(8191);
    fs::write(
        &path,
        format!(
            "{prefix}\u{2003}{}\r\n\u{001c}{}\u{0085}\r{}\n{}",
            row(0),
            row(1),
            row(2),
            row(3)
        ),
    )
    .unwrap();
    fs::write(directory.path().join("events..jsonl.1"), row(4)).unwrap();
    let report = json_report(&writer(&path, 1));
    assert_eq!(report["events"].as_array().unwrap().len(), 5);
    assert_eq!(report["status"], "complete");
    // Unicode NEL is Python strip whitespace, not a text-file line boundary.
    fs::write(&path, format!("{}\u{0085}{}", row(0), row(1))).unwrap();
    assert!(
        json_report(&writer(&path, 0))["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn each_file_has_its_own_tail_and_invalid_utf8_is_not_hidden_before_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let lines = (0..=MAX_LINES).map(row).collect::<Vec<_>>().join("\n");
    fs::write(&path, lines).unwrap();
    fs::write(directory.path().join("audit.jsonl.1"), row(MAX_LINES + 1)).unwrap();
    let report = json_report(&writer(&path, 1));
    assert_eq!(report["status"], "incomplete_search");
    assert_eq!(report["searched_lines_per_file"], MAX_LINES);
    let events = report["events"].as_array().unwrap();
    assert_eq!(events.len(), MAX_LINES + 1);
    assert_eq!(events[0]["index"], 1);
    assert_eq!(events.last().unwrap()["index"], MAX_LINES + 1);
    fs::write(
        &path,
        [b"\xff\n".as_slice(), "\n".repeat(MAX_LINES).as_bytes()].concat(),
    )
    .unwrap();
    assert_eq!(
        writer(&path, 0).explain(ID, "alice").unwrap_err().kind(),
        ExplainErrorKind::UnicodeDecode
    );
}

#[test]
fn io_failure_discards_that_file_and_continues_but_other_errors_escape() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::create_dir(&path).unwrap();
    fs::write(directory.path().join("audit.jsonl.1"), row(1)).unwrap();
    let report = json_report(&writer(&path, 1));
    assert_eq!(report["status"], "error");
    assert_eq!(report["events"].as_array().unwrap().len(), 1);
    for (name, bytes, expected) in [
        ("array", b"[]".as_slice(), ExplainErrorKind::Attribute),
        ("null", b"null".as_slice(), ExplainErrorKind::Attribute),
        (
            "unicode",
            b"\xff".as_slice(),
            ExplainErrorKind::UnicodeDecode,
        ),
        (
            "surrogate",
            br#"{"unrelated":"\ud800"}"#.as_slice(),
            ExplainErrorKind::Compatibility,
        ),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            writer(&path, 0).explain(ID, "alice").unwrap_err().kind(),
            expected
        );
    }
    // A disappearing retained file is a per-file read error, not missing history.
    let absent = directory.path().join("removed-after-enumeration");
    let scan = scan(
        &[absent, directory.path().join("audit.jsonl.1")],
        ID,
        "alice",
    )
    .unwrap();
    assert!(scan.read_error);
    assert_eq!(scan.events.as_array().unwrap().len(), 1);
}

#[test]
fn typed_payload_and_integer_conversion_error_are_not_lossy_or_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::write(&path, format!(r#"{{"request_id":"{ID}","agent":"alice","values":[NaN,Infinity,-Infinity,1e9999,-0.0,18446744073709551616000]}}"#)).unwrap();
    let mut report = writer(&path, 0).explain(ID, "alice").unwrap();
    let encoded = report.render_json(false).unwrap();
    assert!(encoded.contains("NaN, Infinity, -Infinity, Infinity, -0.0, 18446744073709551616000"));
    wipe(&mut report);
    fs::write(&path, format!("{{\"unused\":{}}}", "1".repeat(4301))).unwrap();
    assert_eq!(
        writer(&path, 0).explain(ID, "alice").unwrap_err().kind(),
        ExplainErrorKind::Value
    );
    fs::write(
        &path,
        format!("{}\n{}", "1".repeat(4301), "\n".repeat(MAX_LINES)),
    )
    .unwrap();
    assert_eq!(
        json_report(&writer(&path, 0))["status"],
        "incomplete_search"
    );
}

#[test]
fn first_write_is_visible_and_empty_writer_does_not_create_log() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("new/audit.jsonl");
    let writer = writer(&path, 2);
    assert_eq!(json_report(&writer)["status"], "complete");
    assert!(!path.exists());
    writer.emit(event(1)).unwrap();
    let report = json_report(&writer);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["events"].as_array().unwrap().len(), 1);
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
}

#[test]
fn real_blocked_writer_timeout_status_is_latched_and_error_has_precedence() {
    for read_error in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: owned pathname, no shared/operational filesystem access.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        if read_error {
            fs::create_dir(directory.path().join("audit.jsonl.1")).unwrap();
        }
        fs::write(
            directory.path().join("audit.jsonl.2"),
            format!("{}\n{}", "\n".repeat(MAX_LINES), row(2)),
        )
        .unwrap();
        let writer = writer(&path, 2);
        // The actual worker blocks opening the FIFO until the authoritative
        // scan begins after its drain timeout. No fake pending counter.
        writer.emit(event(1)).unwrap();
        let report = json_report(&writer);
        assert_eq!(
            report["status"],
            if read_error { "error" } else { "pending" }
        );
        assert_eq!(report["searched_lines_per_file"], MAX_LINES);
        assert_eq!(report["events"].as_array().unwrap().len(), 2);
        assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
        assert_eq!(writer.pending_count().unwrap(), 0);
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    }
}

#[test]
fn source_path_names_negative_backups_and_parent_directory_spelling() {
    if std::env::var_os("SAFEYOLO_OWNED_EXPLAIN_PATH_CHILD").is_some() {
        assert_eq!(json_report(&writer(Path::new(""), -1))["status"], "error");
        assert_eq!(
            writer(Path::new(""), 1)
                .explain(ID, "alice")
                .unwrap_err()
                .kind(),
            ExplainErrorKind::Value
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let current = directory.path().join("inner/..");
    fs::create_dir(directory.path().join("inner")).unwrap();
    let rotated = directory.path().join("inner/...jsonl.1");
    fs::write(&rotated, row(1)).unwrap();
    assert_eq!(
        retained(&current, &1.into()).unwrap(),
        [current.clone(), rotated]
    );
    assert_eq!(json_report(&writer(&current, 1))["status"], "error");
    let ordinary_backup = directory.path().join("inner.jsonl.1");
    fs::write(&ordinary_backup, row(2)).unwrap();
    for spelling in ["inner/.", "inner/"] {
        let path = directory.path().join(spelling);
        assert_eq!(
            retained(&path, &1.into()).unwrap(),
            [path, ordinary_backup.clone()]
        );
    }
    assert_eq!(
        retained(Path::new("."), &1.into()).unwrap_err().kind(),
        ExplainErrorKind::Value
    );
    assert_eq!(
        retained(Path::new("/"), &1.into()).unwrap_err().kind(),
        ExplainErrorKind::Value
    );
    assert_eq!(json_report(&writer(Path::new("."), -1))["status"], "error");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("audit::explain::tests::source_path_names_negative_backups_and_parent_directory_spelling")
        .current_dir(directory.path())
        .env("SAFEYOLO_OWNED_EXPLAIN_PATH_CHILD", "1")
        .output().unwrap();
    assert!(child.status.success(), "owned-path child failed");
}

#[test]
fn close_failure_preserves_only_retention_flag_reached_before_close() {
    let mut data = std::io::Cursor::new("\n".repeat(MAX_LINES + 1).into_bytes());
    let result = tail(&mut data);
    let failed_close = || Err(super::super::Error(super::super::ErrorKind::Io));
    assert!(matches!(
        close_tail(result, failed_close()),
        Err(ReadError::Io { incomplete: true })
    ));
    assert!(matches!(
        close_tail(Err(ReadError::Io { incomplete: false }), failed_close()),
        Err(ReadError::Io { incomplete: false })
    ));
    assert!(matches!(
        close_tail(Err(ReadError::Unicode), failed_close()),
        Err(ReadError::Io { incomplete: false })
    ));
}

#[test]
fn actual_source_scans_match_retained_file_recipes() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/agent_api_explain_source.json")).unwrap();
    let mut compared = 0;
    for row in fixture["rows"].as_array().unwrap() {
        let Some(expected) = row["scans"].as_array().unwrap().first() else {
            continue;
        };
        let input = &row["input"];
        let directory = tempfile::tempdir().unwrap();
        for recipe in input["files"]
            .as_array()
            .unwrap()
            .iter()
            .chain(input["drain_files"].as_array().into_iter().flatten())
        {
            let path = directory.path().join(recipe["name"].as_str().unwrap());
            let bytes = if let Some(hex) = recipe["hex"].as_str() {
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect::<Vec<_>>()
            } else {
                recipe["parts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|part| {
                        part["text"]
                            .as_str()
                            .unwrap()
                            .repeat(part["repeat"].as_u64().unwrap() as usize)
                            .into_bytes()
                    })
                    .collect()
            };
            use std::io::Write;
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
        }
        if let Some(failed) = input["open_error"].as_str() {
            let path = directory.path().join(failed);
            fs::remove_file(&path).unwrap();
            fs::create_dir(path).unwrap();
        }
        let path = directory.path().join(input["current"].as_str().unwrap());
        let files = retained(&path, &fixture["backups"].as_i64().unwrap().into()).unwrap();
        assert_eq!(
            files
                .iter()
                .map(|path| path.file_name().unwrap().to_str().unwrap())
                .collect::<Vec<_>>(),
            expected["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            "{}",
            input["name"]
        );
        let result = scan(
            &files,
            expected["request_id"].as_str().unwrap(),
            expected["agent"].as_str().unwrap(),
        );
        if let Some(error) = expected["error_type"].as_str() {
            let actual = match result {
                Err(error) => error.kind(),
                Ok(_) => panic!("source error must remain terminal"),
            };
            assert_eq!(
                actual,
                match error {
                    "UnicodeDecodeError" => ExplainErrorKind::UnicodeDecode,
                    "AttributeError" => ExplainErrorKind::Attribute,
                    _ => panic!("unhandled fixture category"),
                }
            );
        } else {
            let actual = result.unwrap();
            assert_eq!(
                actual.events.render_json(false).unwrap(),
                expected["events_json"].as_str().unwrap(),
                "{}",
                input["name"]
            );
            assert_eq!(actual.incomplete, expected["incomplete"].as_bool().unwrap());
            assert_eq!(actual.read_error, expected["read_error"].as_bool().unwrap());
        }
        compared += 1;
    }
    assert_eq!(compared, 18);
}
