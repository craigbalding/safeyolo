// Exercise the production filesystem helpers without compiling the full library
// test harness. The public writer control also checks their actual caller.
#[path = "../src/audit/writer/durability.rs"]
mod durability;

#[tokio::test]
async fn confirmed_audit_retries_failed_destination_and_rotates_in_nested_directories() {
    use safeyolo_proxy::audit::{Event, Kind, Settings, Severity, Writer};
    use std::{fs, time::Duration};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("new/deep/audit.jsonl");
    fs::create_dir_all(&path).unwrap();
    let writer = Writer::new(
        path.clone(),
        Settings {
            max_bytes: 0.into(),
            ..Settings::default()
        },
    );
    let event = || {
        Event::new(
            "traffic.fixture",
            Kind::Traffic,
            Severity::Low,
            "owned fixture",
        )
    };
    assert!(writer.emit_confirmed(event()).await.is_err());
    fs::remove_dir(&path).unwrap();
    writer.emit_confirmed(event()).await.unwrap();
    writer.emit_confirmed(event()).await.unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
    assert_eq!(
        fs::read_to_string(path.with_extension("jsonl.1"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
}
