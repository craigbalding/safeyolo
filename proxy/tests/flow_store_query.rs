//! Actual SQLite selections, compared with the shipped Python FlowStore.
//! Fixtures contain only synthetic data; authorization is an API caller concern.

use safeyolo_proxy::circuits::CircuitValue;
use safeyolo_proxy::flow_store::{BodyInput, ErrorKind, FlowRecord, FlowStore, Settings};
use serde_json::{Value, json};

fn source() -> Value {
    serde_json::from_str(include_str!("flow_store_query_source.json")).unwrap()
}

#[test]
fn five_query_methods_match_actual_source_rows_filters_order_and_errors() {
    let source = source();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    for record in source["records"].as_array().unwrap() {
        let mut metadata = record.as_object().unwrap().clone();
        let request = metadata.shift_remove("request_body").unwrap();
        let response = metadata.shift_remove("response_body").unwrap();
        let stored = store
            .record(
                FlowRecord {
                    metadata: &metadata,
                    request_body: Some(BodyInput::complete(request.as_str().unwrap().as_bytes())),
                    response_body: Some(BodyInput::complete(response.as_str().unwrap().as_bytes())),
                },
                1000,
            )
            .unwrap();
        assert!(!stored.response_fts_failed && !stored.request_fts_failed);
    }
    // Query-only setup: tags and an authoritative v2 quarantined row. Ordinary
    // record() intentionally backfills a missing legacy owner, just like source.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("INSERT INTO flow_tags(flow_id,tag,value,created_at) VALUES(1,'review','',1000),(2,'review','one:two',1000)", []).unwrap();
    connection
        .execute("UPDATE flows SET evidence_owner=NULL WHERE id=8", [])
        .unwrap();
    drop(connection);

    for case in source["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(source["typed_cases"].as_array().unwrap())
    {
        let filters = if let Some(raw) = case["filters_json"].as_str() {
            CircuitValue::parse_json(raw).unwrap()
        } else {
            CircuitValue::from(case["filters"].clone())
        };
        let filters = &filters;
        let result = match case["method"].as_str().unwrap() {
            "search_flows" => store.search_flows(filters),
            "get_endpoints" => store.get_endpoints(filters),
            "get_facets" => store.get_facets(filters),
            "search_bodies" => store.search_bodies(filters),
            "search_request_bodies" => store.search_request_bodies(filters),
            method => panic!("unknown fixture method {method}"),
        };
        let name = case["name"].as_str().unwrap();
        match case["exception"].as_str() {
            None => {
                let output = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                // Compact rendering tests insertion order too; Value's ordinary
                // map equality alone would miss reordered projected columns.
                assert_eq!(
                    serde_json::to_string(&output).unwrap(),
                    serde_json::to_string(&case["output"]).unwrap(),
                    "{name}"
                );
            }
            Some(exception) => {
                let error = result.expect_err(name);
                let expected = match exception {
                    "ValueError" => ErrorKind::Value,
                    "TypeError" => ErrorKind::Type,
                    "AttributeError" => ErrorKind::Attribute,
                    "OverflowError" => ErrorKind::Overflow,
                    "OperationalError" => ErrorKind::Operational,
                    "ProgrammingError" => ErrorKind::Programming,
                    "IntegrityError" => ErrorKind::Integrity,
                    other => panic!("unmapped source exception {other}"),
                };
                assert_eq!(error.kind(), expected, "{name}");
                assert_eq!(
                    error.validation_message(),
                    case["validation"].as_str(),
                    "{name}"
                );
                assert_eq!(error.to_string(), "flow query failed");
            }
        }
    }
    assert_eq!(source["cases"].as_array().unwrap().len(), 32);
    assert_eq!(source["typed_cases"].as_array().unwrap().len(), 10);
    // Queries neither rewrite the authoritative owner nor repair unrelated
    // provenance; API direct-read authorization must inspect this NULL owner.
    let row = store.get_flow(8).unwrap().unwrap();
    assert_eq!(row["evidence_owner"], Value::Null);
    assert_eq!(row["agent_id"], "alice");
    drop(store);
    directory.close().unwrap();
}

#[test]
fn strict_normalization_does_not_become_lax_query_policy() {
    let directory = tempfile::tempdir().unwrap();
    let store = FlowStore::open(&directory.path().join("flows.db"), Settings::default()).unwrap();
    for (filters, message) in [
        (json!([]), "Search filters must be a JSON object"),
        (json!({"limit":0}), "limit must be at least 1"),
        (
            json!({"from_ts":2,"to_ts":1}),
            "from_ts must not exceed to_ts",
        ),
        (
            json!({"status_class":"1xx"}),
            "status_class must be one of: 2xx, 3xx, 4xx, 5xx",
        ),
        (
            json!({"limit":"1".repeat(4301)}),
            "limit must be an integer",
        ),
        (json!({"limit":"1__0"}), "limit must be an integer"),
    ] {
        assert_eq!(
            store
                .search_flows(&CircuitValue::from(filters))
                .unwrap_err()
                .validation_message(),
            Some(message)
        );
    }
    // Lax min() runs before SQLite parameter binding, as in source. This is an
    // error-order control: eagerly binding agent_id would report Programming.
    assert_eq!(
        store
            .get_endpoints(&CircuitValue::from(json!({"agent_id":[], "limit":"2"})))
            .unwrap_err()
            .kind(),
        ErrorKind::Type
    );
    assert_eq!(
        store
            .search_bodies(&CircuitValue::from(json!({"query":["truthy"]})))
            .unwrap(),
        json!([])
    );
}

#[test]
#[ignore = "requires the pinned source Python environment; no network"]
fn actual_source_query_oracle_still_matches() {
    let python = std::env::var("SAFEYOLO_SOURCE_PYTHON").expect("set SAFEYOLO_SOURCE_PYTHON");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = std::process::Command::new(python)
        .arg(root.join("tests/flow_store_query_oracle.py"))
        .arg("--check")
        .arg(root.join("tests/flow_store_query_source.json"))
        .status()
        .unwrap();
    assert!(status.success());
}
