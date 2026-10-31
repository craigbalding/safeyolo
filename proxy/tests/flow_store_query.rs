//! Current native SQLite selections over synthetic records and fixed expectations.
//! Fixtures contain only synthetic data; authorization is an API caller concern.

use safeyolo_proxy::circuits::CircuitValue;
use safeyolo_proxy::flow_store::{BodyInput, ErrorKind, FlowRecord, FlowStore, Settings};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("flow_store_query_cases.json")).unwrap()
}

#[test]
fn five_query_methods_preserve_native_rows_filters_order_and_errors() {
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    for record in fixture["records"].as_array().unwrap() {
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
    // Query-only setup: tags and an explicitly quarantined row. The records
    // supplied to record() above all have explicit evidence owners.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("INSERT INTO flow_tags(flow_id,tag,value,created_at) VALUES(1,'review','',1000),(2,'review','one:two',1000)", []).unwrap();
    connection
        .execute("UPDATE flows SET evidence_owner=NULL WHERE id=8", [])
        .unwrap();
    drop(connection);

    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(fixture["typed_cases"].as_array().unwrap())
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
        match case["error_kind"].as_str() {
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
            Some(kind) => {
                let error = result.expect_err(name);
                let expected = match kind {
                    "Value" => ErrorKind::Value,
                    "Type" => ErrorKind::Type,
                    "Attribute" => ErrorKind::Attribute,
                    "Overflow" => ErrorKind::Overflow,
                    "Operational" => ErrorKind::Operational,
                    "Programming" => ErrorKind::Programming,
                    "Integrity" => ErrorKind::Integrity,
                    other => panic!("unmapped contract error kind {other}"),
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
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 32);
    assert_eq!(fixture["typed_cases"].as_array().unwrap().len(), 10);
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
    // Lax min() runs before SQLite parameter binding. This is an
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
fn context_queries_keep_expect_and_ignore_search_only_request_id() {
    let directory = tempfile::tempdir().unwrap();
    let store = FlowStore::open(&directory.path().join("flows.db"), Settings::default()).unwrap();
    for (request_id, owner, expect) in [
        ("req-11111111111111111111111111111111", "alice", "allow"),
        ("req-22222222222222222222222222222222", "alice", "deny"),
        ("req-33333333333333333333333333333333", "bob", "deny"),
    ] {
        let metadata = json!({
            "request_id": request_id,
            "ts_start": 1000,
            "engagement_id": "owned-run",
            "agent_id": owner,
            "evidence_owner": owner,
            "expect": expect,
            "flow_state": "complete",
            "host": "example.invalid",
            "path": "/same",
            "method": "GET",
            "status_code": 200,
            "request_content_type": "text/plain",
            "response_content_type": "text/plain"
        });
        store
            .record(
                FlowRecord {
                    metadata: metadata.as_object().unwrap(),
                    request_body: Some(BodyInput::complete(b"needle request")),
                    response_body: Some(BodyInput::complete(b"needle response")),
                },
                1000,
            )
            .unwrap();
    }

    let filters = CircuitValue::from(json!({
        "engagement_id": "owned-run",
        "evidence_owner": "alice",
        "expect": "deny",
        "query": "needle"
    }));
    let with_request_id = CircuitValue::from(json!({
        "engagement_id": "owned-run",
        "evidence_owner": "alice",
        "expect": "deny",
        "request_id": "req-11111111111111111111111111111111",
        "query": "needle"
    }));
    for filters in [&filters, &with_request_id] {
        let endpoints = store.get_endpoints(filters).unwrap();
        assert_eq!(endpoints.as_array().unwrap().len(), 1);
        assert_eq!(endpoints[0]["count"], 1);
        for result in [
            store.search_bodies(filters).unwrap(),
            store.search_request_bodies(filters).unwrap(),
        ] {
            let rows = result.as_array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0]["request_id"],
                "req-22222222222222222222222222222222"
            );
        }
    }
    assert_eq!(
        store
            .search_flows(&CircuitValue::from(json!({
                "evidence_owner": "alice",
                "expect": "deny",
                "request_id": "req-11111111111111111111111111111111"
            })))
            .unwrap(),
        json!([])
    );
    assert_eq!(
        store
            .get_facets(&CircuitValue::from(
                json!({"request_id":"req-11111111111111111111111111111111"})
            ))
            .unwrap_err()
            .validation_message(),
        Some("unknown facet filter(s): request_id")
    );
}
