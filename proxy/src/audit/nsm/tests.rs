use super::*;
use crate::{
    audit::{
        Attribution, AttributionStatus, Decision, Event, Initiator, Kind, Settings, Severity,
        Writer, parse_record,
    },
    policy::{Format, Policy},
    request_logger::{Exchange, PrettyUrl, Request, RequestLogger, Response},
};
use serde_json::json;
use std::{collections::HashSet, time::Duration};

fn attribution() -> Attribution {
    Attribution {
        evidence_owner: Some("alice".into()),
        trusted_transport_identity: Some("alice".into()),
        initiator: Some(Initiator::Unknown),
        status: Some(AttributionStatus::Resolved),
        provenance: Some(json!({"transport_source":"uds","uds_agent":"alice"}).into()),
    }
}

fn connection(id: &str, upstream: bool) -> Event {
    let mut event = Event::new(
        "network.connection",
        Kind::Network,
        Severity::Low,
        "Connection observed",
    );
    event.attribution = Some(attribution());
    event.details = json!({
        "instance_id":"instance-a", "runtime_id":"runtime-1", "connection_id":id,
        "leg":if upstream {"proxy_to_upstream"} else {"client_to_proxy"},
        "transport":if upstream {"tcp"} else {"unix"},
        "started_at":"2026-10-27T12:00:00Z", "ended_at":null, "state":"open",
        "local_endpoint":if upstream {json!({"type":"ip","address":"127.0.0.1:45000"})}
            else {json!({"type":"unix","path":"/run/alice.sock"})},
        "remote_endpoint":if upstream {json!({"type":"ip","address":"203.0.113.10:443"})}
            else {Value::Null},
        "requested_target":if upstream {Some("example.com:443")} else {None},
        "resolved_peer":if upstream {Some("203.0.113.10:443")} else {None},
        "ingress":"agent-uds"
    })
    .into();
    event
}

fn flow(id: &str) -> Event {
    let mut event = Event::new(
        "traffic.flow",
        Kind::Traffic,
        Severity::Low,
        "Transaction observed",
    );
    event.request_id = Some(id.into());
    event.attribution = Some(attribution());
    event.details = json!({"instance_id":"instance-a","runtime_id":"runtime-1",
        "client_connection_id":"C1","server_connection_id":"S1"})
    .into();
    event
}

fn indicator() -> Event {
    let mut event = Event::new(
        "security.indicator",
        Kind::Security,
        Severity::Medium,
        "Sensor indication",
    );
    event.request_id = Some("F1".into());
    event.attribution = Some(attribution());
    event.details = json!({"instance_id":"instance-a","runtime_id":"runtime-1",
        "indicator_type":"fixture","sensor":"fixture","rule":"fixture.v1","confidence":0.4,
        "connection_id":"S1","direction":"server_to_client",
        "evidence_hash":format!("sha256:{}", "a".repeat(64))})
    .into();
    event
}

fn record(event: Event) -> Value {
    let line = event.record(OffsetDateTime::UNIX_EPOCH).encode().unwrap();
    parse_record(&line).unwrap()
}

#[test]
fn writer_and_reader_preserve_namespace_and_many_to_one_correlation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let writer = Writer::new(path.clone(), Settings::default()).with_named_controls(true);
    let mut unscoped = Event::new(
        "traffic.request",
        Kind::Traffic,
        Severity::Low,
        "Unscoped request",
    );
    unscoped.request_id = Some("F1".into());
    writer.emit(unscoped).unwrap();
    for (instance, runtime) in [
        ("instance-a", "runtime-1"),
        ("instance-b", "runtime-1"),
        ("instance-a", "runtime-2"),
    ] {
        for mut event in [
            connection("C1", false),
            connection("S1", true),
            flow("F1"),
            flow("F2"),
            indicator(),
        ] {
            let mut details = event.details.json().unwrap();
            details["instance_id"] = json!(instance);
            details["runtime_id"] = json!(runtime);
            // Untrusted payload fields cannot replace the trust snapshot.
            details["attribution"] = json!({"evidence_owner":"forged","initiator":"agent"});
            event.details = details.into();
            event.addon = Some("fixture".into());
            writer.emit(event).unwrap();
        }
    }
    assert!(writer.shutdown(Duration::from_secs(3)).unwrap());
    let rows: Vec<_> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| parse_record(line).unwrap())
        .collect();
    assert_eq!(rows[0]["schema_version"], 2);
    assert!(!super::is_scoped(&rows[0]));
    let connections: HashSet<_> = rows
        .iter()
        .filter(|row| row["event"] == "network.connection")
        .map(|row| {
            (
                row["details"]["instance_id"].clone(),
                row["details"]["runtime_id"].clone(),
                row["details"]["connection_id"].clone(),
            )
        })
        .collect();
    assert_eq!(connections.len(), 6);
    let mut requests = HashSet::new();
    for row in &rows[1..] {
        assert_eq!(row["schema_version"], 2);
        assert_eq!(row["control"], "fixture");
        assert!(row.get("attribution").is_none());
        let details = &row["details"];
        assert_eq!(details["attribution"]["evidence_owner"], "alice");
        assert_eq!(
            details["attribution"]["trusted_transport_identity"],
            "alice"
        );
        assert_eq!(details["attribution"]["initiator"], "unknown");
        assert_eq!(details["attribution"]["attribution_status"], "resolved");
        assert_eq!(
            details["attribution"]["attribution_provenance"]["transport_source"],
            "uds"
        );
        if row["event"] == "traffic.flow" {
            for field in ["client_connection_id", "server_connection_id"] {
                assert!(connections.contains(&(
                    details["instance_id"].clone(),
                    details["runtime_id"].clone(),
                    details[field].clone()
                )));
            }
            assert!(requests.insert((
                details["instance_id"].clone(),
                details["runtime_id"].clone(),
                row["request_id"].clone()
            )));
        } else if row["event"] == "security.indicator" {
            assert!(connections.contains(&(
                details["instance_id"].clone(),
                details["runtime_id"].clone(),
                details["connection_id"].clone(),
            )));
            assert!(requests.contains(&(
                details["instance_id"].clone(),
                details["runtime_id"].clone(),
                row["request_id"].clone(),
            )));
        }
    }
    assert_eq!(requests.len(), 6);
    assert_eq!(rows[2]["details"]["requested_target"], "example.com:443");
    assert_eq!(rows[2]["details"]["resolved_peer"], "203.0.113.10:443");
}

#[test]
fn strict_versions_kinds_payloads_and_content_boundaries() {
    let connection = record(connection("C1", false));
    let upstream = record(self::connection("S1", true));
    let flow = record(flow("F1"));
    let indicator = record(indicator());
    for mut invalid_record in [connection.clone(), flow.clone(), indicator.clone()] {
        invalid_record["schema_version"] = json!(1);
        assert!(parse_record(&invalid_record.to_string()).is_err());
        invalid_record["schema_version"] = json!(99);
        assert!(parse_record(&invalid_record.to_string()).is_err());
        invalid_record["schema_version"] = json!(2);
        invalid_record["kind"] = json!("ops");
        assert!(parse_record(&invalid_record.to_string()).is_err());
    }
    for (base, pointer, value) in [
        (&connection, "/details/instance_id", json!("")),
        (&connection, "/details/runtime_id", Value::Null),
        (&connection, "/details/connection_id", json!("")),
        (&connection, "/details/leg", json!("unknown")),
        (&connection, "/details/transport", json!("quic")),
        (&connection, "/details/started_at", json!("yesterday")),
        (
            &connection,
            "/details/ended_at",
            json!("2026-10-27T11:00:00Z"),
        ),
        (&connection, "/details/state", json!("closed")),
        (&connection, "/details/ingress", json!("")),
        (&connection, "/ts", json!("yesterday")),
        (&upstream, "/details/transport", json!("unix")),
        (
            &upstream,
            "/details/resolved_peer",
            json!("example.com:443"),
        ),
        (
            &upstream,
            "/details/resolved_peer",
            json!("203.0.113.11:443"),
        ),
        (&flow, "/request_id", json!("")),
        (&flow, "/details/client_connection_id", Value::Null),
        (&flow, "/details/server_connection_id", json!("")),
        (&indicator, "/details/confidence", json!(1.1)),
        (&indicator, "/details/confidence", json!(-0.1)),
        (&indicator, "/details/sensor", json!("")),
        (&indicator, "/details/rule", json!("")),
        (&indicator, "/details/direction", json!("inbound")),
        (&indicator, "/details/evidence_hash", json!("raw content")),
    ] {
        let mut changed = base.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            parse_record(&changed.to_string()).is_err(),
            "accepted {pointer}"
        );
    }
    for field in ["body", "matched_text", "certificate", "headers"] {
        let mut changed = indicator.clone();
        changed["details"][field] = json!("private content");
        assert!(parse_record(&changed.to_string()).is_err());
        changed = indicator.clone();
        changed[field] = json!("private content");
        assert!(parse_record(&changed.to_string()).is_err());
    }
    let mut changed = indicator;
    changed["decision"] = json!("deny");
    assert!(parse_record(&changed.to_string()).is_err());
    changed.as_object_mut().unwrap().remove("decision");
    changed["approval"] = json!({"required":true});
    assert!(parse_record(&changed.to_string()).is_err());
    let mut invalid_event = self::indicator();
    invalid_event.decision = Some(Decision::Deny);
    // Invalid source data becomes a distinct current diagnostic, never NSM evidence.
    assert_eq!(
        record(invalid_event)["event"],
        "ops.audit_validation_failed"
    );
    let mut wrong_kind = self::connection("C1", false);
    wrong_kind.kind = Kind::Traffic;
    assert_eq!(record(wrong_kind)["event"], "ops.audit_validation_failed");
}

#[test]
fn indicator_content_metadata_is_typed_and_requires_hashed_evidence() {
    let mut row = record(indicator());
    row["details"]["content_type"] = json!("text/plain");
    row["details"]["inspected_bytes"] = json!(65536);
    row["details"]["prefix_truncated"] = json!(true);
    row["details"]["source"] = json!({
        "request_id":"source-flow", "connection_id":"source-connection", "host":"source.invalid",
        "evidence_hash":format!("sha256:{}", "b".repeat(64)),
        "matched_fingerprints":8, "source_fingerprints":12,
    });
    assert!(parse_record(&row.to_string()).is_ok());
    for (field, value) in [
        ("content_type", json!("x".repeat(129))),
        ("content_type", json!("")),
        ("inspected_bytes", json!(-1)),
        ("prefix_truncated", json!("true")),
        ("evidence_hash", Value::Null),
    ] {
        let mut invalid = row.clone();
        invalid["details"][field] = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{field}");
    }
    for (field, value) in [
        ("request_id", json!("")),
        ("evidence_hash", json!("raw content")),
        ("matched_fingerprints", json!(0)),
        ("matched_fingerprints", json!(13)),
        ("body", json!("private source content")),
    ] {
        let mut invalid = row.clone();
        invalid["details"]["source"][field] = value;
        assert!(
            parse_record(&invalid.to_string()).is_err(),
            "source {field}"
        );
    }
}

#[test]
fn novelty_links_are_typed_scoped_metadata_and_require_comparable_changes() {
    let mut row = record(indicator());
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "destination":"origin.invalid:443", "route":"direct", "verification_name":null,
        "current":{"connection_id":"S1","event_id":"observation-1", "cert_sha256":null,"spki_sha256":null},
        "previous":null,
    });
    assert!(parse_record(&row.to_string()).is_ok());
    for (pointer, value) in [
        ("/history_scope", json!("all_time")),
        ("/history_capacity", json!(0)),
        ("/history_capacity", json!(4097)),
        ("/destination", json!("")),
        ("/route", json!("unknown")),
        ("/current/connection_id", json!("unrelated")),
        ("/current/event_id", json!("")),
        ("/current/cert_sha256", json!("raw certificate")),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    row["details"]["novelty"]["verification_name"] = json!("origin.invalid");
    row["details"]["novelty"]["previous"] = json!({
        "connection_id":"S0","event_id":"observation-0", "cert_sha256":"a".repeat(64),"spki_sha256":"b".repeat(64),
    });
    row["details"]["novelty"]["current"]["cert_sha256"] = json!("c".repeat(64));
    assert!(
        parse_record(&row.to_string()).is_ok(),
        "a certificate change can have unknown SPKI"
    );
    for (pointer, value) in [
        ("/previous/cert_sha256", Value::Null),
        ("/current/cert_sha256", json!("a".repeat(64))),
        ("/previous/event_id", json!("observation-1")),
        ("/verification_name", Value::Null),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    row["details"]["novelty"]["current"]["body"] = json!("private payload");
    assert!(parse_record(&row.to_string()).is_err());
}

#[test]
fn negotiation_changes_require_two_measured_bounded_results() {
    let mut row = record(indicator());
    row["details"]["indicator_type"] = json!("tls_negotiation_change");
    row["details"]["sensor"] = json!("connection-history.v1");
    row["details"]["rule"] = json!("tls.origin_negotiation_changed.v1");
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "destination":"origin.invalid:443", "route":"direct", "verification_name":"origin.invalid",
        "current":{"connection_id":"S1","event_id":"observation-1",
            "negotiation":{"version":"TLSv1_3","alpn":"http/1.1"}},
        "previous":{"connection_id":"S0","event_id":"observation-0",
            "negotiation":{"version":"TLSv1_3","alpn":null}},
    });
    assert!(
        parse_record(&row.to_string()).is_ok(),
        "observed no-ALPN differs from a negotiated protocol"
    );
    for (pointer, value) in [
        ("/current/negotiation/version", Value::Null),
        ("/current/negotiation/version", json!("")),
        ("/current/negotiation/version", json!("x".repeat(1025))),
        ("/current/negotiation/alpn", json!("x".repeat(1025))),
        ("/current/negotiation/alpn", Value::Null),
        ("/previous/negotiation", Value::Null),
        ("/previous/event_id", json!("observation-1")),
        ("/verification_name", Value::Null),
        ("/previous", Value::Null),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for observation in ["current", "previous"] {
        let mut mixed = row.clone();
        mixed["details"]["novelty"][observation]["cert_sha256"] = json!("a".repeat(64));
        assert!(
            parse_record(&mixed.to_string()).is_err(),
            "certificate and negotiation evidence stay separate"
        );
        let mut unknown = row.clone();
        unknown["details"]["novelty"][observation]["negotiation"]["body"] =
            json!("private payload");
        assert!(parse_record(&unknown.to_string()).is_err());
    }
    row["details"]["novelty"]["current"]["negotiation"] = json!({"version":"TLSv1_2","alpn":null});
    assert!(
        parse_record(&row.to_string()).is_ok(),
        "a version change needs no ALPN protocol"
    );
}

#[test]
fn native_route_facts_keep_origin_and_physical_peer_distinct() {
    let mut upstream = record(connection("S1", true));
    upstream["details"]["client_connection_id"] = json!("C1");
    upstream["details"]["route"] = json!("direct");
    upstream["details"]["resolved_origin_peer"] = upstream["details"]["resolved_peer"].clone();
    upstream["details"]["tls_server_name"] = json!("example.com");
    assert!(parse_record(&upstream.to_string()).is_ok());
    for (field, value) in [
        ("resolved_origin_peer", json!("203.0.113.11:443")),
        ("client_connection_id", json!("")),
        ("route", json!("guess")),
        ("tls_server_name", json!("")),
    ] {
        let mut invalid = upstream.clone();
        invalid["details"][field] = value;
        assert!(
            parse_record(&invalid.to_string()).is_err(),
            "accepted {field}"
        );
    }
    upstream["details"]["route"] = json!("parent");
    assert!(
        parse_record(&upstream.to_string()).is_err(),
        "parent is not a directly observed origin"
    );
    upstream["details"]["resolved_origin_peer"] = Value::Null;
    assert!(parse_record(&upstream.to_string()).is_ok());
    upstream["details"]["route"] = json!("provider");
    upstream["details"]["transport"] = json!("stream");
    assert!(
        parse_record(&upstream.to_string()).is_err(),
        "opaque stream cannot claim a TCP endpoint"
    );
    upstream["details"]["local_endpoint"] = Value::Null;
    upstream["details"]["remote_endpoint"] = Value::Null;
    upstream["details"]["resolved_peer"] = Value::Null;
    assert!(parse_record(&upstream.to_string()).is_ok());
}

#[test]
fn tls_updates_keep_the_connection_key_and_reject_raw_or_unbounded_content() {
    let mut client = record(connection("C1", false));
    client["details"]["state"] = json!("updated");
    client["details"]["tls_client_hello"] = json!({
        "ja3":"ada70206e40642a3e4461f35503241d5",
        "ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1",
        "sni":"example.com","alpn_offers":["h2"],"legacy_version":771,
        "supported_versions":[772,771],"cipher_suites":[4865],"cipher_suite_count":1,
        "extension_types":[0,16],"extension_count":2,"truncated":false
    });
    assert!(parse_record(&client.to_string()).is_ok());
    for (field, value) in [
        ("raw_client_hello", json!("not permitted")),
        ("sni", json!("a".repeat(254))),
        ("alpn_offers", json!(vec!["h2"; 17])),
    ] {
        let mut invalid = client.clone();
        invalid["details"]["tls_client_hello"][field] = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{field}");
    }
    let mut invalid = client.clone();
    invalid["details"]["ended_at"] = json!("2026-10-27T12:00:01Z");
    assert!(parse_record(&invalid.to_string()).is_err());
    let mut upstream = record(connection("S1", true));
    upstream["details"]["tls_sessions"] = json!([{"peer":"origin","sni":"example.com",
        "version":"TLSv1_3","cipher":null,"alpn":null,"handshake_kind":"Full","leaf_certificate":null}]);
    assert!(parse_record(&upstream.to_string()).is_ok());
    upstream["details"]["tls_sessions"][0]["certificate_der"] = json!("not permitted");
    assert!(parse_record(&upstream.to_string()).is_err());
}

#[test]
fn server_hello_schema_retains_status_and_rejects_raw_or_inconsistent_evidence() {
    let mut upstream = record(connection("S1", true));
    let hello = json!({"legacy_version":771,"supported_version":772,"alpn":null,
        "cipher_suite":4865,"extension_types":[43,51],"extension_count":2,"truncated":false,
        "ja3s":"f4febc55ea12b31ae17cfb7e614afda8","ja4s":"t130200_1301_234ea6891581"});
    upstream["details"]["tls_server_hello"] =
        json!({"status":"complete","hello":hello,"hello_retry_request":null});
    assert!(parse_record(&upstream.to_string()).is_ok());
    for (pointer, value) in [
        ("/details/leg", json!("client_to_proxy")),
        ("/details/tls_server_hello/raw_bytes", json!([1, 2, 3])),
        ("/details/tls_server_hello/status", json!("invented")),
        ("/details/tls_server_hello/status", json!("incomplete")),
        ("/details/tls_server_hello/hello", Value::Null),
        ("/details/tls_server_hello/hello/extension_count", json!(1)),
        (
            "/details/tls_server_hello/hello/extension_types",
            json!(vec![43; 65]),
        ),
        ("/details/tls_server_hello/hello/truncated", json!(true)),
        (
            "/details/tls_server_hello/hello/alpn",
            json!("a".repeat(1021)),
        ),
        (
            "/details/tls_server_hello/hello/supported_version",
            json!(65536),
        ),
        (
            "/details/tls_server_hello/hello/ja4s",
            json!("not a fingerprint"),
        ),
        (
            "/details/tls_server_hello/hello/ja4s",
            json!("t120200_1301_234ea6891581"),
        ),
        (
            "/details/tls_server_hello/hello/ja4s",
            json!("t130200_1302_234ea6891581"),
        ),
        (
            "/details/tls_server_hello/hello/ja4s",
            json!("t130200_1301_234EA6891581"),
        ),
        (
            "/details/tls_server_hello/hello/ja4s",
            json!("t130200_1301_234ea689158é"),
        ),
        (
            "/details/tls_server_hello/hello/ja3s",
            json!("not a digest"),
        ),
        (
            "/details/tls_server_hello/hello/extension_payloads",
            json!([]),
        ),
    ] {
        let mut invalid = upstream.clone();
        // Unknown fields must be inserted explicitly; JSON pointers only select
        // existing values.
        if let Some(slot) = invalid.pointer_mut(pointer) {
            *slot = value;
        } else if pointer.ends_with("raw_bytes") {
            invalid["details"]["tls_server_hello"]["raw_bytes"] = value;
        } else {
            invalid["details"]["tls_server_hello"]["hello"]["extension_payloads"] = value;
        }
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for status in ["incomplete", "invalid", "unavailable", "limit_exceeded"] {
        upstream["details"]["tls_server_hello"] =
            json!({"status":status,"hello":null,"hello_retry_request":hello});
        assert!(parse_record(&upstream.to_string()).is_ok());
    }
    // A connection with no recorded ServerHello observation remains representable.
    upstream["details"]
        .as_object_mut()
        .unwrap()
        .remove("tls_server_hello");
    assert!(parse_record(&upstream.to_string()).is_ok());
}

#[test]
fn unknown_observations_external_ingress_and_terminal_states_are_representable() {
    let mut external = connection("external-C1", false);
    external.attribution = Some(Attribution {
        initiator: Some(Initiator::External),
        status: Some(AttributionStatus::Unavailable),
        ..Attribution::default()
    });
    let mut details = external.details.json().unwrap();
    details["ingress"] = json!("switchboard/mobile-test");
    details["remote_endpoint"] = json!({"type":"unix","path":null});
    external.details = details.into();
    let external = record(external);
    assert_eq!(external["details"]["attribution"]["initiator"], "external");
    assert!(
        external["details"]["attribution"]
            .get("trusted_transport_identity")
            .is_none()
    );
    for state in ["closed", "failed"] {
        let mut event = connection("S1", true);
        let mut details = event.details.json().unwrap();
        details["state"] = json!(state);
        details["ended_at"] = json!("2026-10-27T12:00:01Z");
        details["error"] = json!("connection_reset");
        if state == "failed" {
            details["resolved_peer"] = Value::Null;
            details["local_endpoint"] = Value::Null;
            details["remote_endpoint"] = Value::Null;
        }
        event.details = details.into();
        assert_eq!(record(event)["schema_version"], 2);
    }
    let mut event = flow("local-response");
    let mut details = event.details.json().unwrap();
    details["server_connection_id"] = Value::Null;
    event.details = details.into();
    assert_eq!(record(event)["schema_version"], 2);
    let mut event = indicator();
    event.request_id = None;
    event.details = json!({"instance_id":"instance-a","runtime_id":"runtime-1",
        "indicator_type":"fixture","sensor":"fixture","rule":"fixture.v1","confidence":0.0})
    .into();
    assert_eq!(record(event)["schema_version"], 2);
}

#[test]
fn quiet_hosts_suppresses_verbose_transactions_but_not_sparse_connections() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let writer = Writer::new(path.clone(), Settings::default());
    let policy = Policy::parse_at(
        r#"{"addons":{"request_logger":{"quiet_hosts":{"hosts":["quiet.invalid"]}}}}"#,
        Format::Json,
        0.,
    )
    .unwrap();
    let logger = RequestLogger::default();
    let mut exchange = Exchange::new(attribution(), Some("alice".into()));
    let request = Request {
        method: "GET",
        parsed: Ok(PrettyUrl {
            host: "quiet.invalid",
            path: "/",
        }),
        request_id: Some("F1"),
        client: None,
    };
    logger
        .request(
            Some(&policy),
            &mut exchange,
            &request,
            || panic!("quiet request must not inspect content"),
            &writer,
        )
        .unwrap();
    logger
        .response(
            &exchange,
            &request,
            &Response {
                status: Some(200),
                start_time: None,
                now: 0.,
                blocked_by: None,
                block_reason: None,
                credential_fingerprint: None,
                attribution_quarantined: false,
            },
            || panic!("quiet response must not inspect content"),
            &writer,
        )
        .unwrap();
    writer.emit(connection("C1", false)).unwrap();
    writer.emit(connection("S1", true)).unwrap();
    assert!(writer.shutdown(Duration::from_secs(3)).unwrap());
    let rows: Vec<_> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| parse_record(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row["event"] == "network.connection" && row["schema_version"] == 2)
    );
    assert_eq!(logger.stats().unwrap().requests_quieted, 1.into());
}

#[test]
fn client_fingerprint_evidence_requires_measured_changes_and_excludes_other_scopes() {
    let mut row = record(indicator());
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "verification_name":null,
        "current":{"connection_id":"S1","event_id":"client-1", "cert_sha256":null,"spki_sha256":null,
            "client_fingerprint":{"ja3":"a".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}},
        "previous":null,
    });
    assert!(parse_record(&row.to_string()).is_ok());
    row["details"]["novelty"]["previous"] = json!({
        "connection_id":"C0","event_id":"client-0", "cert_sha256":null,"spki_sha256":null,
        "client_fingerprint":{"ja3":"b".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"},
    });
    assert!(parse_record(&row.to_string()).is_ok());
    for (pointer, value) in [
        ("/current/client_fingerprint/ja3", json!("invalid")),
        ("/current/client_fingerprint/ja4", json!("")),
        ("/previous/client_fingerprint", Value::Null),
        ("/previous/client_fingerprint/ja3", json!("a".repeat(32))),
        ("/previous/event_id", json!("client-1")),
        ("/current/connection_id", json!("unrelated")),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for (field, value) in [
        ("destination", json!("origin.invalid:443")),
        ("route", json!("direct")),
        ("verification_name", json!("origin.invalid")),
    ] {
        let mut mixed = row.clone();
        mixed["details"]["novelty"][field] = value;
        assert!(parse_record(&mixed.to_string()).is_err());
    }
    for observation in ["previous", "current"] {
        for (field, value) in [
            ("cert_sha256", json!("c".repeat(64))),
            ("negotiation", json!({"version":"TLSv1_3","alpn":null})),
        ] {
            let mut mixed = row.clone();
            mixed["details"]["novelty"][observation][field] = value;
            assert!(parse_record(&mixed.to_string()).is_err());
        }
        let mut unknown = row.clone();
        unknown["details"]["novelty"][observation]["client_fingerprint"]["body"] =
            json!("private payload");
        assert!(parse_record(&unknown.to_string()).is_err());
    }
}

#[test]
fn origin_spki_ip_evidence_requires_the_same_measured_key_on_distinct_ips() {
    let mut row = record(indicator());
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "destination":"origin.invalid:443", "route":"direct", "verification_name":"origin.invalid",
        "current":{"connection_id":"S1","event_id":"origin-1", "cert_sha256":"a".repeat(64),"spki_sha256":"b".repeat(64),"origin_ip":"192.0.2.2"},
        "previous":{"connection_id":"S0","event_id":"origin-0", "cert_sha256":"c".repeat(64),"spki_sha256":"b".repeat(64),"origin_ip":"2001:db8::1"},
    });
    assert!(parse_record(&row.to_string()).is_ok());
    for (pointer, value) in [
        ("/current/origin_ip", json!("origin.invalid")),
        ("/current/origin_ip", json!("192.0.2.2:443")),
        ("/previous/origin_ip", json!("192.0.2.2")),
        ("/previous/origin_ip", json!("::ffff:192.0.2.2")),
        ("/previous/origin_ip", Value::Null),
        ("/current/origin_ip", Value::Null),
        ("/current/spki_sha256", Value::Null),
        ("/previous/spki_sha256", Value::Null),
        ("/previous/spki_sha256", json!("d".repeat(64))),
        ("/previous/cert_sha256", Value::Null),
        ("/current/cert_sha256", Value::Null),
        ("/previous/event_id", json!("origin-1")),
        ("/verification_name", Value::Null),
        ("/previous", Value::Null),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for observation in ["previous", "current"] {
        for (field, value) in [
            ("negotiation", json!({"version":"TLSv1_3","alpn":null})),
            (
                "client_fingerprint",
                json!({"ja3":"a".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}),
            ),
            ("body", json!("private payload")),
        ] {
            let mut mixed = row.clone();
            mixed["details"]["novelty"][observation][field] = value;
            assert!(parse_record(&mixed.to_string()).is_err());
        }
    }
}

#[test]
fn origin_ip_evidence_accepts_transport_without_mixing_certificate_or_client_scopes() {
    let mut row = record(indicator());
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "verification_name":null, "previous":null,
        "current":{"connection_id":"S1","event_id":"origin-1", "cert_sha256":null,"spki_sha256":null,"origin_ip":"192.0.2.2"}
    });
    for ip in ["192.0.2.2", "2001:db8::1", "::ffff:192.0.2.2"] {
        row["details"]["novelty"]["current"]["origin_ip"] = json!(ip);
        assert!(parse_record(&row.to_string()).is_ok());
    }
    for (pointer, value) in [
        ("/current/origin_ip", json!("origin.invalid")),
        ("/current/origin_ip", json!("192.0.2.2:443")),
        ("/current/origin_ip", Value::Null),
        ("/current/connection_id", json!("other")),
        ("/current/event_id", json!("")),
        ("/current/cert_sha256", json!("a".repeat(64))),
        ("/current/spki_sha256", json!("b".repeat(64))),
        ("/verification_name", json!("origin.invalid")),
        ("/previous", row["details"]["novelty"]["current"].clone()),
        ("/history_capacity", json!(4097)),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for (field, value) in [
        ("destination", json!("origin.invalid:443")),
        ("route", json!("direct")),
        ("client", row["details"]["novelty"]["current"].clone()),
    ] {
        let mut invalid = row.clone();
        invalid["details"]["novelty"][field] = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{field}");
    }
    for (field, value) in [
        ("negotiation", json!({"version":"TLSv1_3","alpn":null})),
        (
            "client_fingerprint",
            json!({"ja3":"a".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}),
        ),
        ("body", json!("private payload")),
    ] {
        let mut invalid = row.clone();
        invalid["details"]["novelty"]["current"][field] = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{field}");
    }
}

#[test]
fn client_destination_evidence_links_separate_client_and_attempt_without_mixing_tls_scopes() {
    let mut row = record(indicator());
    row["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo", "history_capacity":4096,
        "destination":"origin.invalid:443", "route":"parent", "verification_name":null,
        "current":{"connection_id":"S1","event_id":"upstream-1","cert_sha256":null,"spki_sha256":null},
        "previous":null,
        "client":{"connection_id":"C1","event_id":"hello-1","cert_sha256":null,"spki_sha256":null,
            "client_fingerprint":{"ja3":"a".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}},
    });
    assert!(parse_record(&row.to_string()).is_ok());
    for (pointer, value) in [
        ("/client/event_id", json!("upstream-1")),
        ("/client/event_id", json!("")),
        ("/client/connection_id", json!("S1")),
        ("/client/client_fingerprint", Value::Null),
        ("/client/client_fingerprint/ja3", json!("invalid")),
        ("/client/cert_sha256", json!("a".repeat(64))),
        ("/current/cert_sha256", json!("a".repeat(64))),
        ("/route", Value::Null),
        ("/destination", Value::Null),
        ("/verification_name", json!("origin.invalid")),
    ] {
        let mut invalid = row.clone();
        *invalid["details"]["novelty"].pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(&invalid.to_string()).is_err(), "{pointer}");
    }
    for field in ["current", "previous"] {
        let mut mixed = row.clone();
        mixed["details"]["novelty"][field] = mixed["details"]["novelty"]["client"].clone();
        assert!(parse_record(&mixed.to_string()).is_err());
    }
    let mut payload = row;
    payload["details"]["novelty"]["client"]["body"] = json!("private");
    assert!(parse_record(&payload.to_string()).is_err());
}

#[test]
fn current_request_decisions_require_their_explicit_scope_for_nsm() {
    for name in [
        "security.network_guard",
        "security.credential_guard",
        "security.credential_guard.codex_refreshed",
        "gateway.allow",
        "gateway.deny",
        "gateway.refresh_failed",
        "gateway.https_redirect",
        "gateway.http_injection_allowed",
    ] {
        let gateway = name.starts_with("gateway.");
        let make = || {
            let mut event = Event::new(
                name,
                if gateway {
                    Kind::Gateway
                } else {
                    Kind::Security
                },
                Severity::Low,
                "Concrete decision",
            );
            event.agent = Some("alice".into());
            event.request_id = Some("F1".into());
            event.host = Some("origin.invalid".into());
            event.addon = Some(
                if gateway {
                    "service-gateway"
                } else if name == "security.network_guard" {
                    "network-guard"
                } else {
                    "credential-guard"
                }
                .into(),
            );
            event.decision = Some(Decision::Allow);
            event.attribution = Some(attribution());
            event.details =
                json!({"connection_id":"C1", "approval_id":"unrelated-control-id"}).into();
            event
        };
        let unscoped = record(make());
        assert_eq!(unscoped["schema_version"], 2);
        assert!(!super::is_scoped(&unscoped));
        let run = crate::host_runs::AgentRun {
            agent: "alice".into(),
            agent_id: "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            run_id: "0123456789abcdef0123456789abcdef".into(),
        };
        let mut event = make();
        event.bind_request_scope("instance-a", "runtime-1", "C1", Some(&run));
        // Later producer details cannot replace the native owner's snapshot.
        event.details = json!({"connection_id":"C1", "sandbox_run":{"run_id":"claimed"}}).into();
        let scoped = record(event);
        assert_eq!(scoped["schema_version"], 2);
        assert_eq!(scoped["details"]["client_connection_id"], "C1");
        assert_eq!(scoped["details"]["sandbox_run"], json!(run));
        let mut unavailable = make();
        unavailable.details = json!({"connection_id":"C1", "sandbox_run":run}).into();
        unavailable.bind_request_scope("instance-a", "runtime-1", "C1", None);
        assert!(record(unavailable)["details"].get("sandbox_run").is_none());
        for native in [false, true] {
            let mut row = scoped.clone();
            if native {
                let addon = row.as_object_mut().unwrap().remove("addon").unwrap();
                row["control"] = json!(crate::policy::native::control_label(
                    addon.as_str().unwrap()
                ));
            }
            parse_record(&row.to_string()).unwrap();
            for pointer in [
                "/request_id",
                "/event_id",
                "/host",
                "/details/instance_id",
                "/details/runtime_id",
                "/details/client_connection_id",
                "/decision",
                "/details/sandbox_run/agent",
                "/details/sandbox_run/agent_id",
                "/details/sandbox_run/run_id",
            ] {
                for value in [Value::Null, json!(""), json!(5)] {
                    let mut bad = row.clone();
                    *bad.pointer_mut(pointer).unwrap() = value;
                    assert!(parse_record(&bad.to_string()).is_err(), "{name}: {pointer}");
                }
            }
            let mut unknown = row.clone();
            unknown["event"] = json!(format!(
                "{}.unrelated_control",
                row["kind"].as_str().unwrap()
            ));
            assert!(parse_record(&unknown.to_string()).is_ok());
            assert!(!super::is_scoped(&unknown));
            let mut conflict = row.clone();
            conflict["details"]["connection_id"] = json!("another-client");
            if !gateway {
                assert!(parse_record(&conflict.to_string()).is_err());
            }
        }
    }
}

#[test]
fn scoped_guard_evaluations_keep_the_existing_outcome_and_policy_fields() {
    for network in [false, true] {
        let name = if network {
            "security.network_guard.evaluated"
        } else {
            "security.credential_guard.evaluated"
        };
        let mut event = Event::new(name, Kind::Security, Severity::Low, "Evaluation");
        event.request_id = Some("F1".into());
        event.host = Some("origin.invalid".into());
        event.details = json!({"connection_id":"C1", "outcome":"allowed", "pdp":{"effect":"allow"}, "evaluations":[]}).into();
        event.bind_request_scope("instance-a", "runtime-1", "C1", None);
        let value = record(event);
        assert!(value.get("decision").is_none());
        for (pointer, bad) in [
            ("/details/outcome", json!("injected")),
            (
                if network {
                    "/details/pdp"
                } else {
                    "/details/evaluations"
                },
                json!("malformed"),
            ),
        ] {
            let mut malformed = value.clone();
            *malformed.pointer_mut(pointer).unwrap() = bad;
            assert!(parse_record(&malformed.to_string()).is_err());
        }
        let mut bad = value.clone();
        bad["decision"] = json!("allow");
        assert!(parse_record(&bad.to_string()).is_err());
        assert_eq!(value["details"]["pdp"]["effect"], "allow");
    }
}
