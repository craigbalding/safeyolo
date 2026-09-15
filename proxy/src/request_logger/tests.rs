use super::*;
use crate::{
    audit::{AttributionStatus, Initiator, Settings},
    policy::Format,
};
use serde_json::json;
use std::{cell::Cell, fs, path::PathBuf, time::Duration};

fn policy(value: Value) -> Policy {
    Policy::parse_at(&value.to_string(), Format::Json, 0.).unwrap()
}
fn quiet_policy(value: Value) -> Policy {
    policy(json!({"addons":{"request_logger":{"quiet_hosts":value}}}))
}
fn exchange() -> Exchange {
    Exchange::new(
        Attribution {
            evidence_owner: Some("alice".into()),
            trusted_transport_identity: Some("alice".into()),
            initiator: Some(Initiator::Unknown),
            status: Some(AttributionStatus::Resolved),
            provenance: Some(json!({"transport_source":"uds","uds_agent":"alice"}).into()),
        },
        Some("alice".into()),
    )
}
fn request() -> Request<'static> {
    Request {
        method: "POST",
        parsed: Ok(PrettyUrl {
            host: "audit.fixture.invalid",
            path: "/a",
        }),
        request_id: Some("req-00000000000000000000000000000001"),
        client: Some("192.0.2.10"),
    }
}
fn response() -> Response<'static> {
    Response {
        status: Some(201),
        start_time: Some(99.87655),
        now: 100.,
        blocked_by: None,
        block_reason: None,
        credential_fingerprint: None,
        attribution_quarantined: false,
    }
}
struct Sink {
    _dir: tempfile::TempDir,
    path: PathBuf,
    writer: Writer,
}
impl Sink {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Writer::new(path.clone(), Settings::default());
        Self {
            _dir: dir,
            path,
            writer,
        }
    }
    fn records(&self) -> Vec<Value> {
        assert!(self.writer.wait_for_drain(Duration::from_secs(3)).unwrap());
        fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        assert!(self.writer.shutdown(Duration::from_secs(3)).unwrap());
    }
}
fn source() -> Value {
    serde_json::from_str(include_str!("../../tests/request_logger_source.json")).unwrap()
}
fn error_name(error: Error) -> &'static str {
    match error.0 {
        ErrorKind::Type => "TypeError",
        ErrorKind::Attribute => "AttributeError",
        _ => panic!("unexpected {error:?}"),
    }
}

#[test]
fn borrowed_projection_and_reached_quiet_operations_match_source() {
    for row in source()["quiet"].as_array().unwrap() {
        let format = match row["format"].as_str().unwrap() {
            "json" => Format::Json,
            "toml" => Format::Toml,
            "yaml" => Format::Yaml,
            _ => unreachable!(),
        };
        let policy = Policy::parse_at(row["source"].as_str().unwrap(), format, 0.).unwrap();
        let hash = policy.policy_hash();
        let budgets = policy.budget_stats(0.).unwrap();
        assert_eq!(
            policy.request_logger_settings().hash(),
            row["hash"].as_str().unwrap(),
            "{}",
            row["case"]
        );
        match quiet::Quiet::load(&policy) {
            Err(quiet::LoadError::Malformed(message)) => {
                assert_eq!(row["load_error"], "ValueError", "{}", row["case"]);
                assert_eq!(
                    sanitize(&message),
                    row["message"].as_str().unwrap(),
                    "{}",
                    row["case"]
                );
            }
            Err(quiet::LoadError::Reached(error)) => assert_eq!(
                error_name(error),
                row["load_error"].as_str().unwrap(),
                "{}",
                row["case"]
            ),
            Ok(quiet) => {
                assert!(row["load_error"].is_null(), "{}", row["case"]);
                match quiet.matches(row["host"].as_str().unwrap(), row["path"].as_str().unwrap()) {
                    Ok(matched) => {
                        assert_eq!(Value::Bool(matched), row["quiet"], "{}", row["case"])
                    }
                    Err(error) => assert_eq!(
                        error_name(error),
                        row["match_error"].as_str().unwrap(),
                        "{}",
                        row["case"]
                    ),
                }
            }
        }
        assert_eq!(policy.policy_hash(), hash);
        assert_eq!(policy.budget_stats(0.).unwrap(), budgets);
    }
}
#[test]
fn source_decimal_duration_and_sanitizer_controls() {
    let source = source();
    for row in source["durations"].as_array().unwrap() {
        let actual = duration(row["start"].as_f64(), row["now"].as_f64().unwrap());
        assert_eq!(
            actual.map(f64::to_bits),
            row["value"].as_f64().map(f64::to_bits)
        );
    }
    for row in source["sanitize"].as_array().unwrap() {
        assert_eq!(
            sanitize(row["input"].as_str().unwrap()),
            row["output"].as_str().unwrap()
        );
    }
}

#[test]
fn source_hook_sequence_counters_config_latch_and_exact_event_fields() {
    let sink = Sink::new();
    let logger = RequestLogger::default();
    let request = request();
    let source: Value =
        serde_json::from_str(include_str!("../../tests/request_logger_hook_source.json")).unwrap();
    let rows = source["rows"].as_array().unwrap();
    let mut offset = 0;
    let mut verify = |index: usize, error: Option<Error>| {
        let row = &rows[index];
        let actual = error.map(|error| match error.0 {
            ErrorKind::Decode => "ValueError",
            _ => error_name(error),
        });
        assert_eq!(actual, row["error"].as_str(), "{}", row["case"]);
        assert_eq!(
            logger.stats().unwrap().document().json().unwrap(),
            row["stats"],
            "{}",
            row["case"]
        );
        let events = sink.records();
        let observed: Vec<_> = events[offset..]
            .iter()
            .cloned()
            .map(|mut event| {
                event["ts"] = json!("2026-01-02T03:04:05.123456Z");
                event
            })
            .collect();
        // Only runtime timestamp is normalized. Object field order and all
        // payload fields remain compared through the Python JSON formatter.
        assert_eq!(
            crate::python_json::encode(&Value::Array(observed)),
            crate::python_json::encode(&row["events"]),
            "{}",
            row["case"]
        );
        offset = events.len();
    };
    let mut first = exchange();
    verify(
        0,
        logger
            .request(
                Some(&Policy::unconfigured()),
                &mut first,
                &request,
                || Ok(7),
                &sink.writer,
            )
            .err(),
    );
    let one = quiet_policy(json!({"hosts":["audit.fixture.invalid"]}));
    let mut second = exchange();
    verify(
        1,
        logger
            .request(
                Some(&one),
                &mut second,
                &request,
                || panic!("quiet decode"),
                &sink.writer,
            )
            .err(),
    );
    assert!(second.quieted());
    verify(
        2,
        logger
            .response(
                &second,
                &request,
                &response(),
                || panic!("quiet response"),
                &sink.writer,
            )
            .err(),
    );
    let blocked = text("network-guard");
    let reason = text("synthetic denial");
    let fingerprint = text("fixture-fingerprint");
    let block = Response {
        blocked_by: Some(&blocked),
        block_reason: Some(&reason),
        credential_fingerprint: Some(&fingerprint),
        ..response()
    };
    verify(
        3,
        logger
            .response(&second, &request, &block, || Ok(8), &sink.writer)
            .err(),
    );
    let two = quiet_policy(json!({"hosts":"bad"}));
    verify(
        4,
        logger
            .request(
                Some(&two),
                &mut exchange(),
                &request,
                || panic!("retained quiet"),
                &sink.writer,
            )
            .err(),
    );
    verify(
        5,
        logger
            .request(
                Some(&two),
                &mut exchange(),
                &request,
                || panic!("retained quiet"),
                &sink.writer,
            )
            .err(),
    );
    let three = quiet_policy(json!({"hosts":[1]}));
    verify(
        6,
        logger
            .request(
                Some(&three),
                &mut exchange(),
                &request,
                || panic!("type error"),
                &sink.writer,
            )
            .err(),
    );
    verify(
        7,
        logger
            .request(
                Some(&three),
                &mut exchange(),
                &request,
                || panic!("retained quiet"),
                &sink.writer,
            )
            .err(),
    );
    let four = quiet_policy(json!({"paths":{"audit.fixture.invalid":[1]}}));
    verify(
        8,
        logger
            .request(
                Some(&four),
                &mut exchange(),
                &request,
                || panic!("lazy type error"),
                &sink.writer,
            )
            .err(),
    );
    let five = policy(json!({"addons":{"request_logger":{"enabled":false}}}));
    let mut ordinary = exchange();
    verify(
        9,
        logger
            .request(Some(&five), &mut ordinary, &request, || Ok(7), &sink.writer)
            .err(),
    );
    verify(
        10,
        logger
            .response(&ordinary, &request, &response(), || Ok(8), &sink.writer)
            .err(),
    );
    verify(
        11,
        logger
            .response(
                &exchange(),
                &request,
                &Response {
                    status: None,
                    ..response()
                },
                || panic!("absent response"),
                &sink.writer,
            )
            .err(),
    );
    verify(
        12,
        logger
            .request(
                Some(&five),
                &mut exchange(),
                &request,
                || Ok(15),
                &sink.writer,
            )
            .err(),
    );
    verify(
        13,
        logger
            .request(
                Some(&five),
                &mut exchange(),
                &request,
                || Err(Error(ErrorKind::Decode)),
                &sink.writer,
            )
            .err(),
    );
    verify(
        14,
        logger
            .response(
                &exchange(),
                &request,
                &response(),
                || Err(Error(ErrorKind::Decode)),
                &sink.writer,
            )
            .err(),
    );
    verify(
        15,
        logger
            .request(
                Some(&five),
                &mut exchange(),
                &request,
                || Ok(0),
                &sink.writer,
            )
            .err(),
    );
    verify(
        16,
        logger
            .response(&exchange(), &request, &response(), || Ok(0), &sink.writer)
            .err(),
    );
    assert_eq!(logger.state.lock().unwrap().hash, five.policy_hash());
}

#[test]
fn parse_error_consumption_and_immediate_config_submission_preserve_effect_order() {
    let logger = RequestLogger::default();
    let sink = Sink::new();
    let mut exchange = exchange();
    let broken = Request {
        parsed: Err(Error(ErrorKind::Value)),
        ..request()
    };
    let policy = quiet_policy(json!({"hosts":false}));
    assert_eq!(
        logger.request(
            Some(&policy),
            &mut exchange,
            &broken,
            || panic!("parse failed"),
            &sink.writer
        ),
        Err(Error(ErrorKind::Value))
    );
    assert_eq!(sink.records().len(), 1);
    assert_eq!(logger.stats().unwrap().requests_total, 1.into());
    assert_eq!(
        logger.response(
            &exchange,
            &broken,
            &response(),
            || panic!("parse failed"),
            &sink.writer
        ),
        Err(Error(ErrorKind::Value))
    );
    assert_eq!(logger.stats().unwrap().responses_total, 1.into());
    assert_eq!(
        logger.response(
            &exchange,
            &broken,
            &Response {
                status: None,
                ..response()
            },
            || panic!("absent"),
            &sink.writer
        ),
        Err(Error(ErrorKind::Value))
    );
    assert_eq!(logger.stats().unwrap().responses_total, 1.into());
    let next = quiet_policy(json!({"hosts":2}));
    let reached = Cell::new(false);
    logger
        .request(
            Some(&next),
            &mut exchange,
            &request(),
            || {
                assert_eq!(sink.records().len(), 2);
                reached.set(true);
                Ok(0)
            },
            &sink.writer,
        )
        .unwrap();
    assert!(reached.get());
    assert_eq!(sink.records().len(), 3);
}

#[test]
fn stable_owner_early_response_and_trusted_block_metadata() {
    let logger = RequestLogger::default();
    let sink = Sink::new();
    let exchange = exchange();
    let request = Request {
        request_id: None,
        client: None,
        ..request()
    };
    let response = Response {
        start_time: None,
        attribution_quarantined: true,
        ..response()
    };
    logger
        .response(&exchange, &request, &response, || Ok(0), &sink.writer)
        .unwrap();
    let event = sink.records().pop().unwrap();
    assert!(event.get("request_id").is_none());
    assert!(event["details"]["ms"].is_null());
    assert_eq!(event["agent"], "alice");
    assert_eq!(event["details"]["attribution"]["evidence_owner"], "alice");
    assert_eq!(event["details"]["attribution_quarantined"], true);
    assert!(event.get("decision").is_none());
    let false_block = C::Bool(false);
    logger
        .response(
            &exchange,
            &request,
            &Response {
                blocked_by: Some(&false_block),
                ..response
            },
            || Ok(0),
            &sink.writer,
        )
        .unwrap();
    assert_eq!(logger.stats().unwrap().responses_total, 2.into());
    assert_eq!(logger.stats().unwrap().blocks_total, 0.into());
}
