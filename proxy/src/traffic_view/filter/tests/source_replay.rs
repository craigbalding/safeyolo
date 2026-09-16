//! Finite actual-source parser/evaluator observations. Direct parse and shared
//! setter acceptance are tested separately, as the source wraps shared input.
use super::*;
use std::io::Write;

fn bytes(recipe: &Value) -> Option<Vec<u8>> {
    if recipe.is_null() {
        return None;
    }
    let mut bytes = if let Some(hex) = recipe["hex"].as_str() {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    } else {
        recipe["text"].as_str().unwrap_or("").as_bytes().to_vec()
    };
    bytes = bytes.repeat(recipe["repeat"].as_u64().unwrap_or(1) as usize);
    bytes.extend_from_slice(recipe["suffix_text"].as_str().unwrap_or("").as_bytes());
    if recipe["gzip"].as_bool() == Some(true) {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).unwrap();
        bytes = encoder.finish().unwrap();
    }
    Some(bytes)
}
fn headers(input: &Value) -> Vec<(String, String)> {
    input
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().into(),
                pair[1].as_str().unwrap().into(),
            )
        })
        .collect()
}
fn flow(input: &Value, sensitive: bool) -> (Arc<TrafficView>, Arc<crate::traffic_view::Exchange>) {
    let view = Arc::new(TrafficView::with_case_mode(10, usize::MAX, sensitive));
    let request = &input["request"];
    let exchange = view.begin(RequestInfo {
        id: "source".into(),
        connection_id: "owned".into(),
        agent: input["metadata"]["agent"].as_str().map(str::to_owned),
        method: request["method"].as_str().unwrap().into(),
        url: request["url"].as_str().unwrap().into(),
        headers: headers(&request["headers"]),
        started: 1.,
    });
    exchange.request_body(bytes(&request["body"]).as_deref());
    exchange.metadata(input["metadata"].as_object().unwrap());
    if !input["response"].is_null() {
        let response = &input["response"];
        exchange.response_head(
            response["status"].as_u64().unwrap() as u16,
            headers(&response["headers"]),
        );
        exchange.response_body(bytes(&response["body"]).as_deref());
    }
    if input["error"].as_bool().unwrap() {
        exchange.finish(Some("owned source error"));
    }
    if let Some(messages) = input["websocket"].as_array() {
        exchange.websocket_start(2.);
        for message in messages {
            let kind = if message["type"] == "text" {
                crate::websocket::MessageType::Text
            } else {
                crate::websocket::MessageType::Binary
            };
            let id = exchange
                .websocket_message(
                    kind,
                    message["from_client"].as_bool().unwrap(),
                    3.,
                    Arc::new(MessageContent::from_bytes_for_test(
                        bytes(&message["body"]).unwrap(),
                    )),
                )
                .unwrap();
            exchange.websocket_message_dropped(id, message["dropped"].as_bool().unwrap_or(false));
        }
    }
    (view, exchange)
}
fn direct(expression: &str, sensitive: bool) -> Result<UserFilter> {
    let mut parser = Parser {
        input: expression,
        position: 0,
        case_sensitive: sensitive,
        nodes: Vec::new(),
        outer_closed_early: false,
        implicit_offsets: Vec::new(),
    };
    let root = parser.parse()?;
    let mut filter = UserFilter::empty();
    filter.raw = Zeroizing::new(expression.into());
    filter.nodes = parser.nodes;
    filter.root = Some(root);
    filter.plan_needs();
    Ok(filter)
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/traffic_filter_source.json"
    )))
    .unwrap()
}

#[test]
fn actual_source_direct_parser_and_matching_corpus() {
    let fixture = fixture();
    let mut compared = 0;
    let mut gaps = Vec::new();
    for row in fixture["rows"].as_array().unwrap() {
        let name = row["input"]["name"].as_str().unwrap();
        if name == "pretty_url_uses_presented_host" {
            continue;
        }
        let sensitive = row["input"]["case_sensitive"].as_bool().unwrap();
        let (view, _exchange) = flow(&row["input"]["flow"], sensitive);
        for expected in row["results"].as_array().unwrap() {
            let expression = expected["expression"].as_str().unwrap();
            let filter = direct(expression, sensitive);
            if matches!(filter, Err(FilterError::Compatibility)) {
                // Exact finite engine/representation gaps; never silently count
                // a rejected source-valid pattern as a matched replay.
                assert!(
                    matches!(
                        (name, expression),
                        ("invalid_syntax", "~u [")
                            | ("ordered_header_lines", "~hq \"Raw: \\\\xff\\r\\n$\"")
                            | ("regex_backreference_lookaround", "~b \"(ab)\\\\1\"")
                    ),
                    "unexpected compatibility gap {name}: {expression:?}"
                );
                gaps.push((name.to_owned(), expression.to_owned()));
                continue;
            }
            if !expected["parse_error"].is_null() {
                assert!(
                    matches!(filter, Err(FilterError::Invalid)),
                    "expected source parse error {name}: {expression:?}"
                );
            } else {
                let filter =
                    filter.unwrap_or_else(|error| panic!("{name}: {expression:?}: {error}"));
                let snapshot = {
                    let state = view.lock();
                    filter.snapshot(&state.rows["source"]).unwrap()
                };
                let actual = filter.matches(&snapshot);
                if expected["error_type"] == "TypeError" {
                    assert_eq!(
                        actual,
                        Err(FilterError::DecodeType),
                        "{name}: {expression:?}"
                    );
                } else {
                    assert_eq!(
                        actual,
                        Ok(expected["matched"].as_bool().unwrap()),
                        "{name}: {expression:?}"
                    );
                }
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 125);
    assert_eq!(gaps.len(), 2);
    eprintln!(
        "source direct comparison: {compared} observations; exact capability gaps {gaps:?}; 3 URL projection observations excluded"
    );
}

#[test]
fn actual_source_shared_setter_preserves_previous_filter_and_pins() {
    let fixture = fixture();
    let mut count = 0;
    for row in fixture["scope_rows"].as_array().unwrap() {
        let (view, _exchange) = flow(&row["input"]["flow"], false);
        view.set_scope(&json!({"agent":row["input"]["agent"]}))
            .unwrap();
        for step in row["steps"].as_array().unwrap() {
            let result = view.set_user_filter(step["value"].as_str().unwrap());
            assert_eq!(result.is_err(), !step["error_type"].is_null());
            assert_eq!(view.scope(), step["stats"]);
            let visible = !view.flows().unwrap()["flows"]
                .as_array()
                .unwrap()
                .is_empty();
            assert_eq!(
                visible,
                step["effective_evaluation"]["matched"]
                    .as_bool()
                    .unwrap_or(true)
            );
            count += 1;
        }
    }
    assert_eq!(count, 26);
}
