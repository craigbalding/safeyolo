use super::*;
use crate::traffic_view::{RequestInfo, TrafficView};
use serde_json::json;

fn observed(case_sensitive: bool) -> (Arc<TrafficView>, Arc<crate::traffic_view::Exchange>) {
    let view = Arc::new(TrafficView::with_case_mode(10, 1_000_000, case_sensitive));
    let exchange = view.begin(RequestInfo {
        id: "owned".into(),
        connection_id: "connection".into(),
        agent: Some("alice".into()),
        method: "GET".into(),
        url: "https://owned.invalid/path".into(),
        headers: vec![
            ("X-Case".into(), "first".into()),
            ("X-Case".into(), "second".into()),
        ],
        started: 1.,
    });
    (view, exchange)
}
fn matched(view: &TrafficView, expression: &str) -> bool {
    view.set_user_filter(expression)
        .unwrap_or_else(|error| panic!("owned expression {expression:?}: {error}"));
    !view.flows().unwrap()["flows"]
        .as_array()
        .unwrap()
        .is_empty()
}

#[test]
fn filter_publication_preserves_pins_raw_expression_and_prior_valid_state() {
    let (view, _exchange) = observed(false);
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    assert!(matched(&view, "  ~m get  "));
    assert_eq!(view.scope()["user_filter"], "  ~m get  ");
    assert_eq!(
        view.scope()["effective_filter"],
        "~meta \"^agent:\\ alice$\" & (~m get)"
    );
    let prior = view.scope();
    assert_eq!(view.set_user_filter("~b ["), Err(FilterError::Invalid));
    assert_eq!(view.scope(), prior);
    assert_eq!(
        view.set_user_filter("~src address"),
        Err(FilterError::Unsupported)
    );
    assert_eq!(view.scope(), prior);
    view.set_scope(&json!({"agent":"bob"})).unwrap();
    assert_eq!(view.scope()["user_filter"], "  ~m get  ");
    assert!(
        view.flows().unwrap()["flows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    view.set_user_filter("").unwrap();
    assert_eq!(view.scope()["agent"], "bob");
    assert_eq!(view.facets()["agent"], json!([{"value":"alice","count":1}]));
    assert!(view.detail("owned").is_some());
}

#[test]
fn http_byte_matching_headers_decoding_missing_empty_and_error_short_circuit() {
    let (view, exchange) = observed(false);
    assert!(matched(&view, r#"~hq "first\\r\\nX-Case: second\\r\\n$""#));
    assert!(!matched(&view, "~b ^$"));
    exchange.request_body(Some(b""));
    assert!(matched(&view, "~b ^$"));
    exchange.request_headers(vec![("Content-Encoding".into(), "gzip".into())]);
    exchange.request_body(Some(b"not-gzip-but-searchable"));
    assert!(matched(&view, "~b searchable"));
    exchange.request_headers(vec![("Content-Encoding".into(), "rot13".into())]);
    view.set_user_filter("~b missing").unwrap();
    assert_eq!(view.flows(), Err(FilterError::DecodeType));
    assert!(matched(&view, "~m GET | ~b missing"));
    assert!(!matched(&view, "~m POST & ~b missing"));
    exchange.request_headers(Vec::new());
    exchange.request_body(Some(&[0xff, 0, 0xff]));
    assert!(matched(&view, r"~b \xff.\xff"));
    assert_eq!(view.set_user_filter(r"~b (.)"), Err(FilterError::Invalid));
}

#[test]
fn advanced_byte_subjects_keep_backreferences_and_lookaround_byte_wide() {
    for sensitive in [false, true] {
        let (view, exchange) = observed(sensitive);
        exchange.request_body(Some(&[255, 255]));
        if sensitive {
            assert!(matched(&view, r#"~b "(.)\\1""#));
            assert!(matched(&view, r#"~b "(?=(.))\\1""#));
        } else {
            assert_eq!(
                view.set_user_filter(r#"~b "(.)\\1""#),
                Err(FilterError::Compatibility)
            );
            assert_eq!(
                view.set_user_filter(r#"~b "(?=(.))\\1""#),
                Err(FilterError::Compatibility)
            );
        }
        assert!(matched(&view, r#"~b "(?<=.).""#));
        assert!(matched(&view, r#"~b "(?<!a)[^a]""#));
        exchange.request_body(Some(&[255, 254]));
        if sensitive {
            assert!(!matched(&view, r#"~b "(.)\\1""#));
        }
        exchange.request_body(Some(b"aA"));
        if sensitive {
            assert!(!matched(&view, r#"~b "(.)\\1""#));
        }
        for body in [&[255, b'A', 255, b'a'][..], &[b'a', b'A', 128][..]] {
            exchange.request_body(Some(body));
            assert_eq!(
                view.set_user_filter(r#"~b "(?i)(..)\\1""#),
                Err(FilterError::Compatibility)
            );
            assert_eq!(
                view.set_user_filter(r#"~b "(?i)(a)\\1""#),
                Err(FilterError::Compatibility)
            );
        }
        exchange.request_body(Some(&[255, 255]));
        assert!(matched(&view, r#"~b "(?-i:(.)\\1)""#));
        assert_eq!(
            view.set_user_filter(r#"~b "(?=\\xff)\\xff""#),
            Err(FilterError::Compatibility)
        );
    }
}

#[test]
fn shared_lexer_preserves_source_wrapper_and_numeric_escape_behavior() {
    let (view, exchange) = observed(false);
    exchange.request_body(Some(b"A B x41 101"));
    assert!(matched(&view, r#"~b "\x41""#));
    assert!(matched(&view, r#"~b "\x42""#));
    assert!(matched(&view, r#"~b "\101""#));
    assert_eq!(
        view.set_user_filter("~m GET ~u owned"),
        Err(FilterError::Invalid)
    );
    assert!(matched(&view, "~m GET & ~u owned"));
    assert_eq!(view.set_user_filter("~m^GET"), Err(FilterError::Invalid));
    assert_eq!(view.set_user_filter("~all"), Err(FilterError::Invalid));
    assert!(matched(&view, "~all & ~m GET"));
    assert!(!matched(&view, "~c 9999999999999999999999999999999999"));
}

#[test]
fn byte_class_and_verbose_mode_do_not_accept_engine_only_set_operations() {
    let (view, exchange) = observed(false);
    exchange.request_body(Some(b"x"));
    assert!(matched(&view, "~b [^^]"));
    assert_eq!(
        view.set_user_filter("~b [a--b]"),
        Err(FilterError::Compatibility)
    );
    assert!(matched(&view, r#"~b "(?x)x # ignored ( [\n""#));
    assert!(matched(&view, r#"~b "(?x:x)""#));
    exchange.request_body(Some(b"x #"));
    assert!(matched(&view, r#"~b "(?x:x)(?-x: #)""#));
}

#[test]
fn byte_word_boundaries_and_verbose_classes_keep_python_byte_subjects() {
    let (view, exchange) = observed(true);
    exchange.request_body(Some(&[0xc3, 0xa9]));
    assert!(!matched(&view, r#"~b "(\\b)\\1""#));
    assert!(matched(&view, r#"~b "\\B""#));
    exchange.request_body(Some(b" "));
    assert!(matched(&view, r#"~b "(?x)[ a]""#));
    exchange.request_body(Some(b"#"));
    assert!(matched(&view, r#"~b "(?x)[#]""#));
}

#[test]
fn source_anchor_repetition_and_class_bar_do_not_gain_engine_semantics() {
    let (view, exchange) = observed(false);
    exchange.request_body(Some(b"|"));
    assert!(matched(&view, "~b [a||b]"));
    for pattern in [r"~b \b+", "~b $+", "~b ${1}", "~b ^?"] {
        assert_eq!(view.set_user_filter(pattern), Err(FilterError::Invalid));
    }
}

mod source_replay;

#[test]
fn pinned_filter_tree_and_effective_display_resist_raw_wrapper_breakout() {
    let (view, _alice) = observed(false);
    let _bob = view.begin(RequestInfo {
        id: "bob".into(),
        connection_id: "other".into(),
        agent: Some("bob".into()),
        method: "GET".into(),
        url: "http://owned.invalid/".into(),
        headers: Vec::new(),
        started: 2.,
    });
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    let scope = view.set_user_filter("~m POST) | (~m GET").unwrap();
    assert_eq!(
        scope["effective_filter"],
        "~meta \"^agent:\\ alice$\" & ((~m POST) | (~m GET))"
    );
    let flows = view.flows().unwrap();
    assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
    assert_eq!(flows["flows"][0]["agent"], "alice");
    assert!(view.detail("bob").is_some());
}

#[test]
fn immutable_filter_snapshot_survives_replacement_and_eviction_without_capture_lock() {
    let (view, exchange) = observed(false);
    exchange.request_body(Some(b"old matching content"));
    let compiled = UserFilter::compile("~b matching", false).unwrap();
    let (snapshot, weak) = {
        let state = view.lock();
        let Body::Bytes(body) = &state.rows["owned"].request_body else {
            panic!("body missing")
        };
        (
            compiled.snapshot(&state.rows["owned"]).unwrap(),
            Arc::downgrade(body),
        )
    };
    assert!(view.state.try_lock().is_ok());
    exchange.request_body(Some(b"replacement"));
    exchange.finish(None);
    drop(exchange);
    view.configure(0, 0);
    assert!(view.detail("owned").is_none());
    assert!(compiled.matches(&snapshot).unwrap());
    assert!(weak.upgrade().is_some());
    drop(snapshot);
    assert!(weak.upgrade().is_none());
}

#[test]
fn websocket_filter_snapshots_retain_trimmed_bytes_but_new_queries_do_not() {
    let (view, exchange) = observed(false);
    exchange.websocket_start(2.);
    let content = Arc::new(MessageContent::from_bytes_for_test(
        b"matching first".to_vec(),
    ));
    let weak = Arc::downgrade(&content);
    let first = exchange
        .websocket_message(crate::websocket::MessageType::Binary, true, 3., content)
        .unwrap();
    exchange.websocket_message_dropped(first, true);
    view.set_user_filter("~bq matching").unwrap();
    let (compiled, snapshot) = {
        let state = view.lock();
        (
            state.user_filter.clone(),
            state.user_filter.snapshot(&state.rows["owned"]).unwrap(),
        )
    };
    exchange.websocket_message(
        crate::websocket::MessageType::Text,
        false,
        4.,
        Arc::new(MessageContent::from_bytes_for_test(b"later".to_vec())),
    );
    view.configure(10, 0);
    assert!(
        view.flows().unwrap()["flows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(compiled.matches(&snapshot).unwrap());
    assert!(weak.upgrade().is_some());
    drop(snapshot);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn complete_spilled_message_search_crosses_pages_without_changing_forwarded_bytes() {
    use crate::websocket::{Event, MessageType, Reader, Writer};
    use std::io::Cursor;
    let mut payload = vec![b'x'; 65_534];
    payload.extend_from_slice(b"NEEDLE");
    payload.extend_from_slice(&[255, 0]);
    let mut wire = vec![0x82, 127];
    wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    wire.extend_from_slice(&payload);
    let Event::Message(message) = Reader::new(Cursor::new(wire), false, None)
        .read()
        .await
        .unwrap()
    else {
        panic!("message missing")
    };
    assert!(message.spilled());
    let (view, exchange) = observed(false);
    exchange.websocket_start(2.);
    exchange
        .websocket_message(MessageType::Binary, false, 3., message.content())
        .unwrap();
    view.set_user_filter("~bs xNEEDLE").unwrap();
    let worker_view = view.clone();
    let flows = tokio::task::spawn_blocking(move || worker_view.flows())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
    let mut forwarded = Vec::new();
    Writer::new(&mut forwarded, false, None)
        .message(message)
        .await
        .unwrap();
    let Event::Message(delivered) = Reader::new(Cursor::new(forwarded), false, None)
        .read()
        .await
        .unwrap()
    else {
        panic!("forwarded message missing")
    };
    assert_eq!(
        delivered
            .content()
            .read_range(0, payload.len())
            .unwrap()
            .as_slice(),
        payload
    );
}

#[test]
fn escaped_wrapper_with_implicit_conjunction_has_a_truthful_parseable_display() {
    let (view, _exchange) = observed(false);
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    let raw = "~m POST) (~m GET";
    let scope = view.set_user_filter(raw).unwrap();
    assert_eq!(scope["user_filter"], raw);
    assert_eq!(
        scope["effective_filter"],
        "~meta \"^agent:\\ alice$\" & (((~m POST) ) & ((~m GET) ))"
    );
    assert!(
        view.flows().unwrap()["flows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    UserFilter::compile(scope["effective_filter"].as_str().unwrap(), false).unwrap();
}
